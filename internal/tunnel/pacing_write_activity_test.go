package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

func TestQUICWriteActivityCoversPacingAndTransportWait(t *testing.T) {
	stream := &blockingQUICStream{
		writeStarted: make(chan struct{}), writeCanceled: make(chan struct{}),
	}
	waitStarted := make(chan struct{})
	allowWrite := make(chan struct{})
	pacer := &activityQUICWritePacer{waitFn: func(ctx context.Context) error {
		close(waitStarted)
		select {
		case <-allowWrite:
			return nil
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}}
	conn := newQUICStreamConnWithPacer(stream, nil, pacer)
	defer conn.Close()
	done := make(chan error, 1)
	go func() { _, err := conn.Write([]byte("pending")); done <- err }()
	awaitActivitySignal(t, waitStarted)
	assertWriteActivity(t, pacer, 1, 1, 0)
	close(allowWrite)
	awaitActivitySignal(t, stream.writeStarted)
	assertWriteActivity(t, pacer, 1, 1, 0)
	_ = conn.Close()
	if err := awaitActivityResult(t, done); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write error = %v, want net.ErrClosed", err)
	}
	assertWriteActivity(t, pacer, 0, 1, 1)
}

func TestQUICWriteActivityEndsOnEveryReturn(t *testing.T) {
	sentinel := errors.New("write failure")
	for _, test := range []struct {
		name       string
		writeN     int
		writeErr   error
		waitErr    error
		wantN      int
		wantErr    error
		wantWrites int
	}{
		{name: "chunked success", writeN: -1, wantN: 7, wantWrites: 3},
		{name: "transport error", writeErr: sentinel, wantErr: sentinel, wantWrites: 1},
		{name: "partial transport error", writeN: 1, writeErr: sentinel, wantN: 1, wantErr: sentinel, wantWrites: 1},
		{name: "short write", writeN: 1, wantN: 1, wantErr: io.ErrShortWrite, wantWrites: 1},
		{name: "pacing error", waitErr: sentinel, wantErr: sentinel},
	} {
		t.Run(test.name, func(t *testing.T) {
			pacer := &activityQUICWritePacer{maxChunk: 3}
			pacer.waitFn = func(context.Context) error {
				assertWriteActivity(t, pacer, 1, 1, 0)
				return test.waitErr
			}
			writes := 0
			stream := &activityQUICStream{writeFn: func(p []byte) (int, error) {
				assertWriteActivity(t, pacer, 1, 1, 0)
				writes++
				if test.writeN < 0 {
					return len(p), test.writeErr
				}
				return test.writeN, test.writeErr
			}}
			conn := newQUICStreamConnWithPacer(stream, nil, pacer)
			defer conn.Close()
			n, err := conn.Write([]byte("payload"))
			if n != test.wantN || !errors.Is(err, test.wantErr) {
				t.Fatalf("Write = %d, %v; want %d, %v", n, err, test.wantN, test.wantErr)
			}
			if writes != test.wantWrites {
				t.Fatalf("transport writes = %d, want %d", writes, test.wantWrites)
			}
			assertWriteActivity(t, pacer, 0, 1, 1)
		})
	}
}

func TestQUICWriteActivityEndsWhenPacingCanceled(t *testing.T) {
	for _, cancellation := range []string{"local close", "peer cancel", "deadline"} {
		t.Run(cancellation, func(t *testing.T) {
			streamCtx, cancelStream := context.WithCancel(context.Background())
			defer cancelStream()
			stream := &blockingQUICStream{
				ctx: streamCtx, writeStarted: make(chan struct{}), writeCanceled: make(chan struct{}),
			}
			started := make(chan struct{})
			pacer := &activityQUICWritePacer{waitFn: func(ctx context.Context) error {
				select {
				case <-started:
				default:
					close(started)
				}
				<-ctx.Done()
				return context.Cause(ctx)
			}}
			conn := newQUICStreamConnWithPacer(stream, nil, pacer)
			defer conn.Close()
			done := make(chan error, 1)
			go func() { _, err := conn.Write([]byte("pending")); done <- err }()
			awaitActivitySignal(t, started)
			assertWriteActivity(t, pacer, 1, 1, 0)
			wantErr := net.ErrClosed
			switch cancellation {
			case "local close":
				_ = conn.Close()
			case "peer cancel":
				cancelStream()
			case "deadline":
				_ = conn.SetWriteDeadline(time.Now())
				wantErr = context.DeadlineExceeded
			}
			if err := awaitActivityResult(t, done); !errors.Is(err, wantErr) {
				t.Fatalf("Write error = %v, want %v", err, wantErr)
			}
			assertWriteActivity(t, pacer, 0, 1, 1)
			select {
			case <-stream.writeStarted:
				t.Fatal("canceled pacing wait reached the transport")
			default:
			}
		})
	}
}

func TestQUICWriteActivitySerialWrites(t *testing.T) {
	pacer := &activityQUICWritePacer{maxChunk: 2}
	conn := newQUICStreamConnWithPacer(&recordingQUICStream{}, nil, pacer)
	defer conn.Close()
	for i := int64(1); i <= 3; i++ {
		pacer.waitFn = func(context.Context) error {
			assertWriteActivity(t, pacer, 1, i, i-1)
			return nil
		}
		if _, err := conn.Write([]byte("payload")); err != nil {
			t.Fatal(err)
		}
		assertWriteActivity(t, pacer, 0, i, i)
	}
}

func TestQUICWriteActivitySharedAcrossStreams(t *testing.T) {
	started := make(chan struct{}, 2)
	pacer := &activityQUICWritePacer{waitFn: func(ctx context.Context) error {
		started <- struct{}{}
		<-ctx.Done()
		return context.Cause(ctx)
	}}
	first := newQUICStreamConnWithPacer(&recordingQUICStream{}, nil, pacer)
	second := newQUICStreamConnWithPacer(&recordingQUICStream{}, nil, pacer)
	defer first.Close()
	defer second.Close()
	firstDone, secondDone := make(chan error, 1), make(chan error, 1)
	go func() { _, err := first.Write([]byte("one")); firstDone <- err }()
	go func() { _, err := second.Write([]byte("two")); secondDone <- err }()
	awaitActivitySignal(t, started)
	awaitActivitySignal(t, started)
	assertWriteActivity(t, pacer, 2, 2, 0)
	_ = first.Close()
	if err := awaitActivityResult(t, firstDone); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("first Write error = %v", err)
	}
	assertWriteActivity(t, pacer, 1, 2, 1)
	_ = second.Close()
	if err := awaitActivityResult(t, secondDone); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second Write error = %v", err)
	}
	assertWriteActivity(t, pacer, 0, 2, 2)
}

func TestQUICWriteActivitySkipsZeroAndClosedWrites(t *testing.T) {
	for _, closing := range []string{"open", "close", "close write"} {
		t.Run(closing, func(t *testing.T) {
			pacer := &activityQUICWritePacer{}
			stream := &recordingQUICStream{}
			conn := newQUICStreamConnWithPacer(stream, nil, pacer)
			defer conn.Close()
			switch closing {
			case "close":
				_ = conn.Close()
			case "close write":
				_ = conn.CloseWrite()
			}
			n, err := conn.Write(nil)
			if n != 0 || (closing == "open" && err != nil) || (closing != "open" && !errors.Is(err, net.ErrClosed)) {
				t.Fatalf("zero Write = %d, %v", n, err)
			}
			if closing != "open" {
				if n, err := conn.Write([]byte("closed")); n != 0 || !errors.Is(err, net.ErrClosed) {
					t.Fatalf("closed Write = %d, %v", n, err)
				}
			}
			assertWriteActivity(t, pacer, 0, 0, 0)
		})
	}
}

type activityQUICWritePacer struct {
	active, begins, ends atomic.Int64
	maxChunk             int
	waitFn               func(context.Context) error
}

func (p *activityQUICWritePacer) beginWrite()        { p.active.Add(1); p.begins.Add(1) }
func (p *activityQUICWritePacer) endWrite()          { p.active.Add(-1); p.ends.Add(1) }
func (p *activityQUICWritePacer) maxChunkBytes() int { return p.maxChunk }
func (p *activityQUICWritePacer) wait(ctx context.Context, _ int, _ *quic.Conn) error {
	if p.waitFn != nil {
		return p.waitFn(ctx)
	}
	return nil
}

type activityQUICStream struct {
	recordingQUICStream
	writeFn func([]byte) (int, error)
}

func (s *activityQUICStream) Write(p []byte) (int, error) { return s.writeFn(p) }

func assertWriteActivity(t *testing.T, p *activityQUICWritePacer, active, begins, ends int64) {
	t.Helper()
	if gotActive, gotBegins, gotEnds := p.active.Load(), p.begins.Load(), p.ends.Load(); gotActive != active || gotBegins != begins || gotEnds != ends {
		t.Fatalf("write activity = (%d active, %d begins, %d ends), want (%d, %d, %d)", gotActive, gotBegins, gotEnds, active, begins, ends)
	}
}

func awaitActivitySignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal("write activity signal did not arrive")
	}
}

func awaitActivityResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("write activity did not finish")
		return nil
	}
}
