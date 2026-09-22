package tunnel

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/accel"
	quic "github.com/quic-go/quic-go"
)

const feedbackChunkSize = 32 << 10

var feedbackPayload = bytes.Repeat([]byte("QUIC feedback payload:0123456789"), feedbackChunkSize/32)

// These tests cover the real QUIC stream adapter/controller, not authentication
// or serverCore. The deadline bounds failures; no comparison with another mode
// or a minimum transfer speed determines success.
func TestQUICPacingSustainedDownloadDoesNotSelfLimitToFloor(t *testing.T) {
	f := newFeedbackQUICFixture(t, 1, 0)
	const size = 8 << 20
	writer := f.run(func() error { return writeFeedbackPayload(f.serverStreams[0], size) })
	if err := readFeedbackPayload(f.clientStreams[0], size); err != nil {
		t.Fatalf("8 MiB download: %v (target %d)", err, f.pacer.controller.TargetBytesPerSecond())
	}
	f.await(t, writer)
	if got := f.pacer.controller.TargetBytesPerSecond(); got <= 64<<10 {
		t.Fatalf("sustained download reached default minimum target: %d", got)
	}
	if f.clock.sleeps.Load() == 0 {
		t.Fatal("fixture never exercised actual token waiting")
	}
	f.checkReverse(t)
	t.Logf("8 MiB intact; target=%d; real token sleeps=%d", f.pacer.controller.TargetBytesPerSecond(), f.clock.sleeps.Load())
}

func TestQUICPacingSharedStreamsAcceptTransportBackpressure(t *testing.T) {
	// Each stream's fixed 16 KiB receive window is smaller than one 32 KiB
	// write, and cannot auto-grow to absorb the entire slow-reader payload.
	f := newFeedbackQUICFixture(t, 2, 16<<10)
	warmup := f.run(func() error { return writeFeedbackPayload(f.serverStreams[0], 1<<20) })
	if err := readFeedbackPayload(f.clientStreams[0], 1<<20); err != nil {
		t.Fatal(err)
	}
	f.await(t, warmup)
	if f.clock.sleeps.Load() == 0 {
		t.Fatal("warmup never exercised actual token waiting")
	}

	const rounds = 16
	const slowBytes = rounds * feedbackChunkSize
	primaryEntered := make(chan struct{}, 1)
	f.rawStreams[0].entered = primaryEntered
	primaryTransportBefore := f.rawStreams[0].writeTime.Load()
	primaryPacingBefore := f.streamPacers[0].waitTime.Load()
	primary := f.run(func() error { return writeFeedbackPayload(f.serverStreams[0], slowBytes) })
	select {
	case <-primaryEntered:
	case <-f.ctx.Done():
		t.Fatal(f.ctx.Err())
	}
	// Start a fast sibling while the primary cannot drain its finite receive
	// buffer. The real clock observes actual token sleeps, not merely calls to
	// Wait, while the primary is inside the underlying QUIC stream.Write.
	siblingBurst := f.run(func() error { return writeFeedbackPayload(f.serverStreams[1], 128<<10) })
	if err := readFeedbackPayload(f.clientStreams[1], 128<<10); err != nil {
		t.Fatal(err)
	}
	f.await(t, siblingBurst)
	if f.clock.sleepsWithPrimaryWrite.Load() == 0 {
		t.Fatal("did not observe sibling token sleep overlapping a primary QUIC write")
	}

	before := f.pacer.controller.TargetBytesPerSecond()
	// Both streams now have slow readers. Unlike one blocked stream with an
	// unrestricted sibling, this reduces delivery for the shared connection.
	siblingSlow := f.run(func() error { return writeFeedbackPayload(f.serverStreams[1], slowBytes) })
	for round := 0; round < rounds; round++ {
		timer := time.NewTimer(120 * time.Millisecond)
		select {
		case <-timer.C:
		case <-f.ctx.Done():
			timer.Stop()
			t.Fatal(f.ctx.Err())
		}
		for _, reader := range f.clientStreams {
			if err := readFeedbackPayload(reader, feedbackChunkSize); err != nil {
				t.Fatal(err)
			}
		}
	}
	f.await(t, primary)
	f.await(t, siblingSlow)
	after := f.pacer.controller.TargetBytesPerSecond()
	transport := time.Duration(f.rawStreams[0].writeTime.Load() - primaryTransportBefore)
	pacing := time.Duration(f.streamPacers[0].waitTime.Load() - primaryPacingBefore)
	if transport <= pacing {
		t.Fatalf("slow-reader phase was not transport-bound: QUIC Write=%s, pacing Wait=%s", transport, pacing)
	}
	// In the default balanced profile both RTT and loss penalties have a 0.60
	// floor. With unchanged capacity, even applying both worst-case penalties
	// cannot reduce the target below 36% of its previous value. Crossing that
	// bound proves capacity evidence changed, not merely a congestion penalty.
	if after >= before*36/100 {
		t.Fatalf("shared capacity did not adapt to transport backpressure: target %d -> %d, want below %d", before, after, before*36/100)
	}
	// Removing the imposed reader delays must leave the same streams usable.
	for index := range f.serverStreams {
		writer := f.run(func() error { return writeFeedbackPayload(f.serverStreams[index], 128<<10) })
		if err := readFeedbackPayload(f.clientStreams[index], 128<<10); err != nil {
			t.Fatal(err)
		}
		f.await(t, writer)
	}
	f.checkReverse(t)
	t.Logf("shared target %d -> %d; primary QUIC Write=%s, pacing Wait=%s; overlapping token sleeps=%d",
		before, after, transport, pacing, f.clock.sleepsWithPrimaryWrite.Load())
}

type feedbackQUICFixture struct {
	ctx           context.Context
	pacer         *connectionPacer
	clock         *feedbackRealClock
	clientStreams []*quic.Stream
	serverStreams []*quicStreamConn
	rawStreams    []*feedbackRawStream
	streamPacers  []*feedbackObservedPacer
	workers       sync.WaitGroup
}

func newFeedbackQUICFixture(t *testing.T, streamCount int, receiveWindow uint64) *feedbackQUICFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	f := &feedbackQUICFixture{ctx: ctx, clock: &feedbackRealClock{}}
	var listener *quic.Listener
	var client, server *quic.Conn
	t.Cleanup(func() {
		cancel()
		if client != nil {
			_ = client.CloseWithError(applicationShutdown, "test finished")
		}
		if server != nil {
			_ = server.CloseWithError(applicationShutdown, "test finished")
		}
		if listener != nil {
			_ = listener.Close()
		}
		done := make(chan struct{})
		go func() { f.workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("feedback fixture writers did not stop")
		}
	})
	serverTLS, clientTLS := testTLSConfigs(t)
	var err error
	listener, err = quic.ListenAddr("127.0.0.1:0", mustServerTLSConfig(t, serverTLS), hardenedQUICServerConfig(nil, streamCount))
	if err != nil {
		t.Fatal(err)
	}
	rawTLS, err := clientTLSConfig(clientTLS, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	quicConfig := hardenedQUICClientConfig(nil)
	if receiveWindow != 0 {
		quicConfig.InitialStreamReceiveWindow = receiveWindow
		quicConfig.MaxStreamReceiveWindow = receiveWindow
		quicConfig.InitialConnectionReceiveWindow = receiveWindow * uint64(streamCount) * 4
		quicConfig.MaxConnectionReceiveWindow = quicConfig.InitialConnectionReceiveWindow
	}
	client, err = quic.DialAddr(ctx, listener.Addr().String(), rawTLS, quicConfig)
	if err != nil {
		t.Fatal(err)
	}
	server, err = listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.pacer, err = newConnectionPacer(PacingConfig{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	config, err := f.pacer.config.accelConfig(0)
	if err != nil {
		t.Fatal(err)
	}
	// Identical wall-clock semantics to accel's systemClock; this observes
	// actual timer sleeps without changing default rates, gains, or time.
	config.Clock = f.clock
	f.pacer.controller, err = accel.New(config)
	if err != nil {
		t.Fatal(err)
	}
	deadline, _ := ctx.Deadline()
	for index := 0; index < streamCount; index++ {
		clientStream, err := client.OpenStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := clientStream.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		if _, err := clientStream.Write([]byte{byte(index)}); err != nil {
			t.Fatal(err)
		}
		serverStream, err := server.AcceptStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := serverStream.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		var marker [1]byte
		if _, err := io.ReadFull(serverStream, marker[:]); err != nil || marker[0] != byte(index) {
			t.Fatalf("stream marker: %v, %v", marker, err)
		}
		raw := &feedbackRawStream{quicStream: serverStream}
		observed := &feedbackObservedPacer{connectionPacer: f.pacer}
		f.clientStreams = append(f.clientStreams, clientStream)
		f.serverStreams = append(f.serverStreams, newQUICStreamConnWithPacer(raw, server, observed))
		f.rawStreams = append(f.rawStreams, raw)
		f.streamPacers = append(f.streamPacers, observed)
	}
	f.clock.primary = &f.rawStreams[0].pending
	return f
}

func (f *feedbackQUICFixture) run(work func() error) <-chan error {
	done := make(chan error, 1)
	f.workers.Add(1)
	go func() { defer f.workers.Done(); done <- work() }()
	return done
}

func (f *feedbackQUICFixture) await(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-f.ctx.Done():
		t.Fatal(f.ctx.Err())
	}
}

func (f *feedbackQUICFixture) checkReverse(t *testing.T) {
	t.Helper()
	want := []byte("same connection reverse direction remains usable")
	if _, err := f.clientStreams[0].Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(f.serverStreams[0], got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("reverse payload mismatch: %q, %v", got, err)
	}
}

func writeFeedbackPayload(writer io.Writer, size int) error {
	for remaining := size; remaining > 0; {
		chunk := feedbackPayload[:min(remaining, len(feedbackPayload))]
		n, err := writer.Write(chunk)
		if err != nil {
			return err
		}
		if n != len(chunk) {
			return io.ErrShortWrite
		}
		remaining -= n
	}
	return nil
}

func readFeedbackPayload(reader io.Reader, size int) error {
	buffer := make([]byte, len(feedbackPayload))
	for remaining := size; remaining > 0; {
		chunk := buffer[:min(remaining, len(buffer))]
		if _, err := io.ReadFull(reader, chunk); err != nil {
			return err
		}
		if !bytes.Equal(chunk, feedbackPayload[:len(chunk)]) {
			return fmt.Errorf("feedback payload mismatch at byte %d", size-remaining)
		}
		remaining -= len(chunk)
	}
	return nil
}

type feedbackRawStream struct {
	quicStream
	entered   chan struct{}
	pending   atomic.Bool
	writeTime atomic.Int64
}

func (s *feedbackRawStream) Write(p []byte) (int, error) {
	started := time.Now()
	s.pending.Store(true)
	select {
	case s.entered <- struct{}{}:
	default:
	}
	n, err := s.quicStream.Write(p)
	s.pending.Store(false)
	s.writeTime.Add(int64(time.Since(started)))
	return n, err
}

type feedbackObservedPacer struct {
	*connectionPacer
	waitTime atomic.Int64
}

func (p *feedbackObservedPacer) wait(ctx context.Context, size int, conn *quic.Conn) error {
	started := time.Now()
	err := p.connectionPacer.wait(ctx, size, conn)
	p.waitTime.Add(int64(time.Since(started)))
	return err
}

type feedbackRealClock struct {
	primary                *atomic.Bool
	sleeps                 atomic.Int64
	sleepsWithPrimaryWrite atomic.Int64
}

func (*feedbackRealClock) Now() time.Time { return time.Now() }

func (c *feedbackRealClock) Sleep(ctx context.Context, duration time.Duration) error {
	c.sleeps.Add(1)
	if c.primary != nil && c.primary.Load() {
		c.sleepsWithPrimaryWrite.Add(1)
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
