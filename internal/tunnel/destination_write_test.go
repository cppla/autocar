package tunnel

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestDestinationWriteChunksCannotBeBypassedByCopy(t *testing.T) {
	for _, writerTo := range []bool{false, true} {
		name := "reader_only"
		if writerTo {
			name = "source_writer_to"
		}
		t.Run(name, func(t *testing.T) {
			payload := bytes.Repeat([]byte("x"), 3*destinationWriteChunkSize+1)
			raw := &destinationWriteSpy{}
			conn := &destinationWriteConn{Conn: raw, timeout: time.Second}
			if _, ok := any(conn).(io.ReaderFrom); ok {
				t.Fatal("io.Copy could bypass deadline handling through ReaderFrom")
			}
			if _, ok := any(conn).(io.WriterTo); ok {
				t.Fatal("io.Copy could bypass the wrapper through WriterTo")
			}
			var source io.Reader = bytes.NewReader(payload)
			if !writerTo {
				source = struct{ io.Reader }{source}
			}
			before := time.Now()
			n, err := io.Copy(conn, source)
			if err != nil || n != int64(len(payload)) || !bytes.Equal(raw.data.Bytes(), payload) {
				t.Fatalf("copy = %d, %v, target bytes=%d", n, err, raw.data.Len())
			}
			if raw.readFromCalled || raw.maxWrite > destinationWriteChunkSize {
				t.Fatalf("bypassed chunking: ReadFrom=%v, largest write=%d", raw.readFromCalled, raw.maxWrite)
			}
			if raw.writes != 4 || len(raw.deadlines) != 8 {
				t.Fatalf("writes/deadline changes = %d/%d, want 4/8", raw.writes, len(raw.deadlines))
			}
			for i := 0; i < len(raw.deadlines); i += 2 {
				if raw.deadlines[i].Before(before.Add(time.Second)) || !raw.deadlines[i+1].IsZero() {
					t.Fatalf("write %d did not receive and then clear its deadline", i/2)
				}
			}
			if raw.readDeadlines != 0 {
				t.Fatal("destination write policy changed a read deadline")
			}
			if err := conn.CloseWrite(); err != nil || raw.halfCloses != 1 {
				t.Fatal("destination half-close was not forwarded")
			}
		})
	}
}

func TestDestinationWriteErrorsPreservePartialProgress(t *testing.T) {
	writeErr := errors.New("destination write failed")
	deadlineErr := errors.New("deadline update failed")
	for _, tc := range []struct {
		name         string
		n            int
		err          error
		failDeadline int
		wantN        int
		wantErr      error
		wantWrites   int
	}{
		{"partial_error", 2, writeErr, 0, 2, writeErr, 1},
		{"partial_timeout", 2, &net.DNSError{IsTimeout: true}, 0, 2, nil, 1},
		{"zero_progress", 0, nil, 0, 0, io.ErrShortWrite, 1},
		{"arm_error", 0, nil, 1, 0, deadlineErr, 0},
		{"clear_error", 4, nil, 2, 4, deadlineErr, 1},
		{"write_error_wins", 2, writeErr, 2, 2, writeErr, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := &destinationWriteSpy{
				write:        func([]byte) (int, error) { return tc.n, tc.err },
				failDeadline: tc.failDeadline, deadlineErr: deadlineErr,
			}
			conn := &destinationWriteConn{Conn: raw, timeout: time.Second}
			n, err := conn.Write([]byte("data"))
			wantErr := tc.wantErr
			if tc.name == "partial_timeout" {
				wantErr = tc.err
			}
			if n != tc.wantN || !errors.Is(err, wantErr) || raw.writes != tc.wantWrites {
				t.Fatalf("Write=%d,%v writes=%d; want %d,%v writes=%d", n, err, raw.writes, tc.wantN, wantErr, tc.wantWrites)
			}
			if tc.failDeadline != 1 && (len(raw.deadlines) != 2 || !raw.deadlines[1].IsZero()) {
				t.Fatal("completed or failed write did not clear its deadline")
			}
		})
	}
}

func TestDestinationWriteRejectsInvalidCounts(t *testing.T) {
	for _, count := range []int{-1, 5} {
		raw := &destinationWriteSpy{write: func([]byte) (int, error) { return count, nil }}
		conn := &destinationWriteConn{Conn: raw, timeout: time.Second}
		if n, err := conn.Write([]byte("data")); n != 0 || err == nil {
			t.Fatalf("invalid count %d returned %d, %v", count, n, err)
		}
		if len(raw.deadlines) != 2 || !raw.deadlines[1].IsZero() {
			t.Fatal("invalid count left its deadline armed")
		}
	}
}

func TestDestinationWriteContinuesSuccessfulShortWrites(t *testing.T) {
	raw := &destinationWriteSpy{}
	raw.write = func(p []byte) (int, error) {
		return raw.data.Write(p[:min(len(p), 2)])
	}
	conn := &destinationWriteConn{Conn: raw, timeout: time.Second}
	payload := []byte("payload")
	if n, err := conn.Write(payload); n != len(payload) || err != nil || !bytes.Equal(raw.data.Bytes(), payload) {
		t.Fatalf("short-write continuation = %d, %v, %q", n, err, raw.data.Bytes())
	}
	if raw.writes != 4 || len(raw.deadlines) != 8 {
		t.Fatalf("short writes/deadline updates = %d/%d, want 4/8", raw.writes, len(raw.deadlines))
	}
}

func TestDestinationWriteSuccessLeavesIdleAndReadsAlone(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	if err := local.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	conn := &destinationWriteConn{Conn: local, timeout: 80 * time.Millisecond}
	done := make(chan error, 1)
	go func() {
		var payload [5]byte
		if _, err := io.ReadFull(peer, payload[:]); err != nil {
			done <- err
			return
		}
		if _, err := peer.Write([]byte("reply")); err != nil {
			done <- err
			return
		}
		_, err := io.ReadFull(peer, payload[:])
		done <- err
	}()
	if _, err := conn.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * conn.timeout)
	var reply [5]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil || string(reply[:]) != "reply" {
		t.Fatalf("read after successful write and idle = %q, %v", reply, err)
	}
	if _, err := conn.Write([]byte("later")); err != nil {
		t.Fatalf("write after idle: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("target did not finish after resumed write")
	}
}

func TestDestinationWriteDeadlineBoundsPendingIO(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	conn := &destinationWriteConn{Conn: local, timeout: 80 * time.Millisecond}
	done := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("blocked upload"))
		done <- err
	}()
	select {
	case err := <-done:
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("write error = %v, want timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("destination write was not bounded")
	}
}

func TestDestinationWriteCloseDoesNotWaitForWriter(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	entered := make(chan struct{})
	raw := &destinationWriteSignalConn{Conn: local, entered: entered}
	conn := &destinationWriteConn{Conn: raw, timeout: time.Hour}
	done := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := conn.Write([]byte("blocked"))
			done <- err
		}()
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("writer did not enter target Write")
	}
	closed := make(chan struct{})
	go func() { _ = conn.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close waited for the blocked writer lock")
	}
	for range 2 {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("blocked write succeeded after Close")
			}
		case <-time.After(time.Second):
			t.Fatal("writer remained blocked after Close")
		}
	}
}

type destinationWriteSignalConn struct {
	net.Conn
	entered chan struct{}
	once    sync.Once
}

func (c *destinationWriteSignalConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Write(p)
}

type destinationWriteSpy struct {
	net.Conn
	data                                        bytes.Buffer
	writes, maxWrite, readDeadlines, halfCloses int
	deadlines                                   []time.Time
	readFromCalled                              bool
	write                                       func([]byte) (int, error)
	failDeadline                                int
	deadlineErr                                 error
}

func (c *destinationWriteSpy) Write(p []byte) (int, error) {
	c.writes++
	c.maxWrite = max(c.maxWrite, len(p))
	if c.write != nil {
		return c.write(p)
	}
	return c.data.Write(p)
}

func (c *destinationWriteSpy) SetWriteDeadline(deadline time.Time) error {
	c.deadlines = append(c.deadlines, deadline)
	if len(c.deadlines) == c.failDeadline {
		return c.deadlineErr
	}
	return nil
}

func (c *destinationWriteSpy) SetReadDeadline(time.Time) error { c.readDeadlines++; return nil }
func (c *destinationWriteSpy) CloseWrite() error               { c.halfCloses++; return nil }
func (c *destinationWriteSpy) ReadFrom(io.Reader) (int64, error) {
	c.readFromCalled = true
	return 0, errors.New("unbounded ReaderFrom invoked")
}
