package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

func TestWebH2EstablishedReadDeadlineClosesOnlyExpiredStream(t *testing.T) {
	target := startWebTCPEcho(t)
	client := newWebH2DeadlineTestClient(t, transport.DialFunc((&net.Dialer{}).DialContext))
	conn := dialWebH2DeadlineTestConn(t, client, target)
	sibling := dialWebH2DeadlineTestConn(t, client, target)
	client.mu.Lock()
	session := client.current
	client.mu.Unlock()

	result := make(chan error, 1)
	go func() {
		var data [1]byte
		_, err := conn.Read(data[:])
		result <- err
	}()
	if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := awaitWebH2DeadlineResult(t, result); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expired read error = %v, want timeout", err)
	}
	if err := conn.SetReadDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("clearing a terminal stream deadline = %v, want closed", err)
	}
	assertWebSessionSiblingEcho(t, sibling)
	if err := exchangeWebSessionEcho(client, target); err != nil {
		t.Fatalf("opening a stream after the timeout: %v", err)
	}
	assertWebH2DeadlineSessionUnchanged(t, client, session)
}

func TestWebH2EstablishedWriteDeadlineInterruptsFlowControl(t *testing.T) {
	target := startWebTCPEcho(t)
	blocked, stalledTarget := net.Pipe()
	t.Cleanup(func() { _ = blocked.Close(); _ = stalledTarget.Close() })
	client := newWebH2DeadlineTestClient(t, transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "blocked.example:443" {
			return blocked, nil
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}))
	conn := dialWebH2DeadlineTestConn(t, client, "blocked.example:443")
	sibling := dialWebH2DeadlineTestConn(t, client, target)
	client.mu.Lock()
	session := client.current
	client.mu.Unlock()

	// The target never reads. This exceeds the server's stream window and
	// leaves the caller blocked in its request pipe behind HTTP/2 flow control.
	result := make(chan error, 1)
	go func() {
		_, err := conn.Write(make([]byte, 16<<20))
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("write did not block behind flow control: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := conn.SetWriteDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := awaitWebH2DeadlineResult(t, result); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expired write error = %v, want timeout", err)
	}
	assertWebSessionSiblingEcho(t, sibling)
	assertWebH2DeadlineSessionUnchanged(t, client, session)
}

func TestWebH2DeadlineReplacementAndClearIgnoreStaleTimers(t *testing.T) {
	for _, direction := range []string{"read", "write"} {
		t.Run(direction, func(t *testing.T) {
			conn, response, request, _, _ := newWebH2DeadlinePipeConn(t)
			setDeadline := conn.SetReadDeadline
			expire := conn.expireRead
			if direction == "write" {
				setDeadline, expire = conn.SetWriteDeadline, conn.expireWrite
			}
			result := make(chan error, 1)
			go func() {
				var err error
				if direction == "read" {
					var data [1]byte
					_, err = conn.Read(data[:])
				} else {
					_, err = conn.Write([]byte("x"))
				}
				result <- err
			}()
			if err := setDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			conn.mu.Lock()
			oldSeq := conn.readSeq
			if direction == "write" {
				oldSeq = conn.writeSeq
			}
			conn.mu.Unlock()
			if err := setDeadline(time.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			// Model an old timer that has already started running when Stop
			// is called, then check that its original deadline also passes.
			expire(oldSeq)
			select {
			case err := <-result:
				t.Fatalf("replaced deadline ended pending %s: %v", direction, err)
			case <-time.After(75 * time.Millisecond):
			}
			conn.mu.Lock()
			oldSeq = conn.readSeq
			if direction == "write" {
				oldSeq = conn.writeSeq
			}
			conn.mu.Unlock()
			if err := setDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
			expire(oldSeq)
			if direction == "read" {
				if _, err := response.Write([]byte("x")); err != nil {
					t.Fatal(err)
				}
			} else {
				var data [1]byte
				if _, err := io.ReadFull(request, data[:]); err != nil {
					t.Fatal(err)
				}
			}
			if err := awaitWebH2DeadlineResult(t, result); err != nil {
				t.Fatalf("%s after clearing deadline: %v", direction, err)
			}
		})
	}
}

func TestWebH2SetDeadlineExpiresBothDirections(t *testing.T) {
	conn, _, _, cancellations, closes := newWebH2DeadlinePipeConn(t)
	readResult, writeResult := make(chan error, 1), make(chan error, 1)
	go func() { var data [1]byte; _, err := conn.Read(data[:]); readResult <- err }()
	go func() { _, err := conn.Write([]byte("x")); writeResult <- err }()
	if err := conn.SetDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	for _, result := range []<-chan error{readResult, writeResult} {
		if err := awaitWebH2DeadlineResult(t, result); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("expired I/O error = %v, want timeout", err)
		}
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if cancellations.Load() != 1 || closes.Load() != 1 {
		t.Fatalf("cancel/response Close calls = %d/%d, want 1/1", cancellations.Load(), closes.Load())
	}
}

func TestWebH2DeadlinesRaceClose(t *testing.T) {
	for i := 0; i < 100; i++ {
		conn, _, _, cancellations, closes := newWebH2DeadlinePipeConn(t)
		readResult, writeResult := make(chan error, 1), make(chan error, 1)
		go func() { var data [1]byte; _, err := conn.Read(data[:]); readResult <- err }()
		go func() { _, err := conn.Write([]byte("x")); writeResult <- err }()
		var wg sync.WaitGroup
		start := make(chan struct{})
		for worker := 0; worker < 4; worker++ {
			wg.Add(1)
			go func(worker int) {
				defer wg.Done()
				<-start
				switch worker {
				case 0:
					_ = conn.SetDeadline(time.Now())
				case 1:
					_ = conn.SetReadDeadline(time.Now().Add(time.Hour))
					_ = conn.SetWriteDeadline(time.Time{})
				default:
					_ = conn.Close()
				}
			}(worker)
		}
		close(start)
		wg.Wait()
		for _, result := range []<-chan error{readResult, writeResult} {
			if err := awaitWebH2DeadlineResult(t, result); err == nil {
				t.Fatal("closed I/O unexpectedly succeeded")
			}
		}
		if cancellations.Load() != 1 || closes.Load() != 1 {
			t.Fatalf("iteration %d: cancel/response Close calls = %d/%d, want 1/1", i, cancellations.Load(), closes.Load())
		}
	}
}

func newWebH2DeadlineTestClient(t *testing.T, dialer transport.Dialer) *WebH2Client {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	server := startWebH2TestServer(t, WebH2ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
		Dialer: dialer, Cover: http.NotFoundHandler(),
	})
	client, err := NewWebH2Client(WebH2ClientConfig{
		ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func dialWebH2DeadlineTestConn(t *testing.T, client *WebH2Client, target string) net.Conn {
	t.Helper()
	conn, err := client.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func assertWebH2DeadlineSessionUnchanged(t *testing.T, client *WebH2Client, session *webH2ClientSession) {
	t.Helper()
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.current != session || len(client.sessions) != 1 {
		t.Fatalf("deadline replaced physical connection or left extra sessions: same=%v count=%d", client.current == session, len(client.sessions))
	}
}

func awaitWebH2DeadlineResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("stream I/O remained blocked after close or deadline")
		return nil
	}
}

type webH2DeadlineCountingReader struct {
	*io.PipeReader
	closes *atomic.Int32
}

func (r *webH2DeadlineCountingReader) Close() error {
	r.closes.Add(1)
	return r.PipeReader.Close()
}

func newWebH2DeadlinePipeConn(t *testing.T) (*webH2Conn, *io.PipeWriter, *io.PipeReader, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	responseReader, responseWriter := io.Pipe()
	requestReader, requestWriter := io.Pipe()
	cancellations, closes := new(atomic.Int32), new(atomic.Int32)
	var conn *webH2Conn
	conn = newWebH2Conn(&webH2DeadlineCountingReader{responseReader, closes}, requestWriter, func() {
		cancellations.Add(1)
		// The cancellation callback must run outside the state mutex.
		if err := conn.SetDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
			t.Errorf("deadline change during cancellation = %v, want closed", err)
		}
	}, webAddr{}, webAddr{})
	t.Cleanup(func() {
		_ = conn.Close()
		_ = responseWriter.Close()
		_ = requestReader.Close()
	})
	return conn, responseWriter, requestReader, cancellations, closes
}
