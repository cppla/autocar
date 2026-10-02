package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

// Close always closes the real endpoint before returning its injected error.
// Counting calls verifies ownership independently of the peer's EOF signal.
type tcpDialErrorOwnedConn struct {
	net.Conn
	closeCalls atomic.Int32
	closeError error
}

func (c *tcpDialErrorOwnedConn) Close() error {
	c.closeCalls.Add(1)
	_ = c.Conn.Close()
	return c.closeError
}

func tcpDialErrorOwnershipWait(t *testing.T, done <-chan struct{}, label string) bool {
	t.Helper()
	select {
	case <-done:
		return true
	case <-time.After(2 * time.Second):
		t.Errorf("%s did not finish", label)
		return false
	}
}

// Existing HTTP Shutdown can report a duplicate listener close. Accept only
// that known close result, including wrappers; a joined unrelated failure or
// context deadline must still fail the ownership fixture.
func tcpDialErrorOwnershipOnlyClosed(err error) bool {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if !tcpDialErrorOwnershipOnlyClosed(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return tcpDialErrorOwnershipOnlyClosed(wrapped.Unwrap())
	}
	return errors.Is(err, net.ErrClosed)
}

func TestTCPDialErrorOwnershipFrontends(t *testing.T) {
	for _, frontend := range []string{"socks-connect", "http-connect", "http-forward"} {
		t.Run(frontend, func(t *testing.T) {
			for _, typedTimeout := range []bool{false, true} {
				name := "ordinary-error-close-timeout"
				setupError := errors.New("post-dial setup failed")
				var closeError error = &net.OpError{Op: "close", Net: "tcp", Err: context.DeadlineExceeded}
				wantSOCKS, wantHTTP := byte(socksReplyGeneralFailure), http.StatusBadGateway
				if typedTimeout {
					name = "typed-timeout-close-ordinary-error"
					setupError = &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}
					closeError = errors.New("closing failed result failed")
					wantSOCKS, wantHTTP = socksReplyTTLExpired, http.StatusGatewayTimeout
				}
				t.Run(name, func(t *testing.T) {
					testTCPDialErrorOwnershipFrontend(t, frontend, setupError, closeError, wantSOCKS, wantHTTP)
				})
			}
		})
	}
}

func testTCPDialErrorOwnershipFrontend(t *testing.T, frontend string, setupError, closeError error, wantSOCKS byte, wantHTTP int) {
	t.Helper()
	originListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = originListener.Close() })
	if err := originListener.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	returned := make(chan *tcpDialErrorOwnedConn, 1)
	dialStarted, dialDone := make(chan struct{}), make(chan struct{})
	dialer := transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		close(dialStarted)
		defer close(dialDone)
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		observed := &tcpDialErrorOwnedConn{Conn: conn, closeError: closeError}
		returned <- observed
		return observed, setupError
	})
	cfg := Config{Dialer: dialer, DialTimeout: 2 * time.Second, HandshakeTimeout: time.Second, IdleTimeout: 2 * time.Second, MaxConnections: 1}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var shutdown func(context.Context) error
	var tracker *connTracker
	var client, peer net.Conn
	var upstream *tcpDialErrorOwnedConn
	serveDone, handlerDone, handlerEntered := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var serveError error
	workersStarted := false
	t.Cleanup(func() {
		if client != nil {
			_ = client.Close()
		}
		if shutdown != nil {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_ = shutdown(ctx)
		}
		_ = listener.Close()
		if workersStarted {
			tcpDialErrorOwnershipWait(t, serveDone, "frontend Serve cleanup")
			select {
			case <-handlerEntered:
				tcpDialErrorOwnershipWait(t, handlerDone, "frontend handler cleanup")
			default:
			}
		}
		select {
		case <-dialStarted:
			tcpDialErrorOwnershipWait(t, dialDone, "custom dial cleanup")
		default:
		}
		if upstream == nil {
			select {
			case upstream = <-returned:
			default:
			}
		}
		if upstream != nil {
			// Cleanup must also release a regressed leaked socket, without
			// adding a call to the production ownership counter.
			_ = upstream.Conn.Close()
		}
		if peer != nil {
			_ = peer.Close()
		}
	})
	if frontend == "socks-connect" {
		server, err := NewSOCKS5Server(cfg)
		if err != nil {
			t.Fatal(err)
		}
		shutdown, tracker = server.Shutdown, server.lifecycle.tracker
		managed, err := server.lifecycle.manage(listener)
		if err != nil {
			t.Fatal(err)
		}
		workersStarted = true
		go func() {
			defer close(serveDone)
			conn, err := managed.Accept()
			if err != nil {
				serveError = err
				return
			}
			close(handlerEntered)
			server.serveConn(conn)
			close(handlerDone)
		}()
	} else {
		server, err := NewHTTPServer(cfg)
		if err != nil {
			t.Fatal(err)
		}
		shutdown, tracker = server.Shutdown, server.lifecycle.tracker
		var startOnce, doneOnce sync.Once
		server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			startOnce.Do(func() { close(handlerEntered) })
			defer doneOnce.Do(func() { close(handlerDone) })
			server.ServeHTTP(w, r)
		})
		workersStarted = true
		go func() { defer close(serveDone); serveError = server.Serve(listener) }()
	}
	client, err = net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if frontend == "socks-connect" {
		socksGreeting(t, client, nil)
		host, port := splitAddress(t, originListener.Addr().String())
		mustWrite(t, client, domainSOCKSRequest(socksCommandConnect, host, port))
		if reply := readSOCKSReply(t, client); reply != wantSOCKS {
			t.Errorf("SOCKS reply = %d, want original setup error reply %d", reply, wantSOCKS)
		}
	} else {
		method := http.MethodConnect
		request := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", originListener.Addr(), originListener.Addr())
		if frontend == "http-forward" {
			method = http.MethodGet
			request = fmt.Sprintf("GET http://%s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", originListener.Addr(), originListener.Addr())
		}
		mustWrite(t, client, []byte(request))
		response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: method})
		if err != nil {
			t.Fatal(err)
		}
		_, readError := io.ReadAll(response.Body)
		closeError := response.Body.Close()
		if response.StatusCode != wantHTTP || readError != nil || closeError != nil {
			t.Errorf("HTTP failure = status %d (want %d) read %v close %v", response.StatusCode, wantHTTP, readError, closeError)
		}
	}
	if !tcpDialErrorOwnershipWait(t, handlerDone, "failed request handler") || !tcpDialErrorOwnershipWait(t, dialDone, "completed custom dial") {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := tracker.wait(ctx); err != nil {
		t.Fatal("failed request retained its downstream slot: ", err)
	}
	if err := shutdown(ctx); err != nil {
		if !tcpDialErrorOwnershipOnlyClosed(err) {
			t.Fatal("shutdown after failed request: ", err)
		}
		t.Logf("accepted existing duplicate-listener-close Shutdown result: %v", err)
	}
	if !tcpDialErrorOwnershipWait(t, serveDone, "frontend after Shutdown") {
		return
	}
	if serveError != nil {
		t.Fatal(serveError)
	}
	select {
	case upstream = <-returned:
	case <-time.After(time.Second):
		t.Fatal("custom dialer did not return its created TCP socket")
	}
	if got := upstream.closeCalls.Load(); got != 1 {
		t.Errorf("frontend closed returned failed socket %d times, want exactly once", got)
	}
	peer, err = originListener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	n, readError := peer.Read(make([]byte, 1))
	if n != 0 || !errors.Is(readError, io.EOF) {
		t.Errorf("failed returned TCP socket remained open after handler/Shutdown: %d/%v", n, readError)
	}
	// Independently closing the actual endpoint must yield EOF, even on a
	// regressed build. It leaves the wrapper's ownership call count untouched.
	_ = upstream.Conn.Close()
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, readError = peer.Read(make([]byte, 1))
	if n != 0 || !errors.Is(readError, io.EOF) {
		t.Errorf("explicit TCP cleanup did not yield peer EOF: %d/%v", n, readError)
	}
}

func TestHTTPDialErrorOwnershipPreservesOriginalError(t *testing.T) {
	for _, setupError := range []error{errors.New("setup failed"), &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}} {
		t.Run(setupError.Error(), func(t *testing.T) {
			local, peer := net.Pipe()
			t.Cleanup(func() { _ = local.Close(); _ = peer.Close() })
			owned := &tcpDialErrorOwnedConn{Conn: local, closeError: errors.New("close failed")}
			server, err := NewHTTPServer(Config{Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
				return owned, setupError
			})})
			if err != nil {
				t.Fatal(err)
			}
			conn, gotError := server.dialContext(context.Background(), "tcp", "unused.invalid:443")
			if conn != nil || gotError != setupError {
				t.Errorf("failed dial = %T/%v, want nil and original error object %v", conn, gotError, setupError)
			}
			if got := owned.closeCalls.Load(); got != 1 {
				t.Errorf("failed pipe close count = %d, want exactly once", got)
			}
			if err := peer.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err == nil {
				n, err := peer.Read(make([]byte, 1))
				if n != 0 || !errors.Is(err, io.EOF) {
					t.Errorf("failed pipe remained open: %d/%v", n, err)
				}
			} else if !errors.Is(err, io.ErrClosedPipe) {
				t.Errorf("closed peer deadline: %v", err)
			}
		})
	}
}

func TestHTTPDialErrorOwnershipRejectsNilSuccess(t *testing.T) {
	server, err := NewHTTPServer(Config{Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := server.dialContext(context.Background(), "tcp", "unused.invalid:443")
	if conn != nil || err == nil {
		t.Errorf("nil-success dial = %T/%v, want nil connection and error", conn, err)
	}
}
