package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

// The listener observes the standard library's one-byte background read. It
// never performs an additional read or changes deadlines, data, or errors.
type httpShutdownReadListener struct {
	net.Listener
	byteRead  chan struct{}
	closed    chan struct{}
	readOnce  sync.Once
	closeOnce sync.Once
}

func (l *httpShutdownReadListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &httpShutdownReadConn{Conn: conn, listener: l}, nil
}

func (l *httpShutdownReadListener) Close() error {
	err := l.Listener.Close()
	l.closeOnce.Do(func() { close(l.closed) })
	return err
}

type httpShutdownReadConn struct {
	net.Conn
	listener *httpShutdownReadListener
}

func (c *httpShutdownReadConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if len(p) == 1 && n == 1 {
		c.listener.readOnce.Do(func() { close(c.listener.byteRead) })
	}
	return n, err
}

type httpShutdownHarness struct {
	server         *HTTPServer
	client         net.Conn
	listener       *httpShutdownReadListener
	requestContext chan context.Context
	handlerDone    chan struct{}
	serveDone      chan error
}

func newHTTPShutdownHarness(t *testing.T, cfg Config) *httpShutdownHarness {
	t.Helper()
	server, err := NewHTTPServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &httpShutdownHarness{
		server:         server,
		listener:       &httpShutdownReadListener{Listener: listener, byteRead: make(chan struct{}), closed: make(chan struct{})},
		requestContext: make(chan context.Context, 1),
		handlerDone:    make(chan struct{}),
		serveDone:      make(chan error, 1),
	}
	var first sync.Once
	server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isFirst := false
		first.Do(func() {
			isFirst = true
			h.requestContext <- r.Context()
		})
		if isFirst {
			defer close(h.handlerDone)
		}
		server.ServeHTTP(w, r)
	})
	go func() { h.serveDone <- server.Serve(h.listener) }()
	t.Cleanup(func() {
		if h.client != nil {
			_ = h.client.Close()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		_ = h.server.Shutdown(ctx)
		cancel()
		select {
		case err := <-h.serveDone:
			if err != nil {
				t.Errorf("proxy Serve cleanup: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("proxy Serve cleanup did not finish")
		}
	})
	h.client, err = net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return h
}

func httpShutdownWait(t *testing.T, done <-chan struct{}, label string) bool {
	t.Helper()
	select {
	case <-done:
		return true
	case <-time.After(2 * time.Second):
		t.Errorf("%s did not finish", label)
		return false
	}
}

func httpShutdownRequestContext(t *testing.T, h *httpShutdownHarness) context.Context {
	t.Helper()
	select {
	case ctx := <-h.requestContext:
		return ctx
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not enter the request handler")
		return nil
	}
}

// Header receipt and cancellation are tested through real loopback TCP at both
// ends. With a pipelined byte already consumed, net/http has no background read
// left to observe a later forced close. Closing the tracked connection must
// still cancel the actual inbound context and the waiting upstream request.
func TestHTTPForcedShutdownCancelsWaitingResponse(t *testing.T) {
	for _, mode := range []string{"ordinary", "pipelined", "concurrent-pipelined"} {
		t.Run(mode, func(t *testing.T) {
			originEntered, originDone, originCanceled := make(chan struct{}), make(chan struct{}), make(chan struct{})
			release := make(chan struct{})
			var releaseOnce sync.Once
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/first" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				defer close(originDone)
				close(originEntered)
				select {
				case <-r.Context().Done():
					close(originCanceled)
				case <-release:
					w.WriteHeader(http.StatusNoContent)
				}
			}))
			h := newHTTPShutdownHarness(t, Config{Dialer: directDialer(), IdleTimeout: 10 * time.Second, MaxConnections: 1})
			// This cleanup runs before the harness cleanup and releases the origin
			// even if the cancellation assertion fails on a regressed build.
			t.Cleanup(func() {
				releaseOnce.Do(func() { close(release) })
				_ = h.client.Close()
				origin.CloseClientConnections()
				httpShutdownWait(t, h.handlerDone, "proxy handler cleanup")
				httpShutdownWait(t, originDone, "origin handler cleanup")
				origin.Close()
			})
			mustWrite(t, h.client, []byte(fmt.Sprintf("GET %s/first HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n", origin.URL)))
			requestCtx := httpShutdownRequestContext(t, h)
			if !httpShutdownWait(t, originEntered, "origin request") {
				return
			}
			if mode != "ordinary" {
				// Send only after the first request reaches the origin; otherwise
				// both requests could be buffered by the initial header read.
				mustWrite(t, h.client, []byte(fmt.Sprintf("GET %s/next HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n", origin.URL)))
				if !httpShutdownWait(t, h.listener.byteRead, "net/http pipelined-byte read") {
					return
				}
			}
			if err := requestCtx.Err(); err != nil {
				t.Fatalf("request was canceled before Shutdown: %v", err)
			}

			callers := 1
			if mode == "concurrent-pipelined" {
				callers = 3
			}
			start := make(chan struct{})
			results := make(chan error, callers)
			for range callers {
				go func() {
					<-start
					ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
					defer cancel()
					results <- h.server.Shutdown(ctx)
				}()
			}
			close(start)
			deadlineSeen := false
			for range callers {
				select {
				case err := <-results:
					if errors.Is(err, context.DeadlineExceeded) {
						deadlineSeen = true
					} else if err != nil {
						t.Errorf("forced Shutdown: %v", err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("concurrent Shutdown did not finish")
				}
			}
			if !deadlineSeen {
				t.Error("all Shutdown calls completed before their deadline despite the blocked request")
			}
			httpShutdownWait(t, requestCtx.Done(), "inbound request cancellation")
			httpShutdownWait(t, originCanceled, "waiting origin request cancellation")
			httpShutdownWait(t, h.handlerDone, "proxy handler after forced Shutdown")
			httpShutdownWait(t, originDone, "origin handler after forced Shutdown")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := h.server.lifecycle.tracker.wait(ctx); err != nil {
				t.Errorf("forced Shutdown retained an accepted connection slot: %v", err)
			}
			if err := h.server.Shutdown(ctx); err != nil {
				t.Errorf("repeated Shutdown after cleanup: %v", err)
			}
		})
	}
}

func TestHTTPGracefulShutdownPreservesActiveRequest(t *testing.T) {
	originEntered, originDone := make(chan struct{}), make(chan struct{})
	originContext := make(chan context.Context, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(originDone)
		originContext <- r.Context()
		close(originEntered)
		select {
		case <-r.Context().Done():
			return
		case <-release:
			_, _ = io.WriteString(w, "completed during graceful shutdown")
		}
	}))
	h := newHTTPShutdownHarness(t, Config{Dialer: directDialer(), IdleTimeout: 10 * time.Second})
	shutdownDone := make(chan error, 1)
	shutdownStarted := false
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		_ = h.client.Close()
		origin.CloseClientConnections()
		httpShutdownWait(t, h.handlerDone, "proxy handler cleanup")
		httpShutdownWait(t, originDone, "origin handler cleanup")
		origin.Close()
		if shutdownStarted {
			select {
			case <-shutdownDone:
			case <-time.After(4 * time.Second):
				t.Error("graceful Shutdown cleanup did not finish")
			}
		}
	})
	mustWrite(t, h.client, []byte(fmt.Sprintf("GET %s/ HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n", origin.URL)))
	requestCtx := httpShutdownRequestContext(t, h)
	if !httpShutdownWait(t, originEntered, "origin request") {
		return
	}
	originCtx := <-originContext
	shutdownStarted = true
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		shutdownDone <- h.server.Shutdown(ctx)
	}()
	if !httpShutdownWait(t, h.listener.closed, "listener close at Shutdown start") {
		return
	}
	select {
	case <-requestCtx.Done():
		t.Fatalf("graceful Shutdown canceled the active request: %v", requestCtx.Err())
	case <-originCtx.Done():
		t.Fatalf("graceful Shutdown canceled the origin request: %v", originCtx.Err())
	case err := <-shutdownDone:
		shutdownStarted = false
		t.Fatalf("Shutdown returned before origin release: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	response, err := http.ReadResponse(bufio.NewReader(h.client), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || string(body) != "completed during graceful shutdown" {
		t.Fatalf("graceful response = %d/%q, read=%v close=%v", response.StatusCode, body, readErr, closeErr)
	}
	httpShutdownWait(t, h.handlerDone, "completed proxy handler")
	httpShutdownWait(t, originDone, "completed origin handler")
	select {
	case err := <-shutdownDone:
		shutdownStarted = false
		if err != nil {
			t.Errorf("graceful Shutdown: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Error("graceful Shutdown did not finish after origin release")
	}
}

func TestHTTPForcedShutdownCancelsPendingConnect(t *testing.T) {
	dialEntered, dialDone := make(chan struct{}), make(chan struct{})
	dialContext := make(chan context.Context, 1)
	dialRelease := make(chan struct{})
	dialer := transport.DialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
		defer close(dialDone)
		dialContext <- ctx
		close(dialEntered)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-dialRelease:
			return nil, errors.New("test cleanup released pending CONNECT dial")
		}
	})
	h := newHTTPShutdownHarness(t, Config{Dialer: dialer, DialTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second})
	t.Cleanup(func() {
		// Force cleanup independently if an assertion fails before Shutdown.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = h.server.Shutdown(ctx)
		close(dialRelease)
		httpShutdownWait(t, dialDone, "CONNECT dial cleanup")
		httpShutdownWait(t, h.handlerDone, "CONNECT handler cleanup")
	})
	mustWrite(t, h.client, []byte("CONNECT 127.0.0.1:12345 HTTP/1.1\r\nHost: 127.0.0.1:12345\r\n\r\n"))
	requestCtx := httpShutdownRequestContext(t, h)
	if !httpShutdownWait(t, dialEntered, "CONNECT dial") {
		return
	}
	dialCtx := <-dialContext
	// Early tunnel bytes arrive while CONNECT is still awaiting its dial. The
	// passive observer only sees net/http's existing one-byte read; no new
	// reader is allowed to steal these bytes to obtain cancellation.
	mustWrite(t, h.client, []byte("early CONNECT payload"))
	if !httpShutdownWait(t, h.listener.byteRead, "net/http early CONNECT byte") {
		return
	}
	if err := requestCtx.Err(); err != nil {
		t.Fatalf("early CONNECT bytes canceled the request: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	err := h.server.Shutdown(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("forced Shutdown = %v, want deadline exceeded", err)
	}
	httpShutdownWait(t, requestCtx.Done(), "pending CONNECT request cancellation")
	httpShutdownWait(t, dialCtx.Done(), "pending CONNECT dial context cancellation")
	httpShutdownWait(t, dialDone, "pending CONNECT dial after forced Shutdown")
	httpShutdownWait(t, h.handlerDone, "pending CONNECT handler after forced Shutdown")
	if !errors.Is(requestCtx.Err(), context.Canceled) || !errors.Is(dialCtx.Err(), context.Canceled) {
		t.Errorf("CONNECT cancellation errors = request %v, dial %v", requestCtx.Err(), dialCtx.Err())
	}
	_ = h.client.SetReadDeadline(time.Now().Add(2 * time.Second))
	response, readErr := io.ReadAll(h.client)
	if strings.Contains(string(response), "200 Connection Established") {
		t.Errorf("forced canceled CONNECT reported success: %q", response)
	}
	if readErr != nil && !errors.Is(readErr, net.ErrClosed) {
		var netErr net.Error
		if errors.As(readErr, &netErr) && netErr.Timeout() {
			t.Errorf("downstream CONNECT connection remained open: %v", readErr)
		}
	}
}
