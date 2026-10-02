package proxy

import (
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

type shutdownCloseResultEvent struct {
	phase    int64
	raw      error
	returned error
}

type shutdownCloseResultInjection struct {
	phase     int64
	other     error
	wrapped   bool
	preclosed bool
}

// Accept gates only the return of the real closed-listener error until the
// second real Close. Thus net/http still owns a registered managed listener
// when Shutdown closes it, independently of the scheduler. The ordinary case
// never manufactures a Close error. Error controls explicitly add a separate
// fixture sentinel to the actual raw Close result at exactly one phase.
type shutdownCloseResultListener struct {
	*net.TCPListener
	injection      shutdownCloseResultInjection
	acceptStarted  chan struct{}
	rawAcceptDone  chan struct{}
	acceptReturned chan struct{}
	secondClose    chan struct{}
	releaseAccept  chan struct{}
	startOnce      sync.Once
	releaseOnce    sync.Once
	closeCalls     atomic.Int64
	mu             sync.Mutex
	closes         []shutdownCloseResultEvent
	acceptErr      error
}

func (l *shutdownCloseResultListener) Accept() (net.Conn, error) {
	l.startOnce.Do(func() { close(l.acceptStarted) })
	conn, err := l.TCPListener.Accept()
	l.mu.Lock()
	l.acceptErr = err
	l.mu.Unlock()
	close(l.rawAcceptDone)
	if conn == nil && errors.Is(err, net.ErrClosed) {
		<-l.releaseAccept
	}
	close(l.acceptReturned)
	return conn, err
}

func (l *shutdownCloseResultListener) Close() error {
	phase := l.closeCalls.Add(1)
	rawErr := l.TCPListener.Close()
	err := rawErr
	if phase == l.injection.phase {
		err = errors.Join(rawErr, l.injection.other)
		if l.injection.wrapped {
			err = fmt.Errorf("fixture listener close phase %d: %w", phase, err)
		}
	}
	l.mu.Lock()
	l.closes = append(l.closes, shutdownCloseResultEvent{phase: phase, raw: rawErr, returned: err})
	l.mu.Unlock()
	if phase == 2 {
		close(l.secondClose)
		l.release()
	}
	return err
}

func (l *shutdownCloseResultListener) release() {
	l.releaseOnce.Do(func() { close(l.releaseAccept) })
}

func TestHTTPIdleShutdownIgnoresRealDuplicateListenerClose(t *testing.T) {
	err, _ := shutdownCloseResultExercise(t, shutdownCloseResultInjection{})
	if err != nil {
		t.Errorf("clean idle Shutdown = %v, want nil", err)
	}
}

func TestHTTPShutdownPreservesOtherListenerCloseErrors(t *testing.T) {
	for phase, name := range []string{"initial", "http", "final_lifecycle"} {
		for _, wrapped := range []bool{false, true} {
			form := "joined"
			if wrapped {
				form = "wrapped"
			}
			t.Run(name+"/"+form, func(t *testing.T) {
				other := errors.New("fixture " + name + " listener close failure")
				injection := shutdownCloseResultInjection{
					phase: int64(phase + 1), other: other, wrapped: wrapped,
					// An independently preclosed raw endpoint makes the first
					// phase's real Close return net.ErrClosed too. This case
					// proves a joined other error must not be swallowed by an
					// any-match closed-error check. The wrapped first-phase
					// control instead preserves a genuinely non-closed error.
					preclosed: phase == 0 && !wrapped,
				}
				err, events := shutdownCloseResultExercise(t, injection)
				if !errors.Is(err, other) {
					t.Errorf("Shutdown = %v, want original other-error identity %v", err, other)
				}
				for _, event := range events {
					if event.phase != injection.phase {
						continue
					}
					if !errors.Is(err, event.returned) {
						t.Errorf("Shutdown lost selected Close error identity: %v / %v", err, event.returned)
					}
					if errors.Is(err, net.ErrClosed) != errors.Is(event.returned, net.ErrClosed) {
						t.Errorf("Shutdown closed-error membership = %v, want selected error membership %v", errors.Is(err, net.ErrClosed), errors.Is(event.returned, net.ErrClosed))
					}
					if event.raw != nil && !errors.Is(event.returned, event.raw) {
						t.Errorf("fixture control lost its actual raw Close error: %v / %v", event.returned, event.raw)
					}
				}
			})
		}
	}
}

// This is a direct production lifecycle control, not an HTTP handler fixture.
// A genuine listener-close error must survive alongside the caller deadline
// without bypassing forced closure of the already accepted tracked TCP socket.
func TestLifecycleShutdownCloseErrorStillForcesTrackedTCP(t *testing.T) {
	for _, preclosed := range []bool{true, false} {
		name := "closed_and_other"
		if !preclosed {
			name = "other_only"
		}
		t.Run(name, func(t *testing.T) {
			shutdownCloseResultForcedTCP(t, preclosed)
		})
	}
}

func shutdownCloseResultForcedTCP(t *testing.T, preclosed bool) {
	t.Helper()
	raw, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	other := errors.New("fixture lifecycle listener close failure")
	listener := &shutdownCloseResultListener{
		TCPListener: raw, injection: shutdownCloseResultInjection{phase: 1, other: other},
		acceptStarted: make(chan struct{}), rawAcceptDone: make(chan struct{}),
		acceptReturned: make(chan struct{}), secondClose: make(chan struct{}), releaseAccept: make(chan struct{}),
	}
	lifecycle := newServerLifecycle(1)
	managed, err := lifecycle.manage(listener)
	if err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	acceptExited := make(chan struct{})
	go func() {
		defer close(acceptExited)
		conn, err := managed.Accept()
		accepted <- acceptResult{conn, err}
	}()
	var client *net.TCPConn
	var tracked *trackedConn
	ctx := context.Background()
	cancel := func() {}
	shutdownResult := make(chan error, 1)
	shutdownExited := make(chan struct{})
	shutdownStarted := false
	t.Cleanup(func() {
		listener.release()
		_ = raw.Close()
		cancel()
		if tracked != nil {
			_ = tracked.Close()
			cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), time.Second)
			if err := lifecycle.tracker.wait(cleanupCtx); err != nil {
				t.Errorf("independent tracked TCP cleanup retained a socket: %v", err)
			}
			cancelCleanup()
		}
		if client != nil {
			_ = client.Close()
		}
		shutdownCloseResultWait(t, acceptExited, "tracked TCP Accept cleanup")
		select {
		case result := <-accepted:
			if result.conn != nil {
				_ = result.conn.Close()
			}
		default:
		}
		if shutdownStarted {
			shutdownCloseResultWait(t, shutdownExited, "lifecycle Shutdown cleanup")
		}
	})
	client, err = net.DialTCP("tcp", nil, raw.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	if !shutdownCloseResultWait(t, acceptExited, "tracked TCP Accept") {
		t.Fatal("managed Accept did not complete")
	}
	result := <-accepted
	if result.err != nil {
		t.Fatal(result.err)
	}
	var ok bool
	tracked, ok = result.conn.(*trackedConn)
	if !ok {
		_ = result.conn.Close()
		t.Fatalf("managed Accept result = %T, want trackedConn", result.conn)
	}
	connectionCtx := tracked.connectionContext(context.Background())
	if err := connectionCtx.Err(); err != nil {
		t.Fatalf("tracked socket context canceled before Shutdown: %v", err)
	}
	if preclosed {
		// Closing only the listener keeps the accepted socket alive, but
		// makes the lifecycle raw Close yield net.ErrClosed plus other.
		if err := raw.Close(); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel = context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	shutdownStarted = true
	go func() {
		defer close(shutdownExited)
		shutdownResult <- lifecycle.shutdown(ctx)
	}()
	if !shutdownCloseResultWait(t, shutdownExited, "lifecycle forced Shutdown") {
		t.Fatal("lifecycle Shutdown did not return")
	}
	shutdownErr := <-shutdownResult
	if !errors.Is(shutdownErr, other) || !errors.Is(shutdownErr, context.DeadlineExceeded) {
		t.Errorf("forced lifecycle Shutdown = %v, want both original close-error identity and caller deadline", shutdownErr)
	}
	if !errors.Is(connectionCtx.Err(), context.Canceled) {
		t.Errorf("forced tracked socket context = %v, want canceled", connectionCtx.Err())
	}
	lifecycle.tracker.mu.Lock()
	held := len(lifecycle.tracker.conns)
	lifecycle.tracker.mu.Unlock()
	if held != 0 {
		t.Errorf("forced lifecycle retained %d tracked sockets", held)
	}
	if err := client.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	n, readErr := client.Read(b[:])
	if n != 0 || !errors.Is(readErr, io.EOF) {
		t.Errorf("client after forced Shutdown = %d/%v, want real TCP EOF before cleanup", n, readErr)
	}
	listener.mu.Lock()
	events := append([]shutdownCloseResultEvent(nil), listener.closes...)
	listener.mu.Unlock()
	if len(events) != 1 || !errors.Is(events[0].returned, other) || !errors.Is(shutdownErr, events[0].returned) {
		t.Errorf("forced Close observation = %+v, want one original other error retained in Shutdown", events)
	}
	if len(events) == 1 {
		if preclosed && !errors.Is(events[0].raw, net.ErrClosed) {
			t.Errorf("preclosed raw Close = %v, want net.ErrClosed", events[0].raw)
		}
		if !preclosed && events[0].raw != nil {
			t.Errorf("first raw Close = %v, want nil before adding other-only error", events[0].raw)
		}
	}
	t.Logf("direct lifecycle preclosed=%v: Shutdown=%v; tracked context=%v; slots=%d; peer=%d/%v; Accept/Shutdown joined", preclosed, shutdownErr, connectionCtx.Err(), held, n, readErr)
}

func shutdownCloseResultExercise(t *testing.T, injection shutdownCloseResultInjection) (error, []shutdownCloseResultEvent) {
	t.Helper()
	raw, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	listener := &shutdownCloseResultListener{
		TCPListener: raw, injection: injection,
		acceptStarted: make(chan struct{}), rawAcceptDone: make(chan struct{}),
		acceptReturned: make(chan struct{}), secondClose: make(chan struct{}), releaseAccept: make(chan struct{}),
	}
	var dialCalls, handlerCalls atomic.Int64
	server, err := NewHTTPServer(Config{Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
		dialCalls.Add(1)
		return nil, errors.New("unused fixture destination")
	})})
	if err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	server.server.Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) { handlerCalls.Add(1) })
	serveResult := make(chan error, 1)
	serveExited := make(chan struct{})
	go func() {
		defer close(serveExited)
		serveResult <- server.Serve(listener)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	shutdownResult := make(chan error, 1)
	shutdownExited := make(chan struct{})
	shutdownStarted := false
	t.Cleanup(func() {
		// This independent release also works if production never performs
		// its second Close, keeping every failure/negative control joinable.
		listener.release()
		_ = raw.Close()
		cancel()
		if shutdownStarted {
			shutdownCloseResultWait(t, shutdownExited, "Shutdown cleanup")
		}
		shutdownCloseResultWait(t, serveExited, "Serve cleanup")
		if closeErr := server.server.Close(); closeErr != nil {
			t.Errorf("net/http final cleanup: %v", closeErr)
		}
	})
	if server.cfg.handshakeTimeout != defaultHandshakeTimeout || server.cfg.dialTimeout != defaultDialTimeout || server.cfg.idleTimeout != defaultIdleTimeout {
		t.Fatal("listener close fixture changed production default budgets")
	}
	if !shutdownCloseResultWait(t, listener.acceptStarted, "registered listener Accept entry") {
		t.Fatal("Serve did not enter Accept")
	}
	shutdownCloseResultAssertEmpty(t, server, &dialCalls, &handlerCalls)
	if injection.preclosed {
		// Separate fixture preparation, not a counted production Close or
		// synthetic raw error: Accept now really sees a closed TCP listener.
		if err := raw.Close(); err != nil {
			t.Fatal(err)
		}
		if !shutdownCloseResultWait(t, listener.rawAcceptDone, "preclosed real Accept") {
			t.Fatal("preclosed Accept did not return")
		}
	}
	shutdownStarted = true
	go func() {
		defer close(shutdownExited)
		shutdownResult <- server.Shutdown(ctx)
	}()
	if !shutdownCloseResultWait(t, listener.rawAcceptDone, "real Accept returning closed") ||
		!shutdownCloseResultWait(t, listener.secondClose, "second real listener Close") ||
		!shutdownCloseResultWait(t, listener.acceptReturned, "Accept gate return") ||
		!shutdownCloseResultWait(t, shutdownExited, "Shutdown return") ||
		!shutdownCloseResultWait(t, serveExited, "Serve return") {
		t.Fatal("idle shutdown fixture did not complete")
	}
	shutdownErr := <-shutdownResult
	if serveErr := <-serveResult; serveErr != nil {
		t.Errorf("Serve = %v, want nil", serveErr)
	}
	if err := ctx.Err(); err != nil {
		t.Errorf("Shutdown context is not live: %v", err)
	}
	if errors.Is(shutdownErr, context.DeadlineExceeded) || errors.Is(shutdownErr, context.Canceled) {
		t.Errorf("idle Shutdown contains an unexpected context failure: %v", shutdownErr)
	}
	listener.mu.Lock()
	events := append([]shutdownCloseResultEvent(nil), listener.closes...)
	acceptErr := listener.acceptErr
	listener.mu.Unlock()
	if !errors.Is(acceptErr, net.ErrClosed) {
		t.Errorf("underlying Accept error = %v, want real net.ErrClosed", acceptErr)
	}
	if len(events) != 3 || listener.closeCalls.Load() != 3 {
		t.Errorf("Close events=%+v/count %d, want three production phases", events, listener.closeCalls.Load())
	}
	for _, event := range events {
		if event.phase == 1 && !injection.preclosed {
			if event.raw != nil {
				t.Errorf("first actual Close = %v, want nil", event.raw)
			}
		} else if !errors.Is(event.raw, net.ErrClosed) {
			t.Errorf("duplicate actual Close phase %d = %v, want net.ErrClosed", event.phase, event.raw)
		}
		if event.phase != injection.phase && event.raw != event.returned {
			t.Errorf("non-injected phase %d changed the real Close result", event.phase)
		}
		t.Logf("Close phase %d: actual=%v; returned=%v", event.phase, event.raw, event.returned)
	}
	shutdownCloseResultAssertEmpty(t, server, &dialCalls, &handlerCalls)
	t.Logf("Shutdown=%v; context live; Accept/Serve/Shutdown joined; connections/handlers/dials all zero", shutdownErr)
	return shutdownErr, events
}

func shutdownCloseResultWait(t *testing.T, done <-chan struct{}, label string) bool {
	t.Helper()
	select {
	case <-done:
		return true
	case <-time.After(time.Second):
		t.Errorf("%s did not join/complete", label)
		return false
	}
}

func shutdownCloseResultAssertEmpty(t *testing.T, server *HTTPServer, dials, handlers *atomic.Int64) {
	t.Helper()
	server.lifecycle.tracker.mu.Lock()
	held := len(server.lifecycle.tracker.conns)
	server.lifecycle.tracker.mu.Unlock()
	if held != 0 || dials.Load() != 0 || handlers.Load() != 0 {
		t.Errorf("idle held=%d/dials=%d/handlers=%d, want all zero", held, dials.Load(), handlers.Load())
	}
}
