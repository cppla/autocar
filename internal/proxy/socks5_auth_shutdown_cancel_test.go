package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

func TestSOCKS5ForcedShutdownCancelsAuthentication(t *testing.T) {
	entered := make(chan context.Context, 1)
	authDone := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	var dialCalls atomic.Int64
	server, err := NewSOCKS5Server(Config{
		Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
			dialCalls.Add(1)
			return nil, errors.New("authentication must finish before dialing")
		}),
		HandshakeTimeout: time.Hour,
		Authenticator: AuthFunc(func(ctx context.Context, _, _ string) bool {
			defer close(authDone)
			entered <- ctx
			select {
			case <-ctx.Done():
			case <-release: // Independent cleanup only, never evidence of cancellation.
			}
			return false
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	managed, err := server.lifecycle.manage(listener)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	accepted := make(chan error, 1)
	handlerDone := make(chan struct{})
	var client net.Conn
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		if client != nil {
			_ = client.Close()
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = server.Shutdown(ctx)
		select {
		case <-handlerDone:
			t.Log("independent cleanup joined the production authentication handler")
		case <-time.After(2 * time.Second):
			t.Error("authentication handler did not finish after independent cleanup")
		}
	})
	// Keep the production connection tracking and serveConn implementation;
	// expose only the worker's completion so socket closure cannot mask it.
	go func() {
		defer close(handlerDone)
		conn, err := managed.Accept()
		accepted <- err
		if err == nil {
			server.serveConn(conn)
		}
	}()
	client = dialTCP(t, listener.Addr().String())
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("managed listener did not accept the authentication client")
	}
	socksGreeting(t, client, []byte{socksMethodUserPassword})
	mustWrite(t, client, []byte{userPasswordVersion, 1, 'u', 1, 'p'})
	var authCtx context.Context
	select {
	case authCtx = <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("production negotiation did not enter the authenticator")
	}
	if err := authCtx.Err(); err != nil {
		t.Fatalf("authentication was canceled before shutdown: %v", err)
	}

	shutdownCtx, cancel := context.WithCancel(context.Background())
	cancel() // Force the close path without a timer or a scheduling delay.
	shutdownErr := server.Shutdown(shutdownCtx)
	if !errors.Is(shutdownErr, context.Canceled) {
		t.Errorf("forced Shutdown = %v, want context canceled", shutdownErr)
	}
	server.lifecycle.tracker.mu.Lock()
	held := len(server.lifecycle.tracker.conns)
	server.lifecycle.tracker.mu.Unlock()
	if held != 0 {
		t.Errorf("forced Shutdown retained %d tracked connections", held)
	}
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	n, readErr := client.Read(one[:])
	if n != 0 || !errors.Is(readErr, io.EOF) {
		t.Errorf("client after forced Shutdown = %d/%v, want 0/EOF", n, readErr)
	}
	if dialCalls.Load() != 0 {
		t.Errorf("unfinished authentication made %d upstream dial calls", dialCalls.Load())
	}
	if err := authCtx.Err(); !errors.Is(err, context.Canceled) {
		// With neither ctx.Done nor cleanup release closed, the authenticator
		// cannot finish. This is a context ownership assertion, not a sleep.
		t.Errorf("forced Shutdown left authentication context live: %v; tracked=%d client=%d/%v", err, held, n, readErr)
		select {
		case <-authDone:
			t.Error("authenticator unexpectedly finished without cancellation or cleanup")
		default:
			t.Log("before independent cleanup: authenticator and serveConn are still blocked")
		}
		return
	}
	select {
	case <-handlerDone:
		t.Logf("forced Shutdown=%v; context canceled; tracker=%d; client EOF; authentication handler joined", shutdownErr, held)
	case <-time.After(2 * time.Second):
		t.Error("authentication handler did not finish after its context was canceled")
	}
}
