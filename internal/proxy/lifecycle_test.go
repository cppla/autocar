package proxy

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// An unexpected Accept returns immediately, so a shutdown regression fails
// without leaving a blocked server goroutine behind.
type lifecycleListener struct {
	accepts atomic.Int32
	closes  atomic.Int32
	onClose func()
}

func (l *lifecycleListener) Accept() (net.Conn, error) {
	l.accepts.Add(1)
	return nil, errors.New("unexpected accept after shutdown")
}

func (l *lifecycleListener) Close() error {
	l.closes.Add(1)
	if l.onClose != nil {
		l.onClose()
	}
	return nil
}

func (l *lifecycleListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}

func TestServerLifecycleConcurrentManageAndShutdown(t *testing.T) {
	for range 100 {
		lifecycle := newServerLifecycle(1)
		listener := &lifecycleListener{}
		start := make(chan struct{})
		managed := make(chan error, 1)
		stopped := make(chan error, 1)
		go func() {
			<-start
			_, err := lifecycle.manage(listener)
			managed <- err
		}()
		go func() {
			<-start
			stopped <- lifecycle.shutdown(context.Background())
		}()
		close(start)
		if err := <-managed; err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
		if err := <-stopped; err != nil {
			t.Fatal(err)
		}
		if listener.closes.Load() != 1 {
			t.Fatalf("listener close count = %d, want 1", listener.closes.Load())
		}
		lifecycle.tracker.mu.Lock()
		accepting := lifecycle.tracker.accepting
		lifecycle.tracker.mu.Unlock()
		if accepting {
			t.Fatal("tracker resumed accepting after shutdown")
		}
	}
}

func TestServerLifecycleDuplicateServeKeepsActiveListener(t *testing.T) {
	lifecycle := newServerLifecycle(1)
	first := &lifecycleListener{}
	if _, err := lifecycle.manage(first); err != nil {
		t.Fatal(err)
	}
	second := &lifecycleListener{}
	for _, duplicate := range []net.Listener{first, second} {
		if _, err := lifecycle.manage(duplicate); err == nil {
			t.Error("duplicate Serve was accepted")
		}
	}
	if first.closes.Load() != 0 || second.closes.Load() != 0 {
		t.Fatal("duplicate Serve closed a caller's listener")
	}
	if err := lifecycle.shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if first.closes.Load() != 1 || second.closes.Load() != 0 {
		t.Fatal("Shutdown did not close only the managed listener")
	}
}

func TestServerLifecycleClosesOutsideLocks(t *testing.T) {
	for _, shutdownFirst := range []bool{false, true} {
		lifecycle := newServerLifecycle(1)
		listener := &lifecycleListener{onClose: func() {
			if !lifecycle.mu.TryLock() {
				t.Error("listener.Close called under lifecycle mutex")
			} else {
				lifecycle.mu.Unlock()
			}
			if !lifecycle.tracker.mu.TryLock() {
				t.Error("listener.Close called under tracker mutex")
			} else {
				lifecycle.tracker.mu.Unlock()
			}
		}}
		if shutdownFirst {
			if err := lifecycle.shutdown(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		_, err := lifecycle.manage(listener)
		if shutdownFirst && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("late manage error = %v, want closed", err)
		}
		if !shutdownFirst && err != nil {
			t.Fatal(err)
		}
		if err := lifecycle.shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
		if listener.closes.Load() != 1 {
			t.Fatalf("listener close count = %d, want 1", listener.closes.Load())
		}
	}
}

func TestProxyShutdownBeforeServeClosesRealListener(t *testing.T) {
	for _, kind := range []string{"socks5", "http"} {
		t.Run(kind, func(t *testing.T) {
			cfg := Config{Dialer: directDialer()}
			var server Server
			var err error
			if kind == "socks5" {
				server, err = NewSOCKS5Server(cfg)
			} else {
				server, err = NewHTTPServer(cfg)
			}
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			if err := server.Shutdown(context.Background()); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- server.Serve(listener) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				_ = listener.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("Serve did not exit after cleanup")
				}
				t.Fatal("Serve blocked after Shutdown")
			}
			if err := listener.(*net.TCPListener).SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("listener still open after late Serve: %v", err)
			}
		})
	}
}

func TestProxyServeAfterShutdownClosesListener(t *testing.T) {
	for _, kind := range []string{"socks5", "http"} {
		t.Run(kind, func(t *testing.T) {
			var server Server
			var err error
			cfg := Config{Dialer: directDialer()}
			if kind == "socks5" {
				server, err = NewSOCKS5Server(cfg)
			} else {
				server, err = NewHTTPServer(cfg)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := server.Shutdown(context.Background()); err != nil {
				t.Fatal(err)
			}
			listener := &lifecycleListener{}
			if err := server.Serve(listener); err != nil {
				t.Errorf("Serve after Shutdown: %v", err)
			}
			if got := listener.accepts.Load(); got != 0 {
				t.Errorf("Accept called %d times after Shutdown", got)
			}
			if got := listener.closes.Load(); got == 0 {
				t.Error("late listener was not closed")
			}
		})
	}
}
