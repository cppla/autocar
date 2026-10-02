package netbench

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Only the second Accept error is synthetic. The first accepted socket and
// every Close below are real loopback TCP operations with their original result.
type benchmarkErrorListener struct {
	net.Listener
	failure       error
	accepted      chan *benchmarkCancelServerConn
	secondAccept  chan struct{}
	releaseAccept chan struct{}
	acceptCalls   atomic.Int32
	closeCalls    atomic.Int32
	mu            sync.Mutex
	closed        bool
	conn          net.Conn
}

func (l *benchmarkErrorListener) Accept() (net.Conn, error) {
	if l.acceptCalls.Add(1) != 1 {
		close(l.secondAccept)
		<-l.releaseAccept
		return nil, l.failure
	}
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	conn := &benchmarkCancelServerConn{
		Conn: raw, readStarted: make(chan struct{}), uploadStarted: make(chan struct{}),
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		_ = raw.Close()
		return nil, net.ErrClosed
	}
	l.conn = conn
	l.mu.Unlock()
	l.accepted <- conn // Exactly one accepted connection; channel capacity is one.
	return conn, nil
}

func (l *benchmarkErrorListener) Close() error {
	l.closeCalls.Add(1)
	return l.Listener.Close()
}

func (l *benchmarkErrorListener) forceCloseConn() {
	l.mu.Lock()
	l.closed = true
	conn := l.conn
	l.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func TestBenchmarkServerAcceptErrorOwnsListenerAndWorker(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("controlled second Accept failure")
	ln := &benchmarkErrorListener{
		Listener: raw, failure: failure, accepted: make(chan *benchmarkCancelServerConn, 1),
		secondAccept: make(chan struct{}), releaseAccept: make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	result := make(chan error, 1)
	var releaseOnce sync.Once
	var peer net.Conn
	t.Cleanup(func() {
		// Bypass the observed wrapper for independent listener cleanup; its
		// Close counter measures production ownership only.
		cancel()
		_ = raw.Close()
		ln.forceCloseConn()
		if peer != nil {
			_ = peer.Close()
		}
		releaseOnce.Do(func() { close(ln.releaseAccept) })
		benchmarkCancelJoin(t, done, "Accept-error Serve cleanup")
	})
	go func() {
		defer close(done)
		result <- (&Server{MaxConnections: 1}).Serve(ctx, ln)
	}()
	peer, err = (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var conn *benchmarkCancelServerConn
	select {
	case conn = <-ln.accepted:
	case <-time.After(benchmarkCancelJoinBudget):
		t.Fatal("real TCP socket was not accepted")
	}
	benchmarkCancelWaitPhase(t, conn.readStarted, "active real header Read")
	benchmarkCancelWaitPhase(t, ln.secondAccept, "controlled second Accept")
	releaseOnce.Do(func() { close(ln.releaseAccept) })
	benchmarkCancelRequirePeerClosed(t, peer, "Accept-error worker TCP socket")
	select {
	case <-done:
		if got := <-result; got != failure {
			t.Errorf("Serve changed original Accept error identity: got %v, want %v", got, failure)
		}
	case <-time.After(benchmarkCancelReturnBudget):
		t.Error("Serve did not join its active worker after Accept failure")
	}
	if got := ln.closeCalls.Load(); got != 1 {
		t.Errorf("production listener Close calls = %d, want exactly one before cleanup", got)
	}
	if ctx.Err() != nil {
		t.Errorf("Serve canceled its caller-owned parent context: %v", ctx.Err())
	}
}
