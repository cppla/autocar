package netbench

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

type benchmarkCloseCountConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *benchmarkCloseCountConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

func TestBenchmarkRunOwnsFailedDialResult(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		name := "live"
		if canceled {
			name = "canceled during dial"
		}
		t.Run(name, func(t *testing.T) {
			client, peer := net.Pipe()
			defer peer.Close()
			conn := &benchmarkCloseCountConn{Conn: client}
			defer client.Close() // Independent cleanup if Run loses ownership.
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cause := errors.New("selected dial failure")
			dialer := transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
				if canceled {
					cancel()
				}
				return conn, cause
			})
			result, err := Run(ctx, dialer, "unused", ModeDownload, 1)
			if err != cause || result != (Result{}) {
				t.Errorf("Run = %+v, %v; want zero result and original dial error", result, err)
			}
			if got := conn.closes.Load(); got != 1 {
				t.Errorf("failed dial result closed %d times, want 1", got)
			}
		})
	}
}

func TestBenchmarkRunRejectsNilDialResult(t *testing.T) {
	dialer := transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, nil
	})
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Errorf("nil dial result panicked: %v", recovered)
		}
	}()
	result, err := Run(context.Background(), dialer, "unused", ModeDownload, 1)
	if err == nil || result != (Result{}) {
		t.Errorf("Run = %+v, %v; want zero result and an error", result, err)
	}
}

func TestBenchmarkRunSkipsCanceledDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls atomic.Int32
	dialer := transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("dial should not be called")
	})
	result, err := Run(ctx, dialer, "unused", ModeDownload, 1)
	if !errors.Is(err, context.Canceled) || result != (Result{}) {
		t.Errorf("Run = %+v, %v; want zero result and context cancellation", result, err)
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("already canceled context made %d dial calls", got)
	}
}

func TestBenchmarkRunOwnsLateSuccessfulDial(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	conn := &benchmarkCloseCountConn{Conn: client}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	cause := errors.New("selected cancellation cause")
	dialer := transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
		cancel(cause)
		return conn, nil
	})
	result, err := Run(ctx, dialer, "unused", ModeDownload, 1)
	if err != cause || result != (Result{}) {
		t.Errorf("Run = %+v, %v; want zero result and original cancellation cause", result, err)
	}
	if got := conn.closes.Load(); got != 1 {
		t.Errorf("late dial result closed %d times, want 1", got)
	}
}

type benchmarkJoinedCloseConn struct {
	net.Conn
	readStarted   chan struct{}
	readExited    chan struct{}
	closeStarted  chan struct{}
	closeFinished chan struct{}
	releaseClose  chan struct{}
	closes        atomic.Int32
}

func (c *benchmarkJoinedCloseConn) Read(p []byte) (int, error) {
	close(c.readStarted)
	n, err := c.Conn.Read(p)
	close(c.readExited)
	return n, err
}

func (c *benchmarkJoinedCloseConn) Close() error {
	c.closes.Add(1)
	err := c.Conn.Close()
	close(c.closeStarted)
	<-c.releaseClose
	close(c.closeFinished)
	return err
}

func TestBenchmarkRunJoinsCancellationClose(t *testing.T) {
	client, peer := net.Pipe()
	conn := &benchmarkJoinedCloseConn{
		Conn: client, readStarted: make(chan struct{}), readExited: make(chan struct{}),
		closeStarted: make(chan struct{}), closeFinished: make(chan struct{}), releaseClose: make(chan struct{}),
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	cause := errors.New("selected transfer cancellation cause")
	var release sync.Once
	peerDone, runDone := make(chan struct{}), make(chan struct{})
	peerResult, runResult := make(chan error, 1), make(chan error, 1)
	t.Cleanup(func() {
		cancel(nil)
		_ = client.Close()
		_ = peer.Close()
		release.Do(func() { close(conn.releaseClose) })
		benchmarkCancelJoin(t, runDone, "joined-close Run cleanup")
		benchmarkCancelJoin(t, peerDone, "joined-close peer cleanup")
	})
	go func() {
		defer close(peerDone)
		header := make([]byte, headerSize)
		_, err := io.ReadFull(peer, header)
		peerResult <- err
	}()
	dialer := transport.DialFunc(func(context.Context, string, string) (net.Conn, error) { return conn, nil })
	go func() {
		defer close(runDone)
		result, err := Run(ctx, dialer, "unused", ModeDownload, 1)
		if result != (Result{}) {
			t.Errorf("canceled transfer reported a result: %+v", result)
		}
		runResult <- err
	}()
	benchmarkCancelWaitPhase(t, conn.readStarted, "actual download Read")
	benchmarkCancelJoin(t, peerDone, "complete header peer")
	if err := <-peerResult; err != nil {
		t.Fatal(err)
	}
	cancel(cause)
	benchmarkCancelWaitPhase(t, conn.closeStarted, "cancellation Close entry")
	benchmarkCancelWaitPhase(t, conn.readExited, "interrupted download Read return")
	select {
	case <-runDone:
		t.Error("Run returned before its cancellation Close completed")
	default:
	}
	release.Do(func() { close(conn.releaseClose) })
	benchmarkCancelWaitPhase(t, runDone, "Run after Close completion")
	if err := <-runResult; err != cause {
		t.Errorf("Run cancellation = %v, want original cause", err)
	}
	select {
	case <-conn.closeFinished:
	default:
		t.Error("Run returned without joining Close")
	}
	if got := conn.closes.Load(); got != 1 {
		t.Errorf("cancellation closed the connection %d times, want 1", got)
	}
}

func TestBenchmarkRunSkipsExpiredDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	var calls atomic.Int32
	dialer := transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("dial should not be called")
	})
	result, err := Run(ctx, dialer, "unused", ModeDownload, 1)
	if !errors.Is(err, context.DeadlineExceeded) || result != (Result{}) || calls.Load() != 0 {
		t.Errorf("expired deadline Run = %+v, %v, %d dial calls", result, err, calls.Load())
	}
}
