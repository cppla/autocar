package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func trackedContextPipe(t *testing.T) (*trackedConn, net.Conn) {
	t.Helper()
	local, peer := net.Pipe()
	tracker := newConnTracker(1)
	tracked := &trackedConn{Conn: local, tracker: tracker}
	if !tracker.add(tracked) {
		t.Fatal("could not register pipe")
	}
	t.Cleanup(func() {
		_ = peer.Close()
		_ = tracked.Close()
	})
	return tracked, peer
}

func TestTrackedConnectionContextCloseBeforeOrAfterBinding(t *testing.T) {
	for _, closeBeforeBinding := range []bool{false, true} {
		name := "bind-then-close"
		if closeBeforeBinding {
			name = "close-then-bind"
		}
		t.Run(name, func(t *testing.T) {
			tracked, _ := trackedContextPipe(t)
			type valueKey struct{}
			parent := context.WithValue(context.Background(), valueKey{}, "parent-value")
			if closeBeforeBinding {
				if err := tracked.Close(); err != nil {
					t.Fatal(err)
				}
			}
			ctx := tracked.connectionContext(parent)
			if got := ctx.Value(valueKey{}); got != "parent-value" {
				t.Fatalf("connection context value = %v", got)
			}
			if !closeBeforeBinding {
				if err := ctx.Err(); err != nil {
					t.Fatalf("open connection context is canceled: %v", err)
				}
				if err := tracked.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatalf("closed connection context error = %v", ctx.Err())
			}
			if err := parent.Err(); err != nil {
				t.Fatalf("closing one connection canceled its parent: %v", err)
			}
			select {
			case <-tracked.tracker.zero:
			default:
				t.Fatal("closed connection kept its tracker slot")
			}
			if err := tracked.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTrackedConnectionContextConcurrentBindAndClose(t *testing.T) {
	for range 100 {
		tracked, _ := trackedContextPipe(t)
		parent, cancelParent := context.WithCancel(context.Background())
		start := make(chan struct{})
		bound := make(chan context.Context, 1)
		closed := make(chan error, 1)
		go func() {
			<-start
			bound <- tracked.connectionContext(parent)
		}()
		go func() {
			<-start
			closed <- tracked.Close()
		}()
		close(start)
		ctx := <-bound
		err := <-closed
		// Both workers are joined before any assertion can exit this test.
		parentErr := parent.Err()
		connectionErr := ctx.Err()
		cancelParent()
		if err != nil {
			t.Fatal(err)
		}
		if parentErr != nil {
			t.Fatalf("connection close canceled parent: %v", parentErr)
		}
		if !errors.Is(connectionErr, context.Canceled) {
			t.Fatalf("concurrent close missed cancellation: %v", connectionErr)
		}
		select {
		case <-tracked.tracker.zero:
		default:
			t.Fatal("concurrent close kept its tracker slot")
		}
	}
}

func TestTrackedConnectionContextParentCancellationKeepsSocketOpen(t *testing.T) {
	tracked, peer := trackedContextPipe(t)
	parent, cancelParent := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancelParent(nil) })
	ctx := tracked.connectionContext(parent)
	parentCause := errors.New("parent canceled")
	cancelParent(parentCause)
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("parent cancellation did not reach connection: %v", ctx.Err())
	}
	if !errors.Is(context.Cause(ctx), parentCause) {
		t.Fatalf("connection context lost parent cancellation cause: %v", context.Cause(ctx))
	}
	select {
	case <-tracked.tracker.zero:
		t.Fatal("context cancellation released a still-open socket")
	default:
	}
	if err := tracked.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	wrote := make(chan error, 1)
	go func() {
		_, err := peer.Write([]byte("socket-still-open"))
		wrote <- err
	}()
	body := make([]byte, len("socket-still-open"))
	_, readErr := io.ReadFull(tracked, body)
	writeErr := <-wrote
	if readErr != nil || writeErr != nil || string(body) != "socket-still-open" {
		t.Fatalf("socket after context cancellation: body=%q read=%v write=%v", body, readErr, writeErr)
	}
}

func TestTrackedConnectionContextCancellationPrecedesTrackerRelease(t *testing.T) {
	tracked, _ := trackedContextPipe(t)
	ctx := tracked.connectionContext(context.Background())
	cancelStarted := make(chan struct{})
	releaseCancel := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseCancel) }) }
	t.Cleanup(release)
	cancelResult := make(chan error, 1)
	// Instrument the registered cancellation callback so the ordering check is
	// deterministic even if tracker removal and cancellation are adjacent.
	// Registration is complete and no worker has started yet.
	originalCancel := tracked.connectionCancel
	tracked.connectionCancel = func() {
		var err error
		if !tracked.closeMu.TryLock() {
			err = errors.New("context canceled under connection close mutex")
		} else {
			tracked.closeMu.Unlock()
		}
		if !tracked.tracker.mu.TryLock() {
			err = errors.Join(err, errors.New("context canceled under tracker mutex"))
		} else {
			tracked.tracker.mu.Unlock()
		}
		cancelResult <- err
		close(cancelStarted)
		<-releaseCancel
		originalCancel()
	}
	closed := make(chan error, 1)
	go func() { closed <- tracked.Close() }()
	cancelObserved, closeObserved := false, false
	var closeErr error
	select {
	case <-cancelStarted:
		cancelObserved = true
	case closeErr = <-closed:
		closeObserved = true
	case <-time.After(2 * time.Second):
	}
	releasedEarly := false
	select {
	case <-tracked.tracker.zero:
		releasedEarly = true
	default:
	}
	var cancelErr error
	if cancelObserved {
		cancelErr = <-cancelResult
	}
	release()
	if !closeObserved {
		select {
		case closeErr = <-closed:
		case <-time.After(2 * time.Second):
			t.Fatal("Close worker did not finish after releasing cancellation callback")
		}
	}
	// The callback and Close worker are joined before assertions/cleanup.
	if !cancelObserved {
		t.Fatal("Close did not invoke the registered context cancellation callback")
	}
	if cancelErr != nil {
		t.Fatal(cancelErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if releasedEarly {
		t.Fatal("tracker reached zero before connection cancellation returned")
	}
	select {
	case <-tracked.tracker.zero:
	default:
		t.Fatal("tracker did not reach zero after close")
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("tracker reached zero with a live connection context: %v", ctx.Err())
	}
}

func TestTrackedConnectionContextCloseWriteKeepsContextAndReplyAlive(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	peer, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	local, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	tracker := newConnTracker(1)
	tracked := &trackedConn{Conn: local, tracker: tracker}
	t.Cleanup(func() { _ = tracked.Close() })
	if !tracker.add(tracked) {
		t.Fatal("could not register TCP connection")
	}
	ctx := tracked.connectionContext(context.Background())
	if err := tracked.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := tracked.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("TCP write half-close canceled connection context: %v", err)
	}
	select {
	case <-tracker.zero:
		t.Fatal("TCP write half-close released the connection slot")
	default:
	}
	if n, err := peer.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("peer read after write half-close = %d, %v", n, err)
	}
	const response = "response-after-half-close"
	if _, err := peer.Write([]byte(response)); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, len(response))
	if _, err := io.ReadFull(tracked, body); err != nil || string(body) != response {
		t.Fatalf("reply after half-close = %q, %v", body, err)
	}
	if err := tracked.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("full close after half-close did not cancel context: %v", ctx.Err())
	}
}
