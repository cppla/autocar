package tunnel

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type webTCPOwnerObservedConn struct {
	net.Conn
	closes atomic.Int64
	check  func()
}

func (c *webTCPOwnerObservedConn) Close() error {
	c.closes.Add(1)
	if c.check != nil {
		c.check()
	}
	return c.Conn.Close()
}

func webTCPOwnerRealPair(t *testing.T) (*webTCPOwnerObservedConn, net.Conn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	peer, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	_ = listener.SetDeadline(time.Now().Add(time.Second))
	raw, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	return &webTCPOwnerObservedConn{Conn: raw}, peer
}

func TestWebTCPConnectionOwnerClosesOnceOutsideLock(t *testing.T) {
	owner := newWebTCPConnectionOwner()
	t.Cleanup(func() { _ = owner.close() })
	admission, err := newWebConnectionAdmission(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	raw, peer := webTCPOwnerRealPair(t)
	var lockHeld atomic.Bool
	raw.check = func() {
		if !owner.mu.TryLock() {
			lockHeld.Store(true)
			return
		}
		owner.mu.Unlock()
	}
	// The cancellation callback executes synchronously, making the lock
	// assertion independent of scheduler timing of context.AfterFunc.
	cancel := owner.cancel
	owner.cancel = func() {
		if !owner.mu.TryLock() {
			lockHeld.Store(true)
		} else {
			owner.mu.Unlock()
		}
		cancel()
	}
	release, ok := admission.acquire(raw.RemoteAddr())
	if !ok {
		t.Fatal("real TCP admission failed")
	}
	conn := &webAdmissionConn{Conn: raw, release: release, owner: owner}
	if !owner.register(conn) {
		t.Fatal("live owner rejected registration")
	}
	// First exercise owner shutdown without lock contention, then duplicate
	// normal/owner Close concurrently. Every call must retain the first result.
	if err := owner.close(); err != nil {
		t.Fatal(err)
	}
	if lockHeld.Load() {
		t.Error("owner canceled or closed the raw socket under its registry lock")
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() { defer workers.Done(); _ = conn.Close(); _ = owner.close() }()
	}
	joined := make(chan struct{})
	go func() { workers.Wait(); close(joined) }()
	websocketLifecycleJoin(t, "concurrent duplicate owner/connection closes", joined)
	if raw.closes.Load() != 1 || len(admission.slots) != 0 || owner.ctx.Err() == nil {
		t.Errorf("raw closes=%d slots=%d owner context=%v", raw.closes.Load(), len(admission.slots), owner.ctx.Err())
	}
	owner.mu.Lock()
	registered := len(owner.conns)
	owner.mu.Unlock()
	if registered != 0 {
		t.Errorf("closed socket retained %d registry entries", registered)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
		t.Errorf("real peer did not observe close before cleanup: %v", err)
	}
}

type webTCPOwnerDelayedListener struct {
	net.Listener
	entered chan struct{}
	release <-chan struct{}
	raw     chan *webTCPOwnerObservedConn
}

func (l *webTCPOwnerDelayedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	raw := &webTCPOwnerObservedConn{Conn: conn}
	l.raw <- raw
	close(l.entered)
	<-l.release
	return raw, nil
}

func TestWebTCPConnectionOwnerRejectsLateAcceptedRegistration(t *testing.T) {
	owner := newWebTCPConnectionOwner()
	admission, err := newWebConnectionAdmission(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	entered, release, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	ungate := func() { once.Do(func() { close(release) }) }
	observed := make(chan *webTCPOwnerObservedConn, 1)
	acceptResult := make(chan error, 1)
	delayed := &webTCPOwnerDelayedListener{Listener: listener, entered: entered, release: release, raw: observed}
	owned := &webAdmissionListener{Listener: delayed, admission: admission, owner: owner}
	t.Cleanup(func() {
		ungate()
		_ = listener.Close()
		_ = owner.close()
		websocketLifecycleJoin(t, "late raw Accept cleanup", joined)
	})
	go func() {
		defer close(joined)
		conn, err := owned.Accept()
		if conn != nil {
			_ = conn.Close()
			acceptResult <- errors.New("closed owner delivered a late accepted connection")
			return
		}
		acceptResult <- err
	}()
	peer, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("real raw Accept did not reach pre-registration gate")
	}
	raw := <-observed // Buffered publication happens before entered closes.
	t.Cleanup(func() { _ = raw.Conn.Close() })
	if len(admission.slots) != 0 {
		t.Fatal("gate did not precede admission and ownership registration")
	}
	if err := owner.close(); err != nil {
		t.Fatal(err)
	}
	ungate()
	websocketLifecycleJoin(t, "late raw Accept", joined)
	select {
	case err := <-acceptResult:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("late Accept error=%v, want net.ErrClosed", err)
		}
	default:
		t.Error("late Accept did not publish result")
	}
	if raw.closes.Load() != 1 || len(admission.slots) != 0 {
		t.Errorf("late raw closes=%d slots=%d", raw.closes.Load(), len(admission.slots))
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
		t.Errorf("late peer did not observe physical close before cleanup: %v", err)
	}
}
