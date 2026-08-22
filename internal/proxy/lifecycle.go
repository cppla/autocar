package proxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// connTracker makes connection limits and shutdown semantics identical for
// custom protocol servers and net/http. In particular, a hijacked HTTP CONNECT
// remains tracked until the returned net.Conn is actually closed.
type connTracker struct {
	mu        sync.Mutex
	accepting bool
	max       int
	conns     map[*trackedConn]struct{}
	zero      chan struct{}
}

func newConnTracker(max int) *connTracker {
	zero := make(chan struct{})
	close(zero)
	return &connTracker{
		accepting: true,
		max:       max,
		conns:     make(map[*trackedConn]struct{}),
		zero:      zero,
	}
}

func (t *connTracker) add(c *trackedConn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.accepting || len(t.conns) >= t.max {
		return false
	}
	if len(t.conns) == 0 {
		t.zero = make(chan struct{})
	}
	t.conns[c] = struct{}{}
	return true
}

func (t *connTracker) remove(c *trackedConn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.conns[c]; !ok {
		return
	}
	delete(t.conns, c)
	if len(t.conns) == 0 {
		close(t.zero)
	}
}

func (t *connTracker) stopAccepting() {
	t.mu.Lock()
	t.accepting = false
	t.mu.Unlock()
}

func (t *connTracker) wait(ctx context.Context) error {
	t.mu.Lock()
	zero := t.zero
	t.mu.Unlock()
	select {
	case <-zero:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *connTracker) closeAll() {
	t.mu.Lock()
	conns := make([]*trackedConn, 0, len(t.conns))
	for conn := range t.conns {
		conns = append(conns, conn)
	}
	t.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

type trackedConn struct {
	net.Conn
	once            sync.Once
	tracker         *connTracker
	activityTimeout atomic.Int64
	deadlineMu      sync.Mutex
	externalRead    time.Time
	externalWrite   time.Time
}

func (c *trackedConn) Read(p []byte) (int, error) {
	if timeout := time.Duration(c.activityTimeout.Load()); timeout > 0 {
		if err := c.armReadDeadline(timeout); err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(p)
}

func (c *trackedConn) Write(p []byte) (int, error) {
	if timeout := time.Duration(c.activityTimeout.Load()); timeout > 0 {
		if err := c.armWriteDeadline(timeout); err != nil {
			return 0, err
		}
	}
	return c.Conn.Write(p)
}

// SetDeadline records deadlines imposed by net/http. Activity deadlines are
// never allowed to extend a sooner external deadline. This is security- and
// correctness-critical: net/http uses a deadline in the past to interrupt a
// background reader while Hijack turns CONNECT into a raw tunnel.
func (c *trackedConn) SetDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.externalRead = deadline
	c.externalWrite = deadline
	return c.Conn.SetDeadline(deadline)
}

func (c *trackedConn) SetReadDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.externalRead = deadline
	return c.Conn.SetReadDeadline(deadline)
}

func (c *trackedConn) SetWriteDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.externalWrite = deadline
	return c.Conn.SetWriteDeadline(deadline)
}

func (c *trackedConn) armReadDeadline(timeout time.Duration) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.Conn.SetReadDeadline(earlierDeadline(time.Now().Add(timeout), c.externalRead))
}

func (c *trackedConn) armWriteDeadline(timeout time.Duration) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.Conn.SetWriteDeadline(earlierDeadline(time.Now().Add(timeout), c.externalWrite))
}

func earlierDeadline(activity, external time.Time) time.Time {
	if !external.IsZero() && external.Before(activity) {
		return external
	}
	return activity
}

// setActivityTimeout is enabled only while net/http reports StateActive (or
// after a CONNECT hijack). Header and keepalive-idle deadlines remain owned by
// net/http, preserving its absolute ReadHeaderTimeout semantics.
func (c *trackedConn) setActivityTimeout(timeout time.Duration) {
	c.activityTimeout.Store(int64(timeout))
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if timeout > 0 {
		activity := time.Now().Add(timeout)
		_ = c.Conn.SetReadDeadline(earlierDeadline(activity, c.externalRead))
		_ = c.Conn.SetWriteDeadline(earlierDeadline(activity, c.externalWrite))
	} else {
		_ = c.Conn.SetReadDeadline(c.externalRead)
		_ = c.Conn.SetWriteDeadline(c.externalWrite)
	}
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.tracker.remove(c) })
	return err
}

// CloseWrite preserves TCP half-close semantics through the tracking wrapper.
// Some stream implementations don't expose it; for them the no-op fallback is
// the same behavior a plain net.Conn would have in relay.closeWrite.
func (c *trackedConn) CloseWrite() error {
	type closeWriter interface{ CloseWrite() error }
	if conn, ok := c.Conn.(closeWriter); ok {
		return conn.CloseWrite()
	}
	return nil
}

type managedListener struct {
	net.Listener
	tracker *connTracker
}

func (l *managedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		tracked := &trackedConn{Conn: conn, tracker: l.tracker}
		if l.tracker.add(tracked) {
			return tracked, nil
		}
		_ = conn.Close()
		l.tracker.mu.Lock()
		accepting := l.tracker.accepting
		l.tracker.mu.Unlock()
		if !accepting {
			return nil, net.ErrClosed
		}
	}
}

type serverLifecycle struct {
	mu       sync.Mutex
	listener net.Listener
	tracker  *connTracker
}

func newServerLifecycle(max int) *serverLifecycle {
	return &serverLifecycle{tracker: newConnTracker(max)}
}

func (s *serverLifecycle) manage(listener net.Listener) (*managedListener, error) {
	if listener == nil {
		return nil, errors.New("proxy: nil listener")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return nil, errors.New("proxy: server is already serving")
	}
	s.listener = listener
	return &managedListener{Listener: listener, tracker: s.tracker}, nil
}

func (s *serverLifecycle) stopAccepting() error {
	s.tracker.stopAccepting()
	s.mu.Lock()
	listener := s.listener
	s.mu.Unlock()
	if listener == nil {
		return nil
	}
	return listener.Close()
}

func (s *serverLifecycle) shutdown(ctx context.Context) error {
	closeErr := s.stopAccepting()
	if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
		return closeErr
	}
	if err := s.tracker.wait(ctx); err != nil {
		s.tracker.closeAll()
		return err
	}
	return nil
}
