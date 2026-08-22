package hy2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

const defaultFallbackCooldown = 30 * time.Second

const (
	autoRoutePrimary uint32 = iota
	autoRouteFallback
)

type closeDialer interface {
	transport.Dialer
	Close() error
}

// AutoConfig configures UDP-first operation with a real TCP/TLS fallback.
type AutoConfig struct {
	Primary        *Client
	Fallback       closeDialer
	AttemptTimeout time.Duration
	Cooldown       time.Duration
	// OnFallback is called once when a healthy/unknown primary circuit first
	// becomes unavailable. It is intended for concise operational logging and
	// must not retain secrets or block.
	OnFallback func(error)
}

// AutoClient uses Hysteria v2 first and temporarily routes new TCP flows over
// TLS when the UDP path is unavailable. A valid relay-side destination error
// and an authentication rejection never open the circuit.
type AutoClient struct {
	primary  *Client
	fallback closeDialer
	timeout  time.Duration
	cooldown time.Duration
	observer func(error)
	route    atomic.Uint32

	fallbackMu      sync.RWMutex
	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc

	mu        sync.Mutex
	failedAt  time.Time
	probing   bool
	closed    bool
	closeErr  error
	closeDone chan struct{}
}

// NewAutoClient creates an automatic dual-transport dialer.
func NewAutoClient(config AutoConfig) (*AutoClient, error) {
	if config.Primary == nil || config.Fallback == nil {
		return nil, errors.New("hy2: auto mode requires primary and fallback dialers")
	}
	if config.AttemptTimeout <= 0 {
		return nil, errors.New("hy2: auto attempt timeout must be positive")
	}
	if config.Cooldown < 0 {
		return nil, errors.New("hy2: fallback cooldown cannot be negative")
	}
	if config.Cooldown == 0 {
		config.Cooldown = defaultFallbackCooldown
	}
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	return &AutoClient{
		primary:         config.Primary,
		fallback:        config.Fallback,
		timeout:         config.AttemptTimeout,
		cooldown:        config.Cooldown,
		observer:        config.OnFallback,
		lifecycleCtx:    lifecycleCtx,
		lifecycleCancel: lifecycleCancel,
		closeDone:       make(chan struct{}),
	}, nil
}

func (c *AutoClient) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("hy2: nil dial context")
	}
	if c.isClosed() {
		return nil, net.ErrClosed
	}
	if !c.shouldTryPrimary(time.Now()) {
		// Close may race between the first closed check and the routing
		// decision. Never invoke an already-closed fallback in that window.
		if c.isClosed() {
			return nil, net.ErrClosed
		}
		return c.dialFallback(ctx, network, address)
	}
	primaryCtx, cancel := context.WithTimeout(ctx, c.timeout)
	primaryConn, primaryErr := c.primary.DialContext(primaryCtx, network, address)
	cancel()
	if primaryErr == nil {
		c.primarySucceeded()
		return primaryConn, nil
	}
	if callerErr := context.Cause(ctx); callerErr != nil {
		c.probeFinished()
		return nil, callerErr
	}
	if IsRemoteDialError(primaryErr) || IsAuthenticationError(primaryErr) {
		c.primarySucceeded()
		return nil, primaryErr
	}
	if c.isClosed() {
		return nil, net.ErrClosed
	}
	if c.primaryFailed(time.Now()) && c.observer != nil {
		c.observer(primaryErr)
	}
	fallbackConn, fallbackErr := c.dialFallback(ctx, network, address)
	if fallbackErr == nil {
		return fallbackConn, nil
	}
	return nil, errors.Join(
		fmt.Errorf("hy2 primary: %w", primaryErr),
		fmt.Errorf("TLS fallback: %w", fallbackErr),
	)
}

func (c *AutoClient) dialFallback(ctx context.Context, network, address string) (net.Conn, error) {
	// The read lock linearizes fallback dispatch with Close: once Close marks
	// the client closed, no new call can enter the fallback, and an already
	// running call receives lifecycle cancellation before Close waits for it.
	c.fallbackMu.RLock()
	defer c.fallbackMu.RUnlock()
	if c.isClosed() {
		return nil, net.ErrClosed
	}
	callCtx, cancel := context.WithCancelCause(ctx)
	var stop func() bool
	if c.lifecycleCtx != nil {
		stop = context.AfterFunc(c.lifecycleCtx, func() { cancel(net.ErrClosed) })
	}
	defer func() {
		if stop != nil {
			stop()
		}
		cancel(nil)
	}()
	conn, err := c.fallback.DialContext(callCtx, network, address)
	if err == nil {
		c.route.Store(autoRouteFallback)
	}
	return conn, err
}

// DialPacket opens an accelerated UDP session. TCP/TLS cannot carry SOCKS5
// UDP without head-of-line blocking, so datagrams intentionally have no
// fallback and report a primary-path failure directly.
func (c *AutoClient) DialPacket(ctx context.Context) (transport.PacketConn, error) {
	if ctx == nil {
		return nil, errors.New("hy2: nil packet context")
	}
	if c.isClosed() {
		return nil, net.ErrClosed
	}
	packetCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	conn, err := c.primary.DialPacket(packetCtx)
	if err == nil {
		c.route.Store(autoRoutePrimary)
	}
	return conn, err
}

// AccelerationMode reports the transport used by the most recent successful
// flow. A TLS fallback has no QUIC congestion controller.
func (c *AutoClient) AccelerationMode() string {
	if c.route.Load() == autoRouteFallback {
		return "tls-fallback"
	}
	return c.primary.AccelerationMode()
}

// NegotiatedTx reports the primary QUIC path's most recently negotiated
// client-to-server Brutal rate. It is zero while the TLS fallback, BBR or Reno
// is active.
func (c *AutoClient) NegotiatedTx() uint64 {
	if c.route.Load() == autoRouteFallback {
		return 0
	}
	return c.primary.NegotiatedTx()
}

func (c *AutoClient) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *AutoClient) shouldTryPrimary(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	if c.failedAt.IsZero() {
		return true
	}
	if now.Before(c.failedAt.Add(c.cooldown)) || c.probing {
		return false
	}
	c.probing = true
	return true
}

func (c *AutoClient) primarySucceeded() {
	c.mu.Lock()
	c.failedAt = time.Time{}
	c.probing = false
	c.mu.Unlock()
	c.route.Store(autoRoutePrimary)
}

func (c *AutoClient) primaryFailed(now time.Time) bool {
	c.mu.Lock()
	firstFailure := c.failedAt.IsZero()
	c.failedAt = now
	c.probing = false
	c.mu.Unlock()
	return firstFailure
}

func (c *AutoClient) probeFinished() {
	c.mu.Lock()
	c.probing = false
	c.mu.Unlock()
}

// Close closes both transports.
func (c *AutoClient) Close() error {
	c.mu.Lock()
	if c.closed {
		done := c.closeDone
		c.mu.Unlock()
		if done != nil {
			<-done
		}
		c.mu.Lock()
		err := c.closeErr
		c.mu.Unlock()
		return err
	}
	c.closed = true
	if c.closeDone == nil {
		c.closeDone = make(chan struct{})
	}
	done := c.closeDone
	lifecycleCancel := c.lifecycleCancel
	c.mu.Unlock()

	if lifecycleCancel != nil {
		lifecycleCancel()
	}
	c.fallbackMu.Lock()
	err := errors.Join(c.primary.Close(), c.fallback.Close())
	c.fallbackMu.Unlock()
	c.mu.Lock()
	c.closeErr = err
	close(done)
	c.mu.Unlock()
	return err
}

var _ transport.Dialer = (*AutoClient)(nil)
var _ transport.PacketDialer = (*AutoClient)(nil)
