package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/transport"
)

const defaultWebPrimaryAttemptTimeout = 5 * time.Second

const webFallbackCooldownJitterDivisor = 5

// WebClientConfig configures the dual-stack web-cover client. HTTP/3 is the
// preferred path and HTTP/2 is the TCP fallback when the UDP path is
// unavailable.
type WebClientConfig struct {
	ServerAddress string
	Token         string
	TLSConfig     *tls.Config
	QUICConfig    *quic.Config
	// H3FingerprintProfile defaults to the fixed chrome-2026-08 QUIC profile.
	// Native is an explicit interoperability and rollback path.
	H3FingerprintProfile H3FingerprintProfile

	HandshakeTimeout time.Duration
	H3DialTimeout    time.Duration
	H2DialTimeout    time.Duration

	// PrimaryAttemptTimeout bounds an HTTP/3 CONNECT attempt, including a
	// request on an already warm connection. Zero defaults to five seconds.
	PrimaryAttemptTimeout time.Duration
	// FallbackCooldown is the base period for which new streams bypass HTTP/3
	// after a transport failure. Production retries independently jitter that
	// base by +/-20%; once the resulting period expires, exactly one caller
	// probes HTTP/3 while concurrent callers continue over HTTP/2. Zero defaults
	// to thirty seconds.
	FallbackCooldown time.Duration

	// RFC 9298 datagrams always use the HTTP/3 primary. There is deliberately
	// no HTTP/2 UDP fallback. These limits bound one-target H3 request streams
	// and complete responses waiting for a PacketConn consumer.
	MaxUDPSessions     int
	MaxUDPDestinations int
	UDPReceiveQueue    int
}

type webClientPathDialer interface {
	transport.Dialer
	Close() error
}

type webClientPath struct {
	name   string
	dialer webClientPathDialer
}

// WebClient is a concurrent H3-first, H2-fallback web-cover dialer.
//
// Its primary and fallback paths are represented uniformly so a future
// explicit stealth profile can choose a different ordering without duplicating
// the circuit-breaker state machine.
type WebClient struct {
	primary               webClientPath
	fallback              webClientPath
	primaryAttemptTimeout time.Duration
	fallbackCooldown      time.Duration
	cooldownAfterFailure  func(time.Duration) time.Duration
	now                   func() time.Time

	ctx    context.Context
	cancel context.CancelFunc

	mu                sync.Mutex
	closed            bool
	primaryFailedAt   time.Time
	primaryCooldown   time.Duration
	primaryProbeID    uint64
	nextPrimaryID     uint64
	primaryStateID    uint64
	selectedTransport string

	closeOnce sync.Once
	closeErr  error
}

// NewWebClient creates an H3-first client with an automatic standards-based
// HTTP/2 fallback on the same host and port.
func NewWebClient(config WebClientConfig) (*WebClient, error) {
	if config.ServerAddress == "" {
		return nil, errors.New("tunnel: web-cover server address is required")
	}
	if config.HandshakeTimeout < 0 || config.H3DialTimeout < 0 || config.H2DialTimeout < 0 ||
		config.PrimaryAttemptTimeout < 0 || config.FallbackCooldown < 0 {
		return nil, errors.New("tunnel: web-cover client timeouts cannot be negative")
	}

	primaryTimeout := config.PrimaryAttemptTimeout
	if primaryTimeout == 0 {
		primaryTimeout = defaultWebPrimaryAttemptTimeout
	}
	cooldown := config.FallbackCooldown
	if cooldown == 0 {
		cooldown = defaultFallbackCooldown
	}

	h3, err := NewWebH3Client(WebH3ClientConfig{
		ServerAddress:      config.ServerAddress,
		Token:              config.Token,
		TLSConfig:          config.TLSConfig,
		QUICConfig:         config.QUICConfig,
		FingerprintProfile: config.H3FingerprintProfile,
		DialTimeout:        config.H3DialTimeout,
		HandshakeTimeout:   config.HandshakeTimeout,
		MaxUDPSessions:     config.MaxUDPSessions,
		MaxUDPDestinations: config.MaxUDPDestinations,
		UDPReceiveQueue:    config.UDPReceiveQueue,
	})
	if err != nil {
		return nil, fmt.Errorf("tunnel: configure web-cover H3 primary: %w", err)
	}
	h2, err := NewWebH2Client(WebH2ClientConfig{
		ServerAddress:    config.ServerAddress,
		Token:            config.Token,
		TLSConfig:        config.TLSConfig,
		HandshakeTimeout: config.HandshakeTimeout,
		DialTimeout:      config.H2DialTimeout,
	})
	if err != nil {
		_ = h3.Close()
		return nil, fmt.Errorf("tunnel: configure web-cover H2 fallback: %w", err)
	}

	client, err := newWebClientWithPaths(
		webClientPath{name: webAuthTransportH3, dialer: h3},
		webClientPath{name: webAuthTransportH2, dialer: h2},
		primaryTimeout,
		cooldown,
		time.Now,
	)
	if err != nil {
		_ = h3.Close()
		_ = h2.Close()
		return nil, err
	}
	// A fixed retry cadence lets multiple clients fail and probe in lockstep.
	// Production therefore treats the configured cooldown as a base and adds
	// independent +/-20% jitter. The private constructor remains deterministic
	// so state-machine tests can advance an exact clock.
	client.cooldownAfterFailure = jitterWebFallbackCooldown
	return client, nil
}

func newWebClientWithPaths(
	primary webClientPath,
	fallback webClientPath,
	primaryTimeout time.Duration,
	cooldown time.Duration,
	now func() time.Time,
) (*WebClient, error) {
	if primary.name == "" || primary.dialer == nil {
		return nil, errors.New("tunnel: web-cover primary path is required")
	}
	if fallback.name == "" || fallback.dialer == nil {
		return nil, errors.New("tunnel: web-cover fallback path is required")
	}
	if primary.name == fallback.name {
		return nil, errors.New("tunnel: web-cover paths must use different transports")
	}
	if primaryTimeout <= 0 {
		return nil, errors.New("tunnel: web-cover primary attempt timeout must be positive")
	}
	if cooldown <= 0 {
		return nil, errors.New("tunnel: web-cover fallback cooldown must be positive")
	}
	if now == nil {
		now = time.Now
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &WebClient{
		primary:               primary,
		fallback:              fallback,
		primaryAttemptTimeout: primaryTimeout,
		fallbackCooldown:      cooldown,
		cooldownAfterFailure:  func(base time.Duration) time.Duration { return base },
		now:                   now,
		ctx:                   ctx,
		cancel:                cancel,
	}, nil
}

// DialContext opens one TCP CONNECT stream. Only primary transport failures
// trigger HTTP/2 fallback. An authenticated WebConnectError proves the H3 path
// is alive and is returned directly, since retrying the same destination over
// another transport would hide the target-side failure.
func (c *WebClient) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("tunnel: nil web-cover dial context")
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseNetwork(network)
	if err != nil {
		return nil, err
	}
	if parsed != protocol.NetworkTCP {
		return nil, fmt.Errorf("tunnel: web-cover CONNECT does not support network %q", network)
	}
	authority, err := normalizeWebH2Authority(address)
	if err != nil {
		return nil, err
	}

	tryPrimary, primaryID, err := c.shouldTryPrimary(c.now())
	if err != nil {
		return nil, err
	}
	if !tryPrimary {
		return c.dialFallback(ctx, network, authority, nil)
	}

	primaryCtx, cancelPrimary := context.WithTimeout(ctx, c.primaryAttemptTimeout)
	primaryConn, primaryErr := c.dialPath(primaryCtx, c.primary, network, authority)
	cancelPrimary()
	if primaryErr == nil {
		if err := c.recordPrimarySuccess(primaryID, primaryConn); err != nil {
			return nil, err
		}
		return primaryConn, nil
	}
	if callerErr := contextError(ctx); callerErr != nil {
		c.primaryAttemptFinished(primaryID)
		return nil, callerErr
	}
	if c.isClosed() {
		c.primaryAttemptFinished(primaryID)
		return nil, net.ErrClosed
	}
	var connectErr *WebConnectError
	if errors.As(primaryErr, &connectErr) {
		// A signed, authenticated response is positive path-health evidence even
		// when the requested destination was rejected.
		c.recordPrimaryHealthy(primaryID)
		return nil, primaryErr
	}

	if !c.recordPrimaryFailure(primaryID, c.now()) {
		return nil, net.ErrClosed
	}
	return c.dialFallback(ctx, network, authority, primaryErr)
}

func (c *WebClient) dialFallback(ctx context.Context, network, authority string, primaryErr error) (net.Conn, error) {
	conn, err := c.dialPath(ctx, c.fallback, network, authority)
	if err != nil {
		if callerErr := contextError(ctx); callerErr != nil {
			return nil, callerErr
		}
		if c.isClosed() {
			return nil, net.ErrClosed
		}
		if primaryErr == nil {
			return nil, err
		}
		return nil, errors.Join(primaryErr, fmt.Errorf("tunnel: web-cover %s fallback: %w", c.fallback.name, err))
	}
	if err := c.recordFallbackSuccess(conn); err != nil {
		return nil, err
	}
	return conn, nil
}

// dialPath binds only connection establishment to the caller. The concrete
// H2/H3 clients detach a successful stream from this context before returning.
// The client-wide context independently lets Close interrupt in-flight dials.
func (c *WebClient) dialPath(ctx context.Context, path webClientPath, network, authority string) (net.Conn, error) {
	dialCtx, cancelDial := context.WithCancel(ctx)
	stopClient := context.AfterFunc(c.ctx, cancelDial)
	conn, err := path.dialer.DialContext(dialCtx, network, authority)
	stopClient()
	cancelDial()
	if err != nil {
		return nil, err
	}
	if callerErr := contextError(ctx); callerErr != nil {
		_ = conn.Close()
		return nil, callerErr
	}
	if c.isClosed() {
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (c *WebClient) shouldTryPrimary(now time.Time) (try bool, attemptID uint64, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false, 0, net.ErrClosed
	}
	if c.primaryFailedAt.IsZero() {
		c.nextPrimaryID++
		return true, c.nextPrimaryID, nil
	}
	cooldown := c.primaryCooldown
	if cooldown <= 0 {
		cooldown = c.fallbackCooldown
	}
	if now.Before(c.primaryFailedAt.Add(cooldown)) || c.primaryProbeID != 0 {
		return false, 0, nil
	}
	c.nextPrimaryID++
	c.primaryProbeID = c.nextPrimaryID
	return true, c.nextPrimaryID, nil
}

func (c *WebClient) recordPrimarySuccess(attemptID uint64, conn net.Conn) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = conn.Close()
		return net.ErrClosed
	}
	if attemptID >= c.primaryStateID {
		c.primaryStateID = attemptID
		c.primaryFailedAt = time.Time{}
		c.primaryCooldown = 0
	}
	if c.primaryProbeID == attemptID {
		c.primaryProbeID = 0
	}
	c.selectedTransport = c.primary.name
	c.mu.Unlock()
	return nil
}

func (c *WebClient) recordPrimaryHealthy(attemptID uint64) {
	c.mu.Lock()
	if !c.closed {
		if attemptID >= c.primaryStateID {
			c.primaryStateID = attemptID
			c.primaryFailedAt = time.Time{}
			c.primaryCooldown = 0
		}
		if c.primaryProbeID == attemptID {
			c.primaryProbeID = 0
		}
	}
	c.mu.Unlock()
}

// recordOutOfBandPrimaryHealthy records authenticated H3 health that wasn't
// initiated by the TCP circuit breaker, such as a CONNECT-UDP response. Giving
// it a fresh generation prevents an older concurrent TCP failure from reopening
// a path that was proved healthy more recently. A signed target rejection proves
// path health without selecting H3 as the latest successful transport.
func (c *WebClient) recordOutOfBandPrimaryHealthy(selectTransport bool) {
	c.mu.Lock()
	if !c.closed {
		c.nextPrimaryID++
		c.primaryStateID = c.nextPrimaryID
		c.primaryFailedAt = time.Time{}
		c.primaryCooldown = 0
		c.primaryProbeID = 0
		if selectTransport {
			c.selectedTransport = c.primary.name
		}
	}
	c.mu.Unlock()
}

func (c *WebClient) recordPrimaryFailure(attemptID uint64, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		if c.primaryProbeID == attemptID {
			c.primaryProbeID = 0
		}
		return false
	}
	// A slow failure from an older concurrent attempt must not reopen a path
	// already proved healthy by a newer attempt.
	if attemptID >= c.primaryStateID {
		c.primaryStateID = attemptID
		c.primaryFailedAt = now
		c.primaryCooldown = c.cooldownAfterFailure(c.fallbackCooldown)
	}
	if c.primaryProbeID == attemptID {
		c.primaryProbeID = 0
	}
	return true
}

func jitterWebFallbackCooldown(base time.Duration) time.Duration {
	return jitterWebFallbackCooldownWith(base, mathrand.Int64N)
}

func jitterWebFallbackCooldownWith(base time.Duration, sample func(int64) int64) time.Duration {
	span := base / webFallbackCooldownJitterDivisor
	if span <= 0 {
		return base
	}
	// span is at most MaxInt64/5, so doubling it cannot overflow int64.
	return base - span + time.Duration(sample(int64(2*span)+1))
}

func (c *WebClient) primaryAttemptFinished(attemptID uint64) {
	c.mu.Lock()
	if c.primaryProbeID == attemptID {
		c.primaryProbeID = 0
	}
	c.mu.Unlock()
}

func (c *WebClient) recordFallbackSuccess(conn net.Conn) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = conn.Close()
		return net.ErrClosed
	}
	c.selectedTransport = c.fallback.name
	c.mu.Unlock()
	return nil
}

func (c *WebClient) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// SelectedTransport reports the path used by the most recently successful
// authenticated stream. It is blank until a CONNECT succeeds.
func (c *WebClient) SelectedTransport() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.selectedTransport
}

// Snapshot reports the latest successful web-cover path. Web transports do
// not use AutoCAR's native application pacing negotiation.
func (c *WebClient) Snapshot() ClientSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return ClientSnapshot{
		SelectedTransport: c.selectedTransport,
		ClientPacing:      "not-applicable",
		RelayPacing:       "not-applicable",
	}
}

// DialPacket opens an RFC 9298 CONNECT-UDP PacketConn on the HTTP/3 primary.
// HTTP/2 is intentionally never attempted: CONNECT-UDP datagrams require the
// HTTP/3 datagram and Extended CONNECT settings negotiated by WebH3Client.
func (c *WebClient) DialPacket(ctx context.Context) (transport.PacketConn, error) {
	if ctx == nil {
		return nil, errors.New("tunnel: nil web-cover packet dial context")
	}
	packetDialer, ok := c.primary.dialer.(transport.PacketDialer)
	if !ok {
		return nil, errors.New("tunnel: web-cover primary does not support CONNECT-UDP")
	}
	if c.isClosed() {
		return nil, net.ErrClosed
	}
	dialContext, cancelDial := context.WithTimeout(ctx, c.primaryAttemptTimeout)
	stopClient := context.AfterFunc(c.ctx, cancelDial)
	packet, err := packetDialer.DialPacket(dialContext)
	stopClient()
	cancelDial()
	if err != nil {
		if callerErr := contextError(ctx); callerErr != nil {
			return nil, callerErr
		}
		if c.isClosed() {
			return nil, net.ErrClosed
		}
		return nil, fmt.Errorf("tunnel: web-cover %s CONNECT-UDP: %w", c.primary.name, err)
	}
	if c.isClosed() {
		_ = packet.Close()
		return nil, net.ErrClosed
	}
	return &webClientPacketConn{parent: c, inner: packet}, nil
}

type webClientPacketConn struct {
	parent *WebClient
	inner  transport.PacketConn
}

func (c *webClientPacketConn) Send(payload []byte, address string) error {
	if err := c.inner.Send(payload, address); err != nil {
		var connectErr *WebConnectError
		if errors.As(err, &connectErr) {
			c.parent.recordOutOfBandPrimaryHealthy(false)
		}
		return err
	}
	c.parent.recordOutOfBandPrimaryHealthy(true)
	return nil
}

func (c *webClientPacketConn) Receive() ([]byte, string, error) { return c.inner.Receive() }
func (c *webClientPacketConn) Close() error                     { return c.inner.Close() }

func (c *webClientPacketConn) MaxPayloadSize() int {
	if sizer, ok := c.inner.(transport.PacketPayloadSizer); ok {
		return sizer.MaxPayloadSize()
	}
	return webConnectUDPMaxPayloadSize
}

// Close prevents new streams, interrupts in-flight dials, and closes both
// underlying multiplexed transports. It is safe to call concurrently.
func (c *WebClient) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.primaryProbeID = 0
		c.cancel()
		c.mu.Unlock()

		c.closeErr = errors.Join(c.primary.dialer.Close(), c.fallback.dialer.Close())
	})
	return c.closeErr
}

var _ transport.Dialer = (*WebClient)(nil)
var _ transport.PacketDialer = (*WebClient)(nil)
var _ transport.PacketConn = (*webClientPacketConn)(nil)
var _ transport.PacketPayloadSizer = (*webClientPacketConn)(nil)
