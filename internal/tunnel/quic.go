package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/transport"
	quic "github.com/quic-go/quic-go"
)

const (
	applicationShutdown     quic.ApplicationErrorCode = 0x100
	streamCanceled          quic.StreamErrorCode      = 0x101
	connectionRejected      quic.ApplicationErrorCode = 0x102
	authenticationTimeout   quic.ApplicationErrorCode = 0x103
	defaultFallbackCooldown                           = 30 * time.Second
)

// QUICServerConfig configures an encrypted QUIC exit listener.
type QUICServerConfig struct {
	Address              string
	Token                string
	TLSConfig            *tls.Config
	QUICConfig           *quic.Config
	Dialer               transport.Dialer
	HandshakeTimeout     time.Duration
	DialTimeout          time.Duration
	MaxConcurrentStreams int
	// MaxConnections bounds accepted QUIC connections, including authenticated
	// idle sessions. Zero uses a conservative default.
	MaxConnections int
}

// QUICServer accepts long-lived QUIC connections and relays each bidirectional
// stream to an independently dialed TCP destination.
type QUICServer struct {
	listener *quic.Listener
	core     *serverCore

	ctx    context.Context
	cancel context.CancelFunc

	serveMu   sync.Mutex
	serving   bool
	closeOnce sync.Once
	closeErr  error
	lifecycle sync.Mutex
	closing   bool
	wg        sync.WaitGroup
	connMu    sync.Mutex
	conns     map[*quic.Conn]struct{}
	connSem   chan struct{}
}

// ListenQUIC binds the UDP listener. Call Serve to accept traffic.
func ListenQUIC(config QUICServerConfig) (*QUICServer, error) {
	if config.Address == "" {
		return nil, errors.New("tunnel: QUIC listen address is required")
	}
	tlsConfig, err := serverTLSConfig(config.TLSConfig)
	if err != nil {
		return nil, err
	}
	core, err := newServerCore(config.Token, config.Dialer, config.HandshakeTimeout, config.DialTimeout, config.MaxConcurrentStreams)
	if err != nil {
		return nil, err
	}
	if config.MaxConnections < 0 {
		return nil, errors.New("tunnel: maximum QUIC connections cannot be negative")
	}
	maxConnections := config.MaxConnections
	if maxConnections == 0 {
		maxConnections = defaultMaxConnections
	}
	quicConfig := hardenedQUICServerConfig(config.QUICConfig, cap(core.sem))
	listener, err := quic.ListenAddr(config.Address, tlsConfig, quicConfig)
	if err != nil {
		return nil, fmt.Errorf("tunnel: listen QUIC: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &QUICServer{
		listener: listener,
		core:     core,
		ctx:      ctx,
		cancel:   cancel,
		conns:    make(map[*quic.Conn]struct{}),
		connSem:  make(chan struct{}, maxConnections),
	}, nil
}

func hardenedQUICServerConfig(input *quic.Config, maxStreams int) *quic.Config {
	var cfg *quic.Config
	if input == nil {
		cfg = &quic.Config{}
	} else {
		cfg = input.Clone()
	}
	cfg.Allow0RTT = false
	cfg.EnableDatagrams = false
	cfg.MaxIncomingUniStreams = -1
	if cfg.MaxIncomingStreams <= 0 || cfg.MaxIncomingStreams > int64(maxStreams) {
		cfg.MaxIncomingStreams = int64(maxStreams)
	}
	if cfg.HandshakeIdleTimeout == 0 {
		cfg.HandshakeIdleTimeout = 5 * time.Second
	}
	if cfg.MaxIdleTimeout == 0 {
		cfg.MaxIdleTimeout = 60 * time.Second
	}
	// A server-side keepalive would keep unauthenticated idle connections alive
	// forever. The client sends keepalives for authenticated warm sessions.
	cfg.KeepAlivePeriod = 0
	if cfg.InitialStreamReceiveWindow == 0 {
		cfg.InitialStreamReceiveWindow = 1 << 20
	}
	if cfg.MaxStreamReceiveWindow == 0 {
		cfg.MaxStreamReceiveWindow = 16 << 20
	}
	if cfg.InitialConnectionReceiveWindow == 0 {
		cfg.InitialConnectionReceiveWindow = 2 << 20
	}
	if cfg.MaxConnectionReceiveWindow == 0 {
		cfg.MaxConnectionReceiveWindow = 64 << 20
	}
	return cfg
}

// Addr returns the bound UDP address.
func (s *QUICServer) Addr() net.Addr { return s.listener.Addr() }

// Serve accepts until ctx is canceled or Close is called. Serve may be called
// exactly once. Canceling ctx also closes all accepted connections.
func (s *QUICServer) Serve(ctx context.Context) error {
	if ctx == nil {
		return errors.New("tunnel: nil serve context")
	}
	s.serveMu.Lock()
	if s.serving {
		s.serveMu.Unlock()
		return errors.New("tunnel: QUIC server already serving")
	}
	s.serving = true
	s.serveMu.Unlock()

	acceptCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	defer cancel()
	defer s.Close()

	for {
		conn, err := s.listener.Accept(acceptCtx)
		if err != nil {
			if acceptCtx.Err() != nil || s.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("tunnel: accept QUIC connection: %w", err)
		}
		s.lifecycle.Lock()
		if s.closing || acceptCtx.Err() != nil {
			s.lifecycle.Unlock()
			_ = conn.CloseWithError(applicationShutdown, "server shutting down")
			if acceptCtx.Err() != nil {
				return nil
			}
			continue
		}
		select {
		case s.connSem <- struct{}{}:
		default:
			s.lifecycle.Unlock()
			_ = conn.CloseWithError(connectionRejected, "connection limit reached")
			continue
		}
		s.connMu.Lock()
		s.conns[conn] = struct{}{}
		s.connMu.Unlock()
		s.wg.Add(1)
		s.lifecycle.Unlock()
		go s.serveConnection(conn)
	}
}

func (s *QUICServer) serveConnection(conn *quic.Conn) {
	defer s.wg.Done()
	defer func() { <-s.connSem }()
	defer func() {
		s.connMu.Lock()
		delete(s.conns, conn)
		s.connMu.Unlock()
	}()

	// QUIC authentication is carried by the first valid stream request rather
	// than the TLS handshake. Bound the pre-authentication lifetime so a remote
	// peer cannot consume a connection slot indefinitely with PING frames.
	var authMu sync.Mutex
	authenticated := false
	authTimer := time.AfterFunc(s.core.handshakeTimeout, func() {
		authMu.Lock()
		expired := !authenticated
		authMu.Unlock()
		if expired {
			_ = conn.CloseWithError(authenticationTimeout, "authentication timeout")
		}
	})
	defer authTimer.Stop()
	markAuthenticated := func() {
		authMu.Lock()
		first := !authenticated
		authenticated = true
		authMu.Unlock()
		if first {
			authTimer.Stop()
		}
	}
	for {
		stream, err := conn.AcceptStream(conn.Context())
		if err != nil {
			return
		}
		wrapped := newQUICStreamConn(stream, conn.LocalAddr(), conn.RemoteAddr())
		s.lifecycle.Lock()
		if s.closing {
			s.lifecycle.Unlock()
			_ = wrapped.Close()
			return
		}
		if !s.core.acquire() {
			s.lifecycle.Unlock()
			_ = wrapped.SetDeadline(time.Now().Add(time.Second))
			_ = protocol.WriteResponse(wrapped, protocol.Response{Status: protocol.StatusBusy, Message: "server busy"})
			finishStream(wrapped)
			continue
		}
		s.wg.Add(1)
		s.lifecycle.Unlock()
		go func() {
			defer s.wg.Done()
			defer s.core.release()
			// A QUIC stream has an independent lifecycle. In particular, the
			// peer's STOP_SENDING cancels stream.Context without killing sibling
			// streams, allowing an abandoned CONNECT to cancel DNS/dial promptly.
			s.core.handleStream(stream.Context(), wrapped, markAuthenticated)
		}()
	}
}

// Close stops accepting, closes active QUIC connections and waits for relay
// goroutines. It is safe to call more than once.
func (s *QUICServer) Close() error {
	s.closeOnce.Do(func() {
		// Every positive WaitGroup.Add is performed while holding lifecycle and
		// only when closing is false. Publishing closing before listener.Close
		// prevents a just-accepted connection from racing with Wait at zero.
		s.lifecycle.Lock()
		s.closing = true
		s.lifecycle.Unlock()
		s.cancel()
		s.closeErr = s.listener.Close()
		s.connMu.Lock()
		connections := make([]*quic.Conn, 0, len(s.conns))
		for conn := range s.conns {
			connections = append(connections, conn)
		}
		s.connMu.Unlock()
		for _, conn := range connections {
			_ = conn.CloseWithError(applicationShutdown, "server shutting down")
		}
		s.wg.Wait()
	})
	return s.closeErr
}

// ClientConfig configures the preferred QUIC transport. If FallbackAddress is
// set, transport failures are retried over a separate TCP+TLS connection.
type ClientConfig struct {
	ServerAddress    string
	FallbackAddress  string
	Token            string
	TLSConfig        *tls.Config
	QUICConfig       *quic.Config
	HandshakeTimeout time.Duration
	QUICDialTimeout  time.Duration
	TLSDialTimeout   time.Duration
	// PrimaryAttemptTimeout bounds the entire QUIC phase in auto mode,
	// including a reused stream's protocol response. This leaves time in the
	// caller's context for TLS fallback. Zero defaults to five seconds.
	PrimaryAttemptTimeout time.Duration
	// FallbackCooldown controls how long a failed QUIC path is bypassed before
	// one caller probes it again. It defaults to 30 seconds.
	FallbackCooldown time.Duration
}

// Client is a concurrent transport.Dialer backed by one lazily established,
// long-lived QUIC connection.
type Client struct {
	address          string
	token            string
	tlsConfig        *tls.Config
	quicConfig       *quic.Config
	handshakeTimeout time.Duration
	dialTimeout      time.Duration
	primaryTimeout   time.Duration
	fallback         *TLSClient
	fallbackCooldown time.Duration

	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	conn    *quic.Conn
	dialing *quicDialAttempt
	closed  bool
	// primaryFailedAt and primaryProbing implement a small circuit breaker.
	// They are guarded by mu together with the QUIC connection state.
	primaryFailedAt time.Time
	primaryProbing  bool
}

type quicDialAttempt struct {
	done   chan struct{}
	cancel context.CancelFunc
	err    error
}

// NewClient creates a QUIC client. It doesn't perform network I/O until the
// first DialContext call.
func NewClient(config ClientConfig) (*Client, error) {
	if config.ServerAddress == "" {
		return nil, errors.New("tunnel: QUIC server address is required")
	}
	if len(config.Token) < protocol.MinTokenLength || len(config.Token) > protocol.MaxTokenLength {
		return nil, fmt.Errorf("tunnel: token length must be between %d and %d bytes", protocol.MinTokenLength, protocol.MaxTokenLength)
	}
	if config.HandshakeTimeout < 0 || config.QUICDialTimeout < 0 || config.TLSDialTimeout < 0 || config.PrimaryAttemptTimeout < 0 || config.FallbackCooldown < 0 {
		return nil, errors.New("tunnel: timeouts cannot be negative")
	}
	tlsConfig, err := clientTLSConfig(config.TLSConfig, config.ServerAddress)
	if err != nil {
		return nil, err
	}
	handshakeTimeout := config.HandshakeTimeout
	if handshakeTimeout == 0 {
		handshakeTimeout = defaultHandshakeTimeout
	}
	dialTimeout := config.QUICDialTimeout
	if dialTimeout == 0 {
		dialTimeout = 5 * time.Second
	}
	primaryTimeout := config.PrimaryAttemptTimeout
	if primaryTimeout == 0 {
		primaryTimeout = 5 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		address:          config.ServerAddress,
		token:            config.Token,
		tlsConfig:        tlsConfig,
		quicConfig:       hardenedQUICClientConfig(config.QUICConfig),
		handshakeTimeout: handshakeTimeout,
		dialTimeout:      dialTimeout,
		primaryTimeout:   primaryTimeout,
		ctx:              ctx,
		cancel:           cancel,
	}
	if config.FallbackAddress != "" {
		fallbackCooldown := config.FallbackCooldown
		if fallbackCooldown == 0 {
			fallbackCooldown = defaultFallbackCooldown
		}
		fallback, err := NewTLSClient(TLSClientConfig{
			ServerAddress:    config.FallbackAddress,
			Token:            config.Token,
			TLSConfig:        config.TLSConfig,
			HandshakeTimeout: handshakeTimeout,
			DialTimeout:      config.TLSDialTimeout,
		})
		if err != nil {
			cancel()
			return nil, fmt.Errorf("tunnel: configure TLS fallback: %w", err)
		}
		c.fallback = fallback
		c.fallbackCooldown = fallbackCooldown
	}
	return c, nil
}

// NewQUICClient is an explicit alias for NewClient.
func NewQUICClient(config ClientConfig) (*Client, error) { return NewClient(config) }

func hardenedQUICClientConfig(input *quic.Config) *quic.Config {
	var cfg *quic.Config
	if input == nil {
		cfg = &quic.Config{}
	} else {
		cfg = input.Clone()
	}
	// DialAddr (not DialAddrEarly) and this explicit setting guarantee that
	// CONNECT requests are never sent as replayable 0-RTT data.
	cfg.Allow0RTT = false
	cfg.EnableDatagrams = false
	cfg.MaxIncomingStreams = -1
	cfg.MaxIncomingUniStreams = -1
	if cfg.HandshakeIdleTimeout == 0 {
		cfg.HandshakeIdleTimeout = 5 * time.Second
	}
	if cfg.MaxIdleTimeout == 0 {
		cfg.MaxIdleTimeout = 60 * time.Second
	}
	if cfg.KeepAlivePeriod == 0 {
		cfg.KeepAlivePeriod = 15 * time.Second
	}
	if cfg.InitialStreamReceiveWindow == 0 {
		cfg.InitialStreamReceiveWindow = 1 << 20
	}
	if cfg.MaxStreamReceiveWindow == 0 {
		cfg.MaxStreamReceiveWindow = 16 << 20
	}
	if cfg.InitialConnectionReceiveWindow == 0 {
		cfg.InitialConnectionReceiveWindow = 2 << 20
	}
	if cfg.MaxConnectionReceiveWindow == 0 {
		cfg.MaxConnectionReceiveWindow = 64 << 20
	}
	return cfg
}

// DialContext implements transport.Dialer. A stream-open failure invalidates
// the shared connection and is retried once on a freshly authenticated QUIC
// connection before the optional TCP+TLS fallback is used.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("tunnel: nil dial context")
	}
	n, err := protocol.ParseNetwork(network)
	if err != nil {
		return nil, err
	}
	// Validate the complete request before any network activity.
	if err := protocol.WriteRequest(io.Discard, protocol.Request{Network: n, Token: []byte(c.token), Address: address}); err != nil {
		return nil, err
	}
	if c.fallback != nil && !c.shouldTryPrimary(time.Now()) {
		return c.fallback.DialContext(ctx, network, address)
	}

	// In auto mode the primary budget covers the whole QUIC attempt, not just
	// connection establishment. An already-established QUIC connection can
	// otherwise become a silent stream black hole and consume the caller's
	// entire context before TLS fallback gets a chance to run.
	primaryCtx := ctx
	cancelPrimary := func() {}
	if c.fallback != nil {
		primaryCtx, cancelPrimary = context.WithTimeout(ctx, c.primaryTimeout)
	}
	defer cancelPrimary()

	var primaryErr error
	for attempt := 0; attempt < 2; attempt++ {
		if err := contextError(ctx); err != nil {
			c.primaryProbeFinished()
			return nil, err
		}
		if err := contextError(primaryCtx); err != nil {
			primaryErr = fmt.Errorf("tunnel: QUIC attempt budget exhausted: %w", err)
			break
		}
		conn, err := c.connection(primaryCtx)
		if err != nil {
			if callerErr := contextError(ctx); callerErr != nil {
				c.primaryProbeFinished()
				return nil, callerErr
			}
			primaryErr = err
			break
		}
		stream, err := conn.OpenStreamSync(primaryCtx)
		if err != nil {
			primaryErr = fmt.Errorf("tunnel: open QUIC stream: %w", err)
			if callerErr := contextError(ctx); callerErr != nil {
				c.primaryProbeFinished()
				return nil, callerErr
			}
			if contextError(primaryCtx) != nil {
				break
			}
			if conn.Context().Err() == nil {
				// Stream admission/cancellation is not evidence that the shared
				// transport is dead. Preserve unrelated established flows.
				break
			}
			c.invalidate(conn)
			continue
		}
		wrapped := newQUICStreamConn(stream, conn.LocalAddr(), conn.RemoteAddr())
		err = openProtocol(primaryCtx, wrapped, c.token, network, address, c.handshakeTimeout)
		if err == nil {
			c.primarySucceeded()
			return wrapped, nil
		}
		_ = wrapped.Close()
		var remoteErr *RemoteError
		if errors.As(err, &remoteErr) {
			// A valid authenticated response proves the QUIC path is healthy.
			// Destination and authorization failures must never trip the
			// transport circuit breaker.
			c.primarySucceeded()
			return nil, err
		}
		primaryErr = fmt.Errorf("tunnel: QUIC stream handshake: %w", err)
		if callerErr := contextError(ctx); callerErr != nil {
			// A caller controls only its own stream. Canceling one request must
			// never tear down the multiplexed connection and every other flow.
			c.primaryProbeFinished()
			return nil, callerErr
		}
		if contextError(primaryCtx) != nil || conn.Context().Err() == nil {
			// A per-stream deadline can mean a slow destination, not a dead
			// QUIC path. Keep the shared connection; auto mode opens its breaker
			// for new flows and lets this flow try TLS. A truly blackholed QUIC
			// connection will expire via QUIC's transport idle timeout.
			break
		}
		c.invalidate(conn)
		continue
	}
	if callerErr := contextError(ctx); callerErr != nil {
		c.primaryProbeFinished()
		return nil, callerErr
	}
	if c.fallback != nil {
		c.primaryFailed(time.Now())
		fallbackConn, fallbackErr := c.fallback.DialContext(ctx, network, address)
		if fallbackErr == nil {
			return fallbackConn, nil
		}
		return nil, errors.Join(primaryErr, fmt.Errorf("tunnel: TLS fallback: %w", fallbackErr))
	}
	c.primaryProbeFinished()
	if primaryErr == nil {
		primaryErr = errors.New("tunnel: QUIC connection unavailable")
	}
	return nil, primaryErr
}

// shouldTryPrimary returns false while the fallback circuit is open. Once the
// cooldown expires exactly one caller becomes the QUIC probe; concurrent
// callers keep using TLS instead of all paying the UDP timeout.
func (c *Client) shouldTryPrimary(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.primaryFailedAt.IsZero() {
		return true
	}
	if now.Before(c.primaryFailedAt.Add(c.fallbackCooldown)) {
		return false
	}
	if c.primaryProbing {
		return false
	}
	c.primaryProbing = true
	return true
}

func (c *Client) primarySucceeded() {
	c.mu.Lock()
	c.primaryFailedAt = time.Time{}
	c.primaryProbing = false
	c.mu.Unlock()
}

func (c *Client) primaryFailed(now time.Time) {
	c.mu.Lock()
	c.primaryFailedAt = now
	c.primaryProbing = false
	c.mu.Unlock()
}

func (c *Client) primaryProbeFinished() {
	c.mu.Lock()
	c.primaryProbing = false
	c.mu.Unlock()
}

func (c *Client) connection(ctx context.Context) (*quic.Conn, error) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, net.ErrClosed
		}
		if c.conn != nil && c.conn.Context().Err() == nil {
			conn := c.conn
			c.mu.Unlock()
			return conn, nil
		}
		if c.dialing != nil {
			attempt := c.dialing
			c.mu.Unlock()
			select {
			case <-attempt.done:
				if attempt.err != nil {
					return nil, attempt.err
				}
				continue
			case <-ctx.Done():
				return nil, context.Cause(ctx)
			case <-c.ctx.Done():
				return nil, net.ErrClosed
			}
		}

		dialCtx, cancel := context.WithTimeout(ctx, c.dialTimeout)
		attempt := &quicDialAttempt{done: make(chan struct{}), cancel: cancel}
		c.dialing = attempt
		c.mu.Unlock()

		conn, err := quic.DialAddr(dialCtx, c.address, c.tlsConfig.Clone(), c.quicConfig.Clone())
		cancel()

		c.mu.Lock()
		c.dialing = nil
		if err == nil && !c.closed {
			c.conn = conn
		} else if conn != nil {
			_ = conn.CloseWithError(applicationShutdown, "client closed")
		}
		if err != nil {
			attempt.err = fmt.Errorf("tunnel: dial QUIC: %w", err)
			// Publish the open circuit before waking waiters. Otherwise every
			// caller waiting on the same failed UDP handshake could start its
			// own sequential timeout before DialContext records the failure.
			if c.fallback != nil && ctx.Err() == nil && !c.closed {
				c.primaryFailedAt = time.Now()
				c.primaryProbing = false
			}
		}
		close(attempt.done)
		closed := c.closed
		c.mu.Unlock()
		if closed {
			return nil, net.ErrClosed
		}
		if attempt.err != nil {
			return nil, attempt.err
		}
		return conn, nil
	}
}

func (c *Client) invalidate(conn *quic.Conn) {
	c.mu.Lock()
	if c.conn == conn {
		c.conn = nil
	}
	c.mu.Unlock()
	_ = conn.CloseWithError(applicationShutdown, "reconnecting")
}

// Close closes the shared QUIC connection and the optional fallback dialer.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.cancel()
	if c.dialing != nil {
		c.dialing.cancel()
	}
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()
	if conn != nil {
		_ = conn.CloseWithError(applicationShutdown, "client closed")
	}
	if c.fallback != nil {
		return c.fallback.Close()
	}
	return nil
}

type quicStreamConn struct {
	stream *quic.Stream
	local  net.Addr
	remote net.Addr
	once   sync.Once

	writeMu      sync.Mutex
	writeClosed  bool
	writeAborted bool
}

func newQUICStreamConn(stream *quic.Stream, local, remote net.Addr) *quicStreamConn {
	return &quicStreamConn{stream: stream, local: local, remote: remote}
}

func (c *quicStreamConn) Read(p []byte) (int, error)         { return c.stream.Read(p) }
func (c *quicStreamConn) Write(p []byte) (int, error)        { return c.stream.Write(p) }
func (c *quicStreamConn) LocalAddr() net.Addr                { return c.local }
func (c *quicStreamConn) RemoteAddr() net.Addr               { return c.remote }
func (c *quicStreamConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *quicStreamConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *quicStreamConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }
func (c *quicStreamConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeAborted {
		return net.ErrClosed
	}
	if c.writeClosed {
		return nil
	}
	c.writeClosed = true
	return c.stream.Close()
}
func (c *quicStreamConn) CloseRead() error {
	c.stream.CancelRead(streamCanceled)
	return nil
}
func (c *quicStreamConn) Close() error {
	c.once.Do(func() {
		c.stream.CancelRead(streamCanceled)
		c.writeMu.Lock()
		if !c.writeClosed {
			c.writeAborted = true
			c.stream.CancelWrite(streamCanceled)
		}
		c.writeMu.Unlock()
	})
	return nil
}

var _ transport.Dialer = (*Client)(nil)
var _ net.Conn = (*quicStreamConn)(nil)
