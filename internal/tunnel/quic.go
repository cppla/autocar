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

	"github.com/cppla/autocar/internal/accel"
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
	// StreamAdmission optionally shares the active-stream budget with other
	// server transports. When set, MaxConcurrentStreams must be zero or equal
	// to the admission limit. Nil preserves the independent-server behavior.
	StreamAdmission *StreamAdmission
	// MaxConnections bounds accepted QUIC connections, including authenticated
	// idle sessions. Zero uses a conservative default.
	MaxConnections int
	// MaxClientConnections bounds concurrent QUIC sessions per source IPv4 or
	// IPv6 /64. Zero uses a conservative default no larger than MaxConnections.
	MaxClientConnections int
	// Pacing controls the relay-to-client application sender. MaxTx is the
	// relay sender's fixed rate or negotiation ceiling; MaxRx caps an accepted
	// client-to-relay fixed rate. Rates are bytes per second.
	Pacing           PacingConfig
	MaxTx            uint64
	MaxRx            uint64
	AllowClientRates bool
	// UDPResolver resolves datagram destinations. When nil, a Dialer that
	// implements UDPResolver is preferred before the system resolver is used.
	UDPResolver UDPResolver
	// MaxUDPSessions bounds live UDP associations across all QUIC connections.
	MaxUDPSessions int
	// MaxClientUDPSessions bounds live UDP associations per source IPv4 or
	// IPv6 /64.
	MaxClientUDPSessions int
	// MaxUDPDestinations bounds the numeric destinations authorized by one UDP
	// association.
	MaxUDPDestinations int
	// UDPReceiveQueue bounds complete client datagrams awaiting one session's
	// UDP socket worker and connection-wide outbound datagrams awaiting QUIC.
	UDPReceiveQueue int
	// UDPReassemblyTTL is the fixed lifetime of an incomplete fragmented UDP
	// message. Duplicate fragments do not extend it.
	UDPReassemblyTTL time.Duration
	// MaxUDPReassemblyMessages and MaxUDPReassemblyBytes bound incomplete
	// messages on each QUIC connection.
	MaxUDPReassemblyMessages int
	MaxUDPReassemblyBytes    int
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
	streamSem chan struct{}
	clients   *sourceConnectionLimiter
	udp       *serverUDPManager
	pacing    PacingConfig
	maxTx     uint64
	maxRx     uint64
	allowRate bool
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
	core, err := newServerCoreWithAdmission(
		config.Token,
		config.Dialer,
		config.HandshakeTimeout,
		config.DialTimeout,
		config.MaxConcurrentStreams,
		config.StreamAdmission,
	)
	if err != nil {
		return nil, err
	}
	udp, err := newServerUDPManager(config, core.dialer, core.dialTimeout)
	if err != nil {
		return nil, err
	}
	if _, err := newServerPacingNegotiator(config.Pacing, config.MaxTx, config.MaxRx, config.AllowClientRates); err != nil {
		return nil, err
	}
	if config.MaxConnections < 0 {
		return nil, errors.New("tunnel: maximum QUIC connections cannot be negative")
	}
	maxConnections := config.MaxConnections
	if maxConnections == 0 {
		maxConnections = defaultMaxConnections
	}
	maxClientConnections := config.MaxClientConnections
	if maxClientConnections < 0 {
		return nil, errors.New("tunnel: maximum QUIC client connections cannot be negative")
	}
	if maxClientConnections == 0 {
		maxClientConnections = min(defaultMaxClientConnections, maxConnections)
	}
	if maxClientConnections > maxConnections {
		return nil, fmt.Errorf(
			"tunnel: maximum QUIC client connections (%d) exceeds maximum connections (%d)",
			maxClientConnections,
			maxConnections,
		)
	}
	quicConfig := hardenedQUICServerConfig(config.QUICConfig, cap(core.sem))
	listener, err := quic.ListenAddr(config.Address, tlsConfig, quicConfig)
	if err != nil {
		return nil, fmt.Errorf("tunnel: listen QUIC: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &QUICServer{
		listener:  listener,
		core:      core,
		ctx:       ctx,
		cancel:    cancel,
		conns:     make(map[*quic.Conn]struct{}),
		connSem:   make(chan struct{}, maxConnections),
		streamSem: make(chan struct{}, cap(core.sem)),
		clients:   newSourceConnectionLimiter(maxClientConnections),
		udp:       udp,
		pacing:    config.Pacing,
		maxTx:     config.MaxTx,
		maxRx:     config.MaxRx,
		allowRate: config.AllowClientRates,
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
	cfg.EnableDatagrams = true
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
		sourceKey := tlsSourceKey(conn.RemoteAddr())
		if !s.clients.acquire(sourceKey) {
			<-s.connSem
			s.lifecycle.Unlock()
			_ = conn.CloseWithError(connectionRejected, "per-source connection limit reached")
			continue
		}
		s.connMu.Lock()
		s.conns[conn] = struct{}{}
		s.connMu.Unlock()
		s.wg.Add(1)
		s.lifecycle.Unlock()
		go s.serveConnection(conn, sourceKey)
	}
}

func (s *QUICServer) serveConnection(conn *quic.Conn, sourceKey string) {
	defer s.wg.Done()
	defer func() { <-s.connSem }()
	defer s.clients.release(sourceKey)
	defer func() {
		s.connMu.Lock()
		delete(s.conns, conn)
		s.connMu.Unlock()
	}()
	pacing, err := newServerPacingNegotiator(s.pacing, s.maxTx, s.maxRx, s.allowRate)
	if err != nil {
		_ = conn.CloseWithError(connectionRejected, "pacing unavailable")
		return
	}
	datagrams, err := newServerDatagramDispatcher(conn, s.udp, sourceKey, pacing.pacer)
	if err != nil {
		_ = conn.CloseWithError(connectionRejected, "datagram dispatcher unavailable")
		return
	}
	defer datagrams.Close()

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
		wrapped := newQUICStreamConn(stream, conn, pacing.pacer)
		s.lifecycle.Lock()
		if s.closing {
			s.lifecycle.Unlock()
			_ = wrapped.Close()
			return
		}
		select {
		case s.streamSem <- struct{}{}:
		default:
			s.lifecycle.Unlock()
			_ = wrapped.SetDeadline(time.Now().Add(time.Second))
			_ = protocol.WriteResponse(wrapped, protocol.Response{
				Status: protocol.StatusBusy, Message: "server busy",
			})
			finishStream(wrapped)
			continue
		}
		s.wg.Add(1)
		s.lifecycle.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() { <-s.streamSem }()
			// A QUIC stream has an independent lifecycle. In particular, the
			// peer's STOP_SENDING cancels stream.Context without killing sibling
			// streams, allowing an abandoned CONNECT to cancel DNS/dial promptly.
			handler := func(ctx context.Context, requestStream deadlineConn, request protocol.Request) streamRequestOptions {
				response, negotiateErr := pacing.negotiate(request)
				if negotiateErr != nil {
					_ = protocol.WriteResponse(requestStream, protocol.Response{
						Status: protocol.StatusBadRequest, Message: "invalid pacing metadata",
					})
					return streamRequestOptions{Handled: true}
				}
				if request.Network == protocol.NetworkUDP {
					return datagrams.handleRequest(ctx, requestStream, request, response)
				}
				return streamRequestOptions{Response: response, Relay: requestStream}
			}
			s.core.handleStream(stream.Context(), wrapped, markAuthenticated, handler)
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
	// Pacing controls the client-to-relay application sender. MaxTx is the
	// requested fixed sender rate and MaxRx is the requested relay sender rate,
	// both in bytes per second.
	Pacing PacingConfig
	MaxTx  uint64
	MaxRx  uint64
	// MaxUDPSessions bounds live UDP associations on the shared QUIC
	// connection. UDPReceiveQueue bounds complete responses awaiting each
	// PacketConn consumer and connection-wide outbound datagrams awaiting QUIC.
	MaxUDPSessions  int
	UDPReceiveQueue int
	// UDPReassemblyTTL, MaxUDPReassemblyMessages and
	// MaxUDPReassemblyBytes bound incomplete server responses.
	UDPReassemblyTTL         time.Duration
	MaxUDPReassemblyMessages int
	MaxUDPReassemblyBytes    int
	// EventHandler receives low-cardinality fallback and recovery transitions.
	// Events never contain relay addresses, destinations, credentials, or raw
	// error strings. Callbacks are dispatched asynchronously, serialized in
	// transition order, and should return promptly so observations stay current.
	EventHandler ClientEventHandler
}

// Client is a concurrent transport.Dialer backed by one lazily established,
// long-lived QUIC connection.
type Client struct {
	address          string
	token            string
	tlsConfig        *tls.Config
	quicConfig       *quic.Config
	dialQUIC         func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error)
	handshakeTimeout time.Duration
	dialTimeout      time.Duration
	primaryTimeout   time.Duration
	fallback         *TLSClient
	fallbackCooldown time.Duration
	pacing           PacingConfig
	maxTx            uint64
	maxRx            uint64
	txMode           protocol.PacingMode
	txProfile        protocol.PacingProfile

	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	conn    *quic.Conn
	pacer   *connectionPacer
	dialing *quicDialAttempt
	closed  bool
	// primaryFailedAt and primaryProbing implement a small circuit breaker.
	// They are guarded by mu together with the QUIC connection state.
	primaryFailedAt   time.Time
	primaryProbing    bool
	localMode         string
	localRate         uint64
	remoteMode        string
	remoteRate        uint64
	selectedTransport string
	eventHandler      ClientEventHandler
	primaryFailReason ClientEventReason
	lastEvent         ClientEvent
	// lastSelectedFallback describes the most recently completed path. It is
	// deliberately independent from primaryFailedAt: a TLS dial that completes
	// after a concurrent QUIC recovery is still the latest real selection, but
	// it does not reopen the QUIC circuit.
	lastSelectedFallback bool
	eventMu              sync.Mutex
	eventQueue           []ClientEvent
	eventDispatching     bool

	udpConfig      clientUDPConfig
	udpMu          sync.Mutex
	udpDispatchers map[*quic.Conn]*clientDatagramDispatcher
}

type quicDialAttempt struct {
	done   chan struct{}
	cancel context.CancelFunc
	err    error
}

type clientPathMetadata struct {
	localMode  string
	localRate  uint64
	remoteMode string
	remoteRate uint64
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
	if config.MaxTx > protocol.MaxRate || config.MaxRx > protocol.MaxRate {
		return nil, errors.New("tunnel: pacing rate exceeds protocol maximum")
	}
	mode := config.Pacing.Mode
	if mode == "" {
		mode = accel.ModeAdaptive
	}
	if mode != accel.ModeFixedRate && config.MaxTx != 0 {
		return nil, errors.New("tunnel: MaxTx requires fixed-rate client pacing")
	}
	basePacer, err := newConnectionPacer(config.Pacing, config.MaxTx)
	if err != nil {
		return nil, err
	}
	txMode, txProfile, _ := basePacer.metadata()
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
	udpConfig, err := normalizeClientUDPConfig(config)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		address:          config.ServerAddress,
		token:            config.Token,
		tlsConfig:        tlsConfig,
		quicConfig:       hardenedQUICClientConfig(config.QUICConfig),
		dialQUIC:         quic.DialAddr,
		handshakeTimeout: handshakeTimeout,
		dialTimeout:      dialTimeout,
		primaryTimeout:   primaryTimeout,
		pacing:           config.Pacing,
		maxTx:            config.MaxTx,
		maxRx:            config.MaxRx,
		txMode:           txMode,
		txProfile:        txProfile,
		ctx:              ctx,
		cancel:           cancel,
		udpConfig:        udpConfig,
		udpDispatchers:   make(map[*quic.Conn]*clientDatagramDispatcher),
		localMode:        basePacer.label(),
		eventHandler:     config.EventHandler,
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
	cfg.EnableDatagrams = true
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
	request := protocol.Request{
		Network: n, Token: []byte(c.token), Address: address,
		MaxTx: c.maxTx, MaxRx: c.maxRx,
		TxMode: c.txMode, TxProfile: c.txProfile,
	}
	// Validate the complete request before any network activity.
	if err := protocol.WriteRequest(io.Discard, request); err != nil {
		return nil, err
	}
	if c.fallback != nil {
		tryPrimary, fallbackReason := c.shouldTryPrimary(time.Now())
		if !tryPrimary {
			fallbackConn, fallbackErr := c.fallback.DialContext(ctx, network, address)
			if fallbackErr == nil {
				c.recordFallback(fallbackReason)
			}
			return fallbackConn, fallbackErr
		}
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
	fallbackReason := ClientReasonQUICDialFailed
	for attempt := 0; attempt < 2; attempt++ {
		if err := contextError(ctx); err != nil {
			c.primaryProbeFinished()
			return nil, err
		}
		if err := contextError(primaryCtx); err != nil {
			primaryErr = fmt.Errorf("tunnel: QUIC attempt budget exhausted: %w", err)
			fallbackReason = ClientReasonQUICAttemptTimeout
			break
		}
		conn, err := c.connection(primaryCtx)
		if err != nil {
			if callerErr := contextError(ctx); callerErr != nil {
				c.primaryProbeFinished()
				return nil, callerErr
			}
			primaryErr = err
			if contextError(primaryCtx) != nil {
				fallbackReason = ClientReasonQUICAttemptTimeout
			}
			break
		}
		stream, err := conn.OpenStreamSync(primaryCtx)
		if err != nil {
			primaryErr = fmt.Errorf("tunnel: open QUIC stream: %w", err)
			fallbackReason = ClientReasonQUICStreamOpenFailed
			if callerErr := contextError(ctx); callerErr != nil {
				c.primaryProbeFinished()
				return nil, callerErr
			}
			if contextError(primaryCtx) != nil {
				fallbackReason = ClientReasonQUICAttemptTimeout
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
		wrapped := newQUICStreamConn(stream, conn, c.connectionPacer(conn))
		var response protocol.Response
		response, err = openProtocolRequest(primaryCtx, wrapped, request, c.handshakeTimeout)
		if err == nil {
			metadata, pacingErr := c.acceptPacingResponse(conn, response, 0, false)
			if pacingErr != nil {
				_ = wrapped.Close()
				primaryErr = fmt.Errorf("tunnel: invalid pacing response: %w", pacingErr)
				fallbackReason = ClientReasonQUICPacingRejected
				break
			}
			c.primarySucceeded(metadata)
			return wrapped, nil
		}
		_ = wrapped.Close()
		var remoteErr *RemoteError
		if errors.As(err, &remoteErr) {
			// A valid authenticated response proves the QUIC path is healthy.
			// Destination and authorization failures must never trip the
			// transport circuit breaker.
			c.primaryHealthy()
			return nil, err
		}
		primaryErr = fmt.Errorf("tunnel: QUIC stream handshake: %w", err)
		fallbackReason = ClientReasonQUICHandshakeFailed
		if callerErr := contextError(ctx); callerErr != nil {
			// A caller controls only its own stream. Canceling one request must
			// never tear down the multiplexed connection and every other flow.
			c.primaryProbeFinished()
			return nil, callerErr
		}
		if contextError(primaryCtx) != nil || conn.Context().Err() == nil {
			if contextError(primaryCtx) != nil {
				fallbackReason = ClientReasonQUICAttemptTimeout
			}
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
		c.primaryFailed(time.Now(), fallbackReason)
		fallbackConn, fallbackErr := c.fallback.DialContext(ctx, network, address)
		if fallbackErr == nil {
			c.recordFallback(fallbackReason)
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
func (c *Client) shouldTryPrimary(now time.Time) (bool, ClientEventReason) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.primaryFailedAt.IsZero() {
		return true, ""
	}
	if now.Before(c.primaryFailedAt.Add(c.fallbackCooldown)) {
		return false, c.activePrimaryFailureReason()
	}
	if c.primaryProbing {
		return false, c.activePrimaryFailureReason()
	}
	c.primaryProbing = true
	return true, ""
}

func (c *Client) primarySucceeded(metadata clientPathMetadata) {
	var event ClientEvent
	dispatchEvents := false
	c.mu.Lock()
	recovered := c.lastSelectedFallback
	c.localMode = metadata.localMode
	c.localRate = metadata.localRate
	c.remoteMode = metadata.remoteMode
	c.remoteRate = metadata.remoteRate
	c.selectedTransport = "quic"
	c.primaryFailedAt = time.Time{}
	c.primaryProbing = false
	c.primaryFailReason = ""
	c.lastSelectedFallback = false
	if recovered {
		event = ClientEvent{
			Kind:   ClientEventRecovery,
			Reason: ClientReasonQUICPathRestored,
			At:     time.Now().UTC(),
		}
		c.lastEvent = event
		dispatchEvents = c.enqueueClientEvent(event)
	}
	c.mu.Unlock()
	if dispatchEvents {
		go c.dispatchClientEvents()
	}
}

// primaryHealthy closes the fallback circuit after a valid authenticated QUIC
// response that did not open a destination. It intentionally does not claim a
// successful QUIC selection or emit a recovery transition.
func (c *Client) primaryHealthy() {
	c.mu.Lock()
	c.primaryFailedAt = time.Time{}
	c.primaryProbing = false
	c.primaryFailReason = ""
	c.mu.Unlock()
}

func (c *Client) primaryFailed(now time.Time, reason ClientEventReason) {
	c.mu.Lock()
	c.primaryFailedAt = now
	c.primaryProbing = false
	c.primaryFailReason = reason
	c.mu.Unlock()
}

func (c *Client) primaryProbeFinished() {
	c.mu.Lock()
	c.primaryProbing = false
	c.mu.Unlock()
}

func (c *Client) acceptPacingResponse(conn *quic.Conn, response protocol.Response, sessionID uint32, assignedSession bool) (clientPathMetadata, error) {
	if err := c.validatePacingResponse(response, sessionID, assignedSession); err != nil {
		return clientPathMetadata{}, err
	}
	pacer := c.connectionPacer(conn)
	if pacer == nil {
		return clientPathMetadata{}, net.ErrClosed
	}
	if response.MaxTx != 0 {
		if err := pacer.setFixedRate(response.MaxTx); err != nil {
			return clientPathMetadata{}, err
		}
	}
	localMode, localProfile, _ := pacer.metadata()
	if localMode != response.TxMode || localProfile != response.TxProfile {
		return clientPathMetadata{}, errors.New("response changed the client sender identity")
	}
	remoteMode := pacingModeName(response.RxMode, response.RxProfile)
	if remoteMode == "" {
		return clientPathMetadata{}, errors.New("response contains an unknown relay sender")
	}
	return clientPathMetadata{
		localMode:  pacingModeName(localMode, localProfile),
		localRate:  response.MaxTx,
		remoteMode: remoteMode,
		remoteRate: response.MaxRx,
	}, nil
}

func (c *Client) validatePacingResponse(response protocol.Response, sessionID uint32, assignedSession bool) error {
	if assignedSession && response.SessionID == 0 {
		return errors.New("response omitted the assigned session ID")
	}
	if !assignedSession && response.SessionID != sessionID {
		return errors.New("response contains the wrong session ID")
	}
	if response.TxMode == protocol.PacingUnspecified || response.TxProfile == protocol.ProfileUnspecified ||
		response.RxMode == protocol.PacingUnspecified || response.RxProfile == protocol.ProfileUnspecified {
		return errors.New("response omitted sender pacing metadata")
	}
	if (response.MaxTx != 0) != (response.TxMode == protocol.PacingFixedRate) {
		return errors.New("response client rate and sender mode disagree")
	}
	if (response.MaxRx != 0) != (response.RxMode == protocol.PacingFixedRate) {
		return errors.New("response relay rate and sender mode disagree")
	}
	if response.TxMode != c.txMode || response.TxProfile != c.txProfile {
		return errors.New("response changed the client sender identity")
	}
	if c.maxTx == 0 && response.MaxTx != 0 {
		return errors.New("response introduced an unrequested client fixed rate")
	}
	if c.maxTx != 0 && (response.MaxTx == 0 || response.MaxTx > c.maxTx) {
		return errors.New("response client rate is not a valid cap of the requested rate")
	}
	if c.maxRx != 0 && (response.MaxRx == 0 || response.MaxRx > c.maxRx) {
		return errors.New("response relay rate is not a valid cap of the requested rate")
	}
	return nil
}

func (c *Client) recordFallback(reason ClientEventReason) {
	if reason == "" {
		reason = ClientReasonQUICCooldownActive
	}
	var event ClientEvent
	dispatchEvents := false
	c.mu.Lock()
	transitioned := !c.lastSelectedFallback
	c.localMode = "tls-fallback"
	c.localRate = 0
	c.remoteMode = "tls-fallback"
	c.remoteRate = 0
	c.selectedTransport = "tls"
	c.lastSelectedFallback = true
	if transitioned {
		event = ClientEvent{Kind: ClientEventFallback, Reason: reason, At: time.Now().UTC()}
		c.lastEvent = event
		dispatchEvents = c.enqueueClientEvent(event)
	}
	c.mu.Unlock()
	if dispatchEvents {
		go c.dispatchClientEvents()
	}
}

// activePrimaryFailureReason must be called with c.mu held.
func (c *Client) activePrimaryFailureReason() ClientEventReason {
	if c.primaryFailReason != "" {
		return c.primaryFailReason
	}
	return ClientReasonQUICCooldownActive
}

// SelectedTransport reports the authenticated path used by the most recent
// successful stream or datagram association.
func (c *Client) SelectedTransport() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.selectedTransport
}

// AccelerationMode reports the sender policy used by the most recent
// successful client-to-relay path.
func (c *Client) AccelerationMode() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.localMode
}

// NegotiatedTx reports the effective client-to-relay fixed rate in bytes/s.
func (c *Client) NegotiatedTx() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.localRate
}

// RemoteTxAcceleration reports the authenticated relay sender used by the
// most recent successful QUIC stream. It is directionally distinct from the
// client's local sender.
func (c *Client) RemoteTxAcceleration() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.remoteMode
}

// RemoteNegotiatedTx reports the effective relay-to-client fixed rate.
func (c *Client) RemoteNegotiatedTx() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.remoteRate
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
		attempt := c.dialing
		if attempt == nil {
			// A connection attempt is shared transport state, so its lifetime is
			// derived from the client rather than from whichever caller happened to
			// arrive first. Every caller still waits with its own context below.
			dialCtx, cancel := context.WithTimeout(c.ctx, c.dialTimeout)
			attempt = &quicDialAttempt{done: make(chan struct{}), cancel: cancel}
			c.dialing = attempt
			go c.runQUICDial(attempt, dialCtx)
		}
		c.mu.Unlock()

		select {
		case <-attempt.done:
			if attempt.err != nil {
				if err := contextError(ctx); err != nil {
					return nil, err
				}
				return nil, attempt.err
			}
			continue
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-c.ctx.Done():
			return nil, net.ErrClosed
		}
	}
}

func (c *Client) runQUICDial(attempt *quicDialAttempt, dialCtx context.Context) {
	defer attempt.cancel()
	conn, err := c.dialQUIC(dialCtx, c.address, c.tlsConfig.Clone(), c.quicConfig.Clone())
	var pacer *connectionPacer
	if err == nil {
		pacer, err = newConnectionPacer(c.pacing, c.maxTx)
		if err != nil {
			_ = conn.CloseWithError(applicationShutdown, "pacing unavailable")
		}
	}

	c.mu.Lock()
	if c.dialing == attempt {
		c.dialing = nil
	}
	if err == nil && !c.closed {
		c.conn = conn
		c.pacer = pacer
	} else if conn != nil {
		_ = conn.CloseWithError(applicationShutdown, "client closed")
	}
	if err != nil {
		attempt.err = fmt.Errorf("tunnel: dial QUIC: %w", err)
		// Publish the open circuit before waking waiters. Otherwise callers
		// waiting on the same failed UDP handshake could each pay another timeout.
		if c.fallback != nil && !c.closed && c.ctx.Err() == nil {
			c.primaryFailedAt = time.Now()
			c.primaryProbing = false
			c.primaryFailReason = ClientReasonQUICDialFailed
		}
	}
	close(attempt.done)
	c.mu.Unlock()
}

func (c *Client) invalidate(conn *quic.Conn) {
	c.mu.Lock()
	if c.conn == conn {
		c.conn = nil
		c.pacer = nil
	}
	c.mu.Unlock()
	_ = conn.CloseWithError(applicationShutdown, "reconnecting")
}

// Close closes the shared QUIC connection and the optional fallback dialer.
// It does not wait for best-effort observability callbacks; a callback already
// in flight may return after Close.
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
	c.pacer = nil
	c.mu.Unlock()
	if conn != nil {
		_ = conn.CloseWithError(applicationShutdown, "client closed")
	}
	c.closeDatagramDispatchers()
	if c.fallback != nil {
		return c.fallback.Close()
	}
	return nil
}

func (c *Client) connectionPacer(conn *quic.Conn) *connectionPacer {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != conn {
		return nil
	}
	return c.pacer
}

type quicStream interface {
	io.ReadWriteCloser
	Context() context.Context
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
}

type quicWritePacer interface {
	wait(context.Context, int, *quic.Conn) error
	maxChunkBytes() int
}

type quicStreamConn struct {
	stream               quicStream
	conn                 *quic.Conn
	pacer                quicWritePacer
	local                net.Addr
	remote               net.Addr
	once                 sync.Once
	paceCtx              context.Context
	paceCancel           context.CancelFunc
	deadlineMu           sync.Mutex
	writeDeadline        time.Time
	deadlineGeneration   uint64
	activePaceGeneration uint64
	activePaceCancel     context.CancelFunc

	writeMu      sync.Mutex
	writeStateMu sync.Mutex
	writeClosed  bool
	writeAborted bool
}

func newQUICStreamConn(stream quicStream, conn *quic.Conn, pacer *connectionPacer) *quicStreamConn {
	var writePacer quicWritePacer
	if pacer != nil {
		writePacer = pacer
	}
	return newQUICStreamConnWithPacer(stream, conn, writePacer)
}

func newQUICStreamConnWithPacer(stream quicStream, conn *quic.Conn, pacer quicWritePacer) *quicStreamConn {
	paceCtx, paceCancel := context.WithCancel(stream.Context())
	var local, remote net.Addr
	if conn != nil {
		local = conn.LocalAddr()
		remote = conn.RemoteAddr()
	}
	return &quicStreamConn{
		stream: stream, conn: conn, pacer: pacer,
		local: local, remote: remote,
		paceCtx: paceCtx, paceCancel: paceCancel,
	}
}

func (c *quicStreamConn) Read(p []byte) (int, error) { return c.stream.Read(p) }
func (c *quicStreamConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.writeStateMu.Lock()
	closed := c.writeClosed || c.writeAborted
	c.writeStateMu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	chunkSize := len(p)
	if c.pacer != nil {
		maxChunk := c.pacer.maxChunkBytes()
		if maxChunk > 0 && chunkSize > maxChunk {
			chunkSize = maxChunk
		}
	}
	for written := 0; written < len(p); {
		end := written + chunkSize
		if end > len(p) {
			end = len(p)
		}
		chunk := p[written:end]
		if c.pacer != nil {
			if err := c.waitForPacing(len(chunk)); err != nil {
				if c.paceCtx.Err() != nil {
					return written, net.ErrClosed
				}
				return written, err
			}
		}
		n, err := c.stream.Write(chunk)
		written += n
		if err != nil {
			return written, err
		}
		if n != len(chunk) {
			return written, io.ErrShortWrite
		}
	}
	if len(p) == 0 {
		return c.stream.Write(p)
	}
	return len(p), nil
}

func (c *quicStreamConn) waitForPacing(bytes int) error {
	for {
		c.deadlineMu.Lock()
		generation := c.deadlineGeneration
		deadline := c.writeDeadline
		baseCtx, cancelActive := context.WithCancel(c.paceCtx)
		waitCtx := baseCtx
		cancelDeadline := func() {}
		if !deadline.IsZero() {
			waitCtx, cancelDeadline = context.WithDeadline(baseCtx, deadline)
		}
		c.activePaceGeneration = generation
		c.activePaceCancel = cancelActive
		c.deadlineMu.Unlock()

		err := c.pacer.wait(waitCtx, bytes, c.conn)
		cancelDeadline()
		cancelActive()

		c.deadlineMu.Lock()
		deadlineChanged := generation != c.deadlineGeneration
		if c.activePaceGeneration == generation {
			c.activePaceCancel = nil
		}
		c.deadlineMu.Unlock()
		contextInterrupted := errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
		if deadlineChanged && c.paceCtx.Err() == nil && contextInterrupted {
			// net.Conn deadlines apply to pending I/O. Re-enter the wait with
			// the newly installed deadline instead of treating an extension or
			// clear as a spurious write failure.
			continue
		}
		return err
	}
}

func (c *quicStreamConn) LocalAddr() net.Addr  { return c.local }
func (c *quicStreamConn) RemoteAddr() net.Addr { return c.remote }
func (c *quicStreamConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineGeneration++
	if c.activePaceCancel != nil {
		c.activePaceCancel()
	}
	err := c.stream.SetDeadline(t)
	c.deadlineMu.Unlock()
	return err
}
func (c *quicStreamConn) SetReadDeadline(t time.Time) error { return c.stream.SetReadDeadline(t) }
func (c *quicStreamConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineGeneration++
	if c.activePaceCancel != nil {
		c.activePaceCancel()
	}
	err := c.stream.SetWriteDeadline(t)
	c.deadlineMu.Unlock()
	return err
}
func (c *quicStreamConn) CloseWrite() error {
	c.paceCancel()
	// quic-go requires SendStream.Close and Write to be serialized. An orderly
	// half-close may therefore wait for the current Write; the aborting Close
	// path below uses CancelWrite without this mutex to unblock a stalled Write.
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.writeStateMu.Lock()
	if c.writeAborted {
		c.writeStateMu.Unlock()
		return net.ErrClosed
	}
	if c.writeClosed {
		c.writeStateMu.Unlock()
		return nil
	}
	c.writeClosed = true
	c.writeStateMu.Unlock()
	return c.stream.Close()
}
func (c *quicStreamConn) CloseRead() error {
	c.stream.CancelRead(streamCanceled)
	return nil
}
func (c *quicStreamConn) Close() error {
	c.once.Do(func() {
		c.paceCancel()
		c.stream.CancelRead(streamCanceled)
		// CancelWrite must happen without waiting for writeMu: a flow-controlled
		// stream.Write holds that mutex while blocked, and net.Conn.Close is
		// required to unblock it.
		c.writeStateMu.Lock()
		shouldCancelWrite := !c.writeClosed
		c.writeAborted = true
		c.writeStateMu.Unlock()
		if shouldCancelWrite {
			c.stream.CancelWrite(streamCanceled)
		}
	})
	return nil
}

var _ transport.Dialer = (*Client)(nil)
var _ transport.PacketDialer = (*Client)(nil)
var _ net.Conn = (*quicStreamConn)(nil)
