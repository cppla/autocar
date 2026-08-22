package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/transport"
)

// TLSServerConfig configures the TCP+TLS fallback exit listener.
type TLSServerConfig struct {
	Address              string
	Token                string
	TLSConfig            *tls.Config
	Dialer               transport.Dialer
	HandshakeTimeout     time.Duration
	DialTimeout          time.Duration
	MaxConcurrentStreams int
	MaxClientConnections int
}

// TLSServer serves one tunneled TCP stream per TLS 1.3 connection. It is a
// censorship / UDP-blocking fallback, not the preferred multiplexed path.
type TLSServer struct {
	listener  net.Listener
	tlsConfig *tls.Config
	core      *serverCore
	clients   *sourceConnectionLimiter

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
	conns     map[net.Conn]struct{}
}

// ListenTLS binds the TCP listener. Call Serve to accept traffic.
func ListenTLS(config TLSServerConfig) (*TLSServer, error) {
	if config.Address == "" {
		return nil, errors.New("tunnel: TLS listen address is required")
	}
	tlsConfig, err := serverTLSConfig(config.TLSConfig)
	if err != nil {
		return nil, err
	}
	core, err := newServerCore(config.Token, config.Dialer, config.HandshakeTimeout, config.DialTimeout, config.MaxConcurrentStreams)
	if err != nil {
		return nil, err
	}
	maxClientConnections := config.MaxClientConnections
	if maxClientConnections < 0 {
		return nil, errors.New("tunnel: maximum TLS client connections cannot be negative")
	}
	if maxClientConnections == 0 {
		maxClientConnections = min(defaultMaxClientConnections, cap(core.sem))
	}
	if maxClientConnections > cap(core.sem) {
		return nil, fmt.Errorf("tunnel: maximum TLS client connections (%d) exceeds maximum concurrent streams (%d)", maxClientConnections, cap(core.sem))
	}
	listener, err := net.Listen("tcp", config.Address)
	if err != nil {
		return nil, fmt.Errorf("tunnel: listen TLS fallback: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &TLSServer{
		listener:  listener,
		tlsConfig: tlsConfig,
		core:      core,
		clients:   newSourceConnectionLimiter(maxClientConnections),
		ctx:       ctx,
		cancel:    cancel,
		conns:     make(map[net.Conn]struct{}),
	}, nil
}

// Addr returns the bound TCP address.
func (s *TLSServer) Addr() net.Addr { return s.listener.Addr() }

// Serve accepts TLS fallback connections until ctx is canceled or Close is
// called. Canceling ctx closes all active connections.
func (s *TLSServer) Serve(ctx context.Context) error {
	if ctx == nil {
		return errors.New("tunnel: nil serve context")
	}
	s.serveMu.Lock()
	if s.serving {
		s.serveMu.Unlock()
		return errors.New("tunnel: TLS server already serving")
	}
	s.serving = true
	s.serveMu.Unlock()

	acceptCtx, cancel := context.WithCancel(ctx)
	stopServer := context.AfterFunc(s.ctx, cancel)
	defer stopServer()
	defer cancel()
	defer s.Close()
	stopListener := context.AfterFunc(acceptCtx, func() { _ = s.listener.Close() })
	defer stopListener()

	for {
		raw, err := s.listener.Accept()
		if err != nil {
			if acceptCtx.Err() != nil || s.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("tunnel: accept TLS fallback: %w", err)
		}
		s.lifecycle.Lock()
		if s.closing || acceptCtx.Err() != nil {
			s.lifecycle.Unlock()
			_ = raw.Close()
			if acceptCtx.Err() != nil {
				return nil
			}
			continue
		}
		if !s.core.acquire() {
			s.lifecycle.Unlock()
			_ = raw.Close()
			continue
		}
		sourceKey := tlsSourceKey(raw.RemoteAddr())
		if !s.clients.acquire(sourceKey) {
			s.core.release()
			s.lifecycle.Unlock()
			_ = raw.Close()
			continue
		}
		tlsConn := tls.Server(raw, s.tlsConfig)
		s.connMu.Lock()
		s.conns[tlsConn] = struct{}{}
		s.connMu.Unlock()
		s.wg.Add(1)
		s.lifecycle.Unlock()
		go s.serveTLSConnection(acceptCtx, tlsConn, sourceKey)
	}
}

func (s *TLSServer) serveTLSConnection(ctx context.Context, conn *tls.Conn, sourceKey string) {
	defer s.wg.Done()
	defer s.core.release()
	defer s.clients.release(sourceKey)
	defer func() {
		s.connMu.Lock()
		delete(s.conns, conn)
		s.connMu.Unlock()
		_ = conn.Close()
	}()
	handshakeCtx, cancel := context.WithTimeout(ctx, s.core.handshakeTimeout)
	err := conn.HandshakeContext(handshakeCtx)
	cancel()
	if err != nil || conn.ConnectionState().NegotiatedProtocol != protocol.ALPN {
		return
	}
	s.core.handleStream(ctx, conn, nil)
}

type sourceConnectionLimiter struct {
	mu     sync.Mutex
	limit  int
	active map[string]int
}

func newSourceConnectionLimiter(limit int) *sourceConnectionLimiter {
	return &sourceConnectionLimiter{limit: limit, active: make(map[string]int)}
}

func (l *sourceConnectionLimiter) acquire(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active[key] >= l.limit {
		return false
	}
	l.active[key]++
	return true
}

func (l *sourceConnectionLimiter) release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active[key] <= 1 {
		delete(l.active, key)
		return
	}
	l.active[key]--
}

func (l *sourceConnectionLimiter) count(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.active[key]
}

func tlsSourceKey(address net.Addr) string {
	if address == nil {
		return ""
	}
	if tcpAddress, ok := address.(*net.TCPAddr); ok {
		if ip, ok := netip.AddrFromSlice(tcpAddress.IP); ok {
			return sourceIPKey(ip)
		}
	}
	host, _, err := net.SplitHostPort(address.String())
	if err == nil {
		if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
			return sourceIPKey(ip)
		}
	}
	// Unknown address representations share one conservative bucket. Including
	// an unparsed port here would let a peer obtain a fresh bucket per socket.
	return ""
}

func sourceIPKey(ip netip.Addr) string {
	ip = ip.Unmap().WithZone("")
	if ip.Is4() {
		return ip.String()
	}
	if ip.Is6() {
		return netip.PrefixFrom(ip, 64).Masked().String()
	}
	return ""
}

// Close stops the listener, closes active connections and waits for relays.
func (s *TLSServer) Close() error {
	s.closeOnce.Do(func() {
		s.lifecycle.Lock()
		s.closing = true
		s.lifecycle.Unlock()
		s.cancel()
		s.closeErr = s.listener.Close()
		s.connMu.Lock()
		connections := make([]net.Conn, 0, len(s.conns))
		for conn := range s.conns {
			connections = append(connections, conn)
		}
		s.connMu.Unlock()
		for _, conn := range connections {
			_ = conn.Close()
		}
		s.wg.Wait()
	})
	return s.closeErr
}

// TLSClientConfig configures the per-stream TCP+TLS fallback transport.
type TLSClientConfig struct {
	ServerAddress    string
	Token            string
	TLSConfig        *tls.Config
	HandshakeTimeout time.Duration
	DialTimeout      time.Duration
}

// TLSClient implements transport.Dialer using one TLS 1.3 connection for each
// proxied TCP stream.
type TLSClient struct {
	address          string
	token            string
	tlsConfig        *tls.Config
	handshakeTimeout time.Duration
	dialer           net.Dialer

	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
	conns  map[*trackedTLSConn]struct{}
}

// NewTLSClient creates a TCP+TLS fallback dialer.
func NewTLSClient(config TLSClientConfig) (*TLSClient, error) {
	if config.ServerAddress == "" {
		return nil, errors.New("tunnel: TLS fallback server address is required")
	}
	if len(config.Token) < protocol.MinTokenLength || len(config.Token) > protocol.MaxTokenLength {
		return nil, fmt.Errorf("tunnel: token length must be between %d and %d bytes", protocol.MinTokenLength, protocol.MaxTokenLength)
	}
	if config.HandshakeTimeout < 0 || config.DialTimeout < 0 {
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
	dialTimeout := config.DialTimeout
	if dialTimeout == 0 {
		dialTimeout = 5 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &TLSClient{
		address:          config.ServerAddress,
		token:            config.Token,
		tlsConfig:        tlsConfig,
		handshakeTimeout: handshakeTimeout,
		dialer:           net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second},
		ctx:              ctx,
		cancel:           cancel,
		conns:            make(map[*trackedTLSConn]struct{}),
	}, nil
}

// DialContext implements transport.Dialer.
func (c *TLSClient) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("tunnel: nil dial context")
	}
	n, err := protocol.ParseNetwork(network)
	if err != nil {
		return nil, err
	}
	if err := protocol.WriteRequest(io.Discard, protocol.Request{Network: n, Token: []byte(c.token), Address: address}); err != nil {
		return nil, err
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}

	dialCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	defer cancel()
	raw, err := c.dialer.DialContext(dialCtx, "tcp", c.address)
	if err != nil {
		return nil, fmt.Errorf("tunnel: dial TLS fallback: %w", err)
	}
	tlsConn := tls.Client(raw, c.tlsConfig.Clone())
	handshakeCtx, handshakeCancel := context.WithTimeout(dialCtx, c.handshakeTimeout)
	err = tlsConn.HandshakeContext(handshakeCtx)
	handshakeCancel()
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("tunnel: TLS fallback handshake: %w", err)
	}
	if tlsConn.ConnectionState().NegotiatedProtocol != protocol.ALPN {
		_ = tlsConn.Close()
		return nil, errors.New("tunnel: TLS fallback did not negotiate autocar/1")
	}
	if err := openProtocol(dialCtx, tlsConn, c.token, network, address, c.handshakeTimeout); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("tunnel: TLS stream handshake: %w", err)
	}

	tracked := &trackedTLSConn{Conn: tlsConn, owner: c}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = tlsConn.Close()
		return nil, net.ErrClosed
	}
	c.conns[tracked] = struct{}{}
	c.mu.Unlock()
	return tracked, nil
}

// Close prevents future dials and closes every active fallback stream.
func (c *TLSClient) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.cancel()
	connections := make([]*trackedTLSConn, 0, len(c.conns))
	for conn := range c.conns {
		connections = append(connections, conn)
	}
	c.mu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
	return nil
}

func (c *TLSClient) remove(conn *trackedTLSConn) {
	c.mu.Lock()
	delete(c.conns, conn)
	c.mu.Unlock()
}

type trackedTLSConn struct {
	*tls.Conn
	owner *TLSClient
	once  sync.Once
}

func (c *trackedTLSConn) Close() error {
	var err error
	c.once.Do(func() {
		c.owner.remove(c)
		err = c.Conn.Close()
	})
	return err
}

var _ transport.Dialer = (*TLSClient)(nil)
var _ net.Conn = (*trackedTLSConn)(nil)
