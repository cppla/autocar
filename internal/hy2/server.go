package hy2

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	hyserver "github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/security"
)

const (
	defaultMaxConnections       = 256
	defaultMaxClientConnections = 32
	defaultMaxStreams           = 1024
	defaultMaxUniStreams        = 8
	defaultMaxHTTPHeaderBytes   = 16 << 10
	defaultMaxOutboundTCP       = 1024
	defaultMaxOutboundUDP       = 256
	defaultMaxClientTCP         = 128
	defaultMaxClientUDP         = 64
	maxUDPAllowedDestinations   = 256
	defaultDialTimeout          = 4 * time.Second
	defaultRequestTimeout       = 10 * time.Second
	defaultUDPIdleTimeout       = 60 * time.Second
)

// ServerConfig configures the accelerated HTTP/3 relay.
type ServerConfig struct {
	Address   string
	Token     string
	TLSConfig *tls.Config
	Dialer    *security.SafeDialer
	// Outbound is an optional advanced/test adapter. Production callers should
	// leave it nil so every destination is enforced by Dialer.
	Outbound hyserver.Outbound

	Congestion string
	BBRProfile string
	MaxTx      uint64
	MaxRx      uint64

	AllowClientBandwidth    bool
	DisableLossCompensation bool
	DisableUDP              bool
	DisablePathMTUDiscovery bool
	DisableGSO              bool
	ObfuscationKey          []byte
	MaxIdleTimeout          time.Duration
	UDPIdleTimeout          time.Duration
	DialTimeout             time.Duration
	MaxConcurrentStreams    int
	MaxIncomingUniStreams   int
	MaxConnections          int
	MaxClientConnections    int
	MaxOutboundTCP          int
	MaxOutboundUDP          int
	MaxClientTCPHandlers    int
	MaxClientUDPSessions    int
	TCPRequestTimeout       time.Duration
	AuthenticationTimeout   time.Duration
	MasqueradeHandler       http.Handler
}

// Server is an authenticated Hysteria v2 relay.
type Server struct {
	core      hyserver.Server
	address   net.Addr
	admission *admissionController

	serveMu  sync.Mutex
	serving  bool
	closed   atomic.Bool
	close    sync.Once
	closeErr error
}

// Listen binds the UDP socket and constructs the HTTP/3 relay.
func Listen(config ServerConfig) (*Server, error) {
	if err := validateServerConfig(config); err != nil {
		return nil, err
	}
	config.Congestion = normalizeCongestion(config.Congestion)
	config.BBRProfile = normalizeBBRProfile(config.BBRProfile)
	if config.MaxConnections == 0 {
		config.MaxConnections = defaultMaxConnections
	}
	if config.MaxClientConnections == 0 {
		config.MaxClientConnections = min(defaultMaxClientConnections, config.MaxConnections)
	}
	if config.MaxConcurrentStreams == 0 {
		config.MaxConcurrentStreams = defaultMaxStreams
	}
	if config.MaxIncomingUniStreams == 0 {
		config.MaxIncomingUniStreams = defaultMaxUniStreams
	}
	if config.MaxOutboundTCP == 0 {
		config.MaxOutboundTCP = defaultMaxOutboundTCP
	}
	if config.MaxOutboundUDP == 0 {
		config.MaxOutboundUDP = defaultMaxOutboundUDP
	}
	if config.MaxClientTCPHandlers == 0 {
		config.MaxClientTCPHandlers = min(defaultMaxClientTCP, config.MaxOutboundTCP)
	}
	if config.MaxClientUDPSessions == 0 {
		config.MaxClientUDPSessions = min(defaultMaxClientUDP, config.MaxOutboundUDP)
	}
	if config.DialTimeout == 0 {
		config.DialTimeout = defaultDialTimeout
	}
	if config.TCPRequestTimeout == 0 {
		config.TCPRequestTimeout = defaultRequestTimeout
	}
	if config.AuthenticationTimeout == 0 {
		config.AuthenticationTimeout = defaultRequestTimeout
	}
	if config.UDPIdleTimeout == 0 {
		config.UDPIdleTimeout = defaultUDPIdleTimeout
	}

	packetConn, err := net.ListenPacket("udp", config.Address)
	if err != nil {
		return nil, fmt.Errorf("hy2: listen UDP: %w", err)
	}
	address := packetConn.LocalAddr()
	if len(config.ObfuscationKey) != 0 {
		wrapped, wrapErr := obfs.WrapPacketConnSalamander(packetConn, config.ObfuscationKey)
		if wrapErr != nil {
			_ = packetConn.Close()
			return nil, fmt.Errorf("hy2: enable Salamander: %w", wrapErr)
		}
		packetConn = wrapped
	}

	admission := newAdmissionController(config.Token, config.MaxConnections)
	masquerade := config.MasqueradeHandler
	if masquerade == nil {
		masquerade = NewCoverHandler("")
	}
	tlsConfig := config.TLSConfig.Clone()
	outbound := config.Outbound
	if outbound == nil {
		outbound = &safeOutbound{
			dialer:   config.Dialer,
			timeout:  config.DialTimeout,
			tcpSlots: make(chan struct{}, config.MaxOutboundTCP),
			udpSlots: make(chan struct{}, config.MaxOutboundUDP),
		}
	}
	core, err := hyserver.NewServer(&hyserver.Config{
		Conn: packetConn,
		TLSConfig: hyserver.TLSConfig{
			Certificates:   append([]tls.Certificate(nil), tlsConfig.Certificates...),
			GetCertificate: tlsConfig.GetCertificate,
			ClientCAs:      cloneCertPool(tlsConfig.ClientCAs),
			ECHKeys:        append([]tls.EncryptedClientHelloKey(nil), tlsConfig.EncryptedClientHelloKeys...),
			GetECHKeys:     tlsConfig.GetEncryptedClientHelloKeys,
		},
		QUICConfig: hyserver.QUICConfig{
			MaxIdleTimeout:          config.MaxIdleTimeout,
			MaxIncomingStreams:      int64(config.MaxConcurrentStreams),
			MaxIncomingUniStreams:   int64(config.MaxIncomingUniStreams),
			DisablePathMTUDiscovery: config.DisablePathMTUDiscovery,
			DisableGSO:              config.DisableGSO,
		},
		Outbound: outbound,
		CongestionConfig: hyserver.CongestionConfig{
			Type:       config.Congestion,
			BBRProfile: config.BBRProfile,
		},
		BandwidthConfig: hyserver.BandwidthConfig{
			MaxTx:                   config.MaxTx,
			MaxRx:                   config.MaxRx,
			DisableLossCompensation: config.DisableLossCompensation,
		},
		IgnoreClientBandwidth: !config.AllowClientBandwidth,
		DisableUDP:            config.DisableUDP,
		UDPIdleTimeout:        config.UDPIdleTimeout,
		MaxConnections:        config.MaxConnections,
		MaxClientConnections:  config.MaxClientConnections,
		MaxTCPHandlers:        config.MaxOutboundTCP,
		MaxClientTCPHandlers:  config.MaxClientTCPHandlers,
		TCPRequestTimeout:     config.TCPRequestTimeout,
		AuthenticationTimeout: config.AuthenticationTimeout,
		MaxHTTPHeaderBytes:    defaultMaxHTTPHeaderBytes,
		MaxUDPSessions:        config.MaxOutboundUDP,
		MaxClientUDPSessions:  config.MaxClientUDPSessions,
		Authenticator:         admission,
		EventLogger:           admission,
		MasqHandler:           masquerade,
	})
	if err != nil {
		_ = packetConn.Close()
		return nil, fmt.Errorf("hy2: create server: %w", err)
	}
	return &Server{core: core, address: address, admission: admission}, nil
}

func validateServerConfig(config ServerConfig) error {
	if config.Address == "" {
		return errors.New("hy2: listen address is required")
	}
	if len(config.Token) < protocol.MinTokenLength || len(config.Token) > protocol.MaxTokenLength {
		return fmt.Errorf("hy2: token length must be between %d and %d bytes", protocol.MinTokenLength, protocol.MaxTokenLength)
	}
	if config.TLSConfig == nil {
		return errors.New("hy2: server TLS config is required")
	}
	if err := validateServerTLSPolicy(config.TLSConfig); err != nil {
		return err
	}
	if len(config.TLSConfig.Certificates) == 0 && config.TLSConfig.GetCertificate == nil {
		return errors.New("hy2: server TLS certificate is required")
	}
	if config.Dialer == nil && config.Outbound == nil {
		return errors.New("hy2: safe outbound dialer is required")
	}
	congestion := normalizeCongestion(config.Congestion)
	if congestion != CongestionBBR && congestion != CongestionReno {
		return fmt.Errorf("hy2: unsupported congestion controller %q", config.Congestion)
	}
	profile := normalizeBBRProfile(config.BBRProfile)
	if congestion == CongestionBBR && profile != BBRConservative && profile != BBRStandard && profile != BBRAggressive {
		return fmt.Errorf("hy2: unsupported BBR profile %q", config.BBRProfile)
	}
	for name, bandwidth := range map[string]uint64{"MaxTx": config.MaxTx, "MaxRx": config.MaxRx} {
		if bandwidth != 0 && bandwidth < minimumBandwidth {
			return fmt.Errorf("hy2: %s must be zero or at least %d bytes/s", name, minimumBandwidth)
		}
		if bandwidth > maximumBandwidth {
			return fmt.Errorf("hy2: %s must not exceed %d bytes/s", name, maximumBandwidth)
		}
	}
	if config.AllowClientBandwidth && (config.MaxTx == 0 || config.MaxRx == 0) {
		return errors.New("hy2: allowing client bandwidth requires finite MaxTx and MaxRx ceilings")
	}
	if len(config.ObfuscationKey) != 0 && len(config.ObfuscationKey) < minimumObfsKey {
		return fmt.Errorf("hy2: obfuscation key must be at least %d bytes", minimumObfsKey)
	}
	if config.MaxConnections < 0 || config.MaxConnections > 65536 {
		return errors.New("hy2: maximum connections must be zero or at most 65536")
	}
	if config.MaxClientConnections < 0 || config.MaxClientConnections > 65536 {
		return errors.New("hy2: per-source connection limit must be zero or at most 65536")
	}
	if config.MaxClientConnections > 0 && config.MaxConnections > 0 && config.MaxClientConnections > config.MaxConnections {
		return errors.New("hy2: per-source connection limit cannot exceed the global connection limit")
	}
	if config.MaxConcurrentStreams < 0 || config.MaxConcurrentStreams > 65536 || (config.MaxConcurrentStreams > 0 && config.MaxConcurrentStreams < 8) {
		return errors.New("hy2: maximum streams must be zero or between 8 and 65536")
	}
	if config.MaxIncomingUniStreams < 0 || config.MaxIncomingUniStreams > 1024 || (config.MaxIncomingUniStreams > 0 && config.MaxIncomingUniStreams < 3) {
		return errors.New("hy2: maximum unidirectional streams must be zero or between 3 and 1024")
	}
	if config.MaxOutboundTCP < 0 || config.MaxOutboundTCP > 65536 || config.MaxOutboundUDP < 0 || config.MaxOutboundUDP > 65536 {
		return errors.New("hy2: outbound connection limits must be zero or at most 65536")
	}
	if config.MaxClientUDPSessions < 0 || config.MaxClientUDPSessions > 65536 {
		return errors.New("hy2: per-source UDP session limit must be zero or at most 65536")
	}
	if config.MaxClientTCPHandlers < 0 || config.MaxClientTCPHandlers > 65536 {
		return errors.New("hy2: per-source TCP handler limit must be zero or at most 65536")
	}
	if config.MaxClientTCPHandlers > 0 && config.MaxOutboundTCP > 0 && config.MaxClientTCPHandlers > config.MaxOutboundTCP {
		return errors.New("hy2: per-source TCP handler limit cannot exceed the global TCP limit")
	}
	if config.MaxClientUDPSessions > 0 && config.MaxOutboundUDP > 0 && config.MaxClientUDPSessions > config.MaxOutboundUDP {
		return errors.New("hy2: per-source UDP session limit cannot exceed the global UDP limit")
	}
	if config.DialTimeout < 0 {
		return errors.New("hy2: outbound dial timeout cannot be negative")
	}
	if config.TCPRequestTimeout != 0 && (config.TCPRequestTimeout < time.Second || config.TCPRequestTimeout > 60*time.Second) {
		return errors.New("hy2: TCP request timeout must be zero or between 1s and 60s")
	}
	if config.AuthenticationTimeout != 0 && (config.AuthenticationTimeout < time.Second || config.AuthenticationTimeout > 60*time.Second) {
		return errors.New("hy2: authentication timeout must be zero or between 1s and 60s")
	}
	if config.MaxIdleTimeout != 0 && (config.MaxIdleTimeout < 4*time.Second || config.MaxIdleTimeout > 120*time.Second) {
		return errors.New("hy2: maximum idle timeout must be zero or between 4s and 120s")
	}
	if config.UDPIdleTimeout != 0 && (config.UDPIdleTimeout < 2*time.Second || config.UDPIdleTimeout > 600*time.Second) {
		return errors.New("hy2: UDP idle timeout must be zero or between 2s and 600s")
	}
	return nil
}

func cloneCertPool(pool *x509.CertPool) *x509.CertPool {
	if pool == nil {
		return nil
	}
	return pool.Clone()
}

// Addr returns the bound UDP address.
func (s *Server) Addr() net.Addr { return s.address }

// Serve runs until ctx is canceled, Close is called or the listener fails.
func (s *Server) Serve(ctx context.Context) error {
	if ctx == nil {
		return errors.New("hy2: nil serve context")
	}
	s.serveMu.Lock()
	if s.serving {
		s.serveMu.Unlock()
		return errors.New("hy2: server already serving")
	}
	s.serving = true
	s.serveMu.Unlock()

	done := make(chan error, 1)
	go func() { done <- s.core.Serve() }()
	select {
	case err := <-done:
		if s.closed.Load() || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return fmt.Errorf("hy2: serve: %w", err)
	case <-ctx.Done():
		_ = s.Close()
		<-done
		if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) {
			return cause
		}
		return nil
	}
}

// Close stops the listener and all active sessions.
func (s *Server) Close() error {
	s.close.Do(func() {
		s.closed.Store(true)
		s.closeErr = s.core.Close()
	})
	return s.closeErr
}

type admissionController struct {
	token  string
	slots  chan struct{}
	next   atomic.Uint64
	lastTx atomic.Uint64
	open   sync.Map
}

func newAdmissionController(token string, maximum int) *admissionController {
	return &admissionController{token: token, slots: make(chan struct{}, maximum)}
}

func (a *admissionController) Authenticate(addr net.Addr, provided string, _ uint64) (bool, string) {
	if !security.VerifyToken(provided, a.token) {
		return false, ""
	}
	select {
	case a.slots <- struct{}{}:
	default:
		return false, ""
	}
	id := fmt.Sprintf("%s#%d", addr.String(), a.next.Add(1))
	a.open.Store(id, struct{}{})
	return true, id
}

func (a *admissionController) Connect(addr net.Addr, id string, tx uint64) {
	a.lastTx.Store(tx)
	slog.Debug("hy2 session authenticated", "remote", addr.String(), "id", id, "tx_bytes_per_second", tx)
}

func (a *admissionController) Disconnect(addr net.Addr, id string, err error) {
	if _, loaded := a.open.LoadAndDelete(id); loaded {
		<-a.slots
	}
	slog.Debug("hy2 session disconnected", "remote", addr.String(), "id", id, "error", err)
}

func (a *admissionController) TCPRequest(net.Addr, string, string)         {}
func (a *admissionController) TCPError(net.Addr, string, string, error)    {}
func (a *admissionController) UDPRequest(net.Addr, string, uint32, string) {}
func (a *admissionController) UDPError(net.Addr, string, uint32, error)    {}

type safeOutbound struct {
	dialer   *security.SafeDialer
	timeout  time.Duration
	tcpSlots chan struct{}
	udpSlots chan struct{}
}

var (
	ErrOutboundCapacity       = errors.New("hy2: outbound capacity exhausted")
	ErrUDPDestinationCapacity = errors.New("hy2: UDP destination capacity exhausted")
)

func (o *safeOutbound) TCP(address string) (net.Conn, error) {
	if !acquireSlot(o.tcpSlots) {
		return nil, fmt.Errorf("%w: TCP", ErrOutboundCapacity)
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	conn, err := o.dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		releaseSlot(o.tcpSlots)
		return nil, err
	}
	return &releaseConn{Conn: conn, release: func() { releaseSlot(o.tcpSlots) }}, nil
}

func (o *safeOutbound) UDP(address string) (hyserver.UDPConn, error) {
	if !acquireSlot(o.udpSlots) {
		return nil, fmt.Errorf("%w: UDP", ErrOutboundCapacity)
	}
	release := true
	defer func() {
		if release {
			releaseSlot(o.udpSlots)
		}
	}()
	// Hysteria calls UDP directly for the first datagram in a session and uses
	// CheckUDP only when the destination later changes. Enforce policy here as
	// well so the initial address cannot bypass the relay's SSRF boundary.
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	if _, err := o.dialer.ResolveUDPContext(ctx, address); err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	release = false
	return &safeUDPConn{
		conn: conn, dialer: o.dialer, timeout: o.timeout,
		release: func() { releaseSlot(o.udpSlots) },
	}, nil
}

func (o *safeOutbound) CheckUDP(address string) error {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	_, err := o.dialer.ResolveUDPContext(ctx, address)
	return err
}

type safeUDPConn struct {
	conn      *net.UDPConn
	dialer    *security.SafeDialer
	timeout   time.Duration
	allowedMu sync.RWMutex
	// allowed contains only destinations that passed policy and a successful
	// socket write. Entries are never evicted: removing one could cause a valid
	// delayed reply to be mistaken for an unsolicited packet.
	allowed  map[netip.AddrPort]struct{}
	release  func()
	close    sync.Once
	closeErr error
}

type releaseConn struct {
	net.Conn
	release  func()
	close    sync.Once
	closeErr error
}

func acquireSlot(slots chan struct{}) bool {
	if slots == nil {
		return true
	}
	select {
	case slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func releaseSlot(slots chan struct{}) {
	if slots != nil {
		<-slots
	}
}

func (c *releaseConn) Close() error {
	c.close.Do(func() {
		c.closeErr = c.Conn.Close()
		if c.release != nil {
			c.release()
		}
	})
	return c.closeErr
}

func (c *safeUDPConn) ReadFrom(buffer []byte) (int, string, error) {
	for {
		n, address, err := c.conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return n, "", err
		}
		address = netip.AddrPortFrom(address.Addr().Unmap(), address.Port())
		if c.destinationAllowed(address) {
			return n, address.String(), nil
		}
	}
}

func (c *safeUDPConn) WriteTo(payload []byte, address string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	addresses, err := c.dialer.ResolveUDPContext(ctx, address)
	if err != nil {
		return 0, err
	}
	var writeErrors []error
	for _, candidate := range addresses {
		candidate = netip.AddrPortFrom(candidate.Addr().Unmap(), candidate.Port())
		n, writeErr := c.writeToDestination(payload, candidate)
		if writeErr == nil {
			return n, nil
		}
		writeErrors = append(writeErrors, writeErr)
	}
	return 0, errors.Join(writeErrors...)
}

func (c *safeUDPConn) destinationAllowed(address netip.AddrPort) bool {
	c.allowedMu.RLock()
	_, ok := c.allowed[address]
	c.allowedMu.RUnlock()
	return ok
}

func (c *safeUDPConn) writeToDestination(payload []byte, address netip.AddrPort) (int, error) {
	// Existing destinations need no admission change and remain usable even
	// after the fixed-size set is full.
	if c.destinationAllowed(address) {
		return c.conn.WriteToUDPAddrPort(payload, address)
	}

	// Serialize first writes so concurrent successful sends cannot overfill the
	// set. Keep the lock through the socket write: a reply read after that write
	// waits until authorization is recorded, rather than being dropped in the
	// small interval between the two operations.
	c.allowedMu.Lock()
	defer c.allowedMu.Unlock()
	if _, ok := c.allowed[address]; ok {
		return c.conn.WriteToUDPAddrPort(payload, address)
	}
	if len(c.allowed) >= maxUDPAllowedDestinations {
		return 0, ErrUDPDestinationCapacity
	}
	n, err := c.conn.WriteToUDPAddrPort(payload, address)
	if err != nil {
		return n, err
	}
	if c.allowed == nil {
		c.allowed = make(map[netip.AddrPort]struct{}, maxUDPAllowedDestinations)
	}
	c.allowed[address] = struct{}{}
	return n, nil
}

func (c *safeUDPConn) Close() error {
	c.close.Do(func() {
		c.closeErr = c.conn.Close()
		if c.release != nil {
			c.release()
		}
	})
	return c.closeErr
}

// CoverHandler serves a small neutral HTTP site for unauthenticated and
// ordinary HTTP/3 requests. This makes active probes observe a valid web
// service instead of an AutoCAR-specific protocol error.
type CoverHandler struct {
	serverName string
	page       *template.Template
}

// NewCoverHandler creates the built-in HTTP/3 cover. serverName is optional
// and is HTML-escaped by the template package.
func NewCoverHandler(serverName string) http.Handler {
	serverName = strings.TrimSpace(serverName)
	if serverName == "" {
		serverName = "Service"
	}
	page := template.Must(template.New("cover").Parse("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{{.}}</title></head><body><main><h1>{{.}}</h1><p>The service is online.</p></main></body></html>"))
	return &CoverHandler{serverName: serverName, page: page}
}

func (h *CoverHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "public, max-age=300")
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	if (request.Method != http.MethodGet && request.Method != http.MethodHead) || request.URL.Path != "/" {
		http.NotFound(response, request)
		return
	}
	response.WriteHeader(http.StatusOK)
	if request.Method == http.MethodHead {
		return
	}
	_ = h.page.Execute(response, h.serverName)
}

var _ hyserver.Authenticator = (*admissionController)(nil)
var _ hyserver.EventLogger = (*admissionController)(nil)
var _ hyserver.Outbound = (*safeOutbound)(nil)
var _ hyserver.UDPConn = (*safeUDPConn)(nil)
