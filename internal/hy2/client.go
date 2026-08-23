// Package hy2 adapts the Hysteria v2 transport core to AutoCAR's proxy
// interfaces. It provides a long-lived HTTP/3-over-QUIC session, BBR or
// negotiated Brutal congestion control, QUIC datagrams and optional
// Salamander packet obfuscation.
package hy2

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	hyclient "github.com/apernet/hysteria/core/v2/client"
	hyerrors "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/transport"
)

const (
	CongestionBBR  = "bbr"
	CongestionReno = "reno"

	BBRConservative = "conservative"
	BBRStandard     = "standard"
	BBRAggressive   = "aggressive"

	minimumBandwidth       = 65536
	maximumBandwidth       = 1_000_000_000_000 // 8 Tbit/s; keeps signed QUIC arithmetic safely bounded.
	minimumObfsKey         = 16
	defaultMaxPendingOpens = 256
)

// ClientConfig configures the accelerated Hysteria v2 transport. Bandwidth
// values are bytes per second. Leaving both values at zero selects BBR;
// setting a value selects negotiated Brutal for that sending direction.
type ClientConfig struct {
	ServerAddress string
	Token         string
	TLSConfig     *tls.Config

	Congestion string
	BBRProfile string
	MaxTx      uint64
	MaxRx      uint64

	DisableLossCompensation bool
	FastOpen                bool
	ObfuscationKey          []byte
	DisablePathMTUDiscovery bool
	DisableGSO              bool
	DisableChromeParrot     bool
	MaxIdleTimeout          time.Duration
	KeepAlivePeriod         time.Duration
	// OpenTimeout bounds each authenticated session establishment and logical
	// stream/session open. Zero disables this additional deadline; each caller's
	// context still bounds how long that caller waits.
	OpenTimeout     time.Duration
	MaxPendingOpens int
}

// Client is a reconnecting Hysteria v2 client. The first request establishes
// the authenticated HTTP/3 session lazily.
type Client struct {
	config ClientConfig

	coreMu      sync.Mutex
	core        hyclient.Client
	attempt     *connectAttempt
	connectFunc func(context.Context) (hyclient.Client, *hyclient.HandshakeInfo, error)

	closed      sync.Once
	closeErr    error
	closedState atomic.Bool
	closeCh     chan struct{}
	openSlots   chan struct{}

	connections atomic.Uint64
	negotiated  atomic.Uint64
	udpEnabled  atomic.Bool
}

type connectAttempt struct {
	done   chan struct{}
	cancel context.CancelFunc
	core   hyclient.Client
	err    error
}

// NewClient validates config and creates a lazy reconnecting client.
func NewClient(config ClientConfig) (*Client, error) {
	if err := validateClientConfig(config); err != nil {
		return nil, err
	}
	config.Congestion = normalizeCongestion(config.Congestion)
	config.BBRProfile = normalizeBBRProfile(config.BBRProfile)
	config.ObfuscationKey = append([]byte(nil), config.ObfuscationKey...)
	config.TLSConfig = config.TLSConfig.Clone()
	if config.MaxPendingOpens == 0 {
		config.MaxPendingOpens = defaultMaxPendingOpens
	}

	return &Client{
		config:    config,
		closeCh:   make(chan struct{}),
		openSlots: make(chan struct{}, config.MaxPendingOpens),
	}, nil
}

func validateClientConfig(config ClientConfig) error {
	if config.ServerAddress == "" {
		return errors.New("hy2: server address is required")
	}
	if _, _, err := net.SplitHostPort(config.ServerAddress); err != nil {
		return fmt.Errorf("hy2: invalid server address %q: %w", config.ServerAddress, err)
	}
	if len(config.Token) < protocol.MinTokenLength || len(config.Token) > protocol.MaxTokenLength {
		return fmt.Errorf("hy2: token length must be between %d and %d bytes", protocol.MinTokenLength, protocol.MaxTokenLength)
	}
	if config.TLSConfig == nil {
		return errors.New("hy2: TLS config is required")
	}
	if config.TLSConfig.InsecureSkipVerify {
		return errors.New("hy2: InsecureSkipVerify is prohibited")
	}
	if config.TLSConfig.ServerName == "" || config.TLSConfig.RootCAs == nil {
		return errors.New("hy2: verified server name and explicit root CAs are required")
	}
	if err := validateClientTLSPolicy(config.TLSConfig); err != nil {
		return err
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
	if len(config.ObfuscationKey) != 0 && len(config.ObfuscationKey) < minimumObfsKey {
		return fmt.Errorf("hy2: obfuscation key must be at least %d bytes", minimumObfsKey)
	}
	if config.MaxIdleTimeout != 0 && (config.MaxIdleTimeout < 4*time.Second || config.MaxIdleTimeout > 120*time.Second) {
		return errors.New("hy2: maximum idle timeout must be zero or between 4s and 120s")
	}
	if config.KeepAlivePeriod != 0 && (config.KeepAlivePeriod < 2*time.Second || config.KeepAlivePeriod > 60*time.Second) {
		return errors.New("hy2: keepalive period must be zero or between 2s and 60s")
	}
	if config.OpenTimeout < 0 {
		return errors.New("hy2: open timeout cannot be negative")
	}
	if config.MaxPendingOpens < 0 || config.MaxPendingOpens > 65536 {
		return errors.New("hy2: maximum pending opens must be zero or at most 65536")
	}
	return nil
}

func normalizeCongestion(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return CongestionBBR
	}
	return value
}

func normalizeBBRProfile(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return BBRStandard
	}
	return value
}

func (c *Client) newCoreConfig() (*hyclient.Config, error) {
	serverAddress, err := net.ResolveUDPAddr("udp", c.config.ServerAddress)
	if err != nil {
		return nil, fmt.Errorf("hy2: resolve relay: %w", err)
	}
	tlsConfig := c.config.TLSConfig.Clone()
	getClientCertificate := tlsConfig.GetClientCertificate
	if getClientCertificate == nil && len(tlsConfig.Certificates) != 0 {
		certificates := append([]tls.Certificate(nil), tlsConfig.Certificates...)
		getClientCertificate = func(request *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			for i := range certificates {
				if err := request.SupportsCertificate(&certificates[i]); err == nil {
					return &certificates[i], nil
				}
			}
			return &tls.Certificate{}, nil
		}
	}
	return &hyclient.Config{
		ConnFactory: &packetConnFactory{obfuscationKey: c.config.ObfuscationKey},
		ServerAddr:  serverAddress,
		Auth:        c.config.Token,
		TLSConfig: hyclient.TLSConfig{
			ServerName:            tlsConfig.ServerName,
			InsecureSkipVerify:    false,
			VerifyPeerCertificate: tlsConfig.VerifyPeerCertificate,
			RootCAs:               tlsConfig.RootCAs.Clone(),
			GetClientCertificate:  getClientCertificate,
			ECHConfigList:         append([]byte(nil), tlsConfig.EncryptedClientHelloConfigList...),
		},
		QUICConfig: hyclient.QUICConfig{
			MaxIdleTimeout:          c.config.MaxIdleTimeout,
			KeepAlivePeriod:         c.config.KeepAlivePeriod,
			DisablePathMTUDiscovery: c.config.DisablePathMTUDiscovery,
			DisableGSO:              c.config.DisableGSO,
			DisableChromeParrot:     c.config.DisableChromeParrot,
		},
		CongestionConfig: hyclient.CongestionConfig{
			Type:       c.config.Congestion,
			BBRProfile: c.config.BBRProfile,
		},
		BandwidthConfig: hyclient.BandwidthConfig{
			MaxTx:                   c.config.MaxTx,
			MaxRx:                   c.config.MaxRx,
			DisableLossCompensation: c.config.DisableLossCompensation,
		},
		FastOpen: c.config.FastOpen,
	}, nil
}

// coreForContext returns the active authenticated session. Connection setup is
// a context-aware single flight: a UDP black hole can leave at most one
// bounded upstream handshake running, while all other callers wait without
// spawning their own reconnect attempts. A successful session is shared by
// all streams and datagram associations.
func (c *Client) coreForContext(ctx context.Context) (hyclient.Client, error) {
	c.coreMu.Lock()
	if c.closedState.Load() {
		c.coreMu.Unlock()
		return nil, net.ErrClosed
	}
	if c.core != nil {
		core := c.core
		c.coreMu.Unlock()
		return core, nil
	}
	attempt := c.attempt
	if attempt == nil {
		connectCtx := context.Background()
		var cancel context.CancelFunc
		if c.config.OpenTimeout > 0 {
			connectCtx, cancel = context.WithTimeout(connectCtx, c.config.OpenTimeout)
		} else {
			connectCtx, cancel = context.WithCancel(connectCtx)
		}
		attempt = &connectAttempt{done: make(chan struct{}), cancel: cancel}
		c.attempt = attempt
		go c.connect(connectCtx, attempt)
	}
	c.coreMu.Unlock()

	select {
	case <-attempt.done:
		if attempt.err != nil {
			return nil, attempt.err
		}
		return attempt.core, nil
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-c.closeCh:
		return nil, net.ErrClosed
	}
}

func (c *Client) connect(ctx context.Context, attempt *connectAttempt) {
	defer attempt.cancel()
	connect := c.connectFunc
	if connect == nil {
		connect = func(ctx context.Context) (hyclient.Client, *hyclient.HandshakeInfo, error) {
			config, err := c.newCoreConfig()
			if err != nil {
				return nil, nil, err
			}
			return hyclient.NewClientContext(ctx, config)
		}
	}
	core, info, err := connect(ctx)
	if err == nil && (core == nil || info == nil) {
		err = errors.New("hy2: connector returned an incomplete session")
	}
	if err != nil {
		err = c.addChromeCertificateHint(err)
		err = fmt.Errorf("hy2: establish authenticated session: %w", err)
	}

	c.coreMu.Lock()
	if err == nil && c.closedState.Load() {
		err = net.ErrClosed
	}
	if err == nil {
		c.core = core
		c.connections.Add(1)
		c.negotiated.Store(info.Tx)
		c.udpEnabled.Store(info.UDPEnabled)
	}
	attempt.core = core
	attempt.err = err
	if c.attempt == attempt {
		c.attempt = nil
	}
	close(attempt.done)
	c.coreMu.Unlock()

	if err != nil && core != nil {
		_ = core.Close()
	}
}

// addChromeCertificateHint preserves the handshake error while explaining a
// known compatibility constraint of the Chrome-parroting ClientHello. Chrome's
// advertised signature schemes intentionally omit Ed25519; an operator can
// either serve an ECDSA P-256/P-384/RSA certificate or explicitly disable parroting.
func (c *Client) addChromeCertificateHint(err error) error {
	if err == nil || c.config.DisableChromeParrot {
		return err
	}
	message := strings.ToLower(err.Error())
	if !strings.Contains(message, "handshake failure") &&
		!strings.Contains(message, "signature algorithm") {
		return err
	}
	return fmt.Errorf("%w (Chrome QUIC fingerprinting is enabled; if the relay certificate is Ed25519, use ECDSA P-256/P-384/RSA or pass --disable-chrome-parrot)", err)
}

func (c *Client) invalidate(core hyclient.Client, err error) {
	var closedError hyerrors.ClosedError
	if !errors.As(err, &closedError) {
		return
	}
	c.coreMu.Lock()
	if c.core != core {
		c.coreMu.Unlock()
		return
	}
	c.core = nil
	c.udpEnabled.Store(false)
	c.negotiated.Store(0)
	c.coreMu.Unlock()
	_ = core.Close()
}

type packetConnFactory struct {
	obfuscationKey []byte
}

func (f *packetConnFactory) New(net.Addr) (net.PacketConn, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	if len(f.obfuscationKey) == 0 {
		return conn, nil
	}
	wrapped, err := obfs.WrapPacketConnSalamander(conn, f.obfuscationKey)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return wrapped, nil
}

type tcpResult struct {
	conn net.Conn
	err  error
}

// DialContext opens a TCP stream over the authenticated QUIC session.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("hy2: nil dial context")
	}
	if c.closedState.Load() {
		return nil, net.ErrClosed
	}
	if network != "tcp" {
		return nil, fmt.Errorf("hy2: unsupported network %q", network)
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return nil, fmt.Errorf("hy2: invalid destination %q: %w", address, err)
	}
	if c.config.OpenTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.config.OpenTimeout)
		defer cancel()
	}
	if err := c.acquireOpen(ctx); err != nil {
		return nil, err
	}
	core, err := c.coreForContext(ctx)
	if err != nil {
		c.releaseOpen()
		return nil, err
	}
	result := make(chan tcpResult)
	go func() {
		defer c.releaseOpen()
		var conn net.Conn
		var err error
		if contextual, ok := core.(hyclient.ContextualTCPClient); ok {
			conn, err = contextual.TCPContext(ctx, address)
		} else {
			conn, err = core.TCP(address)
		}
		c.invalidate(core, err)
		value := tcpResult{conn: conn, err: err}
		select {
		case result <- value:
		case <-ctx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		case <-c.closeCh:
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()
	select {
	case value := <-result:
		if value.err != nil {
			return nil, fmt.Errorf("hy2: open TCP stream: %w", value.err)
		}
		if err := context.Cause(ctx); err != nil {
			_ = value.conn.Close()
			return nil, err
		}
		return value.conn, nil
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-c.closeCh:
		return nil, net.ErrClosed
	}
}

func (c *Client) acquireOpen(ctx context.Context) error {
	if c.openSlots == nil {
		return nil
	}
	select {
	case c.openSlots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-c.closeCh:
		return net.ErrClosed
	}
}

func (c *Client) releaseOpen() {
	if c.openSlots != nil {
		<-c.openSlots
	}
}

// DialPacket opens one logical UDP session carried by QUIC DATAGRAM frames.
func (c *Client) DialPacket(ctx context.Context) (transport.PacketConn, error) {
	if ctx == nil {
		return nil, errors.New("hy2: nil packet context")
	}
	if c.closedState.Load() {
		return nil, net.ErrClosed
	}
	if c.config.OpenTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.config.OpenTimeout)
		defer cancel()
	}
	core, err := c.coreForContext(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := core.UDP()
	c.invalidate(core, err)
	if err != nil {
		return nil, fmt.Errorf("hy2: open UDP session: %w", err)
	}
	if err := context.Cause(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &packetConn{core: conn}, nil
}

type packetConn struct {
	core hyclient.HyUDPConn
}

func (c *packetConn) Send(payload []byte, address string) error {
	return c.core.Send(payload, address)
}

func (c *packetConn) Receive() ([]byte, string, error) {
	return c.core.Receive()
}

func (c *packetConn) Close() error { return c.core.Close() }

func (c *packetConn) MaxPayloadSize() int { return hyclient.MaxUDPSize }

// NegotiatedTx reports the most recently negotiated client-to-server Brutal
// rate in bytes/s. Zero means BBR or Reno is active for that direction.
func (c *Client) NegotiatedTx() uint64 { return c.negotiated.Load() }

// UDPEnabled reports whether the current server handshake enabled datagrams.
func (c *Client) UDPEnabled() bool { return c.udpEnabled.Load() }

// ConnectionCount reports successful authenticated session establishments,
// including reconnects.
func (c *Client) ConnectionCount() uint64 { return c.connections.Load() }

// AccelerationMode reports the active outbound congestion-control mode. A
// non-zero negotiated rate always means Brutal; otherwise the configured BBR
// profile or Reno controls the connection.
func (c *Client) AccelerationMode() string {
	if c.negotiated.Load() > 0 {
		return "brutal"
	}
	if normalizeCongestion(c.config.Congestion) == CongestionReno {
		return CongestionReno
	}
	return CongestionBBR + "-" + normalizeBBRProfile(c.config.BBRProfile)
}

// Close permanently closes the reconnecting client.
func (c *Client) Close() error {
	c.closed.Do(func() {
		c.closedState.Store(true)
		if c.closeCh != nil {
			close(c.closeCh)
		}
		c.coreMu.Lock()
		core := c.core
		attempt := c.attempt
		c.core = nil
		c.coreMu.Unlock()
		if attempt != nil {
			attempt.cancel()
		}
		if core != nil {
			c.closeErr = core.Close()
		}
	})
	return c.closeErr
}

// IsRemoteDialError reports errors returned by an authenticated relay after it
// attempted the requested target. Auto mode must not retry those requests via
// another transport, because the primary path itself is healthy.
func IsRemoteDialError(err error) bool {
	var dialError hyerrors.DialError
	return errors.As(err, &dialError)
}

// IsAuthenticationError reports Hysteria authentication rejection.
func IsAuthenticationError(err error) bool {
	var authError hyerrors.AuthError
	return errors.As(err, &authError)
}

var _ transport.Dialer = (*Client)(nil)
var _ transport.PacketDialer = (*Client)(nil)
var _ transport.PacketConn = (*packetConn)(nil)
var _ transport.PacketPayloadSizer = (*packetConn)(nil)
