package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/cppla/autocar/internal/transport"
)

// WebH3ServerConfig configures a real HTTP/3 cover origin whose authenticated
// CONNECT requests carry TCP proxy streams.
type WebH3ServerConfig struct {
	Address              string
	Token                string
	TLSConfig            *tls.Config
	QUICConfig           *quic.Config
	Dialer               transport.Dialer
	Cover                http.Handler
	HandshakeTimeout     time.Duration
	DialTimeout          time.Duration
	MaxConcurrentStreams int
	StreamAdmission      *StreamAdmission
	// MaxConnections and MaxClientConnections bound accepted HTTPS
	// connections globally and per source IPv4 or IPv6 /64. A combined
	// WebServer shares these limits with HTTP/2.
	MaxConnections       int
	MaxClientConnections int
	MaxHeaderBytes       int
	ReplayEntries        int
	// UDPResolver and the UDP limits apply only to RFC 9298 CONNECT-UDP
	// request streams. A nil resolver prefers Dialer's UDPResolver capability
	// before falling back to the system resolver.
	UDPResolver          UDPResolver
	MaxUDPSessions       int
	MaxClientUDPSessions int
	MaxUDPDestinations   int
	UDPReceiveQueue      int

	connectionAdmission *webConnectionAdmission
}

// WebH3Server serves both ordinary HTTP/3 cover requests and authenticated
// standard CONNECT streams on one UDP endpoint.
type WebH3Server struct {
	packet   net.PacketConn
	listener *webAdmissionQUICListener
	server   *http3.Server

	serveMu  sync.Mutex
	serving  bool
	once     sync.Once
	closeErr error
}

func ListenWebH3(config WebH3ServerConfig) (*WebH3Server, error) {
	if config.Address == "" {
		return nil, errors.New("tunnel: web-cover H3 listen address is required")
	}
	if config.Cover == nil {
		return nil, errors.New("tunnel: web-cover H3 requires a cover handler")
	}
	if config.Dialer == nil {
		return nil, errors.New("tunnel: web-cover H3 requires an explicit safe destination dialer")
	}
	key, err := deriveWebAuthKey(config.Token)
	if err != nil {
		return nil, err
	}
	verifier, err := newWebAuthVerifier(key, nil, config.ReplayEntries)
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
	return listenWebH3WithCore(config, core, verifier)
}

func listenWebH3WithCore(config WebH3ServerConfig, core *serverCore, verifier *webAuthVerifier) (*WebH3Server, error) {
	if config.MaxHeaderBytes < 0 {
		return nil, errors.New("tunnel: maximum web-cover HTTP header bytes cannot be negative")
	}
	maxHeaderBytes := config.MaxHeaderBytes
	if maxHeaderBytes == 0 {
		maxHeaderBytes = defaultWebH2MaxHeaderBytes
	}
	udp, err := newServerUDPManager(QUICServerConfig{
		UDPResolver:          config.UDPResolver,
		MaxUDPSessions:       config.MaxUDPSessions,
		MaxClientUDPSessions: config.MaxClientUDPSessions,
		MaxUDPDestinations:   config.MaxUDPDestinations,
		UDPReceiveQueue:      config.UDPReceiveQueue,
	}, config.Dialer, config.DialTimeout)
	if err != nil {
		return nil, err
	}
	handler := &webTunnelHandler{auth: verifier, core: core, cover: config.Cover, udp: udp}
	if err := validateWebTunnelHandler(handler); err != nil {
		return nil, err
	}
	tlsConfig, err := webServerTLSConfig(config.TLSConfig, http3.NextProtoH3)
	if err != nil {
		return nil, err
	}
	quicConfig := hardenedWebH3ServerConfig(config.QUICConfig, cap(core.sem), core.handshakeTimeout)
	packet, err := net.ListenPacket("udp", config.Address)
	if err != nil {
		return nil, fmt.Errorf("tunnel: listen web-cover H3: %w", err)
	}
	connectionAdmission := config.connectionAdmission
	if connectionAdmission == nil {
		connectionAdmission, err = newWebConnectionAdmission(config.MaxConnections, config.MaxClientConnections)
		if err != nil {
			_ = packet.Close()
			return nil, err
		}
	}
	quicListener, err := quic.Listen(packet, http3.ConfigureTLSConfig(tlsConfig), quicConfig)
	if err != nil {
		_ = packet.Close()
		return nil, fmt.Errorf("tunnel: listen web-cover H3 QUIC: %w", err)
	}
	listener := &webAdmissionQUICListener{listener: quicListener, admission: connectionAdmission}
	server := &http3.Server{
		Addr:            packet.LocalAddr().String(),
		TLSConfig:       tlsConfig,
		QUICConfig:      quicConfig,
		Handler:         handler,
		EnableDatagrams: true,
		MaxHeaderBytes:  maxHeaderBytes,
		IdleTimeout:     90 * time.Second,
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			ctx = context.WithValue(ctx, webH3ConnectionContextKey{}, conn)
			// Bind authentication state to this exact QUIC connection. Address
			// changes caused by NAT rebinding or connection migration must not
			// create a new identity, while every replacement connection must run
			// the full bootstrap again.
			return context.WithValue(
				ctx,
				webServerConnectionAuthContextKey{},
				newWebServerConnectionAuth(func() error {
					return conn.CloseWithError(
						quic.ApplicationErrorCode(applicationShutdown),
						"connection authentication failed",
					)
				}),
			)
		},
	}
	return &WebH3Server{packet: packet, listener: listener, server: server}, nil
}

func (s *WebH3Server) Addr() net.Addr { return s.packet.LocalAddr() }

func (s *WebH3Server) Serve(ctx context.Context) error {
	if ctx == nil {
		return errors.New("tunnel: nil web-cover H3 serve context")
	}
	s.serveMu.Lock()
	if s.serving {
		s.serveMu.Unlock()
		return errors.New("tunnel: web-cover H3 server already serving")
	}
	s.serving = true
	s.serveMu.Unlock()

	errCh := make(chan error, 1)
	go func() { errCh <- s.server.ServeListener(s.listener) }()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.server.Shutdown(shutdownCtx)
		_ = s.listener.Close()
		_ = s.packet.Close()
		err := <-errCh
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			return err
		}
		return nil
	}
}

func (s *WebH3Server) Close() error {
	s.once.Do(func() {
		s.closeErr = errors.Join(s.server.Close(), s.listener.Close(), s.packet.Close())
	})
	return s.closeErr
}
