package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/cppla/autocar/internal/transport"
	"golang.org/x/net/http2"
)

const (
	webH2ALPN                              = "h2"
	webHTTP11ALPN                          = "http/1.1"
	defaultWebH2MaxHeaderBytes             = 16 << 10
	defaultWebClientMaxResponseHeaderBytes = 256 << 10
)

type webTLSConnectionContextKey struct{}

// WebH2ServerConfig configures the TCP side of the web-cover transport. The
// listener serves an ordinary TLS 1.2 or TLS 1.3 HTTP/2 and HTTP/1.1 origin.
// Only a TLS 1.3 authenticated HTTP/2 CONNECT request is handled as a tunnel;
// all other requests are delegated to Cover.
type WebH2ServerConfig struct {
	Address              string
	Token                string
	TLSConfig            *tls.Config
	Cover                http.Handler
	Dialer               transport.Dialer
	HandshakeTimeout     time.Duration
	DialTimeout          time.Duration
	MaxConcurrentStreams int
	StreamAdmission      *StreamAdmission
	// MaxConnections and MaxClientConnections bound accepted HTTPS
	// connections globally and per source IPv4 or IPv6 /64. A combined
	// WebServer shares these limits with HTTP/3.
	MaxConnections       int
	MaxClientConnections int
	MaxHeaderBytes       int
	// ReplayCacheEntries bounds accepted, unexpired authentication nonces.
	// Zero uses the conservative default shared by the web transports.
	ReplayEntries int

	connectionAdmission *webConnectionAdmission
}

// WebH2Server serves a real HTTPS cover origin and multiplexed TCP tunnels on
// one TLS listener.
type WebH2Server struct {
	listener net.Listener
	server   *http.Server

	serveMu sync.Mutex
	serving bool

	closeOnce sync.Once
	closeErr  error
}

// ListenWebH2 binds the TCP listener. Call Serve to accept traffic.
func ListenWebH2(config WebH2ServerConfig) (*WebH2Server, error) {
	if config.Dialer == nil {
		return nil, errors.New("tunnel: web-cover HTTP/2 requires a policy-enforcing destination dialer")
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
	key, err := deriveWebAuthKey(config.Token)
	if err != nil {
		return nil, err
	}
	auth, err := newWebAuthVerifier(key, nil, config.ReplayEntries)
	if err != nil {
		return nil, err
	}
	return listenWebH2WithCore(config, core, auth)
}

// listenWebH2WithCore lets the combined web server share one replay cache and
// one stream-admission budget across HTTP/2 and HTTP/3 listeners.
func listenWebH2WithCore(config WebH2ServerConfig, core *serverCore, auth *webAuthVerifier) (*WebH2Server, error) {
	if config.Address == "" {
		return nil, errors.New("tunnel: web-cover TCP listen address is required")
	}
	handler := &webTunnelHandler{auth: auth, core: core, cover: config.Cover}
	if err := validateWebTunnelHandler(handler); err != nil {
		return nil, err
	}
	tlsConfig, err := webServerTLSConfig(config.TLSConfig, webH2ALPN, webHTTP11ALPN)
	if err != nil {
		return nil, err
	}

	httpServer := &http.Server{
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: core.handshakeTimeout,
		IdleTimeout:       90 * time.Second,
		ConnContext: func(ctx context.Context, connection net.Conn) context.Context {
			// Request.TLS is normally populated by net/http, but it isn't part of
			// the HTTP/2 handler contract when Serve is given a TLS listener. Keep
			// the actual connection available so the tunnel's TLS 1.3 gate remains
			// correct across Go/x/net HTTP/2 implementations.
			if tlsConnection, ok := connection.(*tls.Conn); ok {
				ctx = context.WithValue(ctx, webTLSConnectionContextKey{}, tlsConnection)
				// Authentication state belongs to this exact physical TLS
				// connection. The handler's first CONNECT performs the padded
				// bootstrap; later streams use its short, sequenced tickets.
				ctx = context.WithValue(
					ctx,
					webServerConnectionAuthContextKey{},
					newWebServerConnectionAuth(tlsConnection.Close),
				)
				return ctx
			}
			return ctx
		},
	}
	if config.MaxHeaderBytes < 0 {
		return nil, errors.New("tunnel: maximum web-cover HTTP header bytes cannot be negative")
	}
	httpServer.MaxHeaderBytes = config.MaxHeaderBytes
	if httpServer.MaxHeaderBytes == 0 {
		httpServer.MaxHeaderBytes = defaultWebH2MaxHeaderBytes
	}
	maxStreams := uint64(min(cap(core.sem), defaultWebMaxStreamsPerConnection))
	if maxStreams > uint64(math.MaxUint32) {
		maxStreams = math.MaxUint32
	}
	if err := http2.ConfigureServer(httpServer, &http2.Server{
		MaxConcurrentStreams: uint32(maxStreams),
	}); err != nil {
		return nil, fmt.Errorf("tunnel: configure web-cover HTTP/2 server: %w", err)
	}
	connectionAdmission := config.connectionAdmission
	if connectionAdmission == nil {
		connectionAdmission, err = newWebConnectionAdmission(config.MaxConnections, config.MaxClientConnections)
		if err != nil {
			return nil, err
		}
	}

	raw, err := net.Listen("tcp", config.Address)
	if err != nil {
		return nil, fmt.Errorf("tunnel: listen web-cover TCP: %w", err)
	}
	return &WebH2Server{
		listener: tls.NewListener(&webAdmissionListener{Listener: raw, admission: connectionAdmission}, tlsConfig),
		server:   httpServer,
	}, nil
}

// Addr returns the bound TCP address.
func (s *WebH2Server) Addr() net.Addr { return s.listener.Addr() }

// Serve accepts HTTP/2 tunnels and ordinary HTTP requests until ctx is
// canceled or Close is called. Serve may be called exactly once.
func (s *WebH2Server) Serve(ctx context.Context) error {
	if ctx == nil {
		return errors.New("tunnel: nil serve context")
	}
	s.serveMu.Lock()
	if s.serving {
		s.serveMu.Unlock()
		return errors.New("tunnel: web-cover HTTP/2 server already serving")
	}
	s.serving = true
	s.serveMu.Unlock()

	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	err := s.server.Serve(s.listener)
	stop()
	_ = s.Close()
	if ctx.Err() != nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return fmt.Errorf("tunnel: serve web-cover HTTP/2: %w", err)
}

// Close stops the listener and aborts active HTTP streams.
func (s *WebH2Server) Close() error {
	s.closeOnce.Do(func() {
		serverErr := s.server.Close()
		listenerErr := s.listener.Close()
		if errors.Is(serverErr, http.ErrServerClosed) || errors.Is(serverErr, net.ErrClosed) {
			serverErr = nil
		}
		if errors.Is(listenerErr, net.ErrClosed) {
			listenerErr = nil
		}
		s.closeErr = errors.Join(serverErr, listenerErr)
	})
	return s.closeErr
}
