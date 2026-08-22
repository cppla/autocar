package proxy

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

// Server is implemented by all stream proxy frontends.
type Server interface {
	Serve(net.Listener) error
	Shutdown(context.Context) error
}

const (
	defaultHandshakeTimeout = 10 * time.Second
	defaultDialTimeout      = 15 * time.Second
	defaultIdleTimeout      = 5 * time.Minute
)

// Config contains settings shared by the SOCKS5 and HTTP proxy frontends.
// A nil Authenticator enables unauthenticated local access. The caller should
// only use that mode on a loopback or otherwise trusted listener.
type Config struct {
	Dialer           transport.Dialer
	Authenticator    Authenticator
	HandshakeTimeout time.Duration
	DialTimeout      time.Duration
	IdleTimeout      time.Duration
	// MaxConnections is the number of accepted client TCP connections that may
	// be active at once. Zero uses a conservative default; a negative value is
	// rejected.
	MaxConnections int
}

type serverConfig struct {
	dialer           transport.Dialer
	packetDialer     transport.PacketDialer
	authenticator    Authenticator
	handshakeTimeout time.Duration
	dialTimeout      time.Duration
	idleTimeout      time.Duration
	maxConnections   int
}

func normalizeConfig(cfg Config) (serverConfig, error) {
	if cfg.Dialer == nil {
		return serverConfig{}, errors.New("proxy: nil transport dialer")
	}
	if cfg.HandshakeTimeout < 0 || cfg.DialTimeout < 0 || cfg.IdleTimeout < 0 {
		return serverConfig{}, errors.New("proxy: timeouts must not be negative")
	}
	if cfg.MaxConnections < 0 {
		return serverConfig{}, errors.New("proxy: max connections must not be negative")
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = defaultHandshakeTimeout
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = defaultDialTimeout
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = defaultIdleTimeout
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = 1024
	}
	packetDialer, _ := cfg.Dialer.(transport.PacketDialer)
	return serverConfig{
		dialer:           cfg.Dialer,
		packetDialer:     packetDialer,
		authenticator:    cfg.Authenticator,
		handshakeTimeout: cfg.HandshakeTimeout,
		dialTimeout:      cfg.DialTimeout,
		idleTimeout:      cfg.IdleTimeout,
		maxConnections:   cfg.MaxConnections,
	}, nil
}
