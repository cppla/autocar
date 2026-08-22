package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

func TestConfigValidationAndDefaults(t *testing.T) {
	noop := transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, nil
	})
	if _, err := NewSOCKS5Server(Config{}); err == nil {
		t.Fatal("nil Dialer was accepted")
	}
	for _, cfg := range []Config{
		{Dialer: noop, HandshakeTimeout: -time.Second},
		{Dialer: noop, DialTimeout: -time.Second},
		{Dialer: noop, IdleTimeout: -time.Second},
		{Dialer: noop, MaxConnections: -1},
	} {
		if _, err := NewHTTPServer(cfg); err == nil {
			t.Fatalf("invalid config was accepted: %+v", cfg)
		}
	}
	server, err := NewSOCKS5Server(Config{Dialer: noop})
	if err != nil {
		t.Fatal(err)
	}
	if server.cfg.handshakeTimeout != defaultHandshakeTimeout ||
		server.cfg.dialTimeout != defaultDialTimeout ||
		server.cfg.idleTimeout != defaultIdleTimeout ||
		server.cfg.maxConnections != 1024 {
		t.Fatalf("unexpected defaults: %+v", server.cfg)
	}
}

func TestStaticAuthenticator(t *testing.T) {
	auth := StaticAuthenticator("user", "password")
	if !auth.Authenticate(context.Background(), "user", "password") {
		t.Fatal("correct credentials rejected")
	}
	for _, credentials := range [][2]string{{"other", "password"}, {"user", "other"}, {"", ""}} {
		if auth.Authenticate(context.Background(), credentials[0], credentials[1]) {
			t.Fatalf("incorrect credentials accepted: %q/%q", credentials[0], credentials[1])
		}
	}
}
