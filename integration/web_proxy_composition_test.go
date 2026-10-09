package integration_test

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/tunnel"
)

// TestWebProxyComposition covers the default web-auto transport through both
// real local proxy frontends. These are functional loopback tests, not evidence
// about passive traffic similarity or a browser's network fingerprint.
func TestWebProxyComposition(t *testing.T) {
	material := newTLSMaterial(t)
	echoAddress := startEchoTarget(t)
	httpTarget := startHTTPTarget(t)

	t.Run("default_h3", func(t *testing.T) {
		server, err := tunnel.ListenWeb(tunnel.WebServerConfig{
			TCPAddress:           "127.0.0.1:0",
			Token:                testToken,
			TLSConfig:            material.server,
			Cover:                http.NotFoundHandler(),
			Dialer:               &net.Dialer{},
			HandshakeTimeout:     operationTimeout,
			DialTimeout:          operationTimeout,
			MaxConcurrentStreams: 64,
		})
		if err != nil {
			t.Fatalf("listen dual-protocol web relay: %v", err)
		}
		serveWebCompositionRelay(t, server)
		// Leave both fingerprint fields omitted: H3 must use the default full
		// handshake profile, even though the verified TLS config has a cache.
		exerciseWebComposition(t, tunnel.WebClientConfig{
			ServerAddress:         server.TCPAddr().String(),
			Token:                 testToken,
			TLSConfig:             material.client,
			HandshakeTimeout:      operationTimeout,
			H3DialTimeout:         operationTimeout,
			H2DialTimeout:         operationTimeout,
			PrimaryAttemptTimeout: operationTimeout,
		}, "h3", echoAddress, httpTarget.URL)
	})

	t.Run("udp_blocked_h2_fallback", func(t *testing.T) {
		// Explicitly cover the compatibility profile and the profile emitted
		// by new configuration bundles, without changing the H3 default.
		for _, profile := range []tunnel.FingerprintProfile{
			tunnel.FingerprintChrome133,
			tunnel.FingerprintChrome155,
		} {
			t.Run(string(profile), func(t *testing.T) {
				server, err := tunnel.ListenWebH2(tunnel.WebH2ServerConfig{
					Address:              "127.0.0.1:0",
					Token:                testToken,
					TLSConfig:            material.server,
					Cover:                http.NotFoundHandler(),
					Dialer:               &net.Dialer{},
					HandshakeTimeout:     operationTimeout,
					DialTimeout:          operationTimeout,
					MaxConcurrentStreams: 64,
				})
				if err != nil {
					t.Fatalf("listen H2-only web relay: %v", err)
				}
				serveWebCompositionRelay(t, server)
				packets := startWebCompositionUDPBlackhole(t, server.Addr().String())
				exerciseWebComposition(t, tunnel.WebClientConfig{
					ServerAddress:         server.Addr().String(),
					Token:                 testToken,
					TLSConfig:             material.client,
					H2FingerprintProfile:  profile,
					HandshakeTimeout:      operationTimeout,
					H3DialTimeout:         250 * time.Millisecond,
					H2DialTimeout:         operationTimeout,
					PrimaryAttemptTimeout: time.Second,
					FallbackCooldown:      time.Minute,
				}, "h2", echoAddress, httpTarget.URL)
				if packets.Load() == 0 {
					t.Fatal("H2 fallback did not attempt the real UDP path")
				}
			})
		}
	})
}

func exerciseWebComposition(t *testing.T, config tunnel.WebClientConfig, wantTransport, echoAddress, targetURL string) {
	t.Helper()
	client, err := tunnel.NewWebClient(config)
	if err != nil {
		t.Fatalf("create web-auto client: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil && !isExpectedClose(err) {
			t.Errorf("close web-auto client: %v", err)
		}
	})
	if got := client.SelectedTransport(); got != "" {
		t.Fatalf("transport before the first request = %q, want empty", got)
	}
	socksAddress := startSOCKSProxy(t, client)
	httpAddress := startHTTPProxy(t, client, nil)
	assertTransport := func(frontend string) {
		t.Helper()
		if got := client.SelectedTransport(); got != wantTransport {
			t.Fatalf("transport after %s = %q, want %q", frontend, got, wantTransport)
		}
	}

	exerciseSOCKSConnect(t, socksAddress, echoAddress)
	assertTransport("SOCKS5 CONNECT")
	exerciseHTTPAbsoluteForm(t, httpAddress, targetURL)
	assertTransport("HTTP absolute form")
	exerciseHTTPConnect(t, httpAddress, echoAddress)
	assertTransport("HTTP CONNECT")
}

func serveWebCompositionRelay(t *testing.T, server interface {
	Serve(context.Context) error
	Close() error
}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := server.Close(); err != nil && !isExpectedClose(err) {
			t.Errorf("close web relay: %v", err)
		}
		waitForServe(t, "web relay", done)
	})
}

// Bind the TCP relay's exact numeric UDP port so the auto client exercises a
// silent UDP failure, not an unrelated destination or an immediate ICMP error.
func startWebCompositionUDPBlackhole(t *testing.T, address string) *atomic.Int64 {
	t.Helper()
	packet, err := net.ListenPacket("udp4", address)
	if err != nil {
		t.Fatalf("listen matching-port UDP blackhole: %v", err)
	}
	packets := &atomic.Int64{}
	done := make(chan error, 1)
	go func() {
		buffer := make([]byte, 64<<10)
		for {
			if _, _, err := packet.ReadFrom(buffer); err != nil {
				done <- err
				return
			}
			packets.Add(1)
		}
	}()
	t.Cleanup(func() {
		_ = packet.Close()
		waitForServe(t, "UDP blackhole", done)
	})
	return packets
}
