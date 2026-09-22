package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/config"
	"github.com/cppla/autocar/internal/security"
	"github.com/cppla/autocar/internal/tunnel"
)

// This checks generated credentials/configuration against real native
// transports, not a full CLI deployment. runServer deliberately blocks loopback
// destinations even with --allow-private; only this test's transport harness
// uses an ordinary local dialer. Production destination policy is unchanged.
func TestInitGeneratedBundleCarriesNativeTraffic(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if err != nil {
			http.Error(w, "read test payload", http.StatusBadRequest)
			return
		}
		_, _ = w.Write(payload)
	}))
	t.Cleanup(func() {
		target.CloseClientConnections()
		target.Close()
	})

	dir := filepath.Join(t.TempDir(), "generated bundle")
	// The target supplies a real ephemeral port to init. Relay endpoints are
	// overridden below with the independently bound QUIC/TLS ephemeral ports;
	// nothing reserves and releases a port in anticipation of another listener.
	if err := runInitWith([]string{
		"--server", target.Listener.Addr().String(), "--out", dir,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}

	serverFlags := flag.NewFlagSet("server", flag.ContinueOnError)
	protocol := serverFlags.String("protocol", "", "")
	listen := serverFlags.String("listen", "", "")
	certFile := serverFlags.String("cert", "", "")
	keyFile := serverFlags.String("key", "", "")
	tokenFile := serverFlags.String("token-file", "", "")
	if err := parseFlagsWithConfig(serverFlags, []string{
		"--config", filepath.Join(dir, "server", "server.json"),
		"--listen=127.0.0.1:0",
	}); err != nil {
		t.Fatal(err)
	}
	if *protocol != "native" {
		t.Fatalf("generated protocol = %q, want native", *protocol)
	}
	certificate, err := security.LoadKeyPair(*certFile, *keyFile)
	if err != nil {
		t.Fatal(err)
	}
	token, err := config.LoadSecret(*tokenFile, "")
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig, err := security.NewServerTLSConfig(security.ServerTLSOptions{
		Certificates: []tls.Certificate{certificate},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	startRelay := func(name string, relay interface {
		Serve(context.Context) error
		Close() error
	}) {
		done := make(chan error, 1)
		go func() { done <- relay.Serve(ctx) }()
		t.Cleanup(func() {
			cancel()
			_ = relay.Close()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("%s relay shutdown: %v", name, err)
				}
			case <-time.After(5 * time.Second):
				t.Errorf("%s relay did not shut down", name)
			}
		})
	}
	quicRelay, err := tunnel.ListenQUIC(tunnel.QUICServerConfig{
		Address: *listen, Token: token, TLSConfig: tlsConfig.Clone(),
		Dialer: &net.Dialer{Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	startRelay("QUIC", quicRelay)
	tlsRelay, err := tunnel.ListenTLS(tunnel.TLSServerConfig{
		Address: *listen, Token: token, TLSConfig: tlsConfig.Clone(),
		Dialer: &net.Dialer{Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	startRelay("TLS", tlsRelay)

	for _, mode := range []string{"quic", "tls", "auto"} {
		t.Run(mode, func(t *testing.T) {
			var tf tunnelFlags
			clientFlags := flag.NewFlagSet("client", flag.ContinueOnError)
			addTunnelFlags(clientFlags, &tf)
			endpoint := quicRelay.Addr().String()
			if mode == "tls" {
				endpoint = tlsRelay.Addr().String()
			}
			args := []string{
				"--config", filepath.Join(dir, "client", "client.json"),
				"--server", endpoint, "--open-timeout=10s",
			}
			if mode == "auto" {
				// Exercise init's default mode rather than overriding it.
				args = append(args, "--fallback-server", tlsRelay.Addr().String())
			} else {
				args = append(args, "--transport", mode)
			}
			if err := parseFlagsWithConfig(clientFlags, args); err != nil {
				t.Fatal(err)
			}
			if tf.mode != mode {
				t.Fatalf("parsed transport = %q, want %q", tf.mode, mode)
			}
			dialer, err := buildTunnelDialer(tf)
			if err != nil {
				t.Fatal(err)
			}
			defer dialer.Close()
			probeCtx, stopProbe := context.WithTimeout(ctx, 10*time.Second)
			defer stopProbe()
			conn, err := dialer.DialContext(probeCtx, "tcp", target.Listener.Addr().String())
			if err != nil {
				t.Fatalf("authenticated tunnel open: %v", err)
			}
			defer conn.Close()
			deadline, _ := probeCtx.Deadline()
			if err := conn.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			payload := bytes.Repeat([]byte("generated bundle native traffic\n"), 1024)
			request, err := http.NewRequestWithContext(probeCtx, http.MethodPost, target.URL, bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			if err := request.Write(conn); err != nil {
				t.Fatalf("write tunneled payload: %v", err)
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), request)
			if err != nil {
				t.Fatalf("read tunneled response: %v", err)
			}
			defer response.Body.Close()
			got, err := io.ReadAll(io.LimitReader(response.Body, int64(len(payload))+1))
			if err != nil || response.StatusCode != http.StatusOK || !bytes.Equal(got, payload) {
				t.Fatalf("payload roundtrip: status=%d bytes=%d error=%v", response.StatusCode, len(got), err)
			}
			wantTransport := mode
			if mode == "auto" {
				wantTransport = "quic"
			}
			reporter, ok := dialer.(selectedTransportReporter)
			if !ok || reporter.SelectedTransport() != wantTransport {
				t.Fatalf("successful %s exchange did not report transport %s", mode, wantTransport)
			}
		})
	}
}
