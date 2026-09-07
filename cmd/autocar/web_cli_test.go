package main

import (
	"context"
	"errors"
	"flag"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/accel"
	"github.com/cppla/autocar/internal/security"
	"github.com/cppla/autocar/internal/transport"
)

func TestValidateServerProtocolOptions(t *testing.T) {
	tests := []struct {
		name            string
		protocol        string
		clientCA        string
		root            string
		upstream        string
		disableFallback bool
		wantError       string
	}{
		{name: "native defaults", protocol: "native"},
		{name: "web static", protocol: "web", root: "/srv/www"},
		{name: "web upstream", protocol: "web", upstream: "https://cover.example"},
		{name: "unknown", protocol: "stealth", wantError: "want native or web"},
		{name: "native cover", protocol: "native", root: "/srv/www", wantError: "require --protocol=web"},
		{name: "web missing cover", protocol: "web", wantError: "exactly one"},
		{name: "web ambiguous cover", protocol: "web", root: "/srv/www", upstream: "https://cover.example", wantError: "exactly one"},
		{name: "web client CA", protocol: "web", root: "/srv/www", clientCA: "clients.pem", wantError: "incompatible"},
		{name: "web without H2", protocol: "web", root: "/srv/www", disableFallback: true, wantError: "HTTP/2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateServerProtocolOptions(test.protocol, test.clientCA, test.root, test.upstream, test.disableFallback)
			if test.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestRunServerValidatesWebCoverBeforeCredentials(t *testing.T) {
	err := runServer(context.Background(), []string{"--protocol", "web"})
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("missing web cover error = %v", err)
	}
	err = runServer(context.Background(), []string{
		"--protocol", "web",
		"--cover-root", "/srv/www",
		"--client-ca", "clients.pem",
	})
	if err == nil || !strings.Contains(err.Error(), "incompatible") {
		t.Fatalf("web mTLS error = %v", err)
	}
}

func TestBuildStaticCoverHandler(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "index.html"), []byte("ordinary cover"), 0o600); err != nil {
		t.Fatal(err)
	}
	handler, err := buildCoverHandler(directory, "")
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://cover.example/", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "ordinary cover") {
		t.Fatalf("cover response = %d %q", response.Code, response.Body.String())
	}
}

func TestBuildUpstreamCoverRejectsNonHTTPOrigin(t *testing.T) {
	if _, err := buildCoverHandler("", "file:///private/cover"); err == nil || !strings.Contains(err.Error(), "http or https") {
		t.Fatalf("non-HTTP cover error = %v", err)
	}
}

func TestRunWebServerAcceptsCanceledLifecycle(t *testing.T) {
	directory := t.TempDir()
	certFile := filepath.Join(directory, "server.crt")
	keyFile := filepath.Join(directory, "server.key")
	tokenFile := filepath.Join(directory, "token")
	coverRoot := filepath.Join(directory, "cover")
	if err := os.Mkdir(coverRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(coverRoot, "index.html"), []byte("cover"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := security.WriteSelfSignedCertificate(certFile, keyFile, security.CertificateOptions{
		Hosts: []string{"127.0.0.1"}, ValidFor: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte("web-server-lifecycle-test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runServer(ctx, []string{
		"--protocol", "web",
		"--listen", "127.0.0.1:0",
		"--cover-root", coverRoot,
		"--cert", certFile,
		"--key", keyFile,
		"--token-file", tokenFile,
	}); err != nil {
		t.Fatalf("canceled web server lifecycle: %v", err)
	}
}

func TestWebTunnelModesAreRecognized(t *testing.T) {
	for _, mode := range []string{"auto", "quic", "tls", "web-auto", "h3", "h2"} {
		if !validTunnelTransport(mode) {
			t.Errorf("transport %q was rejected", mode)
		}
	}
	for _, mode := range []string{"", "web", "http3", "direct"} {
		if validTunnelTransport(mode) {
			t.Errorf("transport %q was accepted", mode)
		}
	}
}

func TestTunnelHelpListsWebTransports(t *testing.T) {
	fs := flag.NewFlagSet("web-help", flag.ContinueOnError)
	var output strings.Builder
	fs.SetOutput(&output)
	var flags tunnelFlags
	addTunnelFlags(fs, &flags)
	fs.PrintDefaults()
	for _, mode := range []string{"web-auto", "h3", "h2"} {
		if !strings.Contains(output.String(), mode) {
			t.Errorf("tunnel help omitted %q: %s", mode, output.String())
		}
	}
	if !strings.Contains(output.String(), "h3-fingerprint") || !strings.Contains(output.String(), "chrome-2026-08") {
		t.Errorf("tunnel help omitted versioned H3 fingerprint profile: %s", output.String())
	}
}

func TestWebTunnelModesRejectNativeFixedRatePacing(t *testing.T) {
	for _, mode := range []string{"web-auto", "h3", "h2"} {
		err := validateClientPacingTransport(mode, accel.ModeFixedRate)
		if err == nil || !strings.Contains(err.Error(), "--transport=quic") {
			t.Errorf("%s fixed-rate result = %v", mode, err)
		}
	}
}

func TestBuildExplicitAndAutomaticWebDialers(t *testing.T) {
	directory := t.TempDir()
	certFile := filepath.Join(directory, "server.crt")
	keyFile := filepath.Join(directory, "server.key")
	tokenFile := filepath.Join(directory, "token")
	if err := security.WriteSelfSignedCertificate(certFile, keyFile, security.CertificateOptions{
		Hosts: []string{"127.0.0.1"}, ValidFor: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte("web-client-constructor-test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		mode       string
		wantPacket bool
	}{
		{mode: "h3", wantPacket: true},
		{mode: "h2", wantPacket: false},
		{mode: "web-auto", wantPacket: true},
	} {
		t.Run(test.mode, func(t *testing.T) {
			dialer, err := buildTunnelDialer(tunnelFlags{
				server:         "127.0.0.1:443",
				mode:           test.mode,
				caFile:         certFile,
				tokenFile:      tokenFile,
				dialTimeout:    time.Second,
				primaryTimeout: time.Second,
				openTimeout:    2 * time.Second,
				fallbackTTL:    time.Second,
				pacing:         "adaptive",
				pacingProfile:  "balanced",
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := dialer.(doctorSnapshotReporter); !ok {
				_ = dialer.Close()
				t.Fatal("web dialer does not expose doctor metadata")
			}
			_, hasPacket := dialer.(transport.PacketDialer)
			if hasPacket != test.wantPacket {
				_ = dialer.Close()
				t.Fatalf("PacketDialer capability = %v, want %v", hasPacket, test.wantPacket)
			}
			if err := dialer.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type selectedTestDialer struct {
	selected string
}

func (*selectedTestDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not used")
}

func (*selectedTestDialer) Close() error { return nil }

func (d *selectedTestDialer) SelectedTransport() string { return d.selected }

func TestWebSnapshotDialerReportsExplicitTransportWithoutPacing(t *testing.T) {
	dialer := newWebSnapshotDialer(&selectedTestDialer{selected: "h2"})
	reporter, ok := dialer.(doctorSnapshotReporter)
	if !ok {
		t.Fatal("explicit web dialer does not expose a doctor snapshot")
	}
	snapshot := reporter.Snapshot()
	if snapshot.SelectedTransport != "h2" || snapshot.ClientPacing != "not-applicable" || snapshot.RelayPacing != "not-applicable" {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}
