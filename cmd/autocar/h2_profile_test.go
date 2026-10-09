package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/tunnel"
)

func TestH2FingerprintConfigAndCLI(t *testing.T) {
	for _, test := range []struct {
		name, config, override, want string
		hasOverride, wantError       bool
	}{
		{name: "legacy omitted", config: `{}`, want: "chrome-133"},
		{name: "legacy empty", config: `{"h2-fingerprint":""}`},
		{name: "explicit 133", config: `{"h2-fingerprint":"chrome-133"}`, want: "chrome-133"},
		{name: "explicit 155", config: `{"h2-fingerprint":"chrome-155"}`, want: "chrome-155"},
		{name: "native", config: `{"h2-fingerprint":"native"}`, want: "native"},
		{name: "override 155", config: `{"h2-fingerprint":"chrome-133"}`, hasOverride: true, override: "chrome-155", want: "chrome-155"},
		{name: "override 133", config: `{"h2-fingerprint":"chrome-155"}`, hasOverride: true, override: "chrome-133", want: "chrome-133"},
		{name: "override native", config: `{"h2-fingerprint":"chrome-155"}`, hasOverride: true, override: "native", want: "native"},
		{name: "override empty", config: `{"h2-fingerprint":"chrome-155"}`, hasOverride: true},
		{name: "invalid config", config: `{"h2-fingerprint":"private-invalid-value"}`, wantError: true},
		{name: "invalid overridden config", config: `{"h2-fingerprint":"private-invalid-value"}`, hasOverride: true, override: "chrome-155", wantError: true},
		{name: "invalid CLI", config: `{"h2-fingerprint":"chrome-155"}`, hasOverride: true, override: "unsupported", wantError: true},
		{name: "number", config: `{"h2-fingerprint":155}`, wantError: true},
		{name: "boolean", config: `{"h2-fingerprint":true}`, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "client.json")
			if err := os.WriteFile(path, []byte(test.config), 0o600); err != nil {
				t.Fatal(err)
			}
			fs := flag.NewFlagSet("client", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			var tf tunnelFlags
			addTunnelFlags(fs, &tf)
			args := []string{"--config", path}
			if test.hasOverride {
				args = append(args, "--h2-fingerprint", test.override)
			}
			err := parseFlagsWithConfig(fs, args)
			if test.wantError {
				if err == nil || !strings.Contains(err.Error(), "h2-fingerprint") {
					t.Fatalf("invalid profile error = %v", err)
				}
				if strings.Contains(err.Error(), "private-invalid-value") {
					t.Fatal("invalid configuration value was exposed")
				}
				return
			}
			if err != nil || string(tf.h2Fingerprint) != test.want {
				t.Fatalf("profile = %q, want %q; error = %v", tf.h2Fingerprint, test.want, err)
			}
		})
	}
}

func TestH2FingerprintInvalidInputStaysOffline(t *testing.T) {
	clearPreflightEnvironment(t)
	dnsCalls := denyPreflightDNS(t)
	for _, mode := range []string{"h2", "web-auto", "h3", "auto", "quic", "tls", "direct"} {
		t.Run(mode, func(t *testing.T) {
			args := []string{"--transport", mode, "--h2-fingerprint", "unsupported"}
			for _, run := range []func(context.Context, []string) error{runClient, runBenchClient} {
				if err := run(context.Background(), args); err == nil || !strings.Contains(err.Error(), "--h2-fingerprint") {
					t.Fatalf("invalid profile was not rejected before credentials/network: %v", err)
				}
			}
			for _, jsonOutput := range []bool{false, true} {
				var stdout, stderr bytes.Buffer
				doctorArgs := []string{"--transport", mode, "--h2-fingerprint", "private-invalid-value"}
				if jsonOutput {
					doctorArgs = append(doctorArgs, "--json")
				}
				err := runDoctorWith(context.Background(), doctorArgs, &stdout, &stderr, func(tunnelFlags) (closeDialer, error) {
					t.Fatal("invalid H2 profile reached doctor dialer construction")
					return nil, nil
				})
				if err == nil || commandExitCode(err) != doctorExitUsageFailure {
					t.Fatalf("doctor invalid profile error = %v", err)
				}
				if strings.Contains(stdout.String()+stderr.String()+err.Error(), "private-invalid-value") {
					t.Fatal("doctor exposed an invalid profile value")
				}
				if jsonOutput {
					var failure doctorFailure
					if err := json.Unmarshal(stdout.Bytes(), &failure); err != nil || failure.Code != "invalid_arguments" {
						t.Fatalf("doctor JSON code = %q, decode error = %v", failure.Code, err)
					}
				}
			}
			// Internal callers must get the same preflight protection without
			// relying on flag parsing or usable credential paths.
			_, err := buildTunnelDialer(tunnelFlags{mode: mode, h2Fingerprint: "private-invalid-value"})
			if err == nil || !strings.Contains(err.Error(), "--h2-fingerprint") || strings.Contains(err.Error(), "private-invalid-value") {
				t.Fatalf("constructor profile validation = %v", err)
			}
		})
	}
	if calls := dnsCalls.Load(); calls != 0 {
		t.Fatalf("invalid profile attempted %d DNS connections", calls)
	}
}

func TestH2FingerprintPreflightAcceptsSupportedProfiles(t *testing.T) {
	clearPreflightEnvironment(t)
	files := newPreflightFiles(t)
	dnsCalls := denyPreflightDNS(t)
	for _, mode := range []string{"h2", "web-auto"} {
		for _, profile := range []string{"", "chrome-133", "chrome-155", "native"} {
			t.Run(mode+"/"+profile, func(t *testing.T) {
				args := append(files.clientArgs(), "--transport", mode, "--h2-fingerprint", profile)
				if err := runClient(context.Background(), args); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	if calls := dnsCalls.Load(); calls != 0 {
		t.Fatalf("profile preflight attempted %d DNS connections", calls)
	}
}

// Observe the actual TLS ClientHello instead of inspecting private transport
// fields: Chrome 155 offers ML-DSA-65 (0x0905), whereas Chrome 133 does not.
// The server deliberately stops after capture; this is a propagation test,
// not a substitute for certificate verification or an authenticated exchange.
func TestH2FingerprintCLIReachesWire(t *testing.T) {
	files := newPreflightFiles(t)
	for _, mode := range []string{"h2", "web-auto"} {
		for _, profile := range []string{"", "chrome-133", "chrome-155"} {
			t.Run(mode+"/"+profile, func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				captured := make(chan []tls.SignatureScheme, 1)
				done := make(chan error, 1)
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						done <- err
						return
					}
					defer conn.Close()
					server := tls.Server(conn, &tls.Config{
						MinVersion: tls.VersionTLS13,
						GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
							captured <- slices.Clone(hello.SignatureSchemes)
							return nil, errors.New("test ClientHello capture complete")
						},
					})
					done <- server.HandshakeContext(ctx)
				}()
				t.Cleanup(func() {
					cancel()
					_ = listener.Close()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("ClientHello capture server did not stop")
					}
				})
				fs := flag.NewFlagSet("client", flag.ContinueOnError)
				fs.SetOutput(io.Discard)
				var tf tunnelFlags
				addTunnelFlags(fs, &tf)
				if err := fs.Parse([]string{
					"--server", listener.Addr().String(), "--server-name", "relay.invalid",
					"--ca", files.cert, "--token-file", files.token,
					"--transport", mode, "--h2-fingerprint", profile,
					"--quic-attempt-timeout=1ns", "--open-timeout=4s",
				}); err != nil {
					t.Fatal(err)
				}
				dialer, err := buildTunnelDialer(tf)
				if err != nil {
					t.Fatal(err)
				}
				defer dialer.Close()
				conn, err := dialer.DialContext(ctx, "tcp", "target.invalid:443")
				if conn != nil {
					_ = conn.Close()
				}
				if err == nil {
					t.Fatal("capture-only TLS server unexpectedly accepted a tunnel")
				}
				select {
				case signatures := <-captured:
					got155 := slices.Contains(signatures, tls.SignatureScheme(0x0905))
					if want155 := profile == string(tunnel.FingerprintChrome155); got155 != want155 {
						t.Fatalf("Chrome 155 signature algorithm present = %v, want %v; signatures = %v", got155, want155, signatures)
					}
				case <-ctx.Done():
					t.Fatal("H2 ClientHello was not captured")
				}
			})
		}
	}
}
