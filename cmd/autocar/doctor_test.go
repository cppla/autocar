package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/security"
	"github.com/cppla/autocar/internal/tunnel"
)

type fakeDoctorDialer struct {
	snapshot tunnel.ClientSnapshot
	dialErr  error
	network  string
	target   string
	closed   bool
}

func (d *fakeDoctorDialer) DialContext(_ context.Context, network, target string) (net.Conn, error) {
	d.network = network
	d.target = target
	if d.dialErr != nil {
		return nil, d.dialErr
	}
	client, peer := net.Pipe()
	_ = peer.Close()
	return client, nil
}

func (d *fakeDoctorDialer) Close() error {
	d.closed = true
	return nil
}

func (d *fakeDoctorDialer) Snapshot() tunnel.ClientSnapshot { return d.snapshot }

func TestDoctorJSONProbesAuthenticatedTunnelAndReportsSnapshot(t *testing.T) {
	eventTime := time.Date(2026, time.September, 3, 8, 30, 0, 0, time.UTC)
	dialer := &fakeDoctorDialer{snapshot: tunnel.ClientSnapshot{
		SelectedTransport:              "tls",
		ClientPacing:                   "tls-fallback",
		RelayPacing:                    "tls-fallback",
		ClientNegotiatedBytesPerSecond: 0,
		RelayNegotiatedBytesPerSecond:  0,
		LastEvent: &tunnel.ClientEvent{
			Kind: tunnel.ClientEventFallback, Reason: tunnel.ClientReasonQUICDialFailed, At: eventTime,
		},
	}}
	var received tunnelFlags
	builder := func(flags tunnelFlags) (closeDialer, error) {
		received = flags
		return dialer, nil
	}
	var stdout, stderr bytes.Buffer
	err := runDoctorWith(context.Background(), []string{
		"--server", "relay.example:443",
		"--ca", "unused.pem",
		"--transport", "auto",
		"--target", "target.example:8443",
		"--json",
	}, &stdout, &stderr, builder)
	if err != nil {
		t.Fatal(err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
	if received.server != "relay.example:443" || received.mode != "auto" || received.caFile != "unused.pem" {
		t.Fatalf("tunnel flags were not reused: %+v", received)
	}
	if dialer.network != "tcp" || dialer.target != "target.example:8443" {
		t.Fatalf("probe dial = %q %q", dialer.network, dialer.target)
	}
	if !dialer.closed {
		t.Fatal("doctor did not close its tunnel dialer")
	}
	var result doctorResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode JSON %q: %v", stdout.String(), err)
	}
	if result.Status != "ok" || result.Probe != "authenticated_tcp_open" ||
		result.RequestedTransport != "auto" || result.SelectedTransport != "tls" ||
		result.ClientPacing != "tls-fallback" || result.RelayPacing != "tls-fallback" {
		t.Fatalf("doctor result = %+v", result)
	}
	if result.LastTransportEvent == nil || result.LastTransportEvent.Reason != tunnel.ClientReasonQUICDialFailed {
		t.Fatalf("doctor transport event = %+v", result.LastTransportEvent)
	}
}

func TestDoctorCommandOpensRealAuthenticatedQUICPath(t *testing.T) {
	directory := t.TempDir()
	certFile := filepath.Join(directory, "server.crt")
	keyFile := filepath.Join(directory, "server.key")
	if err := security.WriteSelfSignedCertificate(certFile, keyFile, security.CertificateOptions{
		Hosts: []string{"127.0.0.1"}, ValidFor: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	certificate, err := security.LoadKeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	const token = "doctor-real-authenticated-test-token"
	tokenFile := filepath.Join(directory, "token")
	if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	targetDone := make(chan struct{})
	go func() {
		defer close(targetDone)
		conn, acceptErr := target.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = target.Close()
		<-targetDone
	})

	server, err := tunnel.ListenQUIC(tunnel.QUICServerConfig{
		Address:   "127.0.0.1:0",
		Token:     token,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}},
		Dialer:    &net.Dialer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	serverCtx, stopServer := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(serverCtx) }()
	t.Cleanup(func() {
		stopServer()
		_ = server.Close()
		if serveErr := <-serveDone; serveErr != nil {
			t.Errorf("serve QUIC: %v", serveErr)
		}
	})

	var stdout, stderr bytes.Buffer
	err = runDoctorWith(context.Background(), []string{
		"--server", server.Addr().String(),
		"--ca", certFile,
		"--token-file", tokenFile,
		"--transport", "quic",
		"--target", target.Addr().String(),
		"--json",
	}, &stdout, &stderr, buildTunnelDialer)
	if err != nil {
		t.Fatalf("doctor failed: %v; stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	var result doctorResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "ok" || result.SelectedTransport != "quic" ||
		result.ClientPacing != "adaptive-balanced" || result.RelayPacing != "adaptive-balanced" {
		t.Fatalf("real doctor result = %+v", result)
	}
}

func TestDoctorHumanOutputIsDirectionallyExplicit(t *testing.T) {
	dialer := &fakeDoctorDialer{snapshot: tunnel.ClientSnapshot{
		SelectedTransport:              "quic",
		ClientPacing:                   "fixed-rate",
		ClientNegotiatedBytesPerSecond: 7_500_000,
		RelayPacing:                    "adaptive-balanced",
		RelayNegotiatedBytesPerSecond:  0,
	}}
	var stdout bytes.Buffer
	err := runDoctorWith(context.Background(), []string{"--target", "example.com:443"}, &stdout, &bytes.Buffer{}, func(tunnelFlags) (closeDialer, error) {
		return dialer, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		"Authenticated relay TCP probe: OK",
		"requested transport: auto",
		"selected transport:  quic",
		"client pacing:        fixed-rate (7500000 bytes/s)",
		"relay pacing:         adaptive-balanced (0 bytes/s)",
	} {
		if !strings.Contains(stdout.String(), text) {
			t.Fatalf("doctor output %q does not contain %q", stdout.String(), text)
		}
	}
}

func TestDoctorFailuresHaveStableCodesAndExitCodes(t *testing.T) {
	t.Run("missing target", func(t *testing.T) {
		called := false
		var stdout bytes.Buffer
		err := runDoctorWith(context.Background(), []string{"--json"}, &stdout, &bytes.Buffer{}, func(tunnelFlags) (closeDialer, error) {
			called = true
			return nil, nil
		})
		if commandExitCode(err) != doctorExitUsageFailure || called {
			t.Fatalf("exit=%d called=%v err=%v", commandExitCode(err), called, err)
		}
		var failure doctorFailure
		if decodeErr := json.Unmarshal(stdout.Bytes(), &failure); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if failure.Status != "failed" || failure.Code != "invalid_target" || failure.Error != "target must be a valid host:port" {
			t.Fatalf("failure = %+v", failure)
		}
	})

	t.Run("probe failure", func(t *testing.T) {
		dialer := &fakeDoctorDialer{dialErr: errors.New("controlled tunnel failure")}
		var stdout bytes.Buffer
		err := runDoctorWith(context.Background(), []string{"--target", "example.com:443", "--json"}, &stdout, &bytes.Buffer{}, func(tunnelFlags) (closeDialer, error) {
			return dialer, nil
		})
		if commandExitCode(err) != doctorExitProbeFailure || !dialer.closed {
			t.Fatalf("exit=%d closed=%v err=%v", commandExitCode(err), dialer.closed, err)
		}
		var failure doctorFailure
		if decodeErr := json.Unmarshal(stdout.Bytes(), &failure); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if failure.Status != "failed" || failure.Code != "probe_failed" || failure.Error != "authenticated tunnel TCP open failed" {
			t.Fatalf("failure = %+v", failure)
		}
		if strings.Contains(stdout.String(), "controlled tunnel failure") || strings.Contains(err.Error(), "controlled tunnel failure") {
			t.Fatalf("JSON probe failure leaked raw cause: stdout=%q err=%q", stdout.String(), err)
		}
	})

	t.Run("JSON flag parse failure", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		err := runDoctorWith(context.Background(), []string{"--json", "--bogus"}, &stdout, &stderr, nil)
		if commandExitCode(err) != doctorExitUsageFailure {
			t.Fatalf("exit=%d err=%v", commandExitCode(err), err)
		}
		var failure doctorFailure
		if decodeErr := json.Unmarshal(stdout.Bytes(), &failure); decodeErr != nil {
			t.Fatalf("decode JSON %q: %v", stdout.String(), decodeErr)
		}
		if failure.Code != "invalid_arguments" || failure.Error != "invalid doctor arguments" {
			t.Fatalf("failure = %+v", failure)
		}
		if stderr.Len() != 0 {
			t.Fatalf("JSON parse failure wrote raw flag diagnostics: %q", stderr.String())
		}
	})

	t.Run("affirmative JSON cannot be disabled after parse failure", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		err := runDoctorWith(context.Background(), []string{
			"--json",
			"--dial-timeout=/private/customer/relay-token",
			"--json=false",
		}, &stdout, &stderr, nil)
		if commandExitCode(err) != doctorExitUsageFailure {
			t.Fatalf("exit=%d err=%v", commandExitCode(err), err)
		}
		var failure doctorFailure
		if decodeErr := json.Unmarshal(stdout.Bytes(), &failure); decodeErr != nil {
			t.Fatalf("decode JSON %q: %v", stdout.String(), decodeErr)
		}
		if failure.Code != "invalid_arguments" || stderr.Len() != 0 {
			t.Fatalf("failure=%+v stderr=%q", failure, stderr.String())
		}
		if strings.Contains(stdout.String(), "/private/customer/relay-token") ||
			strings.Contains(err.Error(), "/private/customer/relay-token") {
			t.Fatalf("JSON parse failure leaked a local path: stdout=%q err=%q", stdout.String(), err)
		}
	})

	t.Run("successful parse uses actual final JSON value", func(t *testing.T) {
		dialer := &fakeDoctorDialer{snapshot: tunnel.ClientSnapshot{
			SelectedTransport: "quic",
			ClientPacing:      "adaptive-balanced",
			RelayPacing:       "adaptive-balanced",
		}}
		var stdout, stderr bytes.Buffer
		err := runDoctorWith(context.Background(), []string{
			"--json", "--json=false", "--target", "example.com:443",
		}, &stdout, &stderr, func(tunnelFlags) (closeDialer, error) {
			return dialer, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(stdout.String(), "Authenticated relay TCP probe: OK") {
			t.Fatalf("final --json=false did not select human output: %q", stdout.String())
		}
	})

	t.Run("positional argument before JSON flag", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		err := runDoctorWith(context.Background(), []string{"stray", "--json"}, &stdout, &stderr, nil)
		if commandExitCode(err) != doctorExitUsageFailure {
			t.Fatalf("exit=%d err=%v", commandExitCode(err), err)
		}
		var failure doctorFailure
		if decodeErr := json.Unmarshal(stdout.Bytes(), &failure); decodeErr != nil {
			t.Fatalf("decode JSON %q: %v", stdout.String(), decodeErr)
		}
		if failure.Code != "invalid_arguments" || stderr.Len() != 0 {
			t.Fatalf("failure=%+v stderr=%q", failure, stderr.String())
		}
	})

	t.Run("missing string value swallows JSON flag", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		err := runDoctorWith(context.Background(), []string{"--target", "--json"}, &stdout, &stderr, nil)
		if commandExitCode(err) != doctorExitUsageFailure {
			t.Fatalf("exit=%d err=%v", commandExitCode(err), err)
		}
		var failure doctorFailure
		if decodeErr := json.Unmarshal(stdout.Bytes(), &failure); decodeErr != nil {
			t.Fatalf("decode JSON %q: %v", stdout.String(), decodeErr)
		}
		if failure.Code != "invalid_target" || stderr.Len() != 0 {
			t.Fatalf("failure=%+v stderr=%q", failure, stderr.String())
		}
	})

	t.Run("JSON plus help prints safe usage", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		err := runDoctorWith(context.Background(), []string{"--json", "-h"}, &stdout, &stderr, nil)
		if !errors.Is(err, flag.ErrHelp) {
			t.Fatalf("error=%v, want flag.ErrHelp", err)
		}
		if stdout.Len() != 0 || !strings.Contains(stderr.String(), "Usage of doctor:") || !strings.Contains(stderr.String(), "-target") {
			t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
	})

	t.Run("JSON configuration failure redacts raw path", func(t *testing.T) {
		const privateCause = "open /private/customer/relay-token: permission denied"
		var stdout bytes.Buffer
		err := runDoctorWith(context.Background(), []string{"--json", "--target", "example.com:443"}, &stdout, &bytes.Buffer{}, func(tunnelFlags) (closeDialer, error) {
			return nil, errors.New(privateCause)
		})
		if commandExitCode(err) != doctorExitUsageFailure || strings.Contains(stdout.String(), privateCause) || strings.Contains(err.Error(), privateCause) {
			t.Fatalf("JSON configuration failure leaked raw cause: stdout=%q err=%q", stdout.String(), err)
		}
	})

	t.Run("configuration failure", func(t *testing.T) {
		err := runDoctorWith(context.Background(), []string{"--target", "example.com:443"}, &bytes.Buffer{}, &bytes.Buffer{}, func(tunnelFlags) (closeDialer, error) {
			return nil, errors.New("bad credentials")
		})
		if commandExitCode(err) != doctorExitUsageFailure || !strings.Contains(err.Error(), "configure authenticated tunnel") {
			t.Fatalf("exit=%d err=%v", commandExitCode(err), err)
		}
	})

	t.Run("nil successful connection", func(t *testing.T) {
		dialer := &nilDoctorDialer{}
		err := runDoctorWith(context.Background(), []string{"--target", "example.com:443"}, &bytes.Buffer{}, &bytes.Buffer{}, func(tunnelFlags) (closeDialer, error) {
			return dialer, nil
		})
		if commandExitCode(err) != doctorExitProbeFailure || !strings.Contains(err.Error(), "returned no TCP connection") {
			t.Fatalf("exit=%d err=%v", commandExitCode(err), err)
		}
	})
}

type nilDoctorDialer struct{}

func (*nilDoctorDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, nil
}
func (*nilDoctorDialer) Close() error { return nil }

func TestValidateDoctorTarget(t *testing.T) {
	for _, valid := range []string{"example.com:443", "127.0.0.1:1", "[2001:db8::1]:65535"} {
		if err := validateDoctorTarget(valid); err != nil {
			t.Errorf("%q: %v", valid, err)
		}
	}
	for _, invalid := range []string{
		"", "example.com", ":443", "2001:db8::1:443", "example.com:0", "example.com:https", "example.com:65536",
		"bad\nhost:443", strings.Repeat("x", 1025),
	} {
		if err := validateDoctorTarget(invalid); err == nil {
			t.Errorf("invalid target %q was accepted", invalid)
		}
	}
}

func TestCommandExitCodeDefaults(t *testing.T) {
	if got := commandExitCode(nil); got != 0 {
		t.Fatalf("nil exit code = %d", got)
	}
	if got := commandExitCode(errors.New("ordinary")); got != 1 {
		t.Fatalf("ordinary exit code = %d", got)
	}
	if got := commandExitCode(withExitCode(2, errors.New("usage"))); got != 2 {
		t.Fatalf("coded exit code = %d", got)
	}
}

func TestDoctorJSONRequested(t *testing.T) {
	tests := []struct {
		args []string
		want bool
	}{
		{args: []string{"--json"}, want: true},
		{args: []string{"-json=true"}, want: true},
		{args: []string{"--bogus", "--json"}, want: true},
		{args: []string{"--json=false"}, want: false},
		{args: []string{"--json=not-a-boolean"}, want: true},
		{args: []string{"--json", "--json=false"}, want: true},
		{args: []string{"--target", "json.example:443"}, want: false},
	}
	for _, test := range tests {
		if got := doctorJSONRequested(test.args); got != test.want {
			t.Errorf("doctorJSONRequested(%q) = %v, want %v", test.args, got, test.want)
		}
	}
}
