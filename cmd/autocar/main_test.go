package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/accel"
	"github.com/cppla/autocar/internal/netbench"
	"github.com/cppla/autocar/internal/security"
)

type benchmarkAccelerationReporter struct {
	mode       string
	tx         uint64
	remoteMode string
	remoteTx   uint64
}

func (r benchmarkAccelerationReporter) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not used")
}

func (r benchmarkAccelerationReporter) AccelerationMode() string { return r.mode }
func (r benchmarkAccelerationReporter) NegotiatedTx() uint64     { return r.tx }
func (r benchmarkAccelerationReporter) RemoteTxAcceleration() string {
	return r.remoteMode
}
func (r benchmarkAccelerationReporter) RemoteNegotiatedTx() uint64 { return r.remoteTx }

type benchmarkLocalReporter struct {
	mode string
	tx   uint64
}

func (r benchmarkLocalReporter) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not used")
}

func (r benchmarkLocalReporter) AccelerationMode() string { return r.mode }
func (r benchmarkLocalReporter) NegotiatedTx() uint64     { return r.tx }

type benchmarkSelectedTransportReporter struct {
	selected string
}

func (r benchmarkSelectedTransportReporter) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not used")
}

func (r benchmarkSelectedTransportReporter) SelectedTransport() string { return r.selected }

func TestMegabitsToBytesPerSecond(t *testing.T) {
	for value, wanted := range map[uint64]uint64{
		0:   0,
		1:   125_000,
		100: 12_500_000,
	} {
		got, err := megabitsToBytesPerSecond(value)
		if err != nil || got != wanted {
			t.Fatalf("%d Mbit/s = %d B/s, %v; want %d", value, got, err, wanted)
		}
	}
	if _, err := megabitsToBytesPerSecond(math.MaxUint64); err == nil {
		t.Fatal("overflowing bandwidth was accepted")
	}
}

func TestParseDeniedPorts(t *testing.T) {
	ports, err := parseDeniedPorts("25, 443,25")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 2 || ports[0] != 25 || ports[1] != 443 {
		t.Fatalf("unexpected ports: %v", ports)
	}
	ports, err = parseDeniedPorts("none")
	if err != nil || len(ports) != 0 {
		t.Fatalf("none: %v, %v", ports, err)
	}
	if _, err := parseDeniedPorts("0"); err == nil {
		t.Fatal("expected invalid-port error")
	}
}

func TestParseDeniedPrefixes(t *testing.T) {
	prefixes, err := parseDeniedPrefixes("10.0.0.1, ::ffff:192.168.0.0/112,10.0.0.1/32,192.168.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	if len(prefixes) != 2 || prefixes[0].String() != "10.0.0.1/32" || prefixes[1].String() != "192.168.0.0/16" {
		t.Fatalf("prefixes = %v", prefixes)
	}
	if _, err := parseDeniedPrefixes("not-a-prefix"); err == nil {
		t.Fatal("invalid prefix accepted")
	}
	for _, ambiguous := range []string{"::ffff:8.8.8.8/95", "::fffe:0:0/95"} {
		if _, err := parseDeniedPrefixes(ambiguous); err == nil {
			t.Fatalf("ambiguous IPv4-mapped prefix %q accepted", ambiguous)
		}
	}
}

func TestEnsureSafeLocalListener(t *testing.T) {
	for _, address := range []string{"127.0.0.1:1080", "[::1]:1080"} {
		if err := ensureSafeLocalListener(address, false); err != nil {
			t.Fatalf("%s: %v", address, err)
		}
	}
	for _, address := range []string{":1080", "0.0.0.0:1080", "192.0.2.10:1080", "localhost:1080"} {
		if err := ensureSafeLocalListener(address, false); err == nil {
			t.Fatalf("expected %s to be rejected", address)
		}
		if err := ensureSafeLocalListener(address, true); err != nil {
			t.Fatalf("authenticated %s: %v", address, err)
		}
	}
}

func TestEnsureProtectedPlaintextListener(t *testing.T) {
	for _, address := range []string{"127.0.0.1:1080", "[::1]:8080"} {
		if err := ensureProtectedPlaintextListener(address, false); err != nil {
			t.Fatalf("loopback %q rejected: %v", address, err)
		}
	}
	if err := ensureProtectedPlaintextListener("0.0.0.0:1080", false); err == nil {
		t.Fatal("public plaintext listener was accepted without explicit opt-in")
	}
	if err := ensureProtectedPlaintextListener("0.0.0.0:1080", true); err != nil {
		t.Fatalf("explicit public plaintext opt-in rejected: %v", err)
	}
	if err := ensureProtectedPlaintextListener("localhost:1080", false); err == nil {
		t.Fatal("hostname listener was trusted without resolving its bind targets")
	}
}

func TestValidateProxyCredentials(t *testing.T) {
	if err := validateProxyCredentials("alice", strings.Repeat("x", 16), true); err != nil {
		t.Fatal(err)
	}
	if err := validateProxyCredentials("alice", "too-short", true); err == nil {
		t.Fatal("short local proxy password accepted")
	}
	if err := validateProxyCredentials(strings.Repeat("u", 256), strings.Repeat("p", 16), true); err == nil {
		t.Fatal("oversized SOCKS5 username accepted")
	}
	if err := validateProxyCredentials("alice", strings.Repeat("p", 256), true); err == nil {
		t.Fatal("oversized SOCKS5 password accepted")
	}
	if err := validateProxyCredentials(strings.Repeat("u", 256), strings.Repeat("p", 256), false); err != nil {
		t.Fatalf("HTTP-only credentials were incorrectly limited to RFC 1929: %v", err)
	}
}

func TestEnsureSafeBenchmarkListener(t *testing.T) {
	for _, address := range []string{"127.0.0.1:9000", "[::1]:9000"} {
		if err := ensureSafeBenchmarkListener(address, false); err != nil {
			t.Fatalf("loopback %q rejected: %v", address, err)
		}
	}
	for _, address := range []string{":9000", "0.0.0.0:9000", "192.0.2.10:9000", "bench.example:9000", "localhost:9000"} {
		if err := ensureSafeBenchmarkListener(address, false); err == nil {
			t.Fatalf("non-loopback %q accepted without explicit opt-in", address)
		}
		if err := ensureSafeBenchmarkListener(address, true); err != nil {
			t.Fatalf("explicit opt-in for %q rejected: %v", address, err)
		}
	}
	if err := ensureSafeBenchmarkListener("missing-port", true); err == nil {
		t.Fatal("malformed benchmark listener accepted")
	}
}

func TestBenchServerRejectsPublicListenerByDefault(t *testing.T) {
	err := runBenchServer(context.Background(), []string{"--listen", "0.0.0.0:0"})
	if err == nil || !strings.Contains(err.Error(), "--allow-public-benchmark") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTokenCommandCreatesPrivateFileAndWillNotOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := runToken([]string{"--out", path}); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.TrimSpace(string(contents))) < 32 {
		t.Fatalf("token unexpectedly short: %d", len(contents))
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode %04o", info.Mode().Perm())
		}
	}
	if err := runToken([]string{"--out", path}); err == nil {
		t.Fatal("expected overwrite refusal")
	}
}

func TestCertCommandCreatesVerifiableCertificate(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	if err := runCert([]string{"--hosts", "relay.test,127.0.0.1", "--cert", certFile, "--key", keyFile, "--days", "30"}); err != nil {
		t.Fatal(err)
	}
	if _, err := security.LoadKeyPair(certFile, keyFile); err != nil {
		t.Fatal(err)
	}
	if err := runCert([]string{"--hosts", "relay.test", "--cert", certFile, "--key", keyFile}); err == nil {
		t.Fatal("expected overwrite refusal")
	}
}

func TestRunHelpAndUnknownCommand(t *testing.T) {
	if err := run(context.Background(), []string{"help"}); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"client", "server", "cert", "token", "bench-server", "bench-client", "doctor"} {
		t.Run(command+" help", func(t *testing.T) {
			if err := run(context.Background(), []string{command, "-h"}); err != nil {
				t.Fatalf("%s -h: %v", command, err)
			}
		})
	}
	if err := run(context.Background(), []string{"does-not-exist"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestServerRejectsFallbackSourceLimitAboveGlobalLimit(t *testing.T) {
	err := runServer(context.Background(), []string{
		"--cert", "unused.crt",
		"--key", "unused.key",
		"--max-streams", "1",
		"--max-client-fallback-connections", "2",
	})
	if err == nil || !strings.Contains(err.Error(), "--max-client-fallback-connections") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServerUDPLimitValidation(t *testing.T) {
	valid := serverUDPLimits{
		maxSessions:           256,
		maxClientSessions:     32,
		maxDestinations:       64,
		receiveQueue:          32,
		reassemblyTTL:         5 * time.Second,
		maxReassemblyMessages: 64,
		maxReassemblyBytes:    256 << 10,
	}
	if err := validateServerUDPLimits(valid); err != nil {
		t.Fatalf("default UDP limits: %v", err)
	}

	tests := []struct {
		name      string
		arguments []string
		want      string
	}{
		{name: "sessions zero", arguments: []string{"--max-udp-sessions", "0"}, want: "--max-udp-sessions"},
		{name: "sessions negative", arguments: []string{"--max-udp-sessions", "-1"}, want: "--max-udp-sessions"},
		{name: "client sessions zero", arguments: []string{"--max-client-udp-sessions", "0"}, want: "--max-client-udp-sessions"},
		{name: "client sessions above global", arguments: []string{"--max-udp-sessions", "1", "--max-client-udp-sessions", "2"}, want: "no greater than --max-udp-sessions"},
		{name: "destinations zero", arguments: []string{"--max-udp-destinations", "0"}, want: "--max-udp-destinations"},
		{name: "queue zero", arguments: []string{"--udp-receive-queue", "0"}, want: "--udp-receive-queue"},
		{name: "ttl zero", arguments: []string{"--udp-reassembly-ttl", "0s"}, want: "--udp-reassembly-ttl"},
		{name: "messages zero", arguments: []string{"--max-udp-reassembly-messages", "0"}, want: "--max-udp-reassembly-messages"},
		{name: "bytes zero", arguments: []string{"--max-udp-reassembly-bytes", "0"}, want: "--max-udp-reassembly-bytes"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			arguments := append([]string{"--cert", "unused.crt", "--key", "unused.key"}, test.arguments...)
			err := runServer(context.Background(), arguments)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("runServer error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestServerHelpListsUDPLimitFlags(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalStderr := os.Stderr
	os.Stderr = writer
	runErr := runServer(context.Background(), []string{"-h"})
	os.Stderr = originalStderr
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(runErr, flag.ErrHelp) {
		t.Fatalf("runServer(-h) error = %v, want flag.ErrHelp", runErr)
	}

	for _, name := range []string{
		"-max-udp-sessions",
		"-max-client-udp-sessions",
		"-max-udp-destinations",
		"-udp-receive-queue",
		"-udp-reassembly-ttl",
		"-max-udp-reassembly-messages",
		"-max-udp-reassembly-bytes",
	} {
		if !strings.Contains(string(output), name) {
			t.Errorf("server help omitted %s", name)
		}
	}
}

func TestPacingConfigValidation(t *testing.T) {
	tests := []struct {
		mode        string
		profile     string
		wantMode    accel.Mode
		wantProfile accel.Profile
		wantError   bool
	}{
		{mode: "", profile: "", wantMode: accel.ModeAdaptive, wantProfile: accel.ProfileBalanced},
		{mode: " ADAPTIVE ", profile: " CONSERVATIVE ", wantMode: accel.ModeAdaptive, wantProfile: accel.ProfileConservative},
		{mode: "reno", profile: "balanced", wantMode: accel.ModeReno, wantProfile: accel.ProfileBalanced},
		{mode: "fixed-rate", profile: "aggressive", wantMode: accel.ModeFixedRate, wantProfile: accel.ProfileAggressive},
		{mode: "unknown", profile: "balanced", wantError: true},
		{mode: "adaptive", profile: "unknown", wantError: true},
	}
	for _, test := range tests {
		config, err := newPacingConfig(test.mode, test.profile)
		if test.wantError {
			if err == nil {
				t.Errorf("newPacingConfig(%q, %q) unexpectedly succeeded", test.mode, test.profile)
			}
			continue
		}
		if err != nil {
			t.Errorf("newPacingConfig(%q, %q): %v", test.mode, test.profile, err)
			continue
		}
		if config.Mode != test.wantMode || config.Profile != test.wantProfile {
			t.Errorf("newPacingConfig(%q, %q) = %+v", test.mode, test.profile, config)
		}
	}
}

func TestPacingRateValidation(t *testing.T) {
	if err := validateClientRates(accel.ModeFixedRate, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := validateClientRates(accel.ModeFixedRate, 1, 0); err == nil {
		t.Fatal("fixed-rate client accepted a missing download rate")
	}
	if err := validateClientRates(accel.ModeAdaptive, 1, 1); err == nil {
		t.Fatal("adaptive client accepted fixed-rate hints")
	}
	if err := validateServerRates(accel.ModeAdaptive, false, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := validateServerRates(accel.ModeAdaptive, true, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := validateServerRates(accel.ModeFixedRate, false, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := validateServerRates(accel.ModeFixedRate, false, 1, 0); err == nil {
		t.Fatal("fixed-rate server accepted a missing direction")
	}
	if err := validateServerRates(accel.ModeAdaptive, false, 1, 1); err == nil {
		t.Fatal("unused server rate maxima were accepted")
	}
}

func TestTLSCannotSilentlyIgnoreFixedRatePacing(t *testing.T) {
	err := validateClientPacingTransport("tls", accel.ModeFixedRate)
	if err == nil || !strings.Contains(err.Error(), "requires --transport=quic") {
		t.Fatalf("unexpected TLS fixed-rate result: %v", err)
	}
	if err := validateClientPacingTransport("auto", accel.ModeFixedRate); err != nil {
		t.Fatalf("auto fixed-rate rejected: %v", err)
	}
}

func TestPercentile(t *testing.T) {
	values := []float64{1, 2, 3, 4, 5}
	if got := percentile(values, 0.5); got != 3 {
		t.Fatalf("median=%v", got)
	}
	if got := percentile(values, 0.95); got != 5 {
		t.Fatalf("p95=%v", got)
	}
}

func TestBenchmarkAccelerationMetadataIsDirectionExplicit(t *testing.T) {
	reporter := benchmarkAccelerationReporter{
		mode:       "adaptive-balanced",
		remoteMode: "fixed-rate",
		remoteTx:   1_875_000,
	}

	upload := benchOutput{}
	populateAccelerationMetadata(&upload, netbench.ModeUpload, reporter)
	if upload.TunnelSenderEndpoint != "client" ||
		upload.LocalTxAcceleration != "adaptive-balanced" ||
		upload.PayloadSenderAcceleration != "adaptive-balanced" ||
		upload.LocalNegotiatedTxBytesSec != reporter.tx ||
		upload.PayloadSenderNegotiatedTxBytesSec != reporter.tx {
		t.Fatalf("upload acceleration metadata = %+v", upload)
	}

	download := benchOutput{}
	populateAccelerationMetadata(&download, netbench.ModeDownload, reporter)
	if download.TunnelSenderEndpoint != "relay" ||
		download.LocalTxAcceleration != "adaptive-balanced" ||
		download.LocalNegotiatedTxBytesSec != reporter.tx {
		t.Fatalf("download local acceleration metadata = %+v", download)
	}
	if download.PayloadSenderAcceleration != "fixed-rate" ||
		download.PayloadSenderNegotiatedTxBytesSec != reporter.remoteTx {
		t.Fatalf("download remote acceleration metadata = %+v", download)
	}

	reno := benchOutput{}
	populateAccelerationMetadata(&reno, netbench.ModeUpload, benchmarkAccelerationReporter{mode: "reno"})
	if reno.LocalTxAcceleration != "reno" || reno.PayloadSenderAcceleration != "reno" {
		t.Fatalf("reno acceleration metadata = %+v", reno)
	}

	localOnly := benchOutput{}
	populateAccelerationMetadata(
		&localOnly,
		netbench.ModeDownload,
		benchmarkLocalReporter{mode: "adaptive-balanced"},
	)
	if localOnly.TunnelSenderEndpoint != "relay" ||
		localOnly.PayloadSenderAcceleration != "" ||
		localOnly.PayloadSenderNegotiatedTxBytesSec != 0 {
		t.Fatalf("download attributed local-only telemetry to the relay: %+v", localOnly)
	}

	direct := benchOutput{}
	populateAccelerationMetadata(&direct, netbench.ModeDownload, nil)
	if direct.TunnelSenderEndpoint != "" || direct.LocalTxAcceleration != "" {
		t.Fatalf("direct metadata unexpectedly names a tunnel controller: %+v", direct)
	}

	selected := benchOutput{Transport: "auto", SelectedTransport: "auto"}
	populateAccelerationMetadata(
		&selected,
		netbench.ModeDownload,
		benchmarkSelectedTransportReporter{selected: "tls"},
	)
	if selected.Transport != "auto" || selected.SelectedTransport != "tls" {
		t.Fatalf("selected transport metadata = %+v", selected)
	}
}
