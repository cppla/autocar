package main

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cppla/autocar/internal/security"
)

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

func TestLoadOptionalSecret(t *testing.T) {
	t.Setenv("AUTOCAR_TEST_OPTIONAL_SECRET", "")
	value, err := loadOptionalSecret("", "AUTOCAR_TEST_OPTIONAL_SECRET", 16)
	if err != nil || value != nil {
		t.Fatalf("empty optional secret = %q, %v", value, err)
	}
	t.Setenv("AUTOCAR_TEST_OPTIONAL_SECRET", "short")
	if _, err := loadOptionalSecret("", "AUTOCAR_TEST_OPTIONAL_SECRET", 16); err == nil {
		t.Fatal("short optional secret was accepted")
	}
	t.Setenv("AUTOCAR_TEST_OPTIONAL_SECRET", strings.Repeat("x", 16))
	value, err = loadOptionalSecret("", "AUTOCAR_TEST_OPTIONAL_SECRET", 16)
	if err != nil || string(value) != strings.Repeat("x", 16) {
		t.Fatalf("optional secret = %q, %v", value, err)
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
	prefixes, err := parseDeniedPrefixes("10.0.0.1, 192.168.0.0/16,10.0.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	if len(prefixes) != 2 || prefixes[0].String() != "10.0.0.1/32" || prefixes[1].String() != "192.168.0.0/16" {
		t.Fatalf("prefixes = %v", prefixes)
	}
	if _, err := parseDeniedPrefixes("not-a-prefix"); err == nil {
		t.Fatal("invalid prefix accepted")
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
	for _, command := range []string{"client", "server", "cert", "token", "bench-server", "bench-client"} {
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

func TestPercentile(t *testing.T) {
	values := []float64{1, 2, 3, 4, 5}
	if got := percentile(values, 0.5); got != 3 {
		t.Fatalf("median=%v", got)
	}
	if got := percentile(values, 0.95); got != 5 {
		t.Fatalf("p95=%v", got)
	}
}
