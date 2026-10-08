package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cppla/autocar/internal/tunnel"
)

func TestRetiredH3FingerprintCLIRejectsBeforeNetwork(t *testing.T) {
	clearPreflightEnvironment(t)
	dnsCalls := denyPreflightDNS(t)
	for _, mode := range []string{"web-auto", "h3", "h2", "auto", "quic", "tls", "direct"} {
		args := []string{"--transport", mode, "--h3-fingerprint", "chrome-2026-08"}
		for _, command := range []string{"client", "doctor", "bench-client"} {
			t.Run(command+"/"+mode, func(t *testing.T) {
				var err error
				switch command {
				case "client":
					err = runClient(context.Background(), args)
				case "bench-client":
					err = runBenchClient(context.Background(), args)
				case "doctor":
					for _, jsonOutput := range []bool{false, true} {
						var stdout, stderr bytes.Buffer
						doctorArgs := append([]string(nil), args...)
						if jsonOutput {
							doctorArgs = append(doctorArgs, "--json")
						}
						err = runDoctorWith(context.Background(), doctorArgs, &stdout, &stderr, func(tunnelFlags) (closeDialer, error) {
							t.Fatal("retired profile reached dialer construction")
							return nil, nil
						})
						if err == nil || commandExitCode(err) != doctorExitUsageFailure {
							t.Fatalf("doctor did not reject retired profile as usage error: %v", err)
						}
						assertRetiredH3MigrationMessage(t, stdout.String()+err.Error())
						if jsonOutput {
							var failure doctorFailure
							if decodeErr := json.Unmarshal(stdout.Bytes(), &failure); decodeErr != nil || failure.Diagnosis != "h3_fingerprint_retired" {
								t.Fatalf("doctor diagnosis=%q decode error=%v", failure.Diagnosis, decodeErr)
							}
						}
					}
					return
				}
				if err == nil {
					t.Fatal("retired H3 profile accepted")
				}
				assertRetiredH3MigrationMessage(t, err.Error())
			})
		}
	}
	if calls := dnsCalls.Load(); calls != 0 {
		t.Fatalf("retired profile performed %d DNS calls", calls)
	}
}

func TestRetiredH3FingerprintConfigRejectsEvenWithCLIOverride(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(configPath, []byte(`{"h3-fingerprint":"chrome-2026-08"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, override := range []string{"", "chrome-2026-10", "native"} {
		t.Run(override, func(t *testing.T) {
			fs := flag.NewFlagSet("client", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			var tf tunnelFlags
			addTunnelFlags(fs, &tf)
			args := []string{"--config", configPath}
			if override != "" {
				args = append(args, "--h3-fingerprint", override)
			}
			err := parseFlagsWithConfig(fs, args)
			if !errors.Is(err, tunnel.ErrH3FingerprintProfileRetired) {
				t.Fatalf("stale config was not rejected: %v", err)
			}
			assertRetiredH3MigrationMessage(t, err.Error())
		})
	}
}

func TestRetiredH3FingerprintConfigCommandsStayOffline(t *testing.T) {
	clearPreflightEnvironment(t)
	dnsCalls := denyPreflightDNS(t)
	configPath := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(configPath, []byte(`{"h3-fingerprint":"chrome-2026-08"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--config", configPath}
	if err := runClient(context.Background(), args); !errors.Is(err, tunnel.ErrH3FingerprintProfileRetired) {
		t.Fatalf("client stale configuration error = %v", err)
	}
	for _, jsonOutput := range []bool{false, true} {
		var stdout, stderr bytes.Buffer
		doctorArgs := append([]string(nil), args...)
		if jsonOutput {
			doctorArgs = append(doctorArgs, "--json")
		}
		err := runDoctorWith(context.Background(), doctorArgs, &stdout, &stderr, func(tunnelFlags) (closeDialer, error) {
			t.Fatal("retired configuration reached dialer construction")
			return nil, nil
		})
		if err == nil || commandExitCode(err) != doctorExitUsageFailure {
			t.Fatalf("doctor stale configuration error = %v", err)
		}
		assertRetiredH3MigrationMessage(t, stdout.String()+err.Error())
	}
	if calls := dnsCalls.Load(); calls != 0 {
		t.Fatalf("retired configuration performed %d DNS calls", calls)
	}
}

func TestH3FingerprintFlagPreservesNonRetiredValues(t *testing.T) {
	for _, profile := range []string{"", "chrome-2026-10", "native", "unused-by-native"} {
		fs := flag.NewFlagSet("native-client", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var tf tunnelFlags
		addTunnelFlags(fs, &tf)
		if err := fs.Parse([]string{"--transport", "quic", "--h3-fingerprint", profile}); err != nil {
			t.Fatalf("non-retired profile %q rejected at parse time: %v", profile, err)
		}
		if string(tf.h3Fingerprint) != profile {
			t.Fatalf("profile %q was silently changed to %q", profile, tf.h3Fingerprint)
		}
	}
}

func assertRetiredH3MigrationMessage(t *testing.T, text string) {
	t.Helper()
	for _, part := range []string{"chrome-2026-08", "retired", "--h3-fingerprint=chrome-2026-10", "--h3-fingerprint=native"} {
		if !strings.Contains(text, part) {
			t.Fatalf("retired profile message lacks %q: %s", part, text)
		}
	}
}
