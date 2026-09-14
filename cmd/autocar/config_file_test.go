package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTestCommandConfig(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "connection.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCommandConfigPrecedenceAndRelativePaths(t *testing.T) {
	path := writeTestCommandConfig(t, `{
		"server":"relay.example.com:8443", "ca":"certs/ca.pem",
		"token-file":"relay-token", "transport":"quic", "system-roots":false,
		"open-timeout":"25s", "upload-mbps":18446744073709551615
	}`)
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var tf tunnelFlags
	addTunnelFlags(fs, &tf)
	if err := parseFlagsWithConfig(fs, []string{"--transport=tls", "--config", path, "--ca", "cli.pem", "--open-timeout", "20s"}); err != nil {
		t.Fatal(err)
	}
	if tf.mode != "tls" || tf.caFile != "cli.pem" || tf.openTimeout != 20*time.Second {
		t.Fatalf("CLI did not take precedence: mode=%s ca=%s timeout=%s", tf.mode, tf.caFile, tf.openTimeout)
	}
	if tf.server != "relay.example.com:8443" || tf.tokenFile != filepath.Join(filepath.Dir(path), "relay-token") || tf.uploadMbps != ^uint64(0) {
		t.Fatal("config strings, relative paths, or exact integer were not retained")
	}
	if tf.primaryTimeout != 5*time.Second || tf.systemRoots {
		t.Fatal("unspecified defaults or explicit false were not retained")
	}
}

func TestCommandConfigPathOptions(t *testing.T) {
	for _, name := range []string{"ca", "client-cert", "client-key", "token-file", "proxy-cert", "proxy-key", "proxy-password-file", "cert", "key", "client-ca", "cover-root"} {
		t.Run(name, func(t *testing.T) {
			for _, relative := range []string{"", "nested/file", filepath.Join(t.TempDir(), "absolute")} {
				data, err := json.Marshal(map[string]string{name: relative})
				if err != nil {
					t.Fatal(err)
				}
				path := writeTestCommandConfig(t, string(data))
				fs := flag.NewFlagSet("test", flag.ContinueOnError)
				got := fs.String(name, "default", "")
				if err := parseFlagsWithConfig(fs, []string{"--config=" + path}); err != nil {
					t.Fatal(err)
				}
				want := relative
				if relative != "" && !filepath.IsAbs(relative) {
					want = filepath.Join(filepath.Dir(path), relative)
				}
				if *got != want {
					t.Fatalf("path = %q; want %q", *got, want)
				}
			}
		})
	}
}

func TestCommandConfigRejectsInvalid(t *testing.T) {
	for _, text := range []string{
		``, `null`, `[]`, `{`, `{} {}`, `{} garbage`,
		`{"server":"a","server":"b"}`, `{"server":"a","\u0073erver":"b"}`,
		`{"server":null}`, `{"server":[]}`, `{"server":{}}`, `{"":true}`,
		`{"unknown":true}`, `{"config":"other.json"}`, `{"--server":"a"}`,
		`{"server":false}`, `{"system-roots":"false"}`, `{"system-roots":0}`,
		`{"open-timeout":0}`, `{"open-timeout":5}`, `{"upload-mbps":-1}`, `{"upload-mbps":1.5}`,
		`{"upload-mbps":"1"}`, `{"upload-mbps":"0x10"}`, `{"upload-mbps":1e3}`,
		`{"upload-mbps":18446744073709551616}`, `{"upload-mbps":true}`,
		`{"open-timeout":"secret-invalid-duration"}`,
	} {
		t.Run(text, func(t *testing.T) {
			path := writeTestCommandConfig(t, text)
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			var tf tunnelFlags
			addTunnelFlags(fs, &tf)
			err := parseFlagsWithConfig(fs, []string{"--config", path, "--open-timeout=30s"})
			if err == nil {
				t.Fatal("invalid config was accepted, including when overridden")
			}
			if strings.Contains(err.Error(), "secret-invalid-duration") {
				t.Fatal("invalid config value leaked into diagnostics")
			}
		})
	}
}

func TestCommandConfigIntegerFlagTypes(t *testing.T) {
	for _, value := range []string{`"1"`, `"0x10"`, `1.5`, `1e3`, `true`, `1`} {
		for _, unsigned := range []bool{false, true} {
			path := writeTestCommandConfig(t, `{"limit":`+value+`}`)
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			if unsigned {
				fs.Uint64("limit", 0, "")
			} else {
				fs.Int("limit", 0, "")
			}
			err := parseFlagsWithConfig(fs, []string{"--config", path})
			if (err == nil) != (value == "1") {
				t.Fatalf("unsigned=%t value=%s err=%v", unsigned, value, err)
			}
		}
	}
}

func TestCommandConfigExplicitFalseAndEmptyOverride(t *testing.T) {
	path := writeTestCommandConfig(t, `{"system-roots":true,"ca":"private.pem"}`)
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var tf tunnelFlags
	addTunnelFlags(fs, &tf)
	if err := parseFlagsWithConfig(fs, []string{"--config", path, "--system-roots=false", "--ca="}); err != nil {
		t.Fatal(err)
	}
	if tf.systemRoots || tf.caFile != "" {
		t.Fatal("explicit false and empty CLI values did not override config")
	}
}

func TestCommandConfigLimitsAndMissingFile(t *testing.T) {
	for _, path := range []string{
		filepath.Join(t.TempDir(), "missing.json"), t.TempDir(),
		writeTestCommandConfig(t, strings.Repeat(" ", maxCommandConfigSize)+"{}"),
	} {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		if err := parseFlagsWithConfig(fs, []string{"--config", path}); err == nil {
			t.Fatal("missing, nonregular or oversized config accepted")
		}
	}
	path := writeTestCommandConfig(t, "{}"+strings.Repeat(" ", maxCommandConfigSize-2))
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	if err := parseFlagsWithConfig(fs, []string{"--config", path}); err != nil {
		t.Fatalf("maximum-sized valid config: %v", err)
	}
}

func TestCommandConfigPreservesCLIParsing(t *testing.T) {
	for _, args := range [][]string{
		nil, {"--transport=tls"}, {"--config=", "--transport=tls"},
		{"--config", filepath.Join(t.TempDir(), "missing"), "--help"},
		{"--server", "--config", "--transport=tls"},
	} {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var tf tunnelFlags
		addTunnelFlags(fs, &tf)
		err := parseFlagsWithConfig(fs, args)
		if len(args) != 0 && args[len(args)-1] == "--help" && !errors.Is(err, flag.ErrHelp) {
			t.Fatalf("help did not return flag.ErrHelp: %v", err)
		}
		if err != nil && !errors.Is(err, flag.ErrHelp) {
			t.Fatalf("%v: %v", args, err)
		}
	}
	for _, args := range [][]string{{"unexpected"}, {"--", "unexpected"}, {"--config"}, {"--bogus"}} {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		if err := parseFlagsWithConfig(fs, args); err == nil {
			t.Fatalf("invalid CLI accepted: %v", args)
		}
	}
}

func TestCommandConfigWiredIntoClientAndServer(t *testing.T) {
	// These fail before any credential access or listener is opened, proving
	// each command consumes its config and keeps normal semantic validation.
	client := writeTestCommandConfig(t, `{"socks":"", "http":"", "https":""}`)
	if err := runClient(context.Background(), []string{"--config", client}); err == nil || !strings.Contains(err.Error(), "at least one") {
		t.Fatalf("client did not use config: %v", err)
	}
	server := writeTestCommandConfig(t, `{"protocol":"not-a-protocol"}`)
	if err := runServer(context.Background(), []string{"--config", server}); err == nil || !strings.Contains(err.Error(), "--protocol") {
		t.Fatalf("server did not use config: %v", err)
	}
}
