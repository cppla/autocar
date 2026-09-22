package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/config"
	"github.com/cppla/autocar/internal/security"
)

func TestInitCreatesPrivatePortableMatchingBundle(t *testing.T) {
	for _, test := range []struct {
		server string
		name   string
	}{
		{"relay.example.com:8443", ""},
		{"127.0.0.1:443", "relay.example.com"},
		{"[::1]:8443", ""},
	} {
		t.Run(test.server+test.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "new bundle")
			var stdout bytes.Buffer
			args := []string{"--server", test.server, "--out", dir, "--days=2"}
			if test.name != "" {
				args = append(args, "--server-name", test.name)
			}
			if err := runInitWith(args, &stdout); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(stdout.String(), "No service or network connection was started") {
				t.Fatal("initialization output did not state its offline scope")
			}
			files := snapshotInitBundle(t, dir)
			wantFiles := []string{".gitignore", "server/.gitignore", "client/.gitignore", "README.txt", "server/server.json", "server/server.crt", "server/server.key", "server/relay-token", "client/client.json", "client/server.crt", "client/relay-token"}
			if len(files) != len(wantFiles) {
				t.Fatalf("unexpected bundle file count: %d", len(files))
			}
			for _, name := range wantFiles {
				if _, ok := files[name]; !ok {
					t.Fatalf("missing bundle file: %s", name)
				}
				if runtime.GOOS != "windows" {
					info, err := os.Stat(filepath.Join(dir, filepath.FromSlash(name)))
					if err != nil || info.Mode().Perm() != 0o600 {
						t.Fatalf("file %s must have mode 0600", name)
					}
				}
			}
			if runtime.GOOS != "windows" {
				for _, name := range []string{".", "server", "client"} {
					info, err := os.Stat(filepath.Join(dir, name))
					if err != nil || info.Mode().Perm() != 0o700 {
						t.Fatalf("directory %s must have mode 0700", name)
					}
				}
			}
			token, err := config.LoadSecret(filepath.Join(dir, "server", "relay-token"), "")
			if err != nil {
				t.Fatal(err)
			}
			random, err := base64.RawURLEncoding.DecodeString(token)
			if err != nil || len(random) != 32 {
				t.Fatal("token is not 32 random bytes in base64url")
			}
			if strings.Contains(stdout.String(), token) || strings.Contains(stdout.String(), "PRIVATE KEY") {
				t.Fatal("initialization output disclosed credentials")
			}
			if files["server/relay-token"] != files["client/relay-token"] || files["server/server.crt"] != files["client/server.crt"] {
				t.Fatal("client and server credentials do not match")
			}
			for _, name := range []string{".gitignore", "server/.gitignore", "client/.gitignore"} {
				if files[name] != sha256.Sum256([]byte("*\n")) {
					t.Fatal("generated credentials are missing accidental Git-add protection")
				}
			}
			pair, err := security.LoadKeyPair(filepath.Join(dir, "server", "server.crt"), filepath.Join(dir, "server", "server.key"))
			if err != nil {
				t.Fatal(err)
			}
			cert, err := x509.ParseCertificate(pair.Certificate[0])
			if err != nil || time.Until(cert.NotAfter) < 47*time.Hour || time.Until(cert.NotAfter) > 49*time.Hour {
				t.Fatal("unexpected certificate validity")
			}
			fs := flag.NewFlagSet("client", flag.ContinueOnError)
			var tf tunnelFlags
			addTunnelFlags(fs, &tf)
			if err := parseFlagsWithConfig(fs, []string{"--config", filepath.Join(dir, "client", "client.json")}); err != nil {
				t.Fatal(err)
			}
			if tf.mode != "auto" || tf.systemRoots || tf.server != test.server {
				t.Fatal("generated client changed transport, server or trust defaults")
			}
			if err := cert.VerifyHostname(tf.serverName); err != nil {
				t.Fatalf("certificate does not match generated client server name: %v", err)
			}
			roots, err := security.LoadCertPool(tf.caFile)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cert.Verify(x509.VerifyOptions{DNSName: tf.serverName, Roots: roots}); err != nil {
				t.Fatalf("pinned certificate validation: %v", err)
			}
			dialer, err := buildTunnelDialer(tf)
			if err != nil {
				t.Fatal(err)
			}
			_ = dialer.Close()
			server, err := readCommandConfig(filepath.Join(dir, "server", "server.json"))
			if err != nil || server["protocol"] != "native" || server["allow-private"] != nil || server["disable-tcp-fallback"] != nil {
				t.Fatal("generated server changed safe defaults")
			}
			if err := runInitWith(args, io.Discard); err == nil {
				t.Fatal("existing output was accepted")
			}
			if !reflect.DeepEqual(files, snapshotInitBundle(t, dir)) {
				t.Fatal("refused initialization changed existing files")
			}
		})
	}
}

func TestInitRejectsInvalidOptionsBeforeWriting(t *testing.T) {
	for _, args := range [][]string{
		nil, {"--server", "host"}, {"--server", ":443"}, {"--server", "host:https"},
		{"--server", "host:0"}, {"--server", "host:65536"}, {"--server", "host:+443"},
		{"--server", "user:password@host:443"}, {"--server", "*.example.com:443"},
		{"--server", "[fe80::1%en0]:443"}, {"--server", "0.0.0.0:443"},
		{"--server", "[::]:443"}, {"--server", "224.0.0.1:443"},
		{"--server", "[::ffff:0.0.0.0]:443"}, {"--server", "[::ffff:224.0.0.1]:443"},
		{"--server", "255.255.255.255:443"}, {"--server", "[::ffff:255.255.255.255]:443"},
		{"--server", "[::ffff:192.0.2.1%en0]:8443"},
		{"--server", "[::ffff:192.0.2.1%en0]:8443", "--server-name", "relay.example.com"},
		{"--server", " relay:443"}, {"--server", "relay..example:443"},
		{"--server", "relay:443", "--server-name", "*.example.com"},
		{"--server", "relay:443", "--server-name", "relay:443"},
		{"--server", "relay:443", "--days=0"}, {"--server", "relay:443", "--days=1826"},
		{"--server", "relay:443", "unexpected"},
	} {
		dir := filepath.Join(t.TempDir(), "not-created")
		full := append([]string{"--out", dir}, args...)
		if err := runInitWith(full, io.Discard); err == nil {
			t.Fatalf("invalid arguments accepted: %v", args)
		}
		if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("invalid arguments created output: %v", err)
		}
	}
}

func TestInitRefusesExistingPathsAndMissingParent(t *testing.T) {
	parent := t.TempDir()
	file := filepath.Join(parent, "file")
	if err := os.WriteFile(file, []byte("leave unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths := []string{file, parent, filepath.Join(parent, "missing", "new")}
	if runtime.GOOS != "windows" {
		link := filepath.Join(parent, "link")
		if err := os.Symlink(filepath.Join(parent, "absent"), link); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, link)
	}
	for _, path := range paths {
		if err := runInitWith([]string{"--server=relay:8443", "--out", path}, io.Discard); err == nil {
			t.Fatal("non-new output path was accepted")
		}
	}
	contents, err := os.ReadFile(file)
	if err != nil || string(contents) != "leave unchanged" {
		t.Fatal("existing file changed")
	}
}

func TestInitIndependentRunsUseDifferentCredentials(t *testing.T) {
	parent := t.TempDir()
	var previous map[string][32]byte
	for _, name := range []string{"first", "second"} {
		dir := filepath.Join(parent, name)
		if err := runInitWith([]string{"--server=relay:8443", "--out", dir}, io.Discard); err != nil {
			t.Fatal(err)
		}
		next := snapshotInitBundle(t, dir)
		if previous != nil && (previous["server/relay-token"] == next["server/relay-token"] || previous["server/server.key"] == next["server/server.key"]) {
			t.Fatal("independent deployments reused credentials")
		}
		previous = next
	}
}

func TestInitHelpAndPartialFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not-created")
	if err := runInitWith([]string{"--out", dir, "--help"}, io.Discard); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("help: %v", err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("help wrote output")
	}
	// Duplicate fixed filenames simulate a mid-bundle filesystem failure. The
	// first file must remain intact and the incomplete directory must be kept.
	if err := writeInitBundle(dir, []initBundleFile{{"server/item", []byte("first")}, {"server/item", []byte("second")}}); err == nil || !strings.Contains(err.Error(), "incomplete bundle") {
		t.Fatalf("partial failure: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "server", "item"))
	if err != nil || string(data) != "first" {
		t.Fatal("partial bundle was overwritten or removed")
	}
}

func TestInitGeneratedConfigurationsPassOfflineChecks(t *testing.T) {
	clearPreflightEnvironment(t)
	dir := filepath.Join(t.TempDir(), "bundle")
	if err := runInitWith([]string{"--server=relay.invalid:8443", "--out", dir}, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"server", "client"} {
		if err := run(context.Background(), []string{role, "--config", filepath.Join(dir, role, role+".json"), "--check"}); err != nil {
			t.Fatalf("generated %s offline check: %v", role, err)
		}
	}
	// Confirm this really is a certificate-only client package, not another
	// private key hidden behind the trust-anchor filename.
	data, err := os.ReadFile(filepath.Join(dir, "client", "server.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("client trust anchor has unexpected PEM material")
	}
}

func snapshotInitBundle(t *testing.T, dir string) map[string][32]byte {
	t.Helper()
	files := make(map[string][32]byte)
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		name, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(name)] = sha256.Sum256(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}
