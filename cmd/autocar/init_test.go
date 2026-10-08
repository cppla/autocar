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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/config"
	"github.com/cppla/autocar/internal/security"
	"github.com/cppla/autocar/internal/tunnel"
)

func TestInitCreatesPrivatePortableMatchingBundle(t *testing.T) {
	for _, test := range []struct {
		server    string
		name      string
		protocol  string
		transport string
	}{
		{"relay.example.com:8443", "", "", "web-auto"},
		{"127.0.0.1:443", "relay.example.com", "", "web-auto"},
		{"[::1]:8443", "", "", "web-auto"},
		{"relay.example.com:8443", "", "native", "auto"},
		{"127.0.0.1:443", "relay.example.com", "native", "auto"},
		{"[::1]:8443", "", "native", "auto"},
		{"relay.example.com:8443", "", "web", "web-auto"},
		{"relay.example.com:8443", "", " Native ", "auto"},
	} {
		t.Run(test.server+test.name+"/"+test.protocol, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "new bundle")
			var stdout bytes.Buffer
			args := []string{"--server", test.server, "--out", dir, "--days=2"}
			if test.protocol != "" {
				args = append(args, "--protocol", test.protocol)
			}
			wantProtocol := "web"
			if test.transport == "auto" {
				wantProtocol = "native"
			}
			if test.name != "" {
				args = append(args, "--server-name", test.name)
			}
			if err := runInitWith(args, &stdout); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(stdout.String(), "No service or network connection was started") {
				t.Fatal("initialization output did not state its offline scope")
			}
			if !strings.Contains(stdout.String(), "Created "+wantProtocol+" configuration bundle") {
				t.Fatal("initialization output did not identify the generated protocol")
			}
			files := snapshotInitBundle(t, dir)
			wantFiles := []string{".gitignore", "server/.gitignore", "client/.gitignore", "README.txt", "server/server.json", "server/server.crt", "server/server.key", "server/relay-token", "client/client.json", "client/server.crt", "client/relay-token"}
			wantDirectories := []string{".", "server", "client"}
			if wantProtocol == "web" {
				wantFiles = append(wantFiles, "server/cover/index.html")
				wantDirectories = append(wantDirectories, "server/cover")
			}
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
				for _, name := range wantDirectories {
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
			if tf.mode != test.transport || tf.systemRoots || tf.server != test.server {
				t.Fatal("generated client changed transport, server or trust defaults")
			}
			clientOptions, err := readCommandConfig(filepath.Join(dir, "client", "client.json"))
			if err != nil {
				t.Fatal(err)
			}
			if wantProtocol == "web" {
				if clientOptions["h3-fingerprint"] != string(tunnel.H3FingerprintChrome202610) || tf.h3Fingerprint != h3FingerprintFlag(tunnel.H3FingerprintChrome202610) {
					t.Fatal("web bundle must explicitly pin the current H3 fingerprint")
				}
			} else if _, ok := clientOptions["h3-fingerprint"]; ok {
				t.Fatal("native bundle unexpectedly contains an H3 fingerprint option")
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
			if err != nil || server["protocol"] != wantProtocol || server["allow-private"] != nil || server["disable-tcp-fallback"] != nil {
				t.Fatal("generated server changed safe defaults")
			}
			if wantProtocol == "web" {
				if server["cover-root"] != "cover" || server["cover-upstream"] != nil {
					t.Fatal("web bundle does not use its isolated static cover directory")
				}
			} else {
				if server["cover-root"] != nil || server["cover-upstream"] != nil {
					t.Fatal("native bundle unexpectedly contains cover options")
				}
				if files["README.txt"] != sha256.Sum256([]byte(initBundleInstructions)) {
					t.Fatal("native bundle instructions changed")
				}
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
		{"--server", "relay:443", "--protocol="},
		{"--server", "relay:443", "--protocol", "auto"},
		{"--server", "relay:443", "--protocol", "quic"},
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
	dnsCalls := denyPreflightDNS(t)
	for _, protocol := range []string{"default-web", "native"} {
		t.Run(protocol, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "bundle")
			args := []string{"--server=relay.invalid:8443", "--out", dir}
			if protocol == "native" {
				args = append(args, "--protocol=native")
			}
			if err := runInitWith(args, io.Discard); err != nil {
				t.Fatal(err)
			}
			before := snapshotInitBundle(t, dir)
			for _, role := range []string{"server", "client"} {
				if err := run(context.Background(), []string{role, "--config", filepath.Join(dir, role, role+".json"), "--check"}); err != nil {
					t.Fatalf("generated %s offline check: %v", role, err)
				}
			}
			if !reflect.DeepEqual(before, snapshotInitBundle(t, dir)) {
				t.Fatal("offline checks changed the generated bundle")
			}
			// The client trust anchor must contain only the certificate.
			data, err := os.ReadFile(filepath.Join(dir, "client", "server.crt"))
			if err != nil {
				t.Fatal(err)
			}
			block, rest := pem.Decode(data)
			if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
				t.Fatal("client trust anchor has unexpected PEM material")
			}
		})
	}
	if dnsCalls.Load() != 0 {
		t.Fatal("generated configuration checks performed a DNS lookup")
	}
}

func TestInitDefaultWebCoverKeepsCredentialsOutsideDocumentRoot(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	if err := runInitWith([]string{"--server=relay.invalid:8443", "--out", dir}, io.Discard); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "server", "cover")
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 || entries[0].Name() != "index.html" || entries[0].IsDir() {
		t.Fatal("public cover directory contains unexpected files")
	}
	page, err := os.ReadFile(filepath.Join(root, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"relay-token", "server.key", "server.crt", "server.json"} {
		private, err := os.ReadFile(filepath.Join(dir, "server", name))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(page, bytes.TrimSpace(private)) {
			t.Fatalf("cover page contains private bundle file %s", name)
		}
	}
	handler, err := buildCoverHandler(root, "")
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://relay.invalid/", nil))
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), page) {
		t.Fatalf("cover page response: status=%d", response.Code)
	}
	for _, path := range []string{"/relay-token", "/server.key", "/server.crt", "/server.json", "/../server.key"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://relay.invalid"+path, nil))
		if response.Code == http.StatusOK {
			t.Fatalf("cover served private path %s", path)
		}
	}
	instructions, err := os.ReadFile(filepath.Join(dir, "README.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"web-cover deployment bundle", "web/web-auto", "server/cover/", "outside that directory", "init --protocol=native"} {
		if !bytes.Contains(instructions, []byte(text)) {
			t.Fatalf("web instructions omit %q", text)
		}
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
