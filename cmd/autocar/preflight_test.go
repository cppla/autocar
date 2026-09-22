package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/security"
)

type preflightFiles struct {
	directory, cert, key, token, cover string
}

func newPreflightFiles(t *testing.T) preflightFiles {
	t.Helper()
	directory := t.TempDir()
	files := preflightFiles{
		directory: directory,
		cert:      filepath.Join(directory, "relay.crt"),
		key:       filepath.Join(directory, "relay.key"),
		token:     filepath.Join(directory, "token"),
		cover:     filepath.Join(directory, "cover"),
	}
	if err := security.WriteSelfSignedCertificate(files.cert, files.key, security.CertificateOptions{
		Hosts: []string{"relay.invalid"}, ValidFor: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files.token, []byte("offline-preflight-secret-never-log-this\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(files.cover, 0o700); err != nil {
		t.Fatal(err)
	}
	return files
}

func (files preflightFiles) clientArgs() []string {
	return []string{"--check", "--server", "relay.invalid:443", "--ca", files.cert, "--token-file", files.token}
}

func (files preflightFiles) serverArgs() []string {
	return []string{"--check", "--listen", "relay.invalid:443", "--cert", files.cert, "--key", files.key, "--token-file", files.token}
}

func denyPreflightDNS(t *testing.T) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	original := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			calls.Add(1)
			return nil, errors.New("unexpected DNS during offline configuration check")
		},
	}
	t.Cleanup(func() { net.DefaultResolver = original })
	return &calls
}

func clearPreflightEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{"AUTOCAR_TOKEN", "AUTOCAR_PROXY_USER", "AUTOCAR_PROXY_PASSWORD"} {
		t.Setenv(key, "")
	}
}

func TestPreflightClientAllTransportsStayOffline(t *testing.T) {
	clearPreflightEnvironment(t)
	files := newPreflightFiles(t)
	dnsCalls := denyPreflightDNS(t)
	for _, mode := range []string{"auto", "quic", "tls", "web-auto", "h2", "h3"} {
		t.Run(mode, func(t *testing.T) {
			args := append(files.clientArgs(), "--transport", mode)
			if err := runClient(context.Background(), args); err != nil {
				t.Fatal(err)
			}
		})
	}
	if got := dnsCalls.Load(); got != 0 {
		t.Fatalf("offline checks attempted %d DNS connections", got)
	}
}

func TestPreflightServerModesStayOffline(t *testing.T) {
	clearPreflightEnvironment(t)
	files := newPreflightFiles(t)
	dnsCalls := denyPreflightDNS(t)
	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamRequests.Add(1)
	}))
	defer upstream.Close()
	for _, test := range []struct {
		name string
		args []string
	}{
		{"native", nil},
		{"native mTLS", []string{"--client-ca", files.cert}},
		{"web static", []string{"--protocol", "web", "--cover-root", files.cover}},
		{"web unresolved upstream", []string{"--protocol", "web", "--cover-upstream", "https://cover.invalid/"}},
		{"web live upstream", []string{"--protocol", "web", "--cover-upstream", upstream.URL}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := runServer(context.Background(), append(files.serverArgs(), test.args...)); err != nil {
				t.Fatal(err)
			}
		})
	}
	if got := dnsCalls.Load(); got != 0 {
		t.Fatalf("offline checks attempted %d DNS connections", got)
	}
	if got := upstreamRequests.Load(); got != 0 {
		t.Fatalf("offline checks made %d cover upstream requests", got)
	}
}

func TestPreflightOccupiedPortsAreNotBoundOrDialed(t *testing.T) {
	clearPreflightEnvironment(t)
	files := newPreflightFiles(t)
	tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: tcp.Addr().(*net.TCPAddr).Port})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	address := tcp.Addr().String()
	for _, mode := range []string{"auto", "quic", "tls", "web-auto", "h2", "h3"} {
		args := append(files.clientArgs(), "--server", address, "--transport", mode, "--socks", address, "--http", "")
		if err := runClient(context.Background(), args); err != nil {
			t.Fatalf("%s client tried to bind or connect: %v", mode, err)
		}
	}
	for _, mode := range []string{"native", "web"} {
		args := append(files.serverArgs(), "--listen", address, "--protocol", mode)
		if mode == "web" {
			args = append(args, "--cover-root", files.cover)
		}
		if err := runServer(context.Background(), args); err != nil {
			t.Fatalf("%s server tried to bind occupied port: %v", mode, err)
		}
	}
	if err := tcp.SetDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	conn, err := tcp.Accept()
	if conn != nil {
		conn.Close()
		t.Fatal("offline check connected to the configured relay")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("check TCP observer: %v", err)
	}
	if err := udp.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, _, err = udp.ReadFromUDP(make([]byte, 1))
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("offline check sent a UDP datagram or observer failed: %v", err)
	}
}

func TestPreflightClientRejectsInvalidConfiguration(t *testing.T) {
	clearPreflightEnvironment(t)
	files := newPreflightFiles(t)
	missing := filepath.Join(files.directory, "missing")
	for _, test := range []struct {
		name, want string
		args       []string
	}{
		{"mode", "invalid --transport", []string{"--transport", "unknown"}},
		{"relay host", "invalid address", []string{"--server", ":443"}},
		{"relay syntax", "invalid host", []string{"--server", "bad host.invalid:443"}},
		{"relay port", "between 1 and 65535", []string{"--server", "relay.invalid:65536"}},
		{"relay zero port", "between 1 and 65535", []string{"--server", "relay.invalid:0"}},
		{"named service", "requires a numeric port", []string{"--server", "relay.invalid:https"}},
		{"fallback", "--fallback-server", []string{"--fallback-server", "relay.invalid:65536"}},
		{"local port", "--socks", []string{"--socks", "127.0.0.1:65536"}},
		{"no listener", "at least one", []string{"--socks", "", "--http", ""}},
		{"public listener", "unauthenticated", []string{"--socks", "0.0.0.0:1080"}},
		{"CA missing", "read CA file", []string{"--ca", missing}},
		{"CA malformed", "parse CA file", []string{"--ca", files.token}},
		{"token missing", "stat secret file", []string{"--token-file", missing}},
		{"mTLS pair missing", "supplied together", []string{"--client-cert", files.cert}},
		{"mTLS key missing", "open TLS private key", []string{"--client-cert", files.cert, "--client-key", missing}},
		{"HTTPS pair missing", "requires --proxy-cert", []string{"--https", "127.0.0.1:8443"}},
		{"HTTPS key missing", "open TLS private key", []string{"--https", "127.0.0.1:8443", "--proxy-cert", files.cert, "--proxy-key", missing}},
		{"idle timeout", "--idle-timeout", []string{"--idle-timeout", "-1s"}},
		{"fallback budget", "fallback retains time", []string{"--quic-attempt-timeout", "15s"}},
		{"H3 profile", "fingerprint", []string{"--transport", "h3", "--h3-fingerprint", "invalid"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := runClient(context.Background(), append(files.clientArgs(), test.args...))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestPreflightServerRejectsInvalidConfiguration(t *testing.T) {
	clearPreflightEnvironment(t)
	files := newPreflightFiles(t)
	missing := filepath.Join(files.directory, "missing")
	for _, test := range []struct {
		name, want string
		args       []string
	}{
		{"mode", "invalid --protocol", []string{"--protocol", "unknown"}},
		{"listen syntax", "invalid address", []string{"--listen", "relay.invalid"}},
		{"listen port", "between 0 and 65535", []string{"--listen", "relay.invalid:65536"}},
		{"named service", "requires a numeric port", []string{"--listen", ":https"}},
		{"fallback port", "--tcp-listen", []string{"--tcp-listen", "relay.invalid:65536"}},
		{"token missing", "stat secret file", []string{"--token-file", missing}},
		{"certificate missing", "open TLS certificate", []string{"--cert", missing}},
		{"key missing", "open TLS private key", []string{"--key", missing}},
		{"client CA missing", "read client CA", []string{"--client-ca", missing}},
		{"client CA malformed", "parse CA file", []string{"--client-ca", files.token}},
		{"ports policy", "invalid denied port", []string{"--deny-ports", "0"}},
		{"CIDR policy", "invalid denied CIDR", []string{"--deny-cidrs", "not-a-CIDR"}},
		{"dial timeout", "--dial-timeout", []string{"--dial-timeout", "-1s"}},
		{"handshake timeout", "--handshake-timeout", []string{"--handshake-timeout", "-1s"}},
		{"destination write timeout", "--destination-write-timeout", []string{"--destination-write-timeout", "-1s"}},
		{"connections", "--max-connections", []string{"--max-connections", "0"}},
		{"UDP sessions", "--max-client-udp-sessions", []string{"--max-udp-sessions", "1"}},
		{"rate bound", "protocol maximum", []string{"--pacing", "fixed-rate", "--max-upload-mbps", "8000001", "--max-download-mbps", "1"}},
		{"web missing root", "static cover", []string{"--protocol", "web", "--cover-root", missing}},
		{"web non-directory root", "not a directory", []string{"--protocol", "web", "--cover-root", files.token}},
		{"web mismatched ports", "ports must match", []string{"--protocol", "web", "--cover-root", files.cover, "--tcp-listen", "relay.invalid:8443"}},
		{"web upstream scheme", "http or https", []string{"--protocol", "web", "--cover-upstream", "file:///tmp/cover"}},
		{"web mTLS", "incompatible", []string{"--protocol", "web", "--cover-root", files.cover, "--client-ca", files.cert}},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := runServer(context.Background(), append(files.serverArgs(), test.args...))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
	if err := os.WriteFile(files.token, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runServer(context.Background(), files.serverArgs()); err == nil || !strings.Contains(err.Error(), "token length") {
		t.Fatalf("short token accepted: %v", err)
	}
}

func TestPreflightLocalFilesAndLogs(t *testing.T) {
	clearPreflightEnvironment(t)
	files := newPreflightFiles(t)
	type snapshot struct {
		info os.FileInfo
		data []byte
	}
	before := make(map[string]snapshot)
	for _, path := range []string{files.cert, files.key, files.token} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		before[path] = snapshot{info, data}
	}
	var output bytes.Buffer
	original := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(original) })
	if err := runClient(context.Background(), append(files.clientArgs(),
		"--https", "127.0.0.1:8443", "--proxy-cert", files.cert, "--proxy-key", files.key,
		"--client-cert", files.cert, "--client-key", files.key,
	)); err != nil {
		t.Fatal(err)
	}
	if err := runServer(context.Background(), files.serverArgs()); err != nil {
		t.Fatal(err)
	}
	for path, previous := range before {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, previous.data) || info.Mode() != previous.info.Mode() || !info.ModTime().Equal(previous.info.ModTime()) {
			t.Fatalf("offline check modified %s", path)
		}
	}
	for _, expected := range []string{"local configuration only", "no DNS lookup", "remote certificate identity", "port availability", "cover upstream health"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("check output omitted limitation %q: %s", expected, output.String())
		}
	}
	if strings.Contains(output.String(), "offline-preflight-secret") || strings.Contains(output.String(), "PRIVATE KEY") {
		t.Fatalf("check output exposed credentials: %s", output.String())
	}
}

func TestPreflightCheckCannotBeSetInConfig(t *testing.T) {
	for _, text := range []string{`{"check":true}`, `{"check":false}`} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, command := range []func(context.Context, []string) error{runClient, runServer} {
			err := command(context.Background(), []string{"--config", path, "--check"})
			if err == nil || !strings.Contains(err.Error(), "unsupported config option") {
				t.Fatalf("config %s error = %v, want unsupported check option", text, err)
			}
		}
	}
}

func TestPreflightWebEphemeralPortsAndDisabledFallback(t *testing.T) {
	for _, ports := range [][2]string{{":0", ":443"}, {":443", ":0"}, {":0", ":0"}} {
		if err := checkServerAddresses("web", ports[0], ports[1], false); err != nil {
			t.Errorf("web %v rejected: %v", ports, err)
		}
	}
	if err := checkServerAddresses("native", ":443", "ignored:service", true); err != nil {
		t.Fatalf("disabled fallback was checked: %v", err)
	}
	for _, address := range []string{"[::1]:443", "[fe80::1%eth0]:443", ":0", "relay.invalid:443"} {
		if _, err := checkLocalAddress("--listen", address, false); err != nil {
			t.Errorf("valid local address %q rejected: %v", address, err)
		}
	}
}

func TestServerExplicitEmptyClientCAFailsClosed(t *testing.T) {
	clearPreflightEnvironment(t)
	files := newPreflightFiles(t)
	emptyCA := filepath.Join(files.directory, "empty-ca.pem")
	if err := os.WriteFile(emptyCA, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, check := range []string{"true", "false"} {
		t.Run("check="+check, func(t *testing.T) {
			args := append(files.serverArgs(), "--check="+check, "--listen", "127.0.0.1:0", "--client-ca", emptyCA)
			err := runServer(ctx, args)
			if err == nil || !strings.Contains(err.Error(), "client CA") {
				t.Fatalf("empty client CA must never disable mTLS, error = %v", err)
			}
		})
	}
}

func TestPreflightRejectsInsecureCredentialPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission policy")
	}
	clearPreflightEnvironment(t)
	files := newPreflightFiles(t)
	for _, test := range []struct {
		name, path string
		run        func(context.Context, []string) error
		args       []string
	}{
		{"client token", files.token, runClient, files.clientArgs()},
		{"server token", files.token, runServer, files.serverArgs()},
		{"server key", files.key, runServer, files.serverArgs()},
		{"proxy key", files.key, runClient, append(files.clientArgs(), "--https", "127.0.0.1:8443", "--proxy-cert", files.cert, "--proxy-key", files.key)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.Chmod(test.path, 0o644); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.Chmod(test.path, 0o600); err != nil {
					t.Error(err)
				}
			})
			err := test.run(context.Background(), test.args)
			if err == nil || !strings.Contains(err.Error(), "permissions") {
				t.Fatalf("insecure credentials accepted: %v", err)
			}
		})
	}
}
