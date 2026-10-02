package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/cover"
	"github.com/cppla/autocar/internal/transport"
)

const (
	webStaticSecurityPublic  = "ordinary static content\n"
	webStaticSecurityToken   = "owned-acme-challenge-token"
	webStaticSecurityOutside = "fictional-outside-marker-never-public"
	webStaticSecurityHidden  = "fictional-hidden-marker-never-public"
)

// All files are synthetic, owned temporary fixtures. The public handler is the
// actual constructor, not a test scrubber or a copy of the production policy.
func TestWebStaticCoverFilesystemSecurityOnWire(t *testing.T) {
	root := webStaticSecurityFiles(t)
	site, err := cover.NewStaticHandler(root)
	if err != nil {
		t.Fatal(err)
	}
	var handlerMu sync.Mutex
	var handlerWorkers sync.WaitGroup
	closing := false
	handlerResults := make(chan string, 64)
	website := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerMu.Lock()
		if closing {
			handlerMu.Unlock()
			http.Error(w, "closing", http.StatusServiceUnavailable)
			return
		}
		handlerWorkers.Add(1)
		handlerMu.Unlock()
		defer handlerWorkers.Done()
		defer func() { handlerResults <- r.Header.Get("X-Static-Fixture") }()
		site.ServeHTTP(w, r)
	})
	serverTLS, clientTLS := testTLSConfigs(t)
	var targetDials, targetResolutions atomic.Int64
	server, err := ListenWeb(WebServerConfig{
		TCPAddress: "127.0.0.1:0", UDPAddress: "127.0.0.1:0",
		Token: webTestToken, TLSConfig: serverTLS, Cover: website,
		Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
			targetDials.Add(1)
			return nil, errors.New("static cover fixture forbids every tunnel destination")
		}),
		UDPResolver: UDPResolverFunc(func(context.Context, string) ([]netip.AddrPort, error) {
			targetResolutions.Add(1)
			return nil, errors.New("static cover fixture forbids UDP target resolution")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	serveCtx, cancelServe := context.WithCancel(context.Background())
	serveResult, serveJoined := make(chan error, 1), make(chan struct{})
	go func() { defer close(serveJoined); serveResult <- server.Serve(serveCtx) }()
	t.Cleanup(func() {
		// Freeze worker admission before Wait, including on a Fatal path.
		handlerMu.Lock()
		closing = true
		handlerMu.Unlock()
		cancelServe()
		_ = server.Close()
		joined := make(chan struct{})
		go func() { defer close(joined); handlerWorkers.Wait() }()
		webCoverMetadataJoin(t, "static cover handlers", joined)
		webCoverMetadataJoin(t, "static combined Serve", serveJoined)
		select {
		case err := <-serveResult:
			if err != nil {
				t.Errorf("static combined Serve: %v", err)
			}
		default:
		}
	})
	cases := []struct {
		name, method, path, rangeHeader string
		status                          int
		body, contentRange, allow       string
		listing                         bool
	}{
		{name: "outside_file", method: "GET", path: "/external-file", status: 404},
		{name: "outside_directory", method: "GET", path: "/external-dir/outside.txt", status: 404},
		{name: "outside_file_head", method: "HEAD", path: "/external-file", status: 404},
		{name: "hidden_file", method: "GET", path: "/.env", status: 404},
		{name: "encoded_hidden_file", method: "GET", path: "/%2eenv", status: 404},
		{name: "hidden_directory", method: "GET", path: "/.git/config", status: 404},
		{name: "encoded_hidden_directory", method: "GET", path: "/%2Egit/config", status: 404},
		{name: "encoded_nested_hidden", method: "GET", path: "/listing/%2eenv", status: 404},
		{name: "well_known_nested_hidden", method: "GET", path: "/.well-known/%2eenv", status: 404},
		{name: "listing_filters_hidden", method: "GET", path: "/listing/", status: 200, listing: true},
		{name: "ordinary_get", method: "GET", path: "/public.txt", status: 200, body: webStaticSecurityPublic},
		{name: "ordinary_head", method: "HEAD", path: "/public.txt", status: 200},
		{name: "ordinary_range", method: "GET", path: "/public.txt", rangeHeader: "bytes=0-7", status: 206, body: webStaticSecurityPublic[:8], contentRange: fmt.Sprintf("bytes 0-7/%d", len(webStaticSecurityPublic))},
		{name: "inside_symlink", method: "GET", path: "/inside-link.txt", status: 200, body: webStaticSecurityPublic},
		{name: "well_known_get", method: "GET", path: "/.well-known/acme-challenge/token", status: 200, body: webStaticSecurityToken},
		{name: "well_known_head", method: "HEAD", path: "/.well-known/acme-challenge/token", status: 200},
		{name: "ordinary_missing", method: "GET", path: "/missing.txt", status: 404},
		{name: "ordinary_post", method: "POST", path: "/public.txt", status: 405, allow: "GET, HEAD"},
		{name: "decoded_traversal", method: "GET", path: "/../outside/outside.txt", status: 404},
		{name: "encoded_traversal", method: "GET", path: "/%2e%2e/outside/outside.txt", status: 404},
	}
	for _, proto := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("h%d", proto), func(t *testing.T) {
			rt := webCoverMetadataPublicTransport(t, clientTLS, proto)
			address := server.TCPAddr().String()
			if proto == 3 {
				address = server.UDPAddr().String()
			}
			for _, test := range cases {
				t.Run(test.name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					request, err := http.NewRequestWithContext(ctx, test.method, "https://"+address+test.path, nil)
					if err != nil {
						t.Fatal(err)
					}
					request.Header.Set("X-Static-Fixture", t.Name())
					request.Header.Set("Proxy-Authorization", "Bearer fictional-invalid-ticket")
					if test.rangeHeader != "" {
						request.Header.Set("Range", test.rangeHeader)
					}
					response, err := rt.RoundTrip(request)
					if err != nil {
						t.Fatal(err)
					}
					body, readErr := io.ReadAll(response.Body)
					_ = response.Body.Close()
					if readErr != nil {
						t.Fatal(readErr)
					}
					if response.ProtoMajor != proto || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
						t.Fatalf("actual static response = %s, verified TLS=%t, want H%d", response.Proto, response.TLS != nil && len(response.TLS.VerifiedChains) != 0, proto)
					}
					if response.StatusCode != test.status {
						t.Errorf("actual %s %s status=%d body=%q, want %d", test.method, test.path, response.StatusCode, body, test.status)
					}
					if strings.Contains(string(body), webStaticSecurityOutside) || strings.Contains(string(body), webStaticSecurityHidden) {
						t.Errorf("dummy private marker escaped on actual H%d %s: %q", proto, test.path, body)
					}
					if test.body != "" && string(body) != test.body {
						t.Errorf("ordinary body=%q, want %q", body, test.body)
					}
					if test.method == http.MethodHead && len(body) != 0 {
						t.Errorf("HEAD returned a body: %q", body)
					}
					if test.method == http.MethodHead && test.status == 200 {
						length := len(webStaticSecurityPublic)
						if test.path == "/.well-known/acme-challenge/token" {
							length = len(webStaticSecurityToken)
						}
						if response.Header.Get("Content-Length") != strconv.Itoa(length) {
							t.Errorf("ordinary HEAD Content-Length=%q, want %d", response.Header.Get("Content-Length"), length)
						}
					}
					if test.contentRange != "" && response.Header.Get("Content-Range") != test.contentRange {
						t.Errorf("ordinary Content-Range=%q, want %q", response.Header.Get("Content-Range"), test.contentRange)
					}
					if test.allow != "" && response.Header.Get("Allow") != test.allow {
						t.Errorf("ordinary Allow=%q, want %q", response.Header.Get("Allow"), test.allow)
					}
					if test.listing {
						if !strings.Contains(string(body), "visible.txt") {
							t.Errorf("ordinary listing entry lost: %q", body)
						}
						for _, hidden := range []string{".env", ".git"} {
							if strings.Contains(string(body), hidden) {
								t.Errorf("hidden listing entry %q escaped: %q", hidden, body)
							}
						}
					}
					if response.Header.Get(webAuthResponseHeader) != "" || response.Header.Get("Proxy-Authenticate") != "" {
						t.Errorf("ordinary static response exposed relay authentication metadata: %v", response.Header)
					}
					select {
					case name := <-handlerResults:
						if name != t.Name() {
							t.Errorf("static handler completion=%q, want %q", name, t.Name())
						}
					case <-time.After(2 * time.Second):
						t.Fatal("actual static handler did not finish within its independent budget")
					}
				})
			}
		})
	}
	if targetDials.Load() != 0 || targetResolutions.Load() != 0 {
		t.Errorf("static public target dial/resolution=%d/%d, want 0/0", targetDials.Load(), targetResolutions.Load())
	}
	t.Log("actual verified H1/H2/H3 static filesystem matrix; target dial/resolution=0/0")
}

func webStaticSecurityFiles(t *testing.T) string {
	t.Helper()
	fixture := t.TempDir()
	root, outside := filepath.Join(fixture, "site"), filepath.Join(fixture, "outside")
	files := map[string]string{
		filepath.Join(root, "public.txt"):                             webStaticSecurityPublic,
		filepath.Join(root, ".env"):                                   webStaticSecurityHidden,
		filepath.Join(root, ".git", "config"):                         webStaticSecurityHidden,
		filepath.Join(root, "listing", "visible.txt"):                 "ordinary visible listing entry",
		filepath.Join(root, "listing", ".env"):                        webStaticSecurityHidden,
		filepath.Join(root, "listing", ".git", "config"):              webStaticSecurityHidden,
		filepath.Join(root, ".well-known", "acme-challenge", "token"): webStaticSecurityToken,
		filepath.Join(root, ".well-known", ".env"):                    webStaticSecurityHidden,
		filepath.Join(outside, "outside.txt"):                         webStaticSecurityOutside,
	}
	for name, body := range files {
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{
		"external-file":   filepath.Join(outside, "outside.txt"),
		"external-dir":    outside,
		"inside-link.txt": "public.txt",
	} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
