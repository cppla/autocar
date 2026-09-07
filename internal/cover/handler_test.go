package cover

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestStaticHandlerServesGETAndHEAD(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("ordinary cover page"), 0o600); err != nil {
		t.Fatal(err)
	}
	handler, err := NewStaticHandler(root)
	if err != nil {
		t.Fatal(err)
	}

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			request := httptest.NewRequest(method, "https://site.example/", nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", response.Code)
			}
			if method == http.MethodGet && response.Body.String() != "ordinary cover page" {
				t.Fatalf("body = %q", response.Body.String())
			}
			if method == http.MethodHead && response.Body.Len() != 0 {
				t.Fatalf("HEAD body = %q", response.Body.String())
			}
			assertNoProductMarker(t, response.Result())
		})
	}
}

func TestStaticHandlerUsesStandardErrors(t *testing.T) {
	handler, err := NewStaticHandler(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	post := httptest.NewRecorder()
	handler.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "https://site.example/", nil))
	if post.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", post.Code)
	}
	if got := post.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("Allow = %q", got)
	}
	assertNoProductMarker(t, post.Result())

	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "https://site.example/missing", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d, want 404", missing.Code)
	}
	assertNoProductMarker(t, missing.Result())
}

func TestStaticHandlerValidatesDirectory(t *testing.T) {
	if _, err := NewStaticHandler(""); err == nil {
		t.Fatal("empty directory was accepted")
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStaticHandler(file); err == nil {
		t.Fatal("regular file was accepted as a directory")
	}
}

func TestReverseProxyUsesOnlyFixedOriginAndScrubsHeaders(t *testing.T) {
	received := make(chan *http.Request, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Clone(context.Background())
		w.Header().Set("Connection", "X-Origin-Hop")
		w.Header().Set("X-Origin-Hop", "response secret")
		w.Header().Set("Authorization", "response credential")
		w.Header().Set("Proxy-Authorization", "response proxy credential")
		w.Header().Set("X-Cover-Origin", "yes")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("origin response"))
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL + "/base")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewReverseProxyHandler(originURL, nil)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://requester.example/asset?q=1", nil)
	request.Host = "attacker.example:8443"
	request.Header.Set("Authorization", "Bearer request-secret")
	request.Header.Set("Proxy-Authorization", "Basic request-secret")
	request.Header.Set("Connection", "X-Request-Hop, Keep-Alive")
	request.Header.Set("X-Request-Hop", "request secret")
	request.Header.Set("Keep-Alive", "timeout=5")
	request.Header.Set("X-End-To-End", "kept")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated || response.Body.String() != "origin response" {
		t.Fatalf("status/body = %d/%q", response.Code, response.Body.String())
	}
	if response.Header().Get("X-Origin-Hop") != "" || response.Header().Get("Authorization") != "" || response.Header().Get("Proxy-Authorization") != "" {
		t.Fatalf("unsafe response headers leaked: %v", response.Header())
	}
	if response.Header().Get("X-Cover-Origin") != "yes" {
		t.Fatal("end-to-end response header was removed")
	}
	assertNoProductMarker(t, response.Result())

	select {
	case got := <-received:
		if got.Host != originURL.Host {
			t.Fatalf("origin Host = %q, want %q", got.Host, originURL.Host)
		}
		if got.URL.Path != "/base/asset" || got.URL.RawQuery != "q=1" {
			t.Fatalf("origin URL = %s", got.URL.String())
		}
		for _, name := range []string{"Authorization", "Proxy-Authorization", "Connection", "Keep-Alive", "X-Request-Hop"} {
			if value := got.Header.Get(name); value != "" {
				t.Fatalf("%s leaked to origin: %q", name, value)
			}
		}
		if got.Header.Get("X-End-To-End") != "kept" {
			t.Fatal("end-to-end request header was removed")
		}
	case <-time.After(time.Second):
		t.Fatal("fixed origin did not receive request")
	}
}

func TestReverseProxyDoesNotUseRequesterDestination(t *testing.T) {
	var originRequests atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		originRequests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewReverseProxyHandler(originURL, nil)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://unreachable.invalid/private", nil)
	request.Host = "another-unreachable.invalid"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
	if originRequests.Load() != 1 {
		t.Fatalf("fixed origin requests = %d, want 1", originRequests.Load())
	}
}

func TestReverseProxyValidatesOrigin(t *testing.T) {
	tests := []struct {
		name   string
		origin *url.URL
	}{
		{name: "nil"},
		{name: "unsupported scheme", origin: &url.URL{Scheme: "ftp", Host: "example.com"}},
		{name: "missing host", origin: &url.URL{Scheme: "https"}},
		{name: "userinfo", origin: &url.URL{Scheme: "https", Host: "example.com", User: url.UserPassword("user", "secret")}},
		{name: "fragment", origin: &url.URL{Scheme: "https", Host: "example.com", Fragment: "part"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewReverseProxyHandler(test.origin, nil); err == nil {
				t.Fatal("invalid origin was accepted")
			}
		})
	}
}

func TestReverseProxyFailureIsGeneric(t *testing.T) {
	origin, err := url.Parse("http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewReverseProxyHandler(origin, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, io.ErrUnexpectedEOF
	}))
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://site.example/", nil))
	if response.Code != http.StatusBadGateway || strings.TrimSpace(response.Body.String()) != http.StatusText(http.StatusBadGateway) {
		t.Fatalf("status/body = %d/%q", response.Code, response.Body.String())
	}
	assertNoProductMarker(t, response.Result())
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func assertNoProductMarker(t *testing.T, response *http.Response) {
	t.Helper()
	var content strings.Builder
	content.WriteString(response.Status)
	for name, values := range response.Header {
		content.WriteString(name)
		content.WriteString(strings.Join(values, ","))
	}
	if response.Body != nil {
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		content.Write(body)
	}
	if strings.Contains(strings.ToLower(content.String()), "autocar") {
		t.Fatalf("response contains product marker: %q", content.String())
	}
}
