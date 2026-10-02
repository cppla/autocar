package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRunServerPublicOriginValidationBeforeCredentials(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{"native", []string{"--cover-public-origin", "https://site.test"}, "requires --protocol=web"},
		{"static", []string{"--protocol", "web", "--cover-root", "/unused", "--cover-public-origin", "https://site.test"}, "requires --protocol=web"},
		{"http public", []string{"--protocol", "web", "--cover-upstream", "http://origin.test", "--cover-public-origin", "http://site.test"}, "configure upstream cover"},
		{"whitespace public", []string{"--protocol", "web", "--cover-upstream", "http://origin.test", "--cover-public-origin", " "}, "configure upstream cover"},
		{"bad public URL", []string{"--protocol", "web", "--cover-upstream", "http://origin.test", "--cover-public-origin", "https://site.test:%"}, "parse --cover-public-origin"},
		{"upstream base path", []string{"--protocol", "web", "--cover-upstream", "http://origin.test/base", "--cover-public-origin", "https://site.test"}, "configure upstream cover"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := runServer(context.Background(), test.args)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v; want %q", err, test.want)
			}
		})
	}
}

func TestPublicOriginPreflightStaysOffline(t *testing.T) {
	clearPreflightEnvironment(t)
	files := newPreflightFiles(t)
	dns := denyPreflightDNS(t)
	var requests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer upstream.Close()
	for _, target := range []string{"https://origin.invalid", upstream.URL} {
		args := append(files.serverArgs(), "--protocol", "web", "--cover-upstream", target, "--cover-public-origin", "https://site.invalid:8443/")
		if err := runServer(context.Background(), args); err != nil {
			t.Fatal(err)
		}
	}
	if dns.Load() != 0 || requests.Load() != 0 {
		t.Fatalf("preflight DNS=%d upstream=%d", dns.Load(), requests.Load())
	}
}

func TestPublicOriginJSONAndCLIOverride(t *testing.T) {
	clearPreflightEnvironment(t)
	files := newPreflightFiles(t)
	path := writeTestCommandConfig(t, `{"protocol":"web","cover-upstream":"https://origin.invalid","cover-public-origin":"https://site.invalid"}`)
	args := append(files.serverArgs(), "--config", path)
	if err := runServer(context.Background(), args); err != nil {
		t.Fatalf("JSON public origin: %v", err)
	}
	// Explicit empty CLI opt-out restores the old upstream base-path policy.
	args = append(args, "--cover-public-origin=", "--cover-upstream=https://origin.invalid/base?fixed=1")
	if err := runServer(context.Background(), args); err != nil {
		t.Fatalf("CLI opt-out: %v", err)
	}
	args = append(args, "--cover-public-origin=http://site.invalid")
	if err := runServer(context.Background(), args); err == nil {
		t.Fatal("invalid CLI override was accepted")
	}
}

func TestPublicOriginCoverFactory(t *testing.T) {
	if _, err := buildCoverHandlerWithPublicOrigin(t.TempDir(), "", "https://site.test"); err == nil {
		t.Fatal("static public-origin combination accepted")
	}
	handler, err := buildCoverHandlerWithPublicOrigin("", "https://origin.invalid", "https://site.test")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://other.test/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusMisdirectedRequest {
		t.Fatalf("wrong Host status=%d", response.Code)
	}
}
