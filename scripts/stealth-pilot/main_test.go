package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type observedRequest struct {
	method          string
	path            string
	seed            string
	requestIndex    string
	bootstrapSeed   string
	proxyConnection string
	body            []byte
}

type recordingDoer struct {
	inner doer
	mu    sync.Mutex
	seen  []observedRequest
}

func (r *recordingDoer) Do(request *http.Request) (*http.Response, error) {
	var body []byte
	if request.Body != nil {
		var err error
		body, err = io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		_ = request.Body.Close()
		request.Body = io.NopCloser(bytes.NewReader(body))
	}
	r.mu.Lock()
	r.seen = append(r.seen, observedRequest{
		method:          request.Method,
		path:            request.URL.Path,
		seed:            request.URL.Query().Get("seed"),
		requestIndex:    request.URL.Query().Get("request"),
		bootstrapSeed:   request.URL.Query().Get("autocar_browser_sample"),
		proxyConnection: request.Header.Get("Proxy-Connection"),
		body:            append([]byte(nil), body...),
	})
	r.mu.Unlock()
	return r.inner.Do(request)
}

func (r *recordingDoer) take() []observedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := append([]observedRequest(nil), r.seen...)
	r.seen = nil
	return seen
}

func TestFixtureSize(t *testing.T) {
	for _, test := range []struct {
		path string
		want int
		ok   bool
	}{
		{"/bytes/0", 0, true},
		{"/bytes/1024", 1024, true},
		{"/bytes/1048576", maxFixtureBytes, true},
		{"/bytes/-1", 0, false},
		{"/bytes/1048577", 0, false},
		{"/bytes/1/extra", 0, false},
		{"https://example.test/bytes/1", 0, false},
	} {
		got, err := fixtureSize(test.path)
		if (err == nil) != test.ok || got != test.want {
			t.Fatalf("fixtureSize(%q) = %d, %v; want %d, ok=%v", test.path, got, err, test.want, test.ok)
		}
	}
}

func TestFixtureBootstrapIsFixedAndSelfContained(t *testing.T) {
	handler := fixtureHandler()
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		request := httptest.NewRequest(method, "/?autocar_browser_sample=42", nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s bootstrap status = %d", method, response.Code)
		}
		if got := response.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("%s bootstrap cache policy = %q", method, got)
		}
		if got := response.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
			t.Fatalf("%s bootstrap content type = %q", method, got)
		}
		if got := response.Header().Get("Content-Length"); got != strconv.Itoa(len(bootstrapHTML)) {
			t.Fatalf("%s bootstrap content length = %q", method, got)
		}
		want := bootstrapHTML
		if method == http.MethodHead {
			want = ""
		}
		if response.Body.String() != want {
			t.Fatalf("%s bootstrap body changed", method)
		}
	}
	if !bytes.Contains([]byte(bootstrapHTML), []byte(`href="data:,"`)) ||
		!bytes.Contains([]byte(bootstrapHTML), []byte(`name="autocar-stealth-bootstrap" content="v1"`)) {
		t.Fatal("bootstrap does not contain the frozen marker and data favicon")
	}
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST bootstrap status = %d, want 405", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Proxy-Connection", "keep-alive")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("origin accepted leaked Proxy-Connection with status %d", response.Code)
	}
}

func TestExecutePilotWorkloads(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		fixtureHandler().ServeHTTP(w, r)
	}))
	defer server.Close()

	for _, test := range []struct {
		name string
		want int64
	}{
		{"idle", 2},
		{"download_1k", 2},
		{"download_128k", 2},
		{"download_1m", 2},
		{"upload_1m", 2},
		{"parallel_20", 21},
		{"interactive", interactiveRounds + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests.Store(0)
			recorder := &recordingDoer{inner: server.Client()}
			if err := executeWorkload(context.Background(), recorder, server.URL, test.name, 42, time.Millisecond); err != nil {
				t.Fatal(err)
			}
			if got := requests.Load(); got != test.want {
				t.Fatalf("request count = %d, want %d", got, test.want)
			}
			seen := recorder.take()
			if int64(len(seen)) != test.want {
				t.Fatalf("recorded request count = %d, want %d", len(seen), test.want)
			}
			assertBootstrapRequest(t, seen[0], "42")
		})
	}
}

func TestH3WorkloadRouteUsesNumericHTTPHostAndPinnedTLSServerName(t *testing.T) {
	roots := x509.NewCertPool()
	baseURL, tlsConfig := h3WorkloadRoute("10.242.7.10:8443", "cover.test", roots)
	parsed, err := url.Parse(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "https" || parsed.Host != "10.242.7.10:8443" || parsed.Hostname() != "10.242.7.10" {
		t.Fatalf("H3 workload URL does not retain the numeric server authority: %q", baseURL)
	}
	if tlsConfig.ServerName != "cover.test" {
		t.Fatalf("TLS ServerName = %q, want cover.test", tlsConfig.ServerName)
	}
	if tlsConfig.RootCAs != roots {
		t.Fatal("H3 workload route did not retain the pinned root pool")
	}
}

func TestProxyWorkloadSendsExplicitKeepAliveOnEveryRequest(t *testing.T) {
	var mu sync.Mutex
	var seenHeaders []string
	connections := make(map[string]struct{})
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenHeaders = append(seenHeaders, r.Header.Get("Proxy-Connection"))
		connections[r.RemoteAddr] = struct{}{}
		mu.Unlock()
		forwarded := r.Clone(r.Context())
		forwarded.Header = r.Header.Clone()
		forwarded.Header.Del("Proxy-Connection")
		fixtureHandler().ServeHTTP(w, forwarded)
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := proxyKeepAliveDoer{inner: &http.Client{Transport: transport}}
	if err := executeWorkload(
		context.Background(), client, "http://10.242.7.40:8080",
		"interactive", 42, time.Millisecond,
	); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seenHeaders) != interactiveRounds+1 {
		t.Fatalf("proxy request count = %d, want %d", len(seenHeaders), interactiveRounds+1)
	}
	for index, value := range seenHeaders {
		if value != "keep-alive" {
			t.Fatalf("proxy request %d Proxy-Connection = %q, want keep-alive", index, value)
		}
	}
	if len(connections) != 1 {
		t.Fatalf("proxy workload used %d local TCP connections, want 1", len(connections))
	}
}

func TestProxyKeepAliveDoerDoesNotMutateCallerRequest(t *testing.T) {
	wireHeader := make(chan string, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wireHeader <- r.Header.Get("Proxy-Connection")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := proxyKeepAliveDoer{inner: &http.Client{Transport: transport}}
	request, err := http.NewRequest(http.MethodGet, "http://10.242.7.40:8080/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if got := <-wireHeader; got != "keep-alive" {
		t.Fatalf("wire Proxy-Connection = %q, want keep-alive", got)
	}
	if got := request.Header.Get("Proxy-Connection"); got != "" {
		t.Fatalf("caller request was mutated with Proxy-Connection %q", got)
	}
}

func TestHysteriaClientCommandDisablesUpdateCheck(t *testing.T) {
	want := []string{"client", "--disable-update-check", "-c", "/pilot/hysteria-client.yaml"}
	got := hysteriaClientCommandArgs("/pilot/hysteria-client.yaml")
	if len(got) != len(want) {
		t.Fatalf("Hysteria client arguments = %q, want %q", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("Hysteria client arguments = %q, want %q", got, want)
		}
	}
}

func TestUploadAndInteractiveWorkloadSemantics(t *testing.T) {
	server := httptest.NewServer(fixtureHandler())
	defer server.Close()
	recorder := &recordingDoer{inner: server.Client()}
	const seed int64 = 42

	if err := executeWorkload(context.Background(), recorder, server.URL, "upload_1m", seed, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	uploads := recorder.take()
	if len(uploads) != 2 {
		t.Fatalf("upload request count = %d, want 2", len(uploads))
	}
	assertBootstrapRequest(t, uploads[0], "42")
	upload := uploads[1]
	if upload.method != http.MethodPost || upload.path != "/upload/1048576" || upload.seed != "42" || upload.requestIndex != "0" {
		t.Fatalf("upload request = %#v", upload)
	}
	wantUpload := seededFixtureBody(1<<20, seed, 0, payloadDomainUpload)
	if !bytes.Equal(upload.body, wantUpload) {
		t.Fatal("upload_1m did not use the deterministic 1 MiB payload")
	}

	if err := executeWorkload(context.Background(), recorder, server.URL, "interactive", seed, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	exchanges := recorder.take()
	if len(exchanges) != interactiveRounds+1 {
		t.Fatalf("interactive request count = %d, want %d", len(exchanges), interactiveRounds+1)
	}
	assertBootstrapRequest(t, exchanges[0], "42")
	for index, exchange := range exchanges[1:] {
		if exchange.method != http.MethodPost || exchange.path != "/exchange/256/512" || exchange.seed != "42" || exchange.requestIndex != strconv.Itoa(index) {
			t.Fatalf("interactive request %d = %#v", index, exchange)
		}
		wantBody := seededFixtureBody(interactiveUploadBytes, seed, index, payloadDomainInteractiveUp)
		if !bytes.Equal(exchange.body, wantBody) {
			t.Fatalf("interactive request %d payload is not deterministic", index)
		}
	}
}

func assertBootstrapRequest(t *testing.T, request observedRequest, seed string) {
	t.Helper()
	if request.method != http.MethodGet || request.path != "/" || request.bootstrapSeed != seed ||
		request.seed != "" || request.requestIndex != "" || len(request.body) != 0 {
		t.Fatalf("bootstrap request = %#v", request)
	}
}

func TestFixtureRejectsInvalidMutatingPayloads(t *testing.T) {
	handler := fixtureHandler()
	valid := seededFixtureBody(16, 7, 3, payloadDomainUpload)
	for _, test := range []struct {
		name        string
		path        string
		body        []byte
		contentType string
		wantStatus  int
	}{
		{"valid upload", "/upload/16?seed=7&request=3", valid, "application/octet-stream", http.StatusOK},
		{"wrong upload bytes", "/upload/16?seed=7&request=3", append([]byte(nil), valid[:15]...), "application/octet-stream", http.StatusBadRequest},
		{"missing coordinates", "/upload/16", valid, "application/octet-stream", http.StatusBadRequest},
		{"wrong content type", "/upload/16?seed=7&request=3", valid, "text/plain", http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, test.path, bytes.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%q", response.Code, test.wantStatus, response.Body.String())
			}
			if test.wantStatus == http.StatusOK {
				wantReceipt := seededFixtureBody(uploadReceiptBytes, 7, 3, payloadDomainUploadReceipt)
				if !bytes.Equal(response.Body.Bytes(), wantReceipt) {
					t.Fatal("upload receipt did not match its deterministic fixture body")
				}
			}
		})
	}
}

func TestSeededFixtureBodyIsStableAndDomainSeparated(t *testing.T) {
	want := seededFixtureBody(128, 99, 4, payloadDomainInteractiveUp)
	if got := seededFixtureBody(128, 99, 4, payloadDomainInteractiveUp); !bytes.Equal(got, want) {
		t.Fatal("same payload coordinates produced different bytes")
	}
	for name, got := range map[string][]byte{
		"seed":    seededFixtureBody(128, 100, 4, payloadDomainInteractiveUp),
		"request": seededFixtureBody(128, 99, 5, payloadDomainInteractiveUp),
		"domain":  seededFixtureBody(128, 99, 4, payloadDomainInteractiveDown),
	} {
		if bytes.Equal(got, want) {
			t.Fatalf("%s did not separate deterministic payload bytes", name)
		}
	}
}

func TestExecuteWorkloadRejectsUnknownLabel(t *testing.T) {
	server := httptest.NewServer(fixtureHandler())
	defer server.Close()
	if err := executeWorkload(context.Background(), server.Client(), server.URL, "download_everything", 1, time.Millisecond); err == nil {
		t.Fatal("unknown workload was accepted")
	}
}

func TestPilotEndpointsArePrivateAndNumeric(t *testing.T) {
	for _, value := range []string{"10.242.7.10:8443", "172.20.1.2:443", "192.168.50.2:8080"} {
		if err := validateRFC1918HostPort(value); err != nil {
			t.Fatalf("private endpoint %q rejected: %v", value, err)
		}
	}
	for _, value := range []string{"example.com:443", "8.8.8.8:443", "127.0.0.1:443", "[::1]:443", "10.0.0.1:0"} {
		if err := validateRFC1918HostPort(value); err == nil {
			t.Fatalf("non-lab endpoint %q accepted", value)
		}
	}
	if err := validatePrivateHTTPURL("http://10.242.7.40:8080"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"https://10.242.7.40:8080", "http://example.test:8080", "http://10.242.7.40:8080/path"} {
		if err := validatePrivateHTTPURL(value); err == nil {
			t.Fatalf("unsafe origin %q accepted", value)
		}
	}
	if err := validatePrivateHTTPProbeURL("http://10.242.7.40:8080/health"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"https://10.242.7.40:8080/health", "http://example.test:8080/health", "http://10.242.7.40:8080"} {
		if err := validatePrivateHTTPProbeURL(value); err == nil {
			t.Fatalf("unsafe probe URL %q accepted", value)
		}
	}
}
