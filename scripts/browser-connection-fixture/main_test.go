package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/security"
	"github.com/quic-go/quic-go/http3"
)

type collectedLog struct {
	mu    sync.Mutex
	data  bytes.Buffer
	ready chan string
}

func (log *collectedLog) Write(data []byte) (int, error) {
	log.mu.Lock()
	defer log.mu.Unlock()
	_, _ = log.data.Write(data)
	var record struct{ Kind, Address string }
	if json.Unmarshal(data, &record) == nil && record.Kind == "ready" {
		log.ready <- record.Address
	}
	return len(data), nil
}

func (log *collectedLog) text() string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return log.data.String()
}

func startFixture(t *testing.T, extra ...string) (string, *x509.CertPool, *collectedLog) {
	t.Helper()
	cert, key, err := security.GenerateSelfSignedCertificate(security.CertificateOptions{
		Hosts: []string{"127.0.0.1", "::1"}, ValidFor: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, cert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		t.Fatal("load test trust anchor")
	}
	log := &collectedLog{ready: make(chan string, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	args := append([]string{"--cert", certPath, "--key", keyPath, "--duration=20s"}, extra...)
	go func() { done <- run(ctx, args, log, io.Discard) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("fixture shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("fixture did not stop")
		}
	})
	select {
	case address := <-log.ready:
		return "https://" + address, roots, log
	case <-time.After(5 * time.Second):
		t.Fatal("fixture did not become ready")
	}
	return "", nil, nil
}

func h3Client(t *testing.T, roots *x509.CertPool) *http.Client {
	t.Helper()
	transport := &http3.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots,
	}}
	t.Cleanup(func() { _ = transport.Close() })
	return &http.Client{Transport: transport, Timeout: 3 * time.Second}
}

func get(t *testing.T, client *http.Client, address string) (int, uint64, []byte) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, address, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Cookie", "cookie=PRIVATE_COOKIE")
	request.Header.Set("Authorization", "Bearer PRIVATE_AUTH")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.ProtoMajor != 3 {
		t.Fatalf("protocol = %s", response.Proto)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := strconv.ParseUint(response.Header.Get("X-Diagnostic-Connection-ID"), 10, 64)
	return response.StatusCode, id, body
}

func TestPhysicalConnectionIdentityAndPrivateLogs(t *testing.T) {
	address, roots, log := startFixture(t)
	first := h3Client(t, roots)
	status, rootID, html := get(t, first, address+"/")
	if status != http.StatusOK || rootID == 0 || !bytes.Contains(html, []byte("data:,")) {
		t.Fatalf("root response: status=%d id=%d", status, rootID)
	}
	for _, trial := range []string{"a_1", "b-2"} {
		status, id, body := get(t, first, address+"/probe?trial="+trial)
		var result struct {
			ConnectionID uint64 `json:"connection_id"`
			Protocol     string `json:"protocol"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatal(err)
		}
		if status != http.StatusOK || id != rootID || result.ConnectionID != rootID || result.Protocol != "HTTP/3.0" {
			t.Fatalf("same transport did not reuse physical connection: status=%d id=%d result=%+v", status, id, result)
		}
	}
	status, secondID, _ := get(t, h3Client(t, roots), address+"/probe?trial=second")
	if status != http.StatusOK || secondID <= rootID {
		t.Fatal("separate transport did not receive a new monotonic connection ID")
	}
	status, _, _ = get(t, first, address+"/probe?trial=valid&token=PRIVATE_QUERY")
	if status != http.StatusBadRequest {
		t.Fatalf("unexpected query status=%d", status)
	}
	status, _, _ = get(t, first, address+"/PRIVATE_PATH?password=PRIVATE_QUERY")
	if status != http.StatusNotFound {
		t.Fatalf("unknown path status=%d", status)
	}
	output := log.text()
	for _, forbidden := range []string{"PRIVATE_", "Authorization", "Cookie", "remote", "127.0.0.1"} {
		// The ready line intentionally contains the numeric listener address;
		// request records must contain no peer addresses or credentials.
		requests := output[strings.IndexByte(output, '\n')+1:]
		if strings.Contains(requests, forbidden) {
			t.Fatalf("diagnostic log contains forbidden text %q", forbidden)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n")[1:] {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if len(record) != 5 {
			t.Fatalf("unexpected request log fields: %v", record)
		}
	}
}

func TestOptionsAreLoopbackAndBounded(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "127.0.0.1:65535", "[::1]:0"} {
		if err := validateListen(address); err != nil {
			t.Errorf("valid address %s: %v", address, err)
		}
	}
	for _, address := range []string{"localhost:443", ":443", "0.0.0.0:443", "127.0.0.2:443", "[::]:443", "[::ffff:127.0.0.1]:443", "127.0.0.1:http", "127.0.0.1:+1", "127.0.0.1:-1", "127.0.0.1:65536"} {
		if err := validateListen(address); err == nil {
			t.Errorf("accepted unsafe address %s", address)
		}
	}
	for _, option := range []string{"--duration=0", "--duration=601s", "--max-requests=0", "--max-requests=65", "--max-connections=0", "--max-connections=33", "positional"} {
		if _, err := parseOptions([]string{"--cert=cert", "--key=key", option}, io.Discard); err == nil {
			t.Errorf("accepted invalid option %s", option)
		}
	}
	if _, err := parseOptions(nil, io.Discard); err == nil {
		t.Fatal("accepted missing credentials")
	}
	opts, err := parseOptions([]string{"--cert=cert", "--key=key"}, io.Discard)
	if err != nil || opts.duration != 180*time.Second || opts.maxRequests != 64 || opts.maxConnections != 32 {
		t.Fatalf("defaults=%+v error=%v", opts, err)
	}
}

func TestHandlerRejectsBodiesMethodsAndInvalidTrials(t *testing.T) {
	for _, test := range []struct {
		method, path, body string
		status             int
	}{
		{"HEAD", "/probe?trial=head", "", 200},
		{"GET", "/probe", "", 400},
		{"GET", "/probe?trial=a&trial=b", "", 400},
		{"GET", "/probe?trial=PRIVATE%0AQUERY", "", 400},
		{"GET", "/probe?trial=%FF", "", 400},
		{"GET", "/probe?trial=" + strings.Repeat("a", 33), "", 400},
		{"GET", "/probe?trial=body", "PRIVATE_BODY", 400},
		{"POST", "/probe?trial=method", "PRIVATE_BODY", 405},
		{"GET", "/unknown", "", 404},
	} {
		t.Run(test.method+test.path, func(t *testing.T) {
			var output bytes.Buffer
			f := &fixture{log: &jsonLog{out: &output}, maxRequests: 1, stop: func() {}}
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request = request.WithContext(context.WithValue(request.Context(), connectionKey{}, uint64(1)))
			response := httptest.NewRecorder()
			f.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status=%d want=%d", response.Code, test.status)
			}
			if test.method == "HEAD" && response.Body.Len() != 0 {
				t.Fatal("HEAD returned a body")
			}
			if strings.Contains(output.String(), "PRIVATE") {
				t.Fatal("logged rejected request contents")
			}
			exhausted := httptest.NewRecorder()
			f.ServeHTTP(exhausted, httptest.NewRequest("GET", "/", nil))
			if exhausted.Code != 429 || strings.Count(output.String(), "\n") != 1 {
				t.Fatal("request budget did not bound handling/log output")
			}
		})
	}
}

func TestConnectionBudget(t *testing.T) {
	address, roots, _ := startFixture(t, "--max-connections=1")
	status, _, _ := get(t, h3Client(t, roots), address+"/probe?trial=first")
	if status != 200 {
		t.Fatal("first connection rejected")
	}
	response, err := h3Client(t, roots).Get(address + "/probe?trial=second")
	if err == nil {
		response.Body.Close()
		t.Fatal("accepted a connection beyond the run budget")
	}
}
