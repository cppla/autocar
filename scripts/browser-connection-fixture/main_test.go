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
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type collectedLog struct {
	mu     sync.Mutex
	data   bytes.Buffer
	ready  chan string
	closed chan uint64
}

func (log *collectedLog) Write(data []byte) (int, error) {
	log.mu.Lock()
	defer log.mu.Unlock()
	_, _ = log.data.Write(data)
	var record struct {
		Kind, Address string
		ConnectionID  uint64 `json:"connection_id"`
	}
	if json.Unmarshal(data, &record) == nil {
		switch record.Kind {
		case "ready":
			log.ready <- record.Address
		case "connection_closed":
			log.closed <- record.ConnectionID
		}
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
	address, roots, log, _ := startFixtureWithStop(t, extra...)
	return address, roots, log
}

func startFixtureWithStop(t *testing.T, extra ...string) (string, *x509.CertPool, *collectedLog, func()) {
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
	log := &collectedLog{ready: make(chan string, 1), closed: make(chan uint64, 32)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	args := append([]string{"--cert", certPath, "--key", keyPath, "--duration=20s"}, extra...)
	go func() { done <- run(ctx, args, log, io.Discard) }()
	stop := sync.OnceFunc(func() {
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
	t.Cleanup(stop)
	select {
	case address := <-log.ready:
		return "https://" + address, roots, log, stop
	case <-time.After(5 * time.Second):
		t.Fatal("fixture did not become ready")
	}
	return "", nil, nil, stop
}

func waitConnectionClosed(t *testing.T, log *collectedLog, want uint64) {
	t.Helper()
	select {
	case id := <-log.closed:
		if id != want {
			t.Fatalf("closed connection ID=%d, want %d", id, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no actual QUIC connection-close observation")
	}
}

func requireJSONKeys(t *testing.T, record map[string]json.RawMessage, keys ...string) {
	t.Helper()
	if len(record) != len(keys) {
		t.Fatalf("unexpected diagnostic fields: %v", record)
	}
	for _, key := range keys {
		if _, ok := record[key]; !ok {
			t.Fatalf("missing diagnostic field %q", key)
		}
	}
}

func fixtureLogRecords(t *testing.T, output string) ([]requestRecord, []connectionClosedRecord) {
	t.Helper()
	var requests []requestRecord
	var closes []connectionClosedRecord
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		var record map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		var kind string
		if err := json.Unmarshal(record["kind"], &kind); err != nil {
			t.Fatal(err)
		}
		if kind == "ready" {
			requireJSONKeys(t, record, "kind", "address")
			continue
		}
		// Both event classes have independent schemas and must not disclose
		// headers, peer addresses, raw close reasons, or arbitrary TLS values.
		for _, forbidden := range []string{"PRIVATE_", "Authorization", "Cookie", "remote", "127.0.0.1"} {
			if strings.Contains(line, forbidden) {
				t.Fatalf("diagnostic %s record contains forbidden text %q", kind, forbidden)
			}
		}
		switch kind {
		case "request":
			requireJSONKeys(t, record, "kind", "connection_id", "path", "trial", "protocol", "tls")
			if string(record["tls"]) != "null" {
				var summary map[string]json.RawMessage
				if err := json.Unmarshal(record["tls"], &summary); err != nil {
					t.Fatal(err)
				}
				requireJSONKeys(t, summary, "handshake_complete", "did_resume", "version", "alpn")
			}
			var request requestRecord
			if err := json.Unmarshal([]byte(line), &request); err != nil {
				t.Fatal(err)
			}
			requests = append(requests, request)
		case "connection_closed":
			requireJSONKeys(t, record, "kind", "connection_id")
			var closed connectionClosedRecord
			if err := json.Unmarshal([]byte(line), &closed); err != nil {
				t.Fatal(err)
			}
			closes = append(closes, closed)
		default:
			t.Fatalf("unexpected diagnostic event %q", kind)
		}
	}
	return requests, closes
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
	requests, _ := fixtureLogRecords(t, log.text())
	if len(requests) != 6 {
		t.Fatalf("request records=%d, want 6", len(requests))
	}
	for _, request := range requests {
		if request.TLS == nil || !request.TLS.HandshakeComplete || request.TLS.DidResume || request.TLS.Version != tls.VersionTLS13 || request.TLS.ALPN != http3.NextProtoH3 {
			t.Fatalf("unexpected cold TLS observation: %+v", request.TLS)
		}
	}
}

type observedTicketCache struct {
	tls.ClientSessionCache
	stored chan struct{}
	once   sync.Once
}

func (cache *observedTicketCache) Put(key string, state *tls.ClientSessionState) {
	cache.ClientSessionCache.Put(key, state)
	if state != nil {
		cache.once.Do(func() { close(cache.stored) })
	}
}

// This is an observer correctness test with a Go peer, not browser evidence.
func TestObservedTLSColdReuseAndResumedPhysicalConnection(t *testing.T) {
	address, roots, log, stop := startFixtureWithStop(t)
	cache := &observedTicketCache{ClientSessionCache: tls.NewLRUClientSessionCache(4), stored: make(chan struct{})}
	config := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ClientSessionCache: cache}
	newClient := func() (*http.Client, *http3.Transport, <-chan *quic.Conn) {
		connections := make(chan *quic.Conn, 1)
		transport := &http3.Transport{
			TLSClientConfig: config.Clone(),
			QUICConfig:      &quic.Config{Allow0RTT: false},
			Dial: func(ctx context.Context, addr string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
				conn, err := quic.DialAddr(ctx, addr, tlsConfig, quicConfig)
				if err == nil {
					connections <- conn
				}
				return conn, err
			},
		}
		t.Cleanup(func() { _ = transport.Close() })
		return &http.Client{Transport: transport, Timeout: 3 * time.Second}, transport, connections
	}
	probe := func(client *http.Client, trial string, wantResume bool) uint64 {
		t.Helper()
		status, id, body := get(t, client, address+"/probe?trial="+trial)
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err != nil {
			t.Fatal(err)
		}
		requireJSONKeys(t, fields, "connection_id", "protocol", "tls")
		var result struct {
			ConnectionID uint64      `json:"connection_id"`
			Protocol     string      `json:"protocol"`
			TLS          *tlsSummary `json:"tls"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatal(err)
		}
		if status != http.StatusOK || id == 0 || result.ConnectionID != id || result.Protocol != "HTTP/3.0" || result.TLS == nil {
			t.Fatalf("invalid probe observation: status=%d header ID=%d result=%+v", status, id, result)
		}
		if !result.TLS.HandshakeComplete || result.TLS.DidResume != wantResume || result.TLS.Version != tls.VersionTLS13 || result.TLS.ALPN != http3.NextProtoH3 {
			t.Fatalf("server TLS observation=%+v, want resumed=%v", result.TLS, wantResume)
		}
		return id
	}
	physical := func(connections <-chan *quic.Conn, wantResume bool) *quic.Conn {
		t.Helper()
		select {
		case conn := <-connections:
			state := conn.ConnectionState()
			if !state.TLS.HandshakeComplete || state.TLS.DidResume != wantResume || state.Used0RTT || state.TLS.Version != tls.VersionTLS13 || state.TLS.NegotiatedProtocol != http3.NextProtoH3 {
				t.Fatalf("client TLS resumed=%v, complete=%v, early=%v; want resumed=%v", state.TLS.DidResume, state.TLS.HandshakeComplete, state.Used0RTT, wantResume)
			}
			return conn
		case <-time.After(3 * time.Second):
			t.Fatal("missing actual client QUIC connection")
			return nil
		}
	}
	coldClient, coldTransport, coldConnections := newClient()
	coldID := probe(coldClient, "cold", false)
	coldConn := physical(coldConnections, false)
	select {
	case <-cache.stored:
	case <-time.After(3 * time.Second):
		t.Fatal("the TLS peer did not actually deliver a session ticket")
	}
	if reusedID := probe(coldClient, "reuse", false); reusedID != coldID {
		t.Fatal("reused request moved to a different physical connection")
	}
	select {
	case <-coldConnections:
		t.Fatal("request reuse performed another physical dial")
	default:
	}
	_, closes := fixtureLogRecords(t, log.text())
	if len(closes) != 0 || coldConn.Context().Err() != nil {
		t.Fatal("request/stream completion was misreported as physical closure")
	}
	if err := coldConn.CloseWithError(0, "PRIVATE_CLOSE_REASON"); err != nil {
		t.Fatal(err)
	}
	if err := coldTransport.Close(); err != nil {
		t.Fatal(err)
	}
	waitConnectionClosed(t, log, coldID)

	warmClient, warmTransport, warmConnections := newClient()
	warmID := probe(warmClient, "warm", true)
	warmConn := physical(warmConnections, true)
	if warmID <= coldID || warmConn == coldConn {
		t.Fatal("resumed handshake reused the old physical identity")
	}
	if err := warmTransport.Close(); err != nil {
		t.Fatal(err)
	}
	waitConnectionClosed(t, log, warmID)
	stop()
	requests, closes := fixtureLogRecords(t, log.text())
	if len(requests) != 3 || len(closes) != 2 || closes[0].ConnectionID != coldID || closes[1].ConnectionID != warmID {
		t.Fatalf("unexpected event accounting: requests=%d closes=%+v", len(requests), closes)
	}
	for index, request := range requests {
		wantID, wantResume := coldID, false
		if index == 2 {
			wantID, wantResume = warmID, true
		}
		if request.ConnectionID != wantID || request.TLS == nil || request.TLS.DidResume != wantResume || !request.TLS.HandshakeComplete {
			t.Fatalf("request %d has inconsistent TLS/identity observation: %+v", index, request)
		}
	}
}

func TestTLSObservationMissingAndSanitized(t *testing.T) {
	for _, test := range []struct {
		name  string
		state *tls.ConnectionState
	}{
		{name: "missing"},
		{name: "unknown_alpn", state: &tls.ConnectionState{HandshakeComplete: true, DidResume: true, Version: tls.VersionTLS13, NegotiatedProtocol: "PRIVATE_ALPN", ServerName: "PRIVATE_SERVER_NAME"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			f := &fixture{log: &jsonLog{out: &output}, maxRequests: 1, stop: func() {}}
			request := httptest.NewRequest(http.MethodGet, "/probe?trial=tls", nil)
			request.TLS = test.state
			response := httptest.NewRecorder()
			f.ServeHTTP(response, request)
			if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "PRIVATE") {
				t.Fatal("TLS probe failed or exposed an arbitrary TLS value")
			}
			var body struct {
				TLS *tlsSummary `json:"tls"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			requests, closes := fixtureLogRecords(t, output.String())
			if len(requests) != 1 || len(closes) != 0 {
				t.Fatal("unexpected handler event accounting")
			}
			if test.state == nil {
				if body.TLS != nil || requests[0].TLS != nil || !strings.Contains(response.Body.String(), `"tls":null`) || !strings.Contains(output.String(), `"tls":null`) {
					t.Fatal("missing TLS state was misrepresented as a cold handshake")
				}
			} else if body.TLS == nil || requests[0].TLS == nil || *body.TLS != *requests[0].TLS || body.TLS.ALPN != "<other>" || !body.TLS.DidResume || !body.TLS.HandshakeComplete {
				t.Fatal("TLS state was not copied accurately or ALPN was not sanitized")
			}
		})
	}
}

func TestShutdownJoinsPhysicalConnectionObservers(t *testing.T) {
	address, roots, log, stop := startFixtureWithStop(t)
	_, id, _ := get(t, h3Client(t, roots), address+"/probe?trial=shutdown")
	stop()
	// Read immediately after run returns: no delayed observer is needed to
	// complete the close record, even when shutdown terminated a live peer.
	requests, closes := fixtureLogRecords(t, log.text())
	if len(requests) != 1 || len(closes) != 1 || closes[0].ConnectionID != id {
		t.Fatalf("shutdown returned before joined close event: requests=%d closes=%+v", len(requests), closes)
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
	address, roots, log, stop := startFixtureWithStop(t, "--max-connections=1")
	status, firstID, _ := get(t, h3Client(t, roots), address+"/probe?trial=first")
	if status != 200 {
		t.Fatal("first connection rejected")
	}
	response, err := h3Client(t, roots).Get(address + "/probe?trial=second")
	if err == nil {
		response.Body.Close()
		t.Fatal("accepted a connection beyond the run budget")
	}
	stop()
	requests, closes := fixtureLogRecords(t, log.text())
	if len(requests) != 1 || len(closes) != 1 || closes[0].ConnectionID != firstID {
		t.Fatalf("connection observer exceeded admitted budget: requests=%d closes=%+v", len(requests), closes)
	}
}
