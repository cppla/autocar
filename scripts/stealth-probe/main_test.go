package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/security"
	"github.com/cppla/autocar/internal/transport"
	"github.com/cppla/autocar/internal/tunnel"
)

func TestMakeWebBearerHasFrozenIndependentWireShape(t *testing.T) {
	nonce := make([]byte, 16)
	for index := range nonce {
		nonce[index] = byte(index + 1)
	}
	now := time.Unix(1_800_000_000, 0)
	padding := bytes.Repeat([]byte{0xa5}, webAuthMinPadding)
	entropy := append(append(append([]byte(nil), nonce...), 0, 0, 0, 0), padding...)
	bearer, err := makeWebBearer(
		"independent-stealth-probe-token", "h3", "target.internal:443", now, bytes.NewReader(entropy),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(bearer, "Bearer ") {
		t.Fatalf("bearer prefix = %q", bearer)
	}
	ticket, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(bearer, "Bearer "))
	if err != nil {
		t.Fatal(err)
	}
	wantTicketBytes := webAuthPaddingOffset + len(padding) + sha256.Size
	if len(ticket) != wantTicketBytes {
		t.Fatalf("ticket bytes = %d, want %d", len(ticket), wantTicketBytes)
	}
	if ticket[0] != 1 || int64(binary.BigEndian.Uint64(ticket[1:9])) != now.Unix() {
		t.Fatalf("ticket version/timestamp = %d/%d", ticket[0], binary.BigEndian.Uint64(ticket[1:9]))
	}
	if !bytes.Equal(ticket[9:25], nonce) {
		t.Fatalf("ticket nonce = %x, want %x", ticket[9:25], nonce)
	}
	if !bytes.Equal(ticket[25:43], make([]byte, 18)) {
		t.Fatalf("zero pacing claims changed: %x", ticket[25:43])
	}
	if got := int(binary.BigEndian.Uint16(ticket[43:webAuthPaddingOffset])); got != webAuthMinPadding {
		t.Fatalf("padding length = %d, want %d", got, webAuthMinPadding)
	}
	if !bytes.Equal(ticket[webAuthPaddingOffset:webAuthPaddingOffset+len(padding)], padding) {
		t.Fatal("ticket padding changed")
	}
	if bytes.Equal(ticket[len(ticket)-sha256.Size:], make([]byte, sha256.Size)) {
		t.Fatal("ticket MAC is all zero")
	}
}

func TestMakeWebBearerUsesProtocolTokenBounds(t *testing.T) {
	for _, length := range []int{protocol.MinTokenLength, protocol.MaxTokenLength} {
		_, err := makeWebBearer(
			strings.Repeat("t", length),
			"h2",
			"target.internal:443",
			time.Unix(1_800_000_000, 0),
			bytes.NewReader(make([]byte, 16+4+webAuthMaxPadding)),
		)
		if err != nil {
			t.Fatalf("token length %d rejected: %v", length, err)
		}
	}
	for _, length := range []int{protocol.MinTokenLength - 1, protocol.MaxTokenLength + 1} {
		_, err := makeWebBearer(
			strings.Repeat("t", length),
			"h2",
			"target.internal:443",
			time.Unix(1_800_000_000, 0),
			bytes.NewReader(make([]byte, 16+4+webAuthMaxPadding)),
		)
		if err == nil {
			t.Fatalf("out-of-range token length %d accepted", length)
		}
	}
}

func TestIndependentBearerAndH2RoundTripperAuthenticateAgainstTunnel(t *testing.T) {
	const (
		token     = "independent-stealth-probe-token"
		authority = "target.internal:443"
	)
	certPEM, keyPEM, err := security.GenerateSelfSignedCertificate(security.CertificateOptions{Hosts: []string{"cover.test"}})
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("append test root certificate")
	}

	var dials atomic.Int64
	type observedRequest struct {
		method      string
		host        string
		path        string
		rawQuery    string
		protocol    string
		tlsVersion  uint16
		authorizers int
	}
	observed := make(chan observedRequest, 1)
	server, err := tunnel.ListenWebH2(tunnel.WebH2ServerConfig{
		Address: "127.0.0.1:0",
		Token:   token,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{certificate},
		},
		Cover: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			seen := observedRequest{
				method: request.Method, host: request.Host, path: request.URL.Path,
				rawQuery: request.URL.RawQuery, protocol: request.Proto,
				authorizers: len(request.Header.Values("Proxy-Authorization")),
			}
			if request.TLS != nil {
				seen.tlsVersion = request.TLS.Version
			}
			observed <- seen
			http.Error(w, "cover", http.StatusMethodNotAllowed)
		}),
		Dialer: transport.DialFunc(func(_ context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != authority {
				return nil, fmt.Errorf("unexpected target %s %s", network, address)
			}
			dials.Add(1)
			serverEnd, peer := net.Pipe()
			go func() {
				defer peer.Close()
				_, _ = io.Copy(io.Discard, peer)
			}()
			return serverEnd, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
	})
	go func() { _ = server.Serve(ctx) }()

	bearer, err := makeWebBearer(token, "h2", authority, time.Now(), strings.NewReader(strings.Repeat("a", 16+4+webAuthMaxPadding)))
	if err != nil {
		t.Fatal(err)
	}
	requestCtx, requestCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer requestCancel()
	response, err := requestH2(
		requestCtx,
		server.Addr().String(),
		"cover.test",
		&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "cover.test"},
		probeSpec{method: http.MethodConnect, authority: authority, header: bearer},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || dials.Load() != 1 {
		var seen observedRequest
		select {
		case seen = <-observed:
		default:
		}
		t.Fatalf("independent H2 result = status %d dials %d cover_request %+v", response.StatusCode, dials.Load(), seen)
	}
}

func TestCanonicalEvidenceIgnoresOnlyDeclaredVolatileHeaders(t *testing.T) {
	left := responseEvidence{
		OK: true, Protocol: "H3", TLSVersion: "TLS1.3", ALPN: "h3", Status: 200,
		Headers:    canonicalHeaders(http.Header{"Date": {"today"}, "Content-Type": {"text/plain"}}),
		BodySHA256: "abc", BodyBytes: 3,
	}
	right := left
	right.Headers = canonicalHeaders(http.Header{"Date": {"tomorrow"}, "Content-Type": {"text/plain"}})
	right.LatencyMS = 999
	if !evidenceEquivalent(left, right) {
		t.Fatal("declared Date/latency variance changed semantic equivalence")
	}
	right.Headers = canonicalHeaders(http.Header{"Server": {"product"}, "Content-Type": {"text/plain"}})
	if evidenceEquivalent(left, right) {
		t.Fatal("stable Server header difference was incorrectly ignored")
	}
}

func TestResponseAuthenticationProofIsRedactedFromJSONEvidence(t *testing.T) {
	const proof = "nextnonce=known-message-mac, padding=credential-derived-padding"
	raw := http.Header{"Proxy-Authentication-Info": {proof}}
	evidence := responseEvidence{
		OK: true, Headers: canonicalHeaders(raw), RawHeaders: raw,
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if strings.Contains(text, proof) || strings.Contains(text, "known-message-mac") || strings.Contains(text, "credential-derived-padding") {
		t.Fatalf("serialized evidence leaked response proof: %s", text)
	}
	var decoded responseEvidence
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.Headers, []string{"proxy-authentication-info:<redacted>"}) {
		t.Fatalf("serialized evidence lost redacted header-presence marker: %v", decoded.Headers)
	}
}

func TestResponseMarkerLeaks(t *testing.T) {
	evidence := responseEvidence{
		OK: true, ALPN: "autocar/2", RawHeaders: make(http.Header),
		Headers: []string{"server:AutoCAR"}, Body: []byte("ordinary"),
	}
	leaks := responseMarkerLeaks("autocar", evidence, "")
	if !reflect.DeepEqual(leaks, []string{"autocar", "native_alpn"}) {
		t.Fatalf("leaks = %v", leaks)
	}
	clean := responseEvidence{OK: true, ALPN: "h2", Headers: []string{"content-type:text/html"}, Body: []byte("site")}
	if got := responseMarkerLeaks("autocar", clean, "Bearer private"); len(got) != 0 {
		t.Fatalf("clean response leaks = %v", got)
	}
}

func TestIsolatedEndpointGuardFreezesOnlyExplicitAllowedAddresses(t *testing.T) {
	allowlist, err := parseIsolatedAllowlist([]string{"127.0.0.1", "10.0.0.0/24", "::1/128"})
	if err != nil {
		t.Fatal(err)
	}
	for endpoint, want := range map[string]string{
		"127.0.0.1:443": "127.0.0.1:443",
		"10.0.0.2:8443": "10.0.0.2:8443",
		"[::1]:443":     "[::1]:443",
	} {
		got, freezeErr := freezeIsolatedHostPort(endpoint, allowlist)
		if freezeErr != nil {
			t.Errorf("private endpoint %s: %v", endpoint, freezeErr)
		} else if got != want {
			t.Errorf("frozen endpoint = %q, want %q", got, want)
		}
	}
	if _, err := freezeIsolatedHostPort("10.0.1.2:443", allowlist); err == nil || !strings.Contains(err.Error(), "explicit") {
		t.Fatalf("unlisted private endpoint guard error = %v", err)
	}
	if _, err := freezeIsolatedHostPort("8.8.8.8:443", allowlist); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("public endpoint guard error = %v", err)
	}
	linkLocal := isolatedAllowlist{prefixes: []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16")}}
	if _, err := freezeIsolatedHostPort("169.254.169.254:80", linkLocal); err == nil || !strings.Contains(err.Error(), "link-local") {
		t.Fatalf("link-local endpoint guard error = %v", err)
	}
	frozenURL, err := freezeIsolatedURL("https://127.0.0.1:9443/test?q=1", allowlist)
	if err != nil || frozenURL != "https://127.0.0.1:9443/test?q=1" {
		t.Fatalf("frozen URL = %q, %v", frozenURL, err)
	}
}

func TestIsolatedAllowlistRejectsBroadOrLinkLocalRanges(t *testing.T) {
	for _, value := range []string{"0.0.0.0/0", "10.0.0.0/7", "169.254.0.0/16", "fe80::/10", "::/0"} {
		if _, err := parseIsolatedAllowlist([]string{value}); err == nil {
			t.Errorf("unsafe allowlist entry %q was accepted", value)
		}
	}
	if _, err := parseIsolatedAllowlist(nil); err == nil {
		t.Fatal("empty allowlist was accepted")
	}
}

func TestInvalidCredentialsUseCountedTarget(t *testing.T) {
	const target = "10.0.0.9:9000"
	probes := genericProbes("autocar", "h3", 1, target)
	seen := 0
	for _, probe := range probes {
		if isNoDialProbe(probe) {
			seen++
			if probe.authority != target {
				t.Errorf("probe %s authority = %q, want counted target %q", probe.name, probe.authority, target)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("counted invalid credential probes = %d, want 2", seen)
	}
}

func TestConfirmDialCountStableObservesWholeQuietWindow(t *testing.T) {
	var accepted atomic.Int64
	accepted.Store(7)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"accepted":%d}`, accepted.Load())
	}))
	defer server.Close()
	if got, stable, err := confirmDialCountStable(server.URL, 7, 30*time.Millisecond); err != nil || !stable || got != 7 {
		t.Fatalf("stable count = %d/%v/%v", got, stable, err)
	}
	go func() {
		time.Sleep(10 * time.Millisecond)
		accepted.Store(8)
	}()
	if got, stable, err := confirmDialCountStable(server.URL, 7, 100*time.Millisecond); err != nil || stable || got != 8 {
		t.Fatalf("changed count = %d/%v/%v", got, stable, err)
	}
}

func TestTLSVersionName(t *testing.T) {
	if got := tlsVersionName(tls.VersionTLS13); got != "TLS1.3" {
		t.Fatalf("TLS name = %q", got)
	}
}
