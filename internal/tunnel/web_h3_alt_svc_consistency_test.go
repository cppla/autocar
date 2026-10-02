package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"net/textproto"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/cppla/autocar/internal/cover"
	"github.com/cppla/autocar/internal/transport"
)

var webAltSvcOriginValues = []string{`h3="unrelated.example:4444"; ma=86400`, `h3=":1"; ma=1`}

func TestWebH3AltSvcConsistencyPublicCommitModes(t *testing.T) {
	var credentials, dials, resolves atomic.Int64
	website := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			credentials.Add(1)
		}
		webAltSvcWebsite(w, strings.TrimPrefix(r.URL.Path, "/"))
	})
	server, clientTLS := webAltSvcCombinedServer(t, website, webAltSvcForbiddenDialer(&dials), &resolves)
	bound := []string{webH3AltSvcValue(server.UDPAddr())}
	for _, proto := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("h%d", proto), func(t *testing.T) {
			rt := webAltSvcPublicTransport(t, clientTLS, proto)
			for _, mode := range []string{"single_103_explicit", "multiple_explicit", "implicit_body", "flush_body", "read_from", "implicit_empty", "clear_empty"} {
				t.Run(mode, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+webAltSvcAddress(server, proto)+"/"+mode, nil)
					if err != nil {
						t.Fatal(err)
					}
					request.Header.Set("Proxy-Authorization", "Bearer invalid")
					result := webAltSvcRoundTrip(t, rt, request, proto)
					codes := []int{103, 102, 103}
					status, body := 200, "ordinary website"
					if mode == "single_103_explicit" {
						codes = []int{103}
					}
					if mode == "single_103_explicit" || mode == "multiple_explicit" {
						status = 202
					}
					if mode == "implicit_empty" || mode == "clear_empty" {
						body = ""
					}
					webAltSvcAssertPublic(t, result, codes, status, body, bound)
					if mode != "clear_empty" && result.header.Get("X-Site") != "ordinary" {
						t.Error("final end-to-end website header lost")
					}
				})
			}
		})
	}
	if dials.Load() != 0 || resolves.Load() != 0 || credentials.Load() != 0 {
		t.Fatalf("public target dial/resolution/credential counters=%d/%d/%d", dials.Load(), resolves.Load(), credentials.Load())
	}
}

func TestWebH3AltSvcConsistencyReverseProxyInvalidProbes(t *testing.T) {
	var credentials, dials, resolves atomic.Int64
	website := webAltSvcReverseProxyOrigin(t, &credentials)
	server, clientTLS := webAltSvcCombinedServer(t, website, webAltSvcForbiddenDialer(&dials), &resolves)
	bound := []string{webH3AltSvcValue(server.UDPAddr())}
	for _, proto := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("h%d", proto), func(t *testing.T) {
			rt := webAltSvcPublicTransport(t, clientTLS, proto)
			probes := []struct {
				name, method, path string
				auth               []string
				udp                bool
			}{
				{name: "visitor", method: http.MethodGet, path: "/"},
				{name: "get_invalid_ticket", method: http.MethodGet, path: "/", auth: []string{"Bearer invalid"}},
				{name: "connect_missing", method: http.MethodConnect},
				{name: "connect_invalid", method: http.MethodConnect, auth: []string{"Bearer invalid"}},
				{name: "connect_duplicate", method: http.MethodConnect, auth: []string{"Bearer invalid", "Bearer another-invalid"}},
			}
			if proto == 3 {
				probes = append(probes,
					struct {
						name, method, path string
						auth               []string
						udp                bool
					}{"udp_invalid", http.MethodConnect, "/.well-known/masque/udp/target.invalid/443/", []string{"Bearer invalid"}, true},
					struct {
						name, method, path string
						auth               []string
						udp                bool
					}{"udp_malformed_invalid", http.MethodConnect, "/not-a-template", []string{"Bearer invalid"}, true},
				)
			}
			var visitor http.Header
			for _, probe := range probes {
				t.Run(probe.name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					request, err := http.NewRequestWithContext(ctx, probe.method, "https://"+webAltSvcAddress(server, proto)+probe.path, nil)
					if err != nil {
						t.Fatal(err)
					}
					if probe.method == http.MethodConnect && !probe.udp {
						request.Host = "target.invalid:443"
					}
					if len(probe.auth) != 0 {
						request.Header["Proxy-Authorization"] = probe.auth
						request.Header.Set("Authorization", "Bearer invalid-origin-credential")
					}
					if probe.udp {
						request.Proto = webConnectUDPProtocol
						request.Header.Set(webCapsuleProtocolHeader, webCapsuleProtocolValue)
					}
					result := webAltSvcRoundTrip(t, rt, request, proto)
					webAltSvcAssertPublic(t, result, []int{103, 102, 103}, 200, "ordinary website", bound)
					normalized := result.header.Clone()
					normalized.Del("Date")
					if probe.name == "visitor" {
						visitor = normalized
					} else if !reflect.DeepEqual(visitor, normalized) {
						t.Errorf("same-protocol invalid probe metadata differs from visitor: %v vs %v", normalized, visitor)
					}
				})
			}
		})
	}
	if dials.Load() != 0 || resolves.Load() != 0 || credentials.Load() != 0 {
		t.Fatalf("public target dial/resolution/credential counters=%d/%d/%d", dials.Load(), resolves.Load(), credentials.Load())
	}
	t.Log("real H1/H2/H3 visitor and invalid probes: target dial/resolution/credential counters=0/0/0")
}

func TestWebH3AltSvcConsistencyAuthenticatedResponsesRemainPrivate(t *testing.T) {
	target := webAltSvcTCPDestination(t)
	var dials, resolves, coverCalls atomic.Int64
	website := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		coverCalls.Add(1)
		webAltSvcWebsite(w, "multiple_explicit")
	})
	dialer := transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		if network != "tcp" || address != target {
			return nil, errors.New("private authenticated destination failure")
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
	})
	server, clientTLS := webAltSvcCombinedServer(t, website, dialer, &resolves)
	for _, proto := range []int{2, 3} {
		for _, success := range []bool{true, false} {
			t.Run(fmt.Sprintf("h%d/success_%t", proto, success), func(t *testing.T) {
				rt := webAltSvcPublicTransport(t, clientTLS, proto) // separate fresh physical auth connection
				authority, wire, status, body := target, webAuthTransportH2, 200, "reply:payload"
				if proto == 3 {
					wire = webAuthTransportH3
				}
				if !success {
					authority, status, body = "target.invalid:443", 502, "bad gateway\n"
				}
				key := mustWebAuthKey(t, webTestToken)
				binding := webAuthBinding{transport: wire, method: http.MethodConnect, authority: authority}
				bearer, claims, err := newWebAuthSigner(key, nil, nil).authorization(binding, webAuthClaims{})
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				request, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+webAltSvcAddress(server, proto), strings.NewReader("payload"))
				if err != nil {
					t.Fatal(err)
				}
				request.Host = authority
				request.Header.Set("Proxy-Authorization", bearer)
				result := webAltSvcRoundTrip(t, rt, request, proto)
				if result.status != status || result.body != body || len(result.infos) != 0 || len(result.header.Values("Alt-Svc")) != 0 {
					t.Fatalf("authenticated response status/body/info/AltSvc=%d/%q/%d/%v", result.status, result.body, len(result.infos), result.header.Values("Alt-Svc"))
				}
				if _, ok := acceptWebSessionBootstrap(key, result.header.Values(webAuthResponseHeader), binding, claims, status); !ok {
					t.Fatal("real authenticated response lacked a valid server bootstrap proof")
				}
			})
		}
	}
	if dials.Load() != 4 || resolves.Load() != 0 || coverCalls.Load() != 0 {
		t.Fatalf("authenticated dials/resolution/cover=%d/%d/%d", dials.Load(), resolves.Load(), coverCalls.Load())
	}
}

func TestWebH3AltSvcConsistencyStandalonePreservesOriginPolicy(t *testing.T) {
	var credentials, dials atomic.Int64
	website := webAltSvcReverseProxyOrigin(t, &credentials)
	serverTLS, clientTLS := testTLSConfigs(t)
	server, err := ListenWebH3(WebH3ServerConfig{Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS, Cover: website, Dialer: webAltSvcForbiddenDialer(&dials)})
	if err != nil {
		t.Fatal(err)
	}
	webAltSvcServe(t, server.Serve, server.Close)
	rt := webAltSvcPublicTransport(t, clientTLS, 3)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+server.Addr().String()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	result := webAltSvcRoundTrip(t, rt, request, 3)
	webAltSvcAssertPublic(t, result, []int{103, 102, 103}, 200, "ordinary website", webAltSvcOriginValues)
	if dials.Load() != 0 || credentials.Load() != 0 {
		t.Fatal("standalone public request touched tunnel destination or credentials")
	}
}

func webAltSvcWebsite(w http.ResponseWriter, mode string) {
	codes := []int{103, 102, 103}
	if mode == "single_103_explicit" {
		codes = []int{103}
	}
	for index, code := range codes {
		clear(w.Header())
		w.Header()["Alt-Svc"] = append([]string(nil), webAltSvcOriginValues...)
		w.Header().Set("Link", "</normal.css>; rel=preload")
		w.Header().Set("X-Info", fmt.Sprintf("info-%d", index))
		w.WriteHeader(code)
	}
	clear(w.Header())
	if mode == "clear_empty" {
		return
	}
	w.Header()["Alt-Svc"] = append([]string(nil), webAltSvcOriginValues...)
	w.Header().Set("X-Site", "ordinary")
	w.Header().Set("Content-Type", "text/plain")
	if mode == "single_103_explicit" || mode == "multiple_explicit" {
		w.WriteHeader(202)
	}
	if mode == "flush_body" {
		_ = http.NewResponseController(w).Flush()
	}
	if mode == "read_from" {
		// Hide WriterTo so io.Copy exercises the wrapper's ReaderFrom, when
		// present, including HTTP/3's underlying-writer fallback path.
		_, _ = io.Copy(w, struct{ io.Reader }{strings.NewReader("ordinary website")})
		return
	}
	if mode != "implicit_empty" {
		_, _ = io.WriteString(w, "ordinary website")
	}
}

func webAltSvcReverseProxyOrigin(t *testing.T, credentials *atomic.Int64) http.Handler {
	t.Helper()
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Proxy-Authorization") != "" {
			credentials.Add(1)
		}
		webAltSvcWebsite(w, "implicit_body")
	}))
	origin.Config.ReadHeaderTimeout, origin.Config.WriteTimeout, origin.Config.IdleTimeout = 2*time.Second, 2*time.Second, 2*time.Second
	origin.Start()
	t.Cleanup(func() { origin.CloseClientConnections(); origin.Close() })
	target, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	rt := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, ResponseHeaderTimeout: 2 * time.Second, IdleConnTimeout: time.Second}
	t.Cleanup(rt.CloseIdleConnections)
	website, err := cover.NewReverseProxyHandler(target, rt)
	if err != nil {
		t.Fatal(err)
	}
	return website
}

func webAltSvcForbiddenDialer(dials *atomic.Int64) transport.Dialer {
	return transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("public test forbids target dials")
	})
}

func webAltSvcCombinedServer(t *testing.T, website http.Handler, dialer transport.Dialer, resolves *atomic.Int64) (*WebServer, *tls.Config) {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	server, err := ListenWeb(WebServerConfig{TCPAddress: "127.0.0.1:0", UDPAddress: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS, Cover: website, Dialer: dialer, UDPResolver: UDPResolverFunc(func(context.Context, string) ([]netip.AddrPort, error) {
		resolves.Add(1)
		return nil, errors.New("public test forbids target resolution")
	})})
	if err != nil {
		t.Fatal(err)
	}
	webAltSvcServe(t, server.Serve, server.Close)
	return server, clientTLS
}

func webAltSvcServe(t *testing.T, serve func(context.Context) error, closeServer func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done, joined := make(chan error, 1), make(chan struct{})
	t.Cleanup(func() {
		cancel()
		_ = closeServer()
		select {
		case <-joined:
		case <-time.After(3 * time.Second):
			t.Error("web Alt-Svc server worker did not join")
		}
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		default:
		}
	})
	go func() { defer close(joined); done <- serve(ctx) }()
}

func webAltSvcAddress(server *WebServer, proto int) string {
	if proto == 3 {
		return server.UDPAddr().String()
	}
	return server.TCPAddr().String()
}

func webAltSvcPublicTransport(t *testing.T, clientTLS *tls.Config, proto int) http.RoundTripper {
	t.Helper()
	if proto == 3 {
		config := clientTLS.Clone()
		config.NextProtos = []string{http3.NextProtoH3}
		rt := &http3.Transport{TLSClientConfig: config, QUICConfig: &quic.Config{EnableDatagrams: true, HandshakeIdleTimeout: 2 * time.Second, MaxIdleTimeout: 3 * time.Second}, EnableDatagrams: true}
		t.Cleanup(func() { _ = rt.Close() })
		return rt
	}
	rt := &http.Transport{Proxy: nil, TLSClientConfig: clientTLS.Clone(), ForceAttemptHTTP2: proto == 2, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second, IdleConnTimeout: time.Second}
	if proto == 1 {
		rt.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
		rt.TLSClientConfig.NextProtos = []string{webHTTP11ALPN}
	}
	t.Cleanup(rt.CloseIdleConnections)
	return rt
}

type webAltSvcInfo struct {
	code   int
	header http.Header
}
type webAltSvcResult struct {
	status int
	header http.Header
	body   string
	infos  []webAltSvcInfo
}

func webAltSvcRoundTrip(t *testing.T, rt http.RoundTripper, request *http.Request, proto int) webAltSvcResult {
	t.Helper()
	var mu sync.Mutex
	var infos []webAltSvcInfo
	trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, h textproto.MIMEHeader) error {
		mu.Lock()
		defer mu.Unlock()
		infos = append(infos, webAltSvcInfo{code, http.Header(h).Clone()})
		return nil
	}}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))
	response, err := rt.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.ProtoMajor != proto || response.TLS == nil {
		t.Fatalf("actual response protocol=%s TLS=%t, want HTTP/%d", response.Proto, response.TLS != nil, proto)
	}
	mu.Lock()
	defer mu.Unlock()
	return webAltSvcResult{response.StatusCode, response.Header.Clone(), string(body), append([]webAltSvcInfo(nil), infos...)}
}

func webAltSvcAssertPublic(t *testing.T, result webAltSvcResult, codes []int, status int, body string, wantAlt []string) {
	t.Helper()
	if result.status != status || result.body != body || len(result.infos) != len(codes) {
		t.Fatalf("website status/body/1xx=%d/%q/%d, want %d/%q/%d", result.status, result.body, len(result.infos), status, body, len(codes))
	}
	for index, info := range result.infos {
		if info.code != codes[index] || info.header.Get("Link") != "</normal.css>; rel=preload" || info.header.Get("X-Info") != fmt.Sprintf("info-%d", index) {
			t.Errorf("website informational status/end-to-end fields changed: %d %v", info.code, info.header)
		}
		if !reflect.DeepEqual(info.header.Values("Alt-Svc"), wantAlt) {
			t.Errorf("1xx Alt-Svc=%v, want %v", info.header.Values("Alt-Svc"), wantAlt)
		}
		if info.header.Get(webAuthResponseHeader) != "" || info.header.Get("Proxy-Authenticate") != "" {
			t.Error("public informational response emitted private proof/challenge")
		}
	}
	if !reflect.DeepEqual(result.header.Values("Alt-Svc"), wantAlt) {
		t.Errorf("final Alt-Svc=%v, want %v", result.header.Values("Alt-Svc"), wantAlt)
	}
	if result.header.Get(webAuthResponseHeader) != "" || result.header.Get("Proxy-Authenticate") != "" {
		t.Error("public response emitted private proof/challenge")
	}
}

func webAltSvcTCPDestination(t *testing.T) string {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	owned := make(map[net.Conn]struct{})
	closed := false
	joined := make(chan struct{})
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		closed = true
		for conn := range owned {
			_ = conn.Close()
		}
		mu.Unlock()
		select {
		case <-joined:
		case <-time.After(3 * time.Second):
			t.Error("authenticated destination workers did not join")
		}
	})
	go func() {
		defer close(joined)
		var workers sync.WaitGroup
		defer workers.Wait()
		for range 2 {
			_ = listener.SetDeadline(time.Now().Add(3 * time.Second))
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				_ = conn.Close()
				return
			}
			owned[conn] = struct{}{}
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				defer func() { mu.Lock(); delete(owned, conn); mu.Unlock() }()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				payload, err := io.ReadAll(io.LimitReader(conn, 1024))
				if err != nil {
					return
				}
				_, _ = conn.Write(append([]byte("reply:"), payload...))
			}()
		}
	}()
	return listener.Addr().String()
}
