package tunnel

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"reflect"
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
	webPublicOriginTLSName    = "fixed-origin.fixture.test"
	webPublicOriginCSRF       = "fictional-local-csrf-token"
	webPublicOriginSession    = "fictional-local-session"
	webPublicOriginForm       = `<form method="post" action="/login"><input type="hidden" name="csrf" value="fictional-local-csrf-token"></form>`
	webPublicOriginWelcome    = "ordinary authenticated website welcome"
	webPublicOriginThirdParty = "https://thirdparty.invalid/callback?opaque=one%2Ftwo"
)

var webPublicOriginRawCookies = []string{
	"origin_cookie=one; Domain=fixed-origin.fixture.test; Path=/; Secure; HttpOnly; SameSite=Lax; Priority=High",
	"odd_cookie=two; Path=/; Secure; Experimental=kept",
}

// These native-client exchanges test a website's independent cookie and CSRF
// policy. They do not claim browser SameSite enforcement or a browser campaign.
func TestWebCoverPublicOriginLoginOnWire(t *testing.T) {
	for _, proto := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("h%d", proto), func(t *testing.T) {
			for _, mode := range []bool{false, true} {
				name := "default_host_mismatch"
				if mode {
					name = "configured_public_vhost"
				}
				t.Run(name, func(t *testing.T) {
					f := newWebPublicOriginFixture(t, proto, mode)
					response, body := f.exchange(t, http.MethodGet, "/form", nil, nil, "")
					if response.StatusCode != 200 || body != webPublicOriginForm {
						t.Fatalf("ordinary form = %d/%q", response.StatusCode, body)
					}
					f.observed(t, "", "")
					assertWebPublicOriginCookie(t, response, "csrf", webPublicOriginCSRF, false)
					postHeaders := http.Header{"Origin": {f.public.String()}, "Referer": {f.public.String() + "/form"}}
					form := url.Values{"csrf": {webPublicOriginCSRF}, "username": {"ordinary-visitor"}, "password": {"fictional-local-password"}}
					response, _ = f.exchange(t, http.MethodPost, "/login", form, postHeaders, "")
					seen := f.observed(t, f.public.String(), f.public.String()+"/form")
					if !strings.Contains(seen.header.Get("Cookie"), "csrf="+webPublicOriginCSRF) {
						t.Error("actual login POST did not return the form's CSRF cookie")
					}
					if !mode {
						// The existing constructor intentionally uses the upstream
						// Host. This is a supported default-policy control, not a
						// compile-failure or a claim that the default is broken.
						if response.StatusCode != 403 || seen.host != f.upstream.Host {
							t.Errorf("default same-origin rejection = %d, actual Host=%q", response.StatusCode, seen.host)
						}
						if response.Header.Get("Location") != "" {
							t.Error("rejected login redirected")
						}
						return
					}
					assertWebPublicOriginRedirect(t, response, f.public.String()+"/welcome")
					assertWebPublicOriginCookie(t, response, "site_session", webPublicOriginSession, false)
					location, err := url.Parse(response.Header.Get("Location"))
					if err != nil || location.Scheme != f.public.Scheme || location.Host != f.public.Host {
						t.Fatalf("refusing any non-owned login redirect: %q, %v", response.Header.Get("Location"), err)
					}
					response, body = f.exchange(t, http.MethodGet, location.RequestURI(), nil, nil, "")
					seen = f.observed(t, "", "")
					if response.StatusCode != 200 || body != webPublicOriginWelcome || !strings.Contains(seen.header.Get("Cookie"), "site_session="+webPublicOriginSession) {
						t.Fatalf("actual cookie-authenticated welcome = %d/%q, Cookie=%q", response.StatusCode, body, seen.header.Get("Cookie"))
					}
					response, _ = f.exchange(t, http.MethodPost, "/logout", url.Values{"csrf": {webPublicOriginCSRF}}, postHeaders, "")
					f.observed(t, f.public.String(), f.public.String()+"/form")
					assertWebPublicOriginRedirect(t, response, f.public.String()+"/form")
					assertWebPublicOriginCookie(t, response, "site_session", "", true)
					response, _ = f.exchange(t, http.MethodGet, "/welcome", nil, nil, "")
					seen = f.observed(t, "", "")
					if response.StatusCode != 401 || strings.Contains(seen.header.Get("Cookie"), "site_session=") {
						t.Errorf("post-logout welcome = %d, Cookie=%q", response.StatusCode, seen.header.Get("Cookie"))
					}
					t.Log("actual website CSRF/cookie login and logout; TLS target/SNI remains fixed origin, HTTP Host is public vhost")
				})
			}
		})
	}
}

func TestWebCoverPublicOriginGuardOnWire(t *testing.T) {
	for _, proto := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("h%d", proto), func(t *testing.T) {
			f := newWebPublicOriginFixture(t, proto, true)
			for _, test := range []struct {
				name, host string
				header     http.Header
				status     int
			}{
				{"wrong_host", "evil.invalid", nil, 421},
				{"wrong_host_before_origin", "evil.invalid", http.Header{"Origin": {"https://evil.invalid"}}, 421},
				{"wrong_port", "127.0.0.1:1", nil, 421},
				{"evil_origin", "", http.Header{"Origin": {"https://evil.invalid"}}, 403},
				{"null_origin", "", http.Header{"Origin": {"null"}}, 403},
				{"empty_origin", "", http.Header{"Origin": {""}}, 403},
				{"duplicate_origin", "", http.Header{"Origin": {f.public.String(), f.public.String()}}, 403},
				{"origin_list", "", http.Header{"Origin": {f.public.String() + " https://evil.invalid"}}, 403},
				{"origin_with_path", "", http.Header{"Origin": {f.public.String() + "/login"}}, 403},
				{"wrong_scheme", "", http.Header{"Origin": {"http://" + f.public.Host}}, 403},
			} {
				t.Run(test.name, func(t *testing.T) {
					before := f.appCalls.Load()
					response, _ := f.exchange(t, http.MethodGet, "/form", nil, test.header, test.host)
					if response.StatusCode != test.status {
						t.Errorf("guard status = %d, want %d", response.StatusCode, test.status)
					}
					if f.appCalls.Load() != before || f.originDials.Load() != 0 {
						t.Error("guard rejection reached the fixed website or dialed its origin")
					}
				})
			}
			// H2 native clients reject Connection: Origin before transmission;
			// connection-specific headers are also forbidden in H3. These are
			// real H1 guard probes, not claimed H2/H3 guard observations.
			if proto == 1 {
				for _, field := range []string{"Origin", "Referer"} {
					t.Run("nominated_missing_"+strings.ToLower(field), func(t *testing.T) {
						response, _ := f.exchange(t, http.MethodGet, "/form", nil, http.Header{"Connection": {field}}, "")
						if response.StatusCode != 403 || f.appCalls.Load() != 0 || f.originDials.Load() != 0 {
							t.Errorf("original missing %s nomination = %d, site/dial=%d/%d", field, response.StatusCode, f.appCalls.Load(), f.originDials.Load())
						}
					})
				}
			}
			t.Run("absent_origin_keeps_site_csrf_policy", func(t *testing.T) {
				before := f.appCalls.Load()
				response, _ := f.exchange(t, http.MethodPost, "/login", url.Values{"csrf": {webPublicOriginCSRF}}, http.Header{"Referer": {"https://evil.invalid/form"}}, "")
				f.observed(t, "", "https://evil.invalid/form")
				if response.StatusCode != 403 || f.appCalls.Load() != before+1 {
					t.Errorf("site's missing-Origin rejection = %d, site call delta=%d", response.StatusCode, f.appCalls.Load()-before)
				}
			})
		})
	}
}

func TestWebCoverPublicOriginForwardingAndMetadataOnWire(t *testing.T) {
	for _, proto := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("h%d", proto), func(t *testing.T) {
			f := newWebPublicOriginFixture(t, proto, true)
			header := http.Header{
				"Origin": {f.public.String()}, "Referer": {f.public.String() + "/ordinary?q=kept"},
				"Cookie": {"ordinary=kept; another=two"}, "Forwarded": {"host=evil.invalid;proto=http"},
				"X-Forwarded-Host": {"evil.invalid", "second.invalid"}, "X-Forwarded-Proto": {"http"},
				"X-Forwarded-For": {"192.0.2.99"}, "X-Forwarded-Mystery": {"poisoned"}, "X-Real-IP": {"192.0.2.98"},
			}
			response, body := f.exchange(t, http.MethodGet, "/metadata?plain=one%2Ftwo&empty=", nil, header, "")
			seen := f.observed(t, f.public.String(), f.public.String()+"/ordinary?q=kept")
			if response.StatusCode != 302 || response.Header.Get("Location") != webPublicOriginThirdParty || body != "location and cookie bytes unchanged" {
				t.Errorf("unmodified metadata response = %d/%q/%q", response.StatusCode, response.Header.Get("Location"), body)
			}
			if got := response.Header.Values("Set-Cookie"); !reflect.DeepEqual(got, webPublicOriginRawCookies) {
				t.Errorf("Set-Cookie bytes = %q, want %q", got, webPublicOriginRawCookies)
			}
			if seen.header.Get("Cookie") != "ordinary=kept; another=two" || seen.rawQuery != "plain=one%2Ftwo&empty=" {
				t.Errorf("ordinary request Cookie/query changed = %q/%q", seen.header.Get("Cookie"), seen.rawQuery)
			}
			for field, values := range seen.header {
				lower := strings.ToLower(field)
				if lower == "forwarded" || lower == "x-real-ip" || (strings.HasPrefix(lower, "x-forwarded-") && lower != "x-forwarded-host" && lower != "x-forwarded-proto") {
					t.Errorf("untrusted forwarding field reached website: %s=%q", field, values)
				}
			}
			if !reflect.DeepEqual(seen.header.Values("X-Forwarded-Host"), []string{f.public.Host}) || !reflect.DeepEqual(seen.header.Values("X-Forwarded-Proto"), []string{"https"}) {
				t.Errorf("trusted forwarding values = %v", seen.header)
			}
			if f.appCalls.Load() != 1 {
				t.Errorf("redirect-disabled website calls=%d, want 1", f.appCalls.Load())
			}
		})
	}
}

func TestWebCoverPublicOriginWebSocketOnWire(t *testing.T) {
	f := newWebPublicOriginFixture(t, 1, true)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", f.public.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	clientTLS := f.frontTLS.Clone()
	clientTLS.NextProtos = []string{webHTTP11ALPN}
	conn := tls.Client(raw, clientTLS)
	defer conn.Close()
	if err := conn.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if len(conn.ConnectionState().VerifiedChains) == 0 {
		t.Fatal("WebSocket frontend TLS was not verified")
	}
	request, err := http.NewRequest(http.MethodGet, f.public.String()+"/websocket", nil)
	if err != nil {
		t.Fatal(err)
	}
	const key = "dGhlIHNhbXBsZSBub25jZQ=="
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Sec-WebSocket-Version", "13")
	request.Header.Set("Sec-WebSocket-Key", key)
	request.Header.Set("Origin", f.public.String())
	request.Header.Set("X-Public-Vhost-Fixture", t.Name())
	request.Header.Set("Proxy-Authorization", "Bearer fictional-invalid-ticket")
	if err := request.Write(conn); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		t.Fatal(err)
	}
	accept := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if response.StatusCode != 101 || response.ProtoMajor != 1 || response.ProtoMinor != 1 || response.Header.Get("Connection") != "Upgrade" || response.Header.Get("Upgrade") != "websocket" || response.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(accept[:]) {
		t.Fatalf("actual public WebSocket handshake=%s/%d/%v", response.Proto, response.StatusCode, response.Header)
	}
	const payload = "echo"
	mask := [4]byte{1, 2, 3, 4}
	frame := []byte{0x81, 0x80 | byte(len(payload))}
	frame = append(frame, mask[:]...)
	for index := range payload {
		frame = append(frame, payload[index]^mask[index%4])
	}
	if n, err := conn.Write(frame); err != nil || n != len(frame) {
		t.Fatalf("masked client frame write=%d/%v", n, err)
	}
	echo := make([]byte, 2+len(payload))
	if _, err := io.ReadFull(reader, echo); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(echo, append([]byte{0x81, byte(len(payload))}, []byte(payload)...)) {
		t.Fatalf("actual unmasked origin echo frame=%x", echo)
	}
	_ = conn.Close()
	f.observed(t, f.public.String(), "")
	select {
	case marker := <-f.completed:
		if marker != t.Name() {
			t.Errorf("WebSocket completion marker=%q", marker)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WebSocket proxy worker did not independently join")
	}
	if f.appCalls.Load() != 1 {
		t.Errorf("actual WebSocket website calls=%d", f.appCalls.Load())
	}
	t.Log("real H1 masked-client/unmasked-origin echo after website default same-origin Host predicate; no extended CONNECT or browser claim")
}

type webPublicOriginObserved struct {
	host, sni, rawQuery string
	proto               int
	header              http.Header
}

type webPublicOriginFixture struct {
	public, upstream                                                                             *url.URL
	client                                                                                       *http.Client
	frontTLS                                                                                     *tls.Config
	proto                                                                                        int
	mode                                                                                         bool
	appCalls, originDials, invalidDials, verifiedOriginResponses, targetDials, targetResolutions atomic.Int64
	records                                                                                      chan webPublicOriginObserved
	completed                                                                                    chan string
	stateMu                                                                                      sync.Mutex
	session                                                                                      bool
	registerHijacked                                                                             func(net.Conn) bool
	unregisterHijacked                                                                           func(net.Conn)
	asyncErrors                                                                                  chan error
}

func newWebPublicOriginFixture(t *testing.T, proto int, mode bool) *webPublicOriginFixture {
	t.Helper()
	originTLS, originClientTLS := webPublicOriginTLSConfigs(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	upstream, err := url.Parse("https://" + net.JoinHostPort(webPublicOriginTLSName, strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)))
	if err != nil {
		t.Fatal(err)
	}
	f := &webPublicOriginFixture{upstream: upstream, proto: proto, mode: mode, records: make(chan webPublicOriginObserved, 64), completed: make(chan string, 64), asyncErrors: make(chan error, 64)}
	var admissionMu sync.Mutex
	var workers sync.WaitGroup
	closing := false
	hijacked := make(map[net.Conn]struct{})
	f.registerHijacked = func(conn net.Conn) bool {
		admissionMu.Lock()
		defer admissionMu.Unlock()
		if closing {
			return false
		}
		hijacked[conn] = struct{}{}
		return true
	}
	f.unregisterHijacked = func(conn net.Conn) { admissionMu.Lock(); defer admissionMu.Unlock(); delete(hijacked, conn) }
	admit := func() bool {
		admissionMu.Lock()
		defer admissionMu.Unlock()
		if closing {
			return false
		}
		workers.Add(1)
		return true
	}
	origin := &http.Server{ReadHeaderTimeout: 2 * time.Second, IdleTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !admit() {
			http.Error(w, "closing", 503)
			return
		}
		defer workers.Done()
		f.appCalls.Add(1)
		sni := ""
		if r.TLS != nil {
			sni = r.TLS.ServerName
		}
		f.records <- webPublicOriginObserved{r.Host, sni, r.URL.RawQuery, r.ProtoMajor, r.Header.Clone()}
		f.website(w, r)
	})}
	originRT := &http.Transport{Proxy: nil, TLSClientConfig: originClientTLS, TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper), TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second, IdleConnTimeout: time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != upstream.Host {
				f.invalidDials.Add(1)
				return nil, errors.New("public-vhost fixture forbids every non-owned upstream")
			}
			f.originDials.Add(1)
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", listener.Addr().String())
		},
	}
	t.Cleanup(originRT.CloseIdleConnections)
	var proxy http.Handler // Assigned once, before either server starts.
	website := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !admit() {
			http.Error(w, "closing", 503)
			return
		}
		defer workers.Done()
		defer func() { f.completed <- r.Header.Get("X-Public-Vhost-Fixture") }()
		proxy.ServeHTTP(w, r)
	})
	serverTLS, clientTLS := testTLSConfigs(t)
	f.frontTLS = clientTLS.Clone()
	server, err := listenWebEphemeralFixture(WebServerConfig{TCPAddress: "127.0.0.1:0", UDPAddress: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS, Cover: website,
		Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
			f.targetDials.Add(1)
			return nil, errors.New("public vhost fixture forbids tunnel dial")
		}),
		UDPResolver: UDPResolverFunc(func(context.Context, string) ([]netip.AddrPort, error) {
			f.targetResolutions.Add(1)
			return nil, errors.New("public vhost fixture forbids UDP resolution")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	f.public, err = url.Parse("https://" + server.TCPAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	checkedRT := webPublicOriginRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		response, err := originRT.RoundTrip(r)
		if err == nil && response != nil {
			if response.ProtoMajor != 1 || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
				_ = response.Body.Close()
				return nil, errors.New("owned origin was not actual verified-TLS H1")
			}
			f.verifiedOriginResponses.Add(1)
		}
		return response, err
	})
	if mode {
		proxy, err = cover.NewReverseProxyHandlerWithPublicOrigin(upstream, f.public, checkedRT)
	} else {
		proxy, err = cover.NewReverseProxyHandler(upstream, checkedRT)
	}
	if err != nil {
		t.Fatal(err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	f.client = &http.Client{Transport: webCoverMetadataPublicTransport(t, clientTLS, proto), Jar: jar, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	serveCtx, cancel := context.WithCancel(context.Background())
	originDone, frontDone := make(chan struct{}), make(chan struct{})
	originResult, frontResult := make(chan error, 1), make(chan error, 1)
	go func() {
		defer close(originDone)
		originResult <- origin.Serve(tls.NewListener(webPublicOriginDeadlineListener{listener}, originTLS))
	}()
	go func() { defer close(frontDone); frontResult <- server.Serve(serveCtx) }()
	t.Cleanup(func() {
		admissionMu.Lock()
		closing = true
		connections := make([]net.Conn, 0, len(hijacked))
		for conn := range hijacked {
			connections = append(connections, conn)
		}
		admissionMu.Unlock()
		for _, conn := range connections {
			_ = conn.Close()
		}
		cancel()
		_ = server.Close()
		_ = origin.Close()
		originRT.CloseIdleConnections()
		joined := make(chan struct{})
		go func() { defer close(joined); workers.Wait() }()
		webCoverMetadataJoin(t, "public-vhost request workers", joined)
		webCoverMetadataJoin(t, "public-vhost fixed origin Serve", originDone)
		webCoverMetadataJoin(t, "public-vhost combined Serve", frontDone)
		select {
		case err := <-originResult:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("origin Serve: %v", err)
			}
		default:
		}
		select {
		case err := <-frontResult:
			if err != nil {
				t.Errorf("combined Serve: %v", err)
			}
		default:
		}
		if f.invalidDials.Load() != 0 || f.targetDials.Load() != 0 || f.targetResolutions.Load() != 0 {
			t.Errorf("non-owned/tunnel dial/UDP resolution=%d/%d/%d", f.invalidDials.Load(), f.targetDials.Load(), f.targetResolutions.Load())
		}
		if f.verifiedOriginResponses.Load() != f.appCalls.Load() {
			t.Errorf("verified TLS H1 responses/site calls=%d/%d", f.verifiedOriginResponses.Load(), f.appCalls.Load())
		}
		for len(f.asyncErrors) > 0 {
			t.Errorf("website worker: %v", <-f.asyncErrors)
		}
		t.Logf("actual site calls=%d, verified fixed-origin TLS H1 responses=%d; non-owned/tunnel dial/UDP resolution=%d/%d/%d", f.appCalls.Load(), f.verifiedOriginResponses.Load(), f.invalidDials.Load(), f.targetDials.Load(), f.targetResolutions.Load())
	})
	return f
}

func (f *webPublicOriginFixture) exchange(t *testing.T, method, path string, form url.Values, header http.Header, host string) (*http.Response, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	request, err := http.NewRequestWithContext(ctx, method, f.public.String()+path, body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header = header.Clone()
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	request.Header.Set("X-Public-Vhost-Fixture", t.Name())
	request.Header.Set("Proxy-Authorization", "Bearer fictional-invalid-ticket")
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if host != "" {
		request.Host = host
	}
	response, err := f.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 32<<10))
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.ProtoMajor != f.proto || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		t.Fatalf("actual public response=%s verifiedTLS=%t, want H%d", response.Proto, response.TLS != nil && len(response.TLS.VerifiedChains) != 0, f.proto)
	}
	if response.Header.Get(webAuthResponseHeader) != "" || response.Header.Get("Proxy-Authenticate") != "" {
		t.Error("ordinary website exposed relay authentication metadata")
	}
	select {
	case marker := <-f.completed:
		if marker != t.Name() {
			t.Errorf("proxy completion marker=%q, want %q", marker, t.Name())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("public-vhost handler did not complete within independent budget")
	}
	return response, string(data)
}

func (f *webPublicOriginFixture) observed(t *testing.T, origin, referer string) webPublicOriginObserved {
	t.Helper()
	var seen webPublicOriginObserved
	select {
	case seen = <-f.records:
	case <-time.After(2 * time.Second):
		t.Fatal("fixed website did not publish an actual request")
	}
	wantHost := f.upstream.Host
	if f.mode {
		wantHost = f.public.Host
	}
	if seen.host != wantHost || seen.sni != webPublicOriginTLSName || seen.proto != 1 {
		t.Errorf("fixed website actual Host/SNI/proto=%q/%q/%d, want %q/%q/1", seen.host, seen.sni, seen.proto, wantHost, webPublicOriginTLSName)
	}
	if seen.header.Get("Origin") != origin || seen.header.Get("Referer") != referer {
		t.Errorf("original Origin/Referer changed=%q/%q, want %q/%q", seen.header.Get("Origin"), seen.header.Get("Referer"), origin, referer)
	}
	return seen
}

func (f *webPublicOriginFixture) website(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/websocket" {
		f.websiteWebSocket(w, r)
		return
	}
	if r.URL.Path == "/metadata" {
		for _, value := range webPublicOriginRawCookies {
			w.Header().Add("Set-Cookie", value)
		}
		w.Header().Set("Location", webPublicOriginThirdParty)
		w.WriteHeader(302)
		_, _ = io.WriteString(w, "location and cookie bytes unchanged")
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/form" {
		http.SetCookie(w, &http.Cookie{Name: "csrf", Value: webPublicOriginCSRF, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, webPublicOriginForm)
		return
	}
	if r.Method == http.MethodPost && (r.URL.Path == "/login" || r.URL.Path == "/logout") {
		// This is independent application policy based on its actual Host,
		// not a reimplementation of the proxy's configured-origin guard.
		if r.Header.Get("Origin") != "https://"+r.Host {
			http.Error(w, "website same-origin policy", 403)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		csrf, err := r.Cookie("csrf")
		if r.ParseForm() != nil || err != nil || csrf.Value != webPublicOriginCSRF || r.PostForm.Get("csrf") != webPublicOriginCSRF {
			http.Error(w, "website CSRF policy", 403)
			return
		}
		f.stateMu.Lock()
		defer f.stateMu.Unlock()
		if r.URL.Path == "/login" {
			if r.PostForm.Get("username") != "ordinary-visitor" || r.PostForm.Get("password") != "fictional-local-password" {
				http.Error(w, "website credentials", 403)
				return
			}
			f.session = true
			http.SetCookie(w, &http.Cookie{Name: "site_session", Value: webPublicOriginSession, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
			http.Redirect(w, r, f.public.String()+"/welcome", 303)
			return
		}
		f.session = false
		http.SetCookie(w, &http.Cookie{Name: "site_session", Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
		http.Redirect(w, r, f.public.String()+"/form", 303)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/welcome" {
		cookie, err := r.Cookie("site_session")
		f.stateMu.Lock()
		valid := f.session
		f.stateMu.Unlock()
		if !valid || err != nil || cookie.Value != webPublicOriginSession {
			http.Error(w, "website session absent", 401)
			return
		}
		_, _ = io.WriteString(w, webPublicOriginWelcome)
		return
	}
	http.NotFound(w, r)
}

func (f *webPublicOriginFixture) websiteWebSocket(w http.ResponseWriter, r *http.Request) {
	// This is the standard website same-origin predicate (as in Gorilla's
	// default): compare the parsed Origin Host to the application's actual
	// request Host, with no knowledge of the proxy's public configuration.
	if origins := r.Header.Values("Origin"); len(origins) != 0 {
		origin, err := url.Parse(origins[0])
		if err != nil || !strings.EqualFold(origin.Host, r.Host) {
			http.Error(w, "website WebSocket origin policy", 403)
			return
		}
	}
	if r.Method != http.MethodGet || r.ProtoMajor != 1 || r.ProtoMinor != 1 || r.Header.Get("Connection") != "Upgrade" || r.Header.Get("Upgrade") != "websocket" || r.Header.Get("Sec-WebSocket-Version") != "13" || r.Header.Get("Sec-WebSocket-Key") != "dGhlIHNhbXBsZSBub25jZQ==" {
		http.Error(w, "website requires a valid observed WebSocket handshake", 400)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "website cannot hijack", 500)
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		f.asyncErrors <- err
		return
	}
	if !f.registerHijacked(conn) {
		_ = conn.Close()
		return
	}
	defer f.unregisterHijacked(conn)
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		f.asyncErrors <- err
		return
	}
	accept := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	_, err = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(accept[:]))
	if err == nil {
		err = rw.Flush()
	}
	if err != nil {
		f.asyncErrors <- err
		return
	}
	header := make([]byte, 6)
	if _, err = io.ReadFull(rw, header); err != nil {
		f.asyncErrors <- err
		return
	}
	if header[0] != 0x81 || header[1] != 0x84 {
		f.asyncErrors <- fmt.Errorf("actual client frame header=%x, want complete masked text frame of four bytes", header[:2])
		return
	}
	payload := make([]byte, 4)
	if _, err = io.ReadFull(rw, payload); err != nil {
		f.asyncErrors <- err
		return
	}
	for index := range payload {
		payload[index] ^= header[2+index%4]
	}
	if string(payload) != "echo" {
		f.asyncErrors <- fmt.Errorf("actual decoded client frame payload=%q", payload)
		return
	}
	frame := append([]byte{0x81, byte(len(payload))}, payload...)
	if n, err := conn.Write(frame); err != nil || n != len(frame) {
		f.asyncErrors <- fmt.Errorf("unmasked origin frame write=%d/%v", n, err)
	}
}

func assertWebPublicOriginRedirect(t *testing.T, response *http.Response, location string) {
	t.Helper()
	if response.StatusCode != 303 || response.Header.Get("Location") != location {
		t.Errorf("website redirect=%d/%q, want303/%q", response.StatusCode, response.Header.Get("Location"), location)
	}
}
func assertWebPublicOriginCookie(t *testing.T, response *http.Response, name, value string, deleted bool) {
	t.Helper()
	for _, cookie := range response.Cookies() {
		if cookie.Name != name {
			continue
		}
		if cookie.Value != value || cookie.Domain != "" || cookie.Path != "/" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || ((cookie.MaxAge < 0) != deleted) {
			t.Errorf("website cookie=%#v", cookie)
		}
		return
	}
	t.Errorf("website Set-Cookie missing %s", name)
}

type webPublicOriginRoundTripFunc func(*http.Request) (*http.Response, error)

func (f webPublicOriginRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type webPublicOriginDeadlineListener struct{ net.Listener }

func (l webPublicOriginDeadlineListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		if err = conn.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, err
}

func webPublicOriginTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "owned private origin fixture"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true, DNSNames: []string{webPublicOriginTLSName}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{webHTTP11ALPN}}, &tls.Config{RootCAs: pool, ServerName: webPublicOriginTLSName, NextProtos: []string{webHTTP11ALPN}}
}
