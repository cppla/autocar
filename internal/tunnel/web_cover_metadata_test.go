package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/textproto"
	"net/url"
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

func TestWebCoverMetadataConnectionNominatedTrailerOnWire(t *testing.T) {
	for _, proto := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("h%d", proto), func(t *testing.T) {
			webCoverMetadataExchange(t, proto, false, false)
		})
	}
}

func TestWebCoverMetadataProxyAuthenticationInfoOnWire(t *testing.T) {
	for _, proto := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("h%d", proto), func(t *testing.T) {
			for _, phase := range []string{"final", "trailer"} {
				t.Run(phase, func(t *testing.T) {
					webCoverMetadataExchange(t, proto, true, phase == "trailer")
				})
			}
		})
	}
}

const (
	webCoverMetadataEarly = "early|"
	webCoverMetadataLate  = "complete-payload"
	webCoverMetadataWWW   = `Basic realm="ordinary-site"`
)

type webCoverMetadataHint struct {
	code   int
	header http.Header
}

func webCoverMetadataExchange(t *testing.T, proto int, authenticationInfo, authTrailer bool) {
	t.Helper()
	origin := webCoverMetadataRawOrigin(t, authenticationInfo, authTrailer)
	// Also release the independent origin gate on Fatal, before server cleanup.
	defer origin.ungate()
	upstream := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != origin.address {
				return nil, errors.New("metadata fixture forbids every non-owned origin")
			}
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
		},
		ResponseHeaderTimeout: 2 * time.Second, IdleConnTimeout: time.Second,
	}
	t.Cleanup(upstream.CloseIdleConnections)
	target, err := url.Parse("http://" + origin.address + "/base?operator=1")
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := cover.NewReverseProxyHandler(target, upstream)
	if err != nil {
		t.Fatal(err)
	}
	coverJoined := make(chan struct{})
	var coverStarted atomic.Bool
	website := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		coverStarted.Store(true)
		defer close(coverJoined)
		proxy.ServeHTTP(w, r)
	})
	serverTLS, clientTLS := testTLSConfigs(t)
	var targetDials, targetResolutions atomic.Int64
	server, err := ListenWeb(WebServerConfig{
		TCPAddress: "127.0.0.1:0", UDPAddress: "127.0.0.1:0",
		Token: webTestToken, TLSConfig: serverTLS, Cover: website,
		Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
			targetDials.Add(1)
			return nil, errors.New("public metadata fixture forbids tunnel destinations")
		}),
		UDPResolver: UDPResolverFunc(func(context.Context, string) ([]netip.AddrPort, error) {
			targetResolutions.Add(1)
			return nil, errors.New("public metadata fixture forbids UDP target resolution")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	serveCtx, cancelServe := context.WithCancel(context.Background())
	serveResult, serveJoined := make(chan error, 1), make(chan struct{})
	go func() { defer close(serveJoined); serveResult <- server.Serve(serveCtx) }()
	t.Cleanup(func() {
		cancelServe()
		_ = server.Close()
		webCoverMetadataJoin(t, "combined Serve", serveJoined)
		if coverStarted.Load() {
			webCoverMetadataJoin(t, "cover handler", coverJoined)
		}
		select {
		case err := <-serveResult:
			if err != nil {
				t.Errorf("combined Serve: %v", err)
			}
		default:
		}
	})
	rt := webCoverMetadataPublicTransport(t, clientTLS, proto)
	address := server.TCPAddr().String()
	if proto == 3 {
		address = server.UDPAddr().String()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var hintsMu sync.Mutex
	var hints []webCoverMetadataHint
	trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
		hintsMu.Lock()
		defer hintsMu.Unlock()
		hints = append(hints, webCoverMetadataHint{code, http.Header(header).Clone()})
		return nil
	}}
	request, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, "https://"+address+"/metadata?visitor=2", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Basic fictional-origin-credential")
	request.Header.Set("Proxy-Authorization", "Bearer fictional-invalid-ticket")
	if authenticationInfo {
		request.Header.Set("Proxy-Authentication-Info", `nextnonce="fictional-request-proxy"`)
		request.Header.Set("Authentication-Info", `nextnonce="ordinary-request"`)
	}
	response, err := rt.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.ProtoMajor != proto || response.TLS == nil || response.StatusCode != http.StatusOK {
		t.Fatalf("actual public response = %s TLS=%t status=%d, want HTTP/%d TLS/200", response.Proto, response.TLS != nil, response.StatusCode, proto)
	}
	if response.Header.Get("X-Site") != "ordinary" || (!authenticationInfo && response.Header.Get(webAuthResponseHeader) != "") || response.Header.Get("Proxy-Authenticate") != "" {
		t.Errorf("ordinary final metadata/proof changed: %v", response.Header)
	}
	for _, name := range []string{"Authorization", "Proxy-Authorization", "Connection", "X-Hop"} {
		webCoverMetadataAssertAbsent(t, "final header", response.Header, name)
	}
	forbiddenTrailer := "X-Hop"
	if authenticationInfo {
		forbiddenTrailer = "Proxy-Authentication-Info"
		webCoverMetadataAssertAbsent(t, "final header", response.Header, forbiddenTrailer)
		wantAuthenticationInfo := `nextnonce="ordinary-final"`
		if authTrailer {
			wantAuthenticationInfo = ""
		}
		if response.Header.Get("Authentication-Info") != wantAuthenticationInfo || response.Header.Get("WWW-Authenticate") != webCoverMetadataWWW {
			t.Errorf("ordinary final authentication metadata lost: %v", response.Header)
		}
	}
	webCoverMetadataAssertAbsent(t, "announced trailer", response.Trailer, forbiddenTrailer)
	for _, value := range response.Header.Values("Trailer") {
		for _, name := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(name), forbiddenTrailer) {
				t.Errorf("unsafe Trailer announcement survived: %q", value)
			}
		}
	}
	if !webCoverMetadataHasField(response.Trailer, "X-End") {
		t.Errorf("ordinary X-End trailer announcement lost: %v", response.Trailer)
	}
	early := make([]byte, len(webCoverMetadataEarly))
	if _, err := io.ReadFull(response.Body, early); err != nil {
		t.Fatalf("early streaming read: %v", err)
	}
	if string(early) != webCoverMetadataEarly {
		t.Errorf("early bytes = %q", early)
	}
	select {
	case <-origin.earlySent:
	case <-time.After(time.Second):
		t.Fatal("owned origin did not publish the early chunk")
	}
	select {
	case <-origin.joined:
		t.Fatal("origin completed before the reader released its body gate")
	default:
	}
	origin.ungate()
	late, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(early)+string(late) != webCoverMetadataEarly+webCoverMetadataLate {
		t.Errorf("complete streamed body = %q", string(early)+string(late))
	}
	webCoverMetadataAssertAbsent(t, "late EOF trailer", response.Trailer, forbiddenTrailer)
	if response.Trailer.Get("X-End") != "retained-at-eof" {
		t.Errorf("ordinary late trailer lost: %v", response.Trailer)
	}
	if authTrailer && response.Trailer.Get("Authentication-Info") != `nextnonce="ordinary-trailer"` {
		t.Errorf("ordinary Authentication-Info trailer lost: %v", response.Trailer)
	}
	hintsMu.Lock()
	observed := append([]webCoverMetadataHint(nil), hints...)
	hintsMu.Unlock()
	if authenticationInfo {
		codes := []int{103, 102, 103}
		if len(observed) != len(codes) {
			t.Errorf("actual 1xx count = %d, want %d", len(observed), len(codes))
		} else {
			for i, hint := range observed {
				webCoverMetadataAssertAbsent(t, fmt.Sprintf("informational %d", i), hint.header, "Proxy-Authentication-Info")
				if hint.code != codes[i] || hint.header.Get("Authentication-Info") != fmt.Sprintf(`nextnonce="ordinary-info-%d"`, i) || hint.header.Get("WWW-Authenticate") != webCoverMetadataWWW || hint.header.Get("Link") != "</ordinary.css>; rel=preload" {
					t.Errorf("ordinary informational metadata changed: %d %v", hint.code, hint.header)
				}
			}
		}
	} else if len(observed) != 0 {
		t.Errorf("unexpected informational responses: %v", observed)
	}
	webCoverMetadataJoin(t, "raw H1 origin", origin.joined)
	select {
	case err := <-origin.result:
		if err != nil {
			t.Errorf("owned raw origin: %v", err)
		}
	default:
		t.Fatal("joined origin did not publish its result")
	}
	select {
	case got := <-origin.request:
		if got.ProtoMajor != 1 || got.ProtoMinor != 1 || got.Method != http.MethodGet || got.Host != origin.address || got.URL.Path != "/base/metadata" || got.URL.RawQuery != "operator=1&visitor=2" {
			t.Errorf("actual fixed H1 origin request = %s %s Host=%q URL=%s", got.Proto, got.Method, got.Host, got.URL)
		}
		for _, name := range []string{"Authorization", "Proxy-Authorization", "Proxy-Authentication-Info"} {
			webCoverMetadataAssertAbsent(t, "origin request", got.Header, name)
		}
		if authenticationInfo && got.Header.Get("Authentication-Info") != `nextnonce="ordinary-request"` {
			t.Errorf("ordinary request end-to-end metadata lost: %v", got.Header)
		}
	default:
		t.Fatal("owned origin did not publish its actual request")
	}
	webCoverMetadataJoin(t, "completed cover handler", coverJoined)
	if targetDials.Load() != 0 || targetResolutions.Load() != 0 {
		t.Errorf("public target dial/resolution = %d/%d, want 0/0", targetDials.Load(), targetResolutions.Load())
	}
	t.Logf("actual H1.1 fixed origin -> HTTPS H%d: early bytes before gate, complete EOF body, target dial/resolution=0/0", proto)
}

type webCoverMetadataOrigin struct {
	address   string
	earlySent chan struct{}
	gate      chan struct{}
	gateOnce  sync.Once
	joined    chan struct{}
	result    chan error
	request   chan *http.Request
}

func (o *webCoverMetadataOrigin) ungate() { o.gateOnce.Do(func() { close(o.gate) }) }

func webCoverMetadataRawOrigin(t *testing.T, authenticationInfo, authTrailer bool) *webCoverMetadataOrigin {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	o := &webCoverMetadataOrigin{listener.Addr().String(), make(chan struct{}), make(chan struct{}), sync.Once{}, make(chan struct{}), make(chan error, 1), make(chan *http.Request, 1)}
	var mu sync.Mutex
	var raw net.Conn
	closed := false
	t.Cleanup(func() {
		o.ungate()
		_ = listener.Close()
		mu.Lock()
		closed = true
		if raw != nil {
			_ = raw.Close()
		}
		mu.Unlock()
		webCoverMetadataJoin(t, "raw origin cleanup", o.joined)
	})
	go func() {
		defer close(o.joined)
		_ = listener.SetDeadline(time.Now().Add(4 * time.Second))
		conn, err := listener.AcceptTCP()
		if err != nil {
			o.result <- err
			return
		}
		defer conn.Close()
		mu.Lock()
		if closed {
			mu.Unlock()
			o.result <- net.ErrClosed
			return
		}
		raw = conn
		mu.Unlock()
		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			o.result <- err
			return
		}
		_, err = io.Copy(io.Discard, request.Body)
		_ = request.Body.Close()
		if err != nil {
			o.result <- err
			return
		}
		o.request <- request.Clone(context.Background())
		if authenticationInfo {
			for i, status := range []int{103, 102, 103} {
				if _, err := fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nProxy-Authentication-Info: nextnonce=\"fictional-info-proxy-%d\"\r\nAuthentication-Info: nextnonce=\"ordinary-info-%d\"\r\nWWW-Authenticate: %s\r\nLink: </ordinary.css>; rel=preload\r\n\r\n", status, http.StatusText(status), i, i, webCoverMetadataWWW); err != nil {
					o.result <- err
					return
				}
			}
		}
		headers := "Connection: X-Hop\r\nX-Hop: fictional-initial-hop\r\nTrailer: X-Hop, X-End\r\n"
		if authenticationInfo {
			// Do not declare a final header's own name as a trailer: native
			// writers can migrate/merge it. These independent cases isolate
			// final-field preservation from late trailer preservation.
			headers = "WWW-Authenticate: " + webCoverMetadataWWW + "\r\n"
			if authTrailer {
				headers += "Trailer: Proxy-Authentication-Info, Authentication-Info, X-End\r\n"
			} else {
				headers += "Proxy-Authentication-Info: nextnonce=\"fictional-final-proxy\"\r\nAuthentication-Info: nextnonce=\"ordinary-final\"\r\nTrailer: X-End\r\n"
			}
		}
		// Deliberately no Connection: close: its parser information-loss boundary
		// is separate. Nominations come only from the initial header, not trailers.
		if _, err := fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Site: ordinary\r\n%s\r\n%x\r\n%s\r\n", headers, len(webCoverMetadataEarly), webCoverMetadataEarly); err != nil {
			o.result <- err
			return
		}
		close(o.earlySent)
		select {
		case <-o.gate:
		case <-time.After(3 * time.Second):
			o.result <- errors.New("owned origin body gate timed out")
			return
		}
		trailers := "X-Hop: fictional-late-hop\r\nX-End: retained-at-eof\r\n"
		if authenticationInfo {
			trailers = "X-End: retained-at-eof\r\n"
			if authTrailer {
				trailers = "Proxy-Authentication-Info: nextnonce=\"fictional-trailer-proxy\"\r\nAuthentication-Info: nextnonce=\"ordinary-trailer\"\r\nX-End: retained-at-eof\r\n"
			}
		}
		_, err = fmt.Fprintf(conn, "%x\r\n%s\r\n0\r\n%s\r\n", len(webCoverMetadataLate), webCoverMetadataLate, trailers)
		o.result <- err
	}()
	return o
}

func webCoverMetadataPublicTransport(t *testing.T, clientTLS *tls.Config, proto int) http.RoundTripper {
	t.Helper()
	if proto == 3 {
		cfg := clientTLS.Clone()
		cfg.NextProtos = []string{http3.NextProtoH3}
		rt := &http3.Transport{TLSClientConfig: cfg, QUICConfig: &quic.Config{HandshakeIdleTimeout: 2 * time.Second, MaxIdleTimeout: 3 * time.Second}}
		t.Cleanup(func() { _ = rt.Close() })
		return rt
	}
	rt := &http.Transport{Proxy: nil, TLSClientConfig: clientTLS.Clone(), ForceAttemptHTTP2: proto == 2, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second, IdleConnTimeout: time.Second}
	if proto == 1 {
		rt.TLSClientConfig.NextProtos = []string{webHTTP11ALPN}
		rt.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
	}
	t.Cleanup(rt.CloseIdleConnections)
	return rt
}

func webCoverMetadataJoin(t *testing.T, name string, joined <-chan struct{}) {
	t.Helper()
	select {
	case <-joined:
	case <-time.After(2 * time.Second):
		t.Errorf("%s did not join within its independent budget", name)
	}
}

func webCoverMetadataHasField(header http.Header, name string) bool {
	for field := range header {
		if strings.EqualFold(field, name) {
			return true
		}
	}
	return false
}

func webCoverMetadataAssertAbsent(t *testing.T, phase string, header http.Header, name string) {
	t.Helper()
	if webCoverMetadataHasField(header, name) {
		t.Errorf("%s leaked %s (including empty declarations): %v", phase, name, header)
	}
}
