package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/cover"
)

// Use the real combined listener and ordinary clients, not a handler recorder:
// net/http's general OPTIONS handler can intercept '*' before cover is called.
func TestWebCoverOptionsAsteriskStaticAcrossProtocols(t *testing.T) {
	website, err := cover.NewStaticHandler(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var dials, resolves atomic.Int64
	server, clientTLS := webAltSvcCombinedServer(t, website, webAltSvcForbiddenDialer(&dials), &resolves)
	for _, proto := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("h%d", proto), func(t *testing.T) {
			rt := webAltSvcPublicTransport(t, clientTLS, proto)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			request := webCoverOptionsRequest(t, ctx, server, proto, "*", "asterisk")
			result := webAltSvcRoundTrip(t, rt, request, proto)
			if result.status != http.StatusMethodNotAllowed || result.body != "Method Not Allowed\n" || result.header.Get("Allow") != "GET, HEAD" {
				t.Errorf("real OPTIONS * static response = %d/%q/Allow:%q, want 405/Method Not Allowed/GET, HEAD", result.status, result.body, result.header.Get("Allow"))
			}
			webCoverOptionsPublicHeaders(t, result, server)
		})
	}
	if dials.Load() != 0 || resolves.Load() != 0 {
		t.Fatalf("ordinary OPTIONS touched tunnel dial/resolution: %d/%d", dials.Load(), resolves.Load())
	}
}

func TestWebCoverOptionsFixedOriginTargetsAcrossProtocols(t *testing.T) {
	observed := make(chan webCoverOptionsObserved, 12)
	var unexpectedRequests atomic.Int64
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		joined := make(chan struct{})
		defer close(joined)
		observation := webCoverOptionsObserved{
			method: r.Method, requestURI: r.RequestURI, host: r.Host,
			path: r.URL.Path, rawPath: r.URL.RawPath, rawQuery: r.URL.RawQuery,
			origin: r.Header.Get("Origin"), referer: r.Header.Get("Referer"),
			authorization: r.Header.Get("Authorization"), proxyAuthorization: r.Header.Get("Proxy-Authorization"),
			caseName: r.Header.Get("X-Options-Case"), joined: joined,
		}
		// This fixture has exactly twelve sequential requests. Never leave an
		// unexpected retry blocked on test observation during independent Close.
		select {
		case observed <- observation:
		default:
			unexpectedRequests.Add(1)
		}
		w.Header().Set("Alt-Svc", `h3=":1"; ma=1`)
		w.Header().Set("X-Options-Origin", "ordinary")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, "origin options\n")
	}))
	origin.Config.DisableGeneralOptionsHandler = true
	origin.Config.ReadHeaderTimeout = 2 * time.Second
	origin.Config.ReadTimeout = 2 * time.Second
	origin.Config.WriteTimeout = 2 * time.Second
	origin.Config.IdleTimeout = 2 * time.Second
	origin.Start()
	t.Cleanup(func() { origin.CloseClientConnections(); origin.Close() })
	target, err := url.Parse(origin.URL + "/base?operator=one")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != target.Host {
				return nil, fmt.Errorf("OPTIONS fixture blocked non-owned origin network/authority: %q/%q", network, address)
			}
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
		},
		ResponseHeaderTimeout: 2 * time.Second, IdleConnTimeout: time.Second,
	}
	t.Cleanup(upstream.CloseIdleConnections)
	website, err := cover.NewReverseProxyHandler(target, upstream)
	if err != nil {
		t.Fatal(err)
	}
	var dials, resolves atomic.Int64
	server, clientTLS := webAltSvcCombinedServer(t, website, webAltSvcForbiddenDialer(&dials), &resolves)
	for _, proto := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("h%d", proto), func(t *testing.T) {
			rt := webAltSvcPublicTransport(t, clientTLS, proto)
			for _, test := range []struct {
				name, target, requestURI, path, rawQuery string
			}{
				{name: "asterisk", target: "*", requestURI: "*", path: "*"},
				{name: "slash_star", target: "/*", requestURI: "/base/*?operator=one", path: "/base/*", rawQuery: "operator=one"},
				{name: "escaped_star", target: "/%2a", requestURI: "/base/%2a?operator=one", path: "/base/*", rawQuery: "operator=one"},
				{name: "query_star", target: "/path?literal=*", requestURI: "/base/path?operator=one&literal=*", path: "/base/path", rawQuery: "operator=one&literal=*"},
			} {
				t.Run(test.name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					request := webCoverOptionsRequest(t, ctx, server, proto, test.target, test.name)
					result := webAltSvcRoundTrip(t, rt, request, proto)
					if result.status != http.StatusAccepted || result.body != "origin options\n" || result.header.Get("X-Options-Origin") != "ordinary" {
						t.Errorf("fixed-origin ordinary response = %d/%q/X-Options-Origin:%q, want 202/origin options/ordinary", result.status, result.body, result.header.Get("X-Options-Origin"))
					}
					webCoverOptionsPublicHeaders(t, result, server)
					select {
					case got := <-observed:
						if got.method != http.MethodOptions || got.requestURI != test.requestURI || got.host != target.Host || got.path != test.path || got.rawQuery != test.rawQuery {
							t.Errorf("actual upstream method/URI/Host/path/query = %s/%q/%q/%q/%q (observed RawPath:%q), want OPTIONS/%q/%q/%q/%q", got.method, got.requestURI, got.host, got.path, got.rawQuery, got.rawPath, test.requestURI, target.Host, test.path, test.rawQuery)
						}
						t.Logf("actual origin OPTIONS URI=%q path=%q query=%q RawPath=%q", got.requestURI, got.path, got.rawQuery, got.rawPath)
						if got.caseName != test.name || got.origin != "https://visitor.invalid" || got.referer != "https://visitor.invalid/app" {
							t.Errorf("origin/referer/case changed or fabricated: %q/%q/%q", got.origin, got.referer, got.caseName)
						}
						if got.authorization != "" || got.proxyAuthorization != "" {
							t.Error("ordinary OPTIONS forwarded request credentials")
						}
						select {
						case <-got.joined:
						case <-time.After(time.Second):
							t.Error("actual origin OPTIONS handler did not join")
						}
					case <-time.After(500 * time.Millisecond):
						t.Error("completed public response never reached configured origin")
					}
					// No prior request may be mistaken for the next matrix case.
					if len(observed) != 0 {
						t.Error("unexpected additional origin OPTIONS request")
					}
				})
			}
		})
	}
	if dials.Load() != 0 || resolves.Load() != 0 || unexpectedRequests.Load() != 0 {
		t.Fatalf("ordinary OPTIONS tunnel dial/resolution/unexpected origin counters = %d/%d/%d", dials.Load(), resolves.Load(), unexpectedRequests.Load())
	}
}

type webCoverOptionsObserved struct {
	method, requestURI, host, path, rawPath, rawQuery  string
	origin, referer, authorization, proxyAuthorization string
	caseName                                           string
	joined                                             <-chan struct{}
}

func webCoverOptionsRequest(t *testing.T, ctx context.Context, server *WebServer, proto int, target, caseName string) *http.Request {
	t.Helper()
	requestTarget := target
	if target == "*" {
		requestTarget = "/"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodOptions, "https://"+webAltSvcAddress(server, proto)+requestTarget, nil)
	if err != nil {
		t.Fatal(err)
	}
	if target == "*" {
		request.URL.Path, request.URL.RawPath, request.URL.RawQuery = "*", "", ""
		if request.URL.RequestURI() != "*" {
			t.Fatal("fixture did not construct an actual asterisk request target")
		}
	}
	request.Host = "requester.invalid"
	request.Header.Set("Origin", "https://visitor.invalid")
	request.Header.Set("Referer", "https://visitor.invalid/app")
	request.Header.Set("X-Options-Case", caseName)
	request.Header.Set("Authorization", "Bearer fictional-origin-credential")
	request.Header.Set("Proxy-Authorization", "Bearer invalid")
	return request
}

func webCoverOptionsPublicHeaders(t *testing.T, result webAltSvcResult, server *WebServer) {
	t.Helper()
	if got, want := result.header.Values("Alt-Svc"), []string{webH3AltSvcValue(server.UDPAddr())}; !reflect.DeepEqual(got, want) {
		t.Errorf("ordinary OPTIONS bound Alt-Svc = %v, want %v", got, want)
	}
	if result.header.Get(webAuthResponseHeader) != "" || result.header.Get("Proxy-Authenticate") != "" || len(result.infos) != 0 {
		t.Error("ordinary OPTIONS emitted tunnel proof/challenge or unexpected informational response")
	}
}
