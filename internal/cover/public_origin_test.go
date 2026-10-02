package cover

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// These tests exercise the opt-in public API, not its normalization helpers.
// Real TLS/SNI and site sessions have separate owned-loopback controls.
func TestPublicOriginConfiguredURLPolicy(t *testing.T) {
	mutations := []struct {
		name string
		edit func(*url.URL)
	}{
		{"nil", nil},
		{"empty_scheme", func(u *url.URL) { u.Scheme = "" }},
		{"other_scheme", func(u *url.URL) { u.Scheme = "wss" }},
		{"empty_host", func(u *url.URL) { u.Host = "" }},
		{"base_path", func(u *url.URL) { u.Path = "/site" }},
		{"raw_path", func(u *url.URL) { u.RawPath = "/" }},
		{"query", func(u *url.URL) { u.RawQuery = "next=site" }},
		{"force_query", func(u *url.URL) { u.ForceQuery = true }},
		{"user", func(u *url.URL) { u.User = url.UserPassword("dummy", "dummy") }},
		{"opaque", func(u *url.URL) { u.Opaque = "//example.com" }},
		{"fragment", func(u *url.URL) { u.Fragment = "section" }},
		{"raw_fragment", func(u *url.URL) { u.RawFragment = "section" }},
		{"omit_host", func(u *url.URL) { u.OmitHost = true }},
	}
	for _, mode := range []string{"public", "upstream"} {
		t.Run(mode, func(t *testing.T) {
			for _, tc := range mutations {
				t.Run(tc.name, func(t *testing.T) {
					upstream, public := publicOriginUnitURLs()
					selected := public
					if mode == "upstream" {
						selected = upstream
					}
					if tc.edit == nil {
						if mode == "public" {
							public = nil
						} else {
							upstream = nil
						}
					} else {
						tc.edit(selected)
					}
					handler, err := NewReverseProxyHandlerWithPublicOrigin(upstream, public, publicOriginUnitTransport())
					if err == nil || handler != nil {
						t.Fatalf("invalid %s URL accepted: handler=%T err=%v", mode, handler, err)
					}
				})
			}
		})
	}
	t.Run("public_http_forbidden", func(t *testing.T) {
		upstream, public := publicOriginUnitURLs()
		public.Scheme = "http"
		if handler, err := NewReverseProxyHandlerWithPublicOrigin(upstream, public, publicOriginUnitTransport()); err == nil || handler != nil {
			t.Fatalf("public HTTP accepted: handler=%T err=%v", handler, err)
		}
	})
	for _, tc := range []struct{ name, upstreamScheme, publicScheme, path string }{
		{"empty_root_http", "http", "https", ""},
		{"slash_root_https", "https", "https", "/"},
		{"scheme_case", "HTTP", "HTTPS", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream, public := publicOriginUnitURLs()
			upstream.Scheme, public.Scheme = tc.upstreamScheme, tc.publicScheme
			upstream.Path, public.Path = tc.path, tc.path
			if _, err := NewReverseProxyHandlerWithPublicOrigin(upstream, public, publicOriginUnitTransport()); err != nil {
				t.Fatalf("valid root origins rejected: %v", err)
			}
		})
	}
}

func TestPublicOriginConfiguredAuthorityPolicy(t *testing.T) {
	longDNS := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	valid := []struct{ authority, canonical string }{
		{"PUBLIC.Example", "public.example"}, {"PUBLIC.Example:443", "public.example"},
		{"public.example:8443", "public.example:8443"}, {"127.0.0.1:443", "127.0.0.1"},
		{"[0:0:0:0:0:0:0:1]:443", "[::1]"}, {"[2001:db8::1]:8443", "[2001:db8::1]:8443"},
		{longDNS, longDNS}, {"a-b.example", "a-b.example"},
	}
	for index, tc := range valid {
		t.Run(fmt.Sprintf("valid_%02d", index), func(t *testing.T) {
			upstream, public := publicOriginUnitURLs()
			upstream.Host = "UPSTREAM.Example:80"
			public.Host = tc.authority
			var gotHost, gotTarget string
			handler, err := NewReverseProxyHandlerWithPublicOrigin(upstream, public, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				gotHost = r.Host
				gotTarget = r.URL.Host
				return publicOriginUnitResponse(nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			request := publicOriginUnitRequest()
			request.Host = tc.authority
			request.Header.Set("Origin", "https://"+tc.authority)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK || gotHost != tc.canonical || gotTarget != "upstream.example" {
				t.Fatalf("canonical authority: status=%d got=%q want=%q fixedtarget=%q", response.Code, gotHost, tc.canonical, gotTarget)
			}
		})
	}
	invalid := []struct{ name, authority string }{
		{"empty", ""}, {"trailing_dot", "public.example."}, {"empty_label", "public..example"},
		{"leading_hyphen", "-public.example"}, {"trailing_hyphen", "public-.example"},
		{"underscore", "public_site.example"}, {"unicode", "püblic.example"},
		{"numeric_last_label", "public.123"}, {"single_decimal", "2130706433"},
		{"short_ipv4", "127.1"}, {"octal_ipv4", "0177.0.0.1"}, {"hex_alias", "0x7f000001"},
		{"hex_last_label", "public.0xdead"}, {"label_too_long", strings.Repeat("a", 64) + ".example"},
		{"dns_too_long", longDNS + "e"}, {"space", "public.example "}, {"tab", "public.example\t"},
		{"newline", "public.example\n"}, {"at", "user@public.example"}, {"slash", "public.example/path"},
		{"backslash", "public.example\\path"}, {"percent", "public%2eexample"},
		{"empty_port", "public.example:"}, {"leading_zero_port", "public.example:0443"},
		{"zero_port", "public.example:0"}, {"port_overflow", "public.example:65536"},
		{"signed_port", "public.example:+443"}, {"named_port", "public.example:https"},
		{"ipv6_unbracketed", "::1"}, {"ipv6_zone", "[fe80::1%lo0]"},
		{"bracketed_ipv4", "[127.0.0.1]"}, {"ipv6_bad_suffix", "[::1]x"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			for _, mode := range []string{"public", "upstream"} {
				upstream, public := publicOriginUnitURLs()
				if mode == "public" {
					public.Host = tc.authority
				} else {
					upstream.Host = tc.authority
				}
				if handler, err := NewReverseProxyHandlerWithPublicOrigin(upstream, public, publicOriginUnitTransport()); err == nil || handler != nil {
					t.Fatalf("invalid %s authority %q accepted", mode, tc.authority)
				}
			}
		})
	}
}

func TestPublicOriginOriginalHostGuard(t *testing.T) {
	for _, tc := range []struct {
		name, host string
		status     int
	}{
		{"exact", "public.example", 200}, {"case", "PUBLIC.EXAMPLE", 200}, {"default_port", "public.example:443", 200},
		{"foreign", "foreign.example", 421}, {"nondefault_port", "public.example:8443", 421},
		{"missing", "", 421}, {"trailing_dot", "public.example.", 421}, {"leading_zero_port", "public.example:0443", 421},
		{"whitespace", " public.example", 421}, {"userinfo", "user@public.example", 421},
		{"unbracketed_ip", "::1", 421}, {"zone", "[fe80::1%lo0]", 421},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls int
			upstream, public := publicOriginUnitURLs()
			handler, err := NewReverseProxyHandlerWithPublicOrigin(upstream, public, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				return publicOriginUnitResponse(nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			request := publicOriginUnitRequest()
			request.Host = tc.host
			request.Header.Set("X-Forwarded-Host", "public.example") // Cannot rescue a foreign original Host.
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			wantCalls := 0
			if tc.status == 200 {
				wantCalls = 1
			}
			if response.Code != tc.status || calls != wantCalls {
				t.Fatalf("status=%d calls=%d want=%d/%d", response.Code, calls, tc.status, wantCalls)
			}
		})
	}
}

func TestPublicOriginOptionsAsteriskAndPortIsolation(t *testing.T) {
	for _, tc := range []struct {
		name, authority, origin string
		status                  int
	}{
		{"ipv6_canonical_origin", "[::1]", "https://[0:0:0:0:0:0:0:1]:443", 200},
		{"nondefault_exact", "public.example:8443", "https://PUBLIC.EXAMPLE:8443", 200},
		{"nondefault_wrong_origin_port", "public.example:8443", "https://public.example:443", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream, public := publicOriginUnitURLs()
			public.Host = tc.authority
			var calls int
			handler, err := NewReverseProxyHandlerWithPublicOrigin(upstream, public, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Header.Get("Origin") != tc.origin || r.Host != tc.authority {
					t.Errorf("accepted original Origin/vhost changed: Host=%s Origin=%q", r.Host, r.Header.Get("Origin"))
				}
				return publicOriginUnitResponse(nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			request := publicOriginUnitRequest()
			request.Host = tc.authority
			request.Header.Set("Origin", tc.origin)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			wantCalls := 0
			if tc.status == 200 {
				wantCalls = 1
			}
			if response.Code != tc.status || calls != wantCalls {
				t.Fatalf("status=%d calls=%d want=%d/%d", response.Code, calls, tc.status, wantCalls)
			}
		})
	}
	for _, tc := range []struct {
		name, host string
		status     int
	}{
		{"options_public", "public.example", 200},
		{"options_foreign_host", "foreign.example", 421},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream, public := publicOriginUnitURLs()
			upstream.Path = "/"
			var calls int
			handler, err := NewReverseProxyHandlerWithPublicOrigin(upstream, public, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodOptions || r.URL.Path != "*" || r.URL.RawPath != "" ||
					r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Scheme != "http" || r.URL.Host != "upstream.example" ||
					r.Host != "public.example" || r.Header.Get("X-Forwarded-Host") != "public.example" || r.Header.Get("X-Forwarded-Proto") != "https" {
					t.Errorf("OPTIONS* route/metadata changed: request=%v URL=%s header=%v", r, r.URL, r.Header)
				}
				return publicOriginUnitResponse(nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodOptions, "*", nil)
			request.Host = tc.host
			request.Header.Set("Origin", "https://public.example")
			request.Header.Set("X-Forwarded-Host", "public.example")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			wantCalls := 0
			if tc.status == 200 {
				wantCalls = 1
			}
			if response.Code != tc.status || calls != wantCalls {
				t.Fatalf("status=%d calls=%d want=%d/%d", response.Code, calls, tc.status, wantCalls)
			}
		})
	}
}

func TestPublicOriginOriginalOriginAndNominations(t *testing.T) {
	cases := []struct {
		name   string
		header http.Header
		status int
	}{
		{"absent", http.Header{}, 200},
		{"exact", http.Header{"Origin": {"https://public.example"}}, 200},
		{"case_default_port", http.Header{"oRiGiN": {"HTTPS://PUBLIC.EXAMPLE:443"}}, 200},
		{"outer_ows", http.Header{"Origin": {" \thttps://public.example\t "}}, 200},
		{"foreign", http.Header{"Origin": {"https://foreign.example"}}, 403},
		{"null", http.Header{"Origin": {"null"}}, 403},
		{"empty", http.Header{"Origin": {""}}, 403},
		{"no_values", http.Header{"Origin": nil}, 403},
		{"multiple", http.Header{"Origin": {"https://public.example", "https://public.example"}}, 403},
		{"case_alias_multiple", http.Header{"Origin": {"https://public.example"}, "origin": {"https://public.example"}}, 403},
		{"comma_list", http.Header{"Origin": {"https://public.example, https://foreign.example"}}, 403},
		{"space_list", http.Header{"Origin": {"https://public.example https://foreign.example"}}, 403},
		{"http", http.Header{"Origin": {"http://public.example"}}, 403},
		{"slash_path", http.Header{"Origin": {"https://public.example/"}}, 403},
		{"resource_path", http.Header{"Origin": {"https://public.example/path"}}, 403},
		{"encoded_path", http.Header{"Origin": {"https://public.example/%2f"}}, 403},
		{"query", http.Header{"Origin": {"https://public.example?"}}, 403},
		{"fragment", http.Header{"Origin": {"https://public.example#"}}, 403},
		{"userinfo", http.Header{"Origin": {"https://user@public.example"}}, 403},
		{"opaque", http.Header{"Origin": {"https:public.example"}}, 403},
		{"non_ows", http.Header{"Origin": {"\u00a0https://public.example"}}, 403},
		{"newline", http.Header{"Origin": {"\nhttps://public.example"}}, 403},
		{"origin_nominated_absent", http.Header{"Connection": {"Origin"}}, 403},
		{"origin_nominated_present", http.Header{"Connection": {"keep-alive, oRiGiN"}, "Origin": {"https://public.example"}}, 403},
		{"referer_nominated_absent", http.Header{"connection": {"keep-alive, Referer"}}, 403},
		{"referer_nominated_present", http.Header{"Connection": {"\tREFERER "}, "Referer": {"https://public.example/page"}}, 403},
		{"alias_connection_nomination", http.Header{"Connection": {"keep-alive"}, "cOnNeCtIoN": {"Origin"}}, 403},
		{"ordinary_nomination", http.Header{"Connection": {"X-Hop"}, "X-Hop": {"dummy"}}, 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream, public := publicOriginUnitURLs()
			var calls int
			var observed http.Header
			handler, err := NewReverseProxyHandlerWithPublicOrigin(upstream, public, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				observed = r.Header.Clone()
				return publicOriginUnitResponse(nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			request := publicOriginUnitRequest()
			request.Header = tc.header.Clone()
			before := request.Header.Clone()
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			wantCalls := 0
			if tc.status == 200 {
				wantCalls = 1
			}
			if response.Code != tc.status || calls != wantCalls {
				t.Fatalf("status=%d calls=%d want=%d/%d", response.Code, calls, tc.status, wantCalls)
			}
			if !reflect.DeepEqual(request.Header, before) {
				t.Fatal("original inbound headers mutated")
			}
			if tc.status == 200 {
				for field, values := range tc.header {
					if strings.EqualFold(field, "Origin") && !reflect.DeepEqual(observed[field], values) {
						t.Fatalf("original Origin bytes changed: got=%q want=%q", observed[field], values)
					}
				}
				if tc.name == "ordinary_nomination" && observed.Get("X-Hop") != "" {
					t.Fatal("ordinary hop nomination survived")
				}
			}
		})
	}
}

func TestPublicOriginFixedRouteAndWebsiteMetadata(t *testing.T) {
	upstream, public := publicOriginUnitURLs()
	upstream.Scheme, upstream.Host = "https", "UPSTREAM.Example:443"
	public.Host = "PUBLIC.Example:443"
	upstreamBefore, publicBefore := *upstream, *public
	websiteHeaders := http.Header{
		"Location":            {"https://login.external.example/callback?next=%2faccount"},
		"Set-Cookie":          {"session=owned-dummy; Path=/; Secure; HttpOnly; SameSite=Strict; Future-Flag=opaque", "oauth=owned-dummy; Domain=public.example; Path=/callback; Secure; Partitioned"},
		"Authentication-Info": {"ordinary-site-proof"}, "Www-Authenticate": {"Basic realm=ordinary-site"},
		"Content-Location": {"https://upstream.example/original"},
	}
	var observed *http.Request
	handler, err := NewReverseProxyHandlerWithPublicOrigin(upstream, public, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		observed = r.Clone(r.Context())
		return publicOriginUnitResponse(websiteHeaders.Clone()), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*upstream, upstreamBefore) || !reflect.DeepEqual(*public, publicBefore) {
		t.Fatal("constructor mutated caller URL inputs")
	}
	request := publicOriginUnitRequest()
	request.Header = http.Header{
		"Origin": {"https://public.example"}, "Referer": {"https://public.example/from?verbatim=%2f"},
		"Cookie": {"session=owned-dummy; opaque=%2F"}, "X-End-To-End": {"ordinary"},
		"Forwarded": {"host=attacker.example;proto=http"}, "forwarded": {"host=other.example"},
		"X-Forwarded-Host": {"attacker.example"}, "x-forwarded-host": {"other.example"},
		"X-Forwarded-Proto": {"http"}, "x-forwarded-proto": {"ftp"},
		"X-Forwarded-For": {"192.0.2.1"}, "x-forwarded-for": {"192.0.2.2"},
		"X-Forwarded-Port": {"80"}, "X-Forwarded-Prefix": {"/attacker"}, "x-forwarded-Whatever": {"dummy"},
		"X-Real-IP": {"192.0.2.3"}, "x-real-ip": {"192.0.2.4"},
		"Authorization": {"dummy-private"}, "Proxy-Authorization": {"dummy-private"},
		"Connection": {"X-Hop, X-Forwarded-Host"}, "X-Hop": {"dummy-hop"},
	}
	request.Trailer = http.Header{
		"Forwarded": {"host=trailer-attacker.example"}, "forwarded": {"proto=http"},
		"X-Forwarded-Host": {"trailer-attacker.example"}, "x-forwarded-proto": {"http"},
		"X-Forwarded-For": {"192.0.2.5"}, "X-Forwarded-Prefix": {"/trailer"},
		"X-Real-IP": {"192.0.2.6"}, "x-real-ip": {"192.0.2.7"},
		"X-Ordinary-Trailer": {"site-trailer-verbatim"},
	}
	beforeHeader, beforeURL := request.Header.Clone(), *request.URL
	beforeTrailer := request.Trailer.Clone()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 200 || observed == nil {
		t.Fatalf("ordinary response failed: %d", response.Code)
	}
	if observed.URL.Scheme != "https" || observed.URL.Host != "upstream.example" || observed.Host != "public.example" ||
		observed.URL.EscapedPath() != "/account%2Fentry" || observed.URL.RawQuery != "next=%2f&x=1" {
		t.Fatalf("route/vhost changed: URL=%s Host=%q", observed.URL, observed.Host)
	}
	for field, values := range observed.Header {
		lower := strings.ToLower(field)
		if lower == "forwarded" || lower == "x-real-ip" || strings.HasPrefix(lower, "x-forwarded-") {
			if field == "X-Forwarded-Host" && reflect.DeepEqual(values, []string{"public.example"}) ||
				field == "X-Forwarded-Proto" && reflect.DeepEqual(values, []string{"https"}) {
				continue
			}
			t.Errorf("untrusted forwarding field survived: %s=%q", field, values)
		}
	}
	if observed.Header.Get("X-Forwarded-Host") != "public.example" || observed.Header.Get("X-Forwarded-Proto") != "https" {
		t.Fatal("fixed forwarding fields missing")
	}
	if !reflect.DeepEqual(observed.Trailer, http.Header{"X-Ordinary-Trailer": {"site-trailer-verbatim"}}) {
		t.Errorf("forwarding trailers survived or ordinary trailer changed: %v", observed.Trailer)
	}
	for _, name := range []string{"Origin", "Referer", "Cookie", "X-End-To-End"} {
		if !reflect.DeepEqual(observed.Header.Values(name), beforeHeader.Values(name)) {
			t.Errorf("ordinary %s bytes changed", name)
		}
	}
	for _, name := range []string{"Authorization", "Proxy-Authorization", "X-Hop"} {
		if observed.Header.Get(name) != "" {
			t.Errorf("unsafe %s survived", name)
		}
	}
	for name, values := range websiteHeaders {
		if !reflect.DeepEqual(response.Header().Values(name), values) {
			t.Errorf("site metadata %s changed: got=%q want=%q", name, response.Header().Values(name), values)
		}
	}
	if response.Body.String() != "ordinary-site-body" || !reflect.DeepEqual(request.Header, beforeHeader) ||
		!reflect.DeepEqual(request.Trailer, beforeTrailer) || !reflect.DeepEqual(*request.URL, beforeURL) {
		t.Fatal("body or original request changed")
	}
}

func TestPublicOriginConfigurationIsImmutableAndConcurrent(t *testing.T) {
	upstream, public := publicOriginUnitURLs()
	var calls atomic.Int32
	violations := make(chan string, 32) // At most two independent oracle failures per request.
	handler, err := NewReverseProxyHandlerWithPublicOrigin(upstream, public, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL.Host != "upstream.example" || r.URL.Scheme != "http" || r.Host != "public.example" ||
			r.Header.Get("X-Forwarded-Host") != "public.example" || r.Header.Get("X-Forwarded-Proto") != "https" ||
			r.Header.Get("Origin") != "https://public.example" {
			violations <- fmt.Sprintf("URL=%s Host=%s header=%v", r.URL, r.Host, r.Header)
		}
		return publicOriginUnitResponse(http.Header{"X-Request-Marker": {r.Header.Get("X-Request-Marker")}}), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	// Mutate only after construction, not concurrently with construction. The
	// handler must own copied policy, not read these caller objects later.
	upstream.Scheme, upstream.Host, upstream.Path, upstream.RawQuery = "https", "foreign.example", "/changed", "changed=1"
	public.Host, public.Scheme = "foreign.example", "http"
	var joined sync.WaitGroup
	for index := range 16 {
		joined.Add(1)
		go func() {
			defer joined.Done()
			request := publicOriginUnitRequest()
			marker := fmt.Sprint(index)
			request.Header.Set("Origin", "https://public.example")
			request.Header.Set("X-Request-Marker", marker)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != 200 || response.Header().Get("X-Request-Marker") != marker {
				violations <- fmt.Sprintf("request=%s status=%d marker=%q", marker, response.Code, response.Header().Get("X-Request-Marker"))
			}
		}()
	}
	joined.Wait() // The fake RoundTripper performs no blocking I/O.
	close(violations)
	for failure := range violations {
		t.Error(failure)
	}
	if calls.Load() != 16 {
		t.Fatalf("calls=%d want=16", calls.Load())
	}
}

func TestPublicOriginDefaultConstructorPolicyUnchanged(t *testing.T) {
	origin := &url.URL{Scheme: "http", Host: "upstream.example", Path: "/base", RawQuery: "fixed=1"}
	var observed *http.Request
	handler, err := NewReverseProxyHandler(origin, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		observed = r.Clone(r.Context())
		return publicOriginUnitResponse(nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := handler.(*httputil.ReverseProxy); !ok {
		t.Fatalf("old constructor return type changed: %T", handler)
	}
	request := publicOriginUnitRequest()
	request.Host = "unconfigured.example"
	request.Header.Set("Origin", "https://foreign.example")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 200 || observed == nil || observed.Host != "upstream.example" ||
		observed.URL.EscapedPath() != "/base/account%2Fentry" || observed.URL.RawQuery != "fixed=1&next=%2f&x=1" ||
		observed.Header.Get("Origin") != "https://foreign.example" || observed.Header.Get("X-Forwarded-Host") != "" {
		t.Fatalf("old default/base-path policy changed: status=%d request=%v", response.Code, observed)
	}
}

func publicOriginUnitURLs() (*url.URL, *url.URL) {
	return &url.URL{Scheme: "http", Host: "upstream.example"}, &url.URL{Scheme: "https", Host: "public.example"}
}

func publicOriginUnitRequest() *http.Request {
	request := httptest.NewRequest(http.MethodGet, "https://public.example/account%2Fentry?next=%2f&x=1", nil)
	request.Host = "public.example"
	return request
}

func publicOriginUnitTransport() http.RoundTripper {
	return roundTripFunc(func(*http.Request) (*http.Response, error) { return publicOriginUnitResponse(nil), nil })
}

func publicOriginUnitResponse(header http.Header) *http.Response {
	if header == nil {
		header = make(http.Header)
	}
	return &http.Response{StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: header,
		Body: io.NopCloser(strings.NewReader("ordinary-site-body"))}
}
