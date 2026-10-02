package cover

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"strings"
	"testing"
)

const metadataPolicyProofHeader = "Proxy-Authentication-Info"

func metadataPolicyHeaders() http.Header {
	header := make(http.Header)
	header.Set(metadataPolicyProofHeader, "nextnonce=fictional-origin-proof")
	header["proxy-authentication-info"] = []string{"nextnonce=fictional-case-alias"}
	header.Set("Authentication-Info", "nextnonce=ordinary-website-auth")
	header.Set("WWW-Authenticate", "Basic realm=ordinary-website")
	header.Set("X-End", "retained")
	return header
}

func metadataPolicyAssertProofAbsent(t *testing.T, header http.Header) {
	t.Helper()
	if values := headerValuesFold(header, metadataPolicyProofHeader); len(values) != 0 {
		t.Errorf("relay-owned proof namespace survived: %v", values)
	}
}

func metadataPolicyAssertEndToEnd(t *testing.T, header http.Header) {
	t.Helper()
	for name, want := range map[string]string{
		"Authentication-Info": "nextnonce=ordinary-website-auth",
		"WWW-Authenticate":    "Basic realm=ordinary-website",
		"X-End":               "retained",
	} {
		if got := header.Get(name); got != want {
			t.Errorf("ordinary %s = %q, want %q", name, got, want)
		}
	}
}

func metadataPolicyProxy(t *testing.T, transport http.RoundTripper) *httputil.ReverseProxy {
	t.Helper()
	handler, err := NewReverseProxyHandler(&url.URL{Scheme: "https", Host: "fixed-origin.invalid:8443", Path: "/base", RawQuery: "operator=one"}, transport)
	if err != nil {
		t.Fatal(err)
	}
	proxy, ok := handler.(*httputil.ReverseProxy)
	if !ok {
		t.Fatalf("handler = %T, want native ReverseProxy", handler)
	}
	return proxy
}

func metadataPolicyPrepareResponse(t *testing.T, response *http.Response) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "https://visitor.invalid/ordinary", nil)
	response.Request = request
	proxy := metadataPolicyProxy(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response, nil
	}))
	got, err := proxy.Transport.RoundTrip(request)
	if err != nil || got != response || got.Request != request {
		t.Fatalf("ordinary response/Request identity changed: %p/%v", got, err)
	}
	// The original nominations must be captured by the transport boundary,
	// before ReverseProxy destructively filters the response Header map.
	if err := proxy.ModifyResponse(got); err != nil {
		t.Fatal(err)
	}
}

func TestCoverMetadataPolicyRelayProofNamespace(t *testing.T) {
	t.Run("helper_ascii_aliases_and_end_to_end_controls", func(t *testing.T) {
		header := metadataPolicyHeaders()
		header.Set("Connection", " X-Private, X-Key, bad(token, X-Private ")
		header.Set("X-Private", "remove")
		header.Set("X-Key", "not nominated by an invalid Unicode token")
		removeUnsafeHeaders(header)
		metadataPolicyAssertProofAbsent(t, header)
		metadataPolicyAssertEndToEnd(t, header)
		if header.Get("Connection") != "" || header.Get("X-Private") != "" || header.Get("X-Key") == "" {
			t.Errorf("valid/invalid nomination boundary changed: %v", header)
		}
	})
	t.Run("nominated_ordinary_auth_fields_still_removed", func(t *testing.T) {
		header := metadataPolicyHeaders()
		header.Set("Connection", "Authentication-Info, WWW-Authenticate")
		removeUnsafeHeaders(header)
		metadataPolicyAssertProofAbsent(t, header)
		if header.Get("Authentication-Info") != "" || header.Get("WWW-Authenticate") != "" || header.Get("X-End") != "retained" {
			t.Errorf("ordinary auth fields did not retain nomination semantics: %v", header)
		}
	})
	t.Run("rewrite_cannot_forward_relay_proof", func(t *testing.T) {
		proxy := metadataPolicyProxy(t, nil)
		request := httptest.NewRequest(http.MethodPost, "https://visitor.invalid/form?q=two", strings.NewReader("ordinary body"))
		request.Header = metadataPolicyHeaders()
		request.Header.Set("Origin", "https://visitor.invalid")
		request.Header.Set("Referer", "https://visitor.invalid/form")
		request.Header.Set("Cookie", "ordinary=retained")
		body := request.Body
		pr := &httputil.ProxyRequest{In: request, Out: request.Clone(request.Context())}
		proxy.Rewrite(pr)
		metadataPolicyAssertProofAbsent(t, pr.Out.Header)
		metadataPolicyAssertEndToEnd(t, pr.Out.Header)
		if pr.Out.Body != body || pr.Out.URL.Path != "/base/form" || pr.Out.URL.RawQuery != "operator=one&q=two" || pr.Out.Host != "fixed-origin.invalid:8443" {
			t.Errorf("ordinary fixed-origin/body behavior changed: %s / %s", pr.Out.URL, pr.Out.Host)
		}
		for name, want := range map[string]string{"Origin": "https://visitor.invalid", "Referer": "https://visitor.invalid/form", "Cookie": "ordinary=retained"} {
			if got := pr.Out.Header.Get(name); got != want {
				t.Errorf("ordinary %s changed: %q", name, got)
			}
		}
		// Rewrite must not mutate caller-owned headers.
		if len(headerValuesFold(request.Header, metadataPolicyProofHeader)) != 2 {
			t.Error("Rewrite mutated the original request metadata")
		}
	})
	t.Run("final_and_initial_trailer", func(t *testing.T) {
		response := &http.Response{StatusCode: http.StatusOK, Header: metadataPolicyHeaders(), Trailer: metadataPolicyHeaders(), Body: http.NoBody}
		modifyTrailerResponse(t, response)
		metadataPolicyAssertProofAbsent(t, response.Header)
		metadataPolicyAssertProofAbsent(t, response.Trailer)
		metadataPolicyAssertEndToEnd(t, response.Header)
		metadataPolicyAssertEndToEnd(t, response.Trailer)
		_ = response.Body.Close()
	})
}

func TestCoverMetadataPolicyInitialNominationsPersist(t *testing.T) {
	t.Run("initial_header_and_trailer_declarations", func(t *testing.T) {
		response := &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Connection": {"X-From-Header"}},
			Trailer: http.Header{
				"Connection": {"X-From-Trailer"}, "X-From-Header": nil,
				"X-From-Trailer": nil, "X-End": nil,
			},
			Body: http.NoBody,
		}
		metadataPolicyPrepareResponse(t, response)
		for _, name := range []string{"Connection", "X-From-Header", "X-From-Trailer"} {
			if len(headerValuesFold(response.Trailer, name)) != 0 || metadataPolicyHasField(response.Trailer, name) {
				t.Errorf("unsafe initial trailer declaration %s survived: %v", name, response.Trailer)
			}
		}
		if _, ok := response.Trailer["X-End"]; !ok {
			t.Error("ordinary initial trailer declaration was removed")
		}
		_ = response.Body.Close()
	})
	readFailure := errors.New("original terminal read failure")
	for _, terminal := range []struct {
		name string
		err  error
	}{{"eof", io.EOF}, {"read_error", readFailure}, {"cancellation", context.Canceled}} {
		for _, replacement := range []bool{false, true} {
			name := terminal.name + "/mutation"
			if replacement {
				name = terminal.name + "/replacement"
			}
			t.Run(name, func(t *testing.T) {
				response := &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Connection": {" X-From-Header, X-From-Header, X-Key, bad(token "}},
					Trailer:    http.Header{"Connection": {"X-From-Trailer"}, "X-End": nil},
				}
				reads, closes := 0, 0
				response.Body = &trailerTestBody{read: func(p []byte) (int, error) {
					reads++
					if reads == 1 {
						return copy(p, "first"), nil
					}
					late := metadataPolicyLateTrailers()
					if replacement {
						response.Trailer = late
					} else {
						for field, values := range late {
							response.Trailer[field] = values
						}
					}
					return copy(p, "last"), terminal.err
				}, close: func() error { closes++; return nil }}
				metadataPolicyPrepareResponse(t, response)
				if reads != 0 || closes != 0 {
					t.Fatal("ModifyResponse consumed or closed the streaming body")
				}
				// A saved policy must not alias the destructively filtered Header
				// or consult a later replacement of it.
				response.Header = http.Header{"Connection": {"X-End, Authentication-Info, WWW-Authenticate"}}
				buffer := make([]byte, 16)
				n, err := response.Body.Read(buffer)
				if n != 5 || err != nil || string(buffer[:n]) != "first" || reads != 1 {
					t.Fatalf("first streaming read = %d/%v/%q, calls=%d", n, err, buffer[:n], reads)
				}
				n, err = response.Body.Read(buffer)
				if n != 4 || err != terminal.err || string(buffer[:n]) != "last" || reads != 2 {
					t.Fatalf("terminal read changed original n/error identity: %d/%v/%q", n, err, buffer[:n])
				}
				metadataPolicyAssertLateTrailers(t, response.Trailer)
				if err := response.Body.Close(); err != nil || closes != 1 {
					t.Errorf("Close delegation = %v/%d", err, closes)
				}
			})
		}
	}
	t.Run("close_replacement_and_original_error_identity", func(t *testing.T) {
		closeFailure := errors.New("original close failure")
		response := &http.Response{
			StatusCode: http.StatusOK, Header: http.Header{"Connection": {"X-From-Header"}},
			Trailer: http.Header{"Connection": {"X-From-Trailer"}},
		}
		closes := 0
		response.Body = &trailerTestBody{close: func() error {
			closes++
			response.Trailer = metadataPolicyLateTrailers()
			return closeFailure
		}}
		metadataPolicyPrepareResponse(t, response)
		response.Header.Set("Connection", "X-End")
		for want := 1; want <= 2; want++ {
			if err := response.Body.Close(); err != closeFailure || closes != want {
				t.Fatalf("Close changed original error/call count: %v/%d", err, closes)
			}
			metadataPolicyAssertLateTrailers(t, response.Trailer)
		}
	})
}

func TestCoverMetadataPolicyInitialNominationsBeforeReverseProxyScrub(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		name := "announced_mutation"
		if replacement {
			name = "unannounced_replacement"
		}
		t.Run(name, func(t *testing.T) {
			response := &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Connection": {"X-From-Header"}},
				Trailer:    http.Header{"X-End": nil},
			}
			if !replacement {
				response.Trailer["X-From-Header"] = nil
			}
			reads, closes := 0, 0
			response.Body = &trailerTestBody{read: func(p []byte) (int, error) {
				reads++
				if reads == 1 {
					return copy(p, "ordinary website body"), nil
				}
				if replacement {
					response.Trailer = make(http.Header)
				}
				response.Trailer.Set("X-From-Header", "fictional late nominated value")
				response.Trailer.Set("X-End", "retained")
				return 0, io.EOF
			}, close: func() error { closes++; return nil }}
			proxy := metadataPolicyProxy(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				return response, nil
			}))
			writer := httptest.NewRecorder()
			proxy.ServeHTTP(writer, httptest.NewRequest(http.MethodGet, "https://visitor.invalid/ordinary", nil))
			result := writer.Result()
			defer result.Body.Close()
			body, err := io.ReadAll(result.Body)
			if err != nil || result.StatusCode != http.StatusOK || string(body) != "ordinary website body" || reads != 2 || closes != 1 {
				t.Fatalf("public response/status/body/read/close = %d/%q/%v/%d/%d", result.StatusCode, body, err, reads, closes)
			}
			if metadataPolicyHasField(result.Trailer, "X-From-Header") || metadataPolicyHasField(response.Trailer, "X-From-Header") {
				t.Errorf("original header nomination survived std hop scrub then EOF: public=%v upstream=%v", result.Trailer, response.Trailer)
			}
			if result.Trailer.Get("X-End") != "retained" {
				t.Errorf("ordinary public trailer was lost: %v", result.Trailer)
			}
		})
	}
}

func metadataPolicyHasField(header http.Header, name string) bool {
	for field := range header {
		if httpToken(field) && strings.EqualFold(field, name) {
			return true
		}
	}
	return false
}

func metadataPolicyLateTrailers() http.Header {
	header := make(http.Header)
	header.Set("X-From-Header", "fictional late header nomination")
	header["x-from-header"] = []string{"fictional late ASCII alias"}
	header.Set("X-From-Trailer", "fictional late initial trailer nomination")
	header.Set("Connection", "X-New-Hop")
	header.Set("X-New-Hop", "fictional terminal nomination")
	header.Set("X-Key", "invalid Unicode nomination must not remove this")
	header.Set("Authentication-Info", "nextnonce=ordinary-website-auth")
	header.Set("WWW-Authenticate", "Basic realm=ordinary-website")
	header.Set("X-End", "retained")
	return header
}

func metadataPolicyAssertLateTrailers(t *testing.T, header http.Header) {
	t.Helper()
	for _, name := range []string{"Connection", "X-From-Header", "X-From-Trailer", "X-New-Hop"} {
		if metadataPolicyHasField(header, name) {
			t.Errorf("initial/terminal nomination %s survived late trailers: %v", name, header)
		}
	}
	metadataPolicyAssertEndToEnd(t, header)
	if header.Get("X-Key") == "" {
		t.Error("invalid Unicode nomination removed an ordinary ASCII field")
	}
}

func TestCoverMetadataPolicyOptionsAsteriskRewrite(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*http.Request)
		star   bool
	}{
		{"h1_authority_absent_on_url", func(*http.Request) {}, true},
		{"h2_public_authority_on_url", func(r *http.Request) { r.ProtoMajor = 2; r.URL.Scheme = "https"; r.URL.Host = "visitor.invalid" }, true},
		{"h3_public_authority_on_url", func(r *http.Request) { r.ProtoMajor = 3; r.URL.Scheme = "https"; r.URL.Host = "visitor.invalid" }, true},
		{"get_is_not_options", func(r *http.Request) { r.Method = http.MethodGet }, false},
		{"post_is_not_options", func(r *http.Request) { r.Method = http.MethodPost }, false},
		{"different_request_uri", func(r *http.Request) { r.RequestURI = "/ordinary" }, false},
		{"different_path", func(r *http.Request) { r.URL.Path = "/ordinary" }, false},
		{"encoded_raw_path", func(r *http.Request) { r.URL.RawPath = "%2A" }, false},
		{"opaque_url", func(r *http.Request) { r.URL.Opaque = "*" }, false},
		{"query", func(r *http.Request) { r.URL.RawQuery = "client=two" }, false},
		{"empty_explicit_query", func(r *http.Request) { r.URL.ForceQuery = true }, false},
		{"fragment", func(r *http.Request) { r.URL.Fragment = "ordinary" }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodOptions, "https://visitor.invalid/ordinary", nil)
			request.URL = &url.URL{Path: "*"}
			request.RequestURI = "*"
			test.change(request)
			original := request.URL.String()
			proxy := metadataPolicyProxy(t, nil)
			pr := &httputil.ProxyRequest{In: request, Out: request.Clone(request.Context())}
			proxy.Rewrite(pr)
			if pr.Out.URL.Scheme != "https" || pr.Out.URL.Host != "fixed-origin.invalid:8443" || pr.Out.Host != "fixed-origin.invalid:8443" {
				t.Errorf("fixed origin authority changed: %s / %s", pr.Out.URL, pr.Out.Host)
			}
			if test.star {
				if pr.Out.URL.Path != "*" || pr.Out.URL.RawPath != "" || pr.Out.URL.Opaque != "" || pr.Out.URL.RawQuery != "" || pr.Out.URL.ForceQuery || pr.Out.URL.Fragment != "" || pr.Out.URL.RequestURI() != "*" {
					t.Errorf("server-wide OPTIONS inherited base/query or lost star: %+v, RequestURI=%q", pr.Out.URL, pr.Out.URL.RequestURI())
				}
			} else {
				// All lookalikes keep the prior normal SetURL policy. This
				// comparison does not promise their acceptance by an HTTP parser.
				ordinary := &httputil.ProxyRequest{In: request, Out: request.Clone(request.Context())}
				ordinary.SetURL(&url.URL{Scheme: "https", Host: "fixed-origin.invalid:8443", Path: "/base", RawQuery: "operator=one"})
				if pr.Out.URL.String() != ordinary.Out.URL.String() {
					t.Errorf("lookalike unexpectedly received star policy: %s, want %s", pr.Out.URL, ordinary.Out.URL)
				}
			}
			if request.URL.String() != original || request.RequestURI != pr.Out.RequestURI {
				t.Error("Rewrite mutated caller URL or unrelated request metadata")
			}
		})
	}
}

func TestCoverMetadataPolicyInformationalProofNamespace(t *testing.T) {
	var observed http.Header
	caller := &httptrace.ClientTrace{Got1xxResponse: func(_ int, header textproto.MIMEHeader) error {
		observed = http.Header(header).Clone()
		return nil
	}}
	proxy := metadataPolicyProxy(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		trace := httptrace.ContextClientTrace(request.Context())
		if trace == nil || trace.Got1xxResponse == nil {
			t.Fatal("transport did not receive the composed informational hook")
		}
		if err := trace.Got1xxResponse(http.StatusEarlyHints, textproto.MIMEHeader(metadataPolicyHeaders())); err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody}, nil
	}))
	request := httptest.NewRequest(http.MethodGet, "https://visitor.invalid/", nil)
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), caller))
	response, err := proxy.Transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if observed == nil {
		t.Fatal("existing informational observer did not run")
	}
	metadataPolicyAssertProofAbsent(t, observed)
	metadataPolicyAssertEndToEnd(t, observed)
}

func TestCoverMetadataPolicyWebsocketProofNamespace(t *testing.T) {
	var response *http.Response
	proxy := metadataPolicyProxy(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response, nil
	}))
	request := websocketUnitRequest()
	pr := &httputil.ProxyRequest{In: request, Out: request.Clone(request.Context())}
	proxy.Rewrite(pr)
	body := &websocketUnitDuplex{}
	response = websocketUnitResponse(nil, body)
	for field, values := range metadataPolicyHeaders() {
		response.Header[field] = values
	}
	got, err := proxy.Transport.RoundTrip(pr.Out)
	if err != nil || got != response {
		t.Fatalf("valid101 transport result = %p/%v", got, err)
	}
	if err := proxy.ModifyResponse(response); err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	metadataPolicyAssertProofAbsent(t, response.Header)
	metadataPolicyAssertEndToEnd(t, response.Header)
	duplex, ok := response.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatal("valid WebSocket body lost duplex I/O")
	}
	if n, err := duplex.Write([]byte("ordinary")); err != nil || n != 8 || body.writes.Load() != 8 {
		t.Errorf("valid WebSocket write delegation changed: %d/%v", n, err)
	}
	if response.Header.Get("Connection") != "Upgrade" || response.Header.Get("Upgrade") != "websocket" {
		t.Error("valid WebSocket normalized pair was lost")
	}
}
