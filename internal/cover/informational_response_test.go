package cover

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestReverseProxyScrubsInformationalResponsesOnWire(t *testing.T) {
	for _, protocol := range []struct {
		name string
		h2   bool
	}{
		{name: "h1"},
		{name: "h2", h2: true},
	} {
		for _, explicitFinal := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/explicit_final_%t", protocol.name, explicitFinal), func(t *testing.T) {
				statuses := []int{http.StatusEarlyHints, http.StatusProcessing, http.StatusEarlyHints}
				origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					for index, status := range statuses {
						for name, values := range informationalTestHeaders(index) {
							w.Header()[name] = values
						}
						w.WriteHeader(status)
						clear(w.Header())
					}
					w.Header().Set("Authorization", "fictional-final-origin")
					w.Header().Set("Proxy-Authorization", "fictional-final-proxy")
					w.Header().Set("Connection", "X-Final-Hop")
					w.Header().Set("X-Final-Hop", "fictional-final-hop")
					w.Header().Set("X-Final-End-To-End", "retained-final")
					w.Header().Set("Trailer", "X-End-Trailer")
					if explicitFinal {
						w.WriteHeader(http.StatusOK)
					}
					_, _ = io.WriteString(w, "ordinary cover body")
					w.Header().Set("X-End-Trailer", "retained-trailer")
				}))
				t.Cleanup(origin.Close)
				originURL, err := url.Parse(origin.URL)
				if err != nil {
					t.Fatal(err)
				}
				upstream := &http.Transport{Proxy: nil}
				t.Cleanup(upstream.CloseIdleConnections)
				handler, err := NewReverseProxyHandler(originURL, upstream)
				if err != nil {
					t.Fatal(err)
				}
				front := httptest.NewUnstartedServer(handler)
				front.EnableHTTP2 = protocol.h2
				front.StartTLS()
				t.Cleanup(front.Close)
				client := front.Client()
				client.Timeout = 3 * time.Second
				var gotStatuses []int
				var gotHeaders []http.Header
				trace := &httptrace.ClientTrace{
					Got1xxResponse: func(status int, header textproto.MIMEHeader) error {
						gotStatuses = append(gotStatuses, status)
						gotHeaders = append(gotHeaders, http.Header(header).Clone())
						return nil
					},
				}
				request, err := http.NewRequest(http.MethodGet, front.URL, nil)
				if err != nil {
					t.Fatal(err)
				}
				request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				wantMajor := 1
				if protocol.h2 {
					wantMajor = 2
				}
				if response.ProtoMajor != wantMajor || response.StatusCode != http.StatusOK || string(body) != "ordinary cover body" {
					t.Fatalf("response = %s %d %q, want HTTP/%d 200 with ordinary body", response.Proto, response.StatusCode, body, wantMajor)
				}
				if !reflect.DeepEqual(gotStatuses, statuses) {
					t.Fatalf("informational statuses = %v, want %v", gotStatuses, statuses)
				}
				for index, header := range gotHeaders {
					assertInformationalTestHeaders(t, header, index)
				}
				for _, name := range []string{"Authorization", "Proxy-Authorization", "Connection", "X-Final-Hop"} {
					if value := response.Header.Get(name); value != "" {
						t.Errorf("unsafe final %s escaped filtering: %q", name, value)
					}
				}
				if response.Header.Get("X-Final-End-To-End") != "retained-final" {
					t.Errorf("ordinary final field was lost: %v", response.Header)
				}
				if response.Trailer.Get("X-End-Trailer") != "retained-trailer" {
					t.Errorf("ordinary trailer was lost: %v", response.Trailer)
				}
			})
		}
	}
}

func TestReverseProxyInformationalTracePreservesCallerAndTransport(t *testing.T) {
	type contextKey struct{}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), contextKey{}, "caller-value"), 3*time.Second)
	t.Cleanup(cancel)
	observerError := errors.New("observer error")
	var observed []http.Header
	var statuses []int
	getConnCalls := 0
	callerTrace := &httptrace.ClientTrace{
		Got1xxResponse: func(status int, header textproto.MIMEHeader) error {
			statuses = append(statuses, status)
			observed = append(observed, http.Header(header).Clone())
			return observerError
		},
		GetConn: func(string) { getConnCalls++ },
	}
	callerContext := httptrace.WithClientTrace(ctx, callerTrace)
	var requestBody io.ReadCloser
	var gotTraces []*httptrace.ClientTrace
	transportCalls := 0
	upstream := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		transportCalls++
		if request.Body != requestBody || request.Header.Get("X-Caller") != "retained" {
			t.Error("transport wrapper changed the caller's body or headers")
		}
		if request.Context().Value(contextKey{}) != "caller-value" || request.Context().Done() != callerContext.Done() {
			t.Error("transport wrapper lost the caller's context value or cancellation")
		}
		gotDeadline, gotOK := request.Context().Deadline()
		wantDeadline, wantOK := callerContext.Deadline()
		if gotDeadline != wantDeadline || gotOK != wantOK {
			t.Error("transport wrapper changed the caller's deadline")
		}
		trace := httptrace.ContextClientTrace(request.Context())
		if trace == nil || trace.Got1xxResponse == nil {
			t.Fatal("transport did not receive an informational trace")
		}
		if trace == callerTrace {
			t.Error("transport reused the caller's trace instead of composing a request-local filter")
		}
		for _, previous := range gotTraces {
			if trace == previous {
				t.Error("transport reused a trace between requests")
			}
		}
		gotTraces = append(gotTraces, trace)
		if trace.GetConn == nil {
			t.Error("transport wrapper lost an unrelated trace hook")
		} else {
			trace.GetConn("origin.invalid:80")
		}
		header := informationalTestHeaders(transportCalls - 1)
		// A custom transport (and Go's H2 transport) can report 101 through
		// Got1xxResponse. This checks that callback boundary, rather than
		// claiming support for a legal H1 protocol upgrade.
		status := http.StatusEarlyHints
		if transportCalls == 2 {
			status = http.StatusSwitchingProtocols
		}
		if err := trace.Got1xxResponse(status, textproto.MIMEHeader(header)); !errors.Is(err, observerError) {
			t.Errorf("composed observer error = %v, want original error", err)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("transport response"))}, nil
	})
	handler, err := NewReverseProxyHandler(&url.URL{Scheme: "http", Host: "origin.invalid"}, upstream)
	if err != nil {
		t.Fatal(err)
	}
	proxy, ok := handler.(*httputil.ReverseProxy)
	if !ok {
		t.Fatalf("handler type = %T, want *httputil.ReverseProxy", handler)
	}
	for index := 0; index < 2; index++ {
		request, err := http.NewRequestWithContext(callerContext, http.MethodPost, "http://origin.invalid/", strings.NewReader("caller body"))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Caller", "retained")
		requestBody = request.Body
		response, err := proxy.Transport.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || string(body) != "transport response" {
			t.Fatalf("delegated response body/error = %q/%v", body, err)
		}
		if request.Context() != callerContext || httptrace.ContextClientTrace(request.Context()) != callerTrace {
			t.Error("transport wrapper mutated the caller's request context or trace")
		}
		if len(observed) != index+1 || getConnCalls != index+1 {
			t.Fatalf("old trace calls = informational %d / GetConn %d, want %d each", len(observed), getConnCalls, index+1)
		}
		assertInformationalTestHeaders(t, observed[index], index)
	}
	if transportCalls != 2 || !reflect.DeepEqual(statuses, []int{http.StatusEarlyHints, http.StatusSwitchingProtocols}) {
		t.Fatalf("delegated transport/statuses = %d/%v, want unchanged 103 and 101 callback events", transportCalls, statuses)
	}
	// The same caller hook remains usable independently, without an injected
	// sanitizer or a callback retained from either completed request.
	originalHeaders := informationalTestHeaders(2)
	if err := callerTrace.Got1xxResponse(http.StatusProcessing, textproto.MIMEHeader(originalHeaders)); !errors.Is(err, observerError) {
		t.Errorf("original observer error = %v, want original error", err)
	}
	if len(observed) != 3 || observed[2].Get("Authorization") != "fictional-origin-credential" || originalHeaders.Get("Authorization") != "fictional-origin-credential" {
		t.Error("transport wrapper modified the caller's original trace hook")
	}
}

func informationalTestHeaders(index int) http.Header {
	return http.Header{
		"Authorization":       {"fictional-origin-credential"},
		"Proxy-Authorization": {"fictional-proxy-credential"},
		"Connection":          {"X-Origin-Hop", "X-Other-Hop, Keep-Alive"},
		"X-Origin-Hop":        {"fictional-first-hop"},
		"X-Other-Hop":         {"fictional-other-hop"},
		"Proxy-Connection":    {"keep-alive"},
		"Keep-Alive":          {"timeout=5"},
		"Proxy-Authenticate":  {"Basic realm=fictional"},
		"Te":                  {"trailers"},
		"Trailer":             {"X-Informational-Trailer"},
		"Transfer-Encoding":   {"chunked"},
		"Upgrade":             {"fictional-protocol"},
		"Link":                {fmt.Sprintf("</style-%d.css>; rel=preload", index)},
		"X-End-To-End":        {fmt.Sprintf("retained-%d", index)},
	}
}

func assertInformationalTestHeaders(t *testing.T, header http.Header, index int) {
	t.Helper()
	for _, name := range []string{
		"Authorization", "Proxy-Authorization", "Connection", "X-Origin-Hop", "X-Other-Hop",
		"Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		if value := header.Get(name); value != "" {
			t.Errorf("informational response %d unsafe %s = %q", index, name, value)
		}
	}
	if got, want := header.Get("Link"), fmt.Sprintf("</style-%d.css>; rel=preload", index); got != want {
		t.Errorf("informational response %d Link = %q, want %q", index, got, want)
	}
	if got, want := header.Get("X-End-To-End"), fmt.Sprintf("retained-%d", index); got != want {
		t.Errorf("informational response %d end-to-end field = %q, want %q", index, got, want)
	}
}
