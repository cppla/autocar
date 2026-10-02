package cover

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const websocketUnitKey = "dGhlIHNhbXBsZSBub25jZQ=="

func websocketUnitRequest() *http.Request {
	request := httptest.NewRequest(http.MethodGet, "http://visitor.invalid/socket", nil)
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Sec-WebSocket-Version", "13")
	request.Header.Set("Sec-WebSocket-Key", websocketUnitKey)
	return request
}

func TestWebsocketRequestEligibilityStrictBoundary(t *testing.T) {
	set := func(name, value string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set(name, value) }
	}
	tests := []struct {
		name   string
		change func(*http.Request)
		want   bool
	}{
		{"valid", func(*http.Request) {}, true},
		{"nil_body", func(r *http.Request) { r.Body = nil }, true},
		{"upgrade_case", set("Upgrade", "WebSocket"), true},
		{"key_ows", set("Sec-WebSocket-Key", "\t "+websocketUnitKey+" \t"), true},
		{"version_ows", set("Sec-WebSocket-Version", " 13\t"), true},
		{"safe_nominations", set("Connection", "keep-alive, Upgrade, Authorization, Proxy-Authorization, X-Private"), true},
		{"h10", func(r *http.Request) { r.ProtoMinor = 0 }, false},
		{"h12", func(r *http.Request) { r.ProtoMinor = 2 }, false},
		{"h2", func(r *http.Request) { r.ProtoMajor, r.ProtoMinor = 2, 0 }, false},
		{"h3", func(r *http.Request) { r.ProtoMajor, r.ProtoMinor = 3, 0 }, false},
		{"post", func(r *http.Request) { r.Method = http.MethodPost }, false},
		{"connect", func(r *http.Request) { r.Method = http.MethodConnect }, false},
		{"body_even_zero_length", func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("")) }, false},
		{"positive_length", func(r *http.Request) { r.ContentLength = 1 }, false},
		{"unknown_length", func(r *http.Request) { r.ContentLength = -1 }, false},
		{"transfer_field", func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }, false},
		{"transfer_header", set("Transfer-Encoding", "chunked"), false},
		{"trailer", func(r *http.Request) { r.Trailer = http.Header{"X-Late": {"value"}} }, false},
		{"missing_upgrade", func(r *http.Request) { r.Header.Del("Upgrade") }, false},
		{"h2c", set("Upgrade", "h2c"), false},
		{"upgrade_list", set("Upgrade", "websocket, h2c"), false},
		{"duplicate_upgrade", func(r *http.Request) { r.Header.Add("Upgrade", "websocket") }, false},
		{"unicode_upgrade_fold", set("Upgrade", "webſocket"), false},
		{"missing_connection", func(r *http.Request) { r.Header.Del("Connection") }, false},
		{"connection_without_upgrade", set("Connection", "keep-alive"), false},
		{"duplicate_connection", func(r *http.Request) { r.Header.Add("Connection", "Upgrade") }, false},
		{"duplicate_token", set("Connection", "Upgrade, uPgRaDe"), false},
		{"duplicate_other_token", set("Connection", "Upgrade, X-Private, x-private"), false},
		{"close", set("Connection", "Upgrade, close"), false},
		{"empty_token", set("Connection", "Upgrade,,X-Private"), false},
		{"invalid_token", set("Connection", "Upgrade, X Private"), false},
		{"unicode_token_fold", set("Connection", "Upgrade, X-Key"), false},
		{"missing_version", func(r *http.Request) { r.Header.Del("Sec-WebSocket-Version") }, false},
		{"version12", set("Sec-WebSocket-Version", "12"), false},
		{"version_list", set("Sec-WebSocket-Version", "13, 12"), false},
		{"duplicate_version", func(r *http.Request) { r.Header.Add("Sec-WebSocket-Version", "13") }, false},
		{"missing_key", func(r *http.Request) { r.Header.Del("Sec-WebSocket-Key") }, false},
		{"key_bad_encoding", set("Sec-WebSocket-Key", "not-base64"), false},
		{"key15", set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString(make([]byte, 15))), false},
		{"key17", set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString(make([]byte, 17))), false},
		{"noncanonical_padding_bits", set("Sec-WebSocket-Key", "AAAAAAAAAAAAAAAAAAAAAB=="), false},
		{"key_embedded_newline", set("Sec-WebSocket-Key", websocketUnitKey[:8]+"\n"+websocketUnitKey[8:]), false},
		{"key_unicode_ows", set("Sec-WebSocket-Key", "\u00a0"+websocketUnitKey), false},
		{"duplicate_key", func(r *http.Request) { r.Header.Add("Sec-WebSocket-Key", websocketUnitKey) }, false},
		{"case_alias_duplicate_key", func(r *http.Request) { r.Header["sec-websocket-key"] = []string{websocketUnitKey} }, false},
		{"unicode_key_field_alias", func(r *http.Request) {
			r.Header.Del("Sec-WebSocket-Key")
			r.Header["Sec-WebSocket-Key"] = []string{websocketUnitKey}
		}, false},
	}
	for _, name := range []string{"Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Accept", "Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions"} {
		tests = append(tests, struct {
			name   string
			change func(*http.Request)
			want   bool
		}{"nominated_" + name, set("Connection", "Upgrade, "+name), false})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := websocketUnitRequest()
			test.change(request)
			info := websocketRequestEligibility(request)
			if info.eligible != test.want || test.want && info.key != websocketUnitKey {
				t.Fatalf("eligibility = %+v, want eligible=%t", info, test.want)
			}
		})
	}
	if websocketRequestEligibility(nil).eligible {
		t.Fatal("nil request was eligible")
	}
}

type websocketUnitDuplex struct {
	closes     atomic.Int64
	writes     atomic.Int64
	halfCloses atomic.Int64
}

func (*websocketUnitDuplex) Read([]byte) (int, error) { return 0, io.EOF }
func (b *websocketUnitDuplex) Write(p []byte) (int, error) {
	b.writes.Add(int64(len(p)))
	return len(p), nil
}
func (b *websocketUnitDuplex) Close() error      { b.closes.Add(1); return nil }
func (b *websocketUnitDuplex) CloseWrite() error { b.halfCloses.Add(1); return nil }

func websocketUnitAccept(key string) string {
	sum := sha1.Sum([]byte(key + websocketGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func websocketUnitResponse(request *http.Request, body io.ReadCloser) *http.Response {
	return &http.Response{
		StatusCode: http.StatusSwitchingProtocols, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Sec-Websocket-Accept": {websocketUnitAccept(websocketUnitKey)}},
		Body:   body, Request: request,
	}
}

func TestWebsocketResponseValidationAndScrubPreservesDuplex(t *testing.T) {
	request := websocketUnitRequest()
	proxyHandler, err := NewReverseProxyHandler(&url.URL{Scheme: "http", Host: "owned.invalid"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Public constructor intentionally still returns the native ReverseProxy.
	proxy, ok := proxyHandler.(*httputil.ReverseProxy)
	if !ok {
		t.Fatalf("handler type = %T", proxyHandler)
	}
	set := func(name, value string) func(*http.Response) {
		return func(r *http.Response) { r.Header.Set(name, value) }
	}
	tests := []struct {
		name   string
		change func(*http.Response)
		want   bool
	}{
		{"valid", func(*http.Response) {}, true},
		{"safe_nominations", set("Connection", "keep-alive, Upgrade, X-Private, Authorization, Proxy-Authorization"), true},
		{"without_closewrite", func(r *http.Response) {
			r.Body = struct{ io.ReadWriteCloser }{r.Body.(io.ReadWriteCloser)}
		}, true},
		{"missing_request", func(r *http.Response) { r.Request = nil }, false},
		{"untrusted_request", func(r *http.Response) { r.Request = websocketUnitRequest() }, false},
		{"h10", func(r *http.Response) { r.ProtoMinor = 0 }, false},
		{"h2", func(r *http.Response) { r.ProtoMajor = 2 }, false},
		{"nil_body", func(r *http.Response) { r.Body = nil }, false},
		{"read_only_body", func(r *http.Response) { r.Body = io.NopCloser(strings.NewReader("ordinary")) }, false},
		{"missing_accept", func(r *http.Response) { r.Header.Del("Sec-WebSocket-Accept") }, false},
		{"wrong_accept", set("Sec-WebSocket-Accept", "private origin failure"), false},
		{"duplicate_accept", func(r *http.Response) { r.Header.Add("Sec-WebSocket-Accept", websocketUnitAccept(websocketUnitKey)) }, false},
		{"accept_case_alias", func(r *http.Response) {
			r.Header["sec-websocket-accept"] = []string{websocketUnitAccept(websocketUnitKey)}
		}, false},
		{"unicode_accept_field_alias", func(r *http.Response) {
			r.Header.Del("Sec-WebSocket-Accept")
			r.Header["Sec-WebsocKet-Accept"] = []string{websocketUnitAccept(websocketUnitKey)}
		}, false},
		{"unicode_long_s_accept_field_alias", func(r *http.Response) {
			r.Header.Del("Sec-WebSocket-Accept")
			r.Header["ſec-WebSocket-Accept"] = []string{websocketUnitAccept(websocketUnitKey)}
		}, false},
		{"missing_upgrade", func(r *http.Response) { r.Header.Del("Upgrade") }, false},
		{"unrelated_upgrade", set("Upgrade", "h2c"), false},
		{"upgrade_list", set("Upgrade", "websocket, h2c"), false},
		{"missing_connection", func(r *http.Response) { r.Header.Del("Connection") }, false},
		{"close", set("Connection", "Upgrade, close"), false},
		{"duplicate_upgrade_token", set("Connection", "Upgrade, upgrade"), false},
		{"empty_token", set("Connection", "Upgrade,"), false},
		{"nominated_accept", set("Connection", "Upgrade, Sec-WebSocket-Accept"), false},
		{"nominated_protocol", set("Connection", "Upgrade, Sec-WebSocket-Protocol"), false},
		{"nominated_extensions", set("Connection", "Upgrade, Sec-WebSocket-Extensions"), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			trusted := websocketResponseRequest(withWebsocketRequestEligibility(request, websocketRequestEligibility(request)))
			body := &websocketUnitDuplex{}
			response := websocketUnitResponse(trusted, body)
			response.Header["authorization"] = []string{"private credential"}
			response.Header["proxy-authorization"] = []string{"private proxy credential"}
			response.Header["x-private"] = []string{"private hop"}
			response.Header.Set("Sec-WebSocket-Protocol", "chat")
			response.Trailer = http.Header{"connection": {"X-Late, Authorization"}, "x-late": {"private trailer"}, "authorization": {"private credential"}, "X-End-To-End": {"kept"}}
			test.change(response)
			err := proxy.ModifyResponse(response)
			if (err == nil) != test.want {
				t.Fatalf("ModifyResponse = %v, want valid=%t", err, test.want)
			}
			if !test.want {
				return // ReverseProxy, not ModifyResponse itself, owns error Close.
			}
			duplex, ok := response.Body.(io.ReadWriteCloser)
			if !ok {
				t.Fatal("duplex capability was hidden")
			}
			if n, err := duplex.Write([]byte("guarded")); err != nil || n != 7 || body.writes.Load() != 7 {
				t.Fatal("duplex Write delegation changed")
			}
			if n, err := duplex.Read(make([]byte, 1)); n != 0 || err != io.EOF {
				t.Fatal("duplex Read delegation changed")
			}
			halfClose, ok := response.Body.(interface{ CloseWrite() error })
			if ok != (test.name != "without_closewrite") {
				t.Fatal("CloseWrite capability was lost or falsely advertised")
			}
			if ok {
				if err := halfClose.CloseWrite(); err != nil || body.halfCloses.Load() != 1 {
					t.Fatal("CloseWrite delegation changed")
				}
			}
			if response.Header.Get("Connection") != "Upgrade" || response.Header.Get("Upgrade") != "websocket" || response.Header.Get("Sec-WebSocket-Protocol") != "chat" {
				t.Fatalf("normalized/safe headers = %v", response.Header)
			}
			for _, name := range []string{"Authorization", "Proxy-Authorization"} {
				if len(headerValuesFold(response.Header, name)) != 0 {
					t.Fatalf("%s leaked: %v", name, response.Header)
				}
			}
			if test.name == "safe_nominations" && len(headerValuesFold(response.Header, "X-Private")) != 0 {
				t.Fatal("nominated case alias leaked")
			}
			if len(response.Trailer) != 1 || response.Trailer.Get("X-End-To-End") != "kept" {
				t.Fatalf("unsafe trailer survived: %v", response.Trailer)
			}
			_ = duplex.Close()
			closeWebsocketResponse(trusted)
			_ = duplex.Close()
			if body.closes.Load() != 1 {
				t.Fatal("accepted body Close was not once-only")
			}
		})
	}
}

type websocketUnitHijackErrorWriter struct {
	*httptest.ResponseRecorder
	err error
}

func (w *websocketUnitHijackErrorWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, w.err
}

func TestWebsocketAccepted101OwnsPreHijackFailures(t *testing.T) {
	for _, mode := range []string{"non_hijacker", "unsupported_hijack", "other_hijack_error"} {
		t.Run(mode, func(t *testing.T) {
			body := &websocketUnitDuplex{}
			response := websocketUnitResponse(nil, body)
			handler, err := NewReverseProxyHandler(&url.URL{Scheme: "http", Host: "owned.invalid"}, roundTripFunc(func(*http.Request) (*http.Response, error) { return response, nil }))
			if err != nil {
				t.Fatal(err)
			}
			recorder := httptest.NewRecorder()
			var writer http.ResponseWriter = recorder
			if mode == "unsupported_hijack" {
				writer = &websocketUnitHijackErrorWriter{recorder, http.ErrNotSupported}
			} else if mode == "other_hijack_error" {
				writer = &websocketUnitHijackErrorWriter{recorder, errors.New("private hijack error")}
			}
			handler.ServeHTTP(writer, websocketUnitRequest())
			// Before explicit cleanup: even the early unsupported-Hijack path
			// must close the accepted original backend exactly once.
			if recorder.Code != http.StatusBadGateway || recorder.Body.String() != "Bad Gateway\n" || body.closes.Load() != 1 {
				t.Fatalf("status/body/actual Close=%d/%q/%d", recorder.Code, recorder.Body.String(), body.closes.Load())
			}
			// Generic Hijack errors install the standard cancellation closer;
			// concurrent callers still close the original backend only once.
			var wg sync.WaitGroup
			for range 12 {
				wg.Add(1)
				go func() { defer wg.Done(); _ = response.Body.Close() }()
			}
			wg.Wait()
			if body.closes.Load() != 1 {
				t.Fatal("cancellation/error cleanup double-closed the original body")
			}
		})
	}
}

type websocketUnitReadBody struct{ closes atomic.Int64 }

func (*websocketUnitReadBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b *websocketUnitReadBody) Close() error           { b.closes.Add(1); return nil }

func TestWebsocketRejected101HasGenericErrorAndOwnsBodyClose(t *testing.T) {
	for _, test := range []string{"unexpected", "wrong_accept", "nonduplex", "nil_body"} {
		t.Run(test, func(t *testing.T) {
			duplex := &websocketUnitDuplex{}
			readOnly := &websocketUnitReadBody{}
			response := websocketUnitResponse(nil, duplex)
			response.Header.Set("Authorization", "private origin credential")
			response.Header.Set("X-Private", "private origin details")
			request := websocketUnitRequest()
			switch test {
			case "unexpected":
				request.Header.Del("Upgrade")
			case "wrong_accept":
				response.Header.Set("Sec-WebSocket-Accept", "private wrong proof")
			case "nonduplex":
				response.Body = readOnly
			case "nil_body":
				response.Body = nil
			}
			handler, err := NewReverseProxyHandler(&url.URL{Scheme: "http", Host: "owned.invalid"}, roundTripFunc(func(*http.Request) (*http.Response, error) { return response, nil }))
			if err != nil {
				t.Fatal(err)
			}
			writer := httptest.NewRecorder()
			handler.ServeHTTP(writer, request)
			if writer.Code != http.StatusBadGateway || writer.Body.String() != "Bad Gateway\n" || writer.Header().Get("Authorization") != "" || writer.Header().Get("X-Private") != "" {
				t.Fatalf("private rejection leaked or status changed: %d %v %q", writer.Code, writer.Header(), writer.Body.String())
			}
			if test == "nonduplex" && readOnly.closes.Load() != 1 || test != "nonduplex" && test != "nil_body" && duplex.closes.Load() != 1 {
				t.Fatalf("upstream Close count duplex/read-only=%d/%d", duplex.closes.Load(), readOnly.closes.Load())
			}
		})
	}
}

func TestWebsocketTransportResponseProvenanceIsRequestLocal(t *testing.T) {
	const attempts = 24
	var wg sync.WaitGroup
	errorsCh := make(chan string, attempts)
	base := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		// A custom transport's Request pointer must never establish eligibility.
		forged := withWebsocketRequestEligibility(websocketUnitRequest(), websocketRequestInfo{eligible: true, key: websocketUnitKey})
		response := websocketUnitResponse(forged, &websocketUnitDuplex{})
		response.Header.Set("Sec-WebSocket-Accept", websocketUnitAccept(request.Header.Get("Sec-WebSocket-Key")))
		return response, nil
	})
	transport := &informationalHeaderTransport{base: base}
	for index := range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			request := websocketUnitRequest()
			keyBytes := make([]byte, 16)
			keyBytes[0] = byte(index)
			request.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString(keyBytes))
			if index%2 != 0 {
				request.Method = http.MethodPost
			}
			request = withWebsocketRequestEligibility(request, websocketRequestEligibility(request))
			response, err := transport.RoundTrip(request)
			if err != nil || response == nil {
				errorsCh <- "transport failed"
				return
			}
			valid := validateWebsocketResponse(response) == nil
			if valid != (index%2 == 0) {
				errorsCh <- "another request or forged Request changed eligibility"
			}
		}()
	}
	wg.Wait()
	close(errorsCh)
	for message := range errorsCh {
		t.Error(message)
	}
	ordinaryRequest := websocketUnitRequest()
	ordinary := &http.Response{StatusCode: http.StatusOK, Request: ordinaryRequest, Body: http.NoBody}
	transport.base = roundTripFunc(func(*http.Request) (*http.Response, error) { return ordinary, nil })
	response, err := transport.RoundTrip(ordinaryRequest)
	if err != nil || response.Request != ordinaryRequest {
		t.Fatal("ordinary response.Request contract changed")
	}
}

func TestWebsocketHeaderLookupUsesASCIIFieldNames(t *testing.T) {
	for _, alias := range []string{"Sec-WebsocKet-Accept", "ſec-WebSocket-Accept"} {
		t.Run(alias, func(t *testing.T) {
			if !strings.EqualFold(alias, "Sec-WebSocket-Accept") {
				t.Fatal("fixture does not exercise Unicode case folding")
			}
			header := http.Header{alias: {"invalid-field-proof"}, "X-Ordinary": {"kept"}}
			var wire bytes.Buffer
			if err := header.Write(&wire); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(wire.String(), "invalid-field-proof") || !strings.Contains(wire.String(), "X-Ordinary: kept") {
				t.Fatalf("native HTTP field-name behavior = %q", wire.String())
			}
			if _, ok := singleHeaderValue(header, "Sec-WebSocket-Accept"); ok {
				t.Fatal("a field discarded by native HTTP writing established handshake proof")
			}
			header["sec-websocket-accept"] = []string{"ascii-field-proof"}
			if value, ok := singleHeaderValue(header, "Sec-WebSocket-Accept"); !ok || value != "ascii-field-proof" {
				t.Fatal("valid ASCII field alias stopped qualifying")
			}
			deleteHeaderFold(header, "Sec-WebSocket-Accept")
			if _, exists := header["sec-websocket-accept"]; exists {
				t.Fatal("valid ASCII alias was not removed")
			}
			if _, exists := header[alias]; !exists {
				t.Fatal("deletion treated an invalid Unicode field as an ASCII alias")
			}
		})
	}
}
