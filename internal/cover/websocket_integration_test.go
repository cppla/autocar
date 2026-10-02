package cover

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const webSocketIntegrationKey = "dGhlIHNhbXBsZSBub25jZQ=="

// These tests use ordinary Go HTTP/1 sockets and complete, small RFC 6455
// frames. They do not claim browser identity or full WebSocket conformance.
func TestReverseProxyWebSocketOnWire(t *testing.T) {
	for _, caseFold := range []bool{false, true} {
		t.Run(fmt.Sprintf("case_fold_%t", caseFold), func(t *testing.T) {
			origin := newWebSocketIntegrationOrigin(t, 1, func(conn net.Conn, reader *bufio.Reader, request *http.Request) error {
				if err := webSocketIntegrationWriteUpgrade(conn, request, nil); err != nil {
					return err
				}
				if err := webSocketIntegrationWriteFrame(conn, "origin greeting", false); err != nil {
					return err
				}
				for _, want := range []string{"client payload one", "client payload two"} {
					payload, err := webSocketIntegrationReadFrame(reader, true)
					if err != nil || payload != want {
						return fmt.Errorf("masked client frame = %q/%v, want %q", payload, err, want)
					}
					if err := webSocketIntegrationWriteFrame(conn, "echo:"+payload, false); err != nil {
						return err
					}
				}
				_, err := reader.ReadByte()
				if !webSocketIntegrationPeerClosed(err) {
					return fmt.Errorf("origin peer after client close = %v", err)
				}
				return nil
			})
			front := webSocketIntegrationProxy(t, origin.url, nil)
			request := webSocketIntegrationRequest("GET", "HTTP/1.1")
			request.Header.Set("Connection", "keep-alive, Upgrade, X-Request-Hop, Authorization, Proxy-Authorization")
			request.Header.Set("X-Request-Hop", "fictional request hop")
			request.Header.Set("Keep-Alive", "timeout=5")
			request.Header.Set("Proxy-Connection", "keep-alive")
			request.Header.Set("Authorization", "Bearer fictional origin credential")
			request.Header.Set("Proxy-Authorization", "Basic fictional proxy credential")
			request.Header.Set("Origin", "https://ordinary.example")
			request.Header.Set("Cookie", "ordinary=one; other=two")
			request.Header.Set("Sec-WebSocket-Protocol", "chat, superchat")
			request.Header.Set("Sec-WebSocket-Extensions", "permessage-deflate; client_max_window_bits")
			request.Header.Set("X-End-To-End", "retained request")
			if caseFold {
				request.Header.Set("Upgrade", "\tWebSocket ")
				request.Header.Set("Connection", "Keep-Alive, uPgRaDe, X-Request-Hop, Authorization, Proxy-Authorization")
				request.Header.Set("Sec-WebSocket-Key", "\t"+webSocketIntegrationKey+" ")
				request.Header.Set("Sec-WebSocket-Version", "\t13 ")
			}
			conn, reader := webSocketIntegrationDial(t, front.addr)
			if err := webSocketIntegrationWriteRequest(conn, request); err != nil {
				t.Fatal(err)
			}
			response := webSocketIntegrationReadResponse(t, reader, request)
			if response.StatusCode != http.StatusSwitchingProtocols || response.Proto != "HTTP/1.1" {
				t.Fatalf("opening response = %s %d, want HTTP/1.1 101", response.Proto, response.StatusCode)
			}
			webSocketIntegrationAssertUpgrade(t, response.Header, webSocketIntegrationKey)
			for name, want := range map[string]string{
				"Sec-WebSocket-Protocol": "chat", "Sec-WebSocket-Extensions": "permessage-deflate",
				"Set-Cookie": "website=retained; HttpOnly", "X-End-To-End": "retained response",
			} {
				if got := response.Header.Get(name); got != want {
					t.Errorf("ordinary upgraded %s = %q, want %q", name, got, want)
				}
			}
			payload, err := webSocketIntegrationReadFrame(reader, false)
			if err != nil || payload != "origin greeting" {
				t.Fatalf("complete unmasked origin frame = %q/%v", payload, err)
			}
			for _, payload := range []string{"client payload one", "client payload two"} {
				if err := webSocketIntegrationWriteFrame(conn, payload, true); err != nil {
					t.Fatal(err)
				}
				got, err := webSocketIntegrationReadFrame(reader, false)
				if err != nil || got != "echo:"+payload {
					t.Fatalf("complete unmasked echo = %q/%v, want %q", got, err, "echo:"+payload)
				}
			}
			_ = conn.Close()
			got := webSocketIntegrationTake(t, origin.requests, "fixed-origin request")
			webSocketIntegrationAssertFixedOrigin(t, got, origin.url)
			if got.Header.Get("Connection") != "Upgrade" || got.Header.Get("Upgrade") != "websocket" {
				t.Errorf("upstream normalized pair = %v", got.Header)
			}
			webSocketIntegrationAssertScrubbed(t, got.Header, "X-Request-Hop")
			for name, want := range map[string]string{
				"Origin": "https://ordinary.example", "Cookie": "ordinary=one; other=two",
				"Sec-WebSocket-Protocol": "chat, superchat", "Sec-WebSocket-Extensions": "permessage-deflate; client_max_window_bits",
				"Sec-WebSocket-Key": webSocketIntegrationKey, "Sec-WebSocket-Version": "13", "X-End-To-End": "retained request",
			} {
				if got.Header.Get(name) != want {
					t.Errorf("upstream ordinary %s = %q, want %q", name, got.Header.Get(name), want)
				}
			}
			webSocketIntegrationAssertOriginFinished(t, origin)
			front.waitHandlers(t)
		})
	}
	t.Run("https_origin_warm_h2_then_h1_upgrade", func(t *testing.T) {
		requests := make(chan *http.Request, 3)
		result := make(chan error, 1)
		joined := make(chan struct{})
		var mu sync.Mutex
		var hijacked net.Conn
		closing := false
		var started atomic.Bool
		origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			requests <- request.Clone(context.Background())
			if request.Header.Get("Upgrade") == "" {
				_, _ = io.WriteString(w, "warm fixed website")
				return
			}
			started.Store(true)
			defer close(joined)
			conn, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				result <- err
				return
			}
			mu.Lock()
			if closing {
				mu.Unlock()
				_ = conn.Close()
				result <- net.ErrClosed
				return
			}
			hijacked = conn
			mu.Unlock()
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			err = webSocketIntegrationWriteUpgrade(conn, request, nil)
			if err == nil {
				err = webSocketIntegrationWriteFrame(conn, "secure greeting", false)
			}
			if err == nil {
				var payload string
				payload, err = webSocketIntegrationReadFrame(rw, true)
				if err == nil && payload != "secure payload" {
					err = fmt.Errorf("secure masked payload = %q", payload)
				}
				if err == nil {
					err = webSocketIntegrationWriteFrame(conn, "secure echo:"+payload, false)
				}
			}
			if err == nil {
				_, err = rw.ReadByte()
				if webSocketIntegrationPeerClosed(err) {
					err = nil
				}
			}
			result <- err
		}))
		origin.Config.ReadHeaderTimeout = time.Second
		origin.Config.ReadTimeout = 3 * time.Second
		origin.Config.WriteTimeout = 3 * time.Second
		origin.EnableHTTP2 = true
		origin.StartTLS()
		t.Cleanup(func() {
			mu.Lock()
			closing = true
			conn := hijacked
			mu.Unlock()
			if conn != nil {
				_ = conn.Close()
			}
			origin.Close()
			if started.Load() {
				webSocketIntegrationJoin(t, joined, "HTTPS origin duplex handler cleanup")
			}
		})
		target, err := url.Parse(origin.URL + "/base?operator=one")
		if err != nil {
			t.Fatal(err)
		}
		upstream := origin.Client().Transport.(*http.Transport).Clone()
		upstream.Proxy = nil
		upstream.ForceAttemptHTTP2 = true
		upstream.ResponseHeaderTimeout = time.Second
		upstream.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != target.Host {
				return nil, errors.New("HTTPS fixture refuses requester-controlled destination")
			}
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
		}
		t.Cleanup(upstream.CloseIdleConnections)
		front := webSocketIntegrationProxy(t, target, upstream)
		clientTransport := &http.Transport{Proxy: nil}
		t.Cleanup(clientTransport.CloseIdleConnections)
		client := &http.Client{Transport: clientTransport, Timeout: 2 * time.Second}
		ordinary := func() {
			t.Helper()
			response, err := client.Get("http://" + front.addr + "/socket?client=one")
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || response.StatusCode != 200 || string(body) != "warm fixed website" {
				t.Fatalf("HTTPS ordinary response = %d/%q/%v", response.StatusCode, body, err)
			}
			got := webSocketIntegrationTake(t, requests, "HTTPS ordinary origin request")
			webSocketIntegrationAssertFixedOrigin(t, got, target)
			if got.ProtoMajor != 2 {
				t.Fatalf("ordinary HTTPS origin protocol = %s, want actual H2", got.Proto)
			}
		}
		ordinary() // Keep the same upstream transport and its warm H2 pool.
		request := webSocketIntegrationRequest("GET", "HTTP/1.1")
		conn, reader := webSocketIntegrationDial(t, front.addr)
		if err := webSocketIntegrationWriteRequest(conn, request); err != nil {
			t.Fatal(err)
		}
		response := webSocketIntegrationReadResponse(t, reader, request)
		if response.StatusCode != 101 {
			t.Fatalf("HTTPS fixed-origin opening response = %d, want 101", response.StatusCode)
		}
		webSocketIntegrationAssertUpgrade(t, response.Header, webSocketIntegrationKey)
		if payload, err := webSocketIntegrationReadFrame(reader, false); err != nil || payload != "secure greeting" {
			t.Fatalf("secure unmasked greeting = %q/%v", payload, err)
		}
		if err := webSocketIntegrationWriteFrame(conn, "secure payload", true); err != nil {
			t.Fatal(err)
		}
		if payload, err := webSocketIntegrationReadFrame(reader, false); err != nil || payload != "secure echo:secure payload" {
			t.Fatalf("secure unmasked echo = %q/%v", payload, err)
		}
		got := webSocketIntegrationTake(t, requests, "HTTPS WebSocket origin request")
		webSocketIntegrationAssertFixedOrigin(t, got, target)
		if got.Proto != "HTTP/1.1" {
			t.Errorf("HTTPS WebSocket origin protocol = %s, want actual HTTP/1.1", got.Proto)
		}
		_ = conn.Close()
		if err := webSocketIntegrationTake(t, result, "HTTPS origin result before cleanup"); err != nil {
			t.Error(err)
		}
		webSocketIntegrationJoin(t, joined, "HTTPS origin duplex handler before cleanup")
		front.waitHandlers(t)
		ordinary() // WebSocket did not disable H2 for subsequent ordinary work.
	})
}

func TestReverseProxyWebSocketInvalidRequestsRemainOrdinary(t *testing.T) {
	tests := []struct {
		name string
		edit func(*http.Request)
	}{
		{"post", func(r *http.Request) { r.Method = http.MethodPost }},
		{"head", func(r *http.Request) { r.Method = http.MethodHead }},
		{"http_1_0", func(r *http.Request) { r.Proto, r.ProtoMajor, r.ProtoMinor = "HTTP/1.0", 1, 0 }},
		{"missing_upgrade", func(r *http.Request) { r.Header.Del("Upgrade") }},
		{"h2c", func(r *http.Request) { r.Header.Set("Upgrade", "h2c") }},
		{"other_upgrade", func(r *http.Request) { r.Header.Set("Upgrade", "other") }},
		{"upgrade_list", func(r *http.Request) { r.Header.Set("Upgrade", "websocket, h2c") }},
		{"duplicate_upgrade_fields", func(r *http.Request) { r.Header.Add("Upgrade", "websocket") }},
		{"missing_connection", func(r *http.Request) { r.Header.Del("Connection") }},
		{"connection_without_upgrade", func(r *http.Request) { r.Header.Set("Connection", "keep-alive") }},
		{"duplicate_connection_fields", func(r *http.Request) { r.Header.Add("Connection", "Upgrade") }},
		{"duplicate_connection_upgrade", func(r *http.Request) { r.Header.Set("Connection", "Upgrade, upgrade") }},
		{"empty_connection_token", func(r *http.Request) { r.Header.Set("Connection", "Upgrade,,keep-alive") }},
		{"connection_close", func(r *http.Request) { r.Header.Set("Connection", "Upgrade, close") }},
		{"bad_connection_token", func(r *http.Request) { r.Header.Set("Connection", "Upgrade, bad(token") }},
		{"missing_key", func(r *http.Request) { r.Header.Del("Sec-WebSocket-Key") }},
		{"duplicate_key", func(r *http.Request) { r.Header.Add("Sec-WebSocket-Key", webSocketIntegrationKey) }},
		{"malformed_key", func(r *http.Request) { r.Header.Set("Sec-WebSocket-Key", "not-base64") }},
		{"short_key", func(r *http.Request) {
			r.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString([]byte("too short")))
		}},
		{"noncanonical_key", func(r *http.Request) { r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZR==") }},
		{"unicode_key_whitespace", func(r *http.Request) { r.Header.Set("Sec-WebSocket-Key", "\u00a0"+webSocketIntegrationKey) }},
		{"missing_version", func(r *http.Request) { r.Header.Del("Sec-WebSocket-Version") }},
		{"wrong_version", func(r *http.Request) { r.Header.Set("Sec-WebSocket-Version", "12") }},
		{"duplicate_version", func(r *http.Request) { r.Header.Add("Sec-WebSocket-Version", "13") }},
		{"body", func(r *http.Request) { r.Body, r.ContentLength = io.NopCloser(strings.NewReader("x")), 1 }},
		{"chunked_body", func(r *http.Request) {
			r.Body, r.ContentLength, r.TransferEncoding = io.NopCloser(strings.NewReader("x")), -1, []string{"chunked"}
		}},
		{"nominated_key", func(r *http.Request) { r.Header.Set("Connection", "Upgrade, Sec-WebSocket-Key") }},
		{"nominated_version", func(r *http.Request) { r.Header.Set("Connection", "Upgrade, Sec-WebSocket-Version") }},
		{"nominated_protocol", func(r *http.Request) {
			r.Header.Set("Connection", "Upgrade, Sec-WebSocket-Protocol")
			r.Header.Set("Sec-WebSocket-Protocol", "chat")
		}},
		{"nominated_extensions", func(r *http.Request) {
			r.Header.Set("Connection", "Upgrade, Sec-WebSocket-Extensions")
			r.Header.Set("Sec-WebSocket-Extensions", "permessage-deflate")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			origin := newWebSocketIntegrationOrigin(t, 1, func(conn net.Conn, _ *bufio.Reader, _ *http.Request) error {
				_, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\nX-Website: ordinary\r\n\r\nordinary website")
				return err
			})
			front := webSocketIntegrationProxy(t, origin.url, nil)
			request := webSocketIntegrationRequest("GET", "HTTP/1.1")
			request.Header.Set("Authorization", "fictional auth")
			request.Header.Set("Proxy-Authorization", "fictional proxy auth")
			request.Header.Set("X-End-To-End", "retained")
			test.edit(request)
			conn, reader := webSocketIntegrationDial(t, front.addr)
			if err := webSocketIntegrationWriteRequest(conn, request); err != nil {
				t.Fatal(err)
			}
			response := webSocketIntegrationReadResponse(t, reader, request)
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			wantBody := "ordinary website"
			if request.Method == http.MethodHead {
				wantBody = ""
			}
			if response.StatusCode != http.StatusOK || string(body) != wantBody || response.Header.Get("X-Website") != "ordinary" {
				t.Fatalf("ineligible request result = %d/%q/%v, want fixed website 200/%q", response.StatusCode, body, response.Header, wantBody)
			}
			got := webSocketIntegrationTake(t, origin.requests, "ordinary fixed-origin request")
			webSocketIntegrationAssertFixedOrigin(t, got, origin.url)
			if got.Method != request.Method || got.Header.Get("Connection") != "" || got.Header.Get("Upgrade") != "" {
				t.Errorf("ineligible upstream method/upgrade = %s/%v", got.Method, got.Header)
			}
			webSocketIntegrationAssertScrubbed(t, got.Header)
			if got.Header.Get("X-End-To-End") != "retained" {
				t.Error("ordinary request header lost on ineligible upgrade")
			}
			for _, nominated := range []string{"Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions"} {
				if strings.Contains(strings.ToLower(request.Header.Get("Connection")), strings.ToLower(nominated)) && got.Header.Get(nominated) != "" {
					t.Errorf("Connection-nominated %s was resurrected: %v", nominated, got.Header)
				}
			}
			_ = conn.Close()
			webSocketIntegrationAssertOriginFinished(t, origin)
			front.waitHandlers(t)
		})
	}
	t.Run("non_ascii_upgrade_native_rejection", func(t *testing.T) {
		// This obs-text field is HTTP-parseable, but the standard ReverseProxy
		// rejects a non-printable upgrade type before its Rewrite callback.
		// Unlike the printable malformed cases above, no origin call is made.
		origin := newWebSocketIntegrationOrigin(t, 0, func(net.Conn, *bufio.Reader, *http.Request) error {
			return errors.New("unexpected non-ASCII upgrade origin call")
		})
		upstream := webSocketIntegrationNewTransport(t, origin.url)
		var calls atomic.Int32
		front := webSocketIntegrationProxy(t, origin.url, webSocketIntegrationRoundTripper(func(r *http.Request) (*http.Response, error) {
			calls.Add(1)
			return upstream.RoundTrip(r)
		}))
		request := webSocketIntegrationRequest("GET", "HTTP/1.1")
		request.Header.Set("Upgrade", "webs\u00f6cket")
		conn, reader := webSocketIntegrationDial(t, front.addr)
		if err := webSocketIntegrationWriteRequest(conn, request); err != nil {
			t.Fatal(err)
		}
		webSocketIntegrationAssertGeneric502(t, webSocketIntegrationReadResponse(t, reader, request))
		front.waitHandlers(t)
		if calls.Load() != 0 {
			t.Errorf("native non-ASCII upgrade rejection made %d origin transport calls", calls.Load())
		}
		webSocketIntegrationJoin(t, origin.joined, "unused fixed-origin worker")
	})
}

func TestReverseProxyWebSocketRejectsUnsafeSwitchingResponses(t *testing.T) {
	tests := []struct {
		name        string
		unsolicited bool
		edit        func(http.Header)
	}{
		{name: "unsolicited", unsolicited: true},
		{name: "wrong_accept", edit: func(h http.Header) { h.Set("Sec-WebSocket-Accept", "fictional private origin proof") }},
		{name: "missing_accept", edit: func(h http.Header) { h.Del("Sec-WebSocket-Accept") }},
		{name: "duplicate_accept", edit: func(h http.Header) { h.Add("Sec-WebSocket-Accept", h.Get("Sec-WebSocket-Accept")) }},
		{name: "wrong_upgrade", edit: func(h http.Header) { h.Set("Upgrade", "h2c") }},
		{name: "upgrade_list", edit: func(h http.Header) { h.Set("Upgrade", "websocket, h2c") }},
		{name: "duplicate_upgrade", edit: func(h http.Header) { h.Add("Upgrade", "websocket") }},
		{name: "missing_upgrade", edit: func(h http.Header) { h.Del("Upgrade") }},
		{name: "missing_connection", edit: func(h http.Header) { h.Del("Connection") }},
		{name: "duplicate_connection", edit: func(h http.Header) { h.Add("Connection", "Upgrade") }},
		{name: "connection_close", edit: func(h http.Header) { h.Set("Connection", "Upgrade, close") }},
		{name: "connection_duplicate_token", edit: func(h http.Header) { h.Set("Connection", "Upgrade, upgrade") }},
		{name: "connection_empty_token", edit: func(h http.Header) { h.Set("Connection", "Upgrade,") }},
		{name: "connection_bad_token", edit: func(h http.Header) { h.Set("Connection", "Upgrade, bad(token") }},
		{name: "nominated_accept", edit: func(h http.Header) { h.Set("Connection", "Upgrade, Sec-WebSocket-Accept") }},
		{name: "nominated_protocol", edit: func(h http.Header) { h.Set("Connection", "Upgrade, Sec-WebSocket-Protocol") }},
		{name: "nominated_extensions", edit: func(h http.Header) { h.Set("Connection", "Upgrade, Sec-WebSocket-Extensions") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			origin := newWebSocketIntegrationOrigin(t, 1, func(conn net.Conn, reader *bufio.Reader, request *http.Request) error {
				if err := webSocketIntegrationWriteUpgrade(conn, request, test.edit); err != nil {
					return err
				}
				_, err := reader.ReadByte()
				if !webSocketIntegrationPeerClosed(err) {
					return fmt.Errorf("rejected 101 origin peer closure before cleanup = %v", err)
				}
				return nil
			})
			upstream := webSocketIntegrationNewTransport(t, origin.url)
			closed := make(chan struct{})
			front := webSocketIntegrationProxy(t, origin.url, webSocketIntegrationRoundTripper(func(r *http.Request) (*http.Response, error) {
				response, err := upstream.RoundTrip(r)
				if err != nil {
					return nil, err
				}
				tracked := &webSocketIntegrationCloseBody{ReadCloser: response.Body, closed: closed}
				if writer, ok := response.Body.(io.Writer); ok {
					response.Body = &webSocketIntegrationDuplexBody{webSocketIntegrationCloseBody: tracked, writer: writer}
				} else {
					response.Body = tracked
				}
				return response, nil
			}))
			request := webSocketIntegrationRequest("GET", "HTTP/1.1")
			if test.unsolicited {
				request.Header.Del("Connection")
				request.Header.Del("Upgrade")
			}
			conn, reader := webSocketIntegrationDial(t, front.addr)
			if err := webSocketIntegrationWriteRequest(conn, request); err != nil {
				t.Fatal(err)
			}
			response := webSocketIntegrationReadResponse(t, reader, request)
			webSocketIntegrationAssertGeneric502(t, response)
			// Both oracles happen before any explicit test client/origin close.
			webSocketIntegrationJoin(t, closed, "original upstream Body.Close before fixture cleanup")
			webSocketIntegrationAssertOriginFinished(t, origin)
			front.waitHandlers(t)
			_ = conn.Close()
		})
	}
	for _, test := range []struct {
		name string
		edit func(*http.Response)
	}{
		{"not_duplex", func(r *http.Response) {}},
		{"nil_body", func(r *http.Response) { r.Body = nil }},
		{"http_2_response", func(r *http.Response) { r.Proto, r.ProtoMajor, r.ProtoMinor = "HTTP/2.0", 2, 0 }},
		{"unspecified_protocol", func(r *http.Response) { r.Proto, r.ProtoMajor, r.ProtoMinor = "", 0, 0 }},
		{"case_alias_duplicate_accept", func(r *http.Response) {
			r.Header["sec-websocket-accept"] = []string{r.Header.Get("Sec-WebSocket-Accept")}
		}},
		{"case_alias_duplicate_connection", func(r *http.Response) { r.Header["connection"] = []string{"Upgrade"} }},
		{"unicode_alias_accept", func(r *http.Response) {
			accept := r.Header.Get("Sec-WebSocket-Accept")
			r.Header.Del("Sec-WebSocket-Accept")
			// Unicode case folding is not HTTP field-name equivalence. Go's
			// wire serializer drops this invalid non-ASCII name, so accepting
			// it as the mandatory proof could send an unverified 101 on wire.
			r.Header["\u017fec-WebSocket-Accept"] = []string{accept}
		}},
	} {
		t.Run("custom_transport/"+test.name, func(t *testing.T) {
			body := &webSocketIntegrationCloseBody{ReadCloser: io.NopCloser(strings.NewReader("fictional private upstream body")), closed: make(chan struct{})}
			var originalBodyPresent bool
			front := webSocketIntegrationProxy(t, &url.URL{Scheme: "http", Host: "fixed-origin.invalid"}, webSocketIntegrationRoundTripper(func(r *http.Request) (*http.Response, error) {
				response := webSocketIntegrationResponse(r.Header.Get("Sec-WebSocket-Key"), body)
				if test.name != "not_duplex" && test.name != "nil_body" {
					response.Body = &webSocketIntegrationDuplexBody{webSocketIntegrationCloseBody: body, writer: io.Discard}
				}
				test.edit(response)
				originalBodyPresent = response.Body != nil
				return response, nil
			}))
			request := webSocketIntegrationRequest("GET", "HTTP/1.1")
			conn, reader := webSocketIntegrationDial(t, front.addr)
			if err := webSocketIntegrationWriteRequest(conn, request); err != nil {
				t.Fatal(err)
			}
			response := webSocketIntegrationReadResponse(t, reader, request)
			webSocketIntegrationAssertGeneric502(t, response)
			front.waitHandlers(t)
			if originalBodyPresent {
				webSocketIntegrationJoin(t, body.closed, "rejected custom upstream Body.Close before fixture cleanup")
				if body.closes.Load() != 1 {
					t.Errorf("rejected custom upstream Close calls = %d, want 1", body.closes.Load())
				}
				if body.reads.Load() != 0 {
					t.Errorf("rejected upstream body was read %d times", body.reads.Load())
				}
			}
			_ = conn.Close()
		})
	}
}

func TestReverseProxyWebSocketTransportRequestAssociation(t *testing.T) {
	for _, failure := range []string{"recorder_without_hijack", "hijack_not_supported", "hijack_other_error"} {
		t.Run(failure, func(t *testing.T) {
			body := &webSocketIntegrationCloseBody{ReadCloser: io.NopCloser(strings.NewReader("fictional private duplex bytes")), closed: make(chan struct{})}
			handler, err := NewReverseProxyHandler(&url.URL{Scheme: "http", Host: "fixed-origin.invalid"}, webSocketIntegrationRoundTripper(func(*http.Request) (*http.Response, error) {
				return webSocketIntegrationResponse(webSocketIntegrationKey, &webSocketIntegrationDuplexBody{webSocketIntegrationCloseBody: body, writer: io.Discard}), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			recorder := httptest.NewRecorder()
			var writer http.ResponseWriter = recorder
			if failure != "recorder_without_hijack" {
				hijackErr := errors.New("fictional downstream hijack failure")
				if failure == "hijack_not_supported" {
					hijackErr = http.ErrNotSupported
				}
				writer = &webSocketIntegrationHijackFailure{ResponseRecorder: recorder, err: hijackErr}
			}
			request := httptest.NewRequest("GET", "http://requester-target.invalid/socket", nil)
			request.Header = webSocketIntegrationRequest("GET", "HTTP/1.1").Header
			handler.ServeHTTP(writer, request)
			if recorder.Code != 502 || recorder.Body.String() != "Bad Gateway\n" {
				t.Errorf("failed downstream hijack = %d/%q, want generic 502", recorder.Code, recorder.Body.String())
			}
			webSocketIntegrationJoin(t, body.closed, "legal upstream 101 Close after failed Hijack before cleanup")
			if body.closes.Load() != 1 || body.reads.Load() != 0 {
				t.Errorf("failed Hijack original body calls = Close %d / Read %d, want 1 / 0", body.closes.Load(), body.reads.Load())
			}
		})
	}
	for _, responseRequest := range []string{"nil", "forged", "lowercase_fields"} {
		for _, eligible := range []bool{true, false} {
			t.Run(fmt.Sprintf("response_request_%s/eligible_%t", responseRequest, eligible), func(t *testing.T) {
				body, pipe := newWebSocketIntegrationPipe(t)
				front := webSocketIntegrationProxy(t, &url.URL{Scheme: "http", Host: "fixed-origin.invalid", Path: "/base", RawQuery: "operator=one"}, webSocketIntegrationRoundTripper(func(r *http.Request) (*http.Response, error) {
					if r.URL.Host != "fixed-origin.invalid" || r.Host != "fixed-origin.invalid" || r.URL.Path != "/base/socket" || r.URL.RawQuery != "operator=one&client=one" {
						return nil, fmt.Errorf("custom transport received requester destination: %s / %s", r.URL, r.Host)
					}
					response := webSocketIntegrationResponse(webSocketIntegrationKey, body)
					if responseRequest == "forged" {
						response.Request = webSocketIntegrationRequest("GET", "HTTP/1.1")
						response.Request.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString([]byte("different-key-16")))
					}
					if responseRequest == "lowercase_fields" {
						lowercase := make(http.Header)
						for name, values := range response.Header {
							lowercase[strings.ToLower(name)] = append([]string(nil), values...)
						}
						response.Header = lowercase
					}
					return response, nil
				}))
				request := webSocketIntegrationRequest("GET", "HTTP/1.1")
				if !eligible {
					request.Header.Del("Sec-WebSocket-Version")
				}
				conn, reader := webSocketIntegrationDial(t, front.addr)
				if err := webSocketIntegrationWriteRequest(conn, request); err != nil {
					t.Fatal(err)
				}
				response := webSocketIntegrationReadResponse(t, reader, request)
				if eligible {
					if response.StatusCode != http.StatusSwitchingProtocols {
						t.Fatalf("trusted eligible request with %s response.Request = %d, want 101", responseRequest, response.StatusCode)
					}
					webSocketIntegrationAssertUpgrade(t, response.Header, webSocketIntegrationKey)
					webSocketIntegrationExchangePipe(t, conn, reader)
					_ = conn.Close()
					if err := webSocketIntegrationTake(t, pipe.result, "custom transport duplex result"); err != nil {
						t.Error(err)
					}
				} else {
					webSocketIntegrationAssertGeneric502(t, response)
					webSocketIntegrationJoin(t, body.closed, "ineligible forged/nil response upstream close before cleanup")
					_ = conn.Close()
				}
				webSocketIntegrationJoin(t, pipe.joined, "custom transport duplex worker before cleanup")
				front.waitHandlers(t)
			})
		}
	}
	t.Run("public_synthetic_request_boundaries", func(t *testing.T) {
		for _, test := range []struct {
			name string
			edit func(*http.Request)
		}{
			{"http_2_request", func(r *http.Request) { r.Proto, r.ProtoMajor, r.ProtoMinor = "HTTP/2.0", 2, 0 }},
			{"empty_non_nil_body", func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("")) }},
			{"trailer_without_body", func(r *http.Request) { r.Trailer = http.Header{"X-End": nil} }},
			{"transfer_encoding_header", func(r *http.Request) { r.Header.Set("Transfer-Encoding", "chunked") }},
			{"case_alias_duplicate_key", func(r *http.Request) { r.Header["sec-websocket-key"] = []string{webSocketIntegrationKey} }},
			{"unicode_alias_key", func(r *http.Request) {
				r.Header.Del("Sec-WebSocket-Key")
				r.Header["\u017fec-WebSocket-Key"] = []string{webSocketIntegrationKey}
			}},
		} {
			t.Run(test.name, func(t *testing.T) {
				var calls int
				handler, err := NewReverseProxyHandler(&url.URL{Scheme: "http", Host: "fixed-origin.invalid"}, webSocketIntegrationRoundTripper(func(r *http.Request) (*http.Response, error) {
					calls++
					if r.Header.Get("Upgrade") != "" || r.Header.Get("Connection") != "" || r.URL.Host != "fixed-origin.invalid" || r.Host != "fixed-origin.invalid" {
						t.Errorf("synthetic ineligible request did not remain scrubbed fixed-origin: %v/%s/%s", r.Header, r.URL, r.Host)
					}
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ordinary"))}, nil
				}))
				if err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequest("GET", "http://requester-target.invalid/socket", nil)
				for key, values := range webSocketIntegrationRequest("GET", "HTTP/1.1").Header {
					request.Header[key] = values
				}
				test.edit(request)
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != 200 || response.Body.String() != "ordinary" || calls != 1 {
					t.Errorf("synthetic ordinary fixed-origin result = %d/%q, calls %d", response.Code, response.Body, calls)
				}
			})
		}
	})
	t.Run("concurrent_marker_isolation", func(t *testing.T) {
		var calls atomic.Int32
		ready := make(chan struct{})
		keys := map[string]string{"eligible-a": webSocketIntegrationKey, "eligible-b": "AAAAAAAAAAAAAAAAAAAAAA==", "invalid": webSocketIntegrationKey}
		bodies := make(map[string]*webSocketIntegrationDuplexBody)
		pipes := make(map[string]*webSocketIntegrationPipe)
		for _, marker := range []string{"eligible-a", "eligible-b", "invalid"} {
			bodies[marker], pipes[marker] = newWebSocketIntegrationPipe(t)
		}
		front := webSocketIntegrationProxy(t, &url.URL{Scheme: "http", Host: "fixed-origin.invalid"}, webSocketIntegrationRoundTripper(func(r *http.Request) (*http.Response, error) {
			if calls.Add(1) == 3 {
				close(ready)
			}
			select {
			case <-ready:
			case <-r.Context().Done():
				return nil, context.Cause(r.Context())
			case <-time.After(time.Second):
				return nil, errors.New("concurrent request barrier timed out")
			}
			marker := r.Header.Get("X-Marker")
			response := webSocketIntegrationResponse(keys[marker], bodies[marker])
			// Every malicious association claims a valid request with another key.
			response.Request = webSocketIntegrationRequest("GET", "HTTP/1.1")
			response.Request.Header.Set("Sec-WebSocket-Key", "AAAAAAAAAAAAAAAAAAAAAA==")
			return response, nil
		}))
		type result struct {
			marker string
			status int
			accept string
			body   string
			err    error
		}
		results := make(chan result, 3)
		joined := make(chan struct{})
		var workers sync.WaitGroup
		for _, marker := range []string{"eligible-a", "eligible-b", "invalid"} {
			conn, reader := webSocketIntegrationDial(t, front.addr)
			workerJoined := make(chan struct{})
			t.Cleanup(func() {
				_ = conn.Close()
				webSocketIntegrationJoin(t, workerJoined, "independent concurrent client worker cleanup")
			})
			workers.Add(1)
			go func() {
				defer close(workerJoined)
				defer workers.Done()
				defer conn.Close()
				request := webSocketIntegrationRequest("GET", "HTTP/1.1")
				request.Header.Set("X-Marker", marker)
				request.Header.Set("Sec-WebSocket-Key", keys[marker])
				if marker == "invalid" {
					request.Header.Del("Sec-WebSocket-Version")
				}
				got := result{marker: marker}
				if got.err = webSocketIntegrationWriteRequest(conn, request); got.err == nil {
					var response *http.Response
					response, got.err = http.ReadResponse(reader, request)
					if got.err == nil {
						got.status = response.StatusCode
						got.accept = response.Header.Get("Sec-WebSocket-Accept")
						if response.StatusCode == 101 {
							got.err = webSocketIntegrationExchangePipeError(conn, reader)
						} else {
							var body []byte
							body, got.err = io.ReadAll(response.Body)
							_ = response.Body.Close()
							got.body = string(body)
						}
					}
				}
				results <- got
			}()
		}
		go func() { defer close(joined); workers.Wait() }()
		for index := 0; index < 3; index++ {
			got := webSocketIntegrationTake(t, results, "concurrent marker result")
			wantStatus := 101
			if got.marker == "invalid" {
				wantStatus = 502
			}
			if got.err != nil || got.status != wantStatus || got.marker == "invalid" && got.body != "Bad Gateway\n" {
				t.Errorf("concurrent %s = %d/%q/%v, want %d with request-local eligibility", got.marker, got.status, got.body, got.err, wantStatus)
			}
			if got.marker != "invalid" && got.accept != webSocketIntegrationAccept(keys[got.marker]) {
				t.Errorf("concurrent %s accept = %q, want proof bound to its own key", got.marker, got.accept)
			}
		}
		webSocketIntegrationJoin(t, joined, "concurrent clients before fixture cleanup")
		for _, marker := range []string{"eligible-a", "eligible-b", "invalid"} {
			webSocketIntegrationJoin(t, bodies[marker].closed, marker+" original body close")
			webSocketIntegrationJoin(t, pipes[marker].joined, marker+" pipe worker")
		}
		front.waitHandlers(t)
	})
}

func TestReverseProxyWebSocketOrdinaryResponseControls(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusUpgradeRequired} {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			origin := newWebSocketIntegrationOrigin(t, 1, func(conn net.Conn, _ *bufio.Reader, _ *http.Request) error {
				for index, code := range []int{103, 102, 103} {
					if _, err := fmt.Fprintf(conn, "HTTP/1.1 %d Information\r\nConnection: X-Info-Hop\r\nX-Info-Hop: fictional\r\nAuthorization: fictional\r\nProxy-Authorization: fictional\r\nLink: </style-%d.css>; rel=preload\r\n\r\n", code, index); err != nil {
						return err
					}
				}
				// Do not combine this nomination oracle with Connection: close:
				// Go's native response parser deletes the entire Connection field
				// for that token before RoundTrip exposes it to the proxy. The
				// owned origin still physically closes after the complete message.
				_, err := fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nConnection: X-Final-Hop\r\nUpgrade: websocket\r\nX-Final-Hop: fictional\r\nAuthorization: fictional initial\r\nProxy-Authorization: fictional initial\r\nX-Website: retained\r\nTransfer-Encoding: chunked\r\nTrailer: X-End, Authorization, Proxy-Authorization, Connection, X-Late-Hop\r\n\r\n1\r\nx\r\n0\r\nAuthorization: fictional late\r\nProxy-Authorization: fictional late\r\nConnection: X-Late-Hop\r\nX-Late-Hop: fictional late\r\nX-End: retained trailer\r\n\r\n", status, http.StatusText(status))
				return err
			})
			front := webSocketIntegrationProxy(t, origin.url, nil)
			request := webSocketIntegrationRequest("GET", "HTTP/1.1")
			conn, reader := webSocketIntegrationDial(t, front.addr)
			if err := webSocketIntegrationWriteRequest(conn, request); err != nil {
				t.Fatal(err)
			}
			for index, want := range []int{103, 102, 103} {
				response := webSocketIntegrationReadResponse(t, reader, request)
				if response.StatusCode != want || response.Header.Get("Link") != fmt.Sprintf("</style-%d.css>; rel=preload", index) {
					t.Errorf("ordinary info response %d = %d/%v", index, response.StatusCode, response.Header)
				}
				webSocketIntegrationAssertScrubbed(t, response.Header, "Connection", "Upgrade", "X-Info-Hop")
			}
			response := webSocketIntegrationReadResponse(t, reader, request)
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || response.StatusCode != status || string(body) != "x" || response.Header.Get("X-Website") != "retained" || response.Trailer.Get("X-End") != "retained trailer" {
				t.Errorf("ordinary non-101 final = %d/%q/%v, headers=%v trailers=%v", response.StatusCode, body, err, response.Header, response.Trailer)
			}
			// Wire framing may legitimately add Transfer-Encoding or Trailer;
			// credential and Connection-nominated values may never reappear.
			for _, fields := range []http.Header{response.Header, response.Trailer} {
				for _, name := range []string{"Authorization", "Proxy-Authorization", "X-Final-Hop", "X-Late-Hop", "Upgrade"} {
					if len(fields.Values(name)) != 0 {
						t.Errorf("unsafe ordinary final/trailer %s = %v", name, fields.Values(name))
					}
				}
			}
			_ = conn.Close()
			webSocketIntegrationAssertOriginFinished(t, origin)
			front.waitHandlers(t)
		})
	}
}

type webSocketIntegrationCloseBody struct {
	io.ReadCloser
	closed chan struct{}
	once   sync.Once
	reads  atomic.Int64
	closes atomic.Int64
}

func (body *webSocketIntegrationCloseBody) Read(p []byte) (int, error) {
	body.reads.Add(1)
	return body.ReadCloser.Read(p)
}

func (body *webSocketIntegrationCloseBody) Close() error {
	body.closes.Add(1)
	err := body.ReadCloser.Close()
	body.once.Do(func() { close(body.closed) })
	return err
}

type webSocketIntegrationHijackFailure struct {
	*httptest.ResponseRecorder
	err error
}

func (writer *webSocketIntegrationHijackFailure) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, writer.err
}

type webSocketIntegrationDuplexBody struct {
	*webSocketIntegrationCloseBody
	writer io.Writer
}

func (body *webSocketIntegrationDuplexBody) Write(p []byte) (int, error) {
	return body.writer.Write(p)
}

func webSocketIntegrationResponse(key string, body io.ReadCloser) *http.Response {
	return &http.Response{StatusCode: 101, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: webSocketIntegrationUpgradeHeader(key), Body: body}
}

func webSocketIntegrationAssertGeneric502(t *testing.T, response *http.Response) {
	t.Helper()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("invalid upstream 101 result = %d/%v, want generic 502", response.StatusCode, response.Header)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || string(body) != "Bad Gateway\n" {
		t.Fatalf("generic 502 body = %q/%v", body, err)
	}
	for _, name := range []string{"Connection", "Upgrade", "Sec-WebSocket-Accept", "X-End-To-End", "Authorization", "Proxy-Authorization", "Proxy-Authenticate"} {
		if response.Header.Get(name) != "" {
			t.Errorf("upstream/private field %s escaped generic rejection: %v", name, response.Header)
		}
	}
}

type webSocketIntegrationPipe struct {
	result chan error
	joined chan struct{}
}

func newWebSocketIntegrationPipe(t *testing.T) (*webSocketIntegrationDuplexBody, *webSocketIntegrationPipe) {
	t.Helper()
	local, peer := net.Pipe()
	_ = local.SetDeadline(time.Now().Add(3 * time.Second))
	_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
	body := &webSocketIntegrationDuplexBody{webSocketIntegrationCloseBody: &webSocketIntegrationCloseBody{ReadCloser: local, closed: make(chan struct{})}, writer: local}
	pipe := &webSocketIntegrationPipe{result: make(chan error, 1), joined: make(chan struct{})}
	go func() {
		defer close(pipe.joined)
		defer peer.Close()
		reader := bufio.NewReader(peer)
		err := webSocketIntegrationWriteFrame(peer, "custom greeting", false)
		if err == nil {
			var payload string
			payload, err = webSocketIntegrationReadFrame(reader, true)
			if err == nil && payload != "custom payload" {
				err = fmt.Errorf("custom masked payload = %q", payload)
			}
			if err == nil {
				err = webSocketIntegrationWriteFrame(peer, "custom echo:"+payload, false)
			}
			if err == nil {
				_, err = reader.ReadByte()
				if webSocketIntegrationPeerClosed(err) {
					err = nil
				}
			}
		}
		pipe.result <- err
	}()
	t.Cleanup(func() {
		_ = local.Close()
		_ = peer.Close()
		webSocketIntegrationJoin(t, pipe.joined, "custom transport pipe cleanup worker")
	})
	return body, pipe
}

func webSocketIntegrationExchangePipe(t *testing.T, conn net.Conn, reader *bufio.Reader) {
	t.Helper()
	if err := webSocketIntegrationExchangePipeError(conn, reader); err != nil {
		t.Fatal(err)
	}
}

func webSocketIntegrationExchangePipeError(conn net.Conn, reader *bufio.Reader) error {
	payload, err := webSocketIntegrationReadFrame(reader, false)
	if err != nil || payload != "custom greeting" {
		return fmt.Errorf("custom unmasked greeting = %q/%v", payload, err)
	}
	if err := webSocketIntegrationWriteFrame(conn, "custom payload", true); err != nil {
		return err
	}
	payload, err = webSocketIntegrationReadFrame(reader, false)
	if err != nil || payload != "custom echo:custom payload" {
		return fmt.Errorf("custom unmasked echo = %q/%v", payload, err)
	}
	return nil
}

type webSocketIntegrationRoundTripper func(*http.Request) (*http.Response, error)

func (f webSocketIntegrationRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type webSocketIntegrationFront struct {
	addr     string
	server   *http.Server
	listener net.Listener
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	closing  bool
	handlers sync.WaitGroup
	joined   chan struct{}
	serveErr chan error
}

func webSocketIntegrationProxy(t *testing.T, origin *url.URL, transport http.RoundTripper) *webSocketIntegrationFront {
	t.Helper()
	if transport == nil {
		transport = webSocketIntegrationNewTransport(t, origin)
	}
	handler, err := NewReverseProxyHandler(origin, transport)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	front := &webSocketIntegrationFront{addr: listener.Addr().String(), listener: listener, conns: make(map[net.Conn]struct{}), joined: make(chan struct{}), serveErr: make(chan error, 1)}
	front.server = &http.Server{ReadHeaderTimeout: time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	front.server.ConnState = func(conn net.Conn, state http.ConnState) {
		front.mu.Lock()
		defer front.mu.Unlock()
		if state == http.StateNew {
			front.conns[conn] = struct{}{}
		} else if state == http.StateClosed {
			delete(front.conns, conn)
		}
	}
	front.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		front.mu.Lock()
		if front.closing {
			front.mu.Unlock()
			http.Error(w, "closing", http.StatusServiceUnavailable)
			return
		}
		front.handlers.Add(1)
		front.mu.Unlock()
		defer front.handlers.Done()
		handler.ServeHTTP(w, r)
	})
	go func() {
		defer close(front.joined)
		front.serveErr <- front.server.Serve(listener)
	}()
	t.Cleanup(func() {
		front.mu.Lock()
		front.closing = true
		var sockets []net.Conn
		for conn := range front.conns {
			sockets = append(sockets, conn)
		}
		front.mu.Unlock()
		_ = listener.Close()
		_ = front.server.Close()
		for _, conn := range sockets {
			_ = conn.Close()
		}
		webSocketIntegrationJoin(t, front.joined, "front Serve worker")
		front.waitHandlers(t)
	})
	return front
}

func webSocketIntegrationNewTransport(t *testing.T, origin *url.URL) *http.Transport {
	t.Helper()
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != origin.Host {
			return nil, errors.New("test refuses requester-controlled destination")
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
	}, ResponseHeaderTimeout: time.Second, IdleConnTimeout: time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	return transport
}

func (front *webSocketIntegrationFront) waitHandlers(t *testing.T) {
	t.Helper()
	joined := make(chan struct{})
	go func() { defer close(joined); front.handlers.Wait() }()
	webSocketIntegrationJoin(t, joined, "front cover handlers")
}

type webSocketIntegrationOrigin struct {
	url      *url.URL
	requests chan *http.Request
	results  chan error
	joined   chan struct{}
}

func newWebSocketIntegrationOrigin(t *testing.T, attempts int, serve func(net.Conn, *bufio.Reader, *http.Request) error) *webSocketIntegrationOrigin {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
	originURL, err := url.Parse("http://" + listener.Addr().String() + "/base?operator=one")
	if err != nil {
		t.Fatal(err)
	}
	origin := &webSocketIntegrationOrigin{url: originURL, requests: make(chan *http.Request, attempts), results: make(chan error, attempts), joined: make(chan struct{})}
	var mu sync.Mutex
	var sockets []net.Conn
	closing := false
	go func() {
		defer close(origin.joined)
		var workers sync.WaitGroup
		defer workers.Wait()
		for attempt := 0; attempt < attempts; attempt++ {
			conn, err := listener.Accept()
			if err != nil {
				origin.results <- err
				return
			}
			mu.Lock()
			if closing {
				mu.Unlock()
				_ = conn.Close()
				origin.results <- net.ErrClosed
				return
			}
			sockets = append(sockets, conn)
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				reader := bufio.NewReader(conn)
				request, err := http.ReadRequest(reader)
				if err != nil {
					origin.results <- err
					return
				}
				if _, err := io.Copy(io.Discard, request.Body); err != nil {
					origin.results <- err
					return
				}
				_ = request.Body.Close()
				origin.requests <- request.Clone(context.Background())
				origin.results <- serve(conn, reader, request)
			}()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		closing = true
		owned := append([]net.Conn(nil), sockets...)
		mu.Unlock()
		_ = listener.Close()
		for _, conn := range owned {
			_ = conn.Close()
		}
		webSocketIntegrationJoin(t, origin.joined, "origin accept/frame workers")
	})
	return origin
}

func webSocketIntegrationRequest(method, protocol string) *http.Request {
	request := &http.Request{Method: method, Proto: protocol, ProtoMajor: 1, ProtoMinor: 1,
		URL:  &url.URL{Scheme: "http", Host: "requester-target.invalid:9876", Path: "/socket", RawQuery: "client=one"},
		Host: "requester-host.invalid:5432", Header: make(http.Header)}
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Sec-WebSocket-Key", webSocketIntegrationKey)
	request.Header.Set("Sec-WebSocket-Version", "13")
	request.Header.Set("Sec-WebSocket-Protocol", "chat, superchat")
	request.Header.Set("Sec-WebSocket-Extensions", "permessage-deflate; client_max_window_bits")
	return request
}

func webSocketIntegrationWriteRequest(w io.Writer, request *http.Request) error {
	var body []byte
	if request.Body != nil {
		var err error
		body, err = io.ReadAll(request.Body)
		_ = request.Body.Close()
		if err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "%s %s %s\r\nHost: %s\r\n", request.Method, request.URL.String(), request.Proto, request.Host); err != nil {
		return err
	}
	if err := request.Header.Write(w); err != nil {
		return err
	}
	if len(request.TransferEncoding) != 0 {
		if _, err := fmt.Fprintf(w, "Transfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(body), body); err != nil {
			return err
		}
		return nil
	}
	if request.ContentLength > 0 {
		if _, err := fmt.Fprintf(w, "Content-Length: %d\r\n", request.ContentLength); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "\r\n%s", body)
	return err
}

func webSocketIntegrationDial(t *testing.T, address string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	return conn, bufio.NewReader(conn)
}

func webSocketIntegrationReadResponse(t *testing.T, reader *bufio.Reader, request *http.Request) *http.Response {
	t.Helper()
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func webSocketIntegrationAccept(key string) string {
	digest := sha1.Sum([]byte(strings.Trim(key, " \t") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(digest[:])
}

func webSocketIntegrationUpgradeHeader(key string) http.Header {
	return http.Header{
		"Connection": {"Upgrade, X-Origin-Hop, Authorization, Proxy-Authorization"}, "Upgrade": {"websocket"},
		"Sec-Websocket-Accept": {webSocketIntegrationAccept(key)}, "Sec-Websocket-Protocol": {"chat"},
		"Sec-Websocket-Extensions": {"permessage-deflate"}, "Set-Cookie": {"website=retained; HttpOnly"},
		"X-End-To-End": {"retained response"}, "X-Origin-Hop": {"fictional response hop"},
		"Authorization": {"fictional origin credential"}, "Proxy-Authorization": {"fictional proxy credential"},
		"Proxy-Authenticate": {"Basic realm=fictional"}, "Keep-Alive": {"timeout=5"}, "Proxy-Connection": {"keep-alive"},
	}
}

func webSocketIntegrationWriteUpgrade(conn net.Conn, request *http.Request, edit func(http.Header)) error {
	header := webSocketIntegrationUpgradeHeader(request.Header.Get("Sec-WebSocket-Key"))
	if edit != nil {
		edit(header)
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\n"); err != nil {
		return err
	}
	if err := header.Write(conn); err != nil {
		return err
	}
	_, err := io.WriteString(conn, "\r\n")
	return err
}

func webSocketIntegrationWriteFrame(w io.Writer, payload string, masked bool) error {
	if len(payload) > 125 {
		return errors.New("fixture frame exceeds small-frame boundary")
	}
	frame := []byte{0x81, byte(len(payload))}
	data := []byte(payload)
	if masked {
		frame[1] |= 0x80
		mask := []byte{0x13, 0x37, 0x42, 0x81}
		frame = append(frame, mask...)
		for index := range data {
			data[index] ^= mask[index%4]
		}
	}
	frame = append(frame, data...)
	for len(frame) != 0 {
		n, err := w.Write(frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}

func webSocketIntegrationReadFrame(r io.Reader, wantMasked bool) (string, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return "", err
	}
	if header[0] != 0x81 || (header[1]&0x80 != 0) != wantMasked || header[1]&0x7f > 125 {
		return "", fmt.Errorf("unexpected complete frame header %x, want masked=%t", header, wantMasked)
	}
	var mask [4]byte
	if wantMasked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return "", err
		}
	}
	payload := make([]byte, int(header[1]&0x7f))
	if _, err := io.ReadFull(r, payload); err != nil {
		return "", err
	}
	if wantMasked {
		for index := range payload {
			payload[index] ^= mask[index%4]
		}
	}
	return string(payload), nil
}

func webSocketIntegrationAssertFixedOrigin(t *testing.T, request *http.Request, target *url.URL) {
	t.Helper()
	if request.Host != target.Host || request.URL.Path != "/base/socket" || request.URL.RawQuery != "operator=one&client=one" {
		t.Errorf("fixed upstream Host/path/query = %q/%q/%q, want %q/base/socket?operator=one&client=one", request.Host, request.URL.Path, request.URL.RawQuery, target.Host)
	}
}

func webSocketIntegrationAssertUpgrade(t *testing.T, header http.Header, key string) {
	t.Helper()
	if !reflect.DeepEqual(header.Values("Connection"), []string{"Upgrade"}) || !reflect.DeepEqual(header.Values("Upgrade"), []string{"websocket"}) || !reflect.DeepEqual(header.Values("Sec-WebSocket-Accept"), []string{webSocketIntegrationAccept(key)}) {
		t.Errorf("normalized verified upgrade response = %v", header)
	}
	webSocketIntegrationAssertScrubbed(t, header, "X-Origin-Hop")
}

func webSocketIntegrationAssertScrubbed(t *testing.T, header http.Header, extra ...string) {
	t.Helper()
	for _, name := range append([]string{"Authorization", "Proxy-Authorization", "Proxy-Authenticate", "Proxy-Connection", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding"}, extra...) {
		if values := header.Values(name); len(values) != 0 {
			t.Errorf("unsafe %s survived: %v", name, values)
		}
	}
}

func webSocketIntegrationPeerClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET)
}

func webSocketIntegrationTake[T any](t *testing.T, channel <-chan T, name string) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
		var zero T
		return zero
	}
}

func webSocketIntegrationJoin(t *testing.T, joined <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-joined:
	case <-time.After(2 * time.Second):
		t.Errorf("%s did not independently join", name)
	}
}

func webSocketIntegrationAssertOriginFinished(t *testing.T, origin *webSocketIntegrationOrigin) {
	t.Helper()
	if err := webSocketIntegrationTake(t, origin.results, "origin result before fixture cleanup"); err != nil {
		t.Errorf("origin worker result = %v", err)
	}
	webSocketIntegrationJoin(t, origin.joined, "origin before fixture cleanup")
}
