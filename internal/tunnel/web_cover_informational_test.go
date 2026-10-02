package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/apernet/quic-go/http3"
	"github.com/cppla/autocar/internal/cover"
	"github.com/cppla/autocar/internal/transport"
)

func TestWebH3CoverFiltersInformationalResponses(t *testing.T) {
	statuses := []int{http.StatusEarlyHints, http.StatusProcessing, http.StatusEarlyHints}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Authorization") != "" {
			t.Error("request credentials reached the fixed origin")
		}
		for _, status := range statuses {
			w.Header().Set("Authorization", "fictional-origin-credential")
			w.Header().Set("Proxy-Authorization", "fictional-proxy-credential")
			w.Header().Set("Connection", "X-Origin-Hop")
			w.Header().Set("X-Origin-Hop", "fictional-hop-value")
			w.Header().Set("Link", "</ordinary.css>; rel=preload")
			w.WriteHeader(status)
			clear(w.Header())
		}
		w.Header().Set("Authorization", "fictional-final-credential")
		w.Header().Set("Trailer", "X-End-Trailer")
		_, _ = io.WriteString(w, "ordinary H3 cover")
		w.Header().Set("X-End-Trailer", "retained")
	}))
	t.Cleanup(origin.Close)
	target, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	upstream := &http.Transport{Proxy: nil}
	t.Cleanup(upstream.CloseIdleConnections)
	handler, err := cover.NewReverseProxyHandler(target, upstream)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, clientTLS := testTLSConfigs(t)
	server, err := ListenWebH3(WebH3ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS, Cover: handler,
		Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
			t.Error("ordinary cover request attempted a tunnel destination")
			return nil, errors.New("cover-only test rejects tunnel destinations")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	serverContext, stopServer := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(serverContext) }()
	t.Cleanup(func() {
		stopServer()
		_ = server.Close()
		select {
		case err := <-serverDone:
			if err != nil {
				t.Errorf("H3 cover Serve: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("H3 cover Serve did not join")
		}
	})
	clientTLS = clientTLS.Clone()
	clientTLS.NextProtos = []string{http3.NextProtoH3}
	client := &http3.Transport{TLSClientConfig: clientTLS}
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var observed []int
	trace := &httptrace.ClientTrace{
		Got1xxResponse: func(status int, header textproto.MIMEHeader) error {
			observed = append(observed, status)
			for _, name := range []string{"Authorization", "Proxy-Authorization", "Connection", "X-Origin-Hop"} {
				if value := header.Get(name); value != "" {
					t.Errorf("H3 informational %d leaked %s: %q", status, name, value)
				}
			}
			if got := header.Get("Link"); got != "</ordinary.css>; rel=preload" {
				t.Errorf("ordinary H3 hint lost: %q", got)
			}
			return nil
		},
	}
	request, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, "https://"+server.Addr().String()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "fictional-request-credential")
	request.Header.Set("Proxy-Authorization", "fictional-invalid-proxy-credential")
	response, err := client.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.ProtoMajor != 3 || response.StatusCode != http.StatusOK || string(body) != "ordinary H3 cover" {
		t.Fatalf("H3 cover = %s %d %q", response.Proto, response.StatusCode, body)
	}
	if !reflect.DeepEqual(observed, statuses) {
		t.Fatalf("H3 hints = %v, want %v", observed, statuses)
	}
	if response.Header.Get("Authorization") != "" || response.Trailer.Get("X-End-Trailer") != "retained" {
		t.Fatalf("H3 final headers/trailers = %v/%v", response.Header, response.Trailer)
	}
}
