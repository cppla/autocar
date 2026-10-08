package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/cppla/autocar/internal/transport"
	"github.com/quic-go/qpack"
)

// The dependency's v0.63 HTTP/3 parser now follows net/http request URL
// semantics. Observe its actual wire decoder, not a hand-built Request: cover
// middleware and authentication must not rely on URL.Host or URL.Scheme being
// populated for ordinary requests or Extended CONNECT.
type webH3UpgradeRequest struct {
	method, protocol, host, scheme, urlHost, path, rawQuery, requestURI string
	credentialBytes                                                     int
	connection                                                          *quic.Conn
}

func snapshotWebH3UpgradeRequest(r *http.Request) webH3UpgradeRequest {
	connection, _ := r.Context().Value(webH3ConnectionContextKey{}).(*quic.Conn)
	return webH3UpgradeRequest{
		method: r.Method, protocol: r.Proto, host: r.Host,
		scheme: r.URL.Scheme, urlHost: r.URL.Host, path: r.URL.EscapedPath(),
		rawQuery: r.URL.RawQuery, requestURI: r.RequestURI,
		credentialBytes: len(r.Header.Get("Proxy-Authorization")), connection: connection,
	}
}

func receiveWebH3UpgradeRequest(t *testing.T, observed <-chan webH3UpgradeRequest) webH3UpgradeRequest {
	t.Helper()
	select {
	case request := <-observed:
		return request
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP/3 handler did not observe the decoded request")
		return webH3UpgradeRequest{}
	}
}

func TestWebH3UpgradeCoverRequestURLSemantics(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	observed := make(chan webH3UpgradeRequest, 1)
	var dials atomic.Int32
	server, err := ListenWebH3(WebH3ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
		Dialer: countingDialer{dials: &dials},
		Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			observed <- snapshotWebH3UpgradeRequest(r)
			w.WriteHeader(http.StatusNoContent)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	serveWebH3ForTest(t, server)
	roundTripper := &http3.Transport{TLSClientConfig: clientTLS}
	t.Cleanup(func() { _ = roundTripper.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	const path = "/news/a%2Fb"
	const query = "source=reader%2Fdaily&next=%2F"
	request := mustWebRequest(t, http.MethodGet, "https://"+server.Addr().String()+path+"?"+query, nil).WithContext(ctx)
	request.Header.Set("Proxy-Authorization", "not-a-valid-tunnel-credential")
	response, err := roundTripper.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("cover status = %d, want 204", response.StatusCode)
	}
	got := receiveWebH3UpgradeRequest(t, observed)
	if got.method != http.MethodGet || got.protocol != "HTTP/3.0" ||
		got.host != server.Addr().String() || got.scheme != "" || got.urlHost != "" ||
		got.path != path || got.rawQuery != query || got.requestURI != path+"?"+query {
		t.Fatalf("decoded cover request = %+v", got)
	}
	if got.credentialBytes != 0 {
		t.Fatal("cover handler received a tunnel credential")
	}
	if got.connection == nil || dials.Load() != 0 {
		t.Fatalf("cover QUIC connection present = %v, destination dials = %d", got.connection != nil, dials.Load())
	}
}

func TestWebH3UpgradeConnectRequestURLAndAuthSemantics(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	tcpTarget, closeTarget := startHalfCloseTarget(t)
	t.Cleanup(closeTarget)
	udpTarget := startWebUDPEcho(t)
	resolver := newWebUDPTestResolver(map[string]netip.AddrPort{udpTarget.String(): udpTarget})
	var dials, coverCalls atomic.Int32
	server, err := ListenWebH3(WebH3ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
		Dialer: countingDialer{dials: &dials}, UDPResolver: resolver,
		Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			coverCalls.Add(1)
			http.NotFound(w, r)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	observed := make(chan webH3UpgradeRequest, 2)
	handler := server.server.Handler
	server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- snapshotWebH3UpgradeRequest(r)
		handler.ServeHTTP(w, r)
	})
	serveWebH3ForTest(t, server)
	client, err := NewWebH3Client(WebH3ClientConfig{
		ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
		DialTimeout: time.Second, HandshakeTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	entropy := &webH2AuthEntropyCounter{}
	client.signer = newWebAuthSigner(mustWebAuthKey(t, webTestToken), nil, entropy)
	if err := exchange(client, tcpTarget, "upgraded H3 TCP authentication"); err != nil {
		t.Fatal(err)
	}
	tcp := receiveWebH3UpgradeRequest(t, observed)
	if tcp.method != http.MethodConnect || tcp.protocol != "HTTP/3.0" ||
		tcp.host != tcpTarget || tcp.scheme != "" || tcp.urlHost != tcpTarget ||
		tcp.path != "" || tcp.rawQuery != "" || tcp.requestURI != tcpTarget {
		t.Fatalf("decoded TCP CONNECT = %+v", tcp)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	packet, err := client.DialPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	assertWebUDPEcho(t, packet, []byte("upgraded H3 UDP authentication"), udpTarget.String())
	udp := receiveWebH3UpgradeRequest(t, observed)
	path, _, err := connectUDPPath(udpTarget.String())
	if err != nil {
		t.Fatal(err)
	}
	if udp.method != http.MethodConnect || udp.protocol != webConnectUDPProtocol ||
		udp.host != server.Addr().String() || udp.scheme != "" || udp.urlHost != "" ||
		udp.path != path || udp.rawQuery != "" || udp.requestURI != path {
		t.Fatalf("decoded CONNECT-UDP = %+v", udp)
	}
	if tcp.connection == nil || udp.connection != tcp.connection || entropy.nonceReads.Load() != 1 {
		t.Fatal("TCP and UDP did not retain one authenticated QUIC connection and one bootstrap")
	}
	if udp.credentialBytes == 0 || udp.credentialBytes >= tcp.credentialBytes {
		t.Fatal("expected a full bootstrap credential followed by a shorter continuation credential")
	}
	if dials.Load() != 1 || resolver.count(udpTarget.String()) != 1 || coverCalls.Load() != 0 {
		t.Fatalf("TCP dials / UDP resolutions / cover requests = %d / %d / %d, want 1 / 1 / 0",
			dials.Load(), resolver.count(udpTarget.String()), coverCalls.Load())
	}
}

// A malformed header block must be rejected by HTTP/3 before AutoCAR sees it,
// even when it carries a valid credential for the intended CONNECT target.
// Public QPACK and QUIC APIs preserve the invalid fields that net/http would
// otherwise normalize before transmission.
func TestWebH3UpgradeRejectsMalformedHeadersBeforeHandler(t *testing.T) {
	const target = "127.0.0.1:9"
	for _, test := range []struct {
		name   string
		fields []qpack.HeaderField
	}{
		{"duplicate_empty_authority", []qpack.HeaderField{
			{Name: ":method", Value: "CONNECT"}, {Name: ":authority", Value: ""}, {Name: ":authority", Value: target},
		}},
		{"duplicate_method", []qpack.HeaderField{
			{Name: ":method", Value: "CONNECT"}, {Name: ":method", Value: "CONNECT"}, {Name: ":authority", Value: target},
		}},
		{"authority_host_conflict", []qpack.HeaderField{
			{Name: ":method", Value: "CONNECT"}, {Name: ":authority", Value: target}, {Name: "host", Value: "other.invalid:9"},
		}},
		{"connect_empty_scheme", []qpack.HeaderField{
			{Name: ":method", Value: "CONNECT"}, {Name: ":authority", Value: target}, {Name: ":scheme", Value: ""},
		}},
		{"connect_host_without_authority", []qpack.HeaderField{
			{Name: ":method", Value: "CONNECT"}, {Name: "host", Value: target},
		}},
		{"pseudo_after_regular", []qpack.HeaderField{
			{Name: ":method", Value: "CONNECT"}, {Name: "user-agent", Value: "test"}, {Name: ":authority", Value: target},
		}},
		{"absolute_request_path", []qpack.HeaderField{
			{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: target}, {Name: ":path", Value: "https://other.invalid/news"},
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			serverTLS, clientTLS := testTLSConfigs(t)
			var handlerCalls, dials, coverCalls atomic.Int32
			server, err := ListenWebH3(WebH3ServerConfig{
				Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
				Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
					dials.Add(1)
					return nil, errors.New("destination must not be dialed")
				}),
				Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					coverCalls.Add(1)
					w.WriteHeader(http.StatusNoContent)
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			handler := server.server.Handler
			server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalls.Add(1)
				handler.ServeHTTP(w, r)
			})
			serveWebH3ForTest(t, server)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			clientTLS.NextProtos = []string{http3.NextProtoH3}
			connection, err := quic.DialAddr(ctx, server.Addr().String(), clientTLS, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = connection.CloseWithError(0, "") })
			h3Transport := &http3.Transport{}
			t.Cleanup(func() { _ = h3Transport.Close() })
			h3Client := h3Transport.NewClientConn(connection)
			stream, err := connection.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
			defer stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
			defer stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
			binding := webAuthBinding{transport: webAuthTransportH3, method: http.MethodConnect, authority: target}
			credential, err := newWebAuthSigner(mustWebAuthKey(t, webTestToken), nil, nil).bearer(binding, webAuthClaims{})
			if err != nil {
				t.Fatal(err)
			}
			var headers bytes.Buffer
			encoder := qpack.NewEncoder(&headers)
			for _, field := range test.fields {
				if err := encoder.WriteField(field); err != nil {
					t.Fatal(err)
				}
			}
			if err := encoder.WriteField(qpack.HeaderField{Name: "proxy-authorization", Value: credential}); err != nil {
				t.Fatal(err)
			}
			if err := encoder.Close(); err != nil {
				t.Fatal(err)
			}
			frame := quicvarint.Append(nil, 1) // HEADERS frame, RFC 9114 section 7.2.2.
			frame = quicvarint.Append(frame, uint64(headers.Len()))
			frame = append(frame, headers.Bytes()...)
			if _, err := stream.Write(frame); err != nil {
				t.Fatal(err)
			}
			_ = stream.Close()
			_, err = stream.Read(make([]byte, 1))
			var streamErr *quic.StreamError
			if !errors.As(err, &streamErr) || !streamErr.Remote || streamErr.ErrorCode != quic.StreamErrorCode(http3.ErrCodeMessageError) {
				t.Fatalf("malformed request error = %v, want remote H3_MESSAGE_ERROR", err)
			}
			if handlerCalls.Load() != 0 || coverCalls.Load() != 0 || dials.Load() != 0 {
				t.Fatalf("malformed request reached handler / cover / destination = %d / %d / %d",
					handlerCalls.Load(), coverCalls.Load(), dials.Load())
			}
			// A stream-local rejection must leave the same physical connection
			// usable for an ordinary cover request, not silently poison it.
			request := mustWebRequest(t, http.MethodGet, "https://"+server.Addr().String()+"/healthy", nil).WithContext(ctx)
			response, err := h3Client.RoundTrip(request)
			if err != nil {
				t.Fatalf("cover request after rejected stream: %v", err)
			}
			_, readErr := io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if readErr != nil || response.StatusCode != http.StatusNoContent || handlerCalls.Load() != 1 || coverCalls.Load() != 1 || dials.Load() != 0 {
				t.Fatalf("healthy follow-up status / read error / handler / cover / dials = %d / %v / %d / %d / %d",
					response.StatusCode, readErr, handlerCalls.Load(), coverCalls.Load(), dials.Load())
			}
		})
	}
}
