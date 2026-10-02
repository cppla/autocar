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
	"net/url"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/cover"
	"github.com/cppla/autocar/internal/transport"
)

// Exercise the actual cover constructor through the combined server, including
// ResponseController/Unwrap, across both public TLS versions. Closing the
// server aborts upgrades; it does not negotiate a WebSocket close handshake.
func TestWebSocketCoverCombinedTLSAndOwnerClose(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, stop := range []string{"close", "serve-cancel"} {
			t.Run(fmt.Sprintf("tls%d/%s", version, stop), func(t *testing.T) {
				runCombinedWebSocketOwnerClose(t, version, stop)
			})
		}
	}
}

func runCombinedWebSocketOwnerClose(t *testing.T, version uint16, stop string) {
	t.Helper()
	origin, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	var originMu sync.Mutex
	var ownedOrigin net.Conn
	originClosed := false
	originResult := make(chan error, 1)
	originJoined := make(chan struct{})
	t.Cleanup(func() {
		_ = origin.Close()
		originMu.Lock()
		originClosed = true
		if ownedOrigin != nil {
			_ = ownedOrigin.Close()
		}
		originMu.Unlock()
		select {
		case <-originJoined:
		case <-time.After(2 * time.Second):
			t.Error("origin Accept/frame worker did not join after independent cleanup")
		}
	})
	go func() {
		defer close(originJoined)
		_ = origin.SetDeadline(time.Now().Add(3 * time.Second))
		raw, err := origin.AcceptTCP()
		if err != nil {
			originResult <- err
			return
		}
		defer raw.Close()
		originMu.Lock()
		if originClosed {
			originMu.Unlock()
			originResult <- raw.Close()
			return
		}
		ownedOrigin = raw
		originMu.Unlock()
		_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
		reader := bufio.NewReader(raw)
		request, err := http.ReadRequest(reader)
		if err != nil {
			originResult <- err
			return
		}
		_ = request.Body.Close()
		if request.Method != http.MethodGet || request.Header.Get("Upgrade") != "websocket" || request.Header.Get("Connection") != "Upgrade" || request.Header.Get("Sec-WebSocket-Key") != "dGhlIHNhbXBsZSBub25jZQ==" || request.Host != origin.Addr().String() || request.URL.Path != "/base/socket" || request.URL.RawQuery != "origin=1&client=2" || request.Header.Get("Origin") != "https://visitor.invalid" || request.Header.Get("Cookie") != "ordinary=yes" || request.Header.Get("Authorization") != "" || request.Header.Get("Proxy-Authorization") != "" || request.Header.Get("X-Remove") != "" {
			originResult <- errors.New("owned origin did not receive the expected standard handshake")
			return
		}
		if _, err := io.WriteString(raw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade, X-Origin-Hop\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nX-Site: ordinary\r\nX-Origin-Hop: do-not-forward\r\nProxy-Authenticate: private\r\nAuthorization: private\r\n\r\n"); err != nil {
			originResult <- err
			return
		}
		for range 2 {
			frame := make([]byte, 9)
			if _, err := io.ReadFull(reader, frame); err != nil {
				originResult <- err
				return
			}
			if frame[0] != 0x81 || frame[1] != 0x83 {
				originResult <- errors.New("unexpected real masked WebSocket frame")
				return
			}
			payload := make([]byte, 3)
			for i := range payload {
				payload[i] = frame[i+6] ^ frame[2+i%4]
			}
			if string(payload) != "hey" {
				originResult <- errors.New("real masked WebSocket payload was corrupted")
				return
			}
			if _, err := raw.Write(append([]byte{0x81, 0x03}, payload...)); err != nil {
				originResult <- err
				return
			}
		}
		_, err = reader.ReadByte()
		originResult <- err
	}()

	upstream := &http.Transport{Proxy: nil}
	t.Cleanup(upstream.CloseIdleConnections)
	originURL, err := url.Parse("http://" + origin.Addr().String() + "/base?origin=1")
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := cover.NewReverseProxyHandler(originURL, upstream)
	if err != nil {
		t.Fatal(err)
	}
	coverDone := make(chan struct{})
	coverContext := make(chan context.Context, 1)
	var coverStarted atomic.Bool
	website := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		coverStarted.Store(true)
		defer close(coverDone)
		coverContext <- r.Context()
		proxy.ServeHTTP(w, r)
	})
	serverTLS, clientTLS := testTLSConfigs(t)
	var destinationCalls atomic.Int64
	server, err := ListenWeb(WebServerConfig{
		TCPAddress: "127.0.0.1:0", UDPAddress: "127.0.0.1:0", Token: webTestToken,
		TLSConfig: serverTLS, Cover: website, MaxConnections: 1, MaxClientConnections: 1,
		Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
			destinationCalls.Add(1)
			return nil, errors.New("combined WebSocket test forbids every tunnel destination")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	serveResult := make(chan error, 1)
	serveJoined := make(chan struct{})
	serveCtx, cancelServe := context.WithCancel(context.Background())
	defer cancelServe()
	go func() { defer close(serveJoined); serveResult <- server.Serve(serveCtx) }()
	var client *tls.Conn
	var closeJoined chan struct{}
	t.Cleanup(func() {
		if client != nil {
			_ = client.Close()
		}
		_ = server.Close()
		workers := map[string]<-chan struct{}{"WebServer Serve worker": serveJoined}
		if closeJoined != nil {
			workers["WebServer stop worker"] = closeJoined
		}
		if coverStarted.Load() {
			workers["hijacked cover handler"] = coverDone
		}
		for name, done := range workers {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Errorf("%s did not join after independent cleanup", name)
			}
		}
	})
	clientTLS = clientTLS.Clone()
	clientTLS.NextProtos = []string{webHTTP11ALPN}
	clientTLS.MinVersion, clientTLS.MaxVersion = version, version
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", server.TCPAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	client = tls.Client(raw, clientTLS)
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if state := client.ConnectionState(); state.NegotiatedProtocol != webHTTP11ALPN || state.Version != version || len(state.VerifiedChains) == 0 {
		t.Fatal("combined WebSocket test did not use verified actual HTTP/1.1 TLS")
	}
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(client, "GET /socket?client=2 HTTP/1.1\r\nHost: requester.invalid\r\nUpgrade: websocket\r\nConnection: Upgrade, X-Remove, Proxy-Authorization\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nOrigin: https://visitor.invalid\r\nCookie: ordinary=yes\r\nAuthorization: Basic fixture-secret\r\nProxy-Authorization: Bearer fixture-ticket\r\nX-Remove: do-not-forward\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil || response.StatusCode != http.StatusSwitchingProtocols || response.Header.Get("Upgrade") != "websocket" || response.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("actual public WebSocket handshake status/error=%v/%v", response, err)
	}
	for _, header := range []string{"X-Origin-Hop", "Authorization", "Proxy-Authenticate", "Proxy-Authorization", webAuthResponseHeader} {
		if response.Header.Get(header) != "" {
			t.Fatalf("private/hop header %s reached the upgraded client", header)
		}
	}
	if response.Header.Get("Connection") != "Upgrade" || response.Header.Get("X-Site") != "ordinary" {
		t.Fatal("safe upgraded response fields changed")
	}
	frame := []byte{0x81, 0x83, 1, 2, 3, 4, 'h' ^ 1, 'e' ^ 2, 'y' ^ 3}
	echo := func() {
		t.Helper()
		if _, err := client.Write(frame); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 5)
		if _, err := io.ReadFull(reader, got); err != nil || string(got) != string([]byte{0x81, 0x03, 'h', 'e', 'y'}) {
			t.Fatalf("complete real frame echo=%x err=%v", got, err)
		}
		if reader.Buffered() != 0 {
			t.Fatal("combined WebSocket test left unread frame bytes")
		}
	}
	echo()
	echo()
	var requestContext context.Context
	select {
	case requestContext = <-coverContext:
	case <-time.After(time.Second):
		t.Fatal("cover did not publish its actual request context")
	}
	closed := make(chan error, 1)
	closeJoined = make(chan struct{})
	go func() {
		defer close(closeJoined)
		if stop == "serve-cancel" {
			cancelServe()
			closed <- nil
		} else {
			closed <- server.Close()
		}
	}()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WebServer.Close did not return")
	}
	select {
	case <-closeJoined:
	case <-time.After(time.Second):
		t.Fatal("WebServer.Close worker did not join")
	}
	select {
	case err := <-serveResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("WebServer.Serve did not return after Close")
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, readErr := reader.ReadByte()
	var timeout net.Error
	if readErr == nil || (errors.As(readErr, &timeout) && timeout.Timeout()) {
		t.Fatalf("owner stop left the upgraded client alive: %v", readErr)
	}
	select {
	case <-requestContext.Done():
	case <-time.After(time.Second):
		t.Fatal("owner stop did not cancel the actual cover request")
	}
	if destinationCalls.Load() != 0 {
		t.Fatal("ordinary H1 upgrade invoked tunnel destination dialer")
	}
	if got := len(server.h3.listener.admission.slots); got != 0 {
		t.Fatalf("owner stop retained %d shared connection admission slots", got)
	}
	select {
	case err := <-originResult:
		if !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("owner stop did not close the real origin peer before cleanup: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("origin worker did not complete after owner stop, before cleanup")
	}
	for name, done := range map[string]<-chan struct{}{"origin worker": originJoined, "Serve worker": serveJoined, "cover handler": coverDone} {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s did not strictly join", name)
		}
	}
}
