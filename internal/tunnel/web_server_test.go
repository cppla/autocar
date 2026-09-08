package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/apernet/quic-go/http3"
	"github.com/cppla/autocar/internal/transport"
)

func TestWebServerSamePortCoverAndConcurrentTunnels(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	targetAddress, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()

	var outboundDials atomic.Int64
	dialer := transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		outboundDials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, address)
	})
	seenProtocols := make(chan int, 3)
	cover := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenProtocols <- r.ProtoMajor
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Cover", "shared-origin")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, "cover:"+r.URL.Path)
	})
	server, err := ListenWeb(WebServerConfig{
		TCPAddress:           "127.0.0.1:0",
		UDPAddress:           "127.0.0.1:0",
		Token:                testToken,
		TLSConfig:            serverTLS,
		Cover:                cover,
		Dialer:               dialer,
		MaxConcurrentStreams: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	tcpPort := addressPort(t, server.TCPAddr())
	udpPort := addressPort(t, server.UDPAddr())
	if tcpPort != udpPort {
		t.Fatalf("TCP/UDP ports = %q/%q, want the same numeric port", tcpPort, udpPort)
	}

	// These pointer identities are an intentional invariant: capacity and
	// replay protection span both wire transports rather than being per-listener.
	h2Handler, ok := server.h2.server.Handler.(*webTunnelHandler)
	if !ok {
		t.Fatalf("HTTP/2 handler type = %T", server.h2.server.Handler)
	}
	h3Handler, ok := server.h3.server.Handler.(*webTunnelHandler)
	if !ok {
		t.Fatalf("HTTP/3 handler type = %T", server.h3.server.Handler)
	}
	if h2Handler.core != h3Handler.core || h2Handler.auth != h3Handler.auth {
		t.Fatal("HTTP/2 and HTTP/3 do not share relay core and replay verifier")
	}

	serveCtx, cancelServe := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(serveCtx) }()
	t.Cleanup(func() {
		cancelServe()
		_ = server.Close()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("dual web-cover server did not stop")
		}
	})

	wantAltSvc := `h3=":` + udpPort + `"`
	h2Transport := http.DefaultTransport.(*http.Transport).Clone()
	h2Transport.TLSClientConfig = clientTLS.Clone()
	h2Transport.ForceAttemptHTTP2 = true
	t.Cleanup(h2Transport.CloseIdleConnections)
	assertDualWebCover(t, &http.Client{Transport: h2Transport}, "https://"+server.TCPAddr().String()+"/h2", 2, wantAltSvc)

	h1TLS := clientTLS.Clone()
	h1TLS.NextProtos = []string{webHTTP11ALPN}
	h1Transport := http.DefaultTransport.(*http.Transport).Clone()
	h1Transport.TLSClientConfig = h1TLS
	h1Transport.ForceAttemptHTTP2 = false
	h1Transport.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
	t.Cleanup(h1Transport.CloseIdleConnections)
	assertDualWebCover(t, &http.Client{Transport: h1Transport}, "https://"+server.TCPAddr().String()+"/h1", 1, wantAltSvc)

	h3TLS := clientTLS.Clone()
	h3TLS.NextProtos = []string{http3.NextProtoH3}
	h3Transport := &http3.Transport{TLSClientConfig: h3TLS}
	t.Cleanup(func() { _ = h3Transport.Close() })
	assertDualWebCover(t, &http.Client{Transport: h3Transport}, "https://"+server.UDPAddr().String()+"/h3", 3, "")

	wantProtocols := map[int]int{1: 1, 2: 1, 3: 1}
	for range 3 {
		select {
		case proto := <-seenProtocols:
			wantProtocols[proto]--
		case <-time.After(2 * time.Second):
			t.Fatal("cover handler did not receive every protocol")
		}
	}
	for proto, remaining := range wantProtocols {
		if remaining != 0 {
			t.Fatalf("cover protocol HTTP/%d count mismatch: %d", proto, remaining)
		}
	}

	h2Client, err := NewWebH2Client(WebH2ClientConfig{
		ServerAddress: server.TCPAddr().String(), Token: testToken, TLSConfig: clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h2Client.Close() })
	h3Client, err := NewWebH3Client(WebH3ClientConfig{
		ServerAddress: server.UDPAddr().String(), Token: testToken, TLSConfig: clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h3Client.Close() })

	const streamsPerTransport = 6
	start := make(chan struct{})
	errorsCh := make(chan error, streamsPerTransport*2)
	var wg sync.WaitGroup
	for _, client := range []transport.Dialer{h2Client, h3Client} {
		for stream := range streamsPerTransport {
			wg.Add(1)
			go func(d transport.Dialer, n int) {
				defer wg.Done()
				<-start
				if err := exchange(d, targetAddress, fmt.Sprintf("dual-%d", n)); err != nil {
					errorsCh <- err
				}
			}(client, stream)
		}
	}
	close(start)
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Error(err)
	}
	if got, want := outboundDials.Load(), int64(streamsPerTransport*2); got != want {
		t.Fatalf("destination dials = %d, want %d", got, want)
	}
}

func TestWebServerAltSvcUsesBoundPortAndOverridesCoverValue(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	server, err := ListenWeb(WebServerConfig{
		TCPAddress: "127.0.0.1:0",
		UDPAddress: "127.0.0.1:0",
		Token:      testToken,
		TLSConfig:  serverTLS,
		Cover: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Alt-Svc", `h3=":1"; ma=1`)
			w.WriteHeader(http.StatusNoContent)
		}),
		Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("unused")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	defer func() {
		cancel()
		_ = server.Close()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	}()

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = clientTLS.Clone()
	transport.ForceAttemptHTTP2 = true
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport}).Get("https://" + server.TCPAddr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	want := webH3AltSvcValue(server.UDPAddr())
	if got := response.Header.Get("Alt-Svc"); got != want {
		t.Fatalf("Alt-Svc = %q, want bound HTTP/3 value %q", got, want)
	}
}

func TestWebClientsRejectCover200WithoutServerProof(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	var dials atomic.Int64
	server, err := ListenWeb(WebServerConfig{
		TCPAddress: "127.0.0.1:0",
		UDPAddress: "127.0.0.1:0",
		Token:      testToken,
		TLSConfig:  serverTLS,
		Cover: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ordinary cover accepted CONNECT")
		}),
		Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("must not dial")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})

	wrongToken := "different-web-cover-token-32-bytes"
	h2, err := NewWebH2Client(WebH2ClientConfig{
		ServerAddress: server.TCPAddr().String(), Token: wrongToken, TLSConfig: clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h2.Close()
	h3, err := NewWebH3Client(WebH3ClientConfig{
		ServerAddress: server.UDPAddr().String(), Token: wrongToken, TLSConfig: clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h3.Close()
	for name, client := range map[string]transport.Dialer{"h2": h2, "h3": h3} {
		t.Run(name, func(t *testing.T) {
			_, err := client.DialContext(context.Background(), "tcp", "127.0.0.1:9")
			if err == nil || !strings.Contains(err.Error(), "server authentication failed") {
				t.Fatalf("cover 200 result = %v", err)
			}
		})
	}
	if got := dials.Load(); got != 0 {
		t.Fatalf("wrong credentials caused %d destination dials", got)
	}
}

func TestWebServerAddressValidationAndUDPBindRollback(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	config := WebServerConfig{
		TCPAddress: "127.0.0.1:41001",
		UDPAddress: "127.0.0.1:41002",
		Token:      testToken,
		TLSConfig:  serverTLS,
		Cover:      http.NotFoundHandler(),
		Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("unused")
		}),
	}
	if _, err := ListenWeb(config); err == nil || !strings.Contains(err.Error(), "ports must match") {
		t.Fatalf("mismatched port error = %v", err)
	}
	if tcp, udp, err := normalizeWebListenAddresses("127.0.0.1:0", "[::1]:8443"); err != nil ||
		tcp != "127.0.0.1:8443" || udp != "[::1]:8443" {
		t.Fatalf("zero/fixed address normalization = %q/%q, %v", tcp, udp, err)
	}

	reservedTCP, occupiedUDP := reserveWebTestTCPUDP(t)
	occupiedAddress := occupiedUDP.LocalAddr().String()
	config.TCPAddress = occupiedAddress
	config.UDPAddress = occupiedAddress

	// An occupied TCP endpoint must not be mistaken for the UDP failure this
	// regression exercises. Holding both sockets also proves that this numeric
	// port was available in both independent protocol namespaces.
	server, err := ListenWeb(config)
	if server != nil {
		_ = server.Close()
		t.Fatal("ListenWeb returned a server while its TCP endpoint was occupied")
	}
	requireWebListenAddressInUse(t, err, "tcp", occupiedAddress)
	if err := reservedTCP.Close(); err != nil {
		t.Fatal(err)
	}

	server, err = ListenWeb(config)
	if server != nil {
		_ = server.Close()
		t.Fatal("ListenWeb returned a server while its UDP endpoint was occupied")
	}
	requireWebListenAddressInUse(t, err, "udp", occupiedAddress)
	// The failed second bind must roll back the already-created TCP listener.
	// Neither the server call nor this check may retry: doing so could hide a
	// genuine rollback leak. A competing TCP bind above has a different error.
	probeTCP, err := net.Listen("tcp", occupiedAddress)
	if err != nil {
		t.Fatalf("TCP listener leaked after UDP bind failure: %v", err)
	}
	_ = probeTCP.Close()
}

func reserveWebTestTCPUDP(t *testing.T) (net.Listener, net.PacketConn) {
	t.Helper()
	// The kernel allocates TCP and UDP ephemeral ports independently. Retry
	// only fixture setup when a TCP-selected port is already occupied on UDP,
	// before invoking ListenWeb or testing any rollback behavior.
	for range 32 {
		tcp, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		udp, err := net.ListenPacket("udp", tcp.Addr().String())
		if err == nil {
			t.Cleanup(func() {
				_ = tcp.Close()
				_ = udp.Close()
			})
			return tcp, udp
		}
		_ = tcp.Close()
		if !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatalf("reserve matching UDP endpoint: %v", err)
		}
	}
	t.Fatal("could not reserve one port in both TCP and UDP namespaces")
	return nil, nil
}

func requireWebListenAddressInUse(t *testing.T, err error, network, address string) {
	t.Helper()
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "listen" || opErr.Net != network ||
		opErr.Addr == nil || opErr.Addr.String() != address || !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("ListenWeb bind error = %v, want listen %s %s: address already in use", err, network, address)
	}
}

func TestWebServerCloseIsConcurrentAndServeIsSingleUse(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	server, err := ListenWeb(WebServerConfig{
		TCPAddress: "127.0.0.1:0",
		UDPAddress: "127.0.0.1:0",
		Token:      testToken,
		TLSConfig:  serverTLS,
		Cover:      http.NotFoundHandler(),
		Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("unused")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Serve(nil); err == nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("Serve(nil) error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := server.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		}()
	}
	wg.Wait()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after concurrent Close")
	}
	if err := server.Serve(context.Background()); err == nil || !strings.Contains(err.Error(), "already served") {
		t.Fatalf("second Serve error = %v", err)
	}
}

func TestWebH3AltSvcValueUsesAuthorityFormForIPv6(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 8443}
	if got, want := webH3AltSvcValue(addr), `h3=":8443"`; got != want {
		t.Fatalf("IPv6 Alt-Svc = %q, want %q", got, want)
	}
	fakeTCP := &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 8443}
	if got, err := webUDPAddressForTCP("[::1]:0", fakeTCP); err != nil || got != "[::1]:8443" {
		t.Fatalf("IPv6 UDP address = %q, %v", got, err)
	}
}

func TestNormalizeWebServerCloseErrorKeepsNonBenignJoinedError(t *testing.T) {
	want := errors.New("close failed")
	got := normalizeWebServerCloseError(errors.Join(net.ErrClosed, http.ErrServerClosed, want))
	if !errors.Is(got, want) || errors.Is(got, net.ErrClosed) || errors.Is(got, http.ErrServerClosed) {
		t.Fatalf("normalized close error = %v, want only %v", got, want)
	}
}

func assertDualWebCover(t *testing.T, client *http.Client, endpoint string, wantProtocol int, wantAltSvc string) {
	t.Helper()
	response, err := client.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusAccepted || response.ProtoMajor != wantProtocol ||
		response.Header.Get("X-Cover") != "shared-origin" || string(body) != fmt.Sprintf("cover:/h%d", wantProtocol) {
		t.Fatalf("cover response = status %d protocol %s headers %v body %q", response.StatusCode, response.Proto, response.Header, body)
	}
	if got := response.Header.Get("Alt-Svc"); got != wantAltSvc {
		t.Fatalf("HTTP/%d Alt-Svc = %q, want %q", wantProtocol, got, wantAltSvc)
	}
}

func addressPort(t *testing.T, address net.Addr) string {
	t.Helper()
	if address == nil {
		t.Fatal("nil listener address")
	}
	_, port, err := net.SplitHostPort(address.String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}
