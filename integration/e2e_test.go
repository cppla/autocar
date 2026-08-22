package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/proxy"
	"github.com/cppla/autocar/internal/security"
	"github.com/cppla/autocar/internal/transport"
	"github.com/cppla/autocar/internal/tunnel"
)

const (
	testToken        = "autocar-integration-token"
	operationTimeout = 5 * time.Second
)

type closeDialer interface {
	transport.Dialer
	io.Closer
}

type tlsMaterial struct {
	certificate tls.Certificate
	server      *tls.Config
	client      *tls.Config
}

// TestProxyComposition exercises every layer over actual loopback sockets:
// proxy client -> SOCKS5/HTTP frontend -> tunnel ingress -> QUIC or TLS exit ->
// target. The exit intentionally receives an ordinary net.Dialer, allowing the
// test-only loopback targets without relaxing the production SafeDialer.
func TestProxyComposition(t *testing.T) {
	material := newTLSMaterial(t)
	echoAddress := startEchoTarget(t)
	httpTarget := startHTTPTarget(t)

	modes := []struct {
		name  string
		start func(*testing.T) closeDialer
	}{
		{
			name: "quic",
			start: func(t *testing.T) closeDialer {
				server := startQUICExit(t, material.server, &net.Dialer{}, testToken)
				client, err := tunnel.NewClient(tunnel.ClientConfig{
					ServerAddress:    server.Addr().String(),
					Token:            testToken,
					TLSConfig:        material.client,
					HandshakeTimeout: operationTimeout,
					QUICDialTimeout:  operationTimeout,
				})
				if err != nil {
					t.Fatalf("create QUIC tunnel client: %v", err)
				}
				t.Cleanup(func() { _ = client.Close() })
				return client
			},
		},
		{
			name: "tls_fallback",
			start: func(t *testing.T) closeDialer {
				server := startTLSExit(t, material.server, &net.Dialer{}, testToken)
				client, err := tunnel.NewTLSClient(tunnel.TLSClientConfig{
					ServerAddress:    server.Addr().String(),
					Token:            testToken,
					TLSConfig:        material.client,
					HandshakeTimeout: operationTimeout,
					DialTimeout:      operationTimeout,
				})
				if err != nil {
					t.Fatalf("create TLS fallback client: %v", err)
				}
				t.Cleanup(func() { _ = client.Close() })
				return client
			},
		},
		{
			name: "auto_udp_blocked",
			start: func(t *testing.T) closeDialer {
				fallback := startTLSExit(t, material.server, &net.Dialer{}, testToken)
				blockedQUICAddress := startUDPBlackhole(t)
				client, err := tunnel.NewClient(tunnel.ClientConfig{
					ServerAddress:    blockedQUICAddress,
					FallbackAddress:  fallback.Addr().String(),
					Token:            testToken,
					TLSConfig:        material.client,
					HandshakeTimeout: time.Second,
					QUICDialTimeout:  150 * time.Millisecond,
					TLSDialTimeout:   operationTimeout,
					FallbackCooldown: time.Minute,
				})
				if err != nil {
					t.Fatalf("create automatic tunnel client: %v", err)
				}
				t.Cleanup(func() { _ = client.Close() })
				return client
			},
		},
	}

	for _, mode := range modes {
		mode := mode
		t.Run(mode.name, func(t *testing.T) {
			dialer := mode.start(t)
			socksAddress := startSOCKSProxy(t, dialer)
			httpProxyAddress := startHTTPProxy(t, dialer, nil)

			exerciseSOCKSConnect(t, socksAddress, echoAddress)
			exerciseHTTPAbsoluteForm(t, httpProxyAddress, httpTarget.URL)
			exerciseHTTPConnect(t, httpProxyAddress, echoAddress)

			// One HTTPS-proxy-listener test is enough: the frontend and tunnel
			// path are otherwise identical, while this verifies that requests to
			// the proxy itself can also be protected by TLS.
			if mode.name == "quic" {
				httpsAddress := startHTTPProxy(t, dialer, &tls.Config{
					MinVersion:   tls.VersionTLS13,
					MaxVersion:   tls.VersionTLS13,
					Certificates: []tls.Certificate{material.certificate},
				})
				exerciseHTTPSProxyAbsoluteForm(t, httpsAddress, material.client, httpTarget.URL)
			}
		})
	}
}

func TestTunnelAuthenticationBoundaries(t *testing.T) {
	good := newTLSMaterial(t)
	bad := newTLSMaterial(t)
	echoAddress := startEchoTarget(t)

	t.Run("untrusted_certificate_quic", func(t *testing.T) {
		counter := &countingDialer{}
		server := startQUICExit(t, good.server, counter, testToken)
		client, err := tunnel.NewClient(tunnel.ClientConfig{
			ServerAddress:    server.Addr().String(),
			Token:            testToken,
			TLSConfig:        bad.client,
			HandshakeTimeout: time.Second,
			QUICDialTimeout:  time.Second,
		})
		if err != nil {
			t.Fatalf("create client with untrusted roots: %v", err)
		}
		defer client.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if conn, err := client.DialContext(ctx, "tcp", echoAddress); err == nil {
			_ = conn.Close()
			t.Fatal("QUIC tunnel accepted a certificate outside its trust store")
		}
		if got := counter.count.Load(); got != 0 {
			t.Fatalf("target dial count = %d, want 0 after certificate rejection", got)
		}
	})

	t.Run("untrusted_certificate_tls", func(t *testing.T) {
		counter := &countingDialer{}
		server := startTLSExit(t, good.server, counter, testToken)
		client, err := tunnel.NewTLSClient(tunnel.TLSClientConfig{
			ServerAddress:    server.Addr().String(),
			Token:            testToken,
			TLSConfig:        bad.client,
			HandshakeTimeout: time.Second,
			DialTimeout:      time.Second,
		})
		if err != nil {
			t.Fatalf("create fallback client with untrusted roots: %v", err)
		}
		defer client.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if conn, err := client.DialContext(ctx, "tcp", echoAddress); err == nil {
			_ = conn.Close()
			t.Fatal("TLS fallback accepted a certificate outside its trust store")
		}
		if got := counter.count.Load(); got != 0 {
			t.Fatalf("target dial count = %d, want 0 after certificate rejection", got)
		}
	})

	t.Run("wrong_token_quic", func(t *testing.T) {
		counter := &countingDialer{}
		server := startQUICExit(t, good.server, counter, testToken)
		client, err := tunnel.NewClient(tunnel.ClientConfig{
			ServerAddress:    server.Addr().String(),
			Token:            "wrong-token-value",
			TLSConfig:        good.client,
			HandshakeTimeout: operationTimeout,
			QUICDialTimeout:  operationTimeout,
		})
		if err != nil {
			t.Fatalf("create client with wrong token: %v", err)
		}
		defer client.Close()
		assertUnauthorized(t, client, echoAddress)
		if got := counter.count.Load(); got != 0 {
			t.Fatalf("target dial count = %d, want 0 after token rejection", got)
		}
	})

	t.Run("wrong_token_tls", func(t *testing.T) {
		counter := &countingDialer{}
		server := startTLSExit(t, good.server, counter, testToken)
		client, err := tunnel.NewTLSClient(tunnel.TLSClientConfig{
			ServerAddress:    server.Addr().String(),
			Token:            "wrong-token-value",
			TLSConfig:        good.client,
			HandshakeTimeout: operationTimeout,
			DialTimeout:      operationTimeout,
		})
		if err != nil {
			t.Fatalf("create fallback client with wrong token: %v", err)
		}
		defer client.Close()
		assertUnauthorized(t, client, echoAddress)
		if got := counter.count.Load(); got != 0 {
			t.Fatalf("target dial count = %d, want 0 after token rejection", got)
		}
	})
}

func newTLSMaterial(t *testing.T) tlsMaterial {
	t.Helper()
	certPEM, keyPEM, err := security.GenerateSelfSignedCertificate(security.CertificateOptions{
		Hosts:    []string{"127.0.0.1"},
		ValidFor: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("generate test certificate: %v", err)
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parse generated key pair: %v", err)
	}
	serverTLS, err := security.NewServerTLSConfig(security.ServerTLSOptions{
		Certificates: []tls.Certificate{certificate},
	})
	if err != nil {
		t.Fatalf("build server TLS config: %v", err)
	}
	clientTLS, err := security.NewClientTLSConfig(security.ClientTLSOptions{
		ServerName: "127.0.0.1",
		CAPEM:      certPEM,
	})
	if err != nil {
		t.Fatalf("build client TLS config: %v", err)
	}
	return tlsMaterial{
		certificate: certificate,
		server:      serverTLS,
		client:      clientTLS,
	}
}

func startQUICExit(t *testing.T, tlsConfig *tls.Config, dialer transport.Dialer, token string) *tunnel.QUICServer {
	t.Helper()
	server, err := tunnel.ListenQUIC(tunnel.QUICServerConfig{
		Address:              "127.0.0.1:0",
		Token:                token,
		TLSConfig:            tlsConfig,
		Dialer:               dialer,
		HandshakeTimeout:     operationTimeout,
		DialTimeout:          operationTimeout,
		MaxConcurrentStreams: 64,
	})
	if err != nil {
		t.Fatalf("listen QUIC exit: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		waitForServe(t, "QUIC exit", done)
	})
	return server
}

func startTLSExit(t *testing.T, tlsConfig *tls.Config, dialer transport.Dialer, token string) *tunnel.TLSServer {
	t.Helper()
	server, err := tunnel.ListenTLS(tunnel.TLSServerConfig{
		Address:              "127.0.0.1:0",
		Token:                token,
		TLSConfig:            tlsConfig,
		Dialer:               dialer,
		HandshakeTimeout:     operationTimeout,
		DialTimeout:          operationTimeout,
		MaxConcurrentStreams: 64,
	})
	if err != nil {
		t.Fatalf("listen TLS exit: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		waitForServe(t, "TLS exit", done)
	})
	return server
}

func startSOCKSProxy(t *testing.T, dialer transport.Dialer) string {
	t.Helper()
	server, err := proxy.NewSOCKS5Server(proxy.Config{
		Dialer:           dialer,
		HandshakeTimeout: operationTimeout,
		DialTimeout:      operationTimeout,
		IdleTimeout:      operationTimeout,
		MaxConnections:   32,
	})
	if err != nil {
		t.Fatalf("create SOCKS5 proxy: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen SOCKS5 proxy: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil && !isExpectedClose(err) {
			t.Errorf("shut down SOCKS5 proxy: %v", err)
		}
		waitForServe(t, "SOCKS5 proxy", done)
	})
	return listener.Addr().String()
}

func startHTTPProxy(t *testing.T, dialer transport.Dialer, tlsConfig *tls.Config) string {
	t.Helper()
	server, err := proxy.NewHTTPServer(proxy.Config{
		Dialer:           dialer,
		HandshakeTimeout: operationTimeout,
		DialTimeout:      operationTimeout,
		IdleTimeout:      operationTimeout,
		MaxConnections:   32,
	})
	if err != nil {
		t.Fatalf("create HTTP proxy: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen HTTP proxy: %v", err)
	}
	address := listener.Addr().String()
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil && !isExpectedClose(err) {
			t.Errorf("shut down HTTP proxy: %v", err)
		}
		waitForServe(t, "HTTP proxy", done)
	})
	return address
}

func startEchoTarget(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo target: %v", err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
		wg.Wait()
	})
	return listener.Addr().String()
}

func startHTTPTarget(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-AutoCAR-Target", "reached")
		_, _ = fmt.Fprintf(w, "target:%s:%s:%s", r.Method, r.URL.Path, r.Header.Get("X-AutoCAR-Test"))
	}))
	t.Cleanup(server.Close)
	return server
}

func startUDPBlackhole(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen UDP blackhole: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 64<<10)
		for {
			if _, _, err := conn.ReadFrom(buffer); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = conn.Close()
		<-done
	})
	return conn.LocalAddr().String()
}

func exerciseSOCKSConnect(t *testing.T, proxyAddress, targetAddress string) {
	t.Helper()
	conn := dialWithDeadline(t, proxyAddress)
	defer conn.Close()

	writeFull(t, conn, []byte{0x05, 0x01, 0x00})
	method := readFull(t, conn, 2)
	if !bytes.Equal(method, []byte{0x05, 0x00}) {
		t.Fatalf("SOCKS5 method response = %x, want 0500", method)
	}
	host, portText, err := net.SplitHostPort(targetAddress)
	if err != nil {
		t.Fatalf("split target address: %v", err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() {
		t.Fatalf("test target is not IPv4: %q", host)
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		t.Fatalf("parse target port: %v", err)
	}
	request := []byte{0x05, 0x01, 0x00, 0x01}
	ip4 := ip.As4()
	request = append(request, ip4[:]...)
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	writeFull(t, conn, request)

	header := readFull(t, conn, 4)
	if header[0] != 0x05 || header[1] != 0x00 {
		t.Fatalf("SOCKS5 CONNECT response header = %x, want success", header)
	}
	discardSOCKSAddress(t, conn, header[3])

	payload := []byte("SOCKS5 -> QUIC/TLS -> target: \x00\x01\xfe\xff")
	writeFull(t, conn, payload)
	if got := readFull(t, conn, len(payload)); !bytes.Equal(got, payload) {
		t.Fatalf("SOCKS5 echo = %q, want %q", got, payload)
	}
}

func discardSOCKSAddress(t *testing.T, r io.Reader, addressType byte) {
	t.Helper()
	switch addressType {
	case 0x01:
		_ = readFull(t, r, net.IPv4len+2)
	case 0x04:
		_ = readFull(t, r, net.IPv6len+2)
	case 0x03:
		length := readFull(t, r, 1)[0]
		_ = readFull(t, r, int(length)+2)
	default:
		t.Fatalf("SOCKS5 response has unknown address type %#x", addressType)
	}
}

func exerciseHTTPAbsoluteForm(t *testing.T, proxyAddress, targetURL string) {
	t.Helper()
	proxyURL := &url.URL{Scheme: "http", Host: proxyAddress}
	transport := &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: operationTimeout}
	request, err := http.NewRequest(http.MethodGet, targetURL+"/absolute", nil)
	if err != nil {
		t.Fatalf("create absolute-form request: %v", err)
	}
	request.Header.Set("X-AutoCAR-Test", "absolute-form")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("HTTP absolute-form request: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read absolute-form response: %v", err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("X-AutoCAR-Target") != "reached" {
		t.Fatalf("absolute-form response = %s, target header %q", response.Status, response.Header.Get("X-AutoCAR-Target"))
	}
	if got, want := string(body), "target:GET:/absolute:absolute-form"; got != want {
		t.Fatalf("absolute-form body = %q, want %q", got, want)
	}
}

func exerciseHTTPConnect(t *testing.T, proxyAddress, targetAddress string) {
	t.Helper()
	conn := dialWithDeadline(t, proxyAddress)
	defer conn.Close()
	request := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", targetAddress, targetAddress)
	writeFull(t, conn, []byte(request))
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}
	if !strings.Contains(statusLine, " 200 ") {
		t.Fatalf("CONNECT status line = %q", statusLine)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	payload := []byte("HTTP CONNECT through an encrypted AutoCAR stream")
	writeFull(t, conn, payload)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatalf("read CONNECT echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("CONNECT echo = %q, want %q", got, payload)
	}
}

func exerciseHTTPSProxyAbsoluteForm(t *testing.T, proxyAddress string, verifiedTLS *tls.Config, targetURL string) {
	t.Helper()
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: operationTimeout},
		Config:    verifiedTLS.Clone(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddress)
	if err != nil {
		t.Fatalf("dial HTTPS proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(operationTimeout))

	parsed, err := url.Parse(targetURL)
	if err != nil {
		t.Fatalf("parse HTTP target URL: %v", err)
	}
	request := fmt.Sprintf("GET %s/secure-proxy HTTP/1.1\r\nHost: %s\r\nX-AutoCAR-Test: https-proxy\r\nConnection: close\r\n\r\n", targetURL, parsed.Host)
	writeFull(t, conn, []byte(request))
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read HTTPS proxy response: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read HTTPS proxy response body: %v", err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("X-AutoCAR-Target") != "reached" {
		t.Fatalf("HTTPS proxy response = %s, target header %q", response.Status, response.Header.Get("X-AutoCAR-Target"))
	}
	if got, want := string(body), "target:GET:/secure-proxy:https-proxy"; got != want {
		t.Fatalf("HTTPS proxy body = %q, want %q", got, want)
	}
}

func assertUnauthorized(t *testing.T, dialer transport.Dialer, targetAddress string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", targetAddress)
	if conn != nil {
		_ = conn.Close()
	}
	var remoteErr *tunnel.RemoteError
	if !errors.As(err, &remoteErr) {
		t.Fatalf("wrong-token error = %v, want *tunnel.RemoteError", err)
	}
	if remoteErr.Status != protocol.StatusUnauthorized {
		t.Fatalf("wrong-token status = %d, want %d", remoteErr.Status, protocol.StatusUnauthorized)
	}
}

func dialWithDeadline(t *testing.T, address string) net.Conn {
	t.Helper()
	dialer := &net.Dialer{Timeout: operationTimeout}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}
	if err := conn.SetDeadline(time.Now().Add(operationTimeout)); err != nil {
		_ = conn.Close()
		t.Fatalf("set connection deadline: %v", err)
	}
	return conn
}

func writeFull(t *testing.T, w io.Writer, data []byte) {
	t.Helper()
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			t.Fatalf("write %d bytes: %v", len(data), err)
		}
		if n <= 0 {
			t.Fatal("writer made no progress")
		}
		data = data[n:]
	}
}

func readFull(t *testing.T, r io.Reader, size int) []byte {
	t.Helper()
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		t.Fatalf("read %d bytes: %v", size, err)
	}
	return data
}

func waitForServe(t *testing.T, name string, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil && !isExpectedClose(err) {
			t.Errorf("%s Serve returned: %v", name, err)
		}
	case <-time.After(operationTimeout):
		t.Errorf("timed out waiting for %s Serve to stop", name)
	}
}

// tls.Listener can wrap net.ErrClosed in an older net.OpError that predates
// errors.Is support. Both spellings represent the same deliberate test
// shutdown and are the only errors ignored by the cleanup assertions.
func isExpectedClose(err error) bool {
	return errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection")
}

type countingDialer struct {
	count atomic.Int64
}

func (d *countingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.count.Add(1)
	return (&net.Dialer{}).DialContext(ctx, network, address)
}
