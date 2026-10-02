package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

type webH3InformationalResult struct {
	proof     string
	bearerLen int
	slots     int
	calls     int64
	canceled  bool
}

// This test-only middleware writes legitimate informational blocks before
// invoking the unmodified production authentication / failure handler. It
// leaves the actual H2 / H3 response writer and its interfaces untouched.
func webH3InformationalServer(t *testing.T, mode string, tlsConfig *tls.Config, hints []int, stall bool) (string, <-chan webH3InformationalResult) {
	t.Helper()
	var calls atomic.Int64
	privateErr := errors.New("private informational target failure")
	dialer := transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, privateErr
	})
	resolver := UDPResolverFunc(func(context.Context, string) ([]netip.AddrPort, error) {
		calls.Add(1)
		return nil, privateErr
	})
	results := make(chan webH3InformationalResult, 4)
	release := make(chan struct{})
	releaseStall := sync.OnceFunc(func() { close(release) })
	wrap := func(next http.Handler) http.Handler {
		core := next.(*webTunnelHandler).core
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, status := range hints {
				w.Header().Set("Link", "</ordinary.css>; rel=preload")
				w.WriteHeader(status)
				clear(w.Header())
			}
			if stall {
				select {
				case <-r.Context().Done():
				case <-release:
				}
			} else {
				next.ServeHTTP(w, r)
			}
			results <- webH3InformationalResult{
				proof: w.Header().Get(webAuthResponseHeader), bearerLen: len(r.Header.Get("Proxy-Authorization")),
				slots: len(core.sem), calls: calls.Load(), canceled: r.Context().Err() != nil,
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var closeServer func() error
	var address string
	if mode == "h2" {
		server, err := ListenWebH2(WebH2ServerConfig{
			Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: tlsConfig,
			Cover: http.NotFoundHandler(), Dialer: dialer,
		})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		server.server.Handler = wrap(server.server.Handler)
		closeServer, address = server.Close, server.Addr().String()
		go func() { done <- server.Serve(ctx) }()
	} else {
		server, err := ListenWebH3(WebH3ServerConfig{
			Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: tlsConfig,
			Cover: http.NotFoundHandler(), Dialer: dialer, UDPResolver: resolver,
		})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		server.server.Handler = wrap(server.server.Handler)
		closeServer, address = server.Close, server.Addr().String()
		go func() { done <- server.Serve(ctx) }()
	}
	t.Cleanup(func() {
		releaseStall()
		_ = closeServer()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("informational Serve join: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("informational Serve did not join")
		}
	})
	return address, results
}

type webH3InformationalClient struct {
	h2      *WebH2Client
	h3      *WebH3Client
	packet  transport.PacketConn
	entropy *webH2AuthEntropyCounter
}

func newWebH3InformationalClient(t *testing.T, mode, address string, tlsConfig *tls.Config, handshakeTimeout time.Duration) *webH3InformationalClient {
	t.Helper()
	c := &webH3InformationalClient{entropy: &webH2AuthEntropyCounter{}}
	signer := newWebAuthSigner(mustWebAuthKey(t, webTestToken), nil, c.entropy)
	var err error
	if mode == "h2" {
		c.h2, err = newWebH2ClientWithSigner(WebH2ClientConfig{
			ServerAddress: address, Token: webTestToken, TLSConfig: tlsConfig,
			HandshakeTimeout: handshakeTimeout,
		}, signer, webAuthClaims{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.h2.Close() })
	} else {
		c.h3, err = NewWebH3Client(WebH3ClientConfig{
			ServerAddress: address, Token: webTestToken, TLSConfig: tlsConfig,
			HandshakeTimeout: handshakeTimeout,
		})
		if err != nil {
			t.Fatal(err)
		}
		c.h3.signer = signer
		t.Cleanup(func() { _ = c.h3.Close() })
		if mode == "h3-udp" {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			c.packet, err = c.h3.DialPacket(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.packet.Close() })
		}
	}
	return c
}

func (c *webH3InformationalClient) request(target string) error {
	if c.packet != nil {
		return c.packet.Send([]byte("not delivered"), target)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var conn net.Conn
	var err error
	if c.h2 != nil {
		conn, err = c.h2.DialContext(ctx, "tcp", target)
	} else {
		conn, err = c.h3.DialContext(ctx, "tcp", target)
	}
	if conn != nil {
		_ = conn.Close()
		return errors.New("rejected destination returned a connection")
	}
	return err
}

func (c *webH3InformationalClient) session() (any, bool) {
	if c.h2 != nil {
		c.h2.mu.Lock()
		defer c.h2.mu.Unlock()
		s := c.h2.current
		return s, s != nil && s.authState == webH2ClientAuthReady && s.auth != nil
	}
	c.h3.mu.Lock()
	defer c.h3.mu.Unlock()
	s := c.h3.conns[c.h3.conn]
	return s, s != nil && s.authState == webH3ClientAuthReady && s.auth != nil
}

func webH3InformationalAwait(t *testing.T, results <-chan webH3InformationalResult) webH3InformationalResult {
	t.Helper()
	select {
	case result := <-results:
		if result.slots != 0 {
			t.Errorf("handler retained %d admission slots", result.slots)
		}
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("informational handler did not join")
		return webH3InformationalResult{}
	}
}

func TestWebH3InformationalSignedFailurePreservesConnection(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	for _, mode := range []string{"h2", "h3-tcp", "h3-udp"} {
		for _, hints := range [][]int{nil, {100, 102, 103}, {100, 102, 103, 102, 103}} {
			t.Run(fmt.Sprintf("%s/hints_%d", mode, len(hints)), func(t *testing.T) {
				address, results := webH3InformationalServer(t, mode, serverTLS, hints, false)
				client := newWebH3InformationalClient(t, mode, address, clientTLS, time.Second)
				var first any
				var bootstrapLen int
				for request := range 2 {
					err := client.request(fmt.Sprintf("missing%d.example:443", request))
					result := webH3InformationalAwait(t, results)
					var rejection *WebConnectError
					if !errors.As(err, &rejection) || rejection.StatusCode != http.StatusBadGateway || rejection.Transport != map[string]string{"h2": "h2", "h3-tcp": "h3", "h3-udp": "h3"}[mode] {
						t.Errorf("target failure = %T %v, want verified %s 502", err, err, mode)
					}
					if mode == "h3-udp" && (!errors.Is(err, transport.ErrPacketTargetUnavailable) || len(client.h3.udpSlots) != 0) {
						t.Error("signed UDP target failure lost recoverability or retained admission")
					}
					if result.proof == "" || result.calls != int64(request+1) {
						t.Errorf("original handler proof-present=%t targetcalls=%d, want %d", result.proof != "", result.calls, request+1)
					}
					session, ready := client.session()
					if !ready {
						t.Error("signed 502 did not retain ready connection authentication")
					}
					if request == 0 {
						first, bootstrapLen = session, result.bearerLen
					} else if session != first || result.bearerLen >= bootstrapLen {
						t.Errorf("continuation replaced physical session or did not use a shorter ticket: same=%t bearer=%d bootstrap=%d", session == first, result.bearerLen, bootstrapLen)
					}
				}
				if got := client.entropy.nonceReads.Load(); got != 1 {
					t.Errorf("full bootstrap ticket count = %d, want one", got)
				}
			})
		}
	}
}

func TestWebH3InformationalLimitRejectsFinalProof(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	for _, mode := range []string{"h3-tcp", "h3-udp"} {
		t.Run(mode, func(t *testing.T) {
			address, results := webH3InformationalServer(t, mode, serverTLS, []int{100, 102, 103, 102, 103, 103}, false)
			client := newWebH3InformationalClient(t, mode, address, clientTLS, time.Second)
			err := client.request("missing.example:443")
			result := webH3InformationalAwait(t, results)
			var rejection *WebConnectError
			if err == nil || errors.As(err, &rejection) || errors.Is(err, transport.ErrPacketTargetUnavailable) {
				t.Errorf("six informational blocks accepted final signed rejection: %v", err)
			}
			if err == nil || !strings.Contains(err.Error(), "too many web-cover H3 informational responses") {
				t.Errorf("six informational blocks error = %v, want the informational limit failure", err)
			}
			if _, ready := client.session(); ready {
				t.Error("excessive informational response retained authenticated bootstrap")
			}
			if mode == "h3-udp" && len(client.h3.udpSlots) != 0 {
				t.Error("excessive informational response retained UDP admission")
			}
			// Depending on cancellation scheduling, the peer may finish writing
			// the valid final proof or notice stream cancellation first. Neither
			// outcome may be accepted after the informational limit is exceeded.
			t.Logf("six-hint rejection=%v; server final proof present=%t, calls=%d", err, result.proof != "", result.calls)
		})
	}
}

func TestWebH3InformationalStalledFinalHonorsDeadline(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	for _, mode := range []string{"h3-tcp", "h3-udp"} {
		t.Run(mode, func(t *testing.T) {
			address, results := webH3InformationalServer(t, mode, serverTLS, []int{103}, true)
			client := newWebH3InformationalClient(t, mode, address, clientTLS, time.Second)
			// Establish QUIC separately so an overloaded TLS handshake cannot
			// masquerade as the target response deadline under test. No request
			// stream or authentication exists yet. The target budget stays 80ms.
			warmContext, cancelWarm := context.WithTimeout(context.Background(), 2*time.Second)
			_, _, warmErr := client.h3.connection(warmContext)
			cancelWarm()
			if warmErr != nil {
				t.Fatal(warmErr)
			}
			client.h3.mu.Lock()
			fresh := client.h3.conns[client.h3.conn]
			isFresh := fresh != nil && fresh.authState == webH3ClientAuthFresh && fresh.users == 0
			client.h3.mu.Unlock()
			if !isFresh {
				t.Fatal("warm physical connection already has authentication or stream owners")
			}
			select {
			case <-results:
				t.Fatal("physical warmup invoked the request handler")
			default:
			}
			// This client is test-exclusive with no concurrent opening request.
			client.h3.handshakeTimeout = 80 * time.Millisecond
			err := client.request("missing.example:443")
			result := webH3InformationalAwait(t, results)
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				t.Errorf("stalled final response error = %T %v, want setup deadline", err, err)
			}
			if !result.canceled || result.calls != 0 || result.proof != "" {
				t.Errorf("stalled handler canceled=%t calls=%d proof-present=%t", result.canceled, result.calls, result.proof != "")
			}
			if _, ready := client.session(); ready {
				t.Error("stalled final response authenticated a bootstrap")
			}
			if mode == "h3-udp" && len(client.h3.udpSlots) != 0 {
				t.Error("setup deadline retained UDP admission")
			}
		})
	}
}
