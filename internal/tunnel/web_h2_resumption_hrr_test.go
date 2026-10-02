package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
	"golang.org/x/net/http2"
)

type webH2HRRWireConn struct {
	net.Conn
	mu           sync.Mutex
	in, out      []byte
	clientClosed bool
}

func (c *webH2HRRWireConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	if n > 0 && len(c.in)+n <= 64<<10 {
		c.in = append(c.in, p[:n]...)
	}
	if errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) {
		c.clientClosed = true
	}
	c.mu.Unlock()
	return n, err
}

func (c *webH2HRRWireConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.mu.Lock()
		if len(c.out)+n <= 64<<10 {
			c.out = append(c.out, p[:n]...)
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *webH2HRRWireConn) snapshot() (parsedClientHello, bool, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.in) < 5 {
		return parsedClientHello{}, false, c.clientClosed, errors.New("missing real ClientHello")
	}
	length := 5 + int(binary.BigEndian.Uint16(c.in[3:5]))
	if length > len(c.in) {
		return parsedClientHello{}, false, c.clientClosed, errors.New("incomplete real ClientHello")
	}
	hello, err := parseTLSClientHello(c.in[:length])
	// TLS 1.3 HRR is a real ServerHello with this fixed RFC 8446 random.
	hrrRandom := []byte{0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c}
	hrr := len(c.out) >= 43 && c.out[0] == 22 && c.out[5] == 2 && bytes.Equal(c.out[11:43], hrrRandom)
	return hello, hrr, c.clientClosed, err
}

type webH2HRRAttempt struct {
	sequence   int
	state      tls.ConnectionState
	hello      parsedClientHello
	hrr        bool
	peerClosed bool
	err        error
}

// Failed HRR and replacement handshakes finish on independent workers.
// Sequence is accept identity, not completion order. This collector belongs
// only to one subtest; it never shares observations with another fixture.
type webH2HRRAttemptCollector struct {
	events  <-chan webH2HRRAttempt
	pending map[int]webH2HRRAttempt
	seen    map[int]struct{}
}

func newWebH2HRRAttemptCollector(events <-chan webH2HRRAttempt) *webH2HRRAttemptCollector {
	return &webH2HRRAttemptCollector{events: events, pending: make(map[int]webH2HRRAttempt), seen: make(map[int]struct{})}
}

func (c *webH2HRRAttemptCollector) take(t *testing.T, sequence int) webH2HRRAttempt {
	t.Helper()
	if attempt, ok := c.pending[sequence]; ok {
		delete(c.pending, sequence)
		return attempt
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case attempt := <-c.events:
			if _, duplicate := c.seen[attempt.sequence]; duplicate {
				t.Fatalf("duplicate real HRR attempt sequence %d", attempt.sequence)
			}
			c.seen[attempt.sequence] = struct{}{}
			if attempt.sequence == sequence {
				return attempt
			}
			c.pending[attempt.sequence] = attempt
		case <-timer.C:
			t.Fatalf("real HRR handshake worker %d did not report", sequence)
		}
	}
}

type webH2HRRClientRaw struct {
	net.Conn
	closes atomic.Int64
}

func (c *webH2HRRClientRaw) Close() error {
	err := c.Conn.Close()
	c.closes.Add(1)
	return err
}

func webH2HRREchoOrigin(t *testing.T) (string, <-chan error) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 4)
	done := make(chan struct{})
	var mu sync.Mutex
	closed := false
	owned := make(map[net.Conn]struct{})
	go func() {
		defer close(done)
		var workers sync.WaitGroup
		defer workers.Wait()
		for range 4 {
			_ = listener.SetDeadline(time.Now().Add(4 * time.Second))
			conn, err := listener.AcceptTCP()
			if err != nil {
				results <- err
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				_ = conn.Close()
				return
			}
			owned[conn] = struct{}{}
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				defer func() { mu.Lock(); delete(owned, conn); mu.Unlock() }()
				_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
				payload, readErr := io.ReadAll(io.LimitReader(conn, 8<<10))
				if readErr != nil {
					results <- readErr
					return
				}
				reply := append([]byte("hrr-reply:"), payload...)
				n, writeErr := conn.Write(reply)
				if writeErr == nil && n != len(reply) {
					writeErr = io.ErrShortWrite
				}
				results <- writeErr
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		closed = true
		for conn := range owned {
			_ = conn.Close()
		}
		mu.Unlock()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("real HRR echo Accept/socket workers did not join")
		}
	})
	return listener.Addr().String(), results
}

func webH2HRRServer(t *testing.T, serverTLS *tls.Config, destination string, expectedAttempts int) (string, <-chan webH2HRRAttempt, <-chan webH2ResumptionRequest, <-chan struct{}, *atomic.Int64) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	var destinationCalls atomic.Int64
	core, err := newServerCoreWithAdmission(webTestToken, transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		destinationCalls.Add(1)
		if network != "tcp" || address != destination {
			return nil, errors.New("unexpected HRR test destination")
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}), 0, 0, 0, 0, nil)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	verifier, err := newWebAuthVerifier(mustWebAuthKey(t, webTestToken), nil, 0)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	handler := &webTunnelHandler{core: core, auth: verifier, cover: http.NotFoundHandler()}
	config := serverTLS.Clone()
	config.MinVersion, config.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	config.NextProtos = []string{webH2ALPN}
	config.CurvePreferences = []tls.CurveID{tls.CurveP256}
	attempts := make(chan webH2HRRAttempt, expectedAttempts)
	requests := make(chan webH2ResumptionRequest, 4)
	handlerDone := make(chan struct{}, 4)
	done := make(chan struct{})
	var mu sync.Mutex
	closed := false
	owned := make(map[net.Conn]struct{})
	go func() {
		defer close(done)
		var workers sync.WaitGroup
		defer workers.Wait()
		for sequence := range expectedAttempts {
			_ = listener.SetDeadline(time.Now().Add(4 * time.Second))
			raw, err := listener.AcceptTCP()
			if err != nil {
				attempts <- webH2HRRAttempt{sequence: sequence, err: err}
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				_ = raw.Close()
				return
			}
			owned[raw] = struct{}{}
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer raw.Close()
				defer func() { mu.Lock(); delete(owned, raw); mu.Unlock() }()
				_ = raw.SetDeadline(time.Now().Add(4 * time.Second))
				wire := &webH2HRRWireConn{Conn: raw}
				tlsConn := tls.Server(wire, config)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				handshakeErr := tlsConn.HandshakeContext(ctx)
				cancel()
				hello, hrr, peerClosed, parseErr := wire.snapshot()
				if handshakeErr == nil {
					handshakeErr = parseErr
				}
				attempts <- webH2HRRAttempt{sequence: sequence, state: tlsConn.ConnectionState(), hello: hello, hrr: hrr, peerClosed: peerClosed, err: handshakeErr}
				if handshakeErr != nil {
					return
				}
				ctx = context.WithValue(context.Background(), webTLSConnectionContextKey{}, tlsConn)
				ctx = context.WithValue(ctx, webServerConnectionAuthContextKey{}, newWebServerConnectionAuth(raw.Close))
				observed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer func() {
						select {
						case handlerDone <- struct{}{}:
						default:
						}
					}()
					select {
					case requests <- webH2ResumptionRequest{physical: sequence, bearerBytes: len(r.Header.Get("Proxy-Authorization"))}:
					case <-r.Context().Done():
						return
					}
					handler.ServeHTTP(w, r)
				})
				(&http2.Server{}).ServeConn(tlsConn, &http2.ServeConnOpts{Context: ctx, Handler: observed})
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		closed = true
		for conn := range owned {
			_ = conn.Close()
		}
		mu.Unlock()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("real HRR Accept/TLS/ServeConn workers did not join")
		}
		if got := len(core.sem); got != 0 {
			t.Errorf("HRR destination admission retained %d slots", got)
		}
	})
	return listener.Addr().String(), attempts, requests, handlerDone, &destinationCalls
}

func webH2HRRReadAttempt(t *testing.T, collector *webH2HRRAttemptCollector, sequence int, wantFailure, wantPSK, wantResume bool) {
	t.Helper()
	attempt := collector.take(t, sequence)
	if attempt.sequence != sequence || !attempt.hrr {
		t.Errorf("attempt sequence/real HRR=%d/%t, want %d/true", attempt.sequence, attempt.hrr, sequence)
	}
	if got := containsUint16(attempt.hello.extensions, 41); got != wantPSK {
		t.Errorf("physical %d actual offered PSK=%t, want %t", sequence, got, wantPSK)
	}
	if containsUint16(attempt.hello.extensions, 42) {
		t.Error("HRR attempt offered TLS early_data")
	}
	if wantFailure {
		if !attempt.peerClosed || (!errors.Is(attempt.err, io.EOF) && !errors.Is(attempt.err, syscall.ECONNRESET)) {
			t.Errorf("failed warm physical %d was not client-closed before cleanup: peerClosed=%t err=%T: %v", sequence, attempt.peerClosed, attempt.err, attempt.err)
		}
	} else {
		if attempt.err != nil {
			t.Errorf("physical %d handshake error: %v", sequence, attempt.err)
		}
		if attempt.state.Version != tls.VersionTLS13 || attempt.state.NegotiatedProtocol != webH2ALPN || attempt.state.DidResume != wantResume {
			t.Errorf("physical %d TLS/h2/DidResume=%#x/%q/%t, want TLS13/h2/%t", sequence, attempt.state.Version, attempt.state.NegotiatedProtocol, attempt.state.DidResume, wantResume)
		}
	}
	t.Logf("physical=%d realHRR=%t offeredPSK=%t serverDidResume=%t peerClosed=%t peerEOF=%t peerReset=%t failed=%t", sequence, attempt.hrr, wantPSK, attempt.state.DidResume, attempt.peerClosed, errors.Is(attempt.err, io.EOF), errors.Is(attempt.err, syscall.ECONNRESET), attempt.err != nil)
}

func TestWebH2ResumptionHRRFallbackKeepsHealthyTunnel(t *testing.T) {
	for _, test := range []struct {
		name            string
		profile         FingerprintProfile
		cacheEnabled    bool
		ticketsDisabled bool
		fallback        bool
		resumed         bool
	}{
		{name: "chrome_enabled", profile: FingerprintChrome133, cacheEnabled: true, fallback: true},
		{name: "chrome_nil_cache", profile: FingerprintChrome133},
		{name: "chrome_tickets_disabled", profile: FingerprintChrome133, cacheEnabled: true, ticketsDisabled: true},
		{name: "native_positive", profile: FingerprintNative, cacheEnabled: true, resumed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			target, targetResults := webH2HRREchoOrigin(t)
			serverTLS, config := webH2ResumptionTLSConfigs(t)
			config.SessionTicketsDisabled = test.ticketsDisabled
			standardCache := &webH2ResumptionTLSCache{inner: tls.NewLRUClientSessionCache(4)}
			if test.cacheEnabled {
				config.ClientSessionCache = standardCache
			}
			physicalCount := 2
			if test.fallback {
				physicalCount = 3
			}
			address, attempts, requests, handlerDone, destinationCalls := webH2HRRServer(t, serverTLS, target, physicalCount)
			collector := newWebH2HRRAttemptCollector(attempts)
			client, err := NewWebH2Client(WebH2ClientConfig{ServerAddress: address, Token: webTestToken, TLSConfig: config, FingerprintProfile: test.profile})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			var chromeCache *webH2ResumptionUTLSCache
			if test.fallback {
				chromeCache = &webH2ResumptionUTLSCache{inner: client.utlsSessionCache}
				client.utlsSessionCache = chromeCache
			}
			var rawMu sync.Mutex
			var rawConnections []*webH2HRRClientRaw
			client.dialer = transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
				rawMu.Lock()
				if test.fallback && len(rawConnections) == 2 && rawConnections[1].closes.Load() == 0 {
					rawMu.Unlock()
					return nil, errors.New("fresh HRR dial began before failed raw TCP Close completed")
				}
				rawMu.Unlock()
				raw, err := (&net.Dialer{}).DialContext(ctx, network, address)
				if err != nil {
					return nil, err
				}
				observed := &webH2HRRClientRaw{Conn: raw}
				rawMu.Lock()
				rawConnections = append(rawConnections, observed)
				rawMu.Unlock()
				return observed, nil
			})
			var successful [2]*webH2ClientSession
			var authKeys [2]webSessionKey
			for request := range 4 {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				conn, dialErr := client.DialContext(ctx, "tcp", target)
				cancel()
				if dialErr != nil {
					if conn != nil {
						_ = conn.Close()
					}
					// Preserve direct warm-PSK/HRR/peer-close evidence even on the old
					// candidate, before fixture/client cleanup can close sockets.
					if request == 2 && test.fallback {
						webH2HRRReadAttempt(t, collector, 1, true, true, false)
					}
					t.Fatalf("healthy authenticated request %d after real HRR: %v", request, dialErr)
				}
				if conn == nil {
					t.Fatal("healthy CONNECT returned nil connection")
				}
				if request%2 == 0 {
					if request == 0 {
						webH2HRRReadAttempt(t, collector, 0, false, false, false)
					} else if test.fallback {
						webH2HRRReadAttempt(t, collector, 1, true, true, false)
						webH2HRRReadAttempt(t, collector, 2, false, false, false)
						rawMu.Lock()
						failedWasClosed := len(rawConnections) == 3 && rawConnections[1].closes.Load() > 0
						rawMu.Unlock()
						if !failedWasClosed {
							t.Error("warm failed raw TCP was not closed by client before fixture cleanup")
						}
					} else {
						webH2HRRReadAttempt(t, collector, 1, false, test.resumed, test.resumed)
					}
				}
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				payload := fmt.Sprintf("hrr-authenticated-payload-%d", request)
				n, writeErr := io.WriteString(conn, payload)
				if writeErr != nil || n != len(payload) {
					_ = conn.Close()
					t.Fatalf("healthy payload write: n=%d err=%v", n, writeErr)
				}
				writer, ok := conn.(interface{ CloseWrite() error })
				if !ok {
					_ = conn.Close()
					t.Fatal("H2 tunnel has no upload FIN")
				}
				if err := writer.CloseWrite(); err != nil {
					_ = conn.Close()
					t.Fatal(err)
				}
				reply, readErr := io.ReadAll(conn)
				_ = conn.Close()
				if readErr != nil || string(reply) != "hrr-reply:"+payload {
					t.Fatalf("healthy full TCP response: %q err=%v", reply, readErr)
				}
				select {
				case err := <-targetResults:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("real TCP echo worker did not report")
				}
				select {
				case <-handlerDone:
				case <-time.After(2 * time.Second):
					t.Fatal("healthy CONNECT handler did not return")
				}
				index := request / 2
				client.mu.Lock()
				current := client.current
				ready := current != nil && current.authState == webH2ClientAuthReady && current.auth != nil
				if ready {
					authKeys[index] = current.auth.key
				}
				client.mu.Unlock()
				if !ready {
					t.Fatal("healthy HRR tunnel did not retain authenticated session")
				}
				if request%2 == 0 {
					successful[index] = current
					state := current.conn.ConnectionState()
					if state.DidResume != (index == 1 && test.resumed) || state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != webH2ALPN || len(state.VerifiedChains) == 0 {
						t.Error("public client lost verified TLS13/h2 or expected resumption policy")
					}
				} else if current != successful[index] {
					t.Error("continuation changed its healthy physical connection")
				}
				select {
				case observed := <-requests:
					physical := index
					if index == 1 && test.fallback {
						physical = 2
					}
					if observed.physical != physical || (request%2 == 0 && observed.bearerBytes <= 41) || (request%2 == 1 && observed.bearerBytes != 41) {
						t.Errorf("request %d physical/bearer=%d/%d violated fresh-bootstrap/continuation policy", request, observed.physical, observed.bearerBytes)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("healthy request auth observation did not arrive")
				}
				if request == 1 {
					current.h2.SetDoNotReuse()
				}
			}
			if successful[0] == successful[1] || authKeys[0] == authKeys[1] {
				t.Error("HRR replacement inherited a physical connection or proxy key")
			}
			if destinationCalls.Load() != 4 {
				t.Errorf("healthy destination calls=%d, want 4", destinationCalls.Load())
			}
			rawMu.Lock()
			actualAttempts := len(rawConnections)
			rawMu.Unlock()
			if actualAttempts != physicalCount {
				t.Errorf("actual raw TCP attempts=%d, want exactly %d", actualAttempts, physicalCount)
			}
			if chromeCache != nil {
				if chromeCache.puts.Load() < 1 || chromeCache.hits.Load() != 1 {
					t.Errorf("real HRR Chrome cache puts/hits=%d/%d, want stored ticket and exactly one loaded attempt", chromeCache.puts.Load(), chromeCache.hits.Load())
				}
				t.Logf("Chrome HRR fallback actual TCP attempts=%d ticket puts=%d hits=%d", actualAttempts, chromeCache.puts.Load(), chromeCache.hits.Load())
			} else if test.resumed && (standardCache.puts.Load() < 1 || standardCache.hits.Load() < 1) {
				t.Error("native resumed HRR cache positive control failed")
			}
			_ = client.Close()
		})
	}
}
