package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/security"
	"github.com/cppla/autocar/internal/transport"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

type webH2ResumptionTLSCache struct {
	inner tls.ClientSessionCache
	hits  atomic.Int64
	puts  atomic.Int64
}

func (c *webH2ResumptionTLSCache) Get(key string) (*tls.ClientSessionState, bool) {
	state, ok := c.inner.Get(key)
	if ok {
		c.hits.Add(1)
	}
	return state, ok
}

func (c *webH2ResumptionTLSCache) Put(key string, state *tls.ClientSessionState) {
	if state != nil {
		c.puts.Add(1)
	}
	c.inner.Put(key, state)
}

type webH2ResumptionUTLSCache struct {
	inner utls.ClientSessionCache
	hits  atomic.Int64
	puts  atomic.Int64
}

func (c *webH2ResumptionUTLSCache) Get(key string) (*utls.ClientSessionState, bool) {
	state, ok := c.inner.Get(key)
	if ok {
		c.hits.Add(1)
	}
	return state, ok
}

func (c *webH2ResumptionUTLSCache) Put(key string, state *utls.ClientSessionState) {
	if state != nil {
		c.puts.Add(1)
	}
	c.inner.Put(key, state)
}

// Capture raw TLS records only in memory, to parse the actual first ClientHello
// received by the trusted loopback TLS server. Never log ticket or auth bytes.
type webH2ResumptionWireConn struct {
	net.Conn
	mu   sync.Mutex
	data []byte
}

func (c *webH2ResumptionWireConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		if len(c.data)+n <= 64<<10 {
			c.data = append(c.data, p[:n]...)
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *webH2ResumptionWireConn) clientHello() (parsedClientHello, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.data) < 5 {
		return parsedClientHello{}, errors.New("missing real TLS record")
	}
	length := 5 + int(binary.BigEndian.Uint16(c.data[3:5]))
	if length > len(c.data) {
		return parsedClientHello{}, errors.New("incomplete real ClientHello record")
	}
	return parseTLSClientHello(c.data[:length])
}

type webH2ResumptionPhysicalResult struct {
	sequence int
	state    tls.ConnectionState
	hello    parsedClientHello
	err      error
}

type webH2ResumptionRequest struct {
	physical    int
	bearerBytes int
}

func webH2ResumptionTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	// A DNS SAN exercises SNI as well as trusted hostname validation, while
	// the actual socket remains loopback and does not require DNS lookup.
	const host = "resumption-cover.example"
	certPEM, keyPEM, err := security.GenerateSelfSignedCertificate(security.CertificateOptions{Hosts: []string{host}, ValidFor: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("could not trust test DNS certificate")
	}
	return &tls.Config{Certificates: []tls.Certificate{certificate}}, &tls.Config{RootCAs: roots, ServerName: host}
}

// The public client talks to the production handler over real TCP/TLS/H2.
// ServeConn lets this fixture observe the handshake without substituting auth
// or a fake TLS state; its context carries the same exact-connection bindings
// as ListenWebH2. Each accepted socket and worker is independently owned.
func webH2ResumptionOrigin(t *testing.T, serverTLS *tls.Config) (string, <-chan webH2ResumptionPhysicalResult, <-chan webH2ResumptionRequest, <-chan struct{}, *atomic.Int64) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	var dialCalls atomic.Int64
	core, err := newServerCoreWithAdmission(webTestToken, transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
		dialCalls.Add(1)
		return nil, errors.New("private resumption test destination failure")
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
	results := make(chan webH2ResumptionPhysicalResult, 2)
	requests := make(chan webH2ResumptionRequest, 4)
	handlerDone := make(chan struct{}, 4)
	done := make(chan struct{})
	var mu sync.Mutex
	closed := false
	owned := make(map[net.Conn]struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		defer wg.Wait()
		for sequence := range 2 {
			_ = listener.SetDeadline(time.Now().Add(3 * time.Second))
			raw, acceptErr := listener.AcceptTCP()
			if acceptErr != nil {
				results <- webH2ResumptionPhysicalResult{sequence: sequence, err: acceptErr}
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
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer raw.Close()
				defer func() { mu.Lock(); delete(owned, raw); mu.Unlock() }()
				_ = raw.SetDeadline(time.Now().Add(4 * time.Second))
				wire := &webH2ResumptionWireConn{Conn: raw}
				tlsConn := tls.Server(wire, config)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				handshakeErr := tlsConn.HandshakeContext(ctx)
				cancel()
				if handshakeErr != nil {
					results <- webH2ResumptionPhysicalResult{sequence: sequence, err: handshakeErr}
					return
				}
				hello, helloErr := wire.clientHello()
				if helloErr != nil {
					results <- webH2ResumptionPhysicalResult{sequence: sequence, err: helloErr}
					return
				}
				ctx = context.WithValue(context.Background(), webTLSConnectionContextKey{}, tlsConn)
				ctx = context.WithValue(ctx, webServerConnectionAuthContextKey{}, newWebServerConnectionAuth(raw.Close))
				observed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Four actual requests fit independently of the test consumer.
					// Unexpected canceled requests must not strand a handler here.
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
				results <- webH2ResumptionPhysicalResult{sequence: sequence, state: tlsConn.ConnectionState(), hello: hello}
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
			t.Error("real resumption Accept/TLS/H2 workers did not join")
		}
		if got := len(core.sem); got != 0 {
			t.Errorf("destination admission retained %d slots", got)
		}
	})
	return listener.Addr().String(), results, requests, handlerDone, &dialCalls
}

func webH2ResumptionCheckChromeHello(t *testing.T, hello parsedClientHello, profile FingerprintProfile, warm bool) {
	t.Helper()
	wantCiphers := []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	if got := withoutGREASE(hello.cipherSuites); !reflect.DeepEqual(got, wantCiphers) {
		t.Errorf("Chrome cold/warm cipher order changed: %#v", got)
	}
	// Both fixed profiles retain this common non-GREASE membership; Chrome155
	// additionally advertises its captured trust-anchor IDs. Extension order
	// is deliberately not frozen: the presets shuffle it.
	wantExtensions := []uint16{0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 17613, 0xfe0d, 0xff01}
	if profile == FingerprintChrome155 {
		wantExtensions = append(wantExtensions, 0xca34)
	}
	if warm {
		wantExtensions = append(wantExtensions, 41)
	}
	gotExtensions := withoutGREASE(hello.extensions)
	slices.Sort(gotExtensions)
	slices.Sort(wantExtensions)
	if !reflect.DeepEqual(gotExtensions, wantExtensions) {
		t.Errorf("Chrome extension membership = %#v, want %#v", gotExtensions, wantExtensions)
	}
	if !containsGREASE(hello.cipherSuites) || !containsGREASE(hello.extensions) {
		t.Error("Chrome ClientHello lost GREASE")
	}
	if !reflect.DeepEqual(hello.alpn, []string{webH2ALPN, webHTTP11ALPN}) {
		t.Errorf("Chrome offered ALPN = %q", hello.alpn)
	}
}

func TestWebH2RealTLSResumptionAndFreshAuthentication(t *testing.T) {
	for _, test := range []struct {
		name            string
		profile         FingerprintProfile
		cacheEnabled    bool
		ticketsDisabled bool
		wantResume      bool
	}{
		{name: "chrome_enabled", profile: FingerprintChrome133, cacheEnabled: true, wantResume: true},
		{name: "chrome_nil_cache", profile: FingerprintChrome133},
		{name: "chrome_tickets_disabled", profile: FingerprintChrome133, cacheEnabled: true, ticketsDisabled: true},
		{name: "chrome155_enabled", profile: FingerprintChrome155, cacheEnabled: true, wantResume: true},
		{name: "chrome155_nil_cache", profile: FingerprintChrome155},
		{name: "chrome155_tickets_disabled", profile: FingerprintChrome155, cacheEnabled: true, ticketsDisabled: true},
		{name: "native_positive", profile: FingerprintNative, cacheEnabled: true, wantResume: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			serverTLS, clientTLS := webH2ResumptionTLSConfigs(t)
			address, results, requests, handlerDone, dialCalls := webH2ResumptionOrigin(t, serverTLS)
			config := clientTLS.Clone()
			config.ClientSessionCache = nil
			config.SessionTicketsDisabled = test.ticketsDisabled
			standardCache := &webH2ResumptionTLSCache{inner: tls.NewLRUClientSessionCache(4)}
			if test.cacheEnabled {
				config.ClientSessionCache = standardCache
			}
			client, err := NewWebH2Client(WebH2ClientConfig{ServerAddress: address, Token: webTestToken, TLSConfig: config, FingerprintProfile: test.profile})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			var chromeCache *webH2ResumptionUTLSCache
			if test.profile == FingerprintChrome133 || test.profile == FingerprintChrome155 {
				if test.wantResume {
					if client.utlsSessionCache == nil {
						t.Fatal("enabled cache policy did not create a uTLS cache")
					}
					chromeCache = &webH2ResumptionUTLSCache{inner: client.utlsSessionCache}
					client.utlsSessionCache = chromeCache
				} else if client.utlsSessionCache != nil {
					t.Fatal("nil-cache/tickets-disabled policy created a uTLS cache")
				}
			}
			var physical [2]*webH2ClientSession
			var states [2]tls.ConnectionState
			var authKeys [2]webSessionKey
			for request := range 4 {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				conn, dialErr := client.DialContext(ctx, "tcp", fmt.Sprintf("resumption-target%d.example:443", request))
				cancel()
				if conn != nil {
					_ = conn.Close()
					t.Error("authenticated destination rejection returned a connection")
				}
				var rejection *WebConnectError
				if !errors.As(dialErr, &rejection) || rejection.StatusCode != http.StatusBadGateway {
					t.Fatalf("real authenticated HTTP/2 refusal: %v", dialErr)
				}
				select {
				case <-handlerDone:
				case <-time.After(2 * time.Second):
					t.Fatal("authenticated handler did not return")
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
					t.Fatal("verified response did not retain ready connection authentication")
				}
				if request%2 == 0 {
					physical[index] = current
					states[index] = current.conn.ConnectionState()
				} else if current != physical[index] {
					t.Fatal("continuation unexpectedly changed physical connection")
				}
				select {
				case observation := <-requests:
					if observation.physical != index {
						t.Errorf("request %d used physical %d, want %d", request, observation.physical, index)
					}
					if request%2 == 0 && observation.bearerBytes <= 41 {
						t.Errorf("new physical %d inherited a short auth ticket", index)
					}
					if request%2 == 1 && observation.bearerBytes != 41 {
						t.Errorf("physical %d continuation bearer bytes=%d, want 41", index, observation.bearerBytes)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("real request observation did not arrive")
				}
				if request == 1 {
					current.h2.SetDoNotReuse()
				}
			}
			if physical[0] == physical[1] || authKeys[0] == authKeys[1] {
				t.Error("replacement inherited physical connection or authentication key")
			}
			if got := dialCalls.Load(); got != 4 {
				t.Errorf("authenticated destination calls=%d, want 4", got)
			}
			for sequence, state := range states {
				wantResume := sequence == 1 && test.wantResume
				if state.DidResume != wantResume {
					t.Errorf("client physical %d DidResume=%t, want %t", sequence, state.DidResume, wantResume)
				}
				if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != webH2ALPN || len(state.VerifiedChains) == 0 || state.ServerName != config.ServerName {
					t.Errorf("client physical %d lost verified TLS 1.3/h2 state", sequence)
				}
			}
			_ = client.Close()
			for range 2 {
				select {
				case result := <-results:
					if result.err != nil {
						t.Fatal(result.err)
					}
					warm := result.sequence == 1 && test.wantResume
					if result.state.DidResume != warm {
						t.Errorf("server physical %d DidResume=%t, want %t", result.sequence, result.state.DidResume, warm)
					}
					if result.state.Version != tls.VersionTLS13 || result.state.NegotiatedProtocol != webH2ALPN || result.state.ServerName != config.ServerName {
						t.Errorf("server physical %d lost TLS 1.3/h2 state", result.sequence)
					}
					if containsUint16(result.hello.extensions, 42) {
						t.Error("ClientHello unexpectedly offered TLS early_data")
					}
					if got := containsUint16(result.hello.extensions, 41); got != warm {
						t.Errorf("physical %d actual wire PSK present=%t, want %t", result.sequence, got, warm)
					}
					if warm && result.hello.extensions[len(result.hello.extensions)-1] != 41 {
						t.Error("warm ClientHello PSK extension is not last")
					}
					if test.profile == FingerprintChrome133 || test.profile == FingerprintChrome155 {
						webH2ResumptionCheckChromeHello(t, result.hello, test.profile, warm)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("real physical HTTP/2 worker did not return")
				}
			}
			if chromeCache != nil {
				if chromeCache.hits.Load() < 1 || chromeCache.puts.Load() < 1 {
					t.Error("Chrome resumed without a real stored/loaded ticket control")
				}
				t.Logf("real Chrome TLS tickets puts=%d hits=%d", chromeCache.puts.Load(), chromeCache.hits.Load())
			} else if test.profile == FingerprintNative {
				if standardCache.hits.Load() < 1 || standardCache.puts.Load() < 1 {
					t.Error("native resumption cache positive control failed")
				}
				t.Logf("real native TLS tickets puts=%d hits=%d", standardCache.puts.Load(), standardCache.hits.Load())
			} else if standardCache.hits.Load() != 0 || standardCache.puts.Load() != 0 {
				t.Error("Chrome caller cache policy leaked into standard cache use")
			}
		})
	}
}
