package tunnel

import (
	"crypto/rand"
	"crypto/tls"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

type webH3ResumptionCache struct {
	inner  tls.ClientSessionCache
	stored chan struct{}
	once   sync.Once
	puts   atomic.Int64
	hits   atomic.Int64
}

func (c *webH3ResumptionCache) Put(key string, state *tls.ClientSessionState) {
	c.inner.Put(key, state)
	if state != nil {
		c.puts.Add(1)
		// Publish only after the real cache has accepted the ticket. A completed
		// handshake alone does not guarantee that NewSessionTicket has arrived.
		c.once.Do(func() { close(c.stored) })
	}
}

func (c *webH3ResumptionCache) Get(key string) (*tls.ClientSessionState, bool) {
	state, ok := c.inner.Get(key)
	if ok {
		c.hits.Add(1)
	}
	return state, ok
}

type webH3ResumptionRequest struct {
	conn      *quic.Conn
	state     quic.ConnectionState
	auth      *webServerConnectionAuth
	authPhase webServerConnectionAuthPhase
}

// This is a transport contract test, not a browser-similarity measurement.
// Reusing an authenticated H3 stream connection is distinct from reconnecting
// with a TLS ticket. Neither case permits application data in QUIC 0-RTT.
func TestWebH3ResumptionReconnectContract(t *testing.T) {
	for _, test := range []struct {
		name            string
		profile         H3FingerprintProfile
		cacheEnabled    bool
		ticketsDisabled bool
		wantResume      bool
	}{
		{name: "native_cache", profile: H3FingerprintNative, cacheEnabled: true, wantResume: true},
		{name: "default_chrome_cache", cacheEnabled: true},
		{name: "native_nil_cache", profile: H3FingerprintNative},
		{name: "native_tickets_disabled", profile: H3FingerprintNative, cacheEnabled: true, ticketsDisabled: true},
		{name: "default_chrome_tickets_disabled", cacheEnabled: true, ticketsDisabled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Reuse the DNS-SAN certificate helper so both profiles must preserve
			// trusted hostname verification, even though every socket is loopback.
			serverTLS, clientTLS := webH2ResumptionTLSConfigs(t)
			var ticketKey [32]byte
			if _, err := rand.Read(ticketKey[:]); err != nil {
				t.Fatal(err)
			}
			serverTLS.SetSessionTicketKeys([][32]byte{ticketKey})
			cache := &webH3ResumptionCache{inner: tls.NewLRUClientSessionCache(4), stored: make(chan struct{})}
			clientTLS.ClientSessionCache = nil
			if test.cacheEnabled {
				clientTLS.ClientSessionCache = cache
			}
			clientTLS.SessionTicketsDisabled = test.ticketsDisabled

			target, closeTarget := startHalfCloseTarget(t)
			t.Cleanup(closeTarget)
			var dials atomic.Int32
			server, err := ListenWebH3(WebH3ServerConfig{
				Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
				Dialer: countingDialer{dials: &dials}, Cover: http.NotFoundHandler(),
			})
			if err != nil {
				t.Fatal(err)
			}
			requests := make(chan webH3ResumptionRequest, 3)
			handlerDone := make(chan struct{}, 3)
			handler := server.server.Handler
			server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Observe the real production connection context before delegating
				// authentication. Never capture or log credentials or ticket bytes.
				conn, _ := r.Context().Value(webH3ConnectionContextKey{}).(*quic.Conn)
				auth, _ := r.Context().Value(webServerConnectionAuthContextKey{}).(*webServerConnectionAuth)
				observation := webH3ResumptionRequest{conn: conn, auth: auth}
				if conn != nil {
					observation.state = conn.ConnectionState()
				}
				if auth != nil {
					auth.mu.Lock()
					observation.authPhase = auth.phase
					auth.mu.Unlock()
				}
				select {
				case requests <- observation:
				case <-r.Context().Done():
					return
				}
				defer func() { handlerDone <- struct{}{} }()
				handler.ServeHTTP(w, r)
			})
			serveWebH3ForTest(t, server)
			client, err := NewWebH3Client(WebH3ClientConfig{
				ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
				FingerprintProfile: test.profile, DialTimeout: 2 * time.Second, HandshakeTimeout: 2 * time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			if test.profile == "" && client.fingerprint != H3FingerprintChrome202608 {
				t.Fatal("default H3 profile changed")
			}
			entropy := &webH2AuthEntropyCounter{}
			client.signer = newWebAuthSigner(mustWebAuthKey(t, webTestToken), nil, entropy)

			var first *webH3ClientSession
			var firstAuth *webSessionClientAuth
			var firstServer webH3ResumptionRequest
			var resumed [3]bool
			for phase, name := range []string{"cold", "same_connection_stream", "physical_reconnect"} {
				if phase == 2 {
					if test.wantResume {
						select {
						case <-cache.stored:
						case <-time.After(3 * time.Second):
							t.Fatal("native TLS cache never received a real session ticket")
						}
					}
					assertWebH3SessionUsers(t, client, first, 0)
					client.retire(first.conn)
					select {
					case <-first.conn.Context().Done():
					case <-time.After(3 * time.Second):
						t.Fatal("retirement did not close the old physical QUIC connection")
					}
				}
				if err := exchange(client, target, name); err != nil {
					t.Fatalf("%s authenticated stream: %v", name, err)
				}
				select {
				case <-handlerDone:
				case <-time.After(3 * time.Second):
					t.Fatalf("%s server handler did not finish", name)
				}
				var observed webH3ResumptionRequest
				select {
				case observed = <-requests:
				case <-time.After(3 * time.Second):
					t.Fatalf("%s server observation missing", name)
				}
				if observed.conn == nil || observed.auth == nil {
					t.Fatalf("%s lost production connection/auth context", name)
				}
				session := webH3SelectedSession(t, client)
				client.mu.Lock()
				auth, ready := session.auth, session.authState == webH3ClientAuthReady
				client.mu.Unlock()
				if !ready || auth == nil {
					t.Fatalf("%s did not establish connection authentication", name)
				}
				wantResume := phase == 2 && test.wantResume
				clientState := session.conn.ConnectionState()
				resumed[phase] = clientState.TLS.DidResume
				for side, state := range map[string]quic.ConnectionState{"client": clientState, "server": observed.state} {
					if state.TLS.DidResume != wantResume || state.Used0RTT || !state.TLS.HandshakeComplete || state.TLS.Version != tls.VersionTLS13 || state.TLS.NegotiatedProtocol != http3.NextProtoH3 || state.TLS.ServerName != clientTLS.ServerName {
						t.Errorf("%s %s: resumed=%t 0-RTT=%t complete=%t TLS=%#x ALPN=%q SNI=%q", name, side, state.TLS.DidResume, state.Used0RTT, state.TLS.HandshakeComplete, state.TLS.Version, state.TLS.NegotiatedProtocol, state.TLS.ServerName)
					}
				}
				if len(clientState.TLS.VerifiedChains) == 0 || len(clientState.TLS.PeerCertificates) == 0 || client.tlsConfig.InsecureSkipVerify {
					t.Fatalf("%s lost server certificate verification", name)
				}
				wantPhase, wantNonces, wantSequence := webServerConnectionAuthFresh, int64(1), uint64(1)
				switch phase {
				case 0:
					first, firstAuth, firstServer = session, auth, observed
				case 1:
					wantPhase, wantSequence = webServerConnectionAuthEstablished, 2
					if session != first || auth != firstAuth || observed.conn != firstServer.conn || observed.auth != firstServer.auth {
						t.Fatal("second stream replaced the physical connection or authentication session")
					}
				case 2:
					wantNonces = 2
					if session == first || session.conn == first.conn || auth == firstAuth || auth.key == firstAuth.key || observed.conn == firstServer.conn || observed.auth == firstServer.auth {
						t.Fatal("physical reconnect reused a connection or proxy authentication session")
					}
				}
				if observed.authPhase != wantPhase || entropy.nonceReads.Load() != wantNonces {
					t.Errorf("%s proxy auth phase=%d bootstrap count=%d, want %d/%d", name, observed.authPhase, entropy.nonceReads.Load(), wantPhase, wantNonces)
				}
				auth.mu.Lock()
				nextSequence := auth.nextSequence
				auth.mu.Unlock()
				if nextSequence != wantSequence {
					t.Errorf("%s next proxy auth sequence=%d, want %d", name, nextSequence, wantSequence)
				}
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if dials.Load() != 3 {
				t.Errorf("authenticated destination dials=%d, want 3", dials.Load())
			}
			if test.wantResume {
				if cache.puts.Load() == 0 || cache.hits.Load() == 0 {
					t.Error("native resumption lacked a real stored/loaded ticket")
				}
			} else if cache.puts.Load() != 0 || cache.hits.Load() != 0 {
				t.Error("full-handshake control unexpectedly used the TLS cache")
			}
			t.Logf("TLS DidResume cold/reuse/reconnect=%v; cache puts=%d hits=%d; proxy bootstraps=%d", resumed, cache.puts.Load(), cache.hits.Load(), entropy.nonceReads.Load())
		})
	}
}
