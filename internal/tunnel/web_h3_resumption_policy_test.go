package tunnel

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	utls "github.com/refraction-networking/utls"
)

func TestWebH3ResumptionCachePolicyAndIsolation(t *testing.T) {
	_, clientTLS := webH2ResumptionTLSConfigs(t)
	clientTLS.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	supplied := utls.NewLRUClientSessionCache(4)
	input := &quic.Config{ChromeParrotSessionCache: supplied, Allow0RTT: true}
	for _, test := range []struct {
		name     string
		profile  H3FingerprintProfile
		nilCache bool
		disabled bool
		want     bool
	}{
		{name: "default"},
		{name: "fixed", profile: H3FingerprintChrome202610},
		{name: "native", profile: H3FingerprintNative},
		{name: "opt_in", profile: H3FingerprintChrome202610Resume, want: true},
		{name: "nil_cache", profile: H3FingerprintChrome202610Resume, nilCache: true},
		{name: "tickets_disabled", profile: H3FingerprintChrome202610Resume, disabled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := clientTLS.Clone()
			config.SessionTicketsDisabled = test.disabled
			if test.nilCache {
				config.ClientSessionCache = nil
			}
			var previous utls.ClientSessionCache
			for range 2 {
				client, err := NewWebH3Client(WebH3ClientConfig{
					ServerAddress: "relay.invalid:443", Token: webTestToken,
					TLSConfig: config, QUICConfig: input, FingerprintProfile: test.profile,
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = client.Close() })
				cache := client.quicConfig.ChromeParrotSessionCache
				if (cache != nil) != test.want || cache == supplied || (cache != nil && cache == previous) {
					t.Fatal("H3 cache policy retained a shared cache or ignored explicit opt-in/TLS policy")
				}
				if client.quicConfig.Allow0RTT {
					t.Fatal("H3 client allowed early application data")
				}
				if cache != client.quicConfig.Clone().ChromeParrotSessionCache {
					t.Fatal("physical reconnect did not retain this client's cache")
				}
				previous = cache
			}
		})
	}
	if input.ChromeParrotSessionCache != supplied || !input.Allow0RTT {
		t.Fatal("client constructor mutated the caller's QUIC config")
	}
	server := hardenedWebH3ServerConfig(input, 8, time.Second)
	if server.ChromeParrotSessionCache != nil || server.Allow0RTT || server.ChromeParrot {
		t.Fatal("server retained client resumption or early-data policy")
	}
	client, err := NewWebClient(WebClientConfig{
		ServerAddress: "relay.invalid:443", Token: webTestToken, TLSConfig: clientTLS,
		H3FingerprintProfile: H3FingerprintChrome202610Resume,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	h3 := client.primary.dialer.(*WebH3Client)
	h2 := client.fallback.dialer.(*WebH2Client)
	if h3.quicConfig.ChromeParrotSessionCache == nil || h2.utlsSessionCache == nil || h3.quicConfig.ChromeParrotSessionCache == h2.utlsSessionCache {
		t.Fatal("web-auto H2 and H3 do not own independent native uTLS caches")
	}
}

func TestWebH3ResumptionRejectsUnsupportedTLSCallbacks(t *testing.T) {
	for _, profile := range []H3FingerprintProfile{H3FingerprintChrome202610, H3FingerprintChrome202610Resume} {
		t.Run(string(profile), func(t *testing.T) {
			_, config := webH2ResumptionTLSConfigs(t)
			config.ClientSessionCache = tls.NewLRUClientSessionCache(4)
			config.VerifyConnection = func(tls.ConnectionState) error { return nil }
			client, err := NewWebH3Client(WebH3ClientConfig{
				ServerAddress: "relay.invalid:443", Token: webTestToken,
				TLSConfig: config, FingerprintProfile: profile,
			})
			if client != nil {
				_ = client.Close()
				t.Fatal("unsupported TLS callback was silently ignored")
			}
			if err == nil {
				t.Fatal("unsupported TLS callback did not fail before network access")
			}
		})
	}
}

func TestWebH3ResumptionConnectUDPReauthenticatesAndRejectsOldContinuations(t *testing.T) {
	serverTLS, clientTLS := webH2ResumptionTLSConfigs(t)
	clientTLS.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	tcpTarget, closeTarget := startHalfCloseTarget(t)
	t.Cleanup(closeTarget)
	udpTarget := startWebUDPEcho(t)
	resolver := newWebUDPTestResolver(map[string]netip.AddrPort{udpTarget.String(): udpTarget})
	var dials atomic.Int32
	server, err := ListenWebH3(WebH3ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
		Dialer: countingDialer{dials: &dials}, UDPResolver: resolver, Cover: http.NotFoundHandler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	observed := make(chan webH3ResumptionRequest, 8)
	handler := server.server.Handler
	server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn := r.Context().Value(webH3ConnectionContextKey{}).(*quic.Conn)
		auth := r.Context().Value(webServerConnectionAuthContextKey{}).(*webServerConnectionAuth)
		observed <- webH3ResumptionRequest{conn: conn, state: conn.ConnectionState(), auth: auth, authPhase: auth.phaseSnapshot()}
		handler.ServeHTTP(w, r)
	})
	serveWebH3ForTest(t, server)
	client, err := NewWebH3Client(WebH3ClientConfig{
		ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
		FingerprintProfile: H3FingerprintChrome202610Resume, DialTimeout: time.Second, HandshakeTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	cache := watchWebH3UTLSTickets(t, client)
	entropy := &webH2AuthEntropyCounter{}
	client.signer = newWebAuthSigner(mustWebAuthKey(t, webTestToken), nil, entropy)
	readObservation := func(wantResume bool, wantPhase webServerConnectionAuthPhase) webH3ResumptionRequest {
		t.Helper()
		select {
		case event := <-observed:
			if event.state.TLS.DidResume != wantResume || event.state.Used0RTT || !event.state.TLS.HandshakeComplete || event.authPhase != wantPhase {
				t.Fatalf("server resumed=%v 0-RTT=%v complete=%v auth=%v, want %v/false/true/%v", event.state.TLS.DidResume, event.state.Used0RTT, event.state.TLS.HandshakeComplete, event.authPhase, wantResume, wantPhase)
			}
			return event
		case <-time.After(3 * time.Second):
			t.Fatal("server request observation missing")
			return webH3ResumptionRequest{}
		}
	}
	openUDP := func(payload string) {
		t.Helper()
		packet, err := client.DialPacket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer packet.Close()
		assertWebUDPEcho(t, packet, []byte(payload), udpTarget.String())
	}
	openUDP("cold UDP bootstrap")
	coldServer := readObservation(false, webServerConnectionAuthFresh)
	first := webH3SelectedSession(t, client)
	firstAuth := first.auth
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	path, _, err := connectUDPPath(udpTarget.String())
	if err != nil {
		t.Fatal(err)
	}
	var oldRequests []*http.Request
	for _, udp := range []bool{false, true} {
		binding := webAuthBinding{transport: webAuthTransportH3, method: http.MethodConnect, authority: tcpTarget}
		if udp {
			binding.authority, binding.protocol, binding.path = server.Addr().String(), webConnectUDPProtocol, path
		}
		bearer, exchange, err := firstAuth.authorization(ctx, binding)
		if err != nil {
			t.Fatal(err)
		}
		firstAuth.complete(exchange)
		request := newWebH2ConnectRequest(tcpTarget, bearer)
		// http3 uses Proto for Extended CONNECT's :protocol, not HTTP version.
		request.Proto = ""
		if udp {
			request = newConnectUDPTestRequest(t, server.Addr().String(), path, bearer)
		}
		oldRequests = append(oldRequests, request)
	}
	waitWebH3Ticket(t, cache.stored)
	assertWebH3SessionUsers(t, client, first, 0)
	client.retire(first.conn)
	assertWebH3SessionRetired(t, client, first)
	conn, h3, err := client.connection(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state := conn.ConnectionState(); !state.TLS.DidResume || state.Used0RTT || !state.TLS.HandshakeComplete || len(state.TLS.VerifiedChains) == 0 {
		t.Fatal("physical UDP reconnect did not resume a verified 1-RTT TLS session")
	}
	// A valid short credential from the previous physical connection is not
	// authentication on the resumed connection, for either request protocol.
	for _, request := range oldRequests {
		stream, err := h3.OpenRequestStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_ = stream.SetDeadline(time.Now().Add(2 * time.Second))
		if err := stream.SendRequestHeader(request); err != nil {
			t.Fatal(err)
		}
		response, err := stream.ReadResponse()
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		if err != nil || response.StatusCode != http.StatusNotFound {
			t.Fatalf("old continuation rejection: response=%v error=%v", response, err)
		}
		readObservation(true, webServerConnectionAuthFresh)
		if dials.Load() != 0 || resolver.count(udpTarget.String()) != 1 {
			t.Fatal("old continuation reached a TCP or UDP destination")
		}
	}
	openUDP("resumed UDP requires fresh bootstrap")
	warmServer := readObservation(true, webServerConnectionAuthFresh)
	warm := webH3SelectedSession(t, client)
	if warm.conn != conn || warm == first || warm.auth == firstAuth || warm.auth.key == firstAuth.key || warmServer.auth == coldServer.auth || warmServer.conn == coldServer.conn {
		t.Fatal("resumed UDP request reused the old proxy-authentication session")
	}
	if err := exchange(client, tcpTarget, "resumed TCP continuation"); err != nil {
		t.Fatal(err)
	}
	readObservation(true, webServerConnectionAuthEstablished)
	if entropy.nonceReads.Load() != 2 || dials.Load() != 1 || resolver.count(udpTarget.String()) != 2 {
		t.Fatalf("bootstrap/TCP/UDP count=%d/%d/%d, want 2/1/2", entropy.nonceReads.Load(), dials.Load(), resolver.count(udpTarget.String()))
	}
}
