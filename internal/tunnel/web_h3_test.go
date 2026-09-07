package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/cppla/autocar/internal/transport"
)

const webTestToken = "web-cover-test-token-32-bytes-long"

func TestWebH3CoverAndAuthenticatedConnect(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	target := startWebTCPEcho(t)
	var dials atomic.Int32
	cover := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Cover", "ordinary-site")
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, "cover:"+r.Method)
	})
	server, err := ListenWebH3(WebH3ServerConfig{
		Address:          "127.0.0.1:0",
		Token:            webTestToken,
		TLSConfig:        serverTLS,
		Dialer:           countingDialer{dials: &dials},
		Cover:            cover,
		DialTimeout:      time.Second,
		HandshakeTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		select {
		case err := <-serveErr:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("web H3 server did not stop")
		}
	})

	publicTLS := clientTLS.Clone()
	publicTLS.NextProtos = []string{http3.NextProtoH3}
	roundTripper := &http3.Transport{TLSClientConfig: publicTLS}
	t.Cleanup(func() { _ = roundTripper.Close() })
	response, err := roundTripper.RoundTrip(mustWebRequest(t, http.MethodGet, "https://"+server.Addr().String()+"/news", nil))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusTeapot || response.Header.Get("X-Cover") != "ordinary-site" || string(body) != "cover:GET" {
		t.Fatalf("cover response = status %d headers %v body %q", response.StatusCode, response.Header, body)
	}
	if response.ProtoMajor != 3 || response.TLS == nil || response.TLS.NegotiatedProtocol != http3.NextProtoH3 {
		t.Fatalf("cover protocol = %s TLS=%+v", response.Proto, response.TLS)
	}
	if dials.Load() != 0 {
		t.Fatalf("ordinary cover request made %d destination dials", dials.Load())
	}

	client, err := NewWebH3Client(WebH3ClientConfig{
		ServerAddress:    server.Addr().String(),
		Token:            webTestToken,
		TLSConfig:        clientTLS,
		DialTimeout:      time.Second,
		HandshakeTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if client.fingerprint != H3FingerprintChrome202608 || !client.quicConfig.ChromeParrot || client.quicConfig.KeepAlivePeriod != 0 {
		t.Fatalf("default H3 profile = %q ChromeParrot=%v keepalive=%s", client.fingerprint, client.quicConfig.ChromeParrot, client.quicConfig.KeepAlivePeriod)
	}
	conn, err := client.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	payload := []byte("authenticated H3 tunnel")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
	if dials.Load() != 1 {
		t.Fatalf("authenticated tunnel made %d destination dials", dials.Load())
	}
	client.mu.Lock()
	var session *webH3ClientSession
	for _, tracked := range client.conns {
		session = tracked
		break
	}
	client.mu.Unlock()
	if session == nil {
		t.Fatal("Chrome H3 session was not tracked")
	}
	if _, ok := session.transport.ConnectionIDGenerator.(quic.ZeroLengthConnectionIDGenerator); !ok {
		t.Fatalf("Chrome H3 source CID generator = %T, want ZeroLengthConnectionIDGenerator", session.transport.ConnectionIDGenerator)
	}
}

func TestWebH3ConnectionAuthMultiplexesOneFullTicket(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	target, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	var dials atomic.Int32
	server, err := ListenWebH3(WebH3ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
		Dialer: countingDialer{dials: &dials}, Cover: http.NotFoundHandler(),
		MaxConcurrentStreams: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
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

	const streams = 16
	start := make(chan struct{})
	errorsCh := make(chan error, streams)
	var wg sync.WaitGroup
	for range streams {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := exchange(client, target, "web-h3-session-ticket"); err != nil {
				errorsCh <- err
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Errorf("stream exchange: %v", err)
	}
	if got := dials.Load(); got != streams {
		t.Fatalf("destination dials = %d, want %d", got, streams)
	}
	if got := entropy.nonceReads.Load(); got != 1 {
		t.Fatalf("full authentication tickets = %d, want exactly one per physical QUIC connection", got)
	}
	client.mu.Lock()
	session := client.conns[client.conn]
	client.mu.Unlock()
	if session == nil || session.authState != webH3ClientAuthReady || session.auth == nil {
		t.Fatal("HTTP/3 physical connection did not retain established authentication")
	}
	session.auth.mu.Lock()
	nextSequence := session.auth.nextSequence
	session.auth.mu.Unlock()
	if nextSequence != streams {
		t.Fatalf("next continuation sequence = %d, want %d after one bootstrap and %d short tickets", nextSequence, streams, streams-1)
	}
}

func TestWebH3AuthenticatedBootstrapErrorKeepsConnectionSession(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	target, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	var dials atomic.Int32
	server, err := ListenWebH3(WebH3ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
		Dialer: transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			if dials.Add(1) == 1 {
				return nil, errors.New("synthetic first destination failure")
			}
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}),
		Cover: http.NotFoundHandler(),
	})
	if err != nil {
		t.Fatal(err)
	}
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

	connection, err := client.DialContext(context.Background(), "tcp", target)
	if connection != nil {
		_ = connection.Close()
	}
	var connectErr *WebConnectError
	if !errors.As(err, &connectErr) || connectErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("first CONNECT error = %v, want authenticated 502", err)
	}
	client.mu.Lock()
	first := client.conns[client.conn]
	client.mu.Unlock()
	if first == nil || first.authState != webH3ClientAuthReady {
		t.Fatal("authenticated 502 did not establish the QUIC connection session")
	}
	if err := exchange(client, target, "after-authenticated-h3-error"); err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	second := client.conns[client.conn]
	client.mu.Unlock()
	if second != first {
		t.Fatal("authenticated bootstrap error unnecessarily replaced the QUIC connection")
	}
	if got := entropy.nonceReads.Load(); got != 1 {
		t.Fatalf("full authentication tickets = %d, want one across authenticated 502 and retry", got)
	}
}

func TestWebH3NativeFingerprintIsExplicitRollback(t *testing.T) {
	_, clientTLS := testTLSConfigs(t)
	client, err := NewWebH3Client(WebH3ClientConfig{
		ServerAddress:      "127.0.0.1:443",
		Token:              webTestToken,
		TLSConfig:          clientTLS,
		FingerprintProfile: H3FingerprintNative,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.fingerprint != H3FingerprintNative || client.quicConfig.ChromeParrot {
		t.Fatalf("native H3 rollback profile = %q ChromeParrot=%v", client.fingerprint, client.quicConfig.ChromeParrot)
	}
}

func TestWebH3AddressCandidatesInterleaveFamilies(t *testing.T) {
	input := []net.IPAddr{
		{IP: net.ParseIP("2001:db8::1")},
		{IP: net.ParseIP("2001:db8::2")},
		{IP: net.ParseIP("192.0.2.1")},
		{IP: net.ParseIP("192.0.2.2")},
	}
	got := interleaveWebH3Addresses(input)
	want := []string{"2001:db8::1", "192.0.2.1", "2001:db8::2", "192.0.2.2"}
	if len(got) != len(want) {
		t.Fatalf("interleaved addresses = %v", got)
	}
	for index := range want {
		if got[index].IP.String() != want[index] {
			t.Fatalf("interleaved address %d = %s, want %s", index, got[index].IP, want[index])
		}
	}
}

func TestWebH3AddressRaceFallsBackAcrossFamilies(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	server, err := ListenWebH3(WebH3ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
		Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("unexpected destination dial")
		}),
		Cover: http.NotFoundHandler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	serveWebH3ForTest(t, server)
	client, err := NewWebH3Client(WebH3ClientConfig{
		ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
		DialTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	_, service, err := net.SplitHostPort(server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.DefaultResolver.LookupPort(context.Background(), "udp", service)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	session, err := client.dialSessionAddresses(ctx, []net.IPAddr{
		{IP: net.ParseIP("::1")},
		{IP: net.ParseIP("127.0.0.1")},
	}, port)
	if err != nil {
		t.Fatal(err)
	}
	if remote, ok := session.conn.RemoteAddr().(*net.UDPAddr); !ok || remote.IP.To4() == nil {
		t.Fatalf("winning H3 remote = %v, want IPv4 fallback", session.conn.RemoteAddr())
	}
	_ = session.conn.CloseWithError(0, "test complete")
	if err := session.closeResources(); err != nil {
		t.Fatal(err)
	}
}

func TestWebH3DefaultChromeInitialWireShape(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	server, err := ListenWebH3(WebH3ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
		Dialer: transport.DialFunc((&net.Dialer{}).DialContext), Cover: http.NotFoundHandler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	serveWebH3ForTest(t, server)

	proxy, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	serverAddress, err := net.ResolveUDPAddr("udp4", server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	firstClientDatagram := make(chan []byte, 1)
	proxyErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, 64<<10)
		var clientAddress *net.UDPAddr
		for {
			n, source, readErr := proxy.ReadFromUDP(buffer)
			if readErr != nil {
				if errors.Is(readErr, net.ErrClosed) {
					return
				}
				proxyErr <- readErr
				return
			}
			payload := append([]byte(nil), buffer[:n]...)
			if source.Port == serverAddress.Port && source.IP.Equal(serverAddress.IP) {
				if clientAddress != nil {
					if _, writeErr := proxy.WriteToUDP(payload, clientAddress); writeErr != nil {
						proxyErr <- writeErr
						return
					}
				}
				continue
			}
			if clientAddress == nil {
				clientAddress = &net.UDPAddr{IP: append(net.IP(nil), source.IP...), Port: source.Port, Zone: source.Zone}
				firstClientDatagram <- payload
			}
			if _, writeErr := proxy.WriteToUDP(payload, serverAddress); writeErr != nil {
				proxyErr <- writeErr
				return
			}
		}
	}()

	client, err := NewWebH3Client(WebH3ClientConfig{
		ServerAddress: proxy.LocalAddr().String(), Token: webTestToken, TLSConfig: clientTLS,
		DialTimeout: time.Second, HandshakeTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _, dialErr := client.connection(ctx)
	if dialErr != nil {
		t.Fatal(dialErr)
	}

	var initial []byte
	select {
	case initial = <-firstClientDatagram:
	case err := <-proxyErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(context.Cause(ctx))
	}
	if len(initial) != 1250 {
		t.Fatalf("Chrome Initial UDP datagram bytes = %d, want 1250", len(initial))
	}
	if len(initial) < 7 || initial[0]&0x80 == 0 {
		t.Fatalf("first Chrome datagram is not a QUIC long header: %x", initial[:min(len(initial), 16)])
	}
	destinationCIDLength := int(initial[5])
	sourceCIDOffset := 6 + destinationCIDLength
	if destinationCIDLength != 8 || sourceCIDOffset >= len(initial) {
		t.Fatalf("Chrome Initial destination CID length = %d", destinationCIDLength)
	}
	if sourceCIDLength := int(initial[sourceCIDOffset]); sourceCIDLength != 0 {
		t.Fatalf("Chrome Initial source CID length = %d, want 0", sourceCIDLength)
	}
}

func TestWebH3ChromeProfileRejectsUnsupportedTLSCallbackEarly(t *testing.T) {
	_, clientTLS := testTLSConfigs(t)
	clientTLS.VerifyConnection = func(tls.ConnectionState) error { return nil }
	_, err := NewWebH3Client(WebH3ClientConfig{
		ServerAddress: "127.0.0.1:443",
		Token:         webTestToken,
		TLSConfig:     clientTLS,
	})
	if err == nil || !strings.Contains(err.Error(), "VerifyConnection") {
		t.Fatalf("unsupported Chrome H3 TLS callback error = %v", err)
	}
}

func TestWebH3WrongCredentialFallsThroughToCoverWithoutDial(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	var dials atomic.Int32
	cover := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("cover observed proxy credential")
		}
		w.Header().Set("X-Cover", "same")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "not found")
	})
	server, err := ListenWebH3(WebH3ServerConfig{
		Address:   "127.0.0.1:0",
		Token:     webTestToken,
		TLSConfig: serverTLS,
		Dialer:    countingDialer{dials: &dials},
		Cover:     cover,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = server.Serve(ctx) }()
	t.Cleanup(func() { cancel(); _ = server.Close() })

	wrongKey, err := deriveWebAuthKey("different-web-cover-token-32-bytes")
	if err != nil {
		t.Fatal(err)
	}
	binding := webAuthBinding{transport: webAuthTransportH3, method: http.MethodConnect, authority: "127.0.0.1:9"}
	bearer, err := newWebAuthSigner(wrongKey, nil, nil).bearer(binding, webAuthClaims{})
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := clientTLS.Clone()
	tlsConfig.NextProtos = []string{http3.NextProtoH3}
	roundTripper := &http3.Transport{TLSClientConfig: tlsConfig}
	defer roundTripper.Close()
	req := mustWebRequest(t, http.MethodConnect, "https://"+server.Addr().String(), nil)
	req.Host = binding.authority
	req.Header.Set("Proxy-Authorization", bearer)
	response, err := roundTripper.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotFound || response.Header.Get("X-Cover") != "same" || string(body) != "not found" {
		t.Fatalf("wrong-auth response = status %d headers %v body %q", response.StatusCode, response.Header, body)
	}
	if dials.Load() != 0 {
		t.Fatalf("wrong credential made %d destination dials", dials.Load())
	}
}

func TestWebH3CanceledOpeningStreamDoesNotCloseSiblingTunnels(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	target, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	blocked := make(chan struct{})
	var blockedOnce sync.Once
	dialer := transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "blocked.example:443" {
			blockedOnce.Do(func() { close(blocked) })
			<-ctx.Done()
			return nil, context.Cause(ctx)
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	})
	server, err := ListenWebH3(WebH3ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
		Dialer: dialer, Cover: http.NotFoundHandler(), MaxConcurrentStreams: 8,
		DialTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	serveWebH3ForTest(t, server)
	client, err := NewWebH3Client(WebH3ClientConfig{
		ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
		DialTimeout: time.Second, HandshakeTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	// Establish the one connection-level bootstrap before testing independent
	// continuation-stream cancellation. A bootstrap stream intentionally gates
	// every sibling until its server proof is known.
	if err := exchange(client, target, "bootstrap-before-cancel-test"); err != nil {
		t.Fatalf("establish connection authentication: %v", err)
	}

	openingContext, cancelOpening := context.WithCancel(context.Background())
	openingDone := make(chan error, 1)
	go func() {
		_, err := client.DialContext(openingContext, "tcp", "blocked.example:443")
		openingDone <- err
	}()
	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked destination dial did not start")
	}
	if err := exchange(client, target, "sibling-before-cancel"); err != nil {
		t.Fatalf("sibling tunnel while another stream opens: %v", err)
	}
	cancelOpening()
	select {
	case err := <-openingDone:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled opening stream error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled opening stream did not return")
	}
	if err := exchange(client, target, "sibling-after-cancel"); err != nil {
		t.Fatalf("connection did not survive sibling cancellation: %v", err)
	}
}

func TestWebH3CanceledBootstrapReauthenticatesReplacementConnection(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	target, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	bootstrapDialStarted := make(chan struct{})
	var bootstrapOnce sync.Once
	var destinationDials atomic.Int32
	dialer := transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		destinationDials.Add(1)
		if address == "blocked.example:443" {
			bootstrapOnce.Do(func() { close(bootstrapDialStarted) })
			<-ctx.Done()
			return nil, context.Cause(ctx)
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	})
	server, err := ListenWebH3(WebH3ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
		Dialer: dialer, Cover: http.NotFoundHandler(), MaxConcurrentStreams: 8,
		DialTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	serveWebH3ForTest(t, server)
	client, err := NewWebH3Client(WebH3ClientConfig{
		ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
		DialTimeout: time.Second, HandshakeTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	entropy := &webH2AuthEntropyCounter{}
	client.signer = newWebAuthSigner(mustWebAuthKey(t, webTestToken), nil, entropy)

	bootstrapContext, cancelBootstrap := context.WithCancel(context.Background())
	bootstrapDone := make(chan error, 1)
	go func() {
		connection, err := client.DialContext(bootstrapContext, "tcp", "blocked.example:443")
		if connection != nil {
			_ = connection.Close()
		}
		bootstrapDone <- err
	}()
	select {
	case <-bootstrapDialStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("bootstrap destination dial did not start")
	}
	client.mu.Lock()
	firstSession := client.conns[client.conn]
	client.mu.Unlock()
	if firstSession == nil || firstSession.authState != webH3ClientAuthBootstrapping {
		t.Fatal("first QUIC connection was not in bootstrap state")
	}

	siblingDone := make(chan error, 1)
	go func() { siblingDone <- exchange(client, target, "waiter-after-canceled-bootstrap") }()
	time.Sleep(25 * time.Millisecond)
	if got := destinationDials.Load(); got != 1 {
		t.Fatalf("bootstrap waiter reached destination before authentication resolved: dials=%d", got)
	}
	if got := entropy.nonceReads.Load(); got != 1 {
		t.Fatalf("full authentication tickets before cancellation = %d, want 1", got)
	}

	cancelBootstrap()
	select {
	case err := <-bootstrapDone:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled bootstrap error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled bootstrap did not return")
	}
	select {
	case err := <-siblingDone:
		if err != nil {
			t.Fatalf("bootstrap waiter did not recover on replacement connection: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("bootstrap waiter did not complete on replacement connection")
	}
	client.mu.Lock()
	secondSession := client.conns[client.conn]
	client.mu.Unlock()
	if secondSession == nil || secondSession == firstSession || secondSession.authState != webH3ClientAuthReady {
		t.Fatal("canceled bootstrap did not create an authenticated replacement QUIC connection")
	}
	if got := entropy.nonceReads.Load(); got != 2 {
		t.Fatalf("full authentication tickets after replacement = %d, want one per two physical connections", got)
	}
}

type countingDialer struct{ dials *atomic.Int32 }

func (d countingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.dials.Add(1)
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func startWebTCPEcho(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String()
}

func mustWebRequest(t *testing.T, method, rawURL string, body io.Reader) *http.Request {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	request := &http.Request{Method: method, URL: parsed, Host: parsed.Host, Header: make(http.Header)}
	if body != nil {
		request.Body = io.NopCloser(body)
	}
	return request
}

var _ transportDialerForWebTest = countingDialer{}

type transportDialerForWebTest interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}
