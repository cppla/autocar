package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/transport"
	"golang.org/x/net/http2"
)

func TestWebH2EndToEndMultiplexesFullDuplexConnectStreams(t *testing.T) {
	targetAddress, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	serverTLS, clientTLS := testTLSConfigs(t)

	var outboundDials atomic.Int64
	outbound := transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		outboundDials.Add(1)
		if network != "tcp" {
			t.Errorf("outbound network = %q, want tcp", network)
		}
		if address != targetAddress {
			t.Errorf("outbound address = %q, want %q", address, targetAddress)
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	})
	var coverRequests atomic.Int64
	server := startWebH2TestServer(t, WebH2ServerConfig{
		Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
		Cover: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			coverRequests.Add(1)
			_, _ = io.WriteString(w, "ordinary cover")
		}),
		Dialer: outbound,
	})
	entropy := &webH2AuthEntropyCounter{}
	key := mustWebAuthKey(t, testToken)
	client, err := newWebH2ClientWithSigner(WebH2ClientConfig{
		ServerAddress: server.Addr().String(),
		Token:         testToken,
		TLSConfig:     clientTLS,
	}, newWebAuthSigner(key, nil, entropy), webAuthClaims{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	const streams = 16
	start := make(chan struct{})
	errorsCh := make(chan error, streams)
	var wg sync.WaitGroup
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := exchange(client, targetAddress, "web-h2-payload"); err != nil {
				errorsCh <- errors.New("stream exchange failed: " + err.Error())
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Error(err)
	}
	if got := outboundDials.Load(); got != streams {
		t.Fatalf("outbound dials = %d, want %d", got, streams)
	}
	if got := coverRequests.Load(); got != 0 {
		t.Fatalf("authenticated CONNECT requests delegated to cover = %d", got)
	}
	if got := client.SelectedTransport(); got != webH2ALPN {
		t.Fatalf("SelectedTransport = %q, want h2", got)
	}
	if got := entropy.nonceReads.Load(); got != 1 {
		t.Fatalf("full authentication tickets = %d, want exactly one per physical connection", got)
	}

	client.mu.Lock()
	if len(client.sessions) != 1 || client.current == nil {
		client.mu.Unlock()
		t.Fatalf("HTTP/2 sessions/current = %d/%v, want one warm session", len(client.sessions), client.current != nil)
	}
	state := client.current.conn.ConnectionState()
	client.mu.Unlock()
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != webH2ALPN {
		t.Fatalf("TLS version/ALPN = %#x/%q, want TLS 1.3/h2", state.Version, state.NegotiatedProtocol)
	}
}

func TestWebH2GOAwayOpensNewAuthenticatedConnection(t *testing.T) {
	targetAddress, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	serverTLS, clientTLS := testTLSConfigs(t)
	server := startWebH2TestServer(t, WebH2ServerConfig{
		Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
		Cover: http.NotFoundHandler(),
		Dialer: transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}),
	})
	entropy := &webH2AuthEntropyCounter{}
	key := mustWebAuthKey(t, testToken)
	client, err := newWebH2ClientWithSigner(WebH2ClientConfig{
		ServerAddress: server.Addr().String(), Token: testToken, TLSConfig: clientTLS,
	}, newWebAuthSigner(key, nil, entropy), webAuthClaims{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	if err := exchange(client, targetAddress, "before-goaway"); err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	first := client.current
	client.mu.Unlock()
	if first == nil || first.authState != webH2ClientAuthReady {
		t.Fatal("first physical connection was not authenticated")
	}
	// SetDoNotReuse is the ClientConn state transition used when a GOAWAY is
	// received. Existing streams may drain, but the next request must bootstrap
	// a distinct physical connection.
	first.h2.SetDoNotReuse()
	if err := exchange(client, targetAddress, "after-goaway"); err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	second := client.current
	client.mu.Unlock()
	if second == nil || second == first || second.authState != webH2ClientAuthReady {
		t.Fatal("GOAWAY did not select and authenticate a new physical connection")
	}
	if got := entropy.nonceReads.Load(); got != 2 {
		t.Fatalf("full authentication tickets after GOAWAY = %d, want one on each of two connections", got)
	}
}

func TestWebH2AuthenticatedBootstrapErrorKeepsConnectionSession(t *testing.T) {
	targetAddress, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	serverTLS, clientTLS := testTLSConfigs(t)
	var dials atomic.Int64
	server := startWebH2TestServer(t, WebH2ServerConfig{
		Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
		Cover: http.NotFoundHandler(),
		Dialer: transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			if dials.Add(1) == 1 {
				return nil, errors.New("synthetic first destination failure")
			}
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}),
	})
	entropy := &webH2AuthEntropyCounter{}
	key := mustWebAuthKey(t, testToken)
	client, err := newWebH2ClientWithSigner(WebH2ClientConfig{
		ServerAddress: server.Addr().String(), Token: testToken, TLSConfig: clientTLS,
	}, newWebAuthSigner(key, nil, entropy), webAuthClaims{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	first, err := client.DialContext(context.Background(), "tcp", targetAddress)
	if first != nil {
		_ = first.Close()
	}
	var connectErr *WebConnectError
	if !errors.As(err, &connectErr) || connectErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("first CONNECT error = %v, want authenticated 502", err)
	}
	client.mu.Lock()
	firstSession := client.current
	client.mu.Unlock()
	if firstSession == nil || firstSession.authState != webH2ClientAuthReady {
		t.Fatal("authenticated bootstrap error did not install the connection session")
	}
	if err := exchange(client, targetAddress, "after-authenticated-error"); err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	secondSession := client.current
	client.mu.Unlock()
	if secondSession != firstSession {
		t.Fatal("authenticated bootstrap error unnecessarily replaced the physical connection")
	}
	if got := entropy.nonceReads.Load(); got != 1 {
		t.Fatalf("full authentication tickets = %d, want one across authenticated 502 and retry", got)
	}
}

func TestWebH2BootstrapFailureClosesConnectionAndUnblocksWaiters(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	var (
		coverRequests atomic.Int64
		targetDials   atomic.Int64
	)
	firstCover := make(chan struct{})
	releaseFirstCover := make(chan struct{})
	var firstCoverOnce sync.Once
	server := startWebH2TestServer(t, WebH2ServerConfig{
		Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
		Cover: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			coverRequests.Add(1)
			first := false
			firstCoverOnce.Do(func() {
				first = true
				close(firstCover)
			})
			if first {
				<-releaseFirstCover
			}
			w.WriteHeader(http.StatusNotFound)
		}),
		Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
			targetDials.Add(1)
			return nil, errors.New("unauthenticated request reached destination dialer")
		}),
	})
	entropy := &webH2AuthEntropyCounter{}
	wrongKey := mustWebAuthKey(t, "fedcba9876543210fedcba9876543210")
	client, err := newWebH2ClientWithSigner(WebH2ClientConfig{
		ServerAddress: server.Addr().String(),
		Token:         "fedcba9876543210fedcba9876543210",
		TLSConfig:     clientTLS,
	}, newWebAuthSigner(wrongKey, nil, entropy), webAuthClaims{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	const requests = 8
	start := make(chan struct{})
	errorsCh := make(chan error, requests)
	var wg sync.WaitGroup
	for range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx, "tcp", "example.com:443")
			if conn != nil {
				_ = conn.Close()
			}
			errorsCh <- err
		}()
	}
	close(start)
	select {
	case <-firstCover:
	case <-time.After(2 * time.Second):
		t.Fatal("first invalid bootstrap did not reach cover")
	}
	// All siblings must still be waiting behind the one full-auth leader.
	time.Sleep(25 * time.Millisecond)
	if got := entropy.nonceReads.Load(); got != 1 {
		t.Fatalf("full authentication tickets before leader completion = %d, want 1", got)
	}
	close(releaseFirstCover)
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err == nil {
			t.Error("invalid bootstrap unexpectedly succeeded")
		}
	}
	if got := targetDials.Load(); got != 0 {
		t.Fatalf("invalid authentication destination dials = %d, want 0", got)
	}
	if got := coverRequests.Load(); got != requests {
		t.Fatalf("cover requests = %d, want %d real cover responses", got, requests)
	}
	client.mu.Lock()
	current := client.current
	sessions := len(client.sessions)
	client.mu.Unlock()
	if current != nil || sessions != 0 {
		t.Fatalf("failed bootstrap retained current/session = %v/%d", current != nil, sessions)
	}
}

func TestWebH2BootstrapFailureRacesClientClose(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	coverStarted := make(chan struct{})
	releaseCover := make(chan struct{})
	server := startWebH2TestServer(t, WebH2ServerConfig{
		Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
		Cover: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			close(coverStarted)
			<-releaseCover
			w.WriteHeader(http.StatusNotFound)
		}),
		Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("invalid bootstrap reached destination dialer")
		}),
	})
	wrongToken := "fedcba9876543210fedcba9876543210"
	client, err := NewWebH2Client(WebH2ClientConfig{
		ServerAddress: server.Addr().String(), Token: wrongToken, TLSConfig: clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	dialDone := make(chan error, 1)
	go func() {
		conn, dialErr := client.DialContext(context.Background(), "tcp", "example.com:443")
		if conn != nil {
			_ = conn.Close()
		}
		dialDone <- dialErr
	}()
	select {
	case <-coverStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("invalid bootstrap did not reach cover")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- client.Close() }()
	close(releaseCover)
	select {
	case dialErr := <-dialDone:
		if dialErr == nil {
			t.Error("invalid bootstrap unexpectedly succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bootstrap dial deadlocked while client closed")
	}
	select {
	case closeErr := <-closeDone:
		if closeErr != nil {
			t.Fatal(closeErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client Close deadlocked with failed bootstrap")
	}
}

func TestWebH2StandardRoundTripperCarriesAuthenticatedConnect(t *testing.T) {
	targetAddress, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	serverTLS, clientTLS := testTLSConfigs(t)
	var dials atomic.Int64
	server := startWebH2TestServer(t, WebH2ServerConfig{
		Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
		Cover: http.NotFoundHandler(),
		Dialer: transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}),
	})
	key := mustWebAuthKey(t, testToken)
	binding := webAuthBinding{transport: webAuthTransportH2, method: http.MethodConnect, authority: targetAddress}
	bearer := mustWebAuthBearer(t, key, time.Now(), bytes.Repeat([]byte{0x61}, webAuthNonceBytes), binding, webAuthClaims{})
	endpoint, err := url.Parse("https://" + server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    endpoint,
		Host:   targetAddress,
		Header: http.Header{"Proxy-Authorization": []string{bearer}},
		Body:   http.NoBody,
	}
	h2 := &http2.Transport{TLSClientConfig: clientTLS}
	defer h2.CloseIdleConnections()
	response, err := h2.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || dials.Load() != 1 {
		t.Fatalf("standard HTTP/2 CONNECT result = status %d dials %d", response.StatusCode, dials.Load())
	}
}

func TestWebH2ServerServesOrdinaryH2AndHTTP11CoverRequests(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	type observed struct {
		proto int
		path  string
		auth  string
	}
	requests := make(chan observed, 2)
	var tunnelDials atomic.Int64
	server := startWebH2TestServer(t, WebH2ServerConfig{
		Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
		Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests <- observed{proto: r.ProtoMajor, path: r.URL.Path, auth: r.Header.Get("Proxy-Authorization")}
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "ordinary cover")
		}),
		Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
			tunnelDials.Add(1)
			return nil, errors.New("unexpected dial")
		}),
	})

	h2Transport := http.DefaultTransport.(*http.Transport).Clone()
	h2Transport.TLSClientConfig = clientTLS.Clone()
	h2Transport.ForceAttemptHTTP2 = true
	t.Cleanup(h2Transport.CloseIdleConnections)
	assertWebH2CoverResponse(t, &http.Client{Transport: h2Transport}, "https://"+server.Addr().String()+"/h2", 2, tls.VersionTLS13)

	h1TLS := clientTLS.Clone()
	h1TLS.NextProtos = []string{webHTTP11ALPN}
	h1TLS.MinVersion = tls.VersionTLS12
	h1TLS.MaxVersion = tls.VersionTLS12
	h1Transport := http.DefaultTransport.(*http.Transport).Clone()
	h1Transport.TLSClientConfig = h1TLS
	h1Transport.ForceAttemptHTTP2 = false
	h1Transport.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
	t.Cleanup(h1Transport.CloseIdleConnections)
	assertWebH2CoverResponse(t, &http.Client{Transport: h1Transport}, "https://"+server.Addr().String()+"/h1", 1, tls.VersionTLS12)

	seen := map[string]int{}
	for range 2 {
		select {
		case request := <-requests:
			if request.auth != "" {
				t.Fatalf("cover observed Proxy-Authorization = %q", request.auth)
			}
			seen[request.path] = request.proto
		case <-time.After(time.Second):
			t.Fatal("cover handler did not observe request")
		}
	}
	if seen["/h2"] != 2 || seen["/h1"] != 1 {
		t.Fatalf("cover protocols = %v, want /h2=2 and /h1=1", seen)
	}
	if got := tunnelDials.Load(); got != 0 {
		t.Fatalf("ordinary cover requests reached tunnel dialer %d times", got)
	}
}

func TestWebH2ConnContextScopesAuthenticationToPhysicalTLSConnection(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	type observation struct {
		path string
		conn *tls.Conn
		auth *webServerConnectionAuth
	}
	observed := make(chan observation, 3)
	server := startWebH2TestServer(t, WebH2ServerConfig{
		Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
		Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			connection, _ := r.Context().Value(webTLSConnectionContextKey{}).(*tls.Conn)
			auth, _ := r.Context().Value(webServerConnectionAuthContextKey{}).(*webServerConnectionAuth)
			observed <- observation{path: r.URL.Path, conn: connection, auth: auth}
			_, _ = io.WriteString(w, "cover")
		}),
		Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("ordinary cover request reached destination dialer")
		}),
	})

	first := &http2.Transport{TLSClientConfig: clientTLS.Clone()}
	defer first.CloseIdleConnections()
	second := &http2.Transport{TLSClientConfig: clientTLS.Clone()}
	defer second.CloseIdleConnections()
	requestCover := func(transport *http2.Transport, path string) {
		t.Helper()
		request, err := http.NewRequest(http.MethodGet, "https://"+server.Addr().String()+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := transport.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("read/close cover response: %v/%v", readErr, closeErr)
		}
	}
	requestCover(first, "/one")
	requestCover(first, "/two")
	requestCover(second, "/three")

	byPath := make(map[string]observation, 3)
	for range 3 {
		select {
		case item := <-observed:
			byPath[item.path] = item
		case <-time.After(time.Second):
			t.Fatal("cover observation timed out")
		}
	}
	one, two, three := byPath["/one"], byPath["/two"], byPath["/three"]
	if one.conn == nil || one.auth == nil || two.conn == nil || two.auth == nil || three.conn == nil || three.auth == nil {
		t.Fatal("ConnContext omitted the TLS connection or its authentication state")
	}
	if one.conn != two.conn || one.auth != two.auth {
		t.Fatal("requests on one HTTP/2 connection did not share connection authentication state")
	}
	if one.conn == three.conn || one.auth == three.auth {
		t.Fatal("distinct physical TLS connections shared authentication state")
	}
}

func TestWebH2TLS12ConnectAlwaysFallsThroughToCover(t *testing.T) {
	var dials atomic.Int64
	core, err := newServerCore(testToken, transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("unexpected destination dial")
	}), time.Second, time.Second, 1)
	if err != nil {
		t.Fatal(err)
	}
	key := mustWebAuthKey(t, testToken)
	verifier := mustWebAuthVerifier(t, key, time.Now, 8)
	var covers atomic.Int64
	handler := &webTunnelHandler{
		auth: verifier,
		core: core,
		cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			covers.Add(1)
			if got := r.Header.Get("Proxy-Authorization"); got != "" {
				t.Errorf("TLS 1.2 cover observed tunnel credential %q", got)
			}
			w.WriteHeader(http.StatusTeapot)
		}),
	}
	target := "example.com:443"
	binding := webAuthBinding{transport: webAuthTransportH2, method: http.MethodConnect, authority: target}
	header := mustWebAuthBearer(t, key, time.Now(), bytes.Repeat([]byte{0x72}, webAuthNonceBytes), binding, webAuthClaims{})
	request := httptest.NewRequest(http.MethodConnect, "https://cover.example/", nil)
	request.ProtoMajor = 2
	request.ProtoMinor = 0
	request.Host = target
	request.URL.Path = ""
	request.Header.Set("Proxy-Authorization", header)
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS12}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusTeapot || covers.Load() != 1 || dials.Load() != 0 {
		t.Fatalf("TLS 1.2 CONNECT result = status %d covers %d dials %d", response.Code, covers.Load(), dials.Load())
	}
}

func TestWebH2DialContextCancellationDoesNotOwnEstablishedStream(t *testing.T) {
	targetAddress, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	serverTLS, clientTLS := testTLSConfigs(t)
	server := startWebH2TestServer(t, WebH2ServerConfig{
		Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
		Cover: http.NotFoundHandler(),
		Dialer: transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}),
	})
	client, err := NewWebH2Client(WebH2ClientConfig{
		ServerAddress: server.Addr().String(), Token: testToken, TLSConfig: clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	dialCtx, cancelDial := context.WithCancel(context.Background())
	conn, err := client.DialContext(dialCtx, "tcp", targetAddress)
	if err != nil {
		cancelDial()
		t.Fatal(err)
	}
	cancelDial()
	if err := completeExchange(conn, "survives-dial-context"); err != nil {
		t.Fatalf("established stream after dial context cancellation: %v", err)
	}
}

func TestWebH2AuthenticationMissAndReplayAreCoverTrafficWithoutDial(t *testing.T) {
	var dials atomic.Int64
	core, err := newServerCore(testToken, transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("test destination unavailable")
	}), time.Second, time.Second, 1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := deriveWebAuthKey(testToken)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := newWebAuthVerifier(key, nil, 8)
	if err != nil {
		t.Fatal(err)
	}
	var covers atomic.Int64
	cover := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		covers.Add(1)
		if got := r.Header.Get("Proxy-Authorization"); got != "" {
			t.Errorf("cover observed tunnel credential %q", got)
		}
		w.WriteHeader(http.StatusTeapot)
	})
	handler := &webTunnelHandler{auth: verifier, core: core, cover: cover}
	target := "example.com:443"

	for _, test := range []struct {
		name   string
		header string
	}{
		{name: "missing"},
		{name: "wrong", header: "Bearer not-a-valid-ticket"},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, newWebH2ConnectRequest(target, test.header))
			if response.Code != http.StatusTeapot {
				t.Fatalf("status = %d, want cover status 418", response.Code)
			}
		})
	}
	if got := dials.Load(); got != 0 {
		t.Fatalf("unauthenticated destination dials = %d, want 0", got)
	}

	signer := newWebAuthSigner(key, nil, nil)
	bearer, err := signer.bearer(webAuthBinding{
		transport: webAuthTransportH2,
		method:    http.MethodConnect,
		authority: target,
	}, webAuthClaims{})
	if err != nil {
		t.Fatal(err)
	}
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, newWebH2ConnectRequest(target, bearer))
	if first.Code != http.StatusBadGateway {
		t.Fatalf("first authenticated status = %d, want 502", first.Code)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("first authenticated destination dials = %d, want 1", got)
	}

	replay := httptest.NewRecorder()
	handler.ServeHTTP(replay, newWebH2ConnectRequest(target, bearer))
	if replay.Code != http.StatusTeapot {
		t.Fatalf("replay status = %d, want cover status 418", replay.Code)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("replay caused destination dial; dials = %d, want 1", got)
	}
	if got := covers.Load(); got != 3 {
		t.Fatalf("cover requests = %d, want missing + wrong + replay", got)
	}
}

func TestWebH2AdmissionPrecedesDestinationDial(t *testing.T) {
	var dials atomic.Int64
	core, err := newServerCore(testToken, transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("unexpected dial")
	}), time.Second, time.Second, 1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := deriveWebAuthKey(testToken)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := newWebAuthVerifier(key, nil, 8)
	if err != nil {
		t.Fatal(err)
	}
	handler := &webTunnelHandler{auth: verifier, core: core, cover: http.NotFoundHandler()}
	core.sem <- struct{}{}
	defer func() { <-core.sem }()

	target := "example.com:443"
	bearer, err := newWebAuthSigner(key, nil, nil).bearer(webAuthBinding{
		transport: webAuthTransportH2,
		method:    http.MethodConnect,
		authority: target,
	}, webAuthClaims{})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, newWebH2ConnectRequest(target, bearer))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("busy status = %d, want 503", response.Code)
	}
	if got := dials.Load(); got != 0 {
		t.Fatalf("busy request destination dials = %d, want 0", got)
	}
}

func TestWebH2ClientValidationAndClose(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	if _, err := ListenWebH2(WebH2ServerConfig{
		Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
		Cover: http.NotFoundHandler(),
	}); err == nil || !strings.Contains(err.Error(), "policy-enforcing destination dialer") {
		t.Fatalf("nil destination dialer error = %v", err)
	}
	if _, err := NewWebH2Client(WebH2ClientConfig{
		ServerAddress: "127.0.0.1:443",
		Token:         testToken,
		TLSConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // rejection test
	}); err == nil || !strings.Contains(err.Error(), "InsecureSkipVerify") {
		t.Fatalf("InsecureSkipVerify error = %v", err)
	}
	client, err := NewWebH2Client(WebH2ClientConfig{
		ServerAddress: "127.0.0.1:443",
		Token:         testToken,
		TLSConfig:     clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.DialContext(context.Background(), "udp", "example.com:443"); err == nil {
		t.Fatal("UDP network was accepted")
	}
	if _, err := client.DialContext(context.Background(), "tcp", "missing-port.example"); !errors.Is(err, protocol.ErrBadAddress) {
		t.Fatalf("invalid authority error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DialContext(context.Background(), "tcp", "example.com:443"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("DialContext after Close error = %v, want net.ErrClosed", err)
	}
}

func TestWebH2SessionGateHonorsCanceledContext(t *testing.T) {
	_, clientTLS := testTLSConfigs(t)
	client, err := NewWebH2Client(WebH2ClientConfig{
		ServerAddress: "127.0.0.1:443", Token: testToken, TLSConfig: clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.dialGate <- struct{}{}
	defer func() { <-client.dialGate }()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = client.reserveSession(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked session gate error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("canceled gate wait took %s", elapsed)
	}
}

func TestWebClientsBoundResponseHeaders(t *testing.T) {
	_, clientTLS := testTLSConfigs(t)
	h2, err := NewWebH2Client(WebH2ClientConfig{
		ServerAddress: "127.0.0.1:443", Token: testToken, TLSConfig: clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h2.Close()
	if got := h2.transport.MaxHeaderListSize; got != defaultWebClientMaxResponseHeaderBytes {
		t.Fatalf("H2 response header limit = %d", got)
	}
	h3, err := NewWebH3Client(WebH3ClientConfig{
		ServerAddress: "127.0.0.1:443", Token: testToken, TLSConfig: clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h3.Close()
	if got := h3.transport.MaxResponseHeaderBytes; got != defaultWebClientMaxResponseHeaderBytes {
		t.Fatalf("H3 response header limit = %d", got)
	}
}

func startWebH2TestServer(t *testing.T, config WebH2ServerConfig) *WebH2Server {
	t.Helper()
	server, err := ListenWebH2(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("web-cover HTTP/2 Serve: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("web-cover HTTP/2 server did not stop")
		}
	})
	return server
}

func assertWebH2CoverResponse(t *testing.T, client *http.Client, endpoint string, wantProtocol int, wantTLS uint16) {
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
	if response.ProtoMajor != wantProtocol || string(body) != "ordinary cover" {
		t.Fatalf("cover protocol/body = %d/%q, want %d/%q", response.ProtoMajor, body, wantProtocol, "ordinary cover")
	}
	if response.TLS == nil || response.TLS.Version != wantTLS {
		t.Fatalf("cover TLS state/version = %v, want %#x", response.TLS, wantTLS)
	}
}

func newWebH2ConnectRequest(authority, bearer string) *http.Request {
	request := httptest.NewRequest(http.MethodConnect, "https://cover.invalid/", nil)
	request.Proto = "HTTP/2.0"
	request.ProtoMajor = 2
	request.ProtoMinor = 0
	request.Host = authority
	request.URL = &url.URL{Host: authority}
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	if bearer != "" {
		request.Header.Set("Proxy-Authorization", bearer)
	}
	return request
}

// webH2AuthEntropyCounter supplies deterministic test entropy while counting
// the 16-byte nonce read that occurs exactly once for each full authentication
// ticket. Continuation tickets are deterministic and never consult this
// reader, making the counter an integration-level assertion that concurrent
// streams use connection authentication.
type webH2AuthEntropyCounter struct {
	reads      atomic.Uint64
	nonceReads atomic.Int64
}

func (r *webH2AuthEntropyCounter) Read(p []byte) (int, error) {
	sequence := r.reads.Add(1)
	if len(p) == webAuthNonceBytes {
		r.nonceReads.Add(1)
	}
	for i := range p {
		p[i] = byte(sequence + uint64(i))
	}
	return len(p), nil
}
