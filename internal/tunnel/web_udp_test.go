package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/cppla/autocar/internal/transport"
)

func TestConnectUDPDefaultTemplateAndContextEncoding(t *testing.T) {
	path, target, err := connectUDPPath("[2001:0db8::1]:0053")
	if err != nil {
		t.Fatal(err)
	}
	if want := "/.well-known/masque/udp/2001%3Adb8%3A%3A1/53/"; path != want {
		t.Fatalf("CONNECT-UDP path = %q, want %q", path, want)
	}
	if want := "[2001:db8::1]:53"; target != want {
		t.Fatalf("canonical target = %q, want %q", target, want)
	}
	parsed, err := parseConnectUDPPath(path)
	if err != nil || parsed != target {
		t.Fatalf("parsed target = %q, %v, want %q", parsed, err, target)
	}

	for _, invalid := range []string{
		"/.well-known/masque/udp/example.test/53",
		"/.well-known/masque/udp/example.test/0/",
		"/.well-known/masque/udp/example.test/not-a-port/",
		"/.well-known/masque/udp/example.test/53/extra/",
		"/.well-known/masque/udp/example%2Ftest/53/",
	} {
		if _, err := parseConnectUDPPath(invalid); err == nil {
			t.Errorf("parseConnectUDPPath(%q) succeeded", invalid)
		}
	}

	payload := []byte("standard CONNECT-UDP payload")
	frame := encodeConnectUDPDatagram(payload)
	if len(frame) != len(payload)+1 || frame[0] != 0 {
		t.Fatalf("context-prefixed frame = %x", frame)
	}
	decoded, ok := parseConnectUDPDatagram(frame)
	if !ok || !bytes.Equal(decoded, payload) {
		t.Fatalf("decoded datagram = %x, %v", decoded, ok)
	}
	unknown := quicvarint.Append(nil, 1)
	unknown = append(unknown, payload...)
	if _, ok := parseConnectUDPDatagram(unknown); ok {
		t.Fatal("non-zero CONNECT-UDP context ID was accepted")
	}
}

func TestWebH3ConnectUDPUsesOneStreamPerTarget(t *testing.T) {
	firstEcho := startWebUDPEcho(t)
	secondEcho := startWebUDPEcho(t)
	firstTarget := "first.example:" + strconv.Itoa(int(firstEcho.Port()))
	secondTarget := "second.example:" + strconv.Itoa(int(secondEcho.Port()))
	resolver := newWebUDPTestResolver(map[string]netip.AddrPort{
		firstTarget:  firstEcho,
		secondTarget: secondEcho,
	})
	server, client := startWebUDPTestPair(t, resolver, WebH3ServerConfig{
		MaxUDPSessions:       4,
		MaxClientUDPSessions: 4,
		MaxUDPDestinations:   2,
		UDPReceiveQueue:      4,
	}, WebH3ClientConfig{
		MaxUDPSessions:     4,
		MaxUDPDestinations: 2,
		UDPReceiveQueue:    4,
	})
	entropy := &webH2AuthEntropyCounter{}
	key := mustWebAuthKey(t, webTestToken)
	client.signer = newWebAuthSigner(key, nil, entropy)

	packet, err := client.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()

	assertWebUDPEcho(t, packet, []byte("first-1"), firstTarget)
	assertWebUDPEcho(t, packet, []byte("first-2"), firstTarget)
	assertWebUDPEcho(t, packet, []byte("second"), secondTarget)

	if got := resolver.count(firstTarget); got != 1 {
		t.Fatalf("first target resolved %d times, want one stream-local resolution", got)
	}
	if got := resolver.count(secondTarget); got != 1 {
		t.Fatalf("second target resolved %d times, want one stream-local resolution", got)
	}
	if got := entropy.nonceReads.Load(); got != 1 {
		t.Fatalf("full authentication tickets = %d, want one across both CONNECT-UDP streams", got)
	}
	handler := server.server.Handler.(*webTunnelHandler)
	if got := len(handler.udp.slots); got != 2 {
		t.Fatalf("live server CONNECT-UDP sessions = %d, want one per target", got)
	}

	if err := packet.Close(); err != nil {
		t.Fatal(err)
	}
	eventuallyWebUDP(t, func() bool { return len(handler.udp.slots) == 0 }, "server sessions were not released")
}

func TestWebH3ConnectionAuthIsSharedAcrossTCPAndConnectUDP(t *testing.T) {
	for _, test := range []struct {
		name     string
		udpFirst bool
	}{
		{name: "tcp_then_udp"},
		{name: "udp_then_tcp", udpFirst: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			tcpTarget, closeTCPTarget := startHalfCloseTarget(t)
			defer closeTCPTarget()
			udpEcho := startWebUDPEcho(t)
			udpTarget := "mixed.example:" + strconv.Itoa(int(udpEcho.Port()))
			resolver := newWebUDPTestResolver(map[string]netip.AddrPort{udpTarget: udpEcho})
			serverTLS, clientTLS := testTLSConfigs(t)
			var tcpDials atomic.Int32
			server, err := ListenWebH3(WebH3ServerConfig{
				Address:              "127.0.0.1:0",
				Token:                webTestToken,
				TLSConfig:            serverTLS,
				Dialer:               countingDialer{dials: &tcpDials},
				Cover:                http.NotFoundHandler(),
				UDPResolver:          resolver,
				MaxUDPSessions:       2,
				MaxClientUDPSessions: 2,
				MaxUDPDestinations:   1,
				UDPReceiveQueue:      2,
			})
			if err != nil {
				t.Fatal(err)
			}
			serveWebH3ForTest(t, server)
			client, err := NewWebH3Client(WebH3ClientConfig{
				ServerAddress:      server.Addr().String(),
				Token:              webTestToken,
				TLSConfig:          clientTLS,
				DialTimeout:        time.Second,
				HandshakeTimeout:   2 * time.Second,
				MaxUDPSessions:     2,
				MaxUDPDestinations: 1,
				UDPReceiveQueue:    2,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			entropy := &webH2AuthEntropyCounter{}
			client.signer = newWebAuthSigner(mustWebAuthKey(t, webTestToken), nil, entropy)

			var packet transport.PacketConn
			openTCP := func() {
				t.Helper()
				if err := exchange(client, tcpTarget, "cross-protocol-auth"); err != nil {
					t.Fatal(err)
				}
			}
			openUDP := func() {
				t.Helper()
				packet, err = client.DialPacket(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				assertWebUDPEcho(t, packet, []byte("cross-protocol-auth"), udpTarget)
			}

			if test.udpFirst {
				openUDP()
			} else {
				openTCP()
			}
			client.mu.Lock()
			firstConnection := client.conn
			firstSession := client.conns[firstConnection]
			client.mu.Unlock()
			if firstConnection == nil || firstSession == nil || firstSession.authState != webH3ClientAuthReady {
				t.Fatal("first protocol did not establish connection authentication")
			}

			if test.udpFirst {
				openTCP()
			} else {
				openUDP()
			}
			client.mu.Lock()
			secondConnection := client.conn
			secondSession := client.conns[secondConnection]
			client.mu.Unlock()
			if secondConnection != firstConnection || secondSession != firstSession {
				t.Fatal("TCP CONNECT and CONNECT-UDP did not share one physical QUIC connection")
			}
			if got := entropy.nonceReads.Load(); got != 1 {
				t.Fatalf("full authentication tickets = %d, want one across TCP CONNECT and CONNECT-UDP", got)
			}
			firstSession.auth.mu.Lock()
			nextSequence := firstSession.auth.nextSequence
			firstSession.auth.mu.Unlock()
			if nextSequence != 2 {
				t.Fatalf("next continuation sequence = %d, want 2 after one bootstrap and one short ticket", nextSequence)
			}
			if got := tcpDials.Load(); got != 1 {
				t.Fatalf("TCP destination dials = %d, want 1", got)
			}
			if got := resolver.count(udpTarget); got != 1 {
				t.Fatalf("UDP target resolutions = %d, want 1", got)
			}
			if packet != nil {
				if err := packet.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestWebH3ConnectionAuthSurvivesClientPathMigration(t *testing.T) {
	tcpTarget, closeTCPTarget := startHalfCloseTarget(t)
	defer closeTCPTarget()
	udpEcho := startWebUDPEcho(t)
	udpTarget := "migrated.example:" + strconv.Itoa(int(udpEcho.Port()))
	resolver := newWebUDPTestResolver(map[string]netip.AddrPort{udpTarget: udpEcho})
	serverTLS, clientTLS := testTLSConfigs(t)
	var tcpDials atomic.Int32
	server, err := ListenWebH3(WebH3ServerConfig{
		Address:              "127.0.0.1:0",
		Token:                webTestToken,
		TLSConfig:            serverTLS,
		Dialer:               countingDialer{dials: &tcpDials},
		Cover:                http.NotFoundHandler(),
		UDPResolver:          resolver,
		MaxUDPSessions:       1,
		MaxClientUDPSessions: 1,
		MaxUDPDestinations:   1,
		UDPReceiveQueue:      2,
	})
	if err != nil {
		t.Fatal(err)
	}
	serveWebH3ForTest(t, server)
	client, err := NewWebH3Client(WebH3ClientConfig{
		ServerAddress:      server.Addr().String(),
		Token:              webTestToken,
		TLSConfig:          clientTLS,
		FingerprintProfile: H3FingerprintNative,
		DialTimeout:        time.Second,
		HandshakeTimeout:   2 * time.Second,
		MaxUDPSessions:     1,
		MaxUDPDestinations: 1,
		UDPReceiveQueue:    2,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	entropy := &webH2AuthEntropyCounter{}
	client.signer = newWebAuthSigner(mustWebAuthKey(t, webTestToken), nil, entropy)

	// Bootstrap through CONNECT-UDP first. Receiving the echoed datagram also
	// proves that HTTP/3 SETTINGS and the datagram receive loop finished before
	// the test asks quic-go to mutate the active path.
	packet, err := client.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertWebUDPEcho(t, packet, []byte("before-migration"), udpTarget)
	if err := packet.Close(); err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	physicalConnection := client.conn
	session := client.conns[physicalConnection]
	client.mu.Unlock()
	if physicalConnection == nil || session == nil || session.authState != webH3ClientAuthReady {
		t.Fatal("CONNECT-UDP did not establish connection authentication before migration")
	}
	// Wait until the HTTP/3 control stream has consumed SETTINGS before asking
	// quic-go to switch paths.  The migration API mutates the active path, while
	// control-stream initialization reads ConnectionState; overlapping those two
	// operations exercises an upstream initialization race instead of the
	// connection-authentication behavior this test is meant to cover.
	settingsContext, cancelSettings := context.WithTimeout(context.Background(), 2*time.Second)
	err = waitWebH3DatagramSettings(settingsContext, session.client)
	cancelSettings()
	if err != nil {
		t.Fatal(err)
	}
	originalAddress := physicalConnection.LocalAddr().String()

	migratedSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	migratedTransport := &quic.Transport{Conn: migratedSocket}
	t.Cleanup(func() {
		// Close the logical connection before its active transport. Client.Close
		// is idempotent, so the earlier cleanup remains safe.
		_ = client.Close()
		_ = migratedTransport.Close()
		_ = migratedSocket.Close()
	})
	path, err := physicalConnection.AddPath(migratedTransport)
	if err != nil {
		t.Fatal(err)
	}
	probeContext, cancelProbe := context.WithTimeout(context.Background(), 2*time.Second)
	err = path.Probe(probeContext)
	cancelProbe()
	if err != nil {
		t.Fatal(err)
	}
	if err := path.Switch(); err != nil {
		t.Fatal(err)
	}

	if err := exchange(client, tcpTarget, "after-migration"); err != nil {
		t.Fatal(err)
	}
	if got := physicalConnection.LocalAddr().String(); got == originalAddress || got != migratedSocket.LocalAddr().String() {
		t.Fatalf("migrated local address = %q, original %q, new socket %q", got, originalAddress, migratedSocket.LocalAddr())
	}

	client.mu.Lock()
	currentConnection := client.conn
	currentSession := client.conns[currentConnection]
	client.mu.Unlock()
	if currentConnection != physicalConnection || currentSession != session {
		t.Fatal("path migration replaced the physical QUIC connection or its authentication state")
	}
	if got := entropy.nonceReads.Load(); got != 1 {
		t.Fatalf("full authentication tickets = %d, want one before and after path migration", got)
	}
	session.auth.mu.Lock()
	nextSequence := session.auth.nextSequence
	session.auth.mu.Unlock()
	if nextSequence != 2 {
		t.Fatalf("next continuation sequence = %d, want 2 after migrated short ticket", nextSequence)
	}
	if got := tcpDials.Load(); got != 1 {
		t.Fatalf("TCP destination dials = %d, want 1", got)
	}
	if got := resolver.count(udpTarget); got != 1 {
		t.Fatalf("UDP target resolutions = %d, want 1", got)
	}
}

func TestWebH3ConnectUDPInteroperatesWithRawRFC9298Request(t *testing.T) {
	echo := startWebUDPEcho(t)
	target := "raw.example:" + strconv.Itoa(int(echo.Port()))
	resolver := newWebUDPTestResolver(map[string]netip.AddrPort{target: echo})
	serverTLS, clientTLS := testTLSConfigs(t)
	server, err := ListenWebH3(WebH3ServerConfig{
		Address:              "127.0.0.1:0",
		Token:                webTestToken,
		TLSConfig:            serverTLS,
		Dialer:               unusedWebUDPDialer(),
		Cover:                http.NotFoundHandler(),
		UDPResolver:          resolver,
		MaxUDPSessions:       2,
		MaxClientUDPSessions: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	serveWebH3ForTest(t, server)

	clientTLS.NextProtos = []string{http3.NextProtoH3}
	quicConfig := &quic.Config{EnableDatagrams: true}
	connection, err := quic.DialAddr(context.Background(), server.Addr().String(), clientTLS, quicConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.CloseWithError(0, "") })
	h3Transport := &http3.Transport{EnableDatagrams: true}
	t.Cleanup(func() { _ = h3Transport.Close() })
	h3Client := h3Transport.NewClientConn(connection)
	if err := waitWebH3DatagramSettings(context.Background(), h3Client); err != nil {
		t.Fatal(err)
	}

	path, canonicalTarget, err := connectUDPPath(target)
	if err != nil {
		t.Fatal(err)
	}
	key, err := deriveWebAuthKey(webTestToken)
	if err != nil {
		t.Fatal(err)
	}
	binding := webAuthBinding{
		transport: webAuthTransportH3,
		method:    http.MethodConnect,
		protocol:  webConnectUDPProtocol,
		authority: server.Addr().String(),
		path:      path,
	}
	bearer, err := newWebAuthSigner(key, nil, nil).bearer(binding, webAuthClaims{})
	if err != nil {
		t.Fatal(err)
	}
	request := newConnectUDPTestRequest(t, server.Addr().String(), path, bearer)
	stream, err := h3Client.OpenRequestStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		_ = stream.Close()
	}()
	if err := stream.SendRequestHeader(request); err != nil {
		t.Fatal(err)
	}
	response, err := stream.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get(webCapsuleProtocolHeader) != webCapsuleProtocolValue {
		t.Fatalf("raw CONNECT-UDP response = %d, %v", response.StatusCode, response.Header)
	}

	payload := []byte("raw RFC 9298 datagram")
	if err := stream.SendDatagram(encodeConnectUDPDatagram(payload)); err != nil {
		t.Fatal(err)
	}
	receiveContext, cancelReceive := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelReceive()
	frame, err := stream.ReceiveDatagram(receiveContext)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := parseConnectUDPDatagram(frame)
	if !ok || !bytes.Equal(got, payload) {
		t.Fatalf("raw RFC 9298 echo = %q, %v", got, ok)
	}
	if resolver.count(canonicalTarget) != 1 {
		t.Fatalf("raw request resolved %q %d times", canonicalTarget, resolver.count(canonicalTarget))
	}
}

func TestWebH3ConnectUDPAuthenticatesBeforePathAndResolution(t *testing.T) {
	var resolverCalls atomic.Int32
	resolver := UDPResolverFunc(func(context.Context, string) ([]netip.AddrPort, error) {
		resolverCalls.Add(1)
		return nil, errors.New("must not be called")
	})
	var coverCalls atomic.Int32
	serverTLS, clientTLS := testTLSConfigs(t)
	server, err := ListenWebH3(WebH3ServerConfig{
		Address:     "127.0.0.1:0",
		Token:       webTestToken,
		TLSConfig:   serverTLS,
		Dialer:      unusedWebUDPDialer(),
		UDPResolver: resolver,
		Cover: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			coverCalls.Add(1)
			if request.Header.Get("Proxy-Authorization") != "" {
				t.Error("cover handler observed CONNECT-UDP credential")
			}
			writer.Header().Set("X-Cover", "ordinary")
			writer.WriteHeader(http.StatusNotFound)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	serveWebH3ForTest(t, server)

	quicConfig := &quic.Config{EnableDatagrams: true}
	clientTLS.NextProtos = []string{http3.NextProtoH3}
	roundTripper := &http3.Transport{
		TLSClientConfig: clientTLS,
		QUICConfig:      quicConfig,
		EnableDatagrams: true,
	}
	t.Cleanup(func() { _ = roundTripper.Close() })

	malformedPath := "/not-a-masque-template"
	wrong := newConnectUDPTestRequest(t, server.Addr().String(), malformedPath, "Bearer invalid")
	response, err := roundTripper.RoundTrip(wrong)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotFound || response.Header.Get("X-Cover") != "ordinary" {
		t.Fatalf("unauthenticated malformed response = %d, %v", response.StatusCode, response.Header)
	}
	if resolverCalls.Load() != 0 || coverCalls.Load() != 1 {
		t.Fatalf("unauthenticated request resolver/cover calls = %d/%d", resolverCalls.Load(), coverCalls.Load())
	}

	key, err := deriveWebAuthKey(webTestToken)
	if err != nil {
		t.Fatal(err)
	}
	binding := webAuthBinding{
		transport: webAuthTransportH3,
		method:    http.MethodConnect,
		protocol:  webConnectUDPProtocol,
		authority: server.Addr().String(),
		path:      malformedPath,
	}
	bearer, err := newWebAuthSigner(key, nil, nil).bearer(binding, webAuthClaims{})
	if err != nil {
		t.Fatal(err)
	}
	authenticated := newConnectUDPTestRequest(t, server.Addr().String(), malformedPath, bearer)
	response, err = roundTripper.RoundTrip(authenticated)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("authenticated malformed response = %d, want 400", response.StatusCode)
	}
	if resolverCalls.Load() != 0 {
		t.Fatalf("malformed authenticated path made %d resolver calls", resolverCalls.Load())
	}
}

func TestWebH3ConnectUDPCapacityAndCloseUnblocksReceive(t *testing.T) {
	firstEcho := startWebUDPEcho(t)
	secondEcho := startWebUDPEcho(t)
	firstTarget := "first.example:" + strconv.Itoa(int(firstEcho.Port()))
	secondTarget := "second.example:" + strconv.Itoa(int(secondEcho.Port()))
	resolver := newWebUDPTestResolver(map[string]netip.AddrPort{
		firstTarget:  firstEcho,
		secondTarget: secondEcho,
	})
	_, client := startWebUDPTestPair(t, resolver, WebH3ServerConfig{
		MaxUDPSessions:       4,
		MaxClientUDPSessions: 4,
	}, WebH3ClientConfig{
		MaxUDPSessions:     1,
		MaxUDPDestinations: 1,
		UDPReceiveQueue:    1,
	})
	packet, err := client.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertWebUDPEcho(t, packet, []byte("capacity"), firstTarget)
	if err := packet.Send([]byte("rejected"), secondTarget); !errors.Is(err, ErrUDPDestinationCapacity) {
		t.Fatalf("second target error = %v, want %v", err, ErrUDPDestinationCapacity)
	}

	receiveDone := make(chan error, 1)
	go func() {
		_, _, err := packet.Receive()
		receiveDone <- err
	}()
	if err := packet.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-receiveDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Receive after Close = %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock Receive")
	}
}

func TestWebH3ConnectUDPClientGlobalSessionLimit(t *testing.T) {
	echo := startWebUDPEcho(t)
	target := "echo.example:" + strconv.Itoa(int(echo.Port()))
	resolver := newWebUDPTestResolver(map[string]netip.AddrPort{target: echo})
	_, client := startWebUDPTestPair(t, resolver, WebH3ServerConfig{
		MaxUDPSessions:       4,
		MaxClientUDPSessions: 4,
	}, WebH3ClientConfig{MaxUDPSessions: 1, MaxUDPDestinations: 1})
	first, err := client.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := client.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	assertWebUDPEcho(t, first, []byte("reserved"), target)
	if err := second.Send([]byte("over capacity"), target); !errors.Is(err, ErrUDPSessionCapacity) {
		t.Fatalf("second PacketConn Send = %v, want %v", err, ErrUDPSessionCapacity)
	}
}

func TestWebH3ConnectUDPConfigValidation(t *testing.T) {
	_, clientTLS := testTLSConfigs(t)
	base := WebH3ClientConfig{
		ServerAddress: "127.0.0.1:443",
		Token:         webTestToken,
		TLSConfig:     clientTLS,
	}
	bad := base
	bad.MaxUDPSessions = -1
	if _, err := NewWebH3Client(bad); err == nil {
		t.Fatal("negative MaxUDPSessions was accepted")
	}
	bad = base
	bad.MaxUDPSessions = 1
	bad.MaxUDPDestinations = 2
	if _, err := NewWebH3Client(bad); err == nil {
		t.Fatal("per-PacketConn target limit above global session limit was accepted")
	}
	bad = base
	bad.UDPReceiveQueue = -1
	if _, err := NewWebH3Client(bad); err == nil {
		t.Fatal("negative UDPReceiveQueue was accepted")
	}
}

func TestWebUDPClientSendQueueIsBoundedAndCopiesPayload(t *testing.T) {
	done := make(chan struct{})
	session := &webUDPClientSession{
		outbound: make(chan []byte, 1),
		done:     done,
	}
	payload := []byte("first")
	if err := session.send(payload); err != nil {
		t.Fatal(err)
	}
	payload[0] = 'X'
	if err := session.send([]byte("second")); !errors.Is(err, transport.ErrPacketQueueFull) {
		t.Fatalf("full send queue error = %v", err)
	}
	frame := <-session.outbound
	got, ok := parseConnectUDPDatagram(frame)
	if !ok || string(got) != "first" {
		t.Fatalf("queued datagram = %q, parsed=%v", got, ok)
	}
	close(done)
}

type webUDPTestResolver struct {
	mu      sync.Mutex
	targets map[string]netip.AddrPort
	calls   map[string]int
}

func newWebUDPTestResolver(targets map[string]netip.AddrPort) *webUDPTestResolver {
	return &webUDPTestResolver{targets: targets, calls: make(map[string]int)}
}

func (r *webUDPTestResolver) ResolveUDPContext(_ context.Context, address string) ([]netip.AddrPort, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls[address]++
	target, ok := r.targets[address]
	if !ok {
		return nil, fmt.Errorf("unexpected test target %q", address)
	}
	return []netip.AddrPort{target}, nil
}

func (r *webUDPTestResolver) count(address string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[address]
}

func startWebUDPTestPair(t *testing.T, resolver UDPResolver, serverOverrides WebH3ServerConfig, clientOverrides WebH3ClientConfig) (*WebH3Server, *WebH3Client) {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	serverOverrides.Address = "127.0.0.1:0"
	serverOverrides.Token = webTestToken
	serverOverrides.TLSConfig = serverTLS
	serverOverrides.Dialer = unusedWebUDPDialer()
	serverOverrides.Cover = http.NotFoundHandler()
	serverOverrides.UDPResolver = resolver
	serverOverrides.HandshakeTimeout = 2 * time.Second
	serverOverrides.DialTimeout = time.Second
	server, err := ListenWebH3(serverOverrides)
	if err != nil {
		t.Fatal(err)
	}
	serveWebH3ForTest(t, server)

	clientOverrides.ServerAddress = server.Addr().String()
	clientOverrides.Token = webTestToken
	clientOverrides.TLSConfig = clientTLS
	clientOverrides.DialTimeout = time.Second
	clientOverrides.HandshakeTimeout = 2 * time.Second
	client, err := NewWebH3Client(clientOverrides)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return server, client
}

func serveWebH3ForTest(t *testing.T, server *WebH3Server) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("web H3 server did not stop")
		}
	})
}

func unusedWebUDPDialer() transport.Dialer {
	return transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("TCP dial is not expected in CONNECT-UDP test")
	})
}

func startWebUDPEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		buffer := make([]byte, 2048)
		for {
			count, source, err := listener.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			_, _ = listener.WriteToUDPAddrPort(buffer[:count], source)
		}
	}()
	return listener.LocalAddr().(*net.UDPAddr).AddrPort()
}

func assertWebUDPEcho(t *testing.T, packet transport.PacketConn, payload []byte, target string) {
	t.Helper()
	if err := packet.Send(payload, target); err != nil {
		t.Fatal(err)
	}
	receive := make(chan packetResult, 1)
	go func() {
		got, address, err := packet.Receive()
		if err != nil {
			receive <- packetResult{address: err.Error()}
			return
		}
		receive <- packetResult{payload: got, address: address}
	}()
	select {
	case result := <-receive:
		if !bytes.Equal(result.payload, payload) || result.address != target {
			t.Fatalf("UDP echo = %q from %q, want %q from %q", result.payload, result.address, payload, target)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for CONNECT-UDP echo")
	}
}

func newConnectUDPTestRequest(t *testing.T, authority, path, bearer string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodConnect, "https://"+authority+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Proto = webConnectUDPProtocol
	request.Host = authority
	request.Header.Set(webCapsuleProtocolHeader, webCapsuleProtocolValue)
	request.Header.Set("Proxy-Authorization", bearer)
	return request
}

func eventuallyWebUDP(t *testing.T, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(message)
}
