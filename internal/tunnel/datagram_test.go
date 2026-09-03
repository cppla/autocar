package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	autodatagram "github.com/cppla/autocar/internal/datagram"
	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/transport"
)

func TestQUICDatagramLoopbackAndTCPRemainIndependent(t *testing.T) {
	echo := startUDPEcho(t, nil)
	targetAddress, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	serverTLS, clientTLS := testTLSConfigs(t)
	resolverDialer := &testUDPResolvingDialer{}
	server := startDatagramQUICServer(t, QUICServerConfig{
		Address:   "127.0.0.1:0",
		Token:     testToken,
		TLSConfig: serverTLS,
		Dialer:    resolverDialer,
	})
	client := newDatagramClient(t, server, clientTLS, ClientConfig{})
	defer client.Close()

	packetConn, err := client.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	if sized, ok := packetConn.(transport.PacketPayloadSizer); !ok || sized.MaxPayloadSize() != autodatagram.MaxPayloadSize {
		t.Fatalf("packet payload size = %T / %v", packetConn, ok)
	}

	payload := bytes.Repeat([]byte{0x5a}, autodatagram.MaxPayloadSize)
	if err := packetConn.Send(payload, echo.address); err != nil {
		t.Fatalf("send fragmented payload: %v", err)
	}
	reply := receivePacket(t, packetConn, 3*time.Second)
	if !bytes.Equal(reply.payload, payload) || reply.address != echo.address {
		t.Fatalf("UDP reply mismatch: bytes=%d address=%q", len(reply.payload), reply.address)
	}
	if resolverDialer.resolveCalls.Load() == 0 {
		t.Fatal("server did not prefer Dialer's UDPResolver capability")
	}

	if err := exchange(client, targetAddress, "TCP remains independent"); err != nil {
		t.Fatalf("TCP exchange while UDP association is open: %v", err)
	}
}

func TestQUICDatagramSessionsUseIndependentSocketsAndDispatcher(t *testing.T) {
	firstEcho := startUDPEcho(t, []byte("first:"))
	secondEcho := startUDPEcho(t, []byte("second:"))
	serverTLS, clientTLS := testTLSConfigs(t)
	server := startDatagramQUICServer(t, QUICServerConfig{
		Address:     "127.0.0.1:0",
		Token:       testToken,
		TLSConfig:   serverTLS,
		UDPResolver: numericUDPResolver(),
	})
	client := newDatagramClient(t, server, clientTLS, ClientConfig{})
	defer client.Close()

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
	firstInternal := first.(*quicPacketConn)
	secondInternal := second.(*quicPacketConn)
	if firstInternal.sessionID == 0 || secondInternal.sessionID == 0 || firstInternal.sessionID == secondInternal.sessionID {
		t.Fatalf("unsafe session IDs: %d and %d", firstInternal.sessionID, secondInternal.sessionID)
	}

	if err := first.Send([]byte("one"), firstEcho.address); err != nil {
		t.Fatal(err)
	}
	if err := second.Send([]byte("two"), secondEcho.address); err != nil {
		t.Fatal(err)
	}
	firstReply := receivePacket(t, first, 3*time.Second)
	secondReply := receivePacket(t, second, 3*time.Second)
	if string(firstReply.payload) != "first:one" || firstReply.address != firstEcho.address {
		t.Fatalf("first association received %+v", firstReply)
	}
	if string(secondReply.payload) != "second:two" || secondReply.address != secondEcho.address {
		t.Fatalf("second association received %+v", secondReply)
	}

	firstReceipt := echoReceiptWithin(t, firstEcho, 3*time.Second)
	secondReceipt := echoReceiptWithin(t, secondEcho, 3*time.Second)
	if firstReceipt.source == secondReceipt.source {
		t.Fatalf("sessions shared one outbound UDP socket: %s", firstReceipt.source)
	}
	client.udpMu.Lock()
	dispatcherCount := len(client.udpDispatchers)
	client.udpMu.Unlock()
	if dispatcherCount != 1 {
		t.Fatalf("connection dispatchers = %d, want 1", dispatcherCount)
	}
}

func TestQUICDatagramCloseUnblocksReceiveAndReleasesSession(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	server := startDatagramQUICServer(t, QUICServerConfig{
		Address:              "127.0.0.1:0",
		Token:                testToken,
		TLSConfig:            serverTLS,
		UDPResolver:          numericUDPResolver(),
		MaxUDPSessions:       1,
		MaxClientUDPSessions: 1,
	})
	client := newDatagramClient(t, server, clientTLS, ClientConfig{})
	defer client.Close()

	first, err := client.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.DialPacket(context.Background())
	var remoteErr *RemoteError
	if !errors.As(err, &remoteErr) || remoteErr.Status != protocol.StatusBusy || second != nil {
		t.Fatalf("second session: conn=%v err=%v", second, err)
	}

	receiveDone := asyncReceive(first)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-receiveDone:
		if !errors.Is(result.err, net.ErrClosed) {
			t.Fatalf("Receive after Close = %v", result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock Receive")
	}
	waitForCondition(t, 2*time.Second, func() bool { return len(server.udp.slots) == 0 }, "server UDP session release")

	replacement, err := client.DialPacket(context.Background())
	if err != nil {
		t.Fatalf("session after control FIN: %v", err)
	}
	defer replacement.Close()
}

func TestQUICDatagramConnectionCloseUnblocksReceive(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	server := startDatagramQUICServer(t, QUICServerConfig{
		Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
	})
	client := newDatagramClient(t, server, clientTLS, ClientConfig{})
	defer client.Close()
	packetConn, err := client.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	receiveDone := asyncReceive(packetConn)
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-receiveDone:
		if !errors.Is(result.err, net.ErrClosed) {
			t.Fatalf("Receive after connection close = %v", result.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("connection close did not unblock Receive")
	}
}

func TestQUICDatagramClientSessionLimit(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	server := startDatagramQUICServer(t, QUICServerConfig{
		Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
	})
	client := newDatagramClient(t, server, clientTLS, ClientConfig{MaxUDPSessions: 1})
	defer client.Close()
	first, err := client.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := client.DialPacket(context.Background())
	if !errors.Is(err, ErrUDPSessionCapacity) || second != nil {
		t.Fatalf("second client session: conn=%v err=%v", second, err)
	}
}

func TestQUICDatagramUnauthorizedAssociation(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	server := startDatagramQUICServer(t, QUICServerConfig{
		Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
	})
	client := newDatagramClient(t, server, clientTLS, ClientConfig{Token: "incorrect token value"})
	defer client.Close()
	packetConn, err := client.DialPacket(context.Background())
	var remoteErr *RemoteError
	if packetConn != nil || !errors.As(err, &remoteErr) || remoteErr.Status != protocol.StatusUnauthorized {
		t.Fatalf("unauthorized association: conn=%v err=%v", packetConn, err)
	}
	if got := len(server.udp.slots); got != 0 {
		t.Fatalf("unauthorized client acquired %d UDP slots", got)
	}
}

func TestQUICDatagramDropsUnsolicitedSource(t *testing.T) {
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	attacker, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer attacker.Close()
	serverTLS, clientTLS := testTLSConfigs(t)
	server := startDatagramQUICServer(t, QUICServerConfig{
		Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
		UDPResolver: numericUDPResolver(),
	})
	client := newDatagramClient(t, server, clientTLS, ClientConfig{})
	defer client.Close()
	packetConn, err := client.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()

	targetSource := make(chan *net.UDPAddr, 1)
	go func() {
		buffer := make([]byte, 64)
		_, source, readErr := target.ReadFromUDP(buffer)
		if readErr != nil {
			return
		}
		targetSource <- source
		_, _ = target.WriteToUDP([]byte("allowed-1"), source)
	}()
	if err := packetConn.Send([]byte("request"), target.LocalAddr().String()); err != nil {
		t.Fatal(err)
	}
	first := receivePacket(t, packetConn, 3*time.Second)
	if string(first.payload) != "allowed-1" || first.address != target.LocalAddr().String() {
		t.Fatalf("authorized response = %+v", first)
	}

	var relaySocket *net.UDPAddr
	select {
	case relaySocket = <-targetSource:
	case <-time.After(time.Second):
		t.Fatal("target did not report relay socket")
	}
	if _, err := attacker.WriteToUDP([]byte("unsolicited"), relaySocket); err != nil {
		t.Fatal(err)
	}
	pending := asyncReceive(packetConn)
	select {
	case result := <-pending:
		t.Fatalf("unsolicited source was relayed: %+v", result)
	case <-time.After(150 * time.Millisecond):
	}
	if _, err := target.WriteToUDP([]byte("allowed-2"), relaySocket); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-pending:
		if result.err != nil || string(result.payload) != "allowed-2" || result.address != target.LocalAddr().String() {
			t.Fatalf("authorized response after drop = %+v", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("authorized source did not pass after unsolicited drop")
	}
}

func TestQUICDatagramConfigValidation(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	serverTests := []QUICServerConfig{
		{MaxUDPSessions: -1},
		{MaxClientUDPSessions: -1},
		{MaxUDPDestinations: -1},
		{UDPReceiveQueue: -1},
		{UDPReassemblyTTL: -1},
		{MaxUDPReassemblyMessages: -1},
		{MaxUDPReassemblyBytes: -1},
		{MaxUDPSessions: 1, MaxClientUDPSessions: 2},
	}
	for _, overrides := range serverTests {
		overrides.Address = "127.0.0.1:0"
		overrides.Token = testToken
		overrides.TLSConfig = serverTLS
		if server, err := ListenQUIC(overrides); err == nil {
			_ = server.Close()
			t.Fatalf("server config accepted: %+v", overrides)
		}
	}

	clientTests := []ClientConfig{
		{MaxUDPSessions: -1},
		{UDPReceiveQueue: -1},
		{UDPReassemblyTTL: -1},
		{MaxUDPReassemblyMessages: -1},
		{MaxUDPReassemblyBytes: -1},
	}
	for _, overrides := range clientTests {
		overrides.ServerAddress = "127.0.0.1:443"
		overrides.Token = testToken
		overrides.TLSConfig = clientTLS
		if client, err := NewClient(overrides); err == nil {
			_ = client.Close()
			t.Fatalf("client config accepted: %+v", overrides)
		}
	}
}

func TestQUICDatagramCustomServerLimitsApplied(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	server, err := ListenQUIC(QUICServerConfig{
		Address:                  "127.0.0.1:0",
		Token:                    testToken,
		TLSConfig:                serverTLS,
		MaxUDPSessions:           11,
		MaxClientUDPSessions:     3,
		MaxUDPDestinations:       7,
		UDPReceiveQueue:          13,
		UDPReassemblyTTL:         17 * time.Second,
		MaxUDPReassemblyMessages: 19,
		MaxUDPReassemblyBytes:    23 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	if got := cap(server.udp.slots); got != 11 {
		t.Fatalf("global UDP sessions = %d, want 11", got)
	}
	if got := server.udp.clients.limit; got != 3 {
		t.Fatalf("per-source UDP sessions = %d, want 3", got)
	}
	config := server.udp.config
	if config.maxDestinations != 7 ||
		config.receiveQueue != 13 ||
		config.reassemblyTTL != 17*time.Second ||
		config.reassemblyMessages != 19 ||
		config.reassemblyBytes != 23<<10 {
		t.Fatalf("custom UDP limits not applied: %+v", config)
	}
}

type testUDPResolvingDialer struct {
	resolveCalls atomic.Int64
}

func (d *testUDPResolvingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (d *testUDPResolvingDialer) ResolveUDPContext(_ context.Context, address string) ([]netip.AddrPort, error) {
	d.resolveCalls.Add(1)
	parsed, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, err
	}
	return []netip.AddrPort{parsed}, nil
}

func numericUDPResolver() UDPResolver {
	return UDPResolverFunc(func(_ context.Context, address string) ([]netip.AddrPort, error) {
		parsed, err := netip.ParseAddrPort(address)
		if err != nil {
			return nil, err
		}
		return []netip.AddrPort{parsed}, nil
	})
}

type udpEchoServer struct {
	address  string
	conn     *net.UDPConn
	prefix   []byte
	receipts chan udpEchoReceipt
	done     chan struct{}
	once     sync.Once
}

type udpEchoReceipt struct {
	payload []byte
	source  netip.AddrPort
}

func startUDPEcho(t *testing.T, prefix []byte) *udpEchoServer {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	server := &udpEchoServer{
		address:  conn.LocalAddr().String(),
		conn:     conn,
		prefix:   append([]byte(nil), prefix...),
		receipts: make(chan udpEchoReceipt, 16),
		done:     make(chan struct{}),
	}
	go func() {
		defer close(server.done)
		buffer := make([]byte, autodatagram.MaxPayloadSize+1)
		for {
			n, source, err := conn.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			payload := append([]byte(nil), buffer[:n]...)
			select {
			case server.receipts <- udpEchoReceipt{payload: payload, source: source}:
			default:
			}
			reply := append(append([]byte(nil), server.prefix...), payload...)
			_, _ = conn.WriteToUDPAddrPort(reply, source)
		}
	}()
	t.Cleanup(func() { server.Close() })
	return server
}

func (s *udpEchoServer) Close() {
	s.once.Do(func() {
		_ = s.conn.Close()
		<-s.done
	})
}

func echoReceiptWithin(t *testing.T, server *udpEchoServer, timeout time.Duration) udpEchoReceipt {
	t.Helper()
	select {
	case receipt := <-server.receipts:
		return receipt
	case <-time.After(timeout):
		t.Fatal("timed out waiting for UDP echo receipt")
		return udpEchoReceipt{}
	}
}

type packetReceiveResult struct {
	payload []byte
	address string
	err     error
}

func asyncReceive(conn transport.PacketConn) <-chan packetReceiveResult {
	done := make(chan packetReceiveResult, 1)
	go func() {
		payload, address, err := conn.Receive()
		done <- packetReceiveResult{payload: payload, address: address, err: err}
	}()
	return done
}

func receivePacket(t *testing.T, conn transport.PacketConn, timeout time.Duration) packetReceiveResult {
	t.Helper()
	select {
	case result := <-asyncReceive(conn):
		if result.err != nil {
			t.Fatalf("Receive: %v", result.err)
		}
		return result
	case <-time.After(timeout):
		t.Fatal("timed out waiting for tunneled UDP response")
		return packetReceiveResult{}
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, condition func() bool, description string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func startDatagramQUICServer(t *testing.T, config QUICServerConfig) *QUICServer {
	t.Helper()
	server, err := ListenQUIC(config)
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
			t.Errorf("QUIC Serve: %v", err)
		}
	})
	return server
}

func newDatagramClient(t *testing.T, server *QUICServer, tlsConfig *tls.Config, overrides ClientConfig) *Client {
	t.Helper()
	overrides.ServerAddress = server.Addr().String()
	if overrides.Token == "" {
		overrides.Token = testToken
	}
	overrides.TLSConfig = tlsConfig
	client, err := NewClient(overrides)
	if err != nil {
		t.Fatal(err)
	}
	return client
}
