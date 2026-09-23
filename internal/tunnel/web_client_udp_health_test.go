package tunnel

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

func assertWebPrimaryFailureGeneration(t *testing.T, client *WebClient, generation uint64) {
	t.Helper()
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.primaryFailedAt.IsZero() || client.primaryStateID != generation {
		t.Fatalf("H3 failure changed without a new authenticated response: failed=%v generation=%d, want %d",
			client.primaryFailedAt, client.primaryStateID, generation)
	}
}

func markWebPrimaryFailed(t *testing.T, client *WebClient, now time.Time) uint64 {
	t.Helper()
	client.mu.Lock()
	client.nextPrimaryID++
	generation := client.nextPrimaryID
	client.mu.Unlock()
	if !client.recordPrimaryFailure(generation, now) {
		t.Fatal("could not record H3 failure")
	}
	return generation
}

func TestWebClientBufferedUDPSendDoesNotRecoverFailedH3Circuit(t *testing.T) {
	clock := newWebClientTestClock(time.Unix(600, 0))
	basePrimary := &webClientTestDialer{dial: func(context.Context, int64, string, string) (net.Conn, error) {
		return nil, errors.New("H3 path unreachable")
	}}
	// Exercise the real cached-target Send path. There is deliberately no
	// sender goroutine or peer: successful Send can only enqueue locally.
	session := &webUDPClientSession{done: make(chan struct{}), outbound: make(chan []byte, 1)}
	inner := &webUDPPacketConn{sessions: map[string]*webUDPClientSession{"example.com:53": session}}
	primary := &webClientTestPacketDialer{webClientTestDialer: basePrimary, packet: inner}
	fallback := &webClientTestDialer{dial: func(context.Context, int64, string, string) (net.Conn, error) {
		return closedWebClientTestConn(), nil
	}}
	client, err := newWebClientWithPaths(
		webClientPath{name: webAuthTransportH3, dialer: primary},
		webClientPath{name: webAuthTransportH2, dialer: fallback},
		time.Second, time.Minute, clock.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	first, err := client.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	client.mu.Lock()
	generation := client.primaryStateID
	client.mu.Unlock()
	packet, err := client.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertWebPrimaryFailureGeneration(t, client, generation)
	if err := packet.Send([]byte("buffered only"), "example.com:53"); err != nil {
		t.Fatal(err)
	}
	if len(session.outbound) != 1 {
		t.Fatal("datagram was not locally buffered")
	}
	assertWebPrimaryFailureGeneration(t, client, generation)
	if err := packet.Send([]byte("queue full"), "example.com:53"); !errors.Is(err, transport.ErrPacketQueueFull) {
		t.Fatalf("full local queue error = %v", err)
	}
	assertWebPrimaryFailureGeneration(t, client, generation)
	second, err := client.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = second.Close()
	if got := basePrimary.calls.Load(); got != 1 {
		t.Fatalf("local UDP enqueue reopened failed H3 circuit: primary calls=%d, want 1 before cooldown", got)
	}
	if got := client.SelectedTransport(); got != webAuthTransportH2 {
		t.Fatalf("local UDP enqueue changed selected transport to %q", got)
	}
}

func TestWebClientH3UDPOnlyNewAuthenticatedResponseRecoversCircuit(t *testing.T) {
	target := startWebUDPEcho(t)
	resolver := newWebUDPTestResolver(map[string]netip.AddrPort{target.String(): target})
	h3 := newWebH3RetirementClient(t, 4, nil, resolver)
	fallback := &webClientTestDialer{dial: func(context.Context, int64, string, string) (net.Conn, error) {
		return closedWebClientTestConn(), nil
	}}
	clock := newWebClientTestClock(time.Unix(700, 0))
	client, err := newWebClientWithPaths(
		webClientPath{name: webAuthTransportH3, dialer: h3},
		webClientPath{name: webAuthTransportH2, dialer: fallback},
		time.Second, time.Minute, clock.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	generation := markWebPrimaryFailed(t, client, clock.Now())
	packet, err := client.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packet.Close() })
	assertWebPrimaryFailureGeneration(t, client, generation)
	assertWebUDPEcho(t, packet, []byte("new authenticated CONNECT-UDP"), target.String())
	client.mu.Lock()
	recovered := client.primaryFailedAt.IsZero() && client.primaryStateID > generation
	client.mu.Unlock()
	if !recovered || client.SelectedTransport() != webAuthTransportH3 {
		t.Fatal("new authenticated H3 UDP response did not recover the circuit")
	}
	generation = markWebPrimaryFailed(t, client, clock.Now())
	assertWebUDPEcho(t, packet, []byte("same cached target"), target.String())
	assertWebPrimaryFailureGeneration(t, client, generation)
	// A newly authenticated target rejection still proves path health, without
	// selecting that failed target as a successful H3 stream.
	fallbackConn, err := client.dialFallback(context.Background(), "tcp", "example.com:443", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = fallbackConn.Close()
	err = packet.Send([]byte("reject target"), "missing.example:53")
	var rejection *WebConnectError
	if !errors.As(err, &rejection) {
		t.Fatalf("expected authenticated H3 target rejection, got %v", err)
	}
	if !errors.Is(err, transport.ErrPacketTargetUnavailable) {
		t.Fatalf("authenticated target failure was terminal for the packet association: %v", err)
	}
	client.mu.Lock()
	recovered = client.primaryFailedAt.IsZero() && client.primaryStateID > generation
	client.mu.Unlock()
	if !recovered || client.SelectedTransport() != webAuthTransportH2 {
		t.Fatal("authenticated target rejection did not restore health while preserving H2 selection")
	}
}

func TestWebClientH3UDPAuthenticationFailureDoesNotRecoverCircuit(t *testing.T) {
	good := newWebH3RetirementClient(t, 4, nil, newWebUDPTestResolver(map[string]netip.AddrPort{}))
	h3, err := NewWebH3Client(WebH3ClientConfig{
		ServerAddress: good.address, Token: webTestToken + "-wrong", TLSConfig: good.tlsConfig,
		FingerprintProfile: H3FingerprintNative, DialTimeout: time.Second, HandshakeTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h3.Close() })
	fallback := &webClientTestDialer{dial: func(context.Context, int64, string, string) (net.Conn, error) {
		return closedWebClientTestConn(), nil
	}}
	clock := newWebClientTestClock(time.Unix(800, 0))
	client, err := newWebClientWithPaths(
		webClientPath{name: webAuthTransportH3, dialer: h3},
		webClientPath{name: webAuthTransportH2, dialer: fallback},
		time.Second, time.Minute, clock.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	generation := markWebPrimaryFailed(t, client, clock.Now())
	packet, err := client.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packet.Close() })
	if err := packet.Send([]byte("wrong credential"), "missing.example:53"); err == nil || errors.Is(err, transport.ErrPacketTargetUnavailable) {
		t.Fatalf("incorrect credentials accepted or mislabeled as a recoverable target failure: %v", err)
	}
	assertWebPrimaryFailureGeneration(t, client, generation)
}
