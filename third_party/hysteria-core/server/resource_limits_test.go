package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go"

	"github.com/apernet/hysteria/core/v2/internal/frag"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
)

type testAuthenticator struct{}

func (testAuthenticator) Authenticate(net.Addr, string, uint64) (bool, string) {
	return true, "test"
}

func TestPerSourceDefaultsRespectSmallGlobalLimits(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	config := &Config{
		TLSConfig:      TLSConfig{Certificates: []tls.Certificate{{}}},
		Conn:           packetConn,
		MaxConnections: 2,
		MaxTCPHandlers: 3,
		MaxUDPSessions: 4,
		Authenticator:  testAuthenticator{},
	}
	if err := config.fill(); err != nil {
		t.Fatal(err)
	}
	if config.MaxClientConnections != 2 || config.MaxClientTCPHandlers != 3 || config.MaxClientUDPSessions != 4 {
		t.Fatalf("per-source defaults = (%d, %d, %d), want (2, 3, 4)", config.MaxClientConnections, config.MaxClientTCPHandlers, config.MaxClientUDPSessions)
	}
}

func TestConnectionAdmissionCoversHandshakeLifecycle(t *testing.T) {
	slots := make(chan struct{}, 1)
	clients := newKeyedLimiter(1)
	firstContext, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	if _, err := admitConnection(firstContext, slots, clients, "192.0.2.10"); err != nil {
		t.Fatalf("first connection admission: %v", err)
	}
	if _, err := admitConnection(context.Background(), slots, clients, "192.0.2.11"); !errors.Is(err, errConnectionCapacity) {
		t.Fatalf("second connection admission error = %v, want capacity", err)
	}
	cancelFirst()
	deadline := time.Now().Add(time.Second)
	for len(slots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(slots) != 0 {
		t.Fatal("connection slot was not released when its context ended")
	}
	secondContext, cancelSecond := context.WithCancel(context.Background())
	defer cancelSecond()
	if _, err := admitConnection(secondContext, slots, clients, "192.0.2.11"); err != nil {
		t.Fatalf("released connection slot was not reusable: %v", err)
	}
}

func TestConnectionAdmissionLimitIsSharedAcrossSourceConnections(t *testing.T) {
	global := make(chan struct{}, 3)
	clients := newKeyedLimiter(1)
	firstContext, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	if _, err := admitConnection(firstContext, global, clients, "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	if _, err := admitConnection(context.Background(), global, clients, "192.0.2.10"); !errors.Is(err, errConnectionCapacity) {
		t.Fatalf("same-source connection error = %v, want capacity", err)
	}
	otherContext, cancelOther := context.WithCancel(context.Background())
	defer cancelOther()
	if _, err := admitConnection(otherContext, global, clients, "192.0.2.11"); err != nil {
		t.Fatalf("different source was rejected: %v", err)
	}
	if len(global) != 2 || clients.count("192.0.2.10") != 1 || clients.count("192.0.2.11") != 1 {
		t.Fatalf("unexpected admission state: global=%d first=%d other=%d", len(global), clients.count("192.0.2.10"), clients.count("192.0.2.11"))
	}

	cancelFirst()
	cancelOther()
	deadline := time.Now().Add(time.Second)
	for (len(global) != 0 || clients.count("192.0.2.10") != 0 || clients.count("192.0.2.11") != 0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(global) != 0 || clients.count("192.0.2.10") != 0 || clients.count("192.0.2.11") != 0 {
		t.Fatal("connection admission retained capacity or empty source entries")
	}
}

func TestSourceIPKeyGroupsIPv6PrefixAndIgnoresPort(t *testing.T) {
	first := &net.UDPAddr{IP: net.ParseIP("2001:db8:1234:5678::1"), Port: 443}
	second := &net.UDPAddr{IP: net.ParseIP("2001:db8:1234:5678:ffff::2"), Port: 8443}
	other := &net.UDPAddr{IP: net.ParseIP("2001:db8:1234:5679::1"), Port: 443}
	if sourceIPKey(first) != sourceIPKey(second) {
		t.Fatalf("same IPv6 /64 produced different keys: %q and %q", sourceIPKey(first), sourceIPKey(second))
	}
	if sourceIPKey(first) == sourceIPKey(other) {
		t.Fatalf("different IPv6 /64 prefixes shared key %q", sourceIPKey(first))
	}
	if got := sourceIPKey(&net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 443}); got != "192.0.2.10" {
		t.Fatalf("IPv4 key = %q, want address without port", got)
	}
}

func TestUDPSessionAdmissionPrecedesDefragmentation(t *testing.T) {
	ioMock := newMockUDPIO(t)
	events := newMockUDPEventLogger(t)
	global := make(chan struct{}, 1)
	first := newUDPSessionManager(ioMock, events, time.Minute, 1, global, "client-a", nil)
	second := newUDPSessionManager(ioMock, events, time.Minute, 1, global, "client-b", nil)

	incomplete := func(id uint32) *protocol.UDPMessage {
		return &protocol.UDPMessage{
			SessionID: id,
			PacketID:  1,
			FragID:    0,
			FragCount: 2,
			Addr:      "example.test:443",
			Data:      []byte("partial"),
		}
	}

	first.feed(incomplete(1))
	second.feed(incomplete(2))
	if got := first.Count(); got != 1 {
		t.Fatalf("first manager count = %d, want 1", got)
	}
	if got := second.Count(); got != 0 {
		t.Fatalf("global admission allowed second incomplete session: %d", got)
	}
	if got := len(global); got != 1 {
		t.Fatalf("global slots = %d, want 1", got)
	}

	events.EXPECT().Close(uint32(1), nil).Once()
	first.cleanup(false)
	second.feed(incomplete(2))
	if got := second.Count(); got != 1 {
		t.Fatalf("released slot was not reusable: count = %d", got)
	}
	events.EXPECT().Close(uint32(2), nil).Once()
	second.cleanup(false)
}

func TestUDPSessionRejectsExcessiveFragmentsWithoutState(t *testing.T) {
	ioMock := newMockUDPIO(t)
	events := newMockUDPEventLogger(t)
	global := make(chan struct{}, 1)
	manager := newUDPSessionManager(ioMock, events, time.Minute, 1, global, "client", nil)
	manager.feed(&protocol.UDPMessage{
		SessionID: 7,
		PacketID:  1,
		FragID:    0,
		FragCount: frag.MaxFragments + 1,
		Addr:      "example.test:443",
		Data:      []byte("partial"),
	})
	if got := manager.Count(); got != 0 {
		t.Fatalf("malformed fragment allocated %d sessions", got)
	}
	if got := len(global); got != 0 {
		t.Fatalf("malformed fragment consumed %d global slots", got)
	}
}

func TestUDPSessionLimitIsSharedAcrossClientConnections(t *testing.T) {
	ioMock := newMockUDPIO(t)
	events := newMockUDPEventLogger(t)
	global := make(chan struct{}, 3)
	clients := newKeyedLimiter(1)
	first := newUDPSessionManager(ioMock, events, time.Minute, 2, global, "192.0.2.10", clients)
	second := newUDPSessionManager(ioMock, events, time.Minute, 2, global, "192.0.2.10", clients)
	other := newUDPSessionManager(ioMock, events, time.Minute, 2, global, "192.0.2.11", clients)
	message := func(id uint32) *protocol.UDPMessage {
		return &protocol.UDPMessage{
			SessionID: id,
			PacketID:  1,
			FragID:    0,
			FragCount: 2,
			Addr:      "example.test:443",
			Data:      []byte("partial"),
		}
	}

	first.feed(message(1))
	second.feed(message(2))
	other.feed(message(3))
	if first.Count() != 1 || second.Count() != 0 || other.Count() != 1 {
		t.Fatalf("cross-connection counts = (%d, %d, %d), want (1, 0, 1)", first.Count(), second.Count(), other.Count())
	}
	if got := clients.count("192.0.2.10"); got != 1 {
		t.Fatalf("shared client count = %d, want 1", got)
	}

	events.EXPECT().Close(uint32(1), nil).Once()
	first.cleanup(false)
	second.feed(message(2))
	if second.Count() != 1 {
		t.Fatal("released per-client slot was not reusable by another connection")
	}
	events.EXPECT().Close(uint32(2), nil).Once()
	events.EXPECT().Close(uint32(3), nil).Once()
	second.cleanup(false)
	other.cleanup(false)
	if clients.count("192.0.2.10") != 0 || clients.count("192.0.2.11") != 0 {
		t.Fatal("per-client limiter retained empty source entries")
	}
}

func TestPendingTCPHeaderTimesOutAndReleasesSlot(t *testing.T) {
	stream := newDeadlineStream()
	slots := make(chan struct{}, 1)
	handler := &h3sHandler{
		config:   &Config{TCPRequestTimeout: 20 * time.Millisecond},
		tcpSlots: slots,
	}
	release, admitted := handler.admitStream(stream)
	if !admitted || release == nil {
		t.Fatal("stream was not admitted")
	}
	if got := len(slots); got != 1 {
		t.Fatalf("TCP handler slots after admission = %d, want 1", got)
	}
	done := make(chan struct{})
	go func() {
		handler.handleTCPRequest(stream, "test-auth")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pending TCP header did not time out")
	}
	if !stream.wasClosed() {
		t.Fatal("timed-out stream was not closed")
	}
	release()
	release()
	if got := len(slots); got != 0 {
		t.Fatalf("TCP handler slot was not released exactly once: %d", got)
	}
}

func TestTCPHandlerLimitIsSharedAcrossClientConnections(t *testing.T) {
	global := make(chan struct{}, 3)
	clients := newKeyedLimiter(1)
	first := &h3sHandler{
		config:         &Config{TCPRequestTimeout: time.Second},
		clientKey:      "192.0.2.10",
		tcpSlots:       global,
		tcpClientSlots: clients,
	}
	second := &h3sHandler{
		config:         &Config{TCPRequestTimeout: time.Second},
		clientKey:      "192.0.2.10",
		tcpSlots:       global,
		tcpClientSlots: clients,
	}
	other := &h3sHandler{
		config:         &Config{TCPRequestTimeout: time.Second},
		clientKey:      "192.0.2.11",
		tcpSlots:       global,
		tcpClientSlots: clients,
	}

	firstRelease, admitted := first.admitStream(newDeadlineStream())
	if !admitted {
		t.Fatal("first source stream was rejected")
	}
	if release, admitted := second.admitStream(newDeadlineStream()); admitted || release != nil {
		t.Fatal("second connection bypassed the shared per-source TCP limit")
	}
	otherRelease, admitted := other.admitStream(newDeadlineStream())
	if !admitted {
		t.Fatal("different source was rejected while global capacity remained")
	}
	if len(global) != 2 || clients.count("192.0.2.10") != 1 || clients.count("192.0.2.11") != 1 {
		t.Fatalf("unexpected limiter state: global=%d first=%d other=%d", len(global), clients.count("192.0.2.10"), clients.count("192.0.2.11"))
	}

	firstRelease()
	secondRelease, admitted := second.admitStream(newDeadlineStream())
	if !admitted {
		t.Fatal("released per-source TCP slot was not reusable across connections")
	}
	secondRelease()
	otherRelease()
	if len(global) != 0 || clients.count("192.0.2.10") != 0 || clients.count("192.0.2.11") != 0 {
		t.Fatal("TCP limiters retained capacity or empty source entries")
	}
}

func TestAuthStateWaitsForAuthenticationUpdate(t *testing.T) {
	handler := &h3sHandler{}
	handler.authMutex.Lock()
	result := make(chan struct {
		id string
		ok bool
	}, 1)
	go func() {
		id, ok := handler.authState()
		result <- struct {
			id string
			ok bool
		}{id: id, ok: ok}
	}()

	select {
	case <-result:
		t.Fatal("authState returned during an in-progress authentication update")
	case <-time.After(20 * time.Millisecond):
	}
	handler.authID = "authenticated-user"
	handler.authenticated = true
	handler.authMutex.Unlock()

	select {
	case state := <-result:
		if !state.ok || state.id != "authenticated-user" {
			t.Fatalf("authState = (%q, %v), want authenticated user", state.id, state.ok)
		}
	case <-time.After(time.Second):
		t.Fatal("authState remained blocked after authentication completed")
	}
}

func TestAuthenticationExpiryIsOneShotAndFailClosed(t *testing.T) {
	handler := &h3sHandler{}
	if !handler.expireAuthentication() {
		t.Fatal("first unauthenticated expiry was ignored")
	}
	if handler.expireAuthentication() {
		t.Fatal("authentication expiry fired more than once")
	}
	if id, ok := handler.authState(); ok || id != "" {
		t.Fatalf("expired auth state = (%q, %v), want unauthenticated", id, ok)
	}

	authenticated := &h3sHandler{authenticated: true, authID: "client"}
	if authenticated.expireAuthentication() {
		t.Fatal("authenticated session was expired")
	}
}

type deadlineStream struct {
	mu       sync.Mutex
	deadline time.Time
	closed   bool
}

func newDeadlineStream() *deadlineStream { return &deadlineStream{} }

func (s *deadlineStream) StreamID() quic.StreamID          { return 0 }
func (s *deadlineStream) Write(p []byte) (int, error)      { return len(p), nil }
func (s *deadlineStream) SetWriteDeadline(time.Time) error { return nil }
func (s *deadlineStream) SetDeadline(deadline time.Time) error {
	return s.SetReadDeadline(deadline)
}
func (s *deadlineStream) SetReadDeadline(deadline time.Time) error {
	s.mu.Lock()
	s.deadline = deadline
	s.mu.Unlock()
	return nil
}
func (s *deadlineStream) Read([]byte) (int, error) {
	s.mu.Lock()
	deadline := s.deadline
	s.mu.Unlock()
	if deadline.IsZero() {
		return 0, errors.New("missing read deadline")
	}
	if delay := time.Until(deadline); delay > 0 {
		time.Sleep(delay)
	}
	return 0, timeoutError{}
}
func (s *deadlineStream) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}
func (s *deadlineStream) wasClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "deadline exceeded" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

var _ HyStream = (*deadlineStream)(nil)
