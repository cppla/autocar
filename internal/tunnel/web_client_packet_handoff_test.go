package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

// The decorator only schedules the return of a real, successful H3 PacketConn.
// It does not synthesize SETTINGS, authentication, packets, or network latency.
type webClientPacketHandoffPrimary struct {
	*WebH3Client
	mu      sync.Mutex
	packets []*webUDPPacketConn
	handoff func(context.Context)
}

func (d *webClientPacketHandoffPrimary) DialPacket(ctx context.Context) (transport.PacketConn, error) {
	packet, err := d.WebH3Client.DialPacket(ctx)
	if err != nil {
		return packet, err
	}
	actual, ok := packet.(*webUDPPacketConn)
	if !ok {
		_ = packet.Close()
		return nil, errors.New("handoff fixture expected a real H3 PacketConn")
	}
	d.mu.Lock()
	d.packets = append(d.packets, actual)
	handoff := d.handoff
	d.mu.Unlock()
	if handoff != nil {
		handoff(ctx)
	}
	return actual, nil
}

type webClientPacketHandoffFallback struct{ calls atomic.Int64 }

func (d *webClientPacketHandoffFallback) DialContext(context.Context, string, string) (net.Conn, error) {
	d.calls.Add(1)
	return nil, errors.New("H2 fallback is forbidden for UDP handoff")
}

func (*webClientPacketHandoffFallback) Close() error { return nil }

type webClientPacketHandoffFixture struct {
	client         *WebClient
	primary        *webClientPacketHandoffPrimary
	fallback       *webClientPacketHandoffFallback
	server         *WebH3Server
	echo           *net.UDPConn
	target         netip.AddrPort
	serveCancel    context.CancelFunc
	serveResult    chan error
	serveDone      chan struct{}
	echoDone       chan struct{}
	echoResult     chan error
	handlerDone    chan struct{}
	joinedHandlers int
	resolver       atomic.Int64
	tcpDials       atomic.Int64
	cover          atomic.Int64
	requests       atomic.Int64
	unexpected     atomic.Int64
	receivers      []<-chan struct{}
}

func webClientPacketHandoffWait(t *testing.T, done <-chan struct{}, label string) bool {
	t.Helper()
	select {
	case <-done:
		return true
	case <-time.After(2 * time.Second):
		t.Errorf("%s did not join", label)
		return false
	}
}

func newWebClientPacketHandoffFixture(t *testing.T) *webClientPacketHandoffFixture {
	t.Helper()
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	f := &webClientPacketHandoffFixture{
		echo: echo, target: echo.LocalAddr().(*net.UDPAddr).AddrPort(),
		echoDone: make(chan struct{}), echoResult: make(chan error, 1),
		serveDone: make(chan struct{}), serveResult: make(chan error, 1),
		handlerDone: make(chan struct{}, 4), fallback: &webClientPacketHandoffFallback{},
	}
	t.Cleanup(func() {
		if f.primary != nil {
			f.primary.mu.Lock()
			packets := append([]*webUDPPacketConn(nil), f.primary.packets...)
			f.primary.mu.Unlock()
			for _, packet := range packets {
				_ = packet.Close()
			}
		}
		if f.client != nil {
			if err := f.client.Close(); err != nil {
				t.Errorf("client Close: %v", err)
			}
		} else if f.primary != nil {
			_ = f.primary.Close()
		}
		for _, done := range f.receivers {
			webClientPacketHandoffWait(t, done, "owned PacketConn Receive worker")
		}
		if f.server != nil {
			if err := normalizeWebServerCloseError(f.server.Close()); err != nil {
				t.Errorf("server Close: %v", err)
			}
			f.serveCancel()
			if webClientPacketHandoffWait(t, f.serveDone, "owned H3 Serve worker") {
				if err := <-f.serveResult; err != nil {
					t.Errorf("server Serve: %v", err)
				}
			}
			for want := int(f.requests.Load()); f.joinedHandlers < want; f.joinedHandlers++ {
				select {
				case <-f.handlerDone:
				case <-time.After(2 * time.Second):
					t.Error("owned H3 request handler did not join during independent cleanup")
					f.joinedHandlers = want
				}
			}
		}
		_ = f.echo.Close()
		if webClientPacketHandoffWait(t, f.echoDone, "owned UDP echo worker") {
			if err := <-f.echoResult; err != nil {
				t.Errorf("UDP echo: %v", err)
			}
		}
	})
	go func() {
		defer close(f.echoDone)
		buffer := make([]byte, 2048)
		for {
			if err := echo.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
				f.echoResult <- err
				return
			}
			n, source, err := echo.ReadFromUDPAddrPort(buffer)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					err = nil
				}
				f.echoResult <- err
				return
			}
			if _, err := echo.WriteToUDPAddrPort(buffer[:n], source); err != nil {
				f.echoResult <- err
				return
			}
		}
	}()
	serverTLS, clientTLS := testTLSConfigs(t)
	f.server, err = ListenWebH3(WebH3ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
		HandshakeTimeout: time.Second, DialTimeout: time.Second,
		Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
			f.tcpDials.Add(1)
			return nil, errors.New("TCP destination forbidden in UDP handoff fixture")
		}),
		Cover: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			f.cover.Add(1)
			http.NotFound(w, nil)
		}),
		UDPResolver: UDPResolverFunc(func(_ context.Context, address string) ([]netip.AddrPort, error) {
			f.resolver.Add(1)
			if address != f.target.String() {
				f.unexpected.Add(1)
				return nil, errors.New("only the numeric owned UDP target is permitted")
			}
			return []netip.AddrPort{f.target}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	original := f.server.server.Handler
	f.server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		defer func() { f.handlerDone <- struct{}{} }()
		original.ServeHTTP(w, r)
	})
	serveCtx, cancelServe := context.WithCancel(context.Background())
	f.serveCancel = cancelServe
	go func() {
		defer close(f.serveDone)
		f.serveResult <- f.server.Serve(serveCtx)
	}()
	h3, err := NewWebH3Client(WebH3ClientConfig{
		ServerAddress: f.server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
		FingerprintProfile: H3FingerprintNative, DialTimeout: time.Second, HandshakeTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.primary = &webClientPacketHandoffPrimary{WebH3Client: h3}
	f.client, err = newWebClientWithPaths(
		webClientPath{name: webAuthTransportH3, dialer: f.primary},
		webClientPath{name: webAuthTransportH2, dialer: f.fallback},
		80*time.Millisecond, time.Minute, time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	// Physical handshake and DATAGRAM SETTINGS use an independent budget. The
	// 80ms tested budget below measures only a warm logical PacketConn handoff.
	warmCtx, cancelWarm := context.WithTimeout(context.Background(), 2*time.Second)
	warm, err := h3.DialPacket(warmCtx)
	cancelWarm()
	if err != nil {
		t.Fatal(err)
	}
	_ = warm.Close()
	h3.mu.Lock()
	physical := h3.conn
	h3.mu.Unlock()
	if physical == nil {
		t.Fatal("missing warm real H3 physical connection")
	}
	state := physical.ConnectionState().TLS
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "h3" || len(state.VerifiedChains) == 0 {
		t.Fatalf("unverified warm H3 TLS state: %+v", state)
	}
	return f
}

func (f *webClientPacketHandoffFixture) echoPayload(t *testing.T, packet transport.PacketConn, payload []byte) {
	t.Helper()
	if err := packet.Send(payload, f.target.String()); err != nil {
		t.Fatal(err)
	}
	result := make(chan webClientPacketHandoffResult, 1)
	done := make(chan struct{})
	f.receivers = append(f.receivers, done)
	go func() {
		defer close(done)
		got, address, err := packet.Receive()
		result <- webClientPacketHandoffResult{payload: got, address: address, err: err}
	}()
	if !webClientPacketHandoffWait(t, done, "owned healthy UDP Receive worker") {
		t.FailNow()
	}
	got := <-result
	if got.err != nil || !bytes.Equal(got.payload, payload) || got.address != f.target.String() {
		t.Fatalf("real UDP echo=%q/%q/%v, want=%q/%q", got.payload, got.address, got.err, payload, f.target)
	}
}

type webClientPacketHandoffResult struct {
	payload []byte
	address string
	err     error
}

func testWebClientPacketHandoff(t *testing.T, deadline bool) {
	f := newWebClientPacketHandoffFixture(t)
	f.primary.WebH3Client.mu.Lock()
	physical := f.primary.conn
	f.primary.WebH3Client.mu.Unlock()
	caller, cancelCaller := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancelCaller(context.Canceled) })
	cause := errors.New("private UDP handoff caller cancellation")
	if deadline {
		cause = context.DeadlineExceeded
	}
	var handoffErr error
	f.primary.handoff = func(budget context.Context) {
		if err := contextError(budget); err != nil {
			handoffErr = fmt.Errorf("warm packet returned after budget before handoff: %w", err)
			return
		}
		if deadline {
			<-budget.Done()
			handoffErr = context.Cause(budget)
		} else {
			cancelCaller(cause)
		}
	}
	f.client.mu.Lock()
	f.client.nextPrimaryID++
	generation := f.client.nextPrimaryID
	f.client.mu.Unlock()
	if !f.client.recordPrimaryFailure(generation, time.Now()) {
		t.Fatal("failed to install the healthy-control circuit generation")
	}
	packet, err := f.client.DialPacket(caller)
	if deadline && !errors.Is(handoffErr, context.DeadlineExceeded) {
		t.Fatalf("primary deadline handoff was not observed: %v", handoffErr)
	}
	if !deadline && handoffErr != nil {
		t.Fatalf("caller handoff was not observed: %v", handoffErr)
	}
	correctCause := err == cause
	if deadline {
		correctCause = errors.Is(err, context.DeadlineExceeded)
	}
	if packet != nil || !correctCause {
		t.Errorf("late PacketConn=%T error=%v, want nil and exact %v", packet, err, cause)
	}
	f.primary.mu.Lock()
	packets := append([]*webUDPPacketConn(nil), f.primary.packets...)
	f.primary.mu.Unlock()
	if len(packets) != 1 {
		t.Fatalf("handoff did not return exactly one real H3 PacketConn: %d", len(packets))
	}
	late := packets[0]
	select {
	case <-late.done:
	default:
		t.Error("late real H3 PacketConn remains open before independent cleanup")
	}
	if deadline && contextError(caller) != nil {
		t.Error("primary-only budget canceled the still-live original caller")
	}
	if f.requests.Load() != 0 || f.resolver.Load() != 0 || f.cover.Load() != 0 || f.tcpDials.Load() != 0 || f.fallback.calls.Load() != 0 {
		t.Error("logical handoff unexpectedly emitted a target/cover/fallback request")
	}
	assertWebPrimaryFailureGeneration(t, f.client, generation)
	if f.client.SelectedTransport() != "" {
		t.Error("unestablished logical packet falsely selected a transport")
	}
	// Independent cleanup follows the ownership oracle even on the old-source
	// failure, so a leaked result cannot pollute the real healthy control.
	_ = late.Close()
	f.primary.mu.Lock()
	f.primary.handoff = nil
	f.primary.mu.Unlock()
	live, cancelLive := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancelLive(context.Canceled) })
	healthy, err := f.client.DialPacket(live)
	if err != nil {
		t.Fatal(err)
	}
	assertWebPrimaryFailureGeneration(t, f.client, generation)
	f.echoPayload(t, healthy, []byte("complete real H3 datagram before caller cancellation"))
	cancelLive(errors.New("successful packet must be detached from caller"))
	f.echoPayload(t, healthy, []byte("complete real H3 datagram after caller cancellation"))
	f.primary.WebH3Client.mu.Lock()
	samePhysical := f.primary.conn == physical
	f.primary.WebH3Client.mu.Unlock()
	if !samePhysical || f.fallback.calls.Load() != 0 || f.requests.Load() != 1 || f.resolver.Load() != 1 || f.unexpected.Load() != 0 {
		t.Error("healthy UDP control did not reuse only the authenticated H3 physical path")
	}
	if f.client.SelectedTransport() != webAuthTransportH3 {
		t.Error("a real newly authenticated UDP target did not select H3")
	}
	_ = healthy.Close()
	select {
	case <-f.handlerDone:
		f.joinedHandlers++
	case <-time.After(2 * time.Second):
		t.Fatal("real authenticated UDP handler did not join after packet Close")
	}
	if got := len(f.primary.udpSlots); got != 0 {
		t.Errorf("UDP session admission remains occupied after packet Close: %d", got)
	}
}

func TestWebClientPacketHandoffHonorsCallerCancellation(t *testing.T) {
	testWebClientPacketHandoff(t, false)
}

func TestWebClientPacketHandoffHonorsPrimaryDeadline(t *testing.T) {
	testWebClientPacketHandoff(t, true)
}
