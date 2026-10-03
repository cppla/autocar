package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
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

	"github.com/cppla/autocar/internal/proxy"
	"github.com/cppla/autocar/internal/transport"
)

// Only resolver scheduling is synthetic. All payloads cross authenticated
// QUIC/H3, a real owned UDP socket, and (where selected) real SOCKS TCP/UDP.
// The independent 500ms wire oracle runs while the resolver's 2s budget is
// still live; a failed oracle still releases the gate and checks recovery.
func TestNativeUDPSlowTargetDoesNotBlockWarmTarget(t *testing.T) {
	f := newUDPTargetIsolation(t, "native")
	f.isolation()
	f.sameTargetFIFO()
	f.closeWhileResolving()
}

func TestWebH3UDPConcurrentSendKeepsWarmTargetLive(t *testing.T) {
	f := newUDPTargetIsolation(t, "h3")
	f.isolation()
	f.closeWhileResolving()
}

func TestWebH3SOCKSUDPSlowTargetDoesNotBlockWarmTarget(t *testing.T) {
	f := newUDPTargetIsolation(t, "socks")
	f.isolation()
	f.closeWhileResolving()
}

func TestWebAutoSOCKSUDPSlowTargetDoesNotBlockWarmTarget(t *testing.T) {
	f := newUDPTargetIsolation(t, "socks_auto")
	f.isolation()
	f.closeWhileResolving()
}

type udpTargetIsolationGate struct {
	entered    chan context.Context
	release    chan struct{}
	joined     chan struct{}
	canceled   chan error
	finish     chan struct{}
	once       sync.Once
	finishOnce sync.Once
	closing    bool
	visits     atomic.Int32
}

func newUDPTargetIsolationGate(closing bool) *udpTargetIsolationGate {
	return &udpTargetIsolationGate{entered: make(chan context.Context, 1), release: make(chan struct{}), joined: make(chan struct{}), canceled: make(chan error, 1), finish: make(chan struct{}), closing: closing}
}

func (g *udpTargetIsolationGate) Release() { g.once.Do(func() { close(g.release) }) }
func (g *udpTargetIsolationGate) Finish()  { g.finishOnce.Do(func() { close(g.finish) }) }

type udpTargetIsolationRecord struct {
	payload  string
	address  string
	source   netip.AddrPort
	sequence int
}

type udpTargetIsolationCall struct {
	joined <-chan struct{}
	result <-chan error
}

type udpTargetIsolationFixture struct {
	*webH2DialSharingFixture
	mode                            string
	echo                            *net.UDPConn
	endpoint                        netip.AddrPort
	warm, slow, fifo, closingTarget string
	gates                           map[string]*udpTargetIsolationGate
	packet                          transport.PacketConn
	h3                              *WebH3Client
	auto                            *WebClient
	physical                        *webH3ClientSession
	entropy                         webH2AuthEntropyCounter
	serverSlots                     func() int
	control                         *net.TCPConn
	local                           *net.UDPConn
	relay                           *net.UDPAddr
	closing                         atomic.Bool
	unexpected                      atomic.Int32
	errors                          chan error
	receipts, replies               chan udpTargetIsolationRecord
	receiptPending, replyPending    map[string]udpTargetIsolationRecord
	warmSource                      netip.AddrPort
	mu                              sync.Mutex
	handlers                        []<-chan struct{}
}

func newUDPTargetIsolation(t *testing.T, mode string) *udpTargetIsolationFixture {
	t.Helper()
	f := &udpTargetIsolationFixture{webH2DialSharingFixture: newWebH2DialSharingFixture(t), mode: mode,
		errors: make(chan error, 32), receipts: make(chan udpTargetIsolationRecord, 32), replies: make(chan udpTargetIsolationRecord, 32),
		receiptPending: make(map[string]udpTargetIsolationRecord), replyPending: make(map[string]udpTargetIsolationRecord)}
	// Also covers early constructor failure before the close list is complete.
	t.Cleanup(func() { f.closing.Store(true) })
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f.echo, f.endpoint = echo, echo.LocalAddr().(*net.UDPAddr).AddrPort()
	port := strconv.Itoa(int(f.endpoint.Port()))
	f.warm, f.slow = "warm.invalid:"+port, "slow.invalid:"+port
	if mode == "native" {
		f.warm = f.endpoint.String()
	}
	f.fifo, f.closingTarget = "fifo.invalid:"+port, "closing.invalid:"+port
	f.gates = map[string]*udpTargetIsolationGate{f.slow: newUDPTargetIsolationGate(false), f.fifo: newUDPTargetIsolationGate(false), f.closingTarget: newUDPTargetIsolationGate(true)}
	f.close = append(f.close, func() { _ = echo.Close() })
	echoJoined := make(chan struct{})
	f.register(echoJoined)
	go func() {
		defer close(echoJoined)
		var buffer [2048]byte
		sequence := 0
		for {
			_ = echo.SetDeadline(time.Now().Add(7 * time.Second))
			n, source, err := echo.ReadFromUDPAddrPort(buffer[:])
			if err != nil {
				f.noteIO(err)
				return
			}
			sequence++
			f.publish(f.receipts, udpTargetIsolationRecord{payload: string(buffer[:n]), source: source, sequence: sequence})
			if _, err := echo.WriteToUDPAddrPort(buffer[:n], source); err != nil {
				f.noteIO(err)
				return
			}
		}
	}()
	resolver := UDPResolverFunc(func(ctx context.Context, address string) ([]netip.AddrPort, error) {
		joined := make(chan struct{})
		f.register(joined)
		defer close(joined)
		if address != f.warm && f.gates[address] == nil {
			f.unexpected.Add(1)
			return nil, errors.New("isolation fixture forbids non-owned UDP targets")
		}
		if gate := f.gates[address]; gate != nil && gate.visits.Add(1) == 1 {
			defer close(gate.joined)
			gate.entered <- ctx
			select {
			case <-gate.release:
			case <-ctx.Done():
				gate.canceled <- ctx.Err()
				if gate.closing {
					// This explicit completion gate distinguishes cancellation from
					// callback completion when checking the real server lease.
					select {
					case <-gate.finish:
					case <-f.ctx.Done():
					}
				}
				return nil, context.Cause(ctx)
			case <-f.ctx.Done():
				return nil, context.Cause(f.ctx)
			}
		}
		return []netip.AddrPort{f.endpoint}, nil
	})
	serverTLS, clientTLS := testTLSConfigs(t)
	refuseTCP := transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
		f.unexpected.Add(1)
		return nil, errors.New("isolation fixture forbids TCP destinations")
	})
	var serve func(context.Context) error
	if mode == "native" {
		server, err := ListenQUIC(QUICServerConfig{Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
			Dialer: refuseTCP, UDPResolver: resolver, DialTimeout: 2 * time.Second, HandshakeTimeout: time.Second,
			MaxUDPSessions: 1, MaxClientUDPSessions: 1, MaxUDPDestinations: 4})
		if err != nil {
			t.Fatal(err)
		}
		f.serverSlots = func() int { return len(server.udp.slots) }
		f.close = append(f.close, func() {
			if err := normalizeWebServerCloseError(server.Close()); err != nil {
				t.Errorf("native server Close: %v", err)
			}
		})
		serve = server.Serve
		client, err := NewClient(ClientConfig{ServerAddress: server.Addr().String(), Token: testToken, TLSConfig: clientTLS, QUICDialTimeout: time.Second, HandshakeTimeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		f.close = append(f.close, func() { _ = client.Close() })
		f.startServe(serve)
		f.packet, err = client.DialPacket(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		verified := f.packet.(*quicPacketConn).dispatcher.conn.ConnectionState().TLS
		if len(verified.VerifiedChains) == 0 {
			t.Fatal("native association did not verify its real TLS peer")
		}
	} else {
		server, err := ListenWebH3(WebH3ServerConfig{Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
			Dialer: refuseTCP, UDPResolver: resolver, DialTimeout: 2 * time.Second, HandshakeTimeout: time.Second,
			MaxUDPSessions: 4, MaxClientUDPSessions: 4, MaxUDPDestinations: 4,
			Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.unexpected.Add(1); http.NotFound(w, r) })})
		if err != nil {
			t.Fatal(err)
		}
		original := server.server.Handler
		manager := original.(*webTunnelHandler).udp
		f.serverSlots = func() int { return len(manager.slots) }
		server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			joined := make(chan struct{})
			f.register(joined)
			f.mu.Lock()
			f.handlers = append(f.handlers, joined)
			f.mu.Unlock()
			defer close(joined)
			original.ServeHTTP(w, r)
		})
		f.close = append(f.close, func() {
			if err := normalizeWebServerCloseError(server.Close()); err != nil {
				t.Errorf("H3 server Close: %v", err)
			}
		})
		var dialer transport.Dialer
		var packetDialer transport.PacketDialer
		if mode == "socks_auto" {
			client, err := NewWebClient(WebClientConfig{ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
				H3FingerprintProfile: H3FingerprintNative, H3DialTimeout: time.Second, H2DialTimeout: time.Second,
				HandshakeTimeout: time.Second, PrimaryAttemptTimeout: time.Second, MaxUDPSessions: 4, MaxUDPDestinations: 4})
			if err != nil {
				t.Fatal(err)
			}
			f.auto, f.h3 = client, client.primary.dialer.(*WebH3Client)
			dialer, packetDialer = client, client
			f.close = append(f.close, func() { _ = client.Close() })
		} else {
			client, err := NewWebH3Client(WebH3ClientConfig{ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
				FingerprintProfile: H3FingerprintNative, DialTimeout: time.Second, HandshakeTimeout: time.Second, MaxUDPSessions: 4, MaxUDPDestinations: 4})
			if err != nil {
				t.Fatal(err)
			}
			f.h3 = client
			dialer, packetDialer = client, client
			f.close = append(f.close, func() { _ = client.Close() })
		}
		f.h3.signer = newWebAuthSigner(mustWebAuthKey(t, webTestToken), nil, &f.entropy)
		f.startServe(server.Serve)
		if f.isSOCKS() {
			f.startSOCKS(dialer, packetDialer)
		} else {
			f.packet, err = packetDialer.DialPacket(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	f.close = append(f.close, func() { _ = f.packet.Close() })
	for _, gate := range f.gates {
		gate := gate
		f.close = append(f.close, func() { gate.Release(); gate.Finish() })
	}
	f.close = append(f.close, func() { f.closing.Store(true) })
	f.checks = append(f.checks, func() {
		for {
			select {
			case err := <-f.errors:
				t.Errorf("owned isolation I/O: %v", err)
			default:
				goto drained
			}
		}
	drained:
		if n := f.unexpected.Load(); n != 0 {
			t.Errorf("unexpected target or observer overflow count=%d", n)
		}
	})
	f.startReceiver()
	return f
}

func (f *udpTargetIsolationFixture) startServe(serve func(context.Context) error) {
	joined, results := make(chan struct{}), make(chan error, 1)
	f.register(joined)
	f.checks = append(f.checks, func() {
		if err := <-results; err != nil {
			f.t.Errorf("owned Serve: %v", err)
		}
	})
	go func() { defer close(joined); results <- serve(f.ctx) }()
}

// Return the exact PacketConn rather than a PacketConn-only wrapper: optional
// downstream capabilities must survive this observation-only PacketDialer.
type udpTargetIsolationDialer struct {
	transport.Dialer
	packetDialer transport.PacketDialer
	returned     chan transport.PacketConn
}

func (d *udpTargetIsolationDialer) DialPacket(ctx context.Context) (transport.PacketConn, error) {
	packet, err := d.packetDialer.DialPacket(ctx)
	if err == nil {
		d.returned <- packet
	}
	return packet, err
}

func (f *udpTargetIsolationFixture) startSOCKS(client transport.Dialer, packetDialer transport.PacketDialer) {
	f.t.Helper()
	dialer := &udpTargetIsolationDialer{Dialer: client, packetDialer: packetDialer, returned: make(chan transport.PacketConn, 1)}
	server, err := proxy.NewSOCKS5Server(proxy.Config{Dialer: dialer, IdleTimeout: 3 * time.Second})
	if err != nil {
		f.t.Fatal(err)
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		f.t.Fatal(err)
	}
	f.close = append(f.close, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			f.t.Errorf("SOCKS Shutdown: %v", err)
		}
		_ = listener.Close()
	})
	joined, result := make(chan struct{}), make(chan error, 1)
	f.register(joined)
	f.checks = append(f.checks, func() {
		if err := <-result; err != nil {
			f.t.Errorf("SOCKS Serve: %v", err)
		}
	})
	go func() { defer close(joined); result <- server.Serve(listener) }()
	control, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		f.t.Fatal(err)
	}
	f.control = control
	f.close = append(f.close, func() { _ = control.Close() })
	_ = control.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := control.Write([]byte{5, 1, 0}); err != nil {
		f.t.Fatal(err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(control, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		f.t.Fatalf("SOCKS greeting=%v/%v", greeting, err)
	}
	if _, err := control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		f.t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(control, reply[:]); err != nil || !bytes.Equal(reply[:4], []byte{5, 0, 0, 1}) {
		f.t.Fatalf("SOCKS reply=%v/%v", reply, err)
	}
	_ = control.SetDeadline(time.Time{})
	f.relay = &net.UDPAddr{IP: append(net.IP(nil), reply[4:8]...), Port: int(binary.BigEndian.Uint16(reply[8:]))}
	select {
	case f.packet = <-dialer.returned:
	case <-f.ctx.Done():
		f.t.Fatal("SOCKS packet ownership missing")
	}
	f.local, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		f.t.Fatal(err)
	}
	f.close = append(f.close, func() { _ = f.local.Close() })
}

func (f *udpTargetIsolationFixture) publish(channel chan<- udpTargetIsolationRecord, record udpTargetIsolationRecord) {
	select {
	case channel <- record:
	default:
		f.unexpected.Add(1)
	}
}

func (f *udpTargetIsolationFixture) noteIO(err error) {
	if err == nil || (f.closing.Load() && errors.Is(err, net.ErrClosed)) {
		return
	}
	select {
	case f.errors <- err:
	default:
		f.unexpected.Add(1)
	}
}

func (f *udpTargetIsolationFixture) isSOCKS() bool {
	return f.mode == "socks" || f.mode == "socks_auto"
}

func (f *udpTargetIsolationFixture) startReceiver() {
	joined := make(chan struct{})
	f.register(joined)
	go func() {
		defer close(joined)
		for {
			if !f.isSOCKS() {
				payload, address, err := f.packet.Receive()
				if err != nil {
					f.noteIO(err)
					return
				}
				f.publish(f.replies, udpTargetIsolationRecord{payload: string(payload), address: address})
				continue
			}
			var buffer [2048]byte
			_ = f.local.SetReadDeadline(time.Now().Add(7 * time.Second))
			n, source, err := f.local.ReadFromUDP(buffer[:])
			if err != nil {
				f.noteIO(err)
				return
			}
			if source.String() != f.relay.String() || n < 7 || !bytes.Equal(buffer[:4], []byte{0, 0, 0, 3}) {
				f.unexpected.Add(1)
				continue
			}
			length := int(buffer[4])
			if n < 7+length {
				f.unexpected.Add(1)
				continue
			}
			address := net.JoinHostPort(string(buffer[5:5+length]), strconv.Itoa(int(binary.BigEndian.Uint16(buffer[5+length:7+length]))))
			f.publish(f.replies, udpTargetIsolationRecord{payload: string(buffer[7+length : n]), address: address})
		}
	}()
}

func (f *udpTargetIsolationFixture) send(payload, target string) udpTargetIsolationCall {
	joined, result := make(chan struct{}), make(chan error, 1)
	f.register(joined)
	go func() {
		defer close(joined)
		if !f.isSOCKS() {
			result <- f.packet.Send([]byte(payload), target)
			return
		}
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			result <- err
			return
		}
		portNumber, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			result <- err
			return
		}
		_ = f.local.SetWriteDeadline(time.Now().Add(time.Second))
		_, err = f.local.WriteToUDP(webSOCKSUDPDomainPacket(host, uint16(portNumber), []byte(payload)), f.relay)
		result <- err
	}()
	return udpTargetIsolationCall{joined: joined, result: result}
}

func (f *udpTargetIsolationFixture) joinCall(call udpTargetIsolationCall, label string) error {
	f.wait(call.joined, label)
	return <-call.result
}

func (f *udpTargetIsolationFixture) entered(gate *udpTargetIsolationGate) context.Context {
	f.t.Helper()
	select {
	case ctx := <-gate.entered:
		if err := ctx.Err(); err != nil {
			f.t.Errorf("resolver was not live at actual entry: %v", err)
		}
		return ctx
	case <-f.ctx.Done():
		f.t.Fatal("owned resolver entry witness missing")
		return nil
	}
}

func (f *udpTargetIsolationFixture) record(ctx context.Context, channel <-chan udpTargetIsolationRecord, pending map[string]udpTargetIsolationRecord, payload string) (udpTargetIsolationRecord, bool) {
	if record, ok := pending[payload]; ok {
		delete(pending, payload)
		return record, true
	}
	for {
		select {
		case record := <-channel:
			if record.payload == payload {
				return record, true
			}
			if _, exists := pending[record.payload]; exists {
				f.unexpected.Add(1)
			}
			pending[record.payload] = record
		case <-ctx.Done():
			return udpTargetIsolationRecord{}, false
		}
	}
}

func (f *udpTargetIsolationFixture) wire(payload, target string, timeout time.Duration) (udpTargetIsolationRecord, bool) {
	ctx, cancel := context.WithTimeout(f.ctx, timeout)
	defer cancel()
	receipt, ok := f.record(ctx, f.receipts, f.receiptPending, payload)
	if !ok {
		return receipt, false
	}
	reply, ok := f.record(ctx, f.replies, f.replyPending, payload)
	if !ok {
		f.receiptPending[payload] = receipt
		return receipt, false
	}
	want := target
	if f.mode == "native" {
		want = f.endpoint.String()
	}
	if reply.address != want {
		f.t.Errorf("actual UDP reply=%q, want %q", reply.address, want)
	}
	if target == f.warm && f.warmSource.IsValid() && receipt.source != f.warmSource {
		f.t.Errorf("warm target relay source changed: %s -> %s", f.warmSource, receipt.source)
	}
	return receipt, true
}

func (f *udpTargetIsolationFixture) requireWire(payload, target string) udpTargetIsolationRecord {
	f.t.Helper()
	record, ok := f.wire(payload, target, 2*time.Second)
	if !ok {
		f.t.Fatalf("unexpected fixture/recovery failure: actual %s echo did not complete", payload)
	}
	return record
}

func (f *udpTargetIsolationFixture) isolation() {
	f.t.Helper()
	if err := f.joinCall(f.send("warm-A1", f.warm), "first warm Send"); err != nil {
		f.t.Fatal(err)
	}
	f.warmSource = f.requireWire("warm-A1", f.warm).source
	if f.h3 != nil {
		f.physical = webH3SelectedSession(f.t, f.h3)
	}
	gate := f.gates[f.slow]
	slow := f.send("slow-B1", f.slow)
	resolverContext := f.entered(gate)
	healthy := f.send("warm-A2", f.warm)
	_, beforeRelease := f.wire("warm-A2", f.warm, 500*time.Millisecond)
	if !beforeRelease {
		f.t.Errorf("warm A2 did not actually echo while the independent slow resolver gate remained held")
	}
	if err := resolverContext.Err(); err != nil {
		f.t.Errorf("slow resolver ended before gate release: %v", err)
	}
	select {
	case <-gate.release:
		f.t.Error("wire oracle ran after gate release")
	default:
	}
	gate.Release() // Recovery still runs after the old implementation's failure.
	if err := f.joinCall(slow, "released slow Send"); err != nil {
		f.t.Errorf("unexpected slow-target recovery error: %v", err)
	}
	if err := f.joinCall(healthy, "warm A2 Send"); err != nil {
		f.t.Errorf("unexpected warm-target recovery error: %v", err)
	}
	if !beforeRelease {
		f.requireWire("warm-A2", f.warm)
	}
	f.requireWire("slow-B1", f.slow)
	f.wait(gate.joined, "released resolver callback")
	f.assertH3Continuity()
	f.t.Logf("%s: actual warm source=%s, A2-before-release=%t; both complete recovery payloads verified", f.mode, f.warmSource, beforeRelease)
}

func (f *udpTargetIsolationFixture) sameTargetFIFO() {
	// Send completion proves the native client accepted each datagram, not
	// server ingress before gate release. This checks actual loopback delivery
	// order only; server queue barriers belong to the dedicated queue tests.
	gate := f.gates[f.fifo]
	first := f.send("fifo-1", f.fifo)
	f.entered(gate)
	second := f.send("fifo-2", f.fifo)
	if err := f.joinCall(second, "second native FIFO enqueue"); err != nil {
		f.t.Fatal(err)
	}
	third := f.send("fifo-3", f.fifo)
	if err := f.joinCall(third, "third native FIFO enqueue"); err != nil {
		f.t.Fatal(err)
	}
	gate.Release()
	if err := f.joinCall(first, "first native FIFO enqueue"); err != nil {
		f.t.Fatal(err)
	}
	var previous udpTargetIsolationRecord
	for _, payload := range []string{"fifo-1", "fifo-2", "fifo-3"} {
		record := f.requireWire(payload, f.fifo)
		if previous.sequence != 0 && record.sequence != previous.sequence+1 {
			f.t.Errorf("native same-target loopback FIFO changed: %+v -> %+v", previous, record)
		}
		if record.source != f.warmSource {
			f.t.Errorf("native target switch changed the association socket: %s/%s", record.source, f.warmSource)
		}
		previous = record
	}
	f.wait(gate.joined, "native FIFO resolver callback")
}

func (f *udpTargetIsolationFixture) assertH3Continuity() {
	if f.h3 == nil {
		return
	}
	f.h3.mu.Lock()
	same := f.h3.conns[f.h3.conn] == f.physical
	ready := f.physical != nil && f.physical.authState == webH3ClientAuthReady && f.physical.auth != nil && !f.physical.retired
	f.h3.mu.Unlock()
	if !same || !ready || f.physical.conn.Context().Err() != nil || f.entropy.nonceReads.Load() != 1 {
		f.t.Errorf("actual H3 physical/Ready/bootstrap continuity=%t/%t/%d", same, ready, f.entropy.nonceReads.Load())
	}
	if f.auto != nil && f.auto.SelectedTransport() != webAuthTransportH3 {
		f.t.Errorf("actual automatic UDP path selected %q, want h3 with no H2 fallback", f.auto.SelectedTransport())
	}
}

func (f *udpTargetIsolationFixture) closeWhileResolving() {
	gate := f.gates[f.closingTarget]
	send := f.send("close-pending", f.closingTarget)
	resolverContext := f.entered(gate)
	f.closing.Store(true)
	closed, result := make(chan struct{}), make(chan error, 1)
	f.register(closed)
	go func() {
		defer close(closed)
		if !f.isSOCKS() {
			result <- f.packet.Close()
			return
		}
		if err := f.control.CloseWrite(); err != nil {
			result <- err
			return
		}
		_ = f.control.SetReadDeadline(time.Now().Add(2 * time.Second))
		var one [1]byte
		_, err := f.control.Read(one[:])
		if errors.Is(err, io.EOF) {
			err = nil
		}
		result <- err
	}()
	select {
	case err := <-gate.canceled:
		if err != context.Canceled || resolverContext.Err() != context.Canceled {
			f.t.Errorf("Close ended live resolver with %v/%v, want cancellation", err, resolverContext.Err())
		}
	case <-time.After(2 * time.Second):
		f.t.Error("Close did not cancel the actual pending resolver")
	}
	if slots := f.serverSlots(); slots < 1 {
		f.t.Errorf("server released all UDP leases while its canceled resolver callback was still held: %d", slots)
	}
	gate.Finish()
	gate.Release() // Independently bounds negative-control cleanup too.
	f.wait(gate.joined, "canceled resolver callback joined")
	f.wait(closed, "association Close/control peer EOF")
	if err := <-result; err != nil {
		f.t.Errorf("association close/actual control EOF: %v", err)
	}
	if err := f.joinCall(send, "pending Send joined after Close"); f.mode == "h3" && err == nil {
		f.t.Error("pending H3 Send succeeded after PacketConn Close")
	}
	if f.h3 != nil {
		f.mu.Lock()
		handlers := append([]<-chan struct{}(nil), f.handlers...)
		f.mu.Unlock()
		for _, handler := range handlers {
			f.wait(handler, "actual H3 handler completion")
		}
		if slots := len(f.h3.udpSlots); slots != 0 {
			f.t.Errorf("client retained UDP leases after Close and handler joins: %d", slots)
		}
	}
	timer, tick := time.NewTimer(2*time.Second), time.NewTicker(10*time.Millisecond)
	defer timer.Stop()
	defer tick.Stop()
	for f.serverSlots() != 0 {
		select {
		case <-tick.C:
		case <-timer.C:
			f.t.Errorf("server retained UDP leases after resolver/association shutdown: %d", f.serverSlots())
			return
		}
	}
	f.t.Log(fmt.Sprintf("%s: Close canceled pending resolver, retained admission until callback completion, and joined shutdown with zero server leases", f.mode))
}

var _ transport.PacketDialer = (*udpTargetIsolationDialer)(nil)
