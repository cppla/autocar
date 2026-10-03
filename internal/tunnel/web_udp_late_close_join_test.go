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

// The gate is test-only scheduling after an actual authenticated response. It
// does not fabricate TLS, HTTP status/proof, resolver results, or stream I/O.
type webUDPLateCloseJoinFixture struct {
	f          *webH2DialSharingFixture
	c          *WebH3Client
	h          *webTunnelHandler
	target     netip.AddrPort
	entered    chan struct{}
	requests   chan (<-chan struct{})
	verified   atomic.Int32
	resolves   atomic.Int32
	unexpected atomic.Int32
}

func newWebUDPLateCloseJoinFixture(t *testing.T, blockResolve bool) *webUDPLateCloseJoinFixture {
	t.Helper()
	f := newWebH2DialSharingFixture(t)
	x := &webUDPLateCloseJoinFixture{f: f, entered: make(chan struct{}), requests: make(chan (<-chan struct{}), 4)}
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	x.target = echo.LocalAddr().(*net.UDPAddr).AddrPort()
	f.close = append(f.close, func() { _ = echo.Close() })
	echoDone := make(chan struct{})
	f.register(echoDone)
	var echoErr error
	f.checks = append(f.checks, func() {
		if echoErr != nil {
			t.Errorf("UDP echo: %v", echoErr)
		}
	})
	go func() {
		defer close(echoDone)
		buffer := make([]byte, 2048)
		for {
			_ = echo.SetDeadline(time.Now().Add(7 * time.Second))
			n, from, err := echo.ReadFromUDPAddrPort(buffer)
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					echoErr = err
				}
				return
			}
			if _, err := echo.WriteToUDPAddrPort(buffer[:n], from); err != nil {
				if !errors.Is(err, net.ErrClosed) {
					echoErr = err
				}
				return
			}
		}
	}()
	serverTLS, clientTLS := testTLSConfigs(t)
	server, err := ListenWebH3(WebH3ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
		HandshakeTimeout: 2 * time.Second, DialTimeout: 2 * time.Second,
		MaxUDPSessions: 2, MaxClientUDPSessions: 2,
		Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { x.unexpected.Add(1); http.NotFound(w, r) }),
		Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
			x.unexpected.Add(1)
			return nil, errors.New("audit forbids TCP/outside target dial")
		}),
		UDPResolver: UDPResolverFunc(func(ctx context.Context, address string) ([]netip.AddrPort, error) {
			x.resolves.Add(1)
			joined := make(chan struct{})
			f.register(joined)
			defer close(joined)
			if address != x.target.String() {
				x.unexpected.Add(1)
				return nil, errors.New("audit requires owned numeric target")
			}
			if blockResolve {
				close(x.entered)
				select {
				case <-ctx.Done():
					return nil, context.Cause(ctx)
				case <-f.ctx.Done():
					return nil, context.Cause(f.ctx)
				}
			}
			return []netip.AddrPort{x.target}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	x.h = server.server.Handler.(*webTunnelHandler)
	base := server.server.Handler
	server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		joined := make(chan struct{})
		f.register(joined)
		defer close(joined)
		if r.ProtoMajor != 3 || r.Proto != webConnectUDPProtocol || r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
			x.unexpected.Add(1)
		}
		select {
		case x.requests <- joined:
		default:
			x.unexpected.Add(1)
		}
		base.ServeHTTP(w, r)
	})
	serveDone := make(chan struct{})
	f.register(serveDone)
	var serveErr error
	f.checks = append(f.checks, func() {
		if serveErr != nil {
			t.Errorf("H3 Serve: %v", serveErr)
		}
	})
	f.close = append(f.close, func() {
		if err := server.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("H3 Close: %v", err)
		}
	})
	go func() { defer close(serveDone); serveErr = server.Serve(f.ctx) }()
	clientTLS = clientTLS.Clone()
	clientTLS.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || state.NegotiatedProtocol != "h3" || state.Version != tls.VersionTLS13 {
			return errors.New("audit TLS verification incomplete")
		}
		x.verified.Add(1)
		return nil
	}
	x.c, err = NewWebH3Client(WebH3ClientConfig{
		ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
		FingerprintProfile: H3FingerprintNative, DialTimeout: time.Second, HandshakeTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.close = append(f.close, func() {
		if err := x.c.Close(); err != nil {
			t.Errorf("client Close: %v", err)
		}
	})
	f.checks = append(f.checks, func() {
		if x.unexpected.Load() != 0 || x.verified.Load() != 1 || x.resolves.Load() != 1 {
			t.Errorf("unexpected/verified/resolves=%d/%d/%d", x.unexpected.Load(), x.verified.Load(), x.resolves.Load())
		}
		if len(x.c.udpSlots) != 0 || len(x.h.udp.slots) != 0 || len(x.h.core.sem) != 0 {
			t.Errorf("cleanup slots client/server/streams=%d/%d/%d", len(x.c.udpSlots), len(x.h.udp.slots), len(x.h.core.sem))
		}
		t.Log("independent server/socket/handler/resolver/send/Close workers joined; slots=0")
	})
	return x
}

func (x *webUDPLateCloseJoinFixture) packet() *webUDPPacketConn {
	x.f.t.Helper()
	p, err := x.c.DialPacket(x.f.ctx)
	if err != nil {
		x.f.t.Fatal(err)
	}
	packet := p.(*webUDPPacketConn)
	x.f.close = append(x.f.close, func() { _ = packet.Close() })
	return packet
}

func (x *webUDPLateCloseJoinFixture) requestJoin() {
	x.f.t.Helper()
	select {
	case done := <-x.requests:
		x.f.wait(done, "actual CONNECT-UDP handler/workers")
	case <-x.f.ctx.Done():
		x.f.t.Fatal("missing actual request")
	}
}

func (x *webUDPLateCloseJoinFixture) zeroUsers() {
	x.c.mu.Lock()
	s := x.c.conns[x.c.conn]
	users, ready, live := -1, false, false
	if s != nil {
		users, ready, live = s.users, s.authState == webH3ClientAuthReady, s.conn.Context().Err() == nil
	}
	x.c.mu.Unlock()
	if users != 0 || !ready || !live || len(x.c.udpSlots) != 0 {
		x.f.t.Errorf("postcleanup users/ready/live/udpSlots=%d/%t/%t/%d", users, ready, live, len(x.c.udpSlots))
	}
}

func TestWebUDPLateSuccessfulOpenCloseJoinsResources(t *testing.T) {
	t.Run("late_valid_success", func(t *testing.T) {
		x := newWebUDPLateCloseJoinFixture(t, false)
		p := x.packet()
		observerEntered, observerRelease := make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		releaseObserver := func() { releaseOnce.Do(func() { close(observerRelease) }) }
		// Registered last: all failure paths release the gate before packet/client cleanup.
		t.Cleanup(releaseObserver)
		p.setAuthenticationObserver(func(connected bool) {
			if !connected {
				x.unexpected.Add(1)
			}
			close(observerEntered)
			select {
			case <-observerRelease:
			case <-x.f.ctx.Done():
			}
		})
		sendDone, closeDone := make(chan struct{}), make(chan struct{})
		sendErr, closeErr := make(chan error, 1), make(chan error, 1)
		x.f.register(sendDone)
		x.f.register(closeDone)
		go func() { defer close(sendDone); sendErr <- p.Send([]byte("late-owned-UDP"), x.target.String()) }()
		x.f.wait(observerEntered, "actual valid CONNECT-UDP proof accepted")
		p.mu.Lock()
		pending := p.pending[x.target.String()]
		p.mu.Unlock()
		if pending == nil {
			t.Fatal("real opening was not pending")
		}
		go func() { defer close(closeDone); closeErr <- p.Close() }()
		x.f.wait(p.done, "Packet.Close ownership/cancellation transition")
		// Existing releaseSession must acquire c.mu. Holding it here is a synthetic
		// cleanup-completion scheduling barrier, not a custom operation ignoring ctx.
		x.c.mu.Lock()
		locked := true
		defer func() {
			if locked {
				x.c.mu.Unlock()
			}
		}()
		session := x.c.conns[x.c.conn]
		if session == nil || session.users != 1 || len(x.c.udpSlots) != 1 || session.authState != webH3ClientAuthReady {
			t.Fatalf("before late handoff users/slot/Ready invalid")
		}
		releaseObserver()
		// Actual server workers have observed cancellation/stream closure. The
		// reservation release is still held by the client mutex, so neither
		// pending completion nor joined Close may yet be published.
		x.requestJoin()
		select {
		case <-pending.done:
			t.Error("late opening published completion before reservation/UDP-slot release")
		default:
		}
		select {
		case <-closeDone:
			t.Errorf("Packet.Close returned before late successful cleanup: physical users=%d UDP slots=%d (cleanup gate still held)", session.users, len(x.c.udpSlots))
		case <-time.After(100 * time.Millisecond):
			t.Log("Packet.Close remained blocked while late cleanup ownership was held")
		}
		select {
		case <-sendDone:
			t.Error("late Send returned before its cleanup ownership gate")
		default:
		}
		if session.users != 1 || len(x.c.udpSlots) != 1 {
			t.Error("cleanup gate did not retain real stream reservation and UDP slot")
		}
		x.c.mu.Unlock()
		locked = false
		x.f.wait(sendDone, "late Send cleanup worker")
		x.f.wait(closeDone, "Packet.Close worker")
		if err := <-sendErr; !errors.Is(err, net.ErrClosed) {
			t.Errorf("late Send=%v, want net.ErrClosed", err)
		}
		if err := <-closeErr; err != nil {
			t.Errorf("Packet.Close=%v", err)
		}
		x.f.wait(pending.done, "late pending completion after real cleanup")
		x.zeroUsers()
		t.Log("real TLS13/H3 valid proof preceded Close; late successful stream/UDP slot released after gate; Send=net.ErrClosed")
	})
	t.Run("normal_success", func(t *testing.T) {
		x := newWebUDPLateCloseJoinFixture(t, false)
		p := x.packet()
		payload := []byte("normal-owned-UDP")
		joined, result := make(chan struct{}), make(chan error, 1)
		x.f.register(joined)
		go func() {
			defer close(joined)
			if err := p.Send(payload, x.target.String()); err != nil {
				result <- err
				return
			}
			got, from, err := p.Receive()
			if err == nil && (!bytes.Equal(got, payload) || from != x.target.String()) {
				err = fmt.Errorf("UDP echo=%q/%q", got, from)
			}
			result <- err
		}()
		x.f.wait(joined, "normal real UDP echo")
		if err := <-result; err != nil {
			t.Fatal(err)
		}
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		x.requestJoin()
		x.zeroUsers()
		t.Log("normal successful UDP echo and joined Close control passed")
	})
	t.Run("canceled_open_error", func(t *testing.T) {
		x := newWebUDPLateCloseJoinFixture(t, true)
		p := x.packet()
		joined, result := make(chan struct{}), make(chan error, 1)
		x.f.register(joined)
		go func() { defer close(joined); result <- p.Send([]byte("cancel-owned-UDP"), x.target.String()) }()
		x.f.wait(x.entered, "actual resolver before response")
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		x.f.wait(joined, "canceled Send error worker")
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Errorf("canceled Send=%v, want context.Canceled", err)
		}
		x.requestJoin()
		if len(x.c.udpSlots) != 0 {
			t.Errorf("canceled-error Close retained UDP slot=%d", len(x.c.udpSlots))
		}
		t.Log("canceled resolver/failed opening Close joined without retained UDP slot")
	})
}
