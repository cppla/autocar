package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

type webUDPOpenCancellationRequest struct {
	auth   *webServerConnectionAuth
	full   bool
	short  bool
	udp    bool
	proto  int
	tls    uint16
	proof  bool // Read only after joined closes.
	joined chan struct{}
}

type webUDPOpenCancellationFixture struct {
	f              *webH2DialSharingFixture
	client         *WebH3Client
	handler        *webTunnelHandler
	tcpTarget      string
	udpTarget      netip.AddrPort
	entropy        *webH2AuthEntropyCounter
	requests       chan *webUDPOpenCancellationRequest
	resolveEntered chan struct{}
	resolveJoined  chan struct{}
	requestCalls   atomic.Int32
	resolves       atomic.Int32
	tcpDials       atomic.Int32
	covers         atomic.Int32
	unexpected     atomic.Int32
	verified       atomic.Int32
}

// Reuse only the frozen owned-socket/deadline/join infrastructure. The first
// real authenticated CONNECT-UDP resolver blocks before any response headers;
// no transport error, authentication result, or response is synthesized.
func newWebUDPOpenCancellationFixture(t *testing.T) *webUDPOpenCancellationFixture {
	t.Helper()
	f := newWebH2DialSharingFixture(t)
	x := &webUDPOpenCancellationFixture{
		f: f, tcpTarget: f.target(), entropy: &webH2AuthEntropyCounter{},
		requests:       make(chan *webUDPOpenCancellationRequest, 4),
		resolveEntered: make(chan struct{}), resolveJoined: make(chan struct{}),
	}
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	x.udpTarget = echo.LocalAddr().(*net.UDPAddr).AddrPort()
	f.close = append(f.close, func() { _ = echo.Close() })
	echoJoined := make(chan struct{})
	f.register(echoJoined)
	var echoErr error
	f.checks = append(f.checks, func() {
		if echoErr != nil {
			t.Errorf("owned UDP echo worker: %v", echoErr)
		}
	})
	go func() {
		defer close(echoJoined)
		buffer := make([]byte, 2048)
		for {
			if err := echo.SetDeadline(time.Now().Add(7 * time.Second)); err != nil {
				echoErr = err
				return
			}
			n, source, err := echo.ReadFromUDPAddrPort(buffer)
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					echoErr = err
				}
				return
			}
			if _, err := echo.WriteToUDPAddrPort(buffer[:n], source); err != nil {
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
		Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			x.covers.Add(1)
			http.NotFound(w, r)
		}),
		Dialer: transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			x.tcpDials.Add(1)
			if network != "tcp" || address != x.tcpTarget {
				x.unexpected.Add(1)
				return nil, errors.New("UDP cancellation fixture refuses a non-owned TCP target")
			}
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", x.tcpTarget)
		}),
		UDPResolver: UDPResolverFunc(func(ctx context.Context, address string) ([]netip.AddrPort, error) {
			call := x.resolves.Add(1)
			joined := make(chan struct{})
			f.register(joined)
			defer close(joined)
			if address != x.udpTarget.String() {
				x.unexpected.Add(1)
				return nil, errors.New("UDP cancellation fixture refuses a non-owned numeric target")
			}
			if call == 1 {
				defer close(x.resolveJoined)
				close(x.resolveEntered)
				select {
				case <-ctx.Done():
					return nil, context.Cause(ctx)
				case <-f.ctx.Done():
					return nil, context.Cause(f.ctx)
				}
			}
			if call != 2 {
				x.unexpected.Add(1)
			}
			return []netip.AddrPort{x.udpTarget}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	x.handler = server.server.Handler.(*webTunnelHandler)
	original := server.server.Handler
	server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		x.requestCalls.Add(1)
		joined := make(chan struct{})
		f.register(joined)
		defer close(joined)
		auth, _ := r.Context().Value(webServerConnectionAuthContextKey{}).(*webServerConnectionAuth)
		bearer := r.Header.Get("Proxy-Authorization")
		_, short := parseWebSessionBearer(bearer)
		request := &webUDPOpenCancellationRequest{
			auth: auth, full: len(bearer) >= 385 && len(bearer) <= 2047, short: short,
			udp: r.Proto == webConnectUDPProtocol, proto: r.ProtoMajor,
			tls: webRequestTLSVersion(r), joined: joined,
		}
		select {
		case x.requests <- request:
		default:
			x.unexpected.Add(1)
		}
		original.ServeHTTP(w, r)
		request.proof = w.Header().Get(webAuthResponseHeader) != ""
	})
	serveJoined := make(chan struct{})
	f.register(serveJoined)
	var serveErr error
	f.checks = append(f.checks, func() {
		if serveErr != nil {
			t.Errorf("owned UDP cancellation H3 Serve: %v", serveErr)
		}
	})
	f.close = append(f.close, func() {
		if err := server.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("owned UDP cancellation H3 server Close: %v", err)
		}
	})
	go func() { defer close(serveJoined); serveErr = server.Serve(f.ctx) }()
	clientTLS = clientTLS.Clone()
	clientTLS.VerifyConnection = func(state tls.ConnectionState) error {
		if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "h3" || len(state.VerifiedChains) == 0 {
			return errors.New("owned UDP cancellation TLS verification is incomplete")
		}
		x.verified.Add(1)
		return nil
	}
	x.client, err = NewWebH3Client(WebH3ClientConfig{
		ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
		FingerprintProfile: H3FingerprintNative, DialTimeout: time.Second, HandshakeTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	x.client.signer = newWebAuthSigner(mustWebAuthKey(t, webTestToken), nil, x.entropy)
	f.close = append(f.close, func() {
		if err := x.client.Close(); err != nil {
			t.Errorf("owned UDP cancellation H3 client Close: %v", err)
		}
	})
	return x
}

func (x *webUDPOpenCancellationFixture) request(udp, full bool, auth *webServerConnectionAuth) *webUDPOpenCancellationRequest {
	x.f.t.Helper()
	var request *webUDPOpenCancellationRequest
	select {
	case request = <-x.requests:
	case <-x.f.ctx.Done():
		x.f.t.Fatal("actual authenticated H3 request observation exceeded fixture budget")
	}
	if request.udp != udp || request.full != full || request.short == full || request.auth == nil ||
		(auth != nil && request.auth != auth) || request.proto != 3 || request.tls != tls.VersionTLS13 {
		x.f.t.Errorf("actual request UDP/full/short/auth/proto/TLS=%t/%t/%t/%t/%d/%x", request.udp, request.full, request.short, request.auth == auth, request.proto, request.tls)
	}
	return request
}

func (x *webUDPOpenCancellationFixture) tcpEcho(conn net.Conn, payload string, fin bool) {
	x.f.t.Helper()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		x.f.t.Fatal(err)
	}
	if n, err := conn.Write([]byte(payload)); err != nil || n != len(payload) {
		x.f.t.Fatalf("owned TCP sibling write=%d/%d, %v", n, len(payload), err)
	}
	if fin {
		if err := conn.(*webH3Conn).CloseWrite(); err != nil {
			x.f.t.Fatal(err)
		}
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != payload {
		x.f.t.Fatalf("owned TCP sibling echo=%q, %v", got, err)
	}
	if fin {
		extra, err := io.ReadAll(io.LimitReader(conn, 1))
		if err != nil || len(extra) != 0 {
			x.f.t.Fatalf("owned TCP sibling FIN remainder=%q, %v", extra, err)
		}
	}
}

func (x *webUDPOpenCancellationFixture) state(session *webH3ClientSession, users int) {
	x.f.t.Helper()
	x.client.mu.Lock()
	same := x.client.conn == session.conn && x.client.conns[session.conn] == session
	ready, retired, gotUsers := session.authState == webH3ClientAuthReady, session.retired, session.users
	x.client.mu.Unlock()
	session.auth.mu.Lock()
	pending := len(session.auth.pending)
	session.auth.mu.Unlock()
	if !same || !ready || retired || gotUsers != users || pending != 0 || session.conn.Context().Err() != nil {
		x.f.t.Errorf("same physical/Ready/retired/users/pending/live=%t/%t/%t/%d/%d/%t; want users=%d", same, ready, retired, gotUsers, pending, session.conn.Context().Err() == nil, users)
	}
}

func (x *webUDPOpenCancellationFixture) healthyUDP() *webUDPOpenCancellationRequest {
	x.f.t.Helper()
	packet, err := x.client.DialPacket(x.f.ctx)
	if err != nil {
		x.f.t.Fatal(err)
	}
	x.f.close = append(x.f.close, func() { _ = packet.Close() })
	result, joined := make(chan error, 1), make(chan struct{})
	x.f.register(joined)
	payload := []byte("healthy-owned-UDP-after-opening-cancellation")
	go func() {
		defer close(joined)
		if err := packet.Send(payload, x.udpTarget.String()); err != nil {
			result <- err
			return
		}
		got, address, err := packet.Receive()
		if err == nil && (!bytes.Equal(got, payload) || address != x.udpTarget.String()) {
			err = fmt.Errorf("owned UDP echo=%q address=%q", got, address)
		}
		result <- err
	}()
	x.f.wait(joined, "later public PacketConn Send/Receive worker")
	if err := <-result; err != nil {
		x.f.t.Fatal(err)
	}
	request := x.request(true, false, nil)
	if err := packet.Close(); err != nil {
		x.f.t.Fatal(err)
	}
	x.f.wait(request.joined, "later healthy CONNECT-UDP server workers")
	if !request.proof {
		x.f.t.Error("later healthy CONNECT-UDP response lacked authenticated proof")
	}
	return request
}

// This tests the internal opening-context contract, not a per-Send context:
// PacketConn.Send has no context argument, and successful DialPacket detaches
// its caller context from the logical packet association's lifetime.
func TestWebH3ConnectUDPReadCancellationPreservesCallerCause(t *testing.T) {
	for _, mode := range []string{"private_cancel", "operation_deadline"} {
		t.Run(mode, func(t *testing.T) {
			x := newWebUDPOpenCancellationFixture(t)
			sibling, err := x.client.DialContext(x.f.ctx, "tcp", x.tcpTarget)
			if err != nil {
				t.Fatal(err)
			}
			x.f.close = append(x.f.close, func() { _ = sibling.Close() })
			warm := x.request(false, true, nil)
			x.tcpEcho(sibling, "live-sibling-before-UDP-cancel", false)
			x.client.mu.Lock()
			session := x.client.conns[x.client.conn]
			x.client.mu.Unlock()
			if session == nil || session.auth == nil {
				t.Fatal("healthy TCP bootstrap did not establish authentication")
			}
			x.state(session, 1)
			ctx, cancelCause := context.WithCancelCause(x.f.ctx)
			defer cancelCause(context.Canceled)
			var expected error = errors.New("private CONNECT-UDP response-wait cancellation")
			if mode == "operation_deadline" {
				var cancelDeadline context.CancelFunc
				ctx, cancelDeadline = context.WithTimeout(ctx, 500*time.Millisecond)
				defer cancelDeadline()
				expected = context.DeadlineExceeded
			}
			type openResult struct {
				err       error
				hadStream bool
			}
			result, joined := make(chan openResult, 1), make(chan struct{})
			x.f.register(joined)
			go func() {
				defer close(joined)
				stream, err := x.client.openConnectUDPSession(ctx, x.udpTarget.String())
				if stream != nil {
					stream.close() // Independently release any unexpected success.
				}
				result <- openResult{err: err, hadStream: stream != nil}
			}()
			x.f.wait(x.resolveEntered, "real authenticated CONNECT-UDP reached owned blocked resolver")
			failed := x.request(true, false, warm.auth)
			if ctx.Err() != nil {
				t.Fatal("opening context expired before the actual response-wait cancellation witness")
			}
			if mode == "private_cancel" {
				cancelCause(expected)
			}
			x.f.wait(joined, "canceled CONNECT-UDP opening worker")
			got := <-result
			if got.hadStream || got.err != expected {
				t.Errorf("canceled CONNECT-UDP returned stream=%t error=%T %v; want exact caller cause %v", got.hadStream, got.err, got.err, expected)
			}
			x.f.wait(x.resolveJoined, "canceled real resolver callback")
			x.f.wait(failed.joined, "canceled real CONNECT-UDP server handler")
			x.state(session, 1)
			if slots := len(x.handler.udp.slots); slots != 0 {
				t.Errorf("canceled CONNECT-UDP retained %d server UDP admission slots", slots)
			}
			x.tcpEcho(sibling, "live-sibling-after-UDP-cancel", false)
			healthy := x.healthyUDP()
			if healthy.auth != warm.auth {
				t.Error("later healthy UDP did not retain the original authenticated server connection")
			}
			x.state(session, 1)
			later, err := x.client.DialContext(x.f.ctx, "tcp", x.tcpTarget)
			if err != nil {
				t.Fatal(err)
			}
			x.f.close = append(x.f.close, func() { _ = later.Close() })
			laterRequest := x.request(false, false, warm.auth)
			x.tcpEcho(later, "later-TCP-complete-FIN-echo", true)
			_ = later.Close()
			x.f.wait(laterRequest.joined, "later healthy TCP server forwarding worker")
			x.tcpEcho(sibling, "original-sibling-complete-FIN-echo", true)
			_ = sibling.Close()
			x.f.wait(warm.joined, "original live TCP sibling server forwarding worker")
			x.state(session, 0)
			if !warm.proof || !laterRequest.proof || x.entropy.nonceReads.Load() != 1 || x.verified.Load() != 1 ||
				x.requestCalls.Load() != 4 || x.resolves.Load() != 2 || x.tcpDials.Load() != 2 || x.covers.Load() != 0 || x.unexpected.Load() != 0 {
				t.Errorf("healthy proof/nonce/TLS/requests/resolves/TCP/cover/unexpected=%t/%t/%d/%d/%d/%d/%d/%d/%d", warm.proof, laterRequest.proof, x.entropy.nonceReads.Load(), x.verified.Load(), x.requestCalls.Load(), x.resolves.Load(), x.tcpDials.Load(), x.covers.Load(), x.unexpected.Load())
			}
			if len(x.handler.udp.slots) != 0 || len(x.handler.core.sem) != 0 || len(x.client.udpSlots) != 0 {
				t.Error("completed owned flows retained server/client admission slots")
			}
			t.Log("real authenticated resolver cancellation joined; original TCP sibling survived; later complete TCP/UDP echoes reused one verified TLS/H3 connection and one full-authentication nonce")
		})
	}
}
