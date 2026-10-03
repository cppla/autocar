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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

// Done always returns the exact real context's channel. With a Fresh session,
// the first Done evaluation after verified bootstrap becomes Ready is the
// standard context.AfterFunc stop's removeChild -> parentCancelCtx evaluation.
// The pinned Go 1.25/1.27 stop has already claimed its once at that point; this
// gate delays its return, not cancellation publication or a protocol response.
type webH3StreamHandoffContext struct {
	context.Context
	client  *WebH3Client
	entered chan struct{}
	release <-chan struct{}
	fixture context.Context
	gated   atomic.Bool
	expired atomic.Bool
}

func (c *webH3StreamHandoffContext) Done() <-chan struct{} {
	done := c.Context.Done()
	c.client.mu.Lock()
	session := c.client.conns[c.client.conn]
	ready := session != nil && session.authState == webH3ClientAuthReady && session.auth != nil
	c.client.mu.Unlock()
	if ready && c.gated.CompareAndSwap(false, true) {
		close(c.entered)
		select {
		case <-c.release:
		case <-c.fixture.Done():
			c.expired.Store(true)
		}
	}
	return done
}

type webH3StreamHandoffObservation struct {
	connection  *webServerConnectionAuth
	full, short bool
	proto       int
	tlsVersion  uint16
	proof       bool
	joined      <-chan struct{}
}

type webH3StreamHandoffFixture struct {
	f                  *webH2DialSharingFixture
	client             *WebH3Client
	server             *WebH3Server
	tcp                string
	udp                netip.AddrPort
	entropy            *webH2AuthEntropyCounter
	observed           chan webH3StreamHandoffObservation
	covers, unexpected atomic.Int32
}

func newWebH3StreamHandoffFixture(t *testing.T) *webH3StreamHandoffFixture {
	t.Helper()
	f := newWebH2DialSharingFixture(t) // Owns bounded cleanup and every worker join.
	x := &webH3StreamHandoffFixture{f: f, tcp: f.target(), entropy: &webH2AuthEntropyCounter{}, observed: make(chan webH3StreamHandoffObservation, 3)}
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	x.udp = echo.LocalAddr().(*net.UDPAddr).AddrPort()
	f.close = append(f.close, func() { _ = echo.Close() })
	echoJoined, echoResult := make(chan struct{}), make(chan error, 1)
	f.register(echoJoined)
	f.checks = append(f.checks, func() {
		if err := <-echoResult; err != nil {
			t.Errorf("owned UDP echo: %v", err)
		}
	})
	go func() {
		defer close(echoJoined)
		buffer := make([]byte, 2048)
		for {
			if err := echo.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
				echoResult <- err
				return
			}
			n, source, err := echo.ReadFromUDPAddrPort(buffer)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					err = nil
				}
				echoResult <- err
				return
			}
			if _, err := echo.WriteToUDPAddrPort(buffer[:n], source); err != nil {
				echoResult <- err
				return
			}
		}
	}()
	serverTLS, clientTLS := testTLSConfigs(t)
	x.server, err = ListenWebH3(WebH3ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
		DialTimeout: time.Second, HandshakeTimeout: time.Second,
		Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { x.covers.Add(1); http.NotFound(w, r) }),
		Dialer: transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != x.tcp {
				x.unexpected.Add(1)
				return nil, errors.New("non-owned TCP destination")
			}
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", x.tcp)
		}),
		UDPResolver: UDPResolverFunc(func(_ context.Context, address string) ([]netip.AddrPort, error) {
			if address != x.udp.String() {
				x.unexpected.Add(1)
				return nil, errors.New("non-owned UDP destination")
			}
			return []netip.AddrPort{x.udp}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	original := x.server.server.Handler
	x.server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		joined := make(chan struct{})
		f.register(joined)
		defer close(joined)
		connection, _ := r.Context().Value(webServerConnectionAuthContextKey{}).(*webServerConnectionAuth)
		bearer := r.Header.Get("Proxy-Authorization")
		_, short := parseWebSessionBearer(bearer)
		original.ServeHTTP(w, r)
		observation := webH3StreamHandoffObservation{connection: connection, full: len(bearer) >= 385 && len(bearer) <= 2047, short: short,
			proto: r.ProtoMajor, tlsVersion: webRequestTLSVersion(r), proof: w.Header().Get(webAuthResponseHeader) != "", joined: joined}
		select {
		case x.observed <- observation:
		default:
			x.unexpected.Add(1)
		}
	})
	serveJoined, serveResult := make(chan struct{}), make(chan error, 1)
	f.register(serveJoined)
	f.close = append(f.close, func() {
		if err := normalizeWebServerCloseError(x.server.Close()); err != nil {
			t.Errorf("owned H3 server Close: %v", err)
		}
	})
	f.checks = append(f.checks, func() {
		if err := <-serveResult; err != nil {
			t.Errorf("owned H3 Serve: %v", err)
		}
	})
	go func() { defer close(serveJoined); serveResult <- x.server.Serve(f.ctx) }()
	x.client, err = NewWebH3Client(WebH3ClientConfig{
		ServerAddress: x.server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
		FingerprintProfile: H3FingerprintNative, DialTimeout: time.Second, HandshakeTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	x.client.signer = newWebAuthSigner(mustWebAuthKey(t, webTestToken), nil, x.entropy)
	f.close = append(f.close, func() {
		if err := x.client.Close(); err != nil {
			t.Errorf("owned H3 client Close: %v", err)
		}
	})
	return x
}

func (x *webH3StreamHandoffFixture) observation() webH3StreamHandoffObservation {
	x.f.t.Helper()
	select {
	case observation := <-x.observed:
		x.f.wait(observation.joined, "actual signed H3 handler completed")
		if observation.connection == nil || !observation.proof || observation.proto != 3 || observation.tlsVersion != tls.VersionTLS13 {
			x.f.t.Errorf("incomplete real H3 authentication observation: %+v", observation)
		}
		return observation
	case <-x.f.ctx.Done():
		x.f.t.Fatal("owned H3 handler observation exceeded fixture budget")
		return webH3StreamHandoffObservation{}
	}
}

func (x *webH3StreamHandoffFixture) healthyTCP() {
	t := x.f.t
	ctx, cancel := context.WithCancelCause(x.f.ctx)
	defer cancel(context.Canceled)
	conn, err := x.client.DialContext(ctx, "tcp", x.tcp)
	if err != nil {
		t.Fatal(err)
	}
	x.f.close = append(x.f.close, func() { _ = conn.Close() })
	// Cancellation after successful API handoff must not kill this live stream.
	cancel(errors.New("post-success TCP caller no longer owns the stream"))
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("complete-detached-H3-TCP-payload")
	_, writeErr := conn.Write(payload)
	finErr := conn.(*webH3Conn).CloseWrite()
	body, readErr := io.ReadAll(io.LimitReader(conn, int64(len(payload))+1))
	closeErr := conn.Close()
	if writeErr != nil || finErr != nil || readErr != nil || closeErr != nil || !bytes.Equal(body, payload) {
		t.Fatalf("detached TCP echo=%q errors=%v/%v/%v/%v", body, writeErr, finErr, readErr, closeErr)
	}
}

func (x *webH3StreamHandoffFixture) healthyUDP() {
	t := x.f.t
	ctx, cancel := context.WithCancelCause(x.f.ctx)
	defer cancel(context.Canceled)
	opened, err := x.client.openConnectUDPSession(ctx, x.udp.String())
	if err != nil {
		t.Fatal(err)
	}
	x.f.close = append(x.f.close, opened.close)
	cancel(errors.New("post-success UDP caller no longer owns the stream"))
	payload := []byte("complete-detached-H3-UDP-payload")
	type datagramResult struct {
		frame []byte
		err   error
	}
	result, joined := make(chan datagramResult, 1), make(chan struct{})
	x.f.register(joined)
	go func() {
		defer close(joined)
		if err := opened.stream.SendDatagram(encodeConnectUDPDatagram(payload)); err != nil {
			result <- datagramResult{err: err}
			return
		}
		readCtx, stop := context.WithTimeout(x.f.ctx, time.Second)
		defer stop()
		frame, err := opened.stream.ReceiveDatagram(readCtx)
		result <- datagramResult{frame, err}
	}()
	x.f.wait(joined, "actual detached UDP datagram sender and receiver")
	got := <-result
	body, ok := parseConnectUDPDatagram(got.frame)
	if got.err != nil || !ok || !bytes.Equal(body, payload) {
		t.Fatalf("detached UDP echo=%q parsed=%t error=%v", body, ok, got.err)
	}
	opened.close()
}

func webH3StreamHandoffCanceled(t *testing.T, udp bool) {
	x := newWebH3StreamHandoffFixture(t)
	ctx, cancel := context.WithCancelCause(x.f.ctx)
	defer cancel(context.Canceled)
	release := make(chan struct{})
	ungate := sync.OnceFunc(func() { close(release) })
	witness := &webH3StreamHandoffContext{Context: ctx, client: x.client, entered: make(chan struct{}), release: release, fixture: x.f.ctx}
	// Appended last: even Fatal cleanup releases Done before client.Close.
	x.f.close = append(x.f.close, ungate)
	type openResult struct {
		tcp net.Conn
		udp *webConnectUDPStream
		err error
	}
	result, joined := make(chan openResult, 1), make(chan struct{})
	x.f.register(joined)
	go func() {
		defer close(joined)
		var got openResult
		if udp {
			got.udp, got.err = x.client.openConnectUDPSession(witness, x.udp.String())
		} else {
			got.tcp, got.err = x.client.DialContext(witness, "tcp", x.tcp)
		}
		result <- got
	}()
	x.f.wait(witness.entered, "real AfterFunc stop held after first verified signed 200")
	x.client.mu.Lock()
	physical := x.client.conn
	session := x.client.conns[physical]
	ready := session != nil && session.authState == webH3ClientAuthReady && session.auth != nil && session.users == 1
	x.client.mu.Unlock()
	if !ready || physical == nil || x.entropy.nonceReads.Load() != 1 {
		t.Fatal("stop gate was not after exactly one real Fresh bootstrap")
	}
	state := physical.ConnectionState().TLS
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "h3" || len(state.VerifiedChains) == 0 {
		t.Fatal("gated physical TLS was not actually verified TLS1.3/H3")
	}
	cause := errors.New("private cancellation after verified H3 stream proof")
	cancel(cause)
	// Do not call witness.Done here: the unmodified real context is the signal.
	x.f.wait(ctx.Done(), "real original caller cancellation published")
	ungate()
	x.f.wait(joined, "post-proof canceled stream opener")
	got := <-result
	if got.tcp != nil || got.udp != nil || got.err != cause {
		t.Errorf("post-proof handoff tcp=%t udp=%t err=%v, want nil objects and exact private cause", got.tcp != nil, got.udp != nil, got.err)
	}
	x.client.mu.Lock()
	current, users, readyAfter, selected := x.client.conn, session.users, session.authState == webH3ClientAuthReady, x.client.selected
	x.client.mu.Unlock()
	if current != physical || !readyAfter || users != 0 || selected {
		t.Errorf("rejected handoff changed ownership/auth/selection: same=%t ready=%t users=%d selected=%t", current == physical, readyAfter, users, selected)
	}
	if witness.expired.Load() {
		t.Error("Done gate was released by fixture expiry rather than explicit test release")
	}
	// Independent disposal preserves bounded old-source failure and allows the
	// later real healthy controls to run even if a live object leaked to caller.
	if got.tcp != nil {
		_ = got.tcp.Close()
	}
	if got.udp != nil {
		got.udp.close()
	}
	first := x.observation()
	if !first.full || first.short {
		t.Error("first real request was not the one full connection credential")
	}
	x.healthyTCP()
	second := x.observation()
	x.healthyUDP()
	third := x.observation()
	x.client.mu.Lock()
	current, users = x.client.conn, session.users
	x.client.mu.Unlock()
	if current != physical || users != 0 || physical.Context().Err() != nil || !second.short || !third.short ||
		first.connection != second.connection || first.connection != third.connection || x.entropy.nonceReads.Load() != 1 || x.covers.Load() != 0 || x.unexpected.Load() != 0 {
		t.Errorf("later healthy TCP/UDP reuse failed: same=%t users=%d physicalErr=%v short=%t/%t fullNonces=%d cover/unexpected=%d/%d", current == physical, users, physical.Context().Err(), second.short, third.short, x.entropy.nonceReads.Load(), x.covers.Load(), x.unexpected.Load())
	}
	t.Log(fmt.Sprintf("real signed %s bootstrap stop gate, exact caller cause, healthy short TCP/UDP complete echoes and detached cancellation controls evaluated", map[bool]string{false: "TCP", true: "UDP"}[udp]))
}

func TestWebH3TCPStreamHandoffPreservesCallerCancellation(t *testing.T) {
	webH3StreamHandoffCanceled(t, false)
}

func TestWebH3UDPStreamHandoffPreservesCallerCancellation(t *testing.T) {
	webH3StreamHandoffCanceled(t, true)
}
