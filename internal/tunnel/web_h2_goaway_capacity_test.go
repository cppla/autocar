package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
	"golang.org/x/net/http2"
)

// Capacity is not an unusable-connection signal, but an active GOAWAY is.
// A genuine client PING_ACK, ordered after the injected GOAWAY, establishes
// that the client read loop processed it before the next public DialContext.
func TestWebH2CapacityDoesNotQueueOnDrainingConnection(t *testing.T) {
	f := newWebH2GoAwayFixture(t)
	first := f.open()
	f.ack(first, []byte("first authenticated stream remains open\x00\xff"))
	initial := f.request(0)
	f.client.mu.Lock()
	old := f.client.current
	ready := old != nil && old.authState == webH2ClientAuthReady && old.auth != nil
	f.client.mu.Unlock()
	if !ready || initial.short || initial.physical == nil {
		t.Fatal("first stream did not establish physical-connection authentication")
	}
	state := old.conn.ConnectionState()
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != webH2ALPN || len(state.VerifiedChains) == 0 {
		t.Fatalf("verified first TLS/ALPN=%#x/%q/chains%d", state.Version, state.NegotiatedProtocol, len(state.VerifiedChains))
	}
	if err := initial.wire.goAwayAndPing(); err != nil {
		t.Fatalf("actual GOAWAY/PING write: %v", err)
	}
	f.require(initial.wire.acked, "client processed GOAWAY then acknowledged following PING")
	// The old physical connection is still carrying the admitted stream.
	// Its continued echo rules out a connection-level shutdown as the witness.
	f.ack(first, []byte("old sibling survives real GOAWAY"))

	second := f.open() // One public call must select/reselect a fresh physical connection.
	secondRequest := f.request(1)
	f.client.mu.Lock()
	fresh := f.client.current
	f.client.mu.Unlock()
	if fresh == nil || fresh == old || fresh.conn == old.conn || secondRequest.wire == initial.wire || secondRequest.physical == initial.physical || secondRequest.short {
		t.Error("new caller did not establish full authentication on a different physical connection")
	}
	f.finish(second, bytes.Repeat([]byte{'n', 'e', 'w', 0, 255, 1}, 2048))
	f.require(secondRequest.done, "new physical connection handler completed")
	f.targetResult()

	// Retiring the selected connection must not kill an already admitted sibling.
	f.ack(first, []byte("old sibling survives new authenticated connection"))
	f.finish(first, nil)
	f.require(initial.done, "old sibling completed its upload and reply FIN")
	f.targetResult()

	third := f.open()
	thirdRequest := f.request(2)
	f.finish(third, bytes.Repeat([]byte{'s', 'h', 'o', 'r', 't', 0}, 2048))
	f.require(thirdRequest.done, "new physical connection short-auth handler completed")
	f.targetResult()
	f.client.mu.Lock()
	sameFresh := f.client.current == fresh && fresh != nil && fresh.authState == webH2ClientAuthReady
	f.client.mu.Unlock()
	if !sameFresh || thirdRequest.wire != secondRequest.wire || thirdRequest.physical != secondRequest.physical || !thirdRequest.short {
		t.Error("later healthy caller did not reuse the new physical connection with short authentication")
	}
	requests := f.requestsSnapshot()
	if len(requests) != 3 {
		t.Errorf("actual authenticated handlers=%d, want full/full/short", len(requests))
	}
	if got := f.physicalDials.Load(); got != 2 {
		t.Errorf("actual physical dials=%d, want 2", got)
	}
	if got := f.accepted.Load(); got != 2 {
		t.Errorf("accepted physical TLS connections=%d, want 2", got)
	}
	if got := f.entropy.nonceReads.Load(); got != 2 {
		t.Errorf("full-auth nonce reads=%d, want 2", got)
	}
	if got := f.destinationDials.Load(); got != 3 {
		t.Errorf("actual owned destination dials=%d, want 3", got)
	}
	if len(f.admission.sem) != 0 {
		t.Error("complete FIN exchanges retained stream admission")
	}
	t.Log("real TLS13/h2: GOAWAY then observed PING_ACK; old admitted sibling survives; one public caller reconnects; full/full/short on two physical connections; three complete FIN echoes")
}

// The second request is really decoded and authenticated by the peer before
// it sends a protocol reset. Unlike an unencoded GOAWAY rejection, this is
// not safe to replay: a live context alone must not authorize another dial.
func TestWebH2EncodedProtocolResetDoesNotRetry(t *testing.T) {
	f := newWebH2GoAwayFixtureConfigured(t, 2, true)
	first := f.open()
	f.ack(first, []byte("first sibling before encoded protocol reset"))
	initial := f.request(0)
	f.client.mu.Lock()
	old := f.client.current
	ready := old != nil && old.authState == webH2ClientAuthReady && old.auth != nil
	f.client.mu.Unlock()
	if !ready || initial.short || initial.physical == nil {
		t.Fatal("first stream did not establish physical-connection authentication")
	}
	state := old.conn.ConnectionState()
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != webH2ALPN || len(state.VerifiedChains) == 0 {
		t.Fatal("first stream did not verify TLS13/h2")
	}
	ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
	conn, err := f.client.DialContext(ctx, "tcp", f.target.Addr().String())
	callerLive := ctx.Err() == nil
	cancel()
	f.own(conn)
	if conn != nil {
		_ = conn.Close()
		t.Error("encoded protocol reset returned a successful connection")
	}
	var reset http2.StreamError
	if !errors.As(err, &reset) || reset.StreamID != 3 || reset.Code != http2.ErrCodeProtocol {
		t.Errorf("encoded reset result=%v, want peer PROTOCOL_ERROR on stream 3", err)
	}
	if !callerLive {
		t.Error("protocol reset result consumed the caller deadline instead of returning its stream error")
	}
	f.require(f.resetWritten, "actual protocol reset written after short authentication")
	f.releaseReset()
	secondRequest := f.request(1)
	f.require(secondRequest.done, "reset request handler completed")
	if !secondRequest.short || secondRequest.wire != initial.wire || secondRequest.physical != initial.physical {
		t.Error("encoded second request did not use the first physical connection's short authentication")
	}
	if got := f.physicalDials.Load(); got != 1 {
		t.Errorf("encoded rejected request automatically made %d physical dials, want 1", got)
	}
	if got := f.entropy.nonceReads.Load(); got != 1 {
		t.Errorf("encoded rejected request automatically generated %d full-auth nonces, want 1", got)
	}
	if got := f.destinationDials.Load(); got != 2 || len(f.requestsSnapshot()) != 2 {
		t.Error("encoded rejected request was retried at the authenticated peer")
	}
	f.ack(first, []byte("first sibling survives encoded protocol reset"))
	f.finish(first, nil)
	f.require(initial.done, "surviving first sibling completed its FIN exchange")
	f.targetResult()

	// A later independent caller can recover on a new physical connection.
	healthy := f.open()
	recovery := f.request(2)
	f.finish(healthy, bytes.Repeat([]byte{'r', 'e', 'c', 'o', 'v', 0}, 2048))
	f.require(recovery.done, "independent recovery handler completed")
	f.targetResult()
	if recovery.short || recovery.wire == initial.wire || recovery.physical == initial.physical {
		t.Error("independent recovery did not establish fresh physical authentication")
	}
	if f.physicalDials.Load() != 2 || f.accepted.Load() != 2 || f.entropy.nonceReads.Load() != 2 || f.destinationDials.Load() != 3 || len(f.requestsSnapshot()) != 3 {
		t.Error("independent healthy recovery did not use exactly one fresh physical dial/bootstrap/destination")
	}
	if len(f.admission.sem) != 0 {
		t.Error("completed reset/recovery handlers retained stream admission")
	}
	t.Log("actual short-auth target dial entry then peer RST_STREAM(PROTOCOL_ERROR); live caller returns typed stream error with no retry; first sibling survives FIN; later independent caller recovers")
}

type webH2GoAwayWireContextKey struct{}

type webH2GoAwayRequest struct {
	physical *webServerConnectionAuth
	short    bool
	wire     *webH2GoAwayTLSConn
	done     chan struct{}
}

type webH2GoAwayFixture struct {
	t                *testing.T
	ctx              context.Context
	cancel           context.CancelFunc
	client           *WebH2Client
	relay            *net.TCPListener
	target           *net.TCPListener
	admission        *StreamAdmission
	entropy          webH2AuthEntropyCounter
	physicalDials    atomic.Int64
	accepted         atomic.Int64
	destinationDials atomic.Int64
	results          chan error
	mu               sync.Mutex
	closed           bool
	conns            []net.Conn
	joins            []<-chan struct{}
	requests         []webH2GoAwayRequest
	workerErrors     []error
	resetWritten     chan struct{}
	resetRelease     chan struct{}
	resetReleaseOnce sync.Once
}

func newWebH2GoAwayFixture(t *testing.T) *webH2GoAwayFixture {
	return newWebH2GoAwayFixtureConfigured(t, 1, false)
}

func newWebH2GoAwayFixtureConfigured(t *testing.T, maxStreams uint32, resetSecond bool) *webH2GoAwayFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	f := &webH2GoAwayFixture{t: t, ctx: ctx, cancel: cancel, results: make(chan error, 4), resetWritten: make(chan struct{}), resetRelease: make(chan struct{})}
	t.Cleanup(f.cleanup)
	var err error
	f.target, err = net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	f.relay, err = net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	f.admission, err = NewStreamAdmission(2)
	if err != nil {
		t.Fatal(err)
	}
	core, err := newServerCoreWithAdmission(testToken, transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != f.target.Addr().String() {
			return nil, fmt.Errorf("fixture refused unowned destination %q/%q", network, address)
		}
		if sequence := f.destinationDials.Add(1); resetSecond && sequence == 2 {
			// The real handler authenticates before invoking its target dialer.
			// This peer reset therefore follows receipt of encoded short-ticket
			// HEADERS, but no second actual destination socket is opened.
			wire, _ := ctx.Value(webH2GoAwayWireContextKey{}).(*webH2GoAwayTLSConn)
			if wire == nil {
				return nil, errors.New("owned target dial omitted its physical TLS context")
			}
			if err := wire.protocolReset(); err != nil {
				f.workerError(err)
				return nil, err
			}
			close(f.resetWritten)
			// Do not race the intended peer stream error with a subsequent
			// signed 502: native RoundTrip favors simultaneously ready headers.
			// This fixture gate is released only after the caller observes the
			// reset, and is independently released on every cleanup path.
			select {
			case <-f.resetRelease:
			case <-ctx.Done():
			}
			return nil, errors.New("owned target refused after an actual encoded-request protocol reset")
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", address)
		f.own(conn)
		return conn, err
	}), 2*time.Second, 2*time.Second, 0, 2, f.admission)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := newWebAuthVerifier(mustWebAuthKey(t, testToken), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	handler := &webTunnelHandler{core: core, auth: auth, cover: http.NotFoundHandler()}
	serverTLS, clientTLS := testTLSConfigs(t)
	serverTLS, err = webServerTLSConfig(serverTLS, webH2ALPN)
	if err != nil {
		t.Fatal(err)
	}
	f.client, err = newWebH2ClientWithSigner(WebH2ClientConfig{ServerAddress: f.relay.Addr().String(), Token: testToken,
		TLSConfig: clientTLS, FingerprintProfile: FingerprintNative, DialTimeout: 2 * time.Second, HandshakeTimeout: 2 * time.Second},
		newWebAuthSigner(mustWebAuthKey(t, testToken), nil, &f.entropy), webAuthClaims{})
	if err != nil {
		t.Fatal(err)
	}
	f.client.dialer = transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != f.relay.Addr().String() {
			return nil, fmt.Errorf("fixture refused unowned relay %q/%q", network, address)
		}
		f.physicalDials.Add(1)
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", address)
		f.own(conn)
		return conn, err
	})
	targetDone := make(chan struct{})
	f.register(targetDone)
	go func() {
		defer close(targetDone)
		for {
			conn, err := f.target.AcceptTCP()
			if err != nil {
				return
			}
			if !f.own(conn) {
				continue
			}
			done := make(chan struct{})
			f.register(done)
			go func() {
				defer close(done)
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(7 * time.Second))
				_, err := io.Copy(conn, conn)
				if err == nil {
					err = conn.CloseWrite()
				}
				select {
				case f.results <- err:
				case <-f.ctx.Done():
				}
			}()
		}
	}()
	relayDone := make(chan struct{})
	f.register(relayDone)
	go func() {
		defer close(relayDone)
		for {
			raw, err := f.relay.AcceptTCP()
			if err != nil {
				return
			}
			if !f.own(raw) {
				continue
			}
			f.accepted.Add(1)
			done := make(chan struct{})
			f.register(done)
			go func() {
				defer close(done)
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(7 * time.Second))
				conn := tls.Server(raw, serverTLS)
				handshakeCtx, stop := context.WithTimeout(f.ctx, 2*time.Second)
				err := conn.HandshakeContext(handshakeCtx)
				stop()
				if err != nil {
					f.workerError(err)
					return
				}
				state := conn.ConnectionState()
				if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != webH2ALPN {
					f.workerError(errors.New("owned peer did not negotiate TLS13/h2"))
					return
				}
				wire := &webH2GoAwayTLSConn{Conn: conn, acked: make(chan struct{})}
				physical := newWebServerConnectionAuth(conn.Close)
				ctx := context.WithValue(f.ctx, webTLSConnectionContextKey{}, conn)
				ctx = context.WithValue(ctx, webServerConnectionAuthContextKey{}, physical)
				ctx = context.WithValue(ctx, webH2GoAwayWireContextKey{}, wire)
				observed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, short := parseWebSessionBearer(r.Header.Get("Proxy-Authorization"))
					request := webH2GoAwayRequest{physical: physical, short: short, wire: wire, done: make(chan struct{})}
					f.mu.Lock()
					if f.closed {
						f.mu.Unlock()
						return
					}
					f.requests = append(f.requests, request)
					f.joins = append(f.joins, request.done)
					f.mu.Unlock()
					defer close(request.done)
					handler.ServeHTTP(w, r)
				})
				(&http2.Server{MaxConcurrentStreams: maxStreams}).ServeConn(wire, &http2.ServeConnOpts{Context: ctx, Handler: observed})
			}()
		}
	}()
	return f
}

func (f *webH2GoAwayFixture) own(conn net.Conn) bool {
	if conn == nil {
		return false
	}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		_ = conn.Close()
		return false
	}
	f.conns = append(f.conns, conn)
	f.mu.Unlock()
	return true
}

func (f *webH2GoAwayFixture) register(done <-chan struct{}) {
	f.mu.Lock()
	f.joins = append(f.joins, done)
	f.mu.Unlock()
}

func (f *webH2GoAwayFixture) workerError(err error) {
	f.mu.Lock()
	if !f.closed {
		f.workerErrors = append(f.workerErrors, err)
	}
	f.mu.Unlock()
}

func (f *webH2GoAwayFixture) require(done <-chan struct{}, what string) {
	f.t.Helper()
	select {
	case <-done:
	case <-f.ctx.Done():
		f.t.Fatalf("%s: %v", what, context.Cause(f.ctx))
	}
}

func (f *webH2GoAwayFixture) open() net.Conn {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
	defer cancel()
	conn, err := f.client.DialContext(ctx, "tcp", f.target.Addr().String())
	f.own(conn)
	if err != nil || conn == nil {
		f.t.Fatalf("healthy public H2 DialContext: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(6 * time.Second)); err != nil {
		f.t.Fatal(err)
	}
	return conn
}

func (f *webH2GoAwayFixture) ack(conn net.Conn, payload []byte) {
	f.t.Helper()
	if _, err := io.Copy(conn, bytes.NewReader(payload)); err != nil {
		f.t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
		f.t.Fatalf("held stream echo=%d bytes, error=%v", len(got), err)
	}
}

func (f *webH2GoAwayFixture) finish(conn net.Conn, payload []byte) {
	f.t.Helper()
	if _, err := io.Copy(conn, bytes.NewReader(payload)); err != nil {
		f.t.Fatal(err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		f.t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	_ = conn.Close()
	if err != nil || !bytes.Equal(got, payload) {
		f.t.Fatalf("FIN echo=%d/%d, error=%v", len(got), len(payload), err)
	}
}

func (f *webH2GoAwayFixture) request(index int) webH2GoAwayRequest {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) <= index {
		f.t.Fatal("successful CONNECT had no actual handler observation")
	}
	return f.requests[index]
}

func (f *webH2GoAwayFixture) requestsSnapshot() []webH2GoAwayRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]webH2GoAwayRequest(nil), f.requests...)
}

func (f *webH2GoAwayFixture) targetResult() {
	f.t.Helper()
	select {
	case err := <-f.results:
		if err != nil {
			f.t.Fatalf("actual target EOF/echo: %v", err)
		}
	case <-f.ctx.Done():
		f.t.Fatal("actual target did not complete")
	}
}

func (f *webH2GoAwayFixture) releaseReset() {
	f.resetReleaseOnce.Do(func() { close(f.resetRelease) })
}

func (f *webH2GoAwayFixture) cleanup() {
	f.mu.Lock()
	f.closed = true
	conns := append([]net.Conn(nil), f.conns...)
	f.mu.Unlock()
	f.cancel()
	f.releaseReset()
	if f.relay != nil {
		_ = f.relay.Close()
	}
	if f.target != nil {
		_ = f.target.Close()
	}
	// Independently close the actual raw sockets before relying on Client.Close.
	for _, conn := range conns {
		_ = conn.Close()
	}
	closed := make(chan struct{})
	var closeErr error
	go func() {
		defer close(closed)
		if f.client != nil {
			closeErr = f.client.Close()
		}
	}()
	limit := time.NewTimer(2 * time.Second)
	defer limit.Stop()
	select {
	case <-closed:
		if !destinationDialOwnershipOnlyClosed(closeErr) {
			f.t.Errorf("client Close: %v", closeErr)
		}
	case <-limit.C:
		f.t.Error("client Close did not join")
		return
	}
	for i := 0; ; i++ {
		f.mu.Lock()
		if i == len(f.joins) {
			f.mu.Unlock()
			break
		}
		done := f.joins[i]
		f.mu.Unlock()
		select {
		case <-done:
		case <-limit.C:
			f.t.Errorf("owned worker %d did not join", i)
			return
		}
	}
	f.mu.Lock()
	errs := append([]error(nil), f.workerErrors...)
	f.mu.Unlock()
	for _, err := range errs {
		f.t.Errorf("owned TLS worker: %v", err)
	}
	if f.admission != nil && len(f.admission.sem) != 0 {
		f.t.Error("cleanup retained stream admission")
	}
	f.t.Log("owned real raw sockets, target/handler/TLS/ServeConn workers and client Close joined")
}

// This test-only wrapper serializes injection with the server's own writes.
// It preserves all bytes and observes only the fixed PING_ACK payload while
// ServeConn remains the sole owner of reading and interpreting client frames.
type webH2GoAwayTLSConn struct {
	*tls.Conn
	writeMu   sync.Mutex
	readMu    sync.Mutex
	acked     chan struct{}
	ackOnce   sync.Once
	header    [9]byte
	headerN   int
	prefaceN  int
	remaining uint32
	pingACK   bool
	ping      [8]byte
	pingN     int
}

var webH2GoAwayPing = [8]byte{'g', 'o', 'a', 'w', 'a', 'y', 0, 255}

func (c *webH2GoAwayTLSConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.Conn.Write(p)
}

func (c *webH2GoAwayTLSConn) goAwayAndPing() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	framer := http2.NewFramer(c.Conn, nil)
	if err := framer.WriteGoAway(1, http2.ErrCodeNo, nil); err != nil {
		return err
	}
	return framer.WritePing(false, webH2GoAwayPing)
}

func (c *webH2GoAwayTLSConn) protocolReset() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return http2.NewFramer(c.Conn, nil).WriteRSTStream(3, http2.ErrCodeProtocol)
}

func (c *webH2GoAwayTLSConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	n, err := c.Conn.Read(p)
	c.observe(p[:n])
	return n, err
}

func (c *webH2GoAwayTLSConn) observe(p []byte) {
	for len(p) > 0 {
		if c.prefaceN < len(http2.ClientPreface) {
			n := min(len(p), len(http2.ClientPreface)-c.prefaceN)
			c.prefaceN += n
			p = p[n:]
			continue
		}
		if c.remaining != 0 {
			n := min(len(p), int(c.remaining))
			if c.pingACK {
				c.pingN += copy(c.ping[c.pingN:], p[:n])
			}
			p = p[n:]
			c.remaining -= uint32(n)
			if c.remaining == 0 && c.pingACK && c.pingN == len(c.ping) && c.ping == webH2GoAwayPing {
				c.ackOnce.Do(func() { close(c.acked) })
			}
			continue
		}
		used := copy(c.header[c.headerN:], p)
		c.headerN += used
		// Consume exactly the copied header bytes, including fragmented headers.
		p = p[used:]
		if c.headerN != len(c.header) {
			continue
		}
		c.remaining = uint32(c.header[0])<<16 | uint32(c.header[1])<<8 | uint32(c.header[2])
		stream := binary.BigEndian.Uint32(c.header[5:]) & 0x7fffffff
		c.pingACK = c.header[3] == byte(http2.FramePing) && c.header[4]&byte(http2.FlagPingAck) != 0 && stream == 0 && c.remaining == 8
		c.pingN = 0
		c.headerN = 0
	}
}
