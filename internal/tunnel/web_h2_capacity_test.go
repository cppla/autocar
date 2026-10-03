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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
	"golang.org/x/net/http2"
)

// An occupied, healthy HTTP/2 connection is not a failed physical connection.
// The peer really advertises one stream and the first authenticated stream
// remains open. The second caller must queue on that connection, not redial.
func TestWebH2CapacityQueuesWithoutReplacingAuthenticatedSession(t *testing.T) {
	f := newWebH2CapacityFixture(t)
	first := f.open()
	f.ack(first, []byte("held authenticated stream\x00\xff"))
	firstRequest := f.request(0)
	f.client.mu.Lock()
	session := f.client.current
	ready := session != nil && session.authState == webH2ClientAuthReady && session.auth != nil
	f.client.mu.Unlock()
	if !ready {
		t.Fatal("first stream did not establish a ready authenticated session")
	}
	state := session.conn.ConnectionState()
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != webH2ALPN || firstRequest.short || firstRequest.physical == nil {
		t.Fatalf("first stream TLS/ALPN/bootstrap=%#x/%q/%v", state.Version, state.NegotiatedProtocol, firstRequest.short)
	}
	observer := f.observe(session.h2)
	f.checkpoint(observer, false)
	if got := f.physicalDials.Load(); got != 1 {
		t.Fatalf("first stream used %d physical dials", got)
	}

	cause := errors.New("capacity fixture private caller cancellation")
	caller, cancel := context.WithCancelCause(f.ctx)
	defer cancel(context.Canceled)
	result := make(chan webH2CapacityDialResult, 1)
	joined := make(chan struct{})
	f.register(joined)
	go func() {
		defer close(joined)
		conn, err := f.client.DialContext(caller, "tcp", f.target.Addr().String())
		f.own(conn)
		result <- webH2CapacityDialResult{conn: conn, err: err}
	}()
	// State.Pending is a real HTTP/2 request waiting for a concurrency slot.
	// The alternative is an actual second physical DialContext invocation.
	// A caller AfterFunc/Done registration is deliberately not a wait witness.
	f.checkpoint(observer, true)
	if got := f.physicalDials.Load(); got != 1 {
		t.Errorf("occupied healthy connection caused %d physical dials, want 1", got)
	}
	if got := f.entropy.nonceReads.Load(); got != 1 {
		t.Errorf("queued caller generated %d full-auth nonces, want 1", got)
	}
	if got := f.requestCount(); got != 1 {
		t.Errorf("queued caller reached %d server handlers before capacity release, want 1", got)
	}
	cancel(cause)
	f.require(joined, "second caller joined after cancellation")
	second := <-result // Publication precedes the joined signal.
	if second.conn != nil {
		_ = second.conn.Close()
		t.Error("canceled queued caller returned a connection")
	}
	if second.err != cause {
		t.Errorf("queued caller error=%v, want exact private cancellation cause", second.err)
	}
	f.ack(first, []byte("first stream survives sibling cancel"))
	f.sameSession(session)
	f.finish(first, nil)
	f.require(firstRequest.done, "first server handler completed after FIN")
	f.targetResult()

	// After genuine capacity release, both independent live callers must use
	// short authentication on the original physical connection and carry data.
	for i := 0; i < 2; i++ {
		conn := f.open()
		payload := bytes.Repeat([]byte{byte(i), 'h', '2', 'q', 0, 255}, 2048)
		f.finish(conn, payload)
		f.targetResult()
		f.sameSession(session)
	}
	for _, request := range f.requestsSnapshot() {
		f.require(request.done, "observed server handler joined")
	}
	requests := f.requestsSnapshot()
	if len(requests) != 3 {
		t.Errorf("server handlers=%d, want initial full plus two healthy short requests", len(requests))
	} else {
		for i, request := range requests {
			if request.physical != firstRequest.physical || request.short != (i != 0) {
				t.Errorf("request %d did not preserve physical auth/full-short sequence", i)
			}
		}
	}
	if got := f.physicalDials.Load(); got != 1 {
		t.Errorf("physical dials=%d after healthy continuations, want 1", got)
	}
	if got := f.entropy.nonceReads.Load(); got != 1 {
		t.Errorf("full-auth nonces=%d after healthy continuations, want 1", got)
	}
	if got := f.destinationDials.Load(); got != 3 {
		t.Errorf("actual destination dials=%d, want 3", got)
	}
	if len(f.admission.sem) != 0 {
		t.Error("completed handlers retained stream admission")
	}
	t.Log("capacity=1: actual pending-or-redial witness, exact caller cause, surviving first stream, two complete FIN echoes, full/short/short on one physical connection")
}

type webH2CapacityDialResult struct {
	conn net.Conn
	err  error
}

type webH2CapacityRequest struct {
	physical *webServerConnectionAuth
	short    bool
	done     chan struct{}
}

type webH2CapacityObserver struct {
	mu      sync.Mutex
	state   http2.ClientConnState
	changed chan struct{}
}

type webH2CapacityFixture struct {
	t                *testing.T
	ctx              context.Context
	cancel           context.CancelFunc
	client           *WebH2Client
	server           *WebH2Server
	target           *net.TCPListener
	admission        *StreamAdmission
	entropy          webH2AuthEntropyCounter
	physicalDials    atomic.Int64
	destinationDials atomic.Int64
	extraPhysical    chan struct{}
	results          chan error
	mu               sync.Mutex
	closed           bool
	conns            []net.Conn
	joins            []<-chan struct{}
	requests         []webH2CapacityRequest
	serveErr         error
}

func newWebH2CapacityFixture(t *testing.T) *webH2CapacityFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	f := &webH2CapacityFixture{t: t, ctx: ctx, cancel: cancel, extraPhysical: make(chan struct{}, 1), results: make(chan error, 4)}
	t.Cleanup(f.cleanup)
	var err error
	f.target, err = net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
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
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
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
	f.admission, err = NewStreamAdmission(1)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, clientTLS := testTLSConfigs(t)
	f.server, err = ListenWebH2(WebH2ServerConfig{Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
		StreamAdmission: f.admission, Cover: http.NotFoundHandler(), Dialer: transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != f.target.Addr().String() {
				return nil, fmt.Errorf("fixture refused unowned target %q/%q", network, address)
			}
			f.destinationDials.Add(1)
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", address)
			f.own(conn)
			return conn, err
		})})
	if err != nil {
		t.Fatal(err)
	}
	handler := f.server.server.Handler
	f.server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		physical, _ := r.Context().Value(webServerConnectionAuthContextKey{}).(*webServerConnectionAuth)
		_, short := parseWebSessionBearer(r.Header.Get("Proxy-Authorization"))
		request := webH2CapacityRequest{physical: physical, short: short, done: make(chan struct{})}
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
	f.client, err = newWebH2ClientWithSigner(WebH2ClientConfig{ServerAddress: f.server.Addr().String(), Token: testToken,
		TLSConfig: clientTLS, FingerprintProfile: FingerprintNative}, newWebAuthSigner(mustWebAuthKey(t, testToken), nil, &f.entropy), webAuthClaims{})
	if err != nil {
		t.Fatal(err)
	}
	f.client.dialer = transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != f.server.Addr().String() {
			return nil, fmt.Errorf("fixture refused unowned relay %q/%q", network, address)
		}
		if f.physicalDials.Add(1) > 1 {
			select {
			case f.extraPhysical <- struct{}{}:
			default:
			}
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", address)
		f.own(conn)
		return conn, err
	})
	serveDone := make(chan struct{})
	f.register(serveDone)
	go func() { defer close(serveDone); f.serveErr = f.server.Serve(f.ctx) }()
	return f
}

func (f *webH2CapacityFixture) own(conn net.Conn) bool {
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

func (f *webH2CapacityFixture) register(done <-chan struct{}) {
	f.mu.Lock()
	f.joins = append(f.joins, done)
	f.mu.Unlock()
}

func (f *webH2CapacityFixture) require(done <-chan struct{}, what string) {
	f.t.Helper()
	select {
	case <-done:
	case <-f.ctx.Done():
		f.t.Fatalf("%s: %v", what, context.Cause(f.ctx))
	}
}

func (f *webH2CapacityFixture) open() net.Conn {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
	defer cancel()
	conn, err := f.client.DialContext(ctx, "tcp", f.target.Addr().String())
	f.own(conn)
	if err != nil || conn == nil {
		f.t.Fatalf("healthy public H2 DialContext: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		f.t.Fatal(err)
	}
	return conn
}

func (f *webH2CapacityFixture) ack(conn net.Conn, payload []byte) {
	f.t.Helper()
	if _, err := io.Copy(conn, bytes.NewReader(payload)); err != nil {
		f.t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
		f.t.Fatalf("live held stream echo=%d bytes, error=%v", len(got), err)
	}
}

func (f *webH2CapacityFixture) finish(conn net.Conn, payload []byte) {
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

func (f *webH2CapacityFixture) targetResult() {
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

func (f *webH2CapacityFixture) request(index int) webH2CapacityRequest {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) <= index {
		f.t.Fatal("successful CONNECT had no server handler observation")
	}
	return f.requests[index]
}

func (f *webH2CapacityFixture) requestCount() int { return len(f.requestsSnapshot()) }

func (f *webH2CapacityFixture) requestsSnapshot() []webH2CapacityRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]webH2CapacityRequest(nil), f.requests...)
}

func (f *webH2CapacityFixture) sameSession(want *webH2ClientSession) {
	f.client.mu.Lock()
	defer f.client.mu.Unlock()
	if f.client.current != want || want.authState != webH2ClientAuthReady || want.auth == nil || len(f.client.sessions) != 1 {
		f.t.Error("capacity/caller cancellation replaced or invalidated the ready physical session")
	}
}

func (f *webH2CapacityFixture) observe(conn *http2.ClientConn) *webH2CapacityObserver {
	observer := &webH2CapacityObserver{changed: make(chan struct{}, 1)}
	done := make(chan struct{})
	f.register(done)
	go func() {
		defer close(done)
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		for {
			// Legacy State may acquire a wire-write lock. Never hold client.mu
			// here; independent cleanup closes the real raw socket before joining.
			state := conn.State()
			observer.mu.Lock()
			observer.state = state
			observer.mu.Unlock()
			select {
			case observer.changed <- struct{}{}:
			default:
			}
			select {
			case <-tick.C:
			case <-f.ctx.Done():
				return
			}
		}
	}()
	return observer
}

func (f *webH2CapacityFixture) checkpoint(observer *webH2CapacityObserver, pending bool) {
	f.t.Helper()
	limit := time.NewTimer(time.Second)
	defer limit.Stop()
	for {
		observer.mu.Lock()
		state := observer.state
		observer.mu.Unlock()
		if state.MaxConcurrentStreams == 1 && state.StreamsActive >= 1 && !state.Closed && !state.Closing && (!pending || state.StreamsPending >= 1) {
			f.t.Logf("real H2 capacity witness: active=%d pending=%d max=%d", state.StreamsActive, state.StreamsPending, state.MaxConcurrentStreams)
			return
		}
		select {
		case <-observer.changed:
		case <-f.extraPhysical:
			f.t.Error("second actual physical DialContext entered while original H2 connection was occupied and healthy")
			return // Continue cancellation, real healthy recovery and cleanup.
		case <-limit.C:
			f.t.Fatalf("no actual H2 capacity/pending witness: %+v", state)
		case <-f.ctx.Done():
			f.t.Fatal("independent fixture expired at capacity checkpoint")
		}
	}
}

func (f *webH2CapacityFixture) cleanup() {
	f.mu.Lock()
	f.closed = true
	conns := append([]net.Conn(nil), f.conns...)
	f.mu.Unlock()
	f.cancel()
	if f.target != nil {
		_ = f.target.Close()
	}
	// Includes actual client raw sockets, not just returned logical streams.
	// Raw closure releases any legacy State/HTTP2 write-lock dependency first.
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
		if f.server != nil {
			closeErr = errors.Join(closeErr, f.server.Close())
		}
	}()
	limit := time.NewTimer(2 * time.Second)
	defer limit.Stop()
	select {
	case <-closed:
		if !destinationDialOwnershipOnlyClosed(closeErr) {
			f.t.Errorf("client/server cleanup: %v", closeErr)
		}
	case <-limit.C:
		f.t.Error("client/server Close did not join")
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
	if f.serveErr != nil {
		f.t.Errorf("owned Serve: %v", f.serveErr)
	}
	if f.admission != nil && len(f.admission.sem) != 0 {
		f.t.Error("cleanup retained stream admission")
	}
	f.t.Log("all owned raw sockets, target/handler/caller/State/Serve workers and client/server Close joined")
}
