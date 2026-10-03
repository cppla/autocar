package tunnel

import (
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
)

// All networking is owned IPv4 loopback. Independent fixture cancellation,
// actual socket closure, and separate goroutine-completion channels bound
// cleanup, including assertion failures against the old implementation.
type webH2DialSharingFixture struct {
	t      *testing.T
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	joins  []<-chan struct{}
	close  []func()
	checks []func()
}

func newWebH2DialSharingFixture(t *testing.T) *webH2DialSharingFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	f := &webH2DialSharingFixture{t: t, ctx: ctx, cancel: cancel}
	t.Cleanup(func() {
		// Close the server before canceling Serve's context to avoid racing two
		// independently triggered server Close paths in this fixture.
		for i := len(f.close) - 1; i >= 0; i-- {
			f.close[i]()
		}
		cancel()
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		// Every parent is registered before launch; it registers its children
		// before returning. Join parents before taking each fresh next entry,
		// so late accept/forward/handler registration cannot escape cleanup.
		for i := 0; ; i++ {
			f.mu.Lock()
			if i == len(f.joins) {
				f.mu.Unlock()
				break
			}
			joined := f.joins[i]
			f.mu.Unlock()
			select {
			case <-joined:
			case <-timer.C:
				t.Errorf("cleanup did not join owned worker %d", i)
				return
			}
		}
		for _, check := range f.checks {
			check()
		}
	})
	return f
}

func (f *webH2DialSharingFixture) register(done <-chan struct{}) {
	f.mu.Lock()
	f.joins = append(f.joins, done)
	f.mu.Unlock()
}

func (f *webH2DialSharingFixture) wait(done <-chan struct{}, name string) {
	f.t.Helper()
	select {
	case <-done:
	case <-f.ctx.Done():
		f.t.Fatalf("%s exceeded independent fixture budget", name)
	}
}

type webH2DialSharingContext struct {
	context.Context
	entered       chan struct{}
	attemptWait   chan struct{}
	doneEvaluated atomic.Int32
}

// First Done evaluation only witnesses the selection gate. The second is the
// wait select after a brief gate's attempt capture. Both must be observed
// before the real peer is released. Old code blocks in the first gate select,
// so the bounded checkpoint fails honestly before testing its extra dials.
// Public AfterFunc registration is deliberately not used as a join witness.
func (c *webH2DialSharingContext) Done() <-chan struct{} {
	switch c.doneEvaluated.Add(1) {
	case 1:
		close(c.entered)
	case 2:
		close(c.attemptWait)
	}
	return c.Context.Done()
}

func (f *webH2DialSharingFixture) joinedWaiters(witnesses []*webH2DialSharingContext) {
	f.t.Helper()
	deadline := time.NewTimer(500 * time.Millisecond)
	defer deadline.Stop()
	for i, witness := range witnesses {
		select {
		case <-witness.attemptWait:
		case <-deadline.C:
			f.t.Errorf("follower %d did not reach shared-attempt wait after selection gate; Done evaluations=%d", i, witness.doneEvaluated.Load())
			return
		case <-f.ctx.Done():
			f.t.Fatal("independent fixture expired at joined-attempt checkpoint")
		}
	}
}

type webH2DialSharingRaw struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *webH2DialSharingRaw) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

type webH2DialSharingFront struct {
	f           *webH2DialSharingFixture
	listener    net.Listener
	destination string
	release     chan struct{}
	firstHello  chan struct{}
	releaseOnce sync.Once
	helloOnce   sync.Once
	mu          sync.Mutex
	conns       []net.Conn
	accepts     int
	hellos      int
	err         error
	closed      bool
}

// With no destination this is a real TCP/TLS blackhole until release, after
// which the peer closes each actual ClientHello connection. Otherwise it
// forwards the captured bytes unchanged to an owned real TLS/H2 server.
// No TLS/HTTP responses, canceled context, or reader stalls are synthesized.
func (f *webH2DialSharingFixture) front(destination string) *webH2DialSharingFront {
	f.t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		f.t.Fatal(err)
	}
	if destination != "" {
		host, _, err := net.SplitHostPort(destination)
		if err != nil || host != "127.0.0.1" {
			f.t.Fatalf("non-owned forwarding destination %q", destination)
		}
	}
	p := &webH2DialSharingFront{f: f, listener: listener, destination: destination,
		release: make(chan struct{}), firstHello: make(chan struct{})}
	f.close = append(f.close, p.Close)
	joined := make(chan struct{})
	f.register(joined)
	go func() {
		defer close(joined)
		for {
			conn, err := listener.Accept()
			if err != nil {
				p.noteError(err)
				return
			}
			p.mu.Lock()
			if p.closed {
				p.mu.Unlock()
				_ = conn.Close()
				continue
			}
			p.accepts++
			p.conns = append(p.conns, conn)
			p.mu.Unlock()
			_ = conn.SetDeadline(time.Now().Add(7 * time.Second))
			workerDone := make(chan struct{})
			f.register(workerDone)
			go func() {
				defer close(workerDone)
				defer conn.Close()
				p.serve(conn)
			}()
		}
	}()
	return p
}

func (p *webH2DialSharingFront) noteError(err error) {
	if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return
	}
	p.mu.Lock()
	if !p.closed && p.f.ctx.Err() == nil {
		p.err = errors.Join(p.err, err)
	}
	p.mu.Unlock()
}

func (p *webH2DialSharingFront) serve(front net.Conn) {
	var header [5]byte
	if _, err := io.ReadFull(front, header[:]); err != nil {
		p.noteError(err)
		return
	}
	n := int(binary.BigEndian.Uint16(header[3:]))
	if header[0] != 22 || n < 4 || n > 16<<10 {
		p.noteError(fmt.Errorf("first wire record is not a bounded TLS handshake: type=%d bytes=%d", header[0], n))
		return
	}
	hello := make([]byte, 5+n)
	copy(hello, header[:])
	if _, err := io.ReadFull(front, hello[5:]); err != nil {
		p.noteError(err)
		return
	}
	if hello[5] != 1 { // TLS handshake message ClientHello.
		p.noteError(errors.New("first actual TLS message was not ClientHello"))
		return
	}
	p.mu.Lock()
	p.hellos++
	p.mu.Unlock()
	p.helloOnce.Do(func() { close(p.firstHello) })
	select {
	case <-p.release:
	case <-p.f.ctx.Done():
		return
	}
	if p.destination == "" {
		return // Deferred actual peer Close, not a synthetic dial error.
	}
	back, err := (&net.Dialer{}).DialContext(p.f.ctx, "tcp4", p.destination)
	if err != nil {
		p.noteError(err)
		return
	}
	defer back.Close()
	_ = back.SetDeadline(time.Now().Add(7 * time.Second))
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.conns = append(p.conns, back)
	p.mu.Unlock()
	if _, err := back.Write(hello); err != nil {
		p.noteError(err)
		return
	}
	result := make(chan error, 2)
	for _, pair := range [][2]net.Conn{{back, front}, {front, back}} {
		done := make(chan struct{})
		p.f.register(done)
		go func(destination, source net.Conn) {
			defer close(done)
			_, err := io.Copy(destination, source)
			if tcp, ok := destination.(*net.TCPConn); ok {
				_ = tcp.CloseWrite()
			}
			result <- err
		}(pair[0], pair[1])
	}
	for range 2 {
		if err := <-result; err != nil {
			// Peer cancellation/reset is expected when running the old policy.
			_ = front.Close()
			_ = back.Close()
		}
	}
}

func (p *webH2DialSharingFront) Release() { p.releaseOnce.Do(func() { close(p.release) }) }

func (p *webH2DialSharingFront) Close() {
	p.mu.Lock()
	p.closed = true
	conns := append([]net.Conn(nil), p.conns...)
	p.mu.Unlock()
	p.Release()
	_ = p.listener.Close()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (p *webH2DialSharingFront) state() (int, int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.accepts, p.hellos, p.err
}

func (f *webH2DialSharingFixture) client(profile FingerprintProfile, address string, config *tls.Config) (*WebH2Client, *webH2AuthEntropyCounter, <-chan *webH2DialSharingRaw) {
	f.t.Helper()
	entropy := &webH2AuthEntropyCounter{}
	client, err := newWebH2ClientWithSigner(WebH2ClientConfig{
		ServerAddress: address, Token: webTestToken, TLSConfig: config, FingerprintProfile: profile,
		DialTimeout: time.Second, HandshakeTimeout: 2 * time.Second,
	}, newWebAuthSigner(mustWebAuthKey(f.t, webTestToken), nil, entropy), webAuthClaims{})
	if err != nil {
		f.t.Fatal(err)
	}
	raws := make(chan *webH2DialSharingRaw, 8)
	client.dialer = transport.DialFunc(func(ctx context.Context, network, target string) (net.Conn, error) {
		if network != "tcp" || target != address {
			return nil, errors.New("non-owned physical dial")
		}
		raw, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", address)
		if err != nil {
			return nil, err
		}
		wire := &webH2DialSharingRaw{Conn: raw, closed: make(chan struct{})}
		raws <- wire
		return wire, nil
	})
	f.close = append(f.close, func() {
		if err := client.Close(); err != nil {
			f.t.Errorf("owned client Close: %v", err)
		}
	})
	return client, entropy, raws
}

type webH2DialSharingResult struct {
	conn net.Conn
	err  error
}

func (f *webH2DialSharingFixture) reserve(client *WebH2Client, ctx context.Context) (<-chan webH2DialSharingResult, <-chan struct{}) {
	results, joined := make(chan webH2DialSharingResult, 1), make(chan struct{})
	f.register(joined)
	go func() {
		defer close(joined)
		reservation, err := client.reserveSession(ctx)
		if reservation.session != nil {
			client.releaseSessionReservation(reservation.session)
		}
		results <- webH2DialSharingResult{err: err}
	}()
	return results, joined
}

func (f *webH2DialSharingFixture) dial(client *WebH2Client, ctx context.Context, target string) (<-chan webH2DialSharingResult, <-chan struct{}) {
	results, joined := make(chan webH2DialSharingResult, 1), make(chan struct{})
	f.register(joined)
	go func() {
		defer close(joined)
		conn, err := client.DialContext(ctx, "tcp", target)
		results <- webH2DialSharingResult{conn: conn, err: err}
	}()
	return results, joined
}

func (f *webH2DialSharingFixture) raw(raws <-chan *webH2DialSharingRaw) *webH2DialSharingRaw {
	f.t.Helper()
	select {
	case raw := <-raws:
		return raw
	case <-f.ctx.Done():
		f.t.Fatal("actual physical dial did not return an owned raw connection")
		return nil
	}
}

func TestWebH2DialSharingFailureAndLaterRetry(t *testing.T) {
	for _, profile := range []FingerprintProfile{FingerprintNative, FingerprintChrome133} {
		t.Run(string(profile), func(t *testing.T) {
			f := newWebH2DialSharingFixture(t)
			_, clientTLS := testTLSConfigs(t)
			front := f.front("")
			client, entropy, raws := f.client(profile, front.listener.Addr().String(), clientTLS)
			results := make([]<-chan webH2DialSharingResult, 3)
			joins := make([]<-chan struct{}, 3)
			results[0], joins[0] = f.reserve(client, f.ctx)
			f.wait(front.firstHello, "real first ClientHello")
			firstRaw := f.raw(raws)
			var witnesses []*webH2DialSharingContext
			for i := 1; i < 3; i++ {
				witness := &webH2DialSharingContext{Context: f.ctx, entered: make(chan struct{}), attemptWait: make(chan struct{})}
				results[i], joins[i] = f.reserve(client, witness)
				f.wait(witness.entered, "direct reserve follower wait selection")
				witnesses = append(witnesses, witness)
			}
			f.joinedWaiters(witnesses)
			if accepts, hellos, err := front.state(); accepts != 1 || hellos != 1 || err != nil {
				t.Fatalf("pre-failure physical accepts/hellos/error=%d/%d/%v", accepts, hellos, err)
			}
			front.Release()
			var firstError error
			for i := range results {
				f.wait(joins[i], "failed reserve caller joined")
				err := (<-results[i]).err
				if err == nil {
					t.Error("real closed TLS peer unexpectedly initialized a session")
				}
				if i == 0 {
					firstError = err
				} else if err != firstError {
					t.Errorf("joined caller %d received a new failure object, not the shared immutable result", i)
				}
			}
			f.wait(firstRaw.closed, "failed physical raw Close completion")
			if accepts, hellos, err := front.state(); accepts != 1 || hellos != 1 || err != nil {
				t.Errorf("one joined failed attempt produced physical accepts/hellos/error=%d/%d/%v, want 1/1/nil", accepts, hellos, err)
			}
			later, laterJoined := f.reserve(client, f.ctx)
			f.wait(laterJoined, "later independent retry joined")
			if err := (<-later).err; err == nil || err == firstError {
				t.Errorf("later retry must be a new failed attempt/result: %v", err)
			}
			if accepts, hellos, err := front.state(); accepts != 2 || hellos != 2 || err != nil {
				t.Errorf("later retry physical accepts/hellos/error=%d/%d/%v, want 2/2/nil", accepts, hellos, err)
			}
			if entropy.nonceReads.Load() != 0 {
				t.Error("failed physical initialization generated application authentication")
			}
			t.Logf("actual TLS ClientHello attempts and same-result/later-retry oracles evaluated; nonce reads=%d", entropy.nonceReads.Load())
		})
	}
}

func (f *webH2DialSharingFixture) target() string {
	f.t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		f.t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	closed := false
	f.close = append(f.close, func() {
		mu.Lock()
		closed = true
		owned := append([]net.Conn(nil), conns...)
		mu.Unlock()
		_ = listener.Close()
		for _, conn := range owned {
			_ = conn.Close()
		}
	})
	joined := make(chan struct{})
	f.register(joined)
	go func() {
		defer close(joined)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				_ = conn.Close()
				return
			}
			conns = append(conns, conn)
			mu.Unlock()
			_ = conn.SetDeadline(time.Now().Add(7 * time.Second))
			done := make(chan struct{})
			f.register(done)
			go func() {
				defer close(done)
				defer conn.Close()
				var payload [256]byte
				for {
					n, err := conn.Read(payload[:])
					if n != 0 {
						if _, writeErr := conn.Write(payload[:n]); writeErr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return listener.Addr().String()
}

func TestWebH2DialInitiatingCallerCancellationKeepsPhysicalInitialization(t *testing.T) {
	for _, profile := range []FingerprintProfile{FingerprintNative, FingerprintChrome133} {
		t.Run(string(profile), func(t *testing.T) {
			f := newWebH2DialSharingFixture(t)
			serverTLS, clientTLS := testTLSConfigs(t)
			target := f.target()
			var targetDials, covers atomic.Int64
			server, err := ListenWebH2(WebH2ServerConfig{
				Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
				Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { covers.Add(1); http.NotFound(w, r) }),
				Dialer: transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
					targetDials.Add(1)
					if network != "tcp" || address != target {
						return nil, errors.New("non-owned destination dial")
					}
					return (&net.Dialer{}).DialContext(ctx, "tcp4", target)
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			var requestsMu sync.Mutex
			var authConnections []*webServerConnectionAuth
			var bearerLengths []int
			original := server.server.Handler
			server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerJoined := make(chan struct{})
				f.register(handlerJoined)
				defer close(handlerJoined)
				state, _ := r.Context().Value(webServerConnectionAuthContextKey{}).(*webServerConnectionAuth)
				requestsMu.Lock()
				authConnections = append(authConnections, state)
				bearerLengths = append(bearerLengths, len(r.Header.Get("Proxy-Authorization")))
				requestsMu.Unlock()
				original.ServeHTTP(w, r)
			})
			serveJoined := make(chan struct{})
			var serveErr error
			f.register(serveJoined)
			f.checks = append(f.checks, func() {
				if serveErr != nil {
					t.Errorf("owned H2 Serve result: %v", serveErr)
				}
			})
			f.close = append(f.close, func() {
				if err := server.Close(); err != nil {
					t.Errorf("owned H2 server Close: %v", err)
				}
			})
			go func() { defer close(serveJoined); serveErr = server.Serve(f.ctx) }()
			front := f.front(server.Addr().String())
			client, entropy, raws := f.client(profile, front.listener.Addr().String(), clientTLS)
			leaderCtx, cancelLeader := context.WithCancelCause(f.ctx)
			defer cancelLeader(context.Canceled)
			leader, leaderJoined := f.dial(client, leaderCtx, target)
			f.wait(front.firstHello, "actual gated public leader ClientHello")
			firstRaw := f.raw(raws)
			cause := errors.New("initiating H2 caller abandoned its wait")
			cancelLeader(cause)
			f.wait(leaderJoined, "canceled public initiating caller joined")
			result := <-leader
			if result.conn != nil {
				_ = result.conn.Close()
				t.Error("canceled initiating caller returned an established stream")
			}
			if !errors.Is(result.err, cause) {
				t.Errorf("initiating caller error=%v, want its custom cause", result.err)
			}
			select {
			case <-firstRaw.closed:
				t.Error("initiating caller cancellation closed the shared cold physical raw connection")
			default:
			}
			front.Release()
			// No live caller exists now. A client-owned successful initializer
			// must publish an unclaimed physical session, not send CONNECT/auth.
			var initialized *webH2ClientSession
			ticker, deadline := time.NewTicker(10*time.Millisecond), time.NewTimer(time.Second)
			defer ticker.Stop()
			defer deadline.Stop()
		waitInitialized:
			for {
				client.mu.Lock()
				initialized = client.current
				unclaimed := initialized != nil && initialized.auth == nil && initialized.opening == 0
				client.mu.Unlock()
				if unclaimed {
					break
				}
				select {
				case <-ticker.C:
				case <-deadline.C:
					t.Error("all waits abandoned: physical initialization did not publish an unclaimed session")
					break waitInitialized
				case <-f.ctx.Done():
					t.Fatal("independent fixture expired before physical initialization")
				}
			}
			requestsMu.Lock()
			before := len(authConnections)
			requestsMu.Unlock()
			if before != 0 || targetDials.Load() != 0 || entropy.nonceReads.Load() != 0 {
				t.Errorf("unclaimed physical session sent requests/target/auth=%d/%d/%d", before, targetDials.Load(), entropy.nonceReads.Load())
			}
			for round := range 2 {
				caller, cancel := context.WithCancel(f.ctx)
				conn, err := client.DialContext(caller, "tcp", target)
				cancel() // A returned stream is not owned by its establishment context.
				if err != nil {
					t.Fatalf("live caller %d real CONNECT: %v", round, err)
				}
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				payload := []byte(fmt.Sprintf("owned-h2-survivor-%d", round))
				_, writeErr := conn.Write(payload)
				got := make([]byte, len(payload))
				_, readErr := io.ReadFull(conn, got)
				_ = conn.Close()
				if writeErr != nil || readErr != nil || string(got) != string(payload) {
					t.Fatalf("live caller %d full echo=%q, write/read=%v/%v", round, got, writeErr, readErr)
				}
			}
			client.mu.Lock()
			warm := client.current
			client.mu.Unlock()
			if initialized != nil && warm != initialized {
				t.Error("live caller did not reuse the initialized unclaimed physical session")
			}
			requestsMu.Lock()
			samePhysical := len(authConnections) == 2 && authConnections[0] != nil && authConnections[0] == authConnections[1]
			fullShort := len(bearerLengths) == 2 && bearerLengths[0] > bearerLengths[1] && bearerLengths[1] != 0
			requestsMu.Unlock()
			if !samePhysical || !fullShort || entropy.nonceReads.Load() != 1 || targetDials.Load() != 2 || covers.Load() != 0 {
				t.Errorf("healthy full/short auth physical=%t fullShort=%t nonce/target/cover=%d/%d/%d", samePhysical, fullShort, entropy.nonceReads.Load(), targetDials.Load(), covers.Load())
			}
			if accepts, hellos, err := front.state(); accepts != 1 || hellos != 1 || err != nil {
				t.Errorf("caller cancellation caused replacement physical accepts/hellos/error=%d/%d/%v, want 1/1/nil", accepts, hellos, err)
			}
			if err := client.Close(); err != nil {
				t.Error(err)
			}
			if err := server.Close(); err != nil {
				t.Error(err)
			}
			f.wait(serveJoined, "owned H2 Serve joined")
			t.Log("actual public survivor and warm sibling full echoes succeeded; one full auth plus short continuation evaluated")
		})
	}
}

func TestWebH2DialAllWaitersAbandonThenClose(t *testing.T) {
	for _, profile := range []FingerprintProfile{FingerprintNative, FingerprintChrome133} {
		t.Run(string(profile), func(t *testing.T) {
			f := newWebH2DialSharingFixture(t)
			_, clientTLS := testTLSConfigs(t)
			front := f.front("")
			client, entropy, raws := f.client(profile, front.listener.Addr().String(), clientTLS)
			results := make([]<-chan webH2DialSharingResult, 3)
			joins := make([]<-chan struct{}, 3)
			cancels := make([]context.CancelCauseFunc, 3)
			causes := make([]error, 3)
			var witnesses []*webH2DialSharingContext
			for i := range 3 {
				ctx, cancel := context.WithCancelCause(f.ctx)
				cancels[i] = cancel
				defer cancel(context.Canceled)
				causes[i] = fmt.Errorf("H2 waiter %d abandoned", i)
				if i == 0 {
					results[i], joins[i] = f.reserve(client, ctx)
					f.wait(front.firstHello, "actual first ClientHello before abandonment")
				} else {
					witness := &webH2DialSharingContext{Context: ctx, entered: make(chan struct{}), attemptWait: make(chan struct{})}
					results[i], joins[i] = f.reserve(client, witness)
					f.wait(witness.entered, "direct reserve follower wait selection")
					witnesses = append(witnesses, witness)
				}
			}
			f.joinedWaiters(witnesses)
			raw := f.raw(raws)
			for i := range cancels {
				cancels[i](causes[i])
			}
			for i := range results {
				f.wait(joins[i], "abandoned reserve caller joined")
				if err := (<-results[i]).err; !errors.Is(err, causes[i]) {
					t.Errorf("waiter %d error=%v, want its own cause", i, err)
				}
			}
			select {
			case <-raw.closed:
				t.Error("all caller cancellations closed the client-owned physical initialization before client Close")
			default:
			}
			if err := client.Close(); err != nil {
				t.Error(err)
			}
			select {
			case <-raw.closed:
			default:
				t.Error("client Close returned before actual cold raw Close completed")
			}
			front.Release()
			if accepts, hellos, err := front.state(); accepts != 1 || hellos != 1 || err != nil || entropy.nonceReads.Load() != 0 {
				t.Errorf("abandon/Close physical accepts/hellos/error/auth=%d/%d/%v/%d", accepts, hellos, err, entropy.nonceReads.Load())
			}
			if _, err := client.DialContext(f.ctx, "tcp", "127.0.0.1:1"); !errors.Is(err, net.ErrClosed) {
				t.Errorf("Dial after explicit Close=%v, want net.ErrClosed without target dial", err)
			}
			t.Log("all direct waiters joined with individual causes; explicit Close and raw-completion checks evaluated")
		})
	}
}
