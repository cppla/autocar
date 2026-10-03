package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/protocol"
)

// The configured Dialer really connects to an owned TCP endpoint, but returns
// that connection only after the server's outbound deadline. This is a causal
// late-result model, not a claim about the scheduling of the default Dialer.
func TestDestinationDialDeadlineRejectsLateOwnedConnection(t *testing.T) {
	for _, mode := range []string{"quic", "tls", "h2", "h3"} {
		t.Run(mode, func(t *testing.T) {
			f := newDestinationDeadlineFixture(t, mode)
			ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
			conn, err := f.client.DialContext(ctx, "tcp", f.target.Addr().String())
			callerLive := ctx.Err() == nil
			cancel()
			f.wait(f.dialReturned, "late destination callback returned")
			if !callerLive || !f.connectedBeforeDeadline || !errors.Is(f.returnCause, context.DeadlineExceeded) {
				t.Fatalf("late-result cause=%v, connected before deadline=%v, caller still live=%v", f.returnCause, f.connectedBeforeDeadline, callerLive)
			}
			lateSucceeded := conn != nil && err == nil
			if conn != nil {
				if !lateSucceeded {
					_ = conn.Close()
					t.Fatalf("destination returned connection and error: %v", err)
				}
				t.Error("server accepted a connection returned after its destination dial deadline")
				// Keep the old-code negative recoverable: actually exercise and
				// close its successful stream, then run both healthy controls.
				f.echo(conn, []byte("late result incorrectly relayed\x00\xff"))
			} else {
				f.assertRejection(err)
			}
			f.wait(f.late.closed, "actual late destination Close completed")
			firstBytes := f.awaitTarget()
			if !lateSucceeded && firstBytes != 0 {
				t.Errorf("rejected late destination received %d bytes", firstBytes)
			}
			if !lateSucceeded && f.late.closes.Load() != 1 {
				t.Errorf("rejected late destination Close count=%d, want 1 before cleanup", f.late.closes.Load())
			}
			f.awaitRequest()
			var before destinationPreserveSession
			if mode == "h2" || mode == "h3" {
				before = destinationPreserveWebSession(t, f.client)
			}
			for i := 0; i < 2; i++ {
				ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
				conn, err := f.client.DialContext(ctx, "tcp", f.target.Addr().String())
				cancel()
				if err != nil || conn == nil {
					t.Fatalf("healthy request %d: %v", i, err)
				}
				payload := bytes.Repeat([]byte{byte(i), 'h', 'e', 'a', 'l', 't', 'h', 'y', 0, 255}, 1024)
				f.echo(conn, payload)
				if received := f.awaitTarget(); received != len(payload) {
					t.Fatalf("healthy target %d received %d/%d bytes", i, received, len(payload))
				}
				f.awaitRequest()
				if mode == "h2" || mode == "h3" {
					if after := destinationPreserveWebSession(t, f.client); before != after {
						t.Fatal("late rejection or healthy continuation replaced the authenticated physical session")
					}
				}
			}
			if calls, closes := f.dialCalls.Load(), f.dialerCloses.Load(); calls != 3 || closes != 0 {
				t.Errorf("destination Dialer calls/closes=%d/%d, want 3/0", calls, closes)
			}
			if got := f.covers.Load(); got != 0 {
				t.Errorf("authenticated requests entered cover %d times", got)
			}
			if mode == "h2" || mode == "h3" {
				f.mu.Lock()
				requests := append([]destinationDeadlineWebRequest(nil), f.requests...)
				f.mu.Unlock()
				if len(requests) != 3 {
					t.Fatalf("web request count=%d, want 3", len(requests))
				}
				if requests[0].physical == nil || requests[0].short {
					t.Fatal("first web request did not bootstrap its actual physical connection")
				}
				for _, request := range requests[1:] {
					if request.physical != requests[0].physical || !request.short {
						t.Fatal("healthy requests did not use short authentication on the same physical connection")
					}
				}
				if got := f.entropy.nonceReads.Load(); got != 1 {
					t.Errorf("full-auth nonce reads=%d, want 1", got)
				}
			}
			t.Logf("%s: late callback deadline=%v, old-success=%v; actual late Close=%d and target EOF; two healthy echoes, destination calls=3, admission=0 before cleanup", mode, f.returnCause, lateSucceeded, f.late.closes.Load())
		})
	}
}

type destinationDeadlineConn struct {
	*net.TCPConn
	closes atomic.Int64
	once   sync.Once
	closed chan struct{}
}

func (c *destinationDeadlineConn) Close() error {
	c.closes.Add(1)
	err := c.TCPConn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

type destinationDeadlineDialer struct{ fixture *destinationDeadlineFixture }

func (d *destinationDeadlineDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	f := d.fixture
	call := f.dialCalls.Add(1)
	if network != "tcp" || address != f.target.Addr().String() {
		return nil, fmt.Errorf("fixture denied unowned destination %q/%q", network, address)
	}
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", address)
	if err != nil {
		return conn, err
	}
	raw := conn.(*net.TCPConn)
	f.mu.Lock()
	if f.closing {
		f.mu.Unlock()
		_ = raw.Close()
		return nil, net.ErrClosed
	}
	f.raw = append(f.raw, raw)
	f.mu.Unlock()
	if call != 1 {
		return raw, nil
	}
	f.late = &destinationDeadlineConn{TCPConn: raw, closed: make(chan struct{})}
	deadline, ok := ctx.Deadline()
	f.connectedBeforeDeadline = ok && time.Now().Before(deadline) && ctx.Err() == nil
	select {
	case <-ctx.Done():
		f.returnCause = context.Cause(ctx)
	case <-f.ctx.Done(): // Independent fatal cleanup releases this callback.
		f.returnCause = context.Cause(f.ctx)
	}
	close(f.dialReturned)
	return f.late, nil
}

func (d *destinationDeadlineDialer) Close() error {
	d.fixture.dialerCloses.Add(1)
	return nil
}

type destinationDeadlineWebRequest struct {
	physical *webServerConnectionAuth
	short    bool
}

type destinationDeadlineTargetResult struct {
	bytes int
	err   error
}

type destinationDeadlineFixture struct {
	t        *testing.T
	mode     string
	ctx      context.Context
	cancel   context.CancelFunc
	target   *net.TCPListener
	client   destinationDialOwnershipDialer
	server   destinationDialOwnershipServer
	stop     context.CancelFunc
	serveErr error

	mu                      sync.Mutex
	closing                 bool
	raw                     []*net.TCPConn
	joins                   []<-chan struct{}
	requests                []destinationDeadlineWebRequest
	webDone                 chan (<-chan struct{})
	results                 chan destinationDeadlineTargetResult
	admission               *StreamAdmission
	nativeDone              func() bool
	late                    *destinationDeadlineConn
	dialReturned            chan struct{}
	connectedBeforeDeadline bool
	returnCause             error
	dialCalls               atomic.Int64
	dialerCloses            atomic.Int64
	covers                  atomic.Int64
	entropy                 webH2AuthEntropyCounter
}

func newDestinationDeadlineFixture(t *testing.T, mode string) *destinationDeadlineFixture {
	t.Helper()
	// Six seconds of independent work plus the two-second cleanup join cap.
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	f := &destinationDeadlineFixture{t: t, mode: mode, ctx: ctx, cancel: cancel,
		results: make(chan destinationDeadlineTargetResult, 3), webDone: make(chan (<-chan struct{}), 3), dialReturned: make(chan struct{})}
	t.Cleanup(f.cleanup)
	var err error
	f.target, err = net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	f.joins = append(f.joins, done)
	go func() { defer close(done); f.serveTarget() }()
	f.admission, err = NewStreamAdmission(1)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, clientTLS := testTLSConfigs(t)
	outbound := &destinationDeadlineDialer{fixture: f}
	cover := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.covers.Add(1); http.NotFound(w, r) })
	const serverDialTimeout = 100 * time.Millisecond
	switch mode {
	case "quic":
		s, e := ListenQUIC(QUICServerConfig{Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS, Dialer: outbound, StreamAdmission: f.admission, DialTimeout: serverDialTimeout, HandshakeTimeout: 2 * time.Second})
		if e != nil {
			t.Fatal(e)
		}
		f.server = s
		f.nativeDone = func() bool { return len(s.streamSem) == 0 }
		c, e := NewClient(ClientConfig{ServerAddress: s.Addr().String(), Token: testToken, TLSConfig: clientTLS, QUICDialTimeout: 2 * time.Second, HandshakeTimeout: 2 * time.Second})
		err = e
		if e == nil {
			f.client = c
		}
	case "tls":
		s, e := ListenTLS(TLSServerConfig{Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS, Dialer: outbound, StreamAdmission: f.admission, DialTimeout: serverDialTimeout, HandshakeTimeout: 2 * time.Second})
		if e != nil {
			t.Fatal(e)
		}
		f.server = s
		f.nativeDone = func() bool { return len(s.connSem) == 0 }
		c, e := NewTLSClient(TLSClientConfig{ServerAddress: s.Addr().String(), Token: testToken, TLSConfig: clientTLS, DialTimeout: 2 * time.Second, HandshakeTimeout: 2 * time.Second})
		err = e
		if e == nil {
			f.client = c
		}
	case "h2":
		s, e := ListenWebH2(WebH2ServerConfig{Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS, Dialer: outbound, StreamAdmission: f.admission, DialTimeout: serverDialTimeout, HandshakeTimeout: 2 * time.Second, Cover: cover})
		if e != nil {
			t.Fatal(e)
		}
		f.server = s
		s.server.Handler = f.observeWeb(s.server.Handler)
		c, e := NewWebH2Client(WebH2ClientConfig{ServerAddress: s.Addr().String(), Token: testToken, TLSConfig: clientTLS, DialTimeout: 2 * time.Second, HandshakeTimeout: 2 * time.Second, FingerprintProfile: FingerprintNative})
		err = e
		if e == nil {
			f.client = c
			c.auth = newWebAuthSigner(mustWebAuthKey(t, testToken), nil, &f.entropy)
		}
	case "h3":
		s, e := ListenWebH3(WebH3ServerConfig{Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS, Dialer: outbound, StreamAdmission: f.admission, DialTimeout: serverDialTimeout, HandshakeTimeout: 2 * time.Second, Cover: cover})
		if e != nil {
			t.Fatal(e)
		}
		f.server = s
		s.server.Handler = f.observeWeb(s.server.Handler)
		c, e := NewWebH3Client(WebH3ClientConfig{ServerAddress: s.Addr().String(), Token: testToken, TLSConfig: clientTLS, DialTimeout: 2 * time.Second, HandshakeTimeout: 2 * time.Second, FingerprintProfile: H3FingerprintNative})
		err = e
		if e == nil {
			f.client = c
			c.signer = newWebAuthSigner(mustWebAuthKey(t, testToken), nil, &f.entropy)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	serveCtx, stop := context.WithCancel(context.Background())
	f.stop = stop
	serveDone := make(chan struct{})
	f.mu.Lock()
	f.joins = append(f.joins, serveDone)
	f.mu.Unlock()
	go func() { defer close(serveDone); f.serveErr = f.server.Serve(serveCtx) }()
	return f
}

func (f *destinationDeadlineFixture) observeWeb(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		done := make(chan struct{})
		f.mu.Lock()
		if f.closing {
			f.mu.Unlock()
			return
		}
		f.joins = append(f.joins, done)
		physical, _ := r.Context().Value(webServerConnectionAuthContextKey{}).(*webServerConnectionAuth)
		values := r.Header.Values("Proxy-Authorization")
		short := false
		if len(values) == 1 {
			_, short = parseWebSessionBearer(values[0])
		}
		f.requests = append(f.requests, destinationDeadlineWebRequest{physical: physical, short: short})
		f.mu.Unlock()
		defer close(done)
		f.webDone <- done
		handler.ServeHTTP(w, r)
	})
}

func (f *destinationDeadlineFixture) serveTarget() {
	for i := 0; i < 3; i++ {
		conn, err := f.target.AcceptTCP()
		if err != nil {
			return
		}
		f.mu.Lock()
		if f.closing {
			f.mu.Unlock()
			_ = conn.Close()
			return
		}
		f.raw = append(f.raw, conn)
		f.mu.Unlock()
		err = conn.SetDeadline(time.Now().Add(3 * time.Second))
		var got []byte
		if err == nil {
			got, err = io.ReadAll(conn)
		}
		if err == nil {
			_, err = io.Copy(conn, bytes.NewReader(got))
		}
		if err == nil {
			err = conn.CloseWrite()
		}
		closeErr := conn.Close()
		if err == nil {
			err = closeErr
		}
		f.results <- destinationDeadlineTargetResult{bytes: len(got), err: err}
	}
}

func (f *destinationDeadlineFixture) echo(conn net.Conn, payload []byte) {
	f.t.Helper()
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		f.t.Fatal(err)
	}
	if _, err := io.Copy(conn, bytes.NewReader(payload)); err != nil {
		f.t.Fatal(err)
	}
	writer, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		f.t.Fatal("successful stream lost CloseWrite")
	}
	if err := writer.CloseWrite(); err != nil {
		f.t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(got, payload) {
		f.t.Fatalf("real echo=%d/%d bytes, error=%v", len(got), len(payload), err)
	}
}

func (f *destinationDeadlineFixture) assertRejection(err error) {
	f.t.Helper()
	if f.mode == "quic" || f.mode == "tls" {
		var remote *RemoteError
		if !errors.As(err, &remote) || remote.Status != protocol.StatusDialFailed || remote.Message != "destination unavailable" {
			f.t.Errorf("late destination rejection=%T %v, want sanitized StatusDialFailed", err, err)
		}
	} else {
		var remote *WebConnectError
		if !errors.As(err, &remote) || remote.Transport != f.mode || remote.StatusCode != http.StatusBadGateway || err.Error() != fmt.Sprintf("tunnel: %s cover CONNECT rejected with HTTP status 502", f.mode) {
			f.t.Errorf("late destination rejection=%T %v, want authenticated typed 502", err, err)
		}
	}
}

func (f *destinationDeadlineFixture) wait(done <-chan struct{}, what string) {
	f.t.Helper()
	select {
	case <-done:
	case <-f.ctx.Done():
		f.t.Fatalf("%s: %v", what, context.Cause(f.ctx))
	}
}

func (f *destinationDeadlineFixture) awaitTarget() int {
	f.t.Helper()
	select {
	case result := <-f.results:
		if result.err != nil {
			f.t.Fatalf("real target EOF/echo: %v", result.err)
		}
		return result.bytes
	case <-f.ctx.Done():
		f.t.Fatal("real target worker did not reach EOF")
	}
	return 0
}

func (f *destinationDeadlineFixture) awaitRequest() {
	f.t.Helper()
	if f.mode == "h2" || f.mode == "h3" {
		select {
		case done := <-f.webDone:
			f.wait(done, "web handler joined")
		case <-f.ctx.Done():
			f.t.Fatal("web request was not observed")
		}
	}
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for len(f.admission.sem) != 0 || (f.nativeDone != nil && !f.nativeDone()) {
		select {
		case <-tick.C:
		case <-f.ctx.Done():
			f.t.Fatal("actual handler did not release admission")
		}
	}
}

func (f *destinationDeadlineFixture) cleanup() {
	f.mu.Lock()
	f.closing = true
	raw := append([]*net.TCPConn(nil), f.raw...)
	f.mu.Unlock()
	f.cancel() // Releases the configured late callback independently of Serve.
	if f.target != nil {
		_ = f.target.Close()
	}
	for _, conn := range raw {
		_ = conn.Close()
	} // Never calls the observed wrapper.
	done := make(chan struct{})
	var closeErr error
	go func() {
		defer close(done)
		if f.client != nil {
			closeErr = f.client.Close()
		}
		if f.server != nil {
			closeErr = errors.Join(closeErr, f.server.Close())
		}
		if f.stop != nil {
			f.stop()
		} // Close precedes Serve cancellation (H3 socket owner).
	}()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
		if !destinationDialOwnershipOnlyClosed(closeErr) {
			f.t.Errorf("client/server cleanup: %v", closeErr)
		}
	case <-timer.C:
		f.t.Error("client/server cleanup did not join")
		return
	}
	// Drain a fresh index, not an early snapshot: accepted children register
	// before their parent completes, and cleanup's closed gate blocks new work.
	for i := 0; ; i++ {
		f.mu.Lock()
		if i == len(f.joins) {
			f.mu.Unlock()
			break
		}
		join := f.joins[i]
		f.mu.Unlock()
		select {
		case <-join:
		case <-timer.C:
			f.t.Error("owned worker cleanup did not join")
			return
		}
	}
	if f.serveErr != nil {
		f.t.Errorf("server Serve cleanup: %v", f.serveErr)
	}
	f.t.Log("all owned target/handler/server workers and client/server Close joined")
}
