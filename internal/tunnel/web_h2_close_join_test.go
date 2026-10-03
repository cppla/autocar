package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

// This is an explicit cleanup-completion barrier: the actual owned TCP socket
// closes first. It does not pretend that the socket's Close or I/O is stalled.
type webH2CloseJoinHeldConn struct {
	net.Conn
	entered  chan struct{}
	returned chan struct{}
	release  <-chan struct{}
	once     sync.Once
	err      error
}

func (c *webH2CloseJoinHeldConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		close(c.entered)
		<-c.release
		close(c.returned)
	})
	return c.err
}

func webH2CloseJoinCall(c *WebH2Client, started chan<- struct{}, results chan<- error, done chan struct{}) {
	defer close(done)
	started <- struct{}{}
	results <- c.Close()
}

func webH2CloseJoinCheckPending(t *testing.T, first, second <-chan struct{}) bool {
	t.Helper()
	timer := time.NewTimer(time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer timer.Stop()
	defer ticker.Stop()
	for {
		select {
		case <-first:
			t.Error("first Close returned before owned physical cleanup completed")
			return false
		case <-second:
			t.Error("concurrent Close returned before owned physical cleanup completed")
			return false
		default:
		}
		stack := make([]byte, 1<<20)
		n := runtime.Stack(stack, true)
		if n == len(stack) {
			t.Error("owned Close stack observation was truncated")
			return false
		}
		for _, block := range strings.Split(string(stack[:n]), "\n\n") {
			line, _, _ := strings.Cut(block, "\n")
			if strings.Contains(line, "[chan receive]") &&
				strings.Contains(block, "(*WebH2Client).Close(") &&
				strings.Contains(block, "webH2CloseJoinCall(") {
				// In these fixtures the first Close has no registered socket to
				// close: the pending dial or detached cleanup is outside the map.
				// Observe the already-closed caller's actual completion wait.
				t.Log("observed own concurrent Close at the shared completion wait")
				select {
				case <-first:
					t.Error("first Close escaped pending cleanup")
					return false
				case <-second:
					t.Error("concurrent Close escaped pending cleanup")
					return false
				case <-time.After(75 * time.Millisecond):
					return true
				}
			}
		}
		select {
		case <-first:
			t.Error("first Close returned before cleanup join")
			return false
		case <-second:
			t.Error("concurrent Close returned before cleanup join")
			return false
		case <-timer.C:
			t.Error("concurrent Close did not reach an actual completion wait")
			return false
		case <-ticker.C:
		}
	}
}

func webH2CloseJoinStartClosers(t *testing.T, c *WebH2Client, results chan<- error, workers *[]<-chan struct{}) (<-chan struct{}, <-chan struct{}) {
	t.Helper()
	started := make(chan struct{}, 2)
	first, second := make(chan struct{}), make(chan struct{})
	*workers = append(*workers, first, second)
	go webH2CloseJoinCall(c, started, results, first)
	webH3CloseJoinRead(t, started, "first H2 Close entry")
	select {
	case <-c.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("first H2 Close did not cancel its actual client lifetime")
	}
	go webH2CloseJoinCall(c, started, results, second)
	webH3CloseJoinRead(t, started, "second H2 Close entry")
	return first, second
}

func webH2CloseJoinAssertFinal(t *testing.T, c *WebH2Client) {
	t.Helper()
	c.mu.Lock()
	closed, count, current := c.closed, len(c.sessions), c.current
	c.mu.Unlock()
	if !closed || count != 0 || current != nil || len(c.dialGate) != 0 {
		t.Errorf("joined Close state closed/sessions/current/gate=%t/%d/%p/%d", closed, count, current, len(c.dialGate))
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := c.DialContext(ctx, "tcp", "target.invalid:443")
	if conn != nil {
		_ = conn.Close()
		t.Error("closed client returned a new tunnel connection")
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Errorf("post-Close dial=%v, want net.ErrClosed", err)
	}
}

func TestWebH2CloseJoinsLatePhysicalDial(t *testing.T) {
	for _, tc := range []struct {
		name string
		conn bool
		err  error
	}{
		{name: "owned_conn_success", conn: true},
		{name: "owned_conn_error", conn: true, err: errors.New("private late physical dial error")},
		{name: "nil_conn_error", err: errors.New("private late nil dial error")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			if err := listener.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				_ = listener.Close()
				t.Fatal(err)
			}
			_, clientTLS := testTLSConfigs(t)
			client, err := NewWebH2Client(WebH2ClientConfig{
				ServerAddress: listener.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
				FingerprintProfile: FingerprintNative, HandshakeTimeout: time.Second, DialTimeout: time.Second,
			})
			if err != nil {
				_ = listener.Close()
				t.Fatal(err)
			}
			fixtureCtx, stopFixture := context.WithTimeout(context.Background(), 4*time.Second)
			defer stopFixture()
			releaseDial, releaseClose := make(chan struct{}), make(chan struct{})
			ungateDial := sync.OnceFunc(func() { close(releaseDial) })
			ungateClose := sync.OnceFunc(func() { close(releaseClose) })
			physicalCtx := make(chan context.Context, 1)
			physicalReturned := make(chan struct{})
			physicalReturnOnce := sync.OnceFunc(func() { close(physicalReturned) })
			var owned atomic.Pointer[webH2CloseJoinHeldConn]
			var dials atomic.Int32
			client.dialer = transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
				defer physicalReturnOnce()
				if dials.Add(1) != 1 {
					return nil, errors.New("late-dial fixture observed an unexpected extra attempt")
				}
				if network != "tcp" || address != listener.Addr().String() {
					return nil, errors.New("late-dial fixture refuses a non-owned endpoint")
				}
				var wire *webH2CloseJoinHeldConn
				if tc.conn {
					raw, dialErr := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
					if dialErr != nil {
						return nil, dialErr
					}
					wire = &webH2CloseJoinHeldConn{Conn: raw, entered: make(chan struct{}), returned: make(chan struct{}), release: releaseClose}
					owned.Store(wire)
				}
				physicalCtx <- ctx
				// A real dial can complete concurrently with lifetime cancellation.
				// The separate bounded fixture gate controls its late publication.
				select {
				case <-releaseDial:
				case <-fixtureCtx.Done():
				}
				if wire == nil {
					return nil, tc.err
				}
				return wire, tc.err
			})
			var peer *net.TCPConn
			var closeWorkers []<-chan struct{}
			dialDone, dialResult := make(chan struct{}), make(chan error, 1)
			t.Cleanup(func() {
				ungateDial()
				ungateClose()
				stopFixture()
				if wire := owned.Load(); wire != nil {
					_ = wire.Conn.Close() // Independent exact-socket cleanup, not an oracle.
				}
				if peer != nil {
					_ = peer.Close()
				}
				_ = listener.Close()
				webH3CloseJoinWait(t, dialDone, "late public H2 dial worker cleanup")
				for _, worker := range closeWorkers {
					webH3CloseJoinWait(t, worker, "H2 Close caller cleanup")
				}
				cleanupDone := make(chan struct{})
				go func() { defer close(cleanupDone); _ = client.Close() }()
				webH3CloseJoinWait(t, cleanupDone, "independent H2 client cleanup")
			})
			go func() {
				defer close(dialDone)
				conn, err := client.DialContext(fixtureCtx, "tcp", "target.invalid:443")
				if conn != nil {
					_ = conn.Close()
					err = errors.New("closed client returned a late tunnel connection")
				}
				dialResult <- err
			}()
			ctx := webH3CloseJoinRead(t, physicalCtx, "actual owned physical dial entry")
			if tc.conn {
				peer, err = listener.AcceptTCP()
				if err != nil {
					t.Fatal(err)
				}
			}
			results := make(chan error, 2)
			first, second := webH2CloseJoinStartClosers(t, client, results, &closeWorkers)
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
				t.Error("Close did not cancel the in-flight physical dial")
			}
			webH2CloseJoinCheckPending(t, first, second)
			ungateDial()
			webH3CloseJoinMustWait(t, physicalReturned, "actual late physical dial return")
			if wire := owned.Load(); wire != nil {
				select {
				case <-wire.entered:
					webH2CloseJoinCheckPending(t, first, second)
				case <-time.After(time.Second):
					t.Error("late owned physical connection was not closed by the client")
				}
				if err := peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
				var one [1]byte
				n, readErr := peer.Read(one[:])
				if n != 0 || !(errors.Is(readErr, io.EOF) || errors.Is(readErr, syscall.ECONNRESET)) {
					t.Errorf("late owned socket not actually closed before independent cleanup: n=%d error=%v", n, readErr)
				}
			}
			ungateClose()
			webH3CloseJoinMustWait(t, first, "first H2 Close result")
			webH3CloseJoinMustWait(t, second, "concurrent H2 Close result")
			webH3CloseJoinMustWait(t, dialDone, "late public H2 dial completion")
			if err := webH3CloseJoinRead(t, dialResult, "late public H2 dial result"); !errors.Is(err, net.ErrClosed) {
				t.Errorf("dial after client Close=%v, want net.ErrClosed", err)
			}
			for range 2 {
				if err := webH3CloseJoinRead(t, results, "joined H2 Close result"); err != nil {
					t.Errorf("joined H2 Close=%v", err)
				}
			}
			webH2CloseJoinAssertFinal(t, client)
			if dials.Load() != 1 {
				t.Errorf("physical dial count=%d, want one exact owned attempt", dials.Load())
			}
		})
	}
}

func TestWebH2CloseJoinsDetachedSessionCleanup(t *testing.T) {
	payload := []byte("owned H2 detached cleanup with complete upload FIN")
	origin := newWebH3CloseJoinOrigin(t, payload) // Bounded actual TCP helper, not H3 setup.
	target := origin.listener.Addr().String()
	serverTLS, clientTLS := testTLSConfigs(t)
	server, err := ListenWebH2(WebH2ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS, Cover: http.NotFoundHandler(),
		Dialer: transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != target {
				return nil, errors.New("warm cleanup fixture refuses a non-owned target")
			}
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := server.server.Handler
	handlerDone, bearerLength := make(chan struct{}), make(chan int, 1)
	handlerReturned := sync.OnceFunc(func() { close(handlerDone) })
	var requests, unexpected atomic.Int32
	server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer handlerReturned()
		requests.Add(1)
		select {
		case bearerLength <- len(r.Header.Get("Proxy-Authorization")):
		default:
			unexpected.Add(1)
		}
		handler.ServeHTTP(w, r)
	})
	serveCtx, cancelServe := context.WithCancel(context.Background())
	serveDone, serveResult := make(chan struct{}), make(chan error, 1)
	go func() { defer close(serveDone); serveResult <- server.Serve(serveCtx) }()
	t.Cleanup(func() {
		_ = server.Close()
		cancelServe()
		webH3CloseJoinWait(t, serveDone, "owned H2 Serve cleanup")
	})
	client, err := NewWebH2Client(WebH2ClientConfig{ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS, FingerprintProfile: FingerprintNative})
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	ungate := sync.OnceFunc(func() { close(release) })
	var held *webH2CloseJoinHeldConn
	var stream net.Conn
	var closeWorkers []<-chan struct{}
	retiredDone := make(chan struct{})
	retiredStarted := false
	t.Cleanup(func() {
		ungate()
		if held != nil {
			_ = held.Conn.Close()
		}
		if stream != nil {
			_ = stream.Close()
		}
		cleanupDone := make(chan struct{})
		go func() { defer close(cleanupDone); _ = client.Close() }()
		webH3CloseJoinWait(t, cleanupDone, "independent warm H2 client cleanup")
		for _, worker := range closeWorkers {
			webH3CloseJoinWait(t, worker, "warm H2 Close caller cleanup")
		}
		if retiredStarted {
			webH3CloseJoinWait(t, retiredDone, "detached H2 retirement cleanup")
		}
	})
	dialCtx, cancelDial := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelDial()
	stream, err = client.DialContext(dialCtx, "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := stream.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(stream)
	if err != nil || !bytes.Equal(reply, append([]byte("reply:"), payload...)) {
		t.Fatalf("actual healthy H2 payload/reply=%q/%v", reply, err)
	}
	webH3CloseJoinMustWait(t, origin.done, "owned complete TCP origin")
	if err := webH3CloseJoinRead(t, origin.result, "actual origin result"); err != nil {
		t.Fatal(err)
	}
	webH3CloseJoinMustWait(t, handlerDone, "actual authenticated H2 CONNECT handler")
	if length := webH3CloseJoinRead(t, bearerLength, "actual full H2 bootstrap"); length < 385 || length > 2047 {
		t.Fatalf("full bootstrap credential length=%d", length)
	}
	if requests.Load() != 1 || unexpected.Load() != 0 {
		t.Fatalf("actual warm request/observer counts=%d/%d", requests.Load(), unexpected.Load())
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	session := client.current
	if session == nil || len(client.sessions) != 1 || session.authState != webH2ClientAuthReady || session.auth == nil || session.opening != 0 || session.active != 0 || !session.h2.CanTakeNewRequest() {
		client.mu.Unlock()
		t.Fatal("exact live authenticated idle H2 session not proved before instrumentation")
	}
	held = &webH2CloseJoinHeldConn{Conn: session.raw, entered: make(chan struct{}), returned: make(chan struct{}), release: release}
	session.raw = held
	client.mu.Unlock()
	retiredStarted = true
	go func() {
		defer close(retiredDone)
		session.h2.SetDoNotReuse()
		client.noteSessionFailure(session)
	}()
	webH3CloseJoinMustWait(t, held.entered, "actual raw socket closed before detached completion gate")
	client.mu.Lock()
	removed := client.current == nil && len(client.sessions) == 0
	client.mu.Unlock()
	if !removed {
		t.Fatal("retirement did not remove the exact session before detached cleanup")
	}
	results := make(chan error, 2)
	first, second := webH2CloseJoinStartClosers(t, client, results, &closeWorkers)
	webH2CloseJoinCheckPending(t, first, second)
	ungate()
	webH3CloseJoinMustWait(t, retiredDone, "actual detached H2 cleanup completion")
	webH3CloseJoinMustWait(t, held.returned, "actual held TCP Close completion")
	webH3CloseJoinMustWait(t, first, "first warm H2 Close")
	webH3CloseJoinMustWait(t, second, "concurrent warm H2 Close")
	for range 2 {
		if err := webH3CloseJoinRead(t, results, "joined warm H2 Close result"); err != nil {
			t.Errorf("joined warm H2 Close=%v", err)
		}
	}
	webH2CloseJoinAssertFinal(t, client)
	_ = server.Close()
	cancelServe()
	webH3CloseJoinMustWait(t, serveDone, "normal H2 Serve shutdown")
	if err := webH3CloseJoinRead(t, serveResult, "actual H2 Serve result"); err != nil {
		t.Errorf("H2 Serve=%v", err)
	}
}
