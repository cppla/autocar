package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

// These lifecycle tests inject a standard fixed-loopback ReverseProxy. They
// isolate ownership of real hijacked TLS sockets from cover-handshake policy.
type websocketLifecycleOrigin struct {
	listener  *net.TCPListener
	mu        sync.Mutex
	closed    bool
	conn      *net.TCPConn
	done      chan struct{}
	result    chan error
	flood     chan struct{}
	floodOnce sync.Once
}

func newWebsocketLifecycleOrigin(t *testing.T, flood bool) *websocketLifecycleOrigin {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	o := &websocketLifecycleOrigin{listener: listener, done: make(chan struct{}), result: make(chan error, 1)}
	if flood {
		o.flood = make(chan struct{})
	}
	t.Cleanup(func() {
		o.releaseFlood()
		_ = listener.Close()
		o.mu.Lock()
		o.closed = true
		conn := o.conn
		o.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		websocketLifecycleJoin(t, "owned origin worker cleanup", o.done)
	})
	go func() {
		defer close(o.done)
		o.result <- o.run()
	}()
	return o
}

func (o *websocketLifecycleOrigin) releaseFlood() {
	if o.flood != nil {
		o.floodOnce.Do(func() { close(o.flood) })
	}
}

func (o *websocketLifecycleOrigin) run() error {
	_ = o.listener.SetDeadline(time.Now().Add(4 * time.Second))
	conn, err := o.listener.AcceptTCP()
	if err != nil {
		return err
	}
	defer conn.Close()
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return net.ErrClosed
	}
	o.conn = conn
	o.mu.Unlock()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return err
	}
	_ = request.Body.Close()
	if request.Method != http.MethodGet || request.Header.Get("Upgrade") != "websocket" || request.Header.Get("Sec-WebSocket-Key") != "dGhlIHNhbXBsZSBub25jZQ==" {
		return errors.New("unexpected owned WebSocket origin handshake")
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"); err != nil {
		return err
	}
	if o.flood != nil {
		select {
		case <-o.flood:
		case <-time.After(2 * time.Second):
			return errors.New("origin flood was not released")
		}
		// One actual unmasked 8-MiB binary frame exceeds loopback socket
		// buffering. No synthetic blocking is inserted in the copy path.
		if _, err := conn.Write([]byte{0x82, 127, 0, 0, 0, 0, 0, 128, 0, 0}); err != nil {
			return err
		}
		payload := make([]byte, 8<<20)
		if _, err := conn.Write(payload); err != nil {
			return err
		}
	}
	for {
		frame := make([]byte, 9)
		if _, err := io.ReadFull(reader, frame); err != nil {
			return err
		}
		if frame[0] != 0x81 || frame[1] != 0x83 || frame[6]^frame[2] != 'h' || frame[7]^frame[3] != 'e' || frame[8]^frame[4] != 'y' {
			return errors.New("owned origin received a corrupted masked frame")
		}
		if _, err := conn.Write([]byte{0x81, 3, 'h', 'e', 'y'}); err != nil {
			return err
		}
	}
}

type websocketLifecycleFixture struct {
	server      *WebH2Server
	clientTLS   *tls.Config
	admission   *webConnectionAdmission
	origin      *websocketLifecycleOrigin
	serveCancel context.CancelFunc
	serveDone   chan struct{}
	serveResult chan error
	handlerDone chan struct{}
	requestCtx  chan context.Context
	started     atomic.Bool
	targetCalls atomic.Int64
}

func newWebsocketLifecycleFixture(t *testing.T, flood bool, wrap func(http.ResponseWriter) http.ResponseWriter, beforeServe func(*WebH2Server)) *websocketLifecycleFixture {
	t.Helper()
	f := &websocketLifecycleFixture{origin: newWebsocketLifecycleOrigin(t, flood), serveDone: make(chan struct{}), serveResult: make(chan error, 1), handlerDone: make(chan struct{}), requestCtx: make(chan context.Context, 1)}
	upstream := &http.Transport{Proxy: nil}
	t.Cleanup(upstream.CloseIdleConnections)
	originURL := &url.URL{Scheme: "http", Host: f.origin.listener.Addr().String()}
	proxy := &httputil.ReverseProxy{Transport: upstream, Rewrite: func(p *httputil.ProxyRequest) {
		p.SetURL(originURL)
		p.Out.Host = originURL.Host
	}}
	website := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ordinary" {
			_, _ = io.WriteString(w, "ordinary healthy")
			return
		}
		f.started.Store(true)
		defer close(f.handlerDone)
		f.requestCtx <- r.Context()
		if wrap != nil {
			w = wrap(w)
		}
		proxy.ServeHTTP(w, r)
	})
	var err error
	f.admission, err = newWebConnectionAdmission(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, clientTLS := testTLSConfigs(t)
	f.clientTLS = clientTLS.Clone()
	f.clientTLS.NextProtos = []string{webHTTP11ALPN}
	// Preserve the combined server's actual ResponseController/Unwrap path.
	f.server, err = ListenWebH2(WebH2ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
		Cover: &webAltSvcCover{next: website, value: `h3=":443"; ma=60`}, connectionAdmission: f.admission,
		Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
			f.targetCalls.Add(1)
			return nil, errors.New("WebSocket lifecycle test forbids tunnel destination dialing")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.serveCancel = cancel
	t.Cleanup(func() {
		cancel()
		_ = f.server.Close()
		websocketLifecycleJoin(t, "Serve cleanup", f.serveDone)
		if f.started.Load() {
			websocketLifecycleJoin(t, "cover handler cleanup", f.handlerDone)
		}
	})
	if beforeServe != nil {
		beforeServe(f.server)
	}
	go func() {
		defer close(f.serveDone)
		f.serveResult <- f.server.Serve(ctx)
	}()
	return f
}

func (f *websocketLifecycleFixture) dial(t *testing.T) *tls.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", f.server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if tcp, ok := raw.(*net.TCPConn); ok {
		_ = tcp.SetReadBuffer(1024)
	}
	client := tls.Client(raw, f.clientTLS.Clone())
	t.Cleanup(func() { _ = client.Close() })
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	state := client.ConnectionState()
	if state.NegotiatedProtocol != webHTTP11ALPN || len(state.VerifiedChains) == 0 {
		t.Fatal("expected verified actual HTTP/1.1 TLS")
	}
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	return client
}

func (f *websocketLifecycleFixture) request(t *testing.T, client *tls.Conn) {
	t.Helper()
	if _, err := fmt.Fprintf(client, "GET /socket HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", f.server.Addr()); err != nil {
		t.Fatal(err)
	}
}

func (f *websocketLifecycleFixture) open(t *testing.T) (*tls.Conn, *bufio.Reader, context.Context) {
	t.Helper()
	client := f.dial(t)
	f.request(t, client)
	reader := bufio.NewReader(client)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil || response.StatusCode != http.StatusSwitchingProtocols || response.Header.Get("Upgrade") != "websocket" || response.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("real public handshake response=%v err=%v", response, err)
	}
	select {
	case ctx := <-f.requestCtx:
		if ctx.Err() != nil || len(f.admission.slots) != 1 {
			t.Fatal("live hijacked connection lost its context or admission slot")
		}
		return client, reader, ctx
	case <-time.After(time.Second):
		t.Fatal("actual cover request context was not published")
		return nil, nil, nil
	}
}

func websocketLifecycleEcho(t *testing.T, client *tls.Conn, reader *bufio.Reader) {
	t.Helper()
	if _, err := client.Write([]byte{0x81, 0x83, 1, 2, 3, 4, 'h' ^ 1, 'e' ^ 2, 'y' ^ 3}); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(reader, got); err != nil || string(got) != string([]byte{0x81, 3, 'h', 'e', 'y'}) {
		t.Fatalf("complete real WebSocket frame=%x err=%v", got, err)
	}
	if reader.Buffered() != 0 {
		t.Fatal("echo left unread frame bytes")
	}
}

func websocketLifecycleJoin(t *testing.T, name string, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Errorf("%s did not join", name)
	}
}

func (f *websocketLifecycleFixture) assertStopped(t *testing.T, requestCtx context.Context) {
	t.Helper()
	websocketLifecycleJoin(t, "Serve", f.serveDone)
	select {
	case err := <-f.serveResult:
		if err != nil {
			t.Errorf("Serve: %v", err)
		}
	default:
		t.Error("Serve did not publish its result")
	}
	f.assertConnectionReleased(t, requestCtx)
}

func (f *websocketLifecycleFixture) assertConnectionReleased(t *testing.T, requestCtx context.Context) {
	t.Helper()
	websocketLifecycleJoin(t, "hijacked cover handler", f.handlerDone)
	websocketLifecycleJoin(t, "owned origin frame worker", f.origin.done)
	if requestCtx.Err() == nil {
		t.Error("hijacked request context is still live")
	}
	if slots := len(f.admission.slots); slots != 0 {
		t.Errorf("closed physical socket retained %d admission slots", slots)
	}
	if f.targetCalls.Load() != 0 {
		t.Error("H1 cover invoked tunnel destination dialer")
	}
	select {
	case err := <-f.origin.result:
		if !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) && !errors.Is(err, syscall.EPIPE) {
			t.Errorf("owned upstream did not observe peer closure: %v", err)
		}
	default:
		t.Error("origin result missing")
	}
}

func TestWebSocketLifecycleIdleCloseAndServeCancellation(t *testing.T) {
	for _, cancelServe := range []bool{false, true} {
		name := "explicit_close"
		if cancelServe {
			name = "serve_context"
		}
		t.Run(name, func(t *testing.T) {
			f := newWebsocketLifecycleFixture(t, false, nil, nil)
			client, reader, requestCtx := f.open(t)
			websocketLifecycleEcho(t, client, reader)
			if cancelServe {
				f.serveCancel()
			} else if err := f.server.Close(); err != nil {
				t.Fatal(err)
			}
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
				t.Errorf("idle downstream was not closed by server shutdown: %v", err)
			}
			f.assertStopped(t, requestCtx)
		})
	}
}

func TestWebSocketLifecycleClientDisconnectReleasesCapacity(t *testing.T) {
	f := newWebsocketLifecycleFixture(t, false, nil, nil)
	client, reader, requestCtx := f.open(t)
	websocketLifecycleEcho(t, client, reader)
	_ = client.Close()
	f.assertConnectionReleased(t, requestCtx)
	// This occurs before server/fixture cleanup: one source with a one-slot
	// allowance must be able to open a second ordinary physical connection.
	ordinary := f.dial(t)
	if _, err := fmt.Fprintf(ordinary, "GET /ordinary HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", f.server.Addr()); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(ordinary), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 200 || string(body) != "ordinary healthy" {
		t.Fatalf("second ordinary request status=%d body=%q err=%v", response.StatusCode, body, err)
	}
	_ = ordinary.Close()
}

type websocketLifecycleHijackGate struct {
	http.ResponseWriter
	entered chan struct{}
	release <-chan struct{}
}

func (w *websocketLifecycleHijackGate) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	close(w.entered)
	<-w.release // Test cleanup always releases this gate independently.
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

func TestWebSocketLifecycleCloseBeforeHijack(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	ungate := func() { once.Do(func() { close(release) }) }
	f := newWebsocketLifecycleFixture(t, false, func(w http.ResponseWriter) http.ResponseWriter {
		return &websocketLifecycleHijackGate{ResponseWriter: w, entered: entered, release: release}
	}, nil)
	// Registered after fixture cleanup, so gate release runs first on failure.
	t.Cleanup(ungate)
	client := f.dial(t)
	f.request(t, client)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("real ReverseProxy did not reach Hijack")
	}
	var requestCtx context.Context
	select {
	case requestCtx = <-f.requestCtx:
	case <-time.After(time.Second):
		t.Fatal("request context missing")
	}
	if err := f.server.Close(); err != nil {
		t.Fatal(err)
	}
	if requestCtx.Err() == nil || len(f.admission.slots) != 0 {
		t.Error("Close did not cancel/release the physical connection before delayed Hijack")
	}
	ungate()
	f.assertStopped(t, requestCtx)
}

type websocketLifecycleAcceptGate struct {
	net.Listener
	entered chan struct{}
	release <-chan struct{}
}

func (l *websocketLifecycleAcceptGate) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		close(l.entered)
		<-l.release // Actual admission already ran; net/http has not seen it.
	}
	return conn, err
}

func TestWebSocketLifecycleCloseDuringAcceptedSocketDelivery(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	ungate := func() { once.Do(func() { close(release) }) }
	f := newWebsocketLifecycleFixture(t, false, nil, func(s *WebH2Server) {
		s.listener = &websocketLifecycleAcceptGate{Listener: s.listener, entered: entered, release: release}
	})
	t.Cleanup(ungate)
	client, err := net.DialTimeout("tcp", f.server.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("actual accepted socket was not gated")
	}
	if len(f.admission.slots) != 1 {
		t.Fatal("test did not pause after real connection admission")
	}
	closeResult, closeDone := make(chan error, 1), make(chan struct{})
	go func() { defer close(closeDone); closeResult <- f.server.Close() }()
	t.Cleanup(func() { ungate(); websocketLifecycleJoin(t, "delayed Accept Close cleanup", closeDone) })
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
		t.Errorf("Close did not close not-yet-delivered physical socket: %v", err)
	}
	ungate()
	websocketLifecycleJoin(t, "Close with delayed Accept return", closeDone)
	select {
	case err := <-closeResult:
		if err != nil {
			t.Error(err)
		}
	default:
		t.Error("Close result missing")
	}
	// Remote EOF can precede the local raw Close return and its admission
	// release callback. Assert callback completion only after Close joins;
	// physical peer closure was independently checked before ungating Accept.
	if len(f.admission.slots) != 0 {
		t.Error("accepted socket retained its admission slot after Close joined")
	}
	websocketLifecycleJoin(t, "Serve with delayed Accept return", f.serveDone)
}

type websocketLifecycleWriteCall struct {
	done chan struct{}
	err  error
}

type websocketLifecycleWriteWitness struct {
	mu      sync.Mutex
	latest  *websocketLifecycleWriteCall
	changed chan struct{}
}

func (w *websocketLifecycleWriteWitness) observe(call *websocketLifecycleWriteCall) {
	w.mu.Lock()
	w.latest = call
	w.mu.Unlock()
	// Coalesce notifications, not evidence: the most recent actual call is
	// retained even when a burst fills the notification channel.
	select {
	case w.changed <- struct{}{}:
	default:
	}
}

func (w *websocketLifecycleWriteWitness) current() *websocketLifecycleWriteCall {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.latest
}

type websocketLifecycleObservedConn struct {
	net.Conn
	writes *websocketLifecycleWriteWitness
}

func (c *websocketLifecycleObservedConn) Write(p []byte) (int, error) {
	call := &websocketLifecycleWriteCall{done: make(chan struct{})}
	c.writes.observe(call)
	n, err := c.Conn.Write(p)
	call.err = err
	close(call.done)
	return n, err
}

type websocketLifecycleWriteObserver struct {
	http.ResponseWriter
	writes *websocketLifecycleWriteWitness
}

func (w *websocketLifecycleWriteObserver) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, buffered, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return conn, buffered, err
	}
	return &websocketLifecycleObservedConn{Conn: conn, writes: w.writes}, buffered, nil
}

func TestWebSocketLifecycleCloseUnblocksRealDownstreamWrite(t *testing.T) {
	writes := &websocketLifecycleWriteWitness{changed: make(chan struct{}, 1)}
	f := newWebsocketLifecycleFixture(t, true, func(w http.ResponseWriter) http.ResponseWriter {
		return &websocketLifecycleWriteObserver{ResponseWriter: w, writes: writes}
	}, nil)
	client, _, requestCtx := f.open(t)
	// Deliberately no client reader after the 101. Observe an actual TLS Write
	// that has not completed for 75 ms, not a fixture-created blocking gate.
	f.origin.releaseFlood()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	var blocked *websocketLifecycleWriteCall
findBlocked:
	for {
		if call := writes.current(); call != nil {
			window := time.NewTimer(75 * time.Millisecond)
			select {
			case <-call.done:
				window.Stop()
			case <-window.C:
				select {
				case <-call.done:
				default:
					blocked = call
					break findBlocked
				}
			case <-deadline.C:
				window.Stop()
				t.Fatal("did not establish actual downstream write backpressure")
			}
		}
		select {
		case <-writes.changed:
		case <-deadline.C:
			t.Fatal("no actual downstream write blocked")
		}
	}
	if requestCtx.Err() != nil {
		t.Fatal("request was canceled before the shutdown oracle")
	}
	select {
	case <-blocked.done:
		t.Fatal("observed actual Write finished before the Close oracle")
	default:
	}
	if err := f.server.Close(); err != nil {
		t.Fatal(err)
	}
	websocketLifecycleJoin(t, "actual downstream Write", blocked.done)
	select {
	case <-blocked.done:
		if blocked.err == nil {
			t.Error("blocked actual Write unexpectedly succeeded after physical close")
		}
		var timeout net.Error
		if errors.As(blocked.err, &timeout) && timeout.Timeout() {
			t.Errorf("blocked Write ended by a timeout, not physical closure: %v", blocked.err)
		}
	default:
	}
	f.assertStopped(t, requestCtx)
	// Explicit client close is cleanup, and occurs after all shutdown oracles.
	_ = client.Close()
}
