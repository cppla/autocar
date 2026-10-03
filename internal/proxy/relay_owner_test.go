package proxy

import (
	"bufio"
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

	"github.com/cppla/autocar/internal/transport"
)

type proxyHalfCloseAuditConn struct {
	net.Conn
	closed       chan struct{}
	once         sync.Once
	setupContext context.Context
}

func (c *proxyHalfCloseAuditConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

func (c *proxyHalfCloseAuditConn) CloseWrite() error {
	return c.Conn.(interface{ CloseWrite() error }).CloseWrite()
}

type proxyHalfCloseAuditPhase struct {
	release        chan struct{}
	releaseOnce    sync.Once
	upload         chan []byte
	originErr      chan error
	handlerDone    chan struct{}
	handlerStarted atomic.Bool
	upstream       chan *proxyHalfCloseAuditConn
}

func (p *proxyHalfCloseAuditPhase) unblock() { p.releaseOnce.Do(func() { close(p.release) }) }

type proxyHalfCloseAuditFixture struct {
	proxy      *net.TCPListener
	origin     *net.TCPListener
	tracker    *connTracker
	shutdown   func(context.Context) error
	serveDone  chan struct{}
	serveErr   error
	originDone chan struct{}
	phases     [2]*proxyHalfCloseAuditPhase
	mu         sync.Mutex
	closed     bool
	owned      []net.Conn
	prefix     *relayOwnerPrefixWriteConn
}

func (f *proxyHalfCloseAuditFixture) own(c net.Conn) bool {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		_ = c.Close()
		return false
	}
	f.owned = append(f.owned, c)
	f.mu.Unlock()
	return true
}

func proxyHalfCloseAuditWait(t *testing.T, done <-chan struct{}, label string) bool {
	t.Helper()
	select {
	case <-done:
		return true
	case <-time.After(2 * time.Second):
		t.Errorf("%s did not join", label)
		return false
	}
}

func newProxyHalfCloseAuditFixture(t *testing.T, mode string, response []byte, bufferedPrefix bool) *proxyHalfCloseAuditFixture {
	t.Helper()
	f := &proxyHalfCloseAuditFixture{serveDone: make(chan struct{}), originDone: make(chan struct{})}
	for i := range f.phases {
		f.phases[i] = &proxyHalfCloseAuditPhase{release: make(chan struct{}), upload: make(chan []byte, 1), originErr: make(chan error, 1), handlerDone: make(chan struct{}), upstream: make(chan *proxyHalfCloseAuditConn, 1)}
	}
	var err error
	f.origin, err = net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f.proxy, err = net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = f.origin.Close()
		t.Fatal(err)
	}
	if bufferedPrefix {
		f.prefix = &relayOwnerPrefixWriteConn{entered: make(chan []byte, 1), closed: make(chan struct{}), release: make(chan struct{})}
	}
	started := false
	t.Cleanup(func() {
		// Independent cleanup releases gates and every actual owned socket,
		// even when the production shutdown oracle fails before either join.
		for _, p := range f.phases {
			p.unblock()
		}
		if f.prefix != nil {
			f.prefix.unblock()
		}
		_ = f.origin.Close()
		_ = f.proxy.Close()
		f.mu.Lock()
		f.closed = true
		owned := append([]net.Conn(nil), f.owned...)
		f.mu.Unlock()
		for _, c := range owned {
			_ = c.Close()
		}
		if f.shutdown != nil {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_ = f.shutdown(ctx)
		}
		if started {
			proxyHalfCloseAuditWait(t, f.originDone, "origin accept/handler worker cleanup")
			serveJoined := proxyHalfCloseAuditWait(t, f.serveDone, "frontend accept/Serve cleanup")
			for i, p := range f.phases {
				if p.handlerStarted.Load() {
					proxyHalfCloseAuditWait(t, p.handlerDone, fmt.Sprintf("handler %d cleanup", i))
				}
			}
			if serveJoined && f.serveErr != nil {
				t.Errorf("frontend Serve = %v", f.serveErr)
			}
		}
	})
	var dialIndex atomic.Int32
	dialer := transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != f.origin.Addr().String() {
			return nil, fmt.Errorf("non-owned target %s/%s", network, address)
		}
		index := int(dialIndex.Add(1) - 1)
		if index >= len(f.phases) {
			return nil, errors.New("unexpected extra dial")
		}
		c, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		if bufferedPrefix && index == 1 {
			f.prefix.Conn = c
			c = f.prefix
		}
		observed := &proxyHalfCloseAuditConn{Conn: c, closed: make(chan struct{}), setupContext: ctx}
		if !f.own(observed) {
			return nil, net.ErrClosed
		}
		f.phases[index].upstream <- observed
		return observed, nil
	})
	cfg := Config{Dialer: dialer, HandshakeTimeout: time.Second, DialTimeout: 100 * time.Millisecond, IdleTimeout: 3 * time.Second, MaxConnections: 1}
	if mode == "http_connect" {
		s, err := NewHTTPServer(cfg)
		if err != nil {
			t.Fatal(err)
		}
		f.tracker, f.shutdown = s.lifecycle.tracker, s.Shutdown
		var handlerIndex atomic.Int32
		s.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			i := int(handlerIndex.Add(1) - 1)
			if i >= len(f.phases) {
				http.Error(w, "unexpected handler", 500)
				return
			}
			p := f.phases[i]
			p.handlerStarted.Store(true)
			defer close(p.handlerDone)
			s.ServeHTTP(w, r)
		})
		started = true
		var listener net.Listener = f.proxy
		if bufferedPrefix {
			request := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", f.origin.Addr(), f.origin.Addr())
			listener = &relayOwnerPrefixListener{Listener: listener, firstReadBytes: len(request) + len("owned-halfclose-marker")}
		}
		go func() { defer close(f.serveDone); f.serveErr = s.Serve(listener) }()
	} else {
		s, err := NewSOCKS5Server(cfg)
		if err != nil {
			t.Fatal(err)
		}
		f.tracker, f.shutdown = s.lifecycle.tracker, s.Shutdown
		managed, err := s.lifecycle.manage(f.proxy)
		if err != nil {
			t.Fatal(err)
		}
		started = true
		go func() {
			defer close(f.serveDone)
			for i := 0; ; i++ {
				c, err := managed.Accept()
				if err != nil {
					if !errors.Is(err, net.ErrClosed) {
						f.serveErr = err
					}
					return
				}
				if !f.own(c) {
					return
				}
				if i >= len(f.phases) {
					_ = c.Close()
					f.serveErr = errors.New("unexpected extra accept")
					return
				}
				p := f.phases[i]
				p.handlerStarted.Store(true)
				go func() { defer close(p.handlerDone); s.serveConn(c) }()
			}
		}()
	}
	go func() {
		defer close(f.originDone)
		for index, p := range f.phases {
			c, err := f.origin.AcceptTCP()
			if err != nil {
				return
			}
			if !f.own(c) {
				return
			}
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			marker := make([]byte, len("owned-halfclose-marker"))
			_, err = io.ReadFull(c, marker)
			if err == nil {
				_, err = c.Write([]byte("ack"))
			}
			var tail []byte
			if err == nil {
				tail, err = io.ReadAll(c)
			}
			p.upload <- append(marker, tail...)
			if err != nil {
				p.originErr <- err
				_ = c.Close()
				continue
			}
			// This gate holds only the ordinary destination's response, not
			// any Close callback or frontend worker completion.
			<-p.release
			if index == 0 {
				_, err = c.Write(response)
				if err == nil {
					err = c.CloseWrite()
				}
			}
			p.originErr <- err
			_ = c.Close()
		}
	}()
	return f
}

func proxyHalfCloseAuditOpen(t *testing.T, f *proxyHalfCloseAuditFixture, mode string) (*net.TCPConn, *bufio.Reader) {
	t.Helper()
	c, err := net.DialTCP("tcp4", nil, f.proxy.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	if !f.own(c) {
		t.Fatal("fixture already closed")
	}
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	r := bufio.NewReader(c)
	if mode == "http_connect" {
		_, err = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", f.origin.Addr(), f.origin.Addr())
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(r, &http.Request{Method: http.MethodConnect})
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("CONNECT response = %v / %v", response, err)
		}
	} else {
		socksGreeting(t, c, nil)
		host, port := splitAddress(t, f.origin.Addr().String())
		mustWrite(t, c, domainSOCKSRequest(socksCommandConnect, host, port))
		if reply := readSOCKSReply(t, c); reply != socksReplySucceeded {
			t.Fatalf("SOCKS reply = %d", reply)
		}
	}
	mustWrite(t, c, []byte("owned-halfclose-marker"))
	ack := make([]byte, 3)
	if _, err := io.ReadFull(r, ack); err != nil || string(ack) != "ack" {
		t.Fatalf("real ack = %q / %v", ack, err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	return c, r
}

func proxyHalfCloseAuditUpload(t *testing.T, p *proxyHalfCloseAuditPhase) {
	t.Helper()
	select {
	case payload := <-p.upload:
		if string(payload) != "owned-halfclose-marker" {
			t.Fatalf("actual origin upload = %q", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("origin did not observe complete upload and real EOF")
	}
}

func TestProxyCONNECTOwnerShutdownReleasesHalfClosedUpstream(t *testing.T) {
	for _, mode := range []string{"http_connect", "socks_connect"} {
		t.Run(mode, func(t *testing.T) {
			response := bytes.Repeat([]byte("delayed-origin-response-"), 8192)
			f := newProxyHalfCloseAuditFixture(t, mode, response, false)
			c, r := proxyHalfCloseAuditOpen(t, f, mode)
			proxyHalfCloseAuditUpload(t, f.phases[0])
			select {
			case <-f.phases[0].handlerDone:
				t.Fatal("healthy handler ended before delayed response")
			default:
			}
			var firstUpstream *proxyHalfCloseAuditConn
			select {
			case firstUpstream = <-f.phases[0].upstream:
			case <-time.After(time.Second):
				t.Fatal("missing healthy setup context")
			}
			if !errors.Is(firstUpstream.setupContext.Err(), context.Canceled) {
				t.Fatalf("successful setup context was not detached/canceled: %v", firstUpstream.setupContext.Err())
			}
			setupDeadline, ok := firstUpstream.setupContext.Deadline()
			if !ok {
				t.Fatal("successful setup had no configured deadline")
			}
			// Cross the original setup deadline before releasing the delayed
			// response. Only the physical owner may govern this live relay.
			deadlinePassed := time.NewTimer(time.Until(setupDeadline.Add(20 * time.Millisecond)))
			<-deadlinePassed.C
			f.phases[0].unblock()
			got, err := io.ReadAll(r)
			if err != nil || !bytes.Equal(got, response) {
				t.Fatalf("delayed half-close response %d/%v, want %d exact bytes", len(got), err, len(response))
			}
			if !proxyHalfCloseAuditWait(t, f.phases[0].handlerDone, "healthy half-close handler") {
				t.FailNow()
			}
			_ = c.Close()
			t.Logf("healthy control: setup deadline crossed + real upload EOF + delayed %d-byte complete response + handler join", len(response))

			c, r = proxyHalfCloseAuditOpen(t, f, mode)
			proxyHalfCloseAuditUpload(t, f.phases[1])
			var upstream *proxyHalfCloseAuditConn
			select {
			case upstream = <-f.phases[1].upstream:
			case <-time.After(time.Second):
				t.Fatal("missing owned upstream witness")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer cancel()
			err = f.shutdown(ctx)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("forced Shutdown = %v, want deadline", err)
			}
			f.tracker.mu.Lock()
			slots := len(f.tracker.conns)
			f.tracker.mu.Unlock()
			if slots != 0 {
				t.Errorf("forced Shutdown retained %d downstream slots", slots)
			}
			_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			_, err = r.ReadByte()
			if !errors.Is(err, io.EOF) {
				t.Errorf("downstream after forced Shutdown = %v, want real EOF", err)
			}
			upstreamClosed, handlerJoined := false, false
			closed, joined := upstream.closed, f.phases[1].handlerDone
			timer := time.NewTimer(200 * time.Millisecond)
		observe:
			for !upstreamClosed || !handlerJoined {
				select {
				case <-closed:
					upstreamClosed = true
					closed = nil
				case <-joined:
					handlerJoined = true
					joined = nil
				case <-timer.C:
					break observe
				}
			}
			timer.Stop()
			t.Logf("before independent cleanup: Shutdown=%v downstreamEOF=%v tracker=%d upstreamCloseReturned=%v handlerJoined=%v idleBudget=3s", ctx.Err(), errors.Is(err, io.EOF), slots, upstreamClosed, handlerJoined)
			if !upstreamClosed {
				t.Error("forced Shutdown left owned upstream open after inbound pump had already half-closed")
			}
			if !handlerJoined {
				t.Error("forced Shutdown left relay handler blocked on destination reverse Read")
			}
			// Cleanup recovery is a separately identified positive control,
			// never evidence for the preceding forced shutdown assertions.
			f.phases[1].unblock()
			if !proxyHalfCloseAuditWait(t, f.phases[1].handlerDone, "handler after independent origin release") {
				t.FailNow()
			}
			if !proxyHalfCloseAuditWait(t, upstream.closed, "upstream Close after independent origin release") {
				t.FailNow()
			}
			if !proxyHalfCloseAuditWait(t, f.serveDone, "Serve after Shutdown") {
				t.FailNow()
			}
			if !proxyHalfCloseAuditWait(t, f.originDone, "origin worker after independent release") {
				t.FailNow()
			}
			for i, p := range f.phases {
				select {
				case originErr := <-p.originErr:
					if originErr != nil {
						t.Errorf("origin %d = %v", i, originErr)
					}
				case <-time.After(time.Second):
					t.Errorf("origin %d missing completion", i)
				}
			}
			t.Log("independent origin release recovered upstream close, both handlers, Serve/accept and origin joins")
		})
	}
}

type relayOwnerReadWitnessConn struct {
	net.Conn
	readStarted chan struct{}
	startOnce   sync.Once
	readEnded   chan struct{}
	readOnce    sync.Once
}

func (c *relayOwnerReadWitnessConn) Read(p []byte) (int, error) {
	c.startOnce.Do(func() { close(c.readStarted) })
	n, err := c.Conn.Read(p)
	if err != nil {
		c.readOnce.Do(func() { close(c.readEnded) })
	}
	return n, err
}

func (c *relayOwnerReadWitnessConn) CloseWrite() error {
	return c.Conn.(*net.TCPConn).CloseWrite()
}

type relayOwnerCloseCompletionConn struct {
	*relayOwnerReadWitnessConn
	firstClose atomic.Bool
	rawClosed  chan struct{}
	release    chan struct{}
}

func (c *relayOwnerCloseCompletionConn) Close() error {
	first := c.firstClose.CompareAndSwap(false, true)
	err := c.Conn.Close()
	if first {
		// The real descriptor has closed before this synthetic completion
		// gate. Later Close calls return immediately, not via a blocking Once.
		close(c.rawClosed)
		<-c.release
	}
	return err
}

// relayOwnerTCPPair joins its sole Accept worker before returning. Independent
// cleanup closes the listener and both returned sockets on every error path.
func relayOwnerTCPPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	type acceptedResult struct {
		conn net.Conn
		err  error
	}
	result := make(chan acceptedResult, 1)
	joined := make(chan struct{})
	var server, client net.Conn
	t.Cleanup(func() {
		_ = listener.Close()
		if client != nil {
			_ = client.Close()
		}
		if proxyHalfCloseAuditWait(t, joined, "real TCP pair Accept cleanup") {
			select {
			case pending := <-result:
				if pending.conn != nil {
					_ = pending.conn.Close()
				}
			default:
			}
		}
		if server != nil {
			_ = server.Close()
		}
	})
	go func() {
		defer close(joined)
		conn, err := listener.AcceptTCP()
		result <- acceptedResult{conn: conn, err: err}
	}()
	client, err = net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !proxyHalfCloseAuditWait(t, joined, "real TCP pair Accept") {
		t.FailNow()
	}
	accepted := <-result // The joined worker published this buffered result.
	if accepted.err != nil {
		t.Fatal(accepted.err)
	}
	server = accepted.conn
	_ = listener.Close()
	return server, client
}

func TestRelayOwnerCancellationJoinsStartedCloseCallback(t *testing.T) {
	leftRaw, leftPeer := relayOwnerTCPPair(t)
	rightRaw, rightPeer := relayOwnerTCPPair(t)
	left := &relayOwnerReadWitnessConn{Conn: leftRaw, readStarted: make(chan struct{}), readEnded: make(chan struct{})}
	right := &relayOwnerCloseCompletionConn{
		relayOwnerReadWitnessConn: &relayOwnerReadWitnessConn{Conn: rightRaw, readStarted: make(chan struct{}), readEnded: make(chan struct{})},
		rawClosed:                 make(chan struct{}), release: make(chan struct{}),
	}
	release := sync.OnceFunc(func() { close(right.release) })
	owner, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	joined := make(chan struct{})
	t.Cleanup(func() {
		release()
		cancel()
		// Bypass the completion wrapper during independent fixture cleanup.
		for _, conn := range []net.Conn{leftRaw, rightRaw, leftPeer, rightPeer} {
			_ = conn.Close()
		}
		proxyHalfCloseAuditWait(t, joined, "relay cancellation worker cleanup")
	})
	go func() {
		defer close(joined)
		result <- relayWithOwner(owner, left, right, 3*time.Second)
	}()
	if !proxyHalfCloseAuditWait(t, left.readStarted, "upload actual Read entry") ||
		!proxyHalfCloseAuditWait(t, right.readStarted, "reverse actual Read entry") {
		t.FailNow()
	}
	cancel()
	if !proxyHalfCloseAuditWait(t, right.rawClosed, "owner callback actual TCP descriptor close") {
		t.FailNow()
	}
	if err := rightPeer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := rightPeer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("real target peer after callback descriptor close = %v, want EOF", err)
	}
	// The reverse pump's real read error triggers the ordinary hard-error
	// shutdown, whose repeated Close returns without waiting on the gate.
	// Both raw Read calls must have ended, yet the callback Close has not.
	if !proxyHalfCloseAuditWait(t, right.readEnded, "reverse raw read cancellation") ||
		!proxyHalfCloseAuditWait(t, left.readEnded, "upload raw read cancellation") {
		t.FailNow()
	}
	select {
	case <-joined:
		t.Error("relay returned before its already-started owner Close callback completed")
	case <-time.After(75 * time.Millisecond):
	}
	release()
	if !proxyHalfCloseAuditWait(t, joined, "relay after independent Close completion release") {
		t.FailNow()
	}
	if err := <-result; err != nil {
		t.Errorf("relay after cancellation = %v", err)
	}
}

type relayOwnerPrefixListener struct {
	net.Listener
	firstReadBytes int
}

func (l *relayOwnerPrefixListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &relayOwnerPrefixReadConn{Conn: c, firstReadBytes: l.firstReadBytes}, nil
}

type relayOwnerPrefixReadConn struct {
	net.Conn
	firstReadBytes int
	firstReadDone  bool
}

func (c *relayOwnerPrefixReadConn) Read(p []byte) (int, error) {
	if !c.firstReadDone {
		c.firstReadDone = true
		if len(p) < c.firstReadBytes {
			return 0, errors.New("fixture first Read buffer too small")
		}
		// Coalesce the real CONNECT header and early payload into one actual
		// socket read so net/http necessarily buffers the payload. This is a
		// fixture scheduling control, not a production reader or TCP claim.
		return io.ReadFull(c.Conn, p[:c.firstReadBytes])
	}
	return c.Conn.Read(p)
}

func (c *relayOwnerPrefixReadConn) CloseWrite() error {
	return c.Conn.(*net.TCPConn).CloseWrite()
}

type relayOwnerPrefixWriteConn struct {
	net.Conn
	entered     chan []byte
	closed      chan struct{}
	release     chan struct{}
	firstWrite  sync.Once
	closeOnce   sync.Once
	releaseOnce sync.Once
}

func (c *relayOwnerPrefixWriteConn) Write(p []byte) (int, error) {
	c.firstWrite.Do(func() {
		c.entered <- append([]byte(nil), p...)
		// Hold only entry to the real prefix Write. This explicit scheduling
		// gate is not evidence of naturally occurring kernel backpressure.
		select {
		case <-c.closed:
		case <-c.release:
		}
	})
	return c.Conn.Write(p)
}

func (c *relayOwnerPrefixWriteConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() { close(c.closed) })
	return err
}

func (c *relayOwnerPrefixWriteConn) CloseWrite() error {
	return c.Conn.(*net.TCPConn).CloseWrite()
}

func (c *relayOwnerPrefixWriteConn) unblock() {
	c.releaseOnce.Do(func() { close(c.release) })
}

func relayOwnerOpenBufferedPrefix(t *testing.T, f *proxyHalfCloseAuditFixture, healthy bool) (*net.TCPConn, *bufio.Reader) {
	t.Helper()
	c, err := net.DialTCP("tcp4", nil, f.proxy.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	if !f.own(c) {
		t.Fatal("fixture already closed")
	}
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	request := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\nowned-halfclose-marker", f.origin.Addr(), f.origin.Addr())
	mustWrite(t, c, []byte(request))
	r := bufio.NewReader(c)
	response, err := http.ReadResponse(r, &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("early-payload CONNECT response = %v / %v", response, err)
	}
	if healthy {
		ack := make([]byte, 3)
		if _, err := io.ReadFull(r, ack); err != nil || string(ack) != "ack" {
			t.Fatalf("actual early-prefix ack = %q / %v", ack, err)
		}
		if err := c.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	}
	return c, r
}

func TestHTTPConnectOwnerShutdownInterruptsBufferedPrefix(t *testing.T) {
	response := bytes.Repeat([]byte("delayed-origin-response-"), 8192)
	f := newProxyHalfCloseAuditFixture(t, "http_connect", response, true)
	c, r := relayOwnerOpenBufferedPrefix(t, f, true)
	proxyHalfCloseAuditUpload(t, f.phases[0])
	f.phases[0].unblock()
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, response) {
		t.Fatalf("healthy prefix response %d/%v, want %d exact bytes", len(got), err, len(response))
	}
	if !proxyHalfCloseAuditWait(t, f.phases[0].handlerDone, "healthy buffered-prefix handler") {
		t.FailNow()
	}
	_ = c.Close()
	t.Logf("healthy real CONNECT buffered prefix + upload EOF + %d-byte exact response", len(got))

	c, r = relayOwnerOpenBufferedPrefix(t, f, false)
	select {
	case prefix := <-f.prefix.entered:
		if string(prefix) != "owned-halfclose-marker" {
			t.Fatalf("buffered prefix Write = %q", prefix)
		}
	case <-time.After(time.Second):
		t.Fatal("buffered prefix did not enter owned upstream Write")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	err = f.shutdown(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("forced Shutdown during prefix = %v, want deadline", err)
	}
	f.tracker.mu.Lock()
	slots := len(f.tracker.conns)
	f.tracker.mu.Unlock()
	if slots != 0 {
		t.Errorf("forced prefix shutdown retained %d slots", slots)
	}
	_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, readErr := r.ReadByte()
	if !errors.Is(readErr, io.EOF) {
		t.Errorf("forced prefix downstream Read = %v, want EOF", readErr)
	}
	closed, joined := false, false
	closedCh, joinedCh := f.prefix.closed, f.phases[1].handlerDone
	timer := time.NewTimer(200 * time.Millisecond)
observe:
	for !closed || !joined {
		select {
		case <-closedCh:
			closed = true
			closedCh = nil
		case <-joinedCh:
			joined = true
			joinedCh = nil
		case <-timer.C:
			break observe
		}
	}
	timer.Stop()
	t.Logf("before independent prefix release: tracker=%d targetRawClose=%v handlerJoined=%v downstreamEOF=%v", slots, closed, joined, errors.Is(readErr, io.EOF))
	if !closed || !joined {
		t.Errorf("owner did not interrupt/join buffered-prefix Write: rawClose=%v handlerJoined=%v", closed, joined)
	}
	// The synthetic Write gate and ordinary target response gate are released
	// independently only after the production lifetime assertions above.
	f.prefix.unblock()
	f.phases[1].unblock()
	if !proxyHalfCloseAuditWait(t, f.phases[1].handlerDone, "prefix handler independent cleanup") ||
		!proxyHalfCloseAuditWait(t, f.originDone, "prefix origin independent cleanup") ||
		!proxyHalfCloseAuditWait(t, f.serveDone, "prefix Serve after Shutdown") {
		t.FailNow()
	}
	for i, p := range f.phases {
		select {
		case originErr := <-p.originErr:
			if i == 0 && originErr != nil {
				t.Errorf("healthy prefix origin = %v", originErr)
			}
			if i == 1 && closed && !errors.Is(originErr, io.EOF) {
				t.Errorf("prefix origin after actual descriptor Close = %v, want real EOF", originErr)
			}
		case <-time.After(time.Second):
			t.Errorf("prefix origin %d missing completion", i)
		}
	}
}
