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
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

// This fixture delays Close's return only after closing the real UDP socket.
// It is an explicit cleanup-completion barrier, not a simulated blocked I/O.
type webH3CloseJoinPacket struct {
	net.PacketConn
	entered  chan struct{}
	release  <-chan struct{}
	returned chan struct{}
	once     sync.Once
	err      error
}

func (p *webH3CloseJoinPacket) Close() error {
	p.once.Do(func() {
		p.err = p.PacketConn.Close()
		close(p.entered)
		<-p.release
		close(p.returned)
	})
	return p.err
}

func webH3CloseJoinWait(t *testing.T, done <-chan struct{}, label string) bool {
	t.Helper()
	select {
	case <-done:
		return true
	case <-time.After(2 * time.Second):
		t.Errorf("%s did not join", label)
		return false
	}
}

func webH3CloseJoinMustWait(t *testing.T, done <-chan struct{}, label string) {
	t.Helper()
	if !webH3CloseJoinWait(t, done, label) {
		t.FailNow()
	}
}

func webH3CloseJoinRead[T any](t *testing.T, values <-chan T, label string) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(2 * time.Second):
		t.Fatalf("%s did not return a result", label)
		var zero T
		return zero
	}
}

type webH3CloseJoinOrigin struct {
	listener *net.TCPListener
	mu       sync.Mutex
	conn     *net.TCPConn
	closed   bool
	done     chan struct{}
	result   chan error
}

func newWebH3CloseJoinOrigin(t *testing.T, payload []byte) *webH3CloseJoinOrigin {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	origin := &webH3CloseJoinOrigin{listener: listener, done: make(chan struct{}), result: make(chan error, 1)}
	t.Cleanup(func() {
		origin.mu.Lock()
		origin.closed = true
		conn := origin.conn
		origin.mu.Unlock()
		_ = listener.Close()
		if conn != nil {
			_ = conn.Close()
		}
		webH3CloseJoinWait(t, origin.done, "owned TCP origin worker")
	})
	go func() {
		defer close(origin.done)
		if err := listener.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			origin.result <- err
			return
		}
		conn, err := listener.AcceptTCP()
		if err != nil {
			origin.result <- err
			return
		}
		origin.mu.Lock()
		if origin.closed {
			origin.mu.Unlock()
			_ = conn.Close()
			origin.result <- net.ErrClosed
			return
		}
		origin.conn = conn
		origin.mu.Unlock()
		defer func() {
			_ = conn.Close()
			origin.mu.Lock()
			origin.conn = nil
			origin.mu.Unlock()
		}()
		if err = conn.SetDeadline(time.Now().Add(2 * time.Second)); err == nil {
			var got []byte
			got, err = io.ReadAll(conn)
			if err == nil && !bytes.Equal(got, payload) {
				err = errors.New("owned TCP origin received the wrong complete payload")
			}
			if err == nil {
				_, err = io.Copy(conn, bytes.NewReader(append([]byte("reply:"), got...)))
			}
			if err == nil {
				err = conn.CloseWrite()
			}
		}
		origin.result <- err
	}()
	return origin
}

func webH3CloseJoinCall(client *WebH3Client, started chan<- struct{}, result chan<- error, done chan struct{}) {
	defer close(done)
	started <- struct{}{}
	result <- client.Close()
}

// The first Close waits in workers.Wait; only the already-closed branch waits
// on a channel. Observe this test's second actual caller at that branch before
// starting the noncompletion window, rather than assuming it was scheduled.
func webH3CloseJoinObserveFollower(t *testing.T, first, second <-chan struct{}) {
	t.Helper()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-first:
			t.Fatal("first Close returned before packet cleanup completion")
		case <-second:
			t.Fatal("concurrent Close returned before packet cleanup completion")
		default:
		}
		buffer := make([]byte, 1<<20)
		n := runtime.Stack(buffer, true)
		if n == len(buffer) {
			t.Fatal("owned Close stack observation was truncated")
		}
		for _, block := range strings.Split(string(buffer[:n]), "\n\n") {
			line, _, _ := strings.Cut(block, "\n")
			if strings.Contains(line, "[chan receive]") &&
				strings.Contains(block, "(*WebH3Client).Close(") &&
				strings.Contains(block, "webH3CloseJoinCall(") {
				t.Log("observed own concurrent Close waiting on the shared completion channel")
				return
			}
		}
		select {
		case <-timer.C:
			t.Fatal("second Close did not reach its actual completion wait")
		case <-first:
			t.Fatal("first Close returned before packet cleanup completion")
		case <-second:
			t.Fatal("concurrent Close returned before packet cleanup completion")
		case <-ticker.C:
		}
	}
}

func TestWebH3CloseJoinsRemovedSessionCleanupAndConcurrentCallers(t *testing.T) {
	payload := []byte("owned H3 cleanup join with upload FIN")
	origin := newWebH3CloseJoinOrigin(t, payload)
	target := origin.listener.Addr().String()
	serverTLS, clientTLS := testTLSConfigs(t)
	server, err := ListenWebH3(WebH3ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
		Cover: http.NotFoundHandler(),
		Dialer: transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != target {
				return nil, errors.New("unexpected owned cleanup-join destination")
			}
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := server.server.Handler
	handlerDone := make(chan struct{})
	bearerLength := make(chan int, 1)
	server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(handlerDone)
		bearerLength <- len(r.Header.Get("Proxy-Authorization"))
		handler.ServeHTTP(w, r)
	})
	serveCtx, cancelServe := context.WithCancel(context.Background())
	serveDone := make(chan struct{})
	serveResult := make(chan error, 1)
	go func() { defer close(serveDone); serveResult <- server.Serve(serveCtx) }()
	t.Cleanup(func() {
		_ = server.Close()
		cancelServe()
		webH3CloseJoinWait(t, serveDone, "owned H3 Serve worker")
	})
	client, err := NewWebH3Client(WebH3ClientConfig{
		ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	ungate := sync.OnceFunc(func() { close(release) })
	var packet *webH3CloseJoinPacket
	var stream net.Conn
	var closeWorkers []<-chan struct{}
	t.Cleanup(func() {
		ungate()
		if packet != nil {
			_ = packet.PacketConn.Close()
		}
		if stream != nil {
			_ = stream.Close()
		}
		cleanupDone := make(chan struct{})
		go func() { defer close(cleanupDone); _ = client.Close() }()
		webH3CloseJoinWait(t, cleanupDone, "independent client cleanup")
		for _, done := range closeWorkers {
			webH3CloseJoinWait(t, done, "Close caller cleanup")
		}
		if packet != nil {
			webH3CloseJoinWait(t, packet.returned, "real packet Close completion")
		}
		workersDone := make(chan struct{})
		go func() { defer close(workersDone); client.workers.Wait() }()
		webH3CloseJoinWait(t, workersDone, "physical dial and session watcher cleanup")
	})
	dialCtx, cancelDial := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelDial()
	stream, err = client.DialContext(dialCtx, "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	if err = stream.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = stream.(*webH3Conn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(stream)
	if err != nil || !bytes.Equal(reply, append([]byte("reply:"), payload...)) {
		t.Fatalf("complete healthy H3 reply = %q, %v", reply, err)
	}
	webH3CloseJoinMustWait(t, origin.done, "successful complete TCP origin")
	if err := webH3CloseJoinRead(t, origin.result, "successful TCP origin"); err != nil {
		t.Fatal(err)
	}
	webH3CloseJoinMustWait(t, handlerDone, "successful authenticated CONNECT handler")
	if length := webH3CloseJoinRead(t, bearerLength, "full bootstrap credential"); length < 385 || length > 2047 {
		t.Fatalf("initial full bootstrap credential length = %d", length)
	}
	client.mu.Lock()
	session := client.conns[client.conn]
	if session == nil || session.conn.Context().Err() != nil || session.retired ||
		session.authState != webH3ClientAuthReady || session.auth == nil || session.users != 1 ||
		client.client != session.client || client.dial != nil || len(client.conns) != 1 {
		client.mu.Unlock()
		t.Fatal("healthy exact live authenticated session was not proved before instrumentation")
	}
	packet = &webH3CloseJoinPacket{
		PacketConn: session.packet, entered: make(chan struct{}), release: release, returned: make(chan struct{}),
	}
	session.packet = packet
	client.mu.Unlock()
	client.retire(session.conn)
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	webH3CloseJoinMustWait(t, packet.entered, "real packet closed before completion gate")
	if packet.err != nil {
		t.Fatalf("instrumented real packet Close = %v", packet.err)
	}
	client.mu.Lock()
	removed := client.conns[session.conn] == nil && client.conn == nil && client.client == nil && session.users == 0
	client.mu.Unlock()
	if !removed {
		t.Fatal("actual watcher did not remove the retired session before blocked resource cleanup")
	}
	select {
	case <-packet.returned:
		t.Fatal("packet Close escaped the explicit completion gate")
	default:
	}
	results := make(chan error, 2)
	started := make(chan struct{}, 2)
	first, second := make(chan struct{}), make(chan struct{})
	closeWorkers = append(closeWorkers, first, second)
	go webH3CloseJoinCall(client, started, results, first)
	webH3CloseJoinRead(t, started, "first Close entry")
	closedDeadline := time.NewTimer(time.Second)
	closedPoll := time.NewTicker(time.Millisecond)
	defer closedDeadline.Stop()
	defer closedPoll.Stop()
	for {
		client.mu.Lock()
		closed := client.closed
		client.mu.Unlock()
		if closed {
			break
		}
		select {
		case <-closedDeadline.C:
			t.Fatal("first Close did not reach the real closed gate")
		case <-closedPoll.C:
		}
	}
	go webH3CloseJoinCall(client, started, results, second)
	webH3CloseJoinRead(t, started, "second Close entry")
	webH3CloseJoinObserveFollower(t, first, second)
	select {
	case <-first:
		t.Fatal("first Close returned while removed-session cleanup was still pending")
	case <-second:
		t.Fatal("concurrent Close returned while removed-session cleanup was still pending")
	case <-client.closeDone:
		t.Fatal("client published final closure before resource cleanup completed")
	case <-time.After(75 * time.Millisecond):
	}
	ungate()
	webH3CloseJoinMustWait(t, first, "first Close")
	webH3CloseJoinMustWait(t, second, "concurrent Close")
	webH3CloseJoinMustWait(t, packet.returned, "packet cleanup after gate release")
	webH3CloseJoinMustWait(t, client.closeDone, "shared client closure completion")
	for range 2 {
		if err := webH3CloseJoinRead(t, results, "joined Close"); err != nil {
			t.Errorf("Close after complete cleanup = %v", err)
		}
	}
	client.mu.Lock()
	final := client.dial == nil && len(client.conns) == 0 && client.conn == nil && client.client == nil
	client.mu.Unlock()
	if !final {
		t.Error("joined Close retained a dial or tracked session")
	}
	_ = server.Close()
	cancelServe()
	webH3CloseJoinMustWait(t, serveDone, "successful H3 Serve shutdown")
	if err := webH3CloseJoinRead(t, serveResult, "joined H3 Serve"); err != nil {
		t.Errorf("H3 Serve = %v", err)
	}
}
