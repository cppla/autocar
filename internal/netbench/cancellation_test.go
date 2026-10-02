package netbench

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

const (
	benchmarkCancelReturnBudget = 400 * time.Millisecond
	benchmarkCancelJoinBudget   = 2 * time.Second
)

// These are actual socket reads. Observing entry does not create an I/O gate
// or consume bytes independently of the production handler.
type benchmarkCancelServerConn struct {
	net.Conn
	readStarted   chan struct{}
	uploadStarted chan struct{}
	readOnce      sync.Once
	uploadOnce    sync.Once
	bytesRead     atomic.Int64
}

func (c *benchmarkCancelServerConn) Read(p []byte) (int, error) {
	c.readOnce.Do(func() { close(c.readStarted) })
	if c.bytesRead.Load() >= headerSize {
		c.uploadOnce.Do(func() { close(c.uploadStarted) })
	}
	n, err := c.Conn.Read(p)
	c.bytesRead.Add(int64(n))
	return n, err
}

type benchmarkCancelListener struct {
	net.Listener
	accepted chan *benchmarkCancelServerConn
	mu       sync.Mutex
	closed   bool
	conns    []*benchmarkCancelServerConn
}

func (l *benchmarkCancelListener) Accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	conn := &benchmarkCancelServerConn{
		Conn: raw, readStarted: make(chan struct{}), uploadStarted: make(chan struct{}),
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	l.conns = append(l.conns, conn)
	l.mu.Unlock()
	// The tests create at most two peers. A bounded notification never
	// changes delivery timing or prevents production Accept from returning.
	select {
	case l.accepted <- conn:
	default:
	}
	return conn, nil
}

func (l *benchmarkCancelListener) forceCloseAccepted() {
	l.mu.Lock()
	l.closed = true
	conns := append([]*benchmarkCancelServerConn(nil), l.conns...)
	l.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

type benchmarkCancelServerFixture struct {
	listener *benchmarkCancelListener
	cancel   context.CancelFunc
	done     chan struct{}
	result   chan error
	peers    []net.Conn
}

func benchmarkCancelStartServer(t *testing.T) *benchmarkCancelServerFixture {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &benchmarkCancelServerFixture{
		listener: &benchmarkCancelListener{Listener: raw, accepted: make(chan *benchmarkCancelServerConn, 4)},
		cancel:   cancel, done: make(chan struct{}), result: make(chan error, 1),
	}
	t.Cleanup(func() {
		// Cleanup remains independent of the implementation's cancellation.
		cancel()
		_ = raw.Close()
		f.listener.forceCloseAccepted()
		for _, peer := range f.peers {
			_ = peer.Close()
		}
		benchmarkCancelJoin(t, f.done, "server cleanup")
	})
	go func() {
		defer close(f.done)
		// Keep the actual default two-minute handler timeout: the test must
		// prove cancellation, not expiration of a shortened socket deadline.
		f.result <- (&Server{MaxBytes: 1 << 20, MaxConnections: 1}).Serve(ctx, f.listener)
	}()
	return f
}

func (f *benchmarkCancelServerFixture) connect(t *testing.T) (net.Conn, *benchmarkCancelServerConn) {
	t.Helper()
	peer, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", f.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	f.peers = append(f.peers, peer)
	select {
	case conn := <-f.listener.accepted:
		return peer, conn
	case <-time.After(benchmarkCancelJoinBudget):
		t.Fatal("owned TCP socket was not accepted")
		return nil, nil
	}
}

func benchmarkCancelJoin(t *testing.T, done <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(benchmarkCancelJoinBudget):
		t.Errorf("%s did not join", name)
	}
}

func benchmarkCancelWaitPhase(t *testing.T, phase <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-phase:
	case <-time.After(benchmarkCancelJoinBudget):
		t.Fatalf("%s was not reached", name)
	}
}

func benchmarkCancelRequirePeerClosed(t *testing.T, peer net.Conn, name string) {
	t.Helper()
	if err := peer.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	n, err := peer.Read(one[:])
	if n != 0 || (!errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET)) {
		t.Errorf("%s remains open before independent cleanup: n=%d err=%v", name, n, err)
	}
}

func benchmarkCancelRequireServerReturned(t *testing.T, f *benchmarkCancelServerFixture) {
	t.Helper()
	select {
	case <-f.done:
		if err := <-f.result; err != nil {
			t.Errorf("Serve result = %v, want nil for cancellation/closed listener", err)
		}
	case <-time.After(benchmarkCancelReturnBudget):
		t.Error("Serve still waits for an accepted worker after shutdown")
	}
}

func TestBenchmarkServerCancellationClosesAcceptedSockets(t *testing.T) {
	for _, phase := range []string{"header", "upload", "pending_admission"} {
		t.Run(phase, func(t *testing.T) {
			f := benchmarkCancelStartServer(t)
			peer, conn := f.connect(t)
			benchmarkCancelWaitPhase(t, conn.readStarted, "actual header Read")
			if phase == "upload" {
				if err := peer.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				if _, err := peer.Write(benchmarkCancelHeader(ModeUpload, 1024)); err != nil {
					t.Fatal(err)
				}
				benchmarkCancelWaitPhase(t, conn.uploadStarted, "actual upload payload Read")
			}
			var pending net.Conn
			if phase == "pending_admission" {
				var pendingConn *benchmarkCancelServerConn
				pending, pendingConn = f.connect(t)
				select {
				case <-pendingConn.readStarted:
					t.Fatal("second socket reached handler despite full admission")
				default:
				}
			}
			f.cancel()
			benchmarkCancelRequirePeerClosed(t, peer, "active TCP socket")
			if pending != nil {
				benchmarkCancelRequirePeerClosed(t, pending, "pending admission TCP socket")
			}
			benchmarkCancelRequireServerReturned(t, f)
		})
	}
}

func TestBenchmarkServerListenerCloseJoinsActiveWorker(t *testing.T) {
	f := benchmarkCancelStartServer(t)
	peer, conn := f.connect(t)
	benchmarkCancelWaitPhase(t, conn.readStarted, "actual header Read")
	if err := f.listener.Close(); err != nil {
		t.Fatal(err)
	}
	// The parent context is deliberately live here. Returning from Accept
	// must also stop owned workers and the listener cancellation watcher.
	benchmarkCancelRequirePeerClosed(t, peer, "externally stopped server TCP socket")
	benchmarkCancelRequireServerReturned(t, f)
}

func benchmarkCancelHeader(mode byte, size int64) []byte {
	header := make([]byte, headerSize)
	copy(header[:4], magic[:])
	header[4], header[5] = protocolVersion, mode
	binary.BigEndian.PutUint64(header[8:], uint64(size))
	return header
}

type benchmarkCancelRunConn struct {
	net.Conn
	headerWrite  chan struct{}
	payloadWrite chan struct{}
	readStarted  chan struct{}
	writeCalls   atomic.Int64
	headerOnce   sync.Once
	payloadOnce  sync.Once
	readOnce     sync.Once
	closeCalls   atomic.Int64
}

func (c *benchmarkCancelRunConn) Write(p []byte) (int, error) {
	if c.writeCalls.Add(1) == 1 {
		c.headerOnce.Do(func() { close(c.headerWrite) })
	} else {
		c.payloadOnce.Do(func() { close(c.payloadWrite) })
	}
	return c.Conn.Write(p)
}

func (c *benchmarkCancelRunConn) Read(p []byte) (int, error) {
	c.readOnce.Do(func() { close(c.readStarted) })
	return c.Conn.Read(p)
}

func (c *benchmarkCancelRunConn) Close() error {
	c.closeCalls.Add(1)
	return c.Conn.Close()
}

func TestBenchmarkRunManualCancellation(t *testing.T) {
	for _, deadline := range []string{"none", "distant"} {
		t.Run(deadline, func(t *testing.T) {
			for _, phase := range []string{"header", "download", "upload", "ack"} {
				t.Run(phase, func(t *testing.T) {
					benchmarkCancelRunAtPhase(t, deadline, phase)
				})
			}
		})
	}
}

func benchmarkCancelRunAtPhase(t *testing.T, deadline, phase string) {
	t.Helper()
	base := context.Background()
	var deadlineCancel context.CancelFunc
	if deadline == "distant" {
		base, deadlineCancel = context.WithTimeout(base, time.Minute)
		defer deadlineCancel()
	}
	ctx, cancel := context.WithCancel(base)
	defer cancel()
	clientRaw, peer := net.Pipe()
	conn := &benchmarkCancelRunConn{
		Conn: clientRaw, headerWrite: make(chan struct{}), payloadWrite: make(chan struct{}), readStarted: make(chan struct{}),
	}
	release := make(chan struct{})
	var releaseOnce sync.Once
	peerDone := make(chan struct{})
	peerResult := make(chan error, 1)
	runDone := make(chan struct{})
	type outcome struct {
		result Result
		err    error
	}
	runResult := make(chan outcome, 1)
	mode, size := ModeDownload, int64(1024)
	if phase == "upload" {
		mode = ModeUpload
	} else if phase == "ack" {
		size = 0
	}
	t.Cleanup(func() {
		cancel()
		// Close both owned endpoints before any joins; do not rely on Run
		// to honor cancellation or the deliberately distant deadline.
		_ = clientRaw.Close()
		_ = peer.Close()
		releaseOnce.Do(func() { close(release) })
		benchmarkCancelJoin(t, runDone, "Run cleanup")
		benchmarkCancelJoin(t, peerDone, "peer cleanup")
	})
	go func() {
		defer close(peerDone)
		var err error
		if phase != "header" {
			header := make([]byte, headerSize)
			_, err = io.ReadFull(peer, header)
			if err == nil && string(header) != string(benchmarkCancelHeader(mode, size)) {
				err = fmt.Errorf("wrong actual benchmark header: %x", header)
			}
		}
		peerResult <- err
		<-release
	}()
	dialer := transport.DialFunc(func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "owned-benchmark.invalid:1" {
			return nil, fmt.Errorf("unexpected benchmark dial %q %q", network, address)
		}
		return conn, nil
	})
	go func() {
		defer close(runDone)
		result, err := Run(ctx, dialer, "owned-benchmark.invalid:1", mode, size)
		runResult <- outcome{result: result, err: err}
	}()
	var operation <-chan struct{}
	switch phase {
	case "header":
		operation = conn.headerWrite
	case "upload":
		operation = conn.payloadWrite
	default:
		operation = conn.readStarted
	}
	benchmarkCancelWaitPhase(t, operation, "actual pending "+phase+" I/O")
	// Set this peer-only oracle deadline before Run closes the other pipe
	// endpoint: net.Pipe rejects SetReadDeadline after a remote Close.
	if err := peer.SetReadDeadline(time.Now().Add(benchmarkCancelReturnBudget + 200*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	// No peer operation can complete the selected I/O. Manual cancellation
	// must stop Run before an endpoint is closed by independent cleanup.
	cancel()
	select {
	case <-runDone:
		got := <-runResult
		if !errors.Is(got.err, ctx.Err()) {
			t.Errorf("manual cancel at %s = %v, want %v identity", phase, got.err, ctx.Err())
		}
		if got.result != (Result{}) {
			t.Errorf("canceled transfer reported success: %+v", got.result)
		}
		if conn.closeCalls.Load() == 0 {
			t.Error("Run returned without closing its owned connection")
		}
		var one [1]byte
		if n, err := peer.Read(one[:]); n != 0 || !errors.Is(err, io.EOF) {
			t.Errorf("Run peer not closed before cleanup: n=%d err=%v", n, err)
		}
	case <-time.After(benchmarkCancelReturnBudget):
		t.Errorf("manual cancel at %s (deadline=%s) leaves Run blocked", phase, deadline)
	}
	select {
	case err := <-peerResult:
		if err != nil {
			t.Errorf("controlled peer header = %v", err)
		}
	case <-time.After(benchmarkCancelJoinBudget):
		t.Error("controlled peer did not observe the complete header")
	}
}
