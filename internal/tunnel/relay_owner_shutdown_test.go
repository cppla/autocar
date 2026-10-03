package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/transport"
)

const relayOwnerMarker = "authenticated-relay-owner-marker"
const relayOwnerAck = "owned-target-ack"

// The target, relay, and client all use actual owned loopback sockets. Only
// target application progress and the return of its first Close are gated;
// neither gate manufactures a transport error or consumes tunnel bytes.
type relayOwnerFixture struct {
	t                             *testing.T
	mode, targetMode              string
	listener                      *net.TCPListener
	mu                            sync.Mutex
	closing                       bool
	origin                        *net.TCPConn
	destination                   *relayOwnerDestination
	workers                       []<-chan struct{}
	release, closeRelease         chan struct{}
	releaseOnce, closeReleaseOnce sync.Once
	originEOF, originDone         chan struct{}
	originErr                     error
	response, tail                []byte
	dialDeadline                  time.Time
	dials                         atomic.Int32
	tlsServer                     *TLSServer
	quicServer                    *QUICServer
	closeServer                   func() error
	closeClient                   func() error
	serveCancel                   context.CancelFunc
	serveContext                  context.Context
	serveDone                     chan struct{}
	serveErr                      error
	conn                          net.Conn
}

type relayOwnerDestination struct {
	*net.TCPConn
	closeRelease                     <-chan struct{}
	closed, closeEntered, halfClosed chan struct{}
	closeDone                        chan struct{}
	closeStarted                     atomic.Bool
	halfOnce                         sync.Once
	closeCalls                       atomic.Int32
	closeErr                         error
}

func (c *relayOwnerDestination) Close() error {
	if c.closeStarted.CompareAndSwap(false, true) {
		defer close(c.closeDone)
		c.closeCalls.Add(1)
		c.closeErr = c.TCPConn.Close()
		close(c.closed)
		close(c.closeEntered)
		<-c.closeRelease
		return c.closeErr
	}
	// Subsequent calls deliberately do not join the first return gate. The
	// server must join its owner callback, not accidentally rely on this fixture
	// making the ordinary deferred target Close wait for that callback.
	return nil
}

func (c *relayOwnerDestination) CloseWrite() error {
	err := c.TCPConn.CloseWrite()
	if err == nil {
		c.halfOnce.Do(func() { close(c.halfClosed) })
	}
	return err
}

func newRelayOwnerFixture(t *testing.T, mode, targetMode string, holdClose bool) *relayOwnerFixture {
	t.Helper()
	f := &relayOwnerFixture{
		t: t, mode: mode, targetMode: targetMode,
		release: make(chan struct{}), closeRelease: make(chan struct{}),
		originEOF: make(chan struct{}), originDone: make(chan struct{}), serveDone: make(chan struct{}),
		response: bytes.Repeat([]byte("complete-response-"), 8192),
		tail:     bytes.Repeat([]byte("late-upload-tail"), 4096),
	}
	t.Cleanup(f.cleanup)
	if !holdClose {
		f.releaseClose()
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f.listener = listener
	if err := listener.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	f.register(f.originDone)
	go f.serveOrigin()

	dialer := transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != listener.Addr().String() {
			return nil, fmt.Errorf("unowned destination %q/%q", network, address)
		}
		f.dials.Add(1)
		raw, err := (&net.Dialer{}).DialContext(ctx, "tcp4", address)
		if err != nil {
			return nil, err
		}
		destination := &relayOwnerDestination{TCPConn: raw.(*net.TCPConn), closeRelease: f.closeRelease,
			closed: make(chan struct{}), closeEntered: make(chan struct{}), halfClosed: make(chan struct{}), closeDone: make(chan struct{})}
		f.register(destination.closeDone)
		f.mu.Lock()
		f.destination = destination
		f.dialDeadline, _ = ctx.Deadline()
		closing := f.closing
		f.mu.Unlock()
		if closing {
			_ = destination.Close()
			return nil, net.ErrClosed
		}
		return destination, nil
	})
	serverTLS, clientTLS := testTLSConfigs(t)
	f.serveContext, f.serveCancel = context.WithCancel(context.Background())
	var client transport.Dialer
	var serve func(context.Context) error
	if mode == "tls" {
		server, err := ListenTLS(TLSServerConfig{Address: "127.0.0.1:0", Token: testToken,
			TLSConfig: serverTLS, Dialer: dialer, DialTimeout: 100 * time.Millisecond,
			MaxConcurrentStreams: 1, MaxClientConnections: 1})
		if err != nil {
			t.Fatal(err)
		}
		f.tlsServer, f.closeServer, serve = server, server.Close, server.Serve
		tlsClient, err := NewTLSClient(TLSClientConfig{ServerAddress: server.Addr().String(), Token: testToken, TLSConfig: clientTLS})
		if err != nil {
			t.Fatal(err)
		}
		client, f.closeClient = tlsClient, tlsClient.Close
	} else {
		server, err := ListenQUIC(QUICServerConfig{Address: "127.0.0.1:0", Token: testToken,
			TLSConfig: serverTLS, Dialer: dialer, DialTimeout: 100 * time.Millisecond,
			MaxConcurrentStreams: 1, MaxConnections: 1, MaxClientConnections: 1})
		if err != nil {
			t.Fatal(err)
		}
		f.quicServer, f.closeServer, serve = server, server.Close, server.Serve
		quicClient, err := NewClient(ClientConfig{ServerAddress: server.Addr().String(), Token: testToken, TLSConfig: clientTLS})
		if err != nil {
			t.Fatal(err)
		}
		client, f.closeClient = quicClient, quicClient.Close
	}
	f.register(f.serveDone)
	go func() { defer close(f.serveDone); f.serveErr = serve(f.serveContext) }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	f.conn, err = client.DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if mode == "tls" {
		state := f.conn.(*trackedTLSConn).ConnectionState()
		if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != protocol.ALPN {
			t.Fatalf("TLS security state=%+v", state)
		}
	} else {
		quicClient := client.(*Client)
		quicClient.mu.Lock()
		physical := quicClient.conn
		quicClient.mu.Unlock()
		if physical == nil {
			t.Fatal("missing actual QUIC connection")
		}
		state := physical.ConnectionState()
		if state.TLS.Version != tls.VersionTLS13 || state.TLS.NegotiatedProtocol != protocol.ALPN || state.Used0RTT {
			t.Fatalf("QUIC security state=%+v", state)
		}
	}
	if _, err := io.Copy(f.conn, bytes.NewBufferString(relayOwnerMarker)); err != nil {
		t.Fatal(err)
	}
	ack := make([]byte, len(relayOwnerAck))
	if _, err := io.ReadFull(f.conn, ack); err != nil || string(ack) != relayOwnerAck {
		t.Fatalf("actual relay ack=%q, %v", ack, err)
	}
	f.assertSlots(1, true)
	if f.dials.Load() != 1 {
		t.Fatalf("actual authenticated target dials=%d, want 1", f.dials.Load())
	}
	t.Logf("%s: verified TLS1.3/%s, actual authenticated target marker/ack", mode, protocol.ALPN)
	return f
}

func (f *relayOwnerFixture) serveOrigin() {
	defer close(f.originDone)
	conn, err := f.listener.AcceptTCP()
	if err != nil {
		f.originErr = err
		return
	}
	defer conn.Close()
	f.mu.Lock()
	f.origin = conn
	closing := f.closing
	f.mu.Unlock()
	if closing {
		return
	}
	if err := conn.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		f.originErr = err
		return
	}
	marker := make([]byte, len(relayOwnerMarker))
	if _, err := io.ReadFull(conn, marker); err != nil || string(marker) != relayOwnerMarker {
		f.originErr = fmt.Errorf("origin marker=%q: %v", marker, err)
		return
	}
	if _, err := conn.Write([]byte(relayOwnerAck)); err != nil {
		f.originErr = err
		return
	}
	if f.targetMode == "response_first" {
		if _, err := io.Copy(conn, bytes.NewReader(f.response)); err != nil {
			f.originErr = err
			return
		}
		if err := conn.CloseWrite(); err != nil {
			f.originErr = err
			return
		}
	}
	upload, err := io.ReadAll(conn)
	if err != nil {
		f.originErr = err
		return
	}
	if f.targetMode == "response_first" && !bytes.Equal(upload, f.tail) {
		f.originErr = fmt.Errorf("complete late tail mismatch: got %d, want %d bytes", len(upload), len(f.tail))
		return
	}
	if f.targetMode != "response_first" && len(upload) != 0 {
		f.originErr = fmt.Errorf("unexpected target upload %d bytes", len(upload))
		return
	}
	close(f.originEOF)
	if f.targetMode == "response_first" {
		return
	}
	<-f.release
	if f.targetMode == "delayed" {
		if _, err := io.Copy(conn, bytes.NewReader(f.response)); err != nil {
			f.originErr = err
			return
		}
		f.originErr = conn.CloseWrite()
	}
}

func (f *relayOwnerFixture) register(done <-chan struct{}) {
	f.mu.Lock()
	f.workers = append(f.workers, done)
	f.mu.Unlock()
}

func (f *relayOwnerFixture) wait(done <-chan struct{}, label string, budget time.Duration) bool {
	f.t.Helper()
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		f.t.Errorf("%s did not complete within %s", label, budget)
		return false
	}
}

func (f *relayOwnerFixture) require(done <-chan struct{}, label string) {
	f.t.Helper()
	if !f.wait(done, label, 2*time.Second) {
		f.t.FailNow()
	}
}

func (f *relayOwnerFixture) releaseTarget() { f.releaseOnce.Do(func() { close(f.release) }) }
func (f *relayOwnerFixture) releaseClose()  { f.closeReleaseOnce.Do(func() { close(f.closeRelease) }) }

func (f *relayOwnerFixture) slots() (streams, connections, source int) {
	if f.tlsServer != nil {
		return len(f.tlsServer.core.sem), len(f.tlsServer.connSem), f.tlsServer.clients.count("127.0.0.1")
	}
	if f.quicServer != nil {
		return len(f.quicServer.core.sem), len(f.quicServer.connSem), f.quicServer.clients.count("127.0.0.1")
	}
	return 0, 0, 0
}

func (f *relayOwnerFixture) assertSlots(streams int, parent bool) {
	f.t.Helper()
	s, connections, source := f.slots()
	if s != streams || (parent && (connections != 1 || source != 1)) {
		f.t.Errorf("stream/connection/source slots=%d/%d/%d, want stream=%d parent=%t", s, connections, source, streams, parent)
	}
	if f.quicServer != nil && len(f.quicServer.streamSem) != streams {
		f.t.Errorf("native stream slots=%d, want %d", len(f.quicServer.streamSem), streams)
	}
}

func (f *relayOwnerFixture) halfClose() {
	f.t.Helper()
	writer, ok := f.conn.(interface{ CloseWrite() error })
	if !ok {
		f.t.Fatalf("%T lacks real CloseWrite", f.conn)
	}
	if err := writer.CloseWrite(); err != nil {
		f.t.Fatal(err)
	}
	f.require(f.originEOF, "actual target upload EOF")
	f.mu.Lock()
	destination := f.destination
	f.mu.Unlock()
	f.require(destination.halfClosed, "completed destination TCP CloseWrite")
	// The upload pump has observed EOF and completed its only remaining I/O;
	// no target response is emitted until independent releaseTarget.
	f.assertSlots(1, true)
}

func (f *relayOwnerFixture) stopOwner(action string) (<-chan struct{}, *error) {
	done := make(chan struct{})
	var err error
	f.register(done)
	go func() {
		defer close(done)
		if action == "close" {
			err = f.closeServer()
		} else {
			f.serveCancel()
			<-f.serveDone
			err = f.serveErr
		}
	}()
	return done, &err
}

func (f *relayOwnerFixture) assertStopped(done <-chan struct{}, result *error) bool {
	if !f.wait(done, "owner shutdown (target independently still held)", 500*time.Millisecond) {
		f.assertSlots(1, false)
		return false
	}
	if *result != nil && !errors.Is(*result, net.ErrClosed) {
		f.t.Errorf("owner shutdown: %v", *result)
	}
	f.assertSlots(0, false)
	if s, connections, source := f.slots(); s != 0 || connections != 0 || source != 0 {
		f.t.Errorf("completed owner retained slots %d/%d/%d", s, connections, source)
	}
	f.require(f.serveDone, "Serve after completed owner shutdown")
	return true
}

func (f *relayOwnerFixture) awaitRelayRelease() {
	f.t.Helper()
	timer, ticker := time.NewTimer(2*time.Second), time.NewTicker(10*time.Millisecond)
	defer timer.Stop()
	defer ticker.Stop()
	for {
		streams, _, _ := f.slots()
		if streams == 0 && (f.quicServer == nil || len(f.quicServer.streamSem) == 0) {
			f.assertSlots(0, false)
			return
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			f.t.Error("completed healthy relay retained its stream lease")
			return
		}
	}
}

func (f *relayOwnerFixture) cleanup() {
	f.releaseTarget()
	f.releaseClose()
	f.mu.Lock()
	f.closing = true
	origin, destination := f.origin, f.destination
	f.mu.Unlock()
	if origin != nil {
		_ = origin.Close()
	}
	if f.listener != nil {
		_ = f.listener.Close()
	}
	if destination != nil {
		_ = destination.TCPConn.Close()
	}
	if f.conn != nil {
		_ = f.conn.Close()
	}
	if f.closeClient != nil {
		_ = f.closeClient()
	}
	if f.serveCancel != nil {
		f.serveCancel()
	}
	if f.closeServer != nil {
		done := make(chan struct{})
		f.register(done)
		go func() { defer close(done); _ = f.closeServer() }()
	}
	f.mu.Lock()
	workers := append([]<-chan struct{}(nil), f.workers...)
	f.mu.Unlock()
	for _, done := range workers {
		f.wait(done, "independent cleanup worker join", 2*time.Second)
	}
	if f.closeServer != nil {
		f.assertSlots(0, false)
		if streams, connections, source := f.slots(); streams != 0 || connections != 0 || source != 0 {
			f.t.Errorf("joined cleanup retained stream/connection/source slots %d/%d/%d", streams, connections, source)
		}
	}
	if f.dials.Load() > 1 {
		f.t.Errorf("unexpected destination dial count %d", f.dials.Load())
	}
}

func TestRelayOwnerShutdownReleasesStalledDestination(t *testing.T) {
	for _, mode := range []string{"tls", "quic"} {
		for _, direction := range []string{"client_open", "client_halfclosed"} {
			for _, action := range []string{"close", "serve_cancel"} {
				t.Run(mode+"/"+direction+"/"+action, func(t *testing.T) {
					f := newRelayOwnerFixture(t, mode, "stalled", false)
					if direction == "client_halfclosed" {
						f.halfClose()
					}
					done, result := f.stopOwner(action)
					if f.assertStopped(done, result) {
						f.require(f.originEOF, "actual target peer EOF before fixture cleanup")
						f.mu.Lock()
						destination := f.destination
						f.mu.Unlock()
						f.require(destination.closed, "real destination FD closed before shutdown completion")
					}
					// Negative controls reach independent cleanup without a Fatal or
					// an origin deadline being counted as successful shutdown.
				})
			}
		}
	}
}

func TestRelayOwnerCancellationPreservesDelayedHalfCloseResponse(t *testing.T) {
	for _, mode := range []string{"tls", "quic"} {
		t.Run(mode, func(t *testing.T) {
			f := newRelayOwnerFixture(t, mode, "delayed", false)
			f.halfClose()
			f.mu.Lock()
			deadline := f.dialDeadline
			f.mu.Unlock()
			if deadline.IsZero() {
				t.Fatal("actual destination dial lacked its configured deadline")
			}
			timer := time.NewTimer(max(0, time.Until(deadline)))
			defer timer.Stop()
			<-timer.C
			if f.serveContext.Err() != nil {
				t.Fatal("normal half-close canceled relay owner")
			}
			f.assertSlots(1, true)
			f.releaseTarget()
			response, err := io.ReadAll(f.conn)
			if err != nil || !bytes.Equal(response, f.response) {
				t.Errorf("delayed full response: %d/%d bytes, %v", len(response), len(f.response), err)
			}
			f.require(f.originDone, "delayed actual target response worker")
			if f.originErr != nil {
				t.Errorf("delayed target: %v", f.originErr)
			}
			f.awaitRelayRelease()
			if f.serveContext.Err() != nil {
				t.Error("successful delayed relay canceled parent")
			}
		})
	}
}

func TestRelayOwnerShutdownJoinsDestinationCloseCallback(t *testing.T) {
	for _, mode := range []string{"tls", "quic"} {
		t.Run(mode, func(t *testing.T) {
			f := newRelayOwnerFixture(t, mode, "stalled", true)
			f.halfClose()
			done, result := f.stopOwner("close")
			f.mu.Lock()
			destination := f.destination
			f.mu.Unlock()
			if !f.wait(destination.closeEntered, "owner triggered real target Close", 500*time.Millisecond) {
				return
			}
			f.require(destination.closed, "real target FD closed before synthetic Close-return gate")
			if destination.closeErr != nil {
				t.Errorf("first actual target FD Close: %v", destination.closeErr)
			}
			timer := time.NewTimer(75 * time.Millisecond)
			select {
			case <-done:
				t.Error("owner shutdown returned before target Close callback completed")
			case <-timer.C:
			}
			timer.Stop()
			f.assertSlots(1, false)
			// This is a Close-completion gate, not a fake FD or a blocked-I/O
			// witness. It verifies that release is ordered after owned cleanup.
			f.releaseClose()
			f.assertStopped(done, result)
			if destination.closeCalls.Load() != 1 {
				t.Errorf("actual target Close calls=%d, want 1", destination.closeCalls.Load())
			}
		})
	}
}

func TestRelayOwnerCancellationPreservesDestinationHalfClose(t *testing.T) {
	for _, mode := range []string{"tls", "quic"} {
		t.Run(mode, func(t *testing.T) {
			f := newRelayOwnerFixture(t, mode, "response_first", false)
			response, err := io.ReadAll(f.conn)
			if err != nil || !bytes.Equal(response, f.response) {
				t.Fatalf("actual response FIN/full bytes: %d/%d, %v", len(response), len(f.response), err)
			}
			if f.serveContext.Err() != nil {
				t.Fatal("destination FIN canceled relay owner")
			}
			f.assertSlots(1, true)
			if _, err := io.Copy(f.conn, bytes.NewReader(f.tail)); err != nil {
				t.Errorf("upload after full response EOF: %v", err)
			}
			if err := f.conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Errorf("late upload FIN: %v", err)
			}
			f.require(f.originDone, "actual complete tail/EOF after destination FIN")
			if f.originErr != nil {
				t.Errorf("destination reverse half-close: %v", f.originErr)
			}
			f.require(f.originEOF, "target received complete tail and upload EOF")
			f.awaitRelayRelease()
			if f.serveContext.Err() != nil {
				t.Error("normal duplex completion canceled parent")
			}
		})
	}
}
