package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

func TestWebH2PostTLSInitializationHonorsCancellation(t *testing.T) {
	for _, profile := range []FingerprintProfile{FingerprintNative, FingerprintChrome133, FingerprintChrome155} {
		t.Run(string(profile), func(t *testing.T) {
			for _, mode := range []string{"caller_cancel", "caller_deadline", "client_close", "initialization_deadline"} {
				t.Run(mode, func(t *testing.T) {
					serverTLS, clientTLS := testTLSConfigs(t)
					serverTLS.NextProtos = []string{webH2ALPN}
					raw, peer := net.Pipe()
					wire := &webH2InitializationWire{Conn: raw, initializing: make(chan struct{}), closed: make(chan struct{})}
					clientTLS.VerifyPeerCertificate = func(_ [][]byte, _ [][]*x509.Certificate) error {
						wire.verified.Store(true)
						return nil
					}
					handshakeTimeout := 2 * time.Second
					if mode == "initialization_deadline" {
						handshakeTimeout = 250 * time.Millisecond
					}
					client, err := NewWebH2Client(WebH2ClientConfig{
						ServerAddress: "127.0.0.1:443", Token: testToken, TLSConfig: clientTLS,
						FingerprintProfile: profile, HandshakeTimeout: handshakeTimeout,
					})
					if err != nil {
						t.Fatal(err)
					}
					client.dialer = transport.DialFunc(func(context.Context, string, string) (net.Conn, error) { return wire, nil })
					serverCtx, cancelServer := context.WithTimeout(context.Background(), 3*time.Second)
					_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
					serverDone := make(chan error, 1)
					serverJoined := make(chan struct{})
					dialJoined := make(chan struct{})
					closeDone := make(chan error, 1)
					closeJoined := make(chan struct{})
					var closeOnce sync.Once
					startClose := func() {
						closeOnce.Do(func() {
							go func() {
								defer close(closeJoined)
								closeDone <- client.Close()
							}()
						})
					}
					t.Cleanup(func() {
						cancelServer()
						_ = raw.Close()
						_ = peer.Close()
						startClose()
						waitWebH2InitializationWorker(t, serverJoined, "TLS peer")
						waitWebH2InitializationWorker(t, dialJoined, "caller dial")
						waitWebH2InitializationWorker(t, closeJoined, "client Close")
					})
					go func() {
						defer close(serverJoined)
						serverDone <- tls.Server(peer, serverTLS).HandshakeContext(serverCtx)
					}()
					ctx, cancel := context.WithCancelCause(context.Background())
					defer cancel(context.Canceled)
					var dialCtx context.Context = ctx
					if mode == "caller_deadline" {
						var cancelDeadline context.CancelFunc
						dialCtx, cancelDeadline = context.WithTimeout(ctx, 250*time.Millisecond)
						defer cancelDeadline()
					}
					dialDone := make(chan error, 1)
					go func() {
						defer close(dialJoined)
						if mode == "initialization_deadline" {
							// Avoid the public CONNECT wait timer winning the same
							// budget first: exercise the physical initializer itself.
							session, err := client.openSession(dialCtx)
							if session != nil {
								_ = closeWebH2Session(session)
							}
							dialDone <- err
							return
						}
						conn, err := client.DialContext(dialCtx, "tcp", "target.invalid:443")
						if conn != nil {
							_ = conn.Close()
						}
						dialDone <- err
					}()
					select {
					case <-wire.initializing:
					case err := <-dialDone:
						t.Fatalf("dial finished before the post-TLS write: %v", err)
					case <-time.After(time.Second):
						t.Fatal("dial did not reach the post-TLS initialization write")
					}
					select {
					case err := <-serverDone:
						if err != nil {
							t.Fatalf("TLS handshake: %v", err)
						}
					case <-time.After(time.Second):
						t.Fatal("TLS peer did not report handshake completion")
					}
					client.mu.Lock()
					registered := len(client.sessions)
					client.mu.Unlock()
					if registered != 0 {
						t.Fatalf("initializing sessions already registered: %d", registered)
					}
					var want error
					switch mode {
					case "caller_cancel":
						want = errors.New("caller stopped H2 initialization")
						cancel(want)
					case "caller_deadline":
						want = context.DeadlineExceeded
						<-dialCtx.Done()
					case "client_close":
						want = net.ErrClosed
						startClose()
					case "initialization_deadline":
						want = context.DeadlineExceeded
					}
					select {
					case err := <-dialDone:
						if !errors.Is(err, want) {
							t.Fatalf("initialization error=%v, want cause %v", err, want)
						}
					case <-time.After(time.Second):
						t.Fatal("post-TLS initialization ignored cancellation")
					}
					// Caller cancellation ends only its wait. The physical setup
					// remains client-owned, so explicitly Close and join it before
					// checking raw-socket and session cleanup in every mode.
					startClose()
					select {
					case err := <-closeDone:
						if err != nil {
							t.Fatalf("client Close: %v", err)
						}
					case <-time.After(2 * time.Second):
						t.Fatal("client Close did not join physical initialization")
					}
					select {
					case <-wire.closed:
					default:
						t.Fatal("joined initialization cleanup left its raw connection open")
					}
					client.mu.Lock()
					registered = len(client.sessions)
					client.mu.Unlock()
					if registered != 0 || len(client.dialGate) != 0 {
						t.Fatalf("canceled initializer left sessions/gate=%d/%d", registered, len(client.dialGate))
					}
				})
			}
		})
	}
}

func TestWebH2InitializationWatcherDetachesAfterSuccess(t *testing.T) {
	for _, profile := range []FingerprintProfile{FingerprintNative, FingerprintChrome133, FingerprintChrome155} {
		t.Run(string(profile), func(t *testing.T) {
			serverTLS, clientTLS := testTLSConfigs(t)
			server := startWebH2TestServer(t, WebH2ServerConfig{
				Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
				Cover: http.NotFoundHandler(), Dialer: &net.Dialer{},
			})
			client, err := NewWebH2Client(WebH2ClientConfig{
				ServerAddress: server.Addr().String(), Token: testToken, TLSConfig: clientTLS,
				FingerprintProfile: profile, HandshakeTimeout: 250 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			dialCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			conn, err := client.DialContext(dialCtx, "tcp", startWebTCPEcho(t))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			cancel()
			// Both caller cancellation and the elapsed initialization timeout
			// must leave ownership with the returned stream and warm session.
			time.Sleep(300 * time.Millisecond)
			assertWebSessionSiblingEcho(t, conn)
		})
	}
}

func TestWebH2CloseAtInitializationHandoff(t *testing.T) {
	for _, profile := range []FingerprintProfile{FingerprintNative, FingerprintChrome133, FingerprintChrome155} {
		t.Run(string(profile), func(t *testing.T) {
			for range 10 {
				t.Run("close", func(t *testing.T) {
					serverTLS, clientTLS := testTLSConfigs(t)
					serverTLS.NextProtos = []string{webH2ALPN}
					raw, peer := net.Pipe()
					wire := &webH2InitializationWire{Conn: raw, initializing: make(chan struct{}), closed: make(chan struct{})}
					clientTLS.VerifyPeerCertificate = func(_ [][]byte, _ [][]*x509.Certificate) error {
						wire.verified.Store(true)
						return nil
					}
					client, err := NewWebH2Client(WebH2ClientConfig{
						ServerAddress: "127.0.0.1:443", Token: testToken, TLSConfig: clientTLS,
						FingerprintProfile: profile, HandshakeTimeout: time.Second,
					})
					if err != nil {
						t.Fatal(err)
					}
					client.dialer = transport.DialFunc(func(context.Context, string, string) (net.Conn, error) { return wire, nil })
					// Close after the first H2 write fully reaches the peer, but
					// before Write returns to the initializer. Close must run on
					// an independent worker: calling it inside Write would join
					// the initializer from that same initializer and deadlock.
					handoff := make(chan struct{})
					releaseHandoff := make(chan struct{})
					var releaseOnce sync.Once
					release := func() { releaseOnce.Do(func() { close(releaseHandoff) }) }
					wire.onInitialized = func() {
						close(handoff)
						<-releaseHandoff
					}
					serverCtx, cancelServer := context.WithTimeout(context.Background(), 3*time.Second)
					_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
					serverDone := make(chan error, 1)
					serverJoined := make(chan struct{})
					dialJoined := make(chan struct{})
					closeDone := make(chan error, 1)
					closeJoined := make(chan struct{})
					var closeOnce sync.Once
					startClose := func() {
						closeOnce.Do(func() {
							go func() {
								defer close(closeJoined)
								closeDone <- client.Close()
							}()
						})
					}
					t.Cleanup(func() {
						// Independent socket closure and gate release also work on
						// Fatal paths; cleanup never depends on a passing oracle.
						release()
						cancelServer()
						_ = raw.Close()
						_ = peer.Close()
						startClose()
						waitWebH2InitializationWorker(t, serverJoined, "handoff TLS peer")
						waitWebH2InitializationWorker(t, dialJoined, "handoff caller dial")
						waitWebH2InitializationWorker(t, closeJoined, "handoff client Close")
					})
					go func() {
						defer close(serverJoined)
						server := tls.Server(peer, serverTLS)
						err := server.HandshakeContext(serverCtx)
						if err == nil {
							var data [1]byte
							_, err = server.Read(data[:])
						}
						serverDone <- err
					}()
					dialDone := make(chan error, 1)
					go func() {
						defer close(dialJoined)
						conn, err := client.DialContext(context.Background(), "tcp", "target.invalid:443")
						if conn != nil {
							_ = conn.Close()
						}
						dialDone <- err
					}()
					select {
					case <-handoff:
					case err := <-dialDone:
						t.Fatalf("dial finished before the post-wire handoff: %v", err)
					case <-time.After(2 * time.Second):
						t.Fatal("initializer did not reach the post-wire handoff")
					}
					select {
					case err := <-serverDone:
						if err != nil {
							t.Fatalf("TLS peer did not receive the first H2 bytes: %v", err)
						}
					case <-time.After(time.Second):
						t.Fatal("handoff TLS peer did not report")
					}
					startClose()
					select {
					case <-wire.closed:
					case <-time.After(time.Second):
						t.Fatal("Close did not cancel the gated initializer's raw socket")
					}
					select {
					case err := <-closeDone:
						t.Fatalf("Close returned before initializer handoff was released: %v", err)
					default:
					}
					client.mu.Lock()
					closed := client.closed
					client.mu.Unlock()
					if !closed {
						t.Fatal("test did not reach Close after the initial H2 write")
					}
					release()
					select {
					case err := <-closeDone:
						if err != nil {
							t.Fatalf("joined client Close: %v", err)
						}
					case <-time.After(2 * time.Second):
						t.Fatal("Close did not join the released initializer")
					}
					select {
					case err := <-dialDone:
						if !errors.Is(err, net.ErrClosed) {
							t.Fatalf("closed initializer dial error=%v, want net.ErrClosed", err)
						}
					case <-time.After(2 * time.Second):
						t.Fatal("caller dial did not finish after initialization handoff Close")
					}
					select {
					case <-wire.closed:
					default:
						t.Fatal("closed initializer left its raw connection open")
					}
					client.mu.Lock()
					registered, current := len(client.sessions), client.current
					client.mu.Unlock()
					if registered != 0 || current != nil {
						t.Fatal("closed client retained a session after initialization handoff")
					}
				})
			}
		})
	}
}

func waitWebH2InitializationWorker(t *testing.T, done <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Errorf("%s worker did not join after independent cleanup", name)
	}
}

// The test peer performs a normal verifying TLS 1.3 handshake, then stops
// reading. With no client certificate, the first encrypted client flight after
// certificate verification contains Finished. Its next write is H2 setup.
// Signaling that write lets tests cancel precisely after TLS, without sleeps
// or runtime-stack inspection to locate the initialization boundary.
type webH2InitializationWire struct {
	net.Conn
	verified      atomic.Bool
	finished      atomic.Bool
	initializing  chan struct{}
	closed        chan struct{}
	startOnce     sync.Once
	closeOnce     sync.Once
	handoffOnce   sync.Once
	onInitialized func()
}

func (c *webH2InitializationWire) Write(p []byte) (int, error) {
	initialWrite := c.finished.Load()
	if initialWrite {
		c.startOnce.Do(func() { close(c.initializing) })
	}
	n, err := c.Conn.Write(p)
	if err == nil && c.verified.Load() && containsH2TestTLSApplicationRecord(p[:n]) {
		c.finished.Store(true)
	}
	if initialWrite && err == nil && c.onInitialized != nil {
		c.handoffOnce.Do(c.onInitialized)
	}
	return n, err
}

func (c *webH2InitializationWire) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() { close(c.closed) })
	return err
}

func containsH2TestTLSApplicationRecord(data []byte) bool {
	for len(data) >= 5 {
		size := 5 + int(binary.BigEndian.Uint16(data[3:5]))
		if size > len(data) {
			return false
		}
		if data[0] == 23 { // TLS record type application_data (encrypted TLS 1.3).
			return true
		}
		data = data[size:]
	}
	return false
}
