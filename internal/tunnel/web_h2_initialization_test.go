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
	for _, profile := range []FingerprintProfile{FingerprintNative, FingerprintChrome133} {
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
					t.Cleanup(func() { _ = raw.Close(); _ = peer.Close(); _ = client.Close() })
					serverDone := make(chan error, 1)
					go func() { serverDone <- tls.Server(peer, serverTLS).HandshakeContext(t.Context()) }()
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
					if err := <-serverDone; err != nil {
						t.Fatalf("TLS handshake: %v", err)
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
						want = context.Canceled
						if err := client.Close(); err != nil {
							t.Fatal(err)
						}
					case "initialization_deadline":
						want = context.DeadlineExceeded
					}
					select {
					case err := <-dialDone:
						if !errors.Is(err, want) {
							t.Fatalf("initialization error=%v, want cause %v", err, want)
						}
					case <-time.After(time.Second):
						_ = raw.Close()
						<-dialDone
						t.Fatal("post-TLS initialization ignored cancellation")
					}
					select {
					case <-wire.closed:
					default:
						t.Fatal("canceled initializer left its raw connection open")
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
	for _, profile := range []FingerprintProfile{FingerprintNative, FingerprintChrome133} {
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
	for _, profile := range []FingerprintProfile{FingerprintNative, FingerprintChrome133} {
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
					t.Cleanup(func() { _ = raw.Close(); _ = peer.Close(); _ = client.Close() })
					// Close after the first H2 write fully reaches the peer, but
					// before its initializer can publish a session. Either the
					// watcher or the closed-client registration gate must win.
					wire.onInitialized = func() { _ = client.Close() }
					serverDone := make(chan struct{})
					go func() {
						defer close(serverDone)
						server := tls.Server(peer, serverTLS)
						if server.HandshakeContext(t.Context()) == nil {
							var data [1]byte
							_, _ = server.Read(data[:])
						}
					}()
					dialDone := make(chan error, 1)
					go func() {
						conn, err := client.DialContext(context.Background(), "tcp", "target.invalid:443")
						if conn != nil {
							_ = conn.Close()
						}
						dialDone <- err
					}()
					select {
					case err := <-dialDone:
						if err == nil {
							t.Fatal("closed client published a cold initialized session")
						}
					case <-time.After(2 * time.Second):
						_ = raw.Close()
						<-dialDone
						t.Fatal("close during initialization handoff did not finish")
					}
					<-serverDone
					select {
					case <-wire.closed:
					default:
						t.Fatal("closed initializer left its raw connection open")
					}
					client.mu.Lock()
					registered, current, closed := len(client.sessions), client.current, client.closed
					client.mu.Unlock()
					if !closed {
						t.Fatal("test did not reach Close after the initial H2 write")
					}
					if registered != 0 || current != nil {
						t.Fatal("closed client retained a session after initialization handoff")
					}
				})
			}
		})
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
