package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

const webH2IntegrationWriteTimeout = 300 * time.Millisecond

func TestWebH2WriteByteTimeoutPreservesHealthyTLS(t *testing.T) {
	for _, profile := range []FingerprintProfile{FingerprintNative, FingerprintChrome133} {
		t.Run(string(profile), func(t *testing.T) {
			client := newWebH2WriteTimeoutIntegrationClient(t, profile)
			target := startWebTCPEcho(t)
			sibling := dialWebH2WriteTimeoutStream(t, client, target)
			assertWebH2WriteTimeoutEcho(t, sibling)
			session := verifiedWebH2WriteTimeoutSession(t, client)
			// This option is a blocked-write timeout, not an idle timeout. No
			// TLS writes are pending during this deliberately longer interval.
			time.Sleep(2*webH2IntegrationWriteTimeout + 50*time.Millisecond)
			reused := dialWebH2WriteTimeoutStream(t, client, target)
			assertWebH2WriteTimeoutEcho(t, reused)
			assertWebH2DeadlineSessionUnchanged(t, client, session)

			address, payload, started, result := startWebH2WriteTimeoutReply(t)
			conn := dialWebH2WriteTimeoutStream(t, client, address)
			if _, err := io.WriteString(conn, "complete upload"); err != nil {
				t.Fatal(err)
			}
			if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("half-closed upload did not start its reply")
			}
			assertWebH2WriteTimeoutEcho(t, sibling)
			// The twelve spaced response writes take longer than the physical
			// write timeout; upload FIN must not truncate this download.
			assertWebEOFBody(t, conn, payload)
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			assertWebH2WriteTimeoutEcho(t, sibling)
			assertWebH2DeadlineSessionUnchanged(t, client, session)
		})
	}
}

func TestWebH2WriteByteTimeoutReachesTLSRawConnection(t *testing.T) {
	for _, profile := range []FingerprintProfile{FingerprintNative, FingerprintChrome133} {
		t.Run(string(profile), func(t *testing.T) {
			client := newWebH2WriteTimeoutIntegrationClient(t, profile)
			target := startWebTCPEcho(t)
			conn := dialWebH2WriteTimeoutStream(t, client, target)
			sibling := dialWebH2WriteTimeoutStream(t, client, target)
			assertWebH2WriteTimeoutEcho(t, conn)
			assertWebH2WriteTimeoutEcho(t, sibling)
			session := verifiedWebH2WriteTimeoutSession(t, client)
			wire := session.raw.(*webH2WriteTimeoutWire)
			wire.bridge.paused.Store(true)

			writeDone, siblingDone := make(chan error, 1), make(chan error, 1)
			// Exceed x/net's 512 KiB request scratch buffer: accepting a
			// smaller caller Write is not proof its bytes reached the wire.
			go func() { _, err := conn.Write(bytes.Repeat([]byte("upload"), 128<<10)); writeDone <- err }()
			go func() { var data [1]byte; _, err := sibling.Read(data[:]); siblingDone <- err }()
			// Even a failed assertion must release and join our I/O workers.
			t.Cleanup(func() {
				_ = client.Close()
				for _, done := range []<-chan error{writeDone, siblingDone} {
					select {
					case <-done:
					case <-time.After(2 * time.Second):
						t.Error("TLS stall worker did not stop")
					}
				}
			})
			select {
			case <-wire.bridge.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("encrypted client writes did not reach the paused byte bridge")
			}
			select {
			case observed := <-wire.timedOut:
				if !errors.Is(observed.err, os.ErrDeadlineExceeded) || observed.deadline.IsZero() {
					t.Fatalf("underlying write error/deadline = %v/%v", observed.err, observed.deadline)
				}
				if observed.budget <= 0 || observed.budget > webH2IntegrationWriteTimeout+100*time.Millisecond {
					t.Fatalf("TLS forwarded write deadline budget %v, want at most %v", observed.budget, webH2IntegrationWriteTimeout)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("real blocked raw Write did not return its deadline error")
			}
			// This is a physical TLS failure, so all streams on that session
			// fail. Unlike per-stream deadlines, it cannot preserve siblings.
			for _, done := range []chan error{writeDone, siblingDone} {
				select {
				case err := <-done:
					done <- err // Leave a completion receipt for cleanup as well.
					if err == nil {
						t.Fatal("stalled physical connection left stream I/O successful")
					}
				case <-time.After(2 * time.Second):
					t.Fatal("physical write timeout did not release sibling/upload")
				}
			}
			if session.h2.CanTakeNewRequest() {
				t.Fatal("timed-out physical session remained reusable")
			}
			fresh := dialWebH2WriteTimeoutStream(t, client, target)
			assertWebH2WriteTimeoutEcho(t, fresh)
			if verifiedWebH2WriteTimeoutSession(t, client) == session {
				t.Fatal("recovery reused the failed TLS connection")
			}
		})
	}
}

func newWebH2WriteTimeoutIntegrationClient(t *testing.T, profile FingerprintProfile) *WebH2Client {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	server := startWebH2TestServer(t, WebH2ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
		Dialer: &net.Dialer{}, Cover: http.NotFoundHandler(),
	})
	client, err := NewWebH2Client(WebH2ClientConfig{
		ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
		FingerprintProfile: profile, WriteByteTimeout: webH2IntegrationWriteTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var bridges []*webH2WriteTimeoutBridge
	client.dialer = transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		tcp, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		raw, peer := net.Pipe()
		bridge := &webH2WriteTimeoutBridge{raw: raw, peer: peer, tcp: tcp, entered: make(chan struct{}), closed: make(chan struct{}), done: make(chan struct{})}
		wire := &webH2WriteTimeoutWire{Conn: raw, bridge: bridge, timedOut: make(chan webH2WriteTimeoutObservation, 1)}
		mu.Lock()
		bridges = append(bridges, bridge)
		mu.Unlock()
		var copies sync.WaitGroup
		copies.Add(2)
		go func() { defer copies.Done(); defer bridge.close(); _, _ = io.Copy(tcp, bridge) }()
		go func() { defer copies.Done(); defer bridge.close(); _, _ = io.Copy(peer, tcp) }()
		go func() { copies.Wait(); close(bridge.done) }()
		return wire, nil
	})
	t.Cleanup(func() {
		_ = client.Close()
		mu.Lock()
		all := append([]*webH2WriteTimeoutBridge(nil), bridges...)
		mu.Unlock()
		for _, bridge := range all {
			bridge.close()
			select {
			case <-bridge.done:
			case <-time.After(2 * time.Second):
				t.Error("TLS byte bridge did not stop")
			}
		}
	})
	return client
}

func dialWebH2WriteTimeoutStream(t *testing.T, client *WebH2Client, target string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func verifiedWebH2WriteTimeoutSession(t *testing.T, client *WebH2Client) *webH2ClientSession {
	t.Helper()
	client.mu.Lock()
	session := client.current
	client.mu.Unlock()
	if session == nil {
		t.Fatal("missing authenticated TLS session")
	}
	state := session.conn.ConnectionState()
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != webH2ALPN || len(state.VerifiedChains) == 0 {
		t.Fatalf("expected verified TLS 1.3 and h2, got version=%x ALPN=%q chains=%d", state.Version, state.NegotiatedProtocol, len(state.VerifiedChains))
	}
	return session
}

func assertWebH2WriteTimeoutEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	assertWebSessionSiblingEcho(t, conn)
	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func startWebH2WriteTimeoutReply(t *testing.T) (string, []byte, <-chan struct{}, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	started, done, result := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	payload := bytes.Repeat([]byte("response after upload FIN\n"), 12)
	go func() {
		defer close(done)
		result <- func() error {
			conn, err := listener.Accept()
			if err != nil {
				return err
			}
			defer conn.Close()
			stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
			defer stop()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			request, err := io.ReadAll(conn)
			if err != nil || string(request) != "complete upload" {
				return fmt.Errorf("half-closed request=%q error=%v", request, err)
			}
			ticker := time.NewTicker(50 * time.Millisecond)
			defer ticker.Stop()
			chunk := len(payload) / 12
			for i := range 12 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-ticker.C:
				}
				if _, err := conn.Write(payload[i*chunk : (i+1)*chunk]); err != nil {
					return err
				}
				if i == 0 {
					close(started)
				}
			}
			return nil
		}()
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("delayed half-close target did not stop")
		}
	})
	return listener.Addr().String(), payload, started, result
}

// The bridge forwards actual TLS bytes to the production loopback H2 server.
// Pausing its read gives net.Pipe a deterministic real raw-write stall without
// fabricating TLS state, I/O errors, or timeout notifications. This is not a
// kernel TCP congestion or real-network performance experiment.
type webH2WriteTimeoutBridge struct {
	raw, peer, tcp net.Conn
	paused         atomic.Bool
	entered        chan struct{}
	closed         chan struct{}
	done           chan struct{}
	enterOnce      sync.Once
	closeOnce      sync.Once
}

func (b *webH2WriteTimeoutBridge) Read(data []byte) (int, error) {
	if b.paused.Load() {
		b.enterOnce.Do(func() { close(b.entered) })
		<-b.closed
		return 0, net.ErrClosed
	}
	return b.peer.Read(data)
}

func (b *webH2WriteTimeoutBridge) close() {
	b.closeOnce.Do(func() {
		close(b.closed)
		_ = b.raw.Close()
		_ = b.peer.Close()
		_ = b.tcp.Close()
	})
}

type webH2WriteTimeoutObservation struct {
	err      error
	deadline time.Time
	budget   time.Duration
}

type webH2WriteTimeoutWire struct {
	net.Conn
	bridge   *webH2WriteTimeoutBridge
	mu       sync.Mutex
	deadline time.Time
	budget   time.Duration
	timedOut chan webH2WriteTimeoutObservation
}

func (w *webH2WriteTimeoutWire) SetWriteDeadline(deadline time.Time) error {
	w.mu.Lock()
	w.deadline, w.budget = deadline, time.Until(deadline)
	w.mu.Unlock()
	return w.Conn.SetWriteDeadline(deadline)
}

func (w *webH2WriteTimeoutWire) Write(data []byte) (int, error) {
	n, err := w.Conn.Write(data)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		w.mu.Lock()
		observed := webH2WriteTimeoutObservation{err: err, deadline: w.deadline, budget: w.budget}
		w.mu.Unlock()
		select {
		case w.timedOut <- observed:
		default:
		}
	}
	return n, err
}

func (w *webH2WriteTimeoutWire) Close() error {
	w.bridge.close()
	return nil
}
