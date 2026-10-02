package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/transport"
)

// A destination connection result belongs to the request, not this reusable
// Dialer. Observe Close separately so a failure cannot reclaim shared state.
type destinationPreserveDialer struct {
	dial   transport.DialFunc
	calls  atomic.Int64
	closes atomic.Int64
}

func (d *destinationPreserveDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.calls.Add(1)
	return d.dial(ctx, network, address)
}

func (d *destinationPreserveDialer) Close() error {
	d.closes.Add(1)
	return nil
}

func TestDestinationDialNilResultFailsClosed(t *testing.T) {
	for _, mode := range []string{"quic", "tls", "h2", "h3"} {
		t.Run(mode, func(t *testing.T) {
			outbound := &destinationPreserveDialer{dial: func(context.Context, string, string) (net.Conn, error) {
				return nil, nil
			}}
			admission, err := NewStreamAdmission(1)
			if err != nil {
				t.Fatal(err)
			}
			client := newDestinationPreserveClient(t, mode, outbound, admission)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx, "tcp", "destination.invalid:443")
			assertDestinationPreserveRejection(t, mode, conn, err)
			awaitWebServerAdmission(t, admission, 0)
			if calls, closes := outbound.calls.Load(), outbound.closes.Load(); calls != 1 || closes != 0 {
				t.Fatalf("nil destination result calls/closes = %d/%d, want 1/0", calls, closes)
			}
		})
	}
}

func TestDestinationDialFailurePreservesWebSession(t *testing.T) {
	for _, mode := range []string{"h2", "h3"} {
		t.Run(mode, func(t *testing.T) {
			payload := bytes.Repeat([]byte("complete upload\x00\xff"), 512)
			reply := bytes.Repeat([]byte("reverse response after upload EOF\x00\xff"), 4096)
			target, targetResult := startDestinationPreserveTarget(t, payload, reply)
			var first atomic.Bool
			outbound := &destinationPreserveDialer{dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
				if err != nil {
					return conn, err
				}
				if first.CompareAndSwap(false, true) {
					return conn, errors.New("private destination failure after TCP dial")
				}
				return conn, nil
			}}
			admission, err := NewStreamAdmission(1)
			if err != nil {
				t.Fatal(err)
			}
			client := newDestinationPreserveClient(t, mode, outbound, admission)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx, "tcp", target)
			assertDestinationPreserveRejection(t, mode, conn, err)
			awaitWebServerAdmission(t, admission, 0)
			before := destinationPreserveWebSession(t, client)
			if got := outbound.closes.Load(); got != 0 {
				t.Fatalf("failed bootstrap closed the shared destination Dialer %d times", got)
			}
			conn, err = client.DialContext(ctx, "tcp", target)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(conn, bytes.NewReader(payload)); err != nil {
				t.Fatal(err)
			}
			writer, ok := conn.(interface{ CloseWrite() error })
			if !ok {
				t.Fatal("healthy stream lost its upload half-close capability")
			}
			if err := writer.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(conn)
			if err != nil || !bytes.Equal(got, reply) {
				t.Fatalf("healthy reverse reply = %d/%d bytes, error=%v", len(got), len(reply), err)
			}
			select {
			case err := <-targetResult:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("destination did not complete the failed-then-healthy requests")
			}
			_ = conn.Close()
			awaitWebServerAdmission(t, admission, 0)
			after := destinationPreserveWebSession(t, client)
			if before != after {
				t.Fatal("destination failure replaced the authenticated physical session or its short-ticket state")
			}
			if calls, closes := outbound.calls.Load(), outbound.closes.Load(); calls != 2 || closes != 0 {
				t.Fatalf("failed-then-healthy destination calls/closes = %d/%d, want 2/0", calls, closes)
			}
		})
	}
}

func assertDestinationPreserveRejection(t *testing.T, mode string, conn net.Conn, err error) {
	t.Helper()
	if conn != nil {
		_ = conn.Close()
		t.Fatalf("rejected destination returned a successful connection: %T", conn)
	}
	if mode == "quic" || mode == "tls" {
		var remoteErr *RemoteError
		if !errors.As(err, &remoteErr) || remoteErr.Status != protocol.StatusDialFailed || remoteErr.Message != "destination unavailable" {
			t.Fatalf("destination rejection = %v, want sanitized typed native failure", err)
		}
		return
	}
	var remoteErr *WebConnectError
	if !errors.As(err, &remoteErr) || remoteErr.Transport != mode || remoteErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("destination rejection = %v, want authenticated %s typed 502", err, mode)
	}
	if err.Error() != fmt.Sprintf("tunnel: %s cover CONNECT rejected with HTTP status 502", mode) {
		t.Fatalf("destination rejection exposed private details: %v", err)
	}
}

type destinationPreserveSession struct {
	physical any
	auth     *webSessionClientAuth
}

func destinationPreserveWebSession(t *testing.T, client transport.Dialer) destinationPreserveSession {
	t.Helper()
	switch client := client.(type) {
	case *WebH2Client:
		client.mu.Lock()
		defer client.mu.Unlock()
		session := client.current
		if session == nil || session.authState != webH2ClientAuthReady || session.auth == nil {
			t.Fatal("authenticated H2 destination failure lost its ready session")
		}
		return destinationPreserveSession{physical: session, auth: session.auth}
	case *WebH3Client:
		client.mu.Lock()
		defer client.mu.Unlock()
		session := client.conns[client.conn]
		if session == nil || session.authState != webH3ClientAuthReady || session.auth == nil {
			t.Fatal("authenticated H3 destination failure lost its ready session")
		}
		return destinationPreserveSession{physical: session, auth: session.auth}
	default:
		t.Fatalf("unsupported web client %T", client)
		return destinationPreserveSession{}
	}
}

// All transport and authentication budgets intentionally retain defaults.
func newDestinationPreserveClient(t *testing.T, mode string, outbound transport.Dialer, admission *StreamAdmission) transport.Dialer {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	var server destinationIntegrationServer
	var err error
	switch mode {
	case "quic":
		server, err = ListenQUIC(QUICServerConfig{Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS, Dialer: outbound, StreamAdmission: admission})
	case "tls":
		server, err = ListenTLS(TLSServerConfig{Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS, Dialer: outbound, StreamAdmission: admission})
	case "h2":
		server, err = ListenWebH2(WebH2ServerConfig{Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS, Dialer: outbound, StreamAdmission: admission, Cover: http.NotFoundHandler()})
	case "h3":
		server, err = ListenWebH3(WebH3ServerConfig{Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS, Dialer: outbound, StreamAdmission: admission, Cover: http.NotFoundHandler()})
	default:
		t.Fatalf("unknown transport %q", mode)
	}
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("%s server cleanup: %v", mode, err)
			}
		case <-time.After(time.Second):
			t.Errorf("%s server cleanup did not join", mode)
		}
	})
	var client interface {
		transport.Dialer
		io.Closer
	}
	switch mode {
	case "quic":
		client, err = NewClient(ClientConfig{ServerAddress: server.Addr().String(), Token: testToken, TLSConfig: clientTLS})
	case "tls":
		client, err = NewTLSClient(TLSClientConfig{ServerAddress: server.Addr().String(), Token: testToken, TLSConfig: clientTLS})
	case "h2":
		client, err = NewWebH2Client(WebH2ClientConfig{ServerAddress: server.Addr().String(), Token: testToken, TLSConfig: clientTLS})
	case "h3":
		client, err = NewWebH3Client(WebH3ClientConfig{ServerAddress: server.Addr().String(), Token: testToken, TLSConfig: clientTLS})
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// One real TCP target first observes reclamation of the failed result, then
// requires upload EOF before sending a complete binary reverse response.
func startDestinationPreserveTarget(t *testing.T, payload, reply []byte) (string, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		result <- func() error {
			for attempt := 0; attempt < 2; attempt++ {
				conn, err := listener.Accept()
				if err != nil {
					return err
				}
				stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
				err = func() error {
					defer conn.Close()
					if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
						return err
					}
					got, err := io.ReadAll(conn)
					if err != nil {
						return fmt.Errorf("destination attempt %d read: %w", attempt, err)
					}
					if attempt == 0 {
						if len(got) != 0 {
							return fmt.Errorf("failed destination received %d upload bytes", len(got))
						}
						return nil
					}
					if !bytes.Equal(got, payload) {
						return fmt.Errorf("healthy destination upload = %d/%d bytes", len(got), len(payload))
					}
					if _, err := io.Copy(conn, bytes.NewReader(reply)); err != nil {
						return err
					}
					return conn.(*net.TCPConn).CloseWrite()
				}()
				stop()
				if err != nil {
					return err
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
		case <-time.After(time.Second):
			t.Error("failed-then-healthy destination cleanup did not join")
		}
	})
	return listener.Addr().String(), result
}
