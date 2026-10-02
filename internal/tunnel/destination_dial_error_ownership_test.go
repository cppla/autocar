package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/transport"
)

type destinationDialOwnershipConn struct {
	*net.TCPConn
	closeErr error
	closes   atomic.Int64
}

func (c *destinationDialOwnershipConn) Close() error {
	c.closes.Add(1)
	_ = c.TCPConn.Close()
	return c.closeErr
}

// Only the configured destination Dialer returns (owned connection, error).
// The public transport, authentication, failure response and handler lifetimes
// are real. Reclamation is checked before client/server or endpoint cleanup.
func TestDestinationDialErrorOwnershipAuthenticatedTransports(t *testing.T) {
	for _, mode := range []string{"quic", "tls", "h2", "h3"} {
		t.Run(mode, func(t *testing.T) {
			dialErr := errors.New("private destination ownership dial failure")
			closeErr := errors.New("private destination ownership close failure")
			owned, peer := destinationDialOwnershipPair(t, closeErr)
			var dialCalls atomic.Int64
			type dialRequest struct{ network, address string }
			request := make(chan dialRequest, 1)
			outbound := transport.DialFunc(func(_ context.Context, network, address string) (net.Conn, error) {
				dialCalls.Add(1)
				select {
				case request <- dialRequest{network, address}:
				default:
				}
				return owned, dialErr
			})
			client, awaitHandler, verified := destinationDialOwnershipClient(t, mode, outbound)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx, "tcp", "destination.invalid:443")
			if conn != nil {
				_ = conn.Close()
				t.Fatalf("rejected destination returned client connection %T", conn)
			}
			if err == nil {
				t.Fatal("destination failure unexpectedly succeeded")
			}
			if mode == "quic" || mode == "tls" {
				var remoteErr *RemoteError
				if !errors.As(err, &remoteErr) || remoteErr.Status != protocol.StatusDialFailed || remoteErr.Message != "destination unavailable" {
					t.Fatalf("native rejection = %T %v, want sanitized typed destination failure", err, err)
				}
			} else {
				var remoteErr *WebConnectError
				if !errors.As(err, &remoteErr) || remoteErr.Transport != mode || remoteErr.StatusCode != http.StatusBadGateway {
					t.Fatalf("web rejection = %T %v, want authenticated %s typed 502", err, err, mode)
				}
				if !verified() {
					t.Fatal("destination rejection did not establish a verified web session")
				}
			}
			for _, private := range []error{dialErr, closeErr} {
				if errors.Is(err, private) || strings.Contains(err.Error(), private.Error()) {
					t.Errorf("client error exposes private destination detail: %v", err)
				}
			}
			awaitHandler()
			if got := dialCalls.Load(); got != 1 {
				t.Errorf("destination dial calls = %d, want one", got)
			}
			select {
			case got := <-request:
				if got.network != "tcp" || got.address != "destination.invalid:443" {
					t.Errorf("destination request = %+v, want tcp/destination.invalid:443", got)
				}
			default:
				t.Error("destination dial did not record its request")
			}
			if got := owned.closes.Load(); got != 1 {
				t.Errorf("failed destination Close calls = %d, want exactly one before cleanup", got)
			}
			if err := peer.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			var b [1]byte
			n, readErr := peer.Read(b[:])
			if n != 0 || !errors.Is(readErr, io.EOF) {
				t.Errorf("peer after handler return = %d/%v, want EOF before cleanup", n, readErr)
			}
			t.Logf("%s: typed rejection=%T; handler complete and admission released; destination Close=%d; peer Read=%d/%v before cleanup", mode, err, owned.closes.Load(), n, readErr)

			// This independent raw-endpoint positive control makes a baseline
			// failure recoverable without manufacturing a counted frontend Close.
			closes := owned.closes.Load()
			_ = owned.TCPConn.Close()
			if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			n, readErr = peer.Read(b[:])
			if n != 0 || !errors.Is(readErr, io.EOF) || owned.closes.Load() != closes {
				t.Fatalf("raw endpoint cleanup control = %d/%v, Close count=%d want=%d", n, readErr, owned.closes.Load(), closes)
			}
			t.Log("independent raw endpoint cleanup: real peer EOF, production Close count unchanged")
		})
	}
}

func destinationDialOwnershipPair(t *testing.T, closeErr error) (*destinationDialOwnershipConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	type acceptedResult struct {
		conn *net.TCPConn
		err  error
	}
	accepted := make(chan acceptedResult, 1)
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		conn, err := listener.AcceptTCP()
		accepted <- acceptedResult{conn, err}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		destinationDialOwnershipWait(t, acceptDone, "destination accept cleanup")
		// Also reclaim a connection accepted just as setup aborted.
		select {
		case result := <-accepted:
			if result.conn != nil {
				_ = result.conn.Close()
			}
		default:
		}
	})
	upstream, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	// Cleanup bypasses the observed wrapper so its count belongs to production.
	t.Cleanup(func() { _ = upstream.Close() })
	var peer *net.TCPConn
	select {
	case result := <-accepted:
		if result.err != nil {
			t.Fatal(result.err)
		}
		peer = result.conn
	case <-time.After(time.Second):
		t.Fatal("destination accept did not complete")
	}
	t.Cleanup(func() { _ = peer.Close() })
	_ = listener.Close()
	destinationDialOwnershipWait(t, acceptDone, "destination accept")
	return &destinationDialOwnershipConn{TCPConn: upstream, closeErr: closeErr}, peer
}

type destinationDialOwnershipServer interface {
	Addr() net.Addr
	Serve(context.Context) error
	Close() error
}

type destinationDialOwnershipDialer interface {
	transport.Dialer
	io.Closer
}

func destinationDialOwnershipClient(t *testing.T, mode string, outbound transport.Dialer) (destinationDialOwnershipDialer, func(), func() bool) {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	admission, err := NewStreamAdmission(1)
	if err != nil {
		t.Fatal(err)
	}
	var server destinationDialOwnershipServer
	var client destinationDialOwnershipDialer
	var core *serverCore
	var awaitHandler func()
	verified := func() bool { return true }
	var covers atomic.Int64
	cover := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		covers.Add(1)
		http.NotFound(w, r)
	})
	webCompletion := func(handler http.Handler) (http.Handler, func()) {
		done := make(chan struct{})
		var once sync.Once
		wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer once.Do(func() { close(done) })
			handler.ServeHTTP(w, r)
		})
		return wrapped, func() {
			destinationDialOwnershipWait(t, done, "authenticated web handler")
			destinationDialOwnershipAwait(t, func() bool { return len(admission.sem) == 0 }, "web stream admission release")
			if got := covers.Load(); got != 0 {
				t.Errorf("destination failure entered cover handler %d times", got)
			}
		}
	}
	switch mode {
	case "quic":
		s, listenErr := ListenQUIC(QUICServerConfig{
			Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS, Dialer: outbound, StreamAdmission: admission,
		})
		if listenErr != nil {
			t.Fatal(listenErr)
		}
		server, core = s, s.core
		client, err = NewClient(ClientConfig{ServerAddress: s.Addr().String(), Token: testToken, TLSConfig: clientTLS})
		awaitHandler = func() {
			destinationDialOwnershipAwait(t, func() bool { return len(admission.sem) == 0 && len(s.streamSem) == 0 }, "native QUIC handler and stream admission release")
		}
	case "tls":
		s, listenErr := ListenTLS(TLSServerConfig{
			Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS, Dialer: outbound, StreamAdmission: admission,
		})
		if listenErr != nil {
			t.Fatal(listenErr)
		}
		server, core = s, s.core
		client, err = NewTLSClient(TLSClientConfig{ServerAddress: s.Addr().String(), Token: testToken, TLSConfig: clientTLS})
		awaitHandler = func() {
			destinationDialOwnershipAwait(t, func() bool { return len(admission.sem) == 0 && len(s.connSem) == 0 }, "native TLS handler and stream admission release")
		}
	case "h2":
		s, listenErr := ListenWebH2(WebH2ServerConfig{
			Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS, Dialer: outbound, StreamAdmission: admission, Cover: cover,
		})
		if listenErr != nil {
			t.Fatal(listenErr)
		}
		server, core = s, s.server.Handler.(*webTunnelHandler).core
		s.server.Handler, awaitHandler = webCompletion(s.server.Handler)
		c, clientErr := NewWebH2Client(WebH2ClientConfig{ServerAddress: s.Addr().String(), Token: testToken, TLSConfig: clientTLS})
		client, err = c, clientErr
		verified = func() bool {
			c.mu.Lock()
			defer c.mu.Unlock()
			return c.current != nil && c.current.authState == webH2ClientAuthReady
		}
	case "h3":
		s, listenErr := ListenWebH3(WebH3ServerConfig{
			Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS, Dialer: outbound, StreamAdmission: admission, Cover: cover,
		})
		if listenErr != nil {
			t.Fatal(listenErr)
		}
		server, core = s, s.server.Handler.(*webTunnelHandler).core
		s.server.Handler, awaitHandler = webCompletion(s.server.Handler)
		c, clientErr := NewWebH3Client(WebH3ClientConfig{ServerAddress: s.Addr().String(), Token: testToken, TLSConfig: clientTLS})
		client, err = c, clientErr
		verified = func() bool {
			c.mu.Lock()
			defer c.mu.Unlock()
			session := c.conns[c.conn]
			return session != nil && session.authState == webH3ClientAuthReady
		}
	default:
		t.Fatalf("unknown destination ownership transport %q", mode)
	}
	if err != nil {
		_ = server.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cleanupDone := make(chan []error, 1)
		go func() {
			clientErr := client.Close()
			cancel()
			cleanupDone <- []error{clientErr, server.Close()}
		}()
		select {
		case closeErrors := <-cleanupDone:
			for _, closeErr := range closeErrors {
				if !destinationDialOwnershipOnlyClosed(closeErr) {
					t.Errorf("%s client/server Close: %v", mode, closeErr)
				}
			}
		case <-time.After(3 * time.Second):
			t.Errorf("%s client/server Close cleanup did not join", mode)
		}
		select {
		case serveErr := <-serveDone:
			if serveErr != nil {
				t.Errorf("%s Serve cleanup: %v", mode, serveErr)
			}
			t.Logf("%s client/server Serve cleanup joined", mode)
		case <-time.After(3 * time.Second):
			t.Errorf("%s Serve cleanup did not join", mode)
		}
	})
	if core.handshakeTimeout != defaultHandshakeTimeout || core.dialTimeout != defaultDialTimeout || core.destinationWriteTimeout != defaultDestinationWriteTimeout {
		t.Fatal("ownership fixture changed the production setup/write budgets")
	}
	return client, awaitHandler, verified
}

func destinationDialOwnershipAwait(t *testing.T, complete func() bool, what string) {
	t.Helper()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for !complete() {
		select {
		case <-tick.C:
		case <-timer.C:
			t.Fatalf("%s did not complete", what)
		}
	}
}

func destinationDialOwnershipWait(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Errorf("%s did not join", what)
	}
}

// Ignore only closed-resource leaves, not an unrelated joined cleanup error.
func destinationDialOwnershipOnlyClosed(err error) bool {
	if err == nil {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if !destinationDialOwnershipOnlyClosed(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		if child := wrapped.Unwrap(); child != nil {
			return destinationDialOwnershipOnlyClosed(child)
		}
	}
	return errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed)
}
