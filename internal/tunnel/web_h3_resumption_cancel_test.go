package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

func TestWebH3ResumptionHandshakeCancellation(t *testing.T) {
	for _, mode := range []string{"caller_cancel", "client_close"} {
		t.Run(mode, func(t *testing.T) {
			serverTLS, clientTLS := webH2ResumptionTLSConfigs(t)
			clientTLS.ClientSessionCache = tls.NewLRUClientSessionCache(4)
			serverTLS.SetSessionTicketKeys([][32]byte{{1, 2, 3}})
			entered, release := make(chan struct{}), make(chan struct{})
			var signal, unblock sync.Once
			defer unblock.Do(func() { close(release) })
			serverTLS.UnwrapSession = func(identity []byte, state tls.ConnectionState) (*tls.SessionState, error) {
				signal.Do(func() { close(entered) })
				<-release
				return serverTLS.DecryptTicket(identity, state)
			}
			target, closeTarget := startHalfCloseTarget(t)
			t.Cleanup(closeTarget)
			var dials atomic.Int32
			server, err := ListenWebH3(WebH3ServerConfig{
				Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
				Dialer: countingDialer{dials: &dials}, Cover: http.NotFoundHandler(),
			})
			if err != nil {
				t.Fatal(err)
			}
			serveWebH3ForTest(t, server)
			client, err := NewWebH3Client(WebH3ClientConfig{
				ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
				FingerprintProfile: H3FingerprintChrome202610Resume, DialTimeout: 2 * time.Second, HandshakeTimeout: 2 * time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			cache := watchWebH3UTLSTickets(t, client)
			entropy := &webH2AuthEntropyCounter{}
			client.signer = newWebAuthSigner(mustWebAuthKey(t, webTestToken), nil, entropy)
			if err := exchange(client, target, "prime resumption cancellation"); err != nil {
				t.Fatal(err)
			}
			waitWebH3Ticket(t, cache.stored)
			first := webH3SelectedSession(t, client)
			client.retire(first.conn)
			assertWebH3SessionRetired(t, client, first)
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(context.Canceled)
			opened := make(chan error, 1)
			go func() {
				conn, err := client.DialContext(ctx, "tcp", target)
				if conn != nil {
					_ = conn.Close()
				}
				opened <- err
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("warm handshake did not reach real server ticket processing")
			}
			client.mu.Lock()
			attempt := client.dial
			client.mu.Unlock()
			if attempt == nil {
				t.Fatal("warm handshake finished before the cancellation gate")
			}
			want := error(net.ErrClosed)
			if mode == "caller_cancel" {
				want = errors.New("cancel warm H3 ticket handshake")
				cancel(want)
			} else {
				closed := make(chan error, 1)
				go func() { closed <- client.Close() }()
				select {
				case err := <-closed:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("Close did not join the unfinished resumed handshake")
				}
			}
			select {
			case err := <-opened:
				if !errors.Is(err, want) {
					t.Fatalf("warm handshake cancellation = %v, want %v", err, want)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("warm handshake ignored cancellation")
			}
			unblock.Do(func() { close(release) })
			select {
			case <-attempt.done:
			case <-time.After(3 * time.Second):
				t.Fatal("shared warm handshake did not finish after release")
			}
			if dials.Load() != 1 || entropy.nonceReads.Load() != 1 {
				t.Fatal("canceled warm handshake reached proxy authentication or a destination")
			}
		})
	}
}

func TestWebH3ResumptionCanceledContinuationKeepsHealthySibling(t *testing.T) {
	serverTLS, clientTLS := webH2ResumptionTLSConfigs(t)
	clientTLS.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	entered, left := make(chan struct{}), make(chan struct{})
	const blocked = "blocked.invalid:9"
	server, err := ListenWebH3(WebH3ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS, Cover: http.NotFoundHandler(),
		Dialer: transport.DialFunc(func(ctx context.Context, network, target string) (net.Conn, error) {
			if target == blocked {
				close(entered)
				<-ctx.Done()
				close(left)
				return nil, context.Cause(ctx)
			}
			return (&net.Dialer{}).DialContext(ctx, network, target)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	serveWebH3ForTest(t, server)
	client, err := NewWebH3Client(WebH3ClientConfig{
		ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
		FingerprintProfile: H3FingerprintChrome202610Resume, DialTimeout: time.Second, HandshakeTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	cache := watchWebH3UTLSTickets(t, client)
	target, closeTarget := startHalfCloseTarget(t)
	t.Cleanup(closeTarget)
	if err := exchange(client, target, "prime sibling test"); err != nil {
		t.Fatal(err)
	}
	waitWebH3Ticket(t, cache.stored)
	first := webH3SelectedSession(t, client)
	client.retire(first.conn)
	assertWebH3SessionRetired(t, client, first)
	sibling, err := client.DialContext(context.Background(), "tcp", startWebTCPEcho(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sibling.Close() })
	warm := webH3SelectedSession(t, client)
	if !warm.conn.ConnectionState().TLS.DidResume {
		t.Fatal("healthy sibling is not on a resumed physical connection")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opened := make(chan error, 1)
	go func() {
		conn, err := client.DialContext(ctx, "tcp", blocked)
		if conn != nil {
			_ = conn.Close()
		}
		opened <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("continuation never reached the destination gate")
	}
	cancel()
	select {
	case err := <-opened:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("continuation cancellation = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("continuation cancellation did not return")
	}
	select {
	case <-left:
	case <-time.After(3 * time.Second):
		t.Fatal("server retained the canceled destination dial")
	}
	assertWebH3StreamEcho(t, sibling)
	if err := exchange(client, target, "healthy later continuation"); err != nil {
		t.Fatal(err)
	}
	if webH3SelectedSession(t, client) != warm || warm.conn.Context().Err() != nil {
		t.Fatal("one canceled stream retired the healthy resumed connection")
	}
}
