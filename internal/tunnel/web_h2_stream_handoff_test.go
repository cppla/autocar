package tunnel

import (
	"context"
	"crypto/tls"
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

// Deadline returns the real context's deadline snapshot. The first call after
// the fresh physical session becomes Ready occurs inside contextError, after
// it already read a nil Cause and after the caller watcher was stopped. Hold
// the client mutex at that point so real caller cancellation precedes the
// serialized handoff. Done and Value remain the real context's methods;
// neither cancellation publication nor a transport response is fabricated.
type webH2TCPHandoffSnapshot struct {
	session         *webH2ClientSession
	state           tls.ConnectionState
	opening, active int
	selected        bool
}

type webH2TCPHandoffContext struct {
	context.Context
	client  *WebH2Client
	entered chan webH2TCPHandoffSnapshot
	release <-chan struct{}
	fixture context.Context
	gated   atomic.Bool
	expired atomic.Bool
}

func (c *webH2TCPHandoffContext) Deadline() (time.Time, bool) {
	deadline, ok := c.Context.Deadline()
	c.client.mu.Lock()
	session := c.client.current
	ready := session != nil && session.authState == webH2ClientAuthReady && session.auth != nil
	if ready && c.gated.CompareAndSwap(false, true) {
		c.entered <- webH2TCPHandoffSnapshot{session: session, state: session.conn.ConnectionState(),
			opening: session.opening, active: session.active, selected: c.client.selected}
		select {
		case <-c.release:
		case <-c.fixture.Done():
			c.expired.Store(true)
		}
	}
	c.client.mu.Unlock()
	return deadline, ok
}

func TestWebH2TCPHandoffHonorsCallerCancellation(t *testing.T) {
	for _, profile := range []FingerprintProfile{FingerprintNative, FingerprintChrome133, FingerprintChrome155} {
		t.Run(string(profile), func(t *testing.T) {
			f := newWebH2DialSharingFixture(t)
			target := f.target()
			serverTLS, clientTLS := testTLSConfigs(t)
			var destinations, covers, unexpected atomic.Int32
			server, err := ListenWebH2(WebH2ServerConfig{
				Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
				DialTimeout: time.Second, HandshakeTimeout: time.Second,
				Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					covers.Add(1)
					http.NotFound(w, r)
				}),
				Dialer: transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
					destinations.Add(1)
					if network != "tcp" || address != target {
						unexpected.Add(1)
						return nil, errors.New("diagnostic refuses a non-owned destination")
					}
					return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", target)
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			type observation struct {
				state  *webServerConnectionAuth
				bearer string
			}
			observed := make(chan observation, 3)
			original := server.server.Handler
			server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				joined := make(chan struct{})
				f.register(joined)
				defer close(joined)
				state, _ := r.Context().Value(webServerConnectionAuthContextKey{}).(*webServerConnectionAuth)
				select {
				case observed <- observation{state: state, bearer: r.Header.Get("Proxy-Authorization")}:
				default:
					unexpected.Add(1)
				}
				original.ServeHTTP(w, r)
			})
			serveJoined := make(chan struct{})
			var serveErr error
			f.register(serveJoined)
			f.checks = append(f.checks, func() {
				if serveErr != nil {
					t.Errorf("owned H2 Serve: %v", serveErr)
				}
			})
			f.close = append(f.close, func() {
				if err := server.Close(); err != nil {
					t.Errorf("owned H2 server Close: %v", err)
				}
			})
			go func() { defer close(serveJoined); serveErr = server.Serve(f.ctx) }()
			client, entropy, raws := f.client(profile, server.Addr().String(), clientTLS)
			caller, cancel := context.WithCancelCause(f.ctx)
			f.close = append(f.close, func() { cancel(context.Canceled) })
			release := make(chan struct{})
			ungate := sync.OnceFunc(func() { close(release) })
			gate := &webH2TCPHandoffContext{Context: caller, client: client,
				entered: make(chan webH2TCPHandoffSnapshot, 1), release: release, fixture: f.ctx}
			// Release before any client Close tries to acquire the held mutex.
			f.close = append(f.close, ungate)
			results, joined := f.dial(client, gate, target)
			var snapshot webH2TCPHandoffSnapshot
			select {
			case snapshot = <-gate.entered:
			case <-f.ctx.Done():
				t.Fatal("actual post-proof scheduling checkpoint exceeded fixture budget")
			}
			physical := f.raw(raws)
			session, state, selected := snapshot.session, snapshot.state, snapshot.selected
			ready := session != nil && snapshot.opening == 1 && snapshot.active == 0
			cause := errors.New("private caller cancellation in H2 final handoff window")
			cancel(cause)
			f.wait(caller.Done(), "real caller cancellation published")
			ungate()
			if !ready || selected || state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != webH2ALPN || len(state.VerifiedChains) == 0 {
				t.Errorf("checkpoint Ready/selected/version/ALPN/chains=%t/%t/%x/%s/%d", ready, selected, state.Version, state.NegotiatedProtocol, len(state.VerifiedChains))
			}
			f.wait(joined, "canceled public CONNECT caller joined")
			got := <-results
			if got.conn != nil || got.err != cause {
				t.Errorf("post-proof canceled handoff conn=%t err=%v; want nil and exact caller cause", got.conn != nil, got.err)
			}
			// Run recovery controls even if the old source returns a live stream.
			if got.conn != nil {
				assertWebH2TCPHandoffEcho(t, got.conn, "late-detached-success")
				_ = got.conn.Close()
				t.Log("old handoff returned a genuinely live echo stream despite already-published caller cancellation")
			}
			for round := range 2 {
				ctx, stop := context.WithCancelCause(f.ctx)
				conn, err := client.DialContext(ctx, "tcp", target)
				stop(errors.New("successful H2 caller no longer owns its stream"))
				if err != nil {
					t.Fatalf("later healthy CONNECT %d: %v", round, err)
				}
				assertWebH2TCPHandoffEcho(t, conn, fmt.Sprintf("healthy-detached-%d", round))
				_ = conn.Close()
			}
			client.mu.Lock()
			same, readyAfter, owners := client.current == session, session.authState == webH2ClientAuthReady, session.opening+session.active
			client.mu.Unlock()
			select {
			case <-physical.closed:
				t.Error("caller handoff cancellation closed the physical H2 wire")
			default:
			}
			var seen [3]observation
			for i := range seen {
				select {
				case seen[i] = <-observed:
				case <-f.ctx.Done():
					t.Fatal("actual handler entry observation exceeded fixture budget")
				}
			}
			_, secondShort := parseWebSessionBearer(seen[1].bearer)
			_, thirdShort := parseWebSessionBearer(seen[2].bearer)
			if !same || !readyAfter || owners != 0 || seen[0].state == nil || seen[0].state != seen[1].state || seen[0].state != seen[2].state || len(seen[0].bearer) < 385 || !secondShort || !thirdShort || entropy.nonceReads.Load() != 1 || destinations.Load() != 3 || covers.Load() != 0 || unexpected.Load() != 0 {
				t.Errorf("Ready/same/owners/full-short-short/nonce/dest/cover/unexpected=%t/%t/%d/%d,%t,%t/%d/%d/%d/%d", readyAfter, same, owners, len(seen[0].bearer), secondShort, thirdShort, entropy.nonceReads.Load(), destinations.Load(), covers.Load(), unexpected.Load())
			}
			if !gate.gated.Load() || gate.expired.Load() {
				t.Error("controlled handoff gate did not complete within its independent budget")
			}
			t.Log("two complete post-success-cancel echo controls used one verified Ready physical H2 session and full/short/short authentication; owned fixture cleanup joins all workers")
		})
	}
}

func assertWebH2TCPHandoffEcho(t *testing.T, conn net.Conn, payload string) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatalf("actual owned echo write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != payload {
		t.Fatalf("actual owned echo body=%q err=%v, want %q", got, err, payload)
	}
}
