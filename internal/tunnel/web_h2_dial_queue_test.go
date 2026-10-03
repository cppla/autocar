package tunnel

import (
	"context"
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

func TestWebH2DialQueuedCallersShareCompletedFailure(t *testing.T) {
	f := newWebH2DialSharingFixture(t)
	serverTLS, clientTLS := testTLSConfigs(t)
	target := f.target()
	var destinationDials, covers, unexpected atomic.Int32
	server, err := ListenWebH2(WebH2ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
		Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { covers.Add(1); http.NotFound(w, r) }),
		Dialer: transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			destinationDials.Add(1)
			if network != "tcp" || address != target {
				return nil, errors.New("queue fixture refuses a non-owned destination")
			}
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", target)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	type observedRequest struct {
		state  *webServerConnectionAuth
		bearer string
	}
	requests := make(chan observedRequest, 2)
	original := server.server.Handler
	server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		joined := make(chan struct{})
		f.register(joined)
		defer close(joined)
		state, _ := r.Context().Value(webServerConnectionAuthContextKey{}).(*webServerConnectionAuth)
		select {
		case requests <- observedRequest{state: state, bearer: r.Header.Get("Proxy-Authorization")}:
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
			t.Errorf("owned queue-control H2 Serve: %v", serveErr)
		}
	})
	f.close = append(f.close, func() {
		if err := server.Close(); err != nil {
			t.Errorf("owned queue-control H2 server Close: %v", err)
		}
	})
	go func() { defer close(serveJoined); serveErr = server.Serve(f.ctx) }()
	client, entropy, _ := f.client(FingerprintNative, server.Addr().String(), clientTLS)
	realDialer := client.dialer
	entered, releaseFailure := make(chan struct{}), make(chan struct{})
	markEntered := sync.OnceFunc(func() { close(entered) })
	finishFailure := sync.OnceFunc(func() { close(releaseFailure) })
	f.close = append(f.close, finishFailure)
	fault := errors.New("private controlled first physical failure")
	var healthy atomic.Bool
	var physicalDials atomic.Int32
	client.dialer = transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		physicalDials.Add(1)
		if network != "tcp" || address != server.Addr().String() {
			return nil, errors.New("queue fixture refuses a non-owned physical endpoint")
		}
		if healthy.Load() {
			return realDialer.DialContext(ctx, network, address)
		}
		markEntered()
		select {
		case <-releaseFailure:
		case <-ctx.Done():
		}
		// Explicit synthetic fast failure, not a TCP performance observation.
		return nil, fault
	})
	leader, leaderJoined := f.reserve(client, f.ctx)
	f.wait(entered, "actual first physical DialFunc entry")
	// The existing selection gate is an explicit scheduling barrier. The
	// first attempt is already running, but these callers cannot be admitted
	// until after that attempt has actually published its completed result.
	select {
	case client.dialGate <- struct{}{}:
	case <-f.ctx.Done():
		t.Fatal("first reserve did not release the selection gate")
	}
	releaseGate := sync.OnceFunc(func() { <-client.dialGate })
	f.close = append(f.close, releaseGate) // Fatal cleanup always releases it.
	queued := make([]<-chan webH2DialSharingResult, 2)
	joins := make([]<-chan struct{}, 2)
	for i := range queued {
		ctx := &webH2DialSharingContext{Context: f.ctx, entered: make(chan struct{}), attemptWait: make(chan struct{})}
		queued[i], joins[i] = f.reserve(client, ctx)
		f.wait(ctx.entered, "actual queued caller's gate-wait Done evaluation")
	}
	finishFailure()
	f.wait(leaderJoined, "first physical failure published to initiating caller")
	firstError := (<-leader).err
	if !errors.Is(firstError, fault) {
		t.Fatalf("first physical result=%v, want its exact private cause", firstError)
	}
	client.mu.Lock()
	cleared := client.dial == nil && client.current == nil && len(client.sessions) == 0
	client.mu.Unlock()
	if !cleared || physicalDials.Load() != 1 || len(client.dialGate) != 1 {
		t.Fatalf("completed failure while gate held: cleared=%t physical=%d gate=%d", cleared, physicalDials.Load(), len(client.dialGate))
	}
	releaseGate()
	for i := range queued {
		f.wait(joins[i], "previously queued reserve caller joined")
		if err := (<-queued[i]).err; err != firstError {
			t.Errorf("queued caller %d missed the completed immutable failure: got=%v want same object=%v", i, err, firstError)
		}
	}
	failedDials := physicalDials.Load()
	if failedDials != 1 || entropy.nonceReads.Load() != 0 || destinationDials.Load() != 0 {
		t.Errorf("queued failure made physical/auth/destination attempts=%d/%d/%d, want 1/0/0", failedDials, entropy.nonceReads.Load(), destinationDials.Load())
	}

	// A genuinely later invocation may retry; a failure is not cached forever.
	// Both flows use real verifying TLS/H2 and the same owned TCP echo target.
	healthy.Store(true)
	var physical *webH2ClientSession
	for round := range 2 {
		ctx, cancel := context.WithTimeout(f.ctx, time.Second)
		conn, err := client.DialContext(ctx, "tcp", target)
		cancel()
		if err != nil {
			t.Fatalf("later healthy public CONNECT %d: %v", round, err)
		}
		if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		payload := []byte(fmt.Sprintf("owned-queued-failure-retry-%d", round))
		_, writeErr := conn.Write(payload)
		got := make([]byte, len(payload))
		_, readErr := io.ReadFull(conn, got)
		closeErr := conn.Close()
		if writeErr != nil || readErr != nil || closeErr != nil || string(got) != string(payload) {
			t.Fatalf("later healthy echo %d=%q, write/read/close=%v/%v/%v", round, got, writeErr, readErr, closeErr)
		}
		client.mu.Lock()
		current := client.current
		client.mu.Unlock()
		if current == nil || (round == 1 && current != physical) {
			t.Fatal("later healthy flows did not reuse one physical session")
		}
		physical = current
	}
	var observed [2]observedRequest
	for i := range observed {
		select {
		case observed[i] = <-requests:
		case <-f.ctx.Done():
			t.Fatal("healthy handler observation exceeded fixture budget")
		}
	}
	_, short := parseWebSessionBearer(observed[1].bearer)
	if observed[0].state == nil || observed[0].state != observed[1].state || len(observed[0].bearer) < 385 || !short || entropy.nonceReads.Load() != 1 || physicalDials.Load() != failedDials+1 || destinationDials.Load() != 2 || covers.Load() != 0 || unexpected.Load() != 0 {
		t.Errorf("healthy retry/full-short auth violated: lengths=%d/%d short=%t physical/nonce/destination/cover/unexpected=%d/%d/%d/%d/%d", len(observed[0].bearer), len(observed[1].bearer), short, physicalDials.Load(), entropy.nonceReads.Load(), destinationDials.Load(), covers.Load(), unexpected.Load())
	}
	t.Log("queued-before-completion failure and independent real TLS/H2 full/short-auth echo controls evaluated")
}
