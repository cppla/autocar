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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/cppla/autocar/internal/transport"
)

// Deadline is reached only after contextError has read the real context's
// still-nil Cause. Compute its actual deadline before publishing the witness;
// cancellation must not retroactively change that preflight result. Value,
// Err and Done all retain the real WithCancelCause context's semantics.
type webH3SelectionPreflightContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *webH3SelectionPreflightContext) Deadline() (time.Time, bool) {
	deadline, ok := c.Context.Deadline()
	c.once.Do(func() { close(c.entered) })
	return deadline, ok
}

type webH3SelectionObservation struct {
	connection *webServerConnectionAuth
	full       bool
	short      bool
	proof      bool
	proto      int
	tlsVersion uint16
	joined     <-chan struct{}
}

type webH3SelectionFixture struct {
	f           *webH2DialSharingFixture
	client      *WebH3Client
	target      string
	entropy     *webH2AuthEntropyCounter
	observed    chan webH3SelectionObservation
	verified    chan struct{}
	verifyCalls atomic.Int32
	dials       atomic.Int32
	covers      atomic.Int32
	unexpected  atomic.Int32
}

func newWebH3SelectionFixture(t *testing.T) *webH3SelectionFixture {
	t.Helper()
	f := newWebH2DialSharingFixture(t)
	x := &webH3SelectionFixture{
		f: f, target: f.target(), entropy: &webH2AuthEntropyCounter{},
		observed: make(chan webH3SelectionObservation, 2), verified: make(chan struct{}, 4),
	}
	serverTLS, clientTLS := testTLSConfigs(t)
	server, err := ListenWebH3(WebH3ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
		HandshakeTimeout: time.Second, DialTimeout: time.Second,
		Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			x.covers.Add(1)
			http.NotFound(w, r)
		}),
		Dialer: transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			x.dials.Add(1)
			if network != "tcp" || address != x.target {
				return nil, errors.New("selection fixture refuses a non-owned destination")
			}
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", x.target)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	original := server.server.Handler
	server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		joined := make(chan struct{})
		f.register(joined)
		defer close(joined)
		connection, _ := r.Context().Value(webServerConnectionAuthContextKey{}).(*webServerConnectionAuth)
		bearer := r.Header.Get("Proxy-Authorization")
		_, short := parseWebSessionBearer(bearer)
		original.ServeHTTP(w, r)
		observation := webH3SelectionObservation{
			connection: connection, full: len(bearer) >= 385 && len(bearer) <= 2047,
			short: short, proof: w.Header().Get(webAuthResponseHeader) != "",
			proto: r.ProtoMajor, tlsVersion: webRequestTLSVersion(r), joined: joined,
		}
		select {
		case x.observed <- observation:
		default:
			x.unexpected.Add(1)
		}
	})
	serveJoined := make(chan struct{})
	f.register(serveJoined)
	var serveErr error
	f.checks = append(f.checks, func() {
		if serveErr != nil {
			t.Errorf("owned selection H3 Serve: %v", serveErr)
		}
	})
	f.close = append(f.close, func() {
		if err := server.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("owned selection H3 server Close: %v", err)
		}
	})
	go func() { defer close(serveJoined); serveErr = server.Serve(f.ctx) }()

	// Native's standard certificate chain/name verification still runs before
	// this callback. It is an actual successful TLS handshake observation, not
	// a synthetic physical dial hook or a browser-profile claim.
	clientTLS = clientTLS.Clone()
	clientTLS.VerifyConnection = func(state tls.ConnectionState) error {
		if state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 || state.NegotiatedProtocol != "h3" {
			return errors.New("owned selection TLS verification state is incomplete")
		}
		x.verifyCalls.Add(1)
		select {
		case x.verified <- struct{}{}:
		default:
			x.unexpected.Add(1)
		}
		return nil
	}
	x.client, err = NewWebH3Client(WebH3ClientConfig{
		ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
		FingerprintProfile: H3FingerprintNative, DialTimeout: time.Second, HandshakeTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	x.client.signer = newWebAuthSigner(mustWebAuthKey(t, webTestToken), nil, x.entropy)
	f.close = append(f.close, func() {
		if err := x.client.Close(); err != nil {
			t.Errorf("owned selection H3 client Close: %v", err)
		}
	})
	return x
}

func (x *webH3SelectionFixture) canceledAtPreflight(call func(context.Context) error) error {
	x.f.t.Helper()
	ctx, cancel := context.WithCancelCause(x.f.ctx)
	defer cancel(context.Canceled)
	witness := &webH3SelectionPreflightContext{Context: ctx, entered: make(chan struct{})}
	cause := errors.New("private cancellation after successful selection preflight")
	result, joined := make(chan error, 1), make(chan struct{})
	x.f.register(joined)
	x.client.mu.Lock()
	unlock := sync.OnceFunc(x.client.mu.Unlock)
	// This is appended last and therefore runs before client.Close on Fatal.
	x.f.close = append(x.f.close, unlock)
	go func() { defer close(joined); result <- call(witness) }()
	x.f.wait(witness.entered, "preflight read nil Cause before actual mutex wait")
	cancel(cause)
	x.f.wait(ctx.Done(), "real caller cancellation publication while mutex held")
	if context.Cause(witness) != cause {
		x.f.t.Fatal("wrapper did not retain the real caller's cancellation cause")
	}
	unlock()
	x.f.wait(joined, "canceled selection caller completion")
	err := <-result
	if err != cause {
		x.f.t.Errorf("canceled selection result=%v, want exact private caller cause", err)
	}
	return err
}

// These later controls deliberately still run after a negative assertion.
// On old source they can prove healthy replacement/retry even when the
// cancellation incorrectly changed a Fresh connection's authentication state.
func (x *webH3SelectionFixture) healthy(expected *quic.Conn) {
	x.f.t.Helper()
	noncesBefore, verifiesBefore := x.entropy.nonceReads.Load(), x.verifyCalls.Load()
	var physical *quic.Conn
	for round := range 2 {
		ctx, cancel := context.WithTimeout(x.f.ctx, 2*time.Second)
		conn, err := x.client.DialContext(ctx, "tcp", x.target)
		if err != nil {
			cancel()
			x.f.t.Fatalf("later healthy public H3 CONNECT %d: %v", round, err)
		}
		if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			_ = conn.Close()
			cancel()
			x.f.t.Fatalf("later healthy H3 I/O deadline: %v", err)
		}
		payload := []byte(fmt.Sprintf("owned-selection-cancellation-echo-%d", round))
		_, writeErr := conn.Write(payload)
		closeWriteErr := conn.(*webH3Conn).CloseWrite()
		got, readErr := io.ReadAll(io.LimitReader(conn, int64(len(payload))+1))
		closeErr := conn.Close()
		cancel()
		if writeErr != nil || closeWriteErr != nil || readErr != nil || closeErr != nil || !bytes.Equal(got, payload) {
			x.f.t.Fatalf("full H3/TCP echo %d=%q write/FIN/read/close=%v/%v/%v/%v", round, got, writeErr, closeWriteErr, readErr, closeErr)
		}
		x.client.mu.Lock()
		current := x.client.conn
		x.client.mu.Unlock()
		if current == nil || (round == 1 && current != physical) {
			x.f.t.Error("two later healthy public flows did not reuse one actual H3 connection")
		}
		physical = current
	}
	var observations [2]webH3SelectionObservation
	for i := range observations {
		select {
		case observations[i] = <-x.observed:
		case <-x.f.ctx.Done():
			x.f.t.Fatal("later authenticated handler observation exceeded fixture budget")
		}
		x.f.wait(observations[i].joined, "later actual authenticated H3 handler joined")
		if !observations[i].proof || observations[i].proto != 3 || observations[i].tlsVersion != tls.VersionTLS13 || observations[i].connection == nil {
			x.f.t.Errorf("healthy handler %d proof/proto/TLS/connection=%t/%d/%x/%t", i, observations[i].proof, observations[i].proto, observations[i].tlsVersion, observations[i].connection != nil)
		}
	}
	if observations[0].connection != observations[1].connection || !observations[0].full || observations[0].short || !observations[1].short || x.entropy.nonceReads.Load()-noncesBefore != 1 || x.dials.Load() != 2 || x.covers.Load() != 0 || x.unexpected.Load() != 0 {
		x.f.t.Errorf("healthy full/short authentication control failed: full/short=%t/%t newnonce=%d destination/cover/unexpected=%d/%d/%d", observations[0].full, observations[1].short, x.entropy.nonceReads.Load()-noncesBefore, x.dials.Load(), x.covers.Load(), x.unexpected.Load())
	}
	if expected != nil && physical != expected {
		x.f.t.Error("caller cancellation replaced the previously initialized Fresh physical connection")
	}
	if expected != nil && x.verifyCalls.Load() != verifiesBefore {
		x.f.t.Error("reusing the initialized Fresh connection performed another actual TLS handshake")
	}
	x.f.t.Log("later public H3 two complete TCP echoes, same physical connection and full/short authentication controls evaluated")
}

func TestWebH3ConnectionCanceledWhileWaitingForSelection(t *testing.T) {
	x := newWebH3SelectionFixture(t)
	x.canceledAtPreflight(func(ctx context.Context) error {
		conn, client, err := x.client.connection(ctx)
		if conn != nil || client != nil {
			x.f.t.Error("canceled cold selection returned a physical H3 connection")
		}
		return err
	})
	x.client.mu.Lock()
	attempt := x.client.dial
	started := attempt != nil || x.client.conn != nil || x.client.client != nil || len(x.client.conns) != 0
	x.client.mu.Unlock()
	if started {
		t.Error("caller canceled while waiting for mutex nevertheless started client-owned physical H3 setup")
	}
	// Old source can already have cleared dial after publishing a connection.
	// A captured attempt is awaited through its immutable result, not a private
	// WaitGroup/runtime-stack introspection. Standard TLS callback is wire proof.
	if attempt != nil {
		x.f.wait(attempt.done, "unexpected old-source actual physical attempt completed")
	}
	if calls := x.verifyCalls.Load(); calls != 0 {
		t.Errorf("canceled-before-selection performed %d actual verified TLS handshakes", calls)
	}
	if started {
		select {
		case <-x.verified:
			t.Log("negative boundary also reached actual owned native TLS certificate verification")
		default:
			t.Log("negative boundary observed physical setup state before verified TLS completion")
		}
	}
	if x.entropy.nonceReads.Load() != 0 || x.dials.Load() != 0 || x.covers.Load() != 0 {
		t.Error("canceled cold selection attempted application authentication, destination dialing or public cover")
	}
	x.healthy(nil)
}

func TestWebH3FreshSessionCancellationDoesNotClaimAuthentication(t *testing.T) {
	x := newWebH3SelectionFixture(t)
	physical, _, err := x.client.connection(x.f.ctx)
	if err != nil || physical == nil {
		t.Fatalf("real owned H3 initialization without authentication: %v", err)
	}
	x.client.mu.Lock()
	session := x.client.conns[physical]
	fresh := session != nil && session.authState == webH3ClientAuthFresh && session.users == 0 && !session.retired && physical.Context().Err() == nil
	x.client.mu.Unlock()
	if !fresh || x.verifyCalls.Load() != 1 || x.entropy.nonceReads.Load() != 0 || x.dials.Load() != 0 {
		t.Fatal("actual verified initialized Fresh H3 connection was not established before scheduling")
	}
	x.canceledAtPreflight(func(ctx context.Context) error {
		conn, err := x.client.DialContext(ctx, "tcp", x.target)
		if conn != nil {
			_ = conn.Close()
			t.Error("canceled Fresh selection returned an application stream")
		}
		return err
	})
	x.client.mu.Lock()
	preserved := x.client.conn == physical && x.client.conns[physical] == session && session.authState == webH3ClientAuthFresh && session.users == 0 && !session.retired && physical.Context().Err() == nil
	x.client.mu.Unlock()
	if !preserved || x.entropy.nonceReads.Load() != 0 || x.dials.Load() != 0 || x.covers.Load() != 0 {
		t.Errorf("canceled Fresh selection changed physical/authentication state: preserved=%t nonce/destination/cover=%d/%d/%d", preserved, x.entropy.nonceReads.Load(), x.dials.Load(), x.covers.Load())
	}
	// This public path causally exercises connection's mutex recheck. The
	// narrower return-to-reserve mutex window remains a source-order defense,
	// not a separately injected scheduling claim in this test.
	x.healthy(physical)
}
