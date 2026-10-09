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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// This test gates the real bootstrap commit, not a synthetic response Body.
// The peer has sent a valid status-bound proof and unread DATA before its next
// SETTINGS makes the actual HTTP/2 writer block in a TLS write over net.Pipe.
// Releasing the commit lock must return the HTTP error without waiting for
// that unrelated write, without retiring the healthy physical connection,
// and without losing ownership of the still-pending response cleanup.
func TestWebH2FailedResponseCleanupDoesNotWaitForWriter(t *testing.T) {
	for _, profile := range []FingerprintProfile{FingerprintNative, FingerprintChrome133, FingerprintChrome155} {
		t.Run(string(profile), func(t *testing.T) {
			for _, mode := range []string{"authenticated_error", "canceled_handoff", "client_close", "bootstrap_lost_selection"} {
				t.Run(mode, func(t *testing.T) { testWebH2FailedResponseCleanup(t, profile, mode) })
			}
		})
	}
}

func testWebH2FailedResponseCleanup(t *testing.T, profile FingerprintProfile, mode string) {
	status := http.StatusBadGateway
	if mode == "canceled_handoff" {
		status = http.StatusOK
	}
	f := newWebH2FailedResponseFixture(t, profile, status)
	caller, cancel := context.WithCancelCause(f.ctx)
	t.Cleanup(func() { cancel(context.Canceled) })
	var gate *webH2TCPHandoffContext
	var dialCtx context.Context = caller
	if mode == "canceled_handoff" {
		release := make(chan struct{})
		gate = &webH2TCPHandoffContext{Context: caller, client: f.client,
			entered: make(chan webH2TCPHandoffSnapshot, 1), release: release, fixture: f.ctx}
		dialCtx = gate
		f.releaseHandoff = sync.OnceFunc(func() { close(release) })
		t.Cleanup(f.releaseHandoff)
	}
	result, joined := f.dial(dialCtx)
	f.wait(f.requestReceived, "first authenticated CONNECT headers")
	var session *webH2ClientSession
	var state tls.ConnectionState
	var unlock func()
	if gate == nil {
		f.client.mu.Lock()
		unlock = sync.OnceFunc(f.client.mu.Unlock)
		t.Cleanup(unlock)
		session = f.client.current
		if session == nil || session.authState != webH2ClientAuthBootstrapping {
			unlock()
			t.Fatal("first CONNECT did not own a real bootstrapping session")
		}
		state = session.conn.ConnectionState()
		close(f.respond)
	} else {
		close(f.respond)
		select {
		case snapshot := <-gate.entered:
			session, state = snapshot.session, snapshot.state
			if snapshot.opening != 1 || snapshot.active != 0 || snapshot.selected {
				t.Fatal("handoff gate did not observe an opening, unreturned CONNECT")
			}
		case <-f.ctx.Done():
			t.Fatal("actual post-proof handoff checkpoint exceeded fixture budget")
		}
		unlock = f.releaseHandoff
	}
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != webH2ALPN || len(state.VerifiedChains) == 0 {
		unlock()
		t.Fatal("fixture did not negotiate verified TLS 1.3 and H2")
	}
	f.wait(f.wire.started, "SETTINGS ACK entering the blocked TLS writer")
	cause := errors.New("caller canceled after verified CONNECT proof")
	if gate != nil {
		cancel(cause)
		f.wait(caller.Done(), "actual caller cancellation")
	}
	if mode == "bootstrap_lost_selection" {
		// The proof remains valid. Only the selected session is invalidated
		// under the held application mutex, so completeSessionBootstrap must
		// reject its late result. This is not an invalid-MAC test.
		f.client.current = nil
	}
	unlock()

	// This is an assertion deadline after a witnessed blocking event,
	// not a sleep used to manufacture the scheduling order. The wire's
	// production write timeout is deliberately much longer (30s).
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Error("failed-response DialContext waited for the stalled SETTINGS ACK writer")
		f.release()
		f.wait(joined, "failed DialContext after explicit fixture release")
	}
	got := <-result
	if got.conn != nil {
		_ = got.conn.Close()
		t.Fatal("failed or canceled CONNECT returned a tunnel")
	}
	if mode == "bootstrap_lost_selection" {
		if got.err == nil || !strings.Contains(got.err.Error(), "server authentication failed") {
			t.Fatalf("late bootstrap result = %v, want authentication failure", got.err)
		}
		f.client.mu.Lock()
		opening, active, registered := session.opening, session.active, len(f.client.sessions)
		failed := session.authState == webH2ClientAuthFailed
		f.client.mu.Unlock()
		if !failed || opening != 0 || active != 0 || registered != 0 || f.wire.closes.Load() == 0 {
			t.Errorf("rejected bootstrap failed/opening/active/registered/raw-closes=%t/%d/%d/%d/%d", failed, opening, active, registered, f.wire.closes.Load())
		}
		return
	}
	var connectErr *WebConnectError
	if gate != nil {
		if !errors.Is(got.err, cause) || !gate.gated.Load() || gate.expired.Load() {
			t.Fatalf("canceled handoff error=%v, gated/expired=%t/%t", got.err, gate.gated.Load(), gate.expired.Load())
		}
	} else if !errors.As(got.err, &connectErr) || connectErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("authenticated HTTP error = %v, want status-bound 502", got.err)
	}
	if !f.released {
		f.client.mu.Lock()
		current, opening, active := f.client.current == session, session.opening, session.active
		f.client.mu.Unlock()
		if !current || opening != 1 || active != 0 || f.wire.closes.Load() != 0 {
			t.Errorf("pending cleanup current/opening/active/raw-closes=%t/%d/%d/%d, want true/1/0/0", current, opening, active, f.wire.closes.Load())
		}
	}
	if mode == "client_close" {
		closed := make(chan struct{})
		go func() { _ = f.client.Close(); close(closed) }()
		f.joins = append(f.joins, closed)
		f.wait(closed, "Client.Close joins pending response cleanup while ACK is blocked")
		f.client.mu.Lock()
		opening, active, registered := session.opening, session.active, len(f.client.sessions)
		f.client.mu.Unlock()
		if opening != 0 || active != 0 || registered != 0 || f.wire.closes.Load() == 0 {
			t.Errorf("joined cleanup opening/active/registered/raw-closes=%d/%d/%d/%d, want 0/0/0/positive", opening, active, registered, f.wire.closes.Load())
		}
		return
	}
	f.release()
	f.wait(f.firstReset, "failed stream reset after writer release")

	// A second public DialContext must use the same physical TLS/H2
	// connection and its real short-ticket continuation authentication.
	healthy, err := f.client.DialContext(f.ctx, "tcp", "owned.invalid:443")
	if err != nil {
		t.Fatalf("healthy continuation after failed response: %v", err)
	}
	defer healthy.Close()
	if err := healthy.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(healthy, "healthy sibling"); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, len("healthy sibling"))
	if _, err := io.ReadFull(healthy, body); err != nil || string(body) != "healthy sibling" {
		t.Fatalf("healthy continuation echo failed: %v", err)
	}
	f.client.mu.Lock()
	same := f.client.current == session
	f.client.mu.Unlock()
	if !same || f.wire.closes.Load() != 0 {
		t.Fatal("failed response cleanup replaced or closed the healthy physical session")
	}
}

type webH2FailedResponseResult struct {
	conn net.Conn
	err  error
}

type webH2FailedResponseFixture struct {
	t               *testing.T
	ctx             context.Context
	client          *WebH2Client
	wire            *webH2StalledWriter
	requestReceived chan struct{}
	respond         chan struct{}
	resume          chan struct{}
	firstReset      chan struct{}
	firstStatus     int
	releaseHandoff  func()
	released        bool // owned only by the test goroutine
	joins           []<-chan struct{}
}

func newWebH2FailedResponseFixture(t *testing.T, profile FingerprintProfile, status int) *webH2FailedResponseFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	raw, peer := net.Pipe()
	wire := &webH2StalledWriter{Conn: raw, started: make(chan struct{})}
	serverTLS, clientTLS := testTLSConfigs(t)
	serverTLS.NextProtos = []string{webH2ALPN}
	client, err := NewWebH2Client(WebH2ClientConfig{ServerAddress: "127.0.0.1:443", Token: webTestToken,
		TLSConfig: clientTLS, FingerprintProfile: profile, HandshakeTimeout: 5 * time.Second})
	if err != nil {
		cancel()
		_ = raw.Close()
		_ = peer.Close()
		t.Fatal(err)
	}
	var dialOnce sync.Once
	client.dialer = transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
		var result net.Conn
		dialOnce.Do(func() { result = wire })
		if result == nil {
			return nil, errors.New("fixture refuses a replacement physical dial")
		}
		return result, nil
	})
	f := &webH2FailedResponseFixture{t: t, ctx: ctx, client: client, wire: wire,
		requestReceived: make(chan struct{}), respond: make(chan struct{}), resume: make(chan struct{}), firstReset: make(chan struct{}), firstStatus: status}
	serverJoined := make(chan struct{})
	f.joins = append(f.joins, serverJoined)
	serverResult := make(chan error, 1)
	t.Cleanup(func() {
		cancel()
		_ = raw.Close()
		_ = peer.Close()
		closed := make(chan struct{})
		go func() { _ = client.Close(); close(closed) }()
		for _, joined := range append(f.joins, closed) {
			select {
			case <-joined:
			case <-time.After(2 * time.Second):
				t.Error("failed-response fixture did not join an owned worker")
			}
		}
		select {
		case err := <-serverResult:
			if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
				t.Errorf("failed-response peer: %v", err)
			}
		default:
			t.Error("failed-response peer result absent after cleanup join")
		}
	})
	go func() {
		defer close(serverJoined)
		serverResult <- f.serve(peer, serverTLS)
	}()
	return f
}

func (f *webH2FailedResponseFixture) wait(done <-chan struct{}, name string) {
	f.t.Helper()
	select {
	case <-done:
	case <-f.ctx.Done():
		f.t.Fatalf("%s exceeded independent fixture budget", name)
	}
}

func (f *webH2FailedResponseFixture) release() {
	if !f.released {
		f.released = true
		close(f.resume)
	}
}

func (f *webH2FailedResponseFixture) dial(ctx context.Context) (<-chan webH2FailedResponseResult, <-chan struct{}) {
	result, joined := make(chan webH2FailedResponseResult, 1), make(chan struct{})
	f.joins = append(f.joins, joined)
	go func() {
		defer close(joined)
		conn, err := f.client.DialContext(ctx, "tcp", "owned.invalid:443")
		result <- webH2FailedResponseResult{conn, err}
	}()
	return result, joined
}

func (f *webH2FailedResponseFixture) serve(peer net.Conn, serverTLS *tls.Config) error {
	deadline, _ := f.ctx.Deadline()
	_ = peer.SetDeadline(deadline)
	conn := tls.Server(peer, serverTLS)
	if err := conn.HandshakeContext(f.ctx); err != nil {
		return err
	}
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		return err
	}
	if string(preface) != http2.ClientPreface {
		return errors.New("unexpected HTTP/2 preface")
	}
	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	for range 2 {
		if _, err := fr.ReadFrame(); err != nil {
			return err
		}
	}
	if err := fr.WriteSettings(); err != nil {
		return err
	}
	key, err := deriveWebAuthKey(webTestToken)
	if err != nil {
		return err
	}
	verifier, err := newWebAuthVerifier(key, nil, 16)
	if err != nil {
		return err
	}
	var auth *webSessionServerAuth
	var firstStream uint32
	startupAck := false
	var encoded bytes.Buffer
	encoder := hpack.NewEncoder(&encoded)
	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			return err
		}
		switch frame := frame.(type) {
		case *http2.MetaHeadersFrame:
			// HEADERS can arrive before the initial SETTINGS ACK. Drain that
			// ACK before pausing peer reads, so only the deliberately later
			// SETTINGS can hold the client's writer during the response.
			for !startupAck {
				pending, err := fr.ReadFrame()
				if err != nil {
					return err
				}
				if settings, ok := pending.(*http2.SettingsFrame); ok && settings.IsAck() {
					startupAck = true
				}
			}
			binding := webAuthBinding{transport: webAuthTransportH2, method: frame.PseudoValue("method"), authority: frame.PseudoValue("authority")}
			var bearer string
			for _, field := range frame.RegularFields() {
				if field.Name == "proxy-authorization" {
					bearer = field.Value
				}
			}
			status, proof := http.StatusOK, ""
			if auth == nil {
				claims, valid := verifier.verifyBearer(bearer, binding)
				if !valid {
					return errors.New("fixture received invalid full authentication")
				}
				status = f.firstStatus
				proof, auth, err = issueWebSessionBootstrap(key, binding, claims, status, nil)
				if err != nil {
					return err
				}
				firstStream = frame.StreamID
				close(f.requestReceived)
				select {
				case <-f.respond:
				case <-f.ctx.Done():
					return f.ctx.Err()
				}
			} else {
				exchange, valid := auth.verifyAuthorization(bearer, binding)
				if !valid {
					return errors.New("fixture received invalid continuation authentication")
				}
				proof = auth.responseProof(binding, exchange, status)
			}
			encoded.Reset()
			for _, field := range []hpack.HeaderField{{Name: ":status", Value: strconv.Itoa(status)}, {Name: "proxy-authentication-info", Value: proof}} {
				if err := encoder.WriteField(field); err != nil {
					return err
				}
			}
			if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: frame.StreamID, BlockFragment: encoded.Bytes(), EndHeaders: true}); err != nil {
				return err
			}
			if frame.StreamID == firstStream {
				if err := fr.WriteData(firstStream, false, []byte("unread authenticated error")); err != nil {
					return err
				}
				f.wire.signal.Store(true)
				if err := fr.WriteSettings(); err != nil {
					return err
				}
				select {
				case <-f.resume:
				case <-f.ctx.Done():
					return f.ctx.Err()
				}
			}
		case *http2.SettingsFrame:
			if !frame.IsAck() {
				return fmt.Errorf("unexpected additional non-ACK client SETTINGS")
			}
			startupAck = true
		case *http2.RSTStreamFrame:
			if frame.StreamID == firstStream {
				select {
				case <-f.firstReset:
				default:
					close(f.firstReset)
				}
			}
		case *http2.DataFrame:
			if frame.StreamID != firstStream && len(frame.Data()) != 0 {
				if err := fr.WriteData(frame.StreamID, frame.StreamEnded(), append([]byte(nil), frame.Data()...)); err != nil {
					return err
				}
			}
		}
	}
}
