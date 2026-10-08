package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

func TestWebH2ResumptionHRRInitializationCancellation(t *testing.T) {
	for _, stage := range []string{"hrr_read", "h2_preface"} {
		t.Run(stage, func(t *testing.T) {
			for _, mode := range []string{"handshake_timeout", "caller_cancel", "client_close"} {
				t.Run(mode, func(t *testing.T) {
					fixture := webH2HRRPrime(t)
					fixture.client.handshakeTimeout = 1500 * time.Millisecond
					warm := webH2HRRInstallWarm(t, fixture)
					warm.blockPreface = stage == "h2_preface"
					caller, cancel := context.WithCancelCause(context.Background())
					defer cancel(context.Canceled)
					openDone := webH2HRROpenWorker(t, fixture.client, caller, warm)
					select {
					case <-warm.started:
					case <-time.After(2 * time.Second):
						t.Fatal("warm HRR TLS read was not reached")
					}
					webH2HRRWaitForSecondHello(t, fixture)
					if stage == "h2_preface" {
						warm.releaseOnce.Do(func() { close(warm.release) })
						select {
						case <-warm.preface:
						case err := <-openDone:
							t.Fatalf("resumed HRR did not reach H2 preface: %v", err)
						case <-time.After(time.Second):
							t.Fatal("resumed HRR did not reach H2 preface")
						}
						webH2HRRReadAttempt(t, newWebH2HRRAttemptCollector(fixture.attempts), 1, true)
					}
					want := error(context.DeadlineExceeded)
					switch mode {
					case "caller_cancel":
						want = errors.New("caller cancelled HRR initialization")
						cancel(want)
					case "client_close":
						want = context.Canceled
						if err := fixture.client.Close(); err != nil {
							t.Fatal(err)
						}
					}
					select {
					case err := <-openDone:
						if !errors.Is(err, want) {
							t.Fatalf("HRR initialization error = %v, want %v", err, want)
						}
					case <-time.After(2 * time.Second):
						t.Fatal("HRR initialization ignored cancellation/budget")
					}
					select {
					case <-warm.closed:
					default:
						t.Fatal("failed HRR initializer retained its raw connection")
					}
					if stage == "hrr_read" {
						webH2HRRCheckWarmHRR(t, fixture)
					}
					fixture.assertEmpty(t, 2)
				})
			}
		})
	}
}

func TestWebH2ResumptionHRRWriteFailureDoesNotRetry(t *testing.T) {
	fixture := webH2HRRPrime(t)
	warm := webH2HRRInstallWarm(t, fixture)
	// Even the retired library's exact error text is only an I/O failure here.
	// A genuine HRR must not turn it into an extra cold physical connection.
	fault := errors.New("uTLS does not support reprocessing of PSK key triggered by HelloRetryRequest")
	warm.secondHelloError = fault
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := webH2HRROpenWorker(t, fixture.client, ctx, warm)
	select {
	case <-warm.started:
	case <-ctx.Done():
		t.Fatal("warm HRR read was not reached")
	}
	webH2HRRWaitForSecondHello(t, fixture)
	warm.releaseOnce.Do(func() { close(warm.release) })
	select {
	case err := <-done:
		if !errors.Is(err, fault) {
			t.Fatalf("second ClientHello write failure = %v, want original cause", err)
		}
	case <-ctx.Done():
		t.Fatal("second ClientHello write failure did not return")
	}
	if warm.clientHellos != 2 {
		t.Fatalf("fault injected at ClientHello %d, want 2", warm.clientHellos)
	}
	webH2HRRCheckWarmHRR(t, fixture)
	fixture.assertEmpty(t, 2)
}

func TestWebH2ResumptionDoesNotRetryOtherTLSErrors(t *testing.T) {
	for _, mode := range []string{"certificate", "alpn", "matching_text_without_hrr"} {
		t.Run(mode, func(t *testing.T) {
			fixture := webH2HRRPrime(t)
			serverTLS := fixture.serverTLS.Clone()
			serverTLS.SessionTicketsDisabled = true
			serverTLS.CurvePreferences = []tls.CurveID{tls.X25519}
			if mode == "certificate" {
				serverTLS, _ = webH2ResumptionTLSConfigs(t)
				serverTLS.SessionTicketsDisabled = true
			}
			if mode == "alpn" {
				serverTLS.NextProtos = []string{webHTTP11ALPN}
			}
			// The retired dependency's diagnostic must remain an ordinary
			// callback failure, not an instruction to open another connection.
			fault := errors.New("uTLS does not support reprocessing of PSK key triggered by HelloRetryRequest")
			if mode == "matching_text_without_hrr" {
				fixture.client.tlsConfig.VerifyPeerCertificate = func(_ [][]byte, _ [][]*x509.Certificate) error { return fault }
			}
			observed := make(chan *webH2HRRWireConn, 1)
			var raw *webH2HRRRaw
			fixture.client.dialer = transport.DialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
				if fixture.calls.Add(1) != 2 {
					return nil, errors.New("unexpected retry for ordinary TLS failure")
				}
				conn, err := webH2HRROtherTLSPeer(t, ctx, serverTLS, observed)
				if err != nil {
					return nil, err
				}
				raw = &webH2HRRRaw{Conn: conn, closed: make(chan struct{})}
				return raw, nil
			})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, err := fixture.client.openSession(ctx)
			switch mode {
			case "certificate":
				var untrusted x509.UnknownAuthorityError
				if !errors.As(err, &untrusted) {
					t.Fatalf("ordinary certificate failure = %v", err)
				}
			case "alpn":
				if err == nil || !strings.Contains(err.Error(), "did not negotiate h2") {
					t.Fatalf("ordinary ALPN failure = %v", err)
				}
			case "matching_text_without_hrr":
				if !errors.Is(err, fault) {
					t.Fatalf("certificate callback failure = %v", err)
				}
			}
			select {
			case <-raw.closed:
			default:
				t.Fatal("ordinary TLS failure retained its raw connection")
			}
			var wire *webH2HRRWireConn
			select {
			case wire = <-observed:
			case <-time.After(2 * time.Second):
				t.Fatal("ordinary TLS failure peer was not observed")
			}
			hello, hrr, _, parseErr := wire.snapshot()
			if parseErr != nil || hrr || !containsUint16(hello.extensions, 41) {
				t.Fatalf("ordinary failed warm attempt: parse=%v HRR=%t PSK=%t", parseErr, hrr, containsUint16(hello.extensions, 41))
			}
			fixture.assertEmpty(t, 2)
		})
	}
}

type webH2HRRFixture struct {
	client             *WebH2Client
	serverTLS          *tls.Config
	attempts           <-chan webH2HRRAttempt
	calls              atomic.Int64
	destination        *atomic.Int64
	waitingSecondHello <-chan struct{}
}

// GET primes only TLS tickets and H2 initialization, deliberately bypassing
// CONNECT/app authentication. Healthy authenticated HRR tests live separately.
func webH2HRRPrime(t *testing.T) *webH2HRRFixture {
	t.Helper()
	serverTLS, config := webH2ResumptionTLSConfigs(t)
	waitingSecondHello := make(chan struct{})
	address, attempts, requests, handlerDone, destination := webH2HRRServer(t, serverTLS, "unused.invalid:443", 2, waitingSecondHello)
	config.ClientSessionCache = tls.NewLRUClientSessionCache(2)
	client, err := NewWebH2Client(WebH2ClientConfig{ServerAddress: address, Token: webTestToken, TLSConfig: config, HandshakeTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	fixture := &webH2HRRFixture{client: client, serverTLS: serverTLS, attempts: attempts, destination: destination, waitingSecondHello: waitingSecondHello}
	client.dialer = transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		fixture.calls.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, address)
	})
	t.Cleanup(func() { _ = client.Close() })
	cache := &webH2ResumptionUTLSCache{inner: client.utlsSessionCache}
	client.utlsSessionCache = cache
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	session, err := client.openSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.raw.Close(); _ = session.h2.Close() })
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address+"/prime", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := session.h2.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusNotFound || cache.puts.Load() == 0 {
		t.Fatalf("ordinary GET prime: status=%d read=%v ticket puts=%d", response.StatusCode, readErr, cache.puts.Load())
	}
	select {
	case request := <-requests:
		if request.physical != 0 || request.bearerBytes != 0 {
			t.Fatal("ticket prime unexpectedly used application authentication")
		}
	case <-ctx.Done():
		t.Fatal("ordinary GET prime was not observed")
	}
	select {
	case <-handlerDone:
	case <-ctx.Done():
		t.Fatal("ordinary prime handler did not return")
	}
	select {
	case attempt := <-attempts:
		if attempt.sequence != 0 || !attempt.hrr || attempt.err != nil || containsUint16(attempt.hello.extensions, 41) {
			t.Fatalf("prime was not real cold HRR: %+v", attempt)
		}
	case <-ctx.Done():
		t.Fatal("cold HRR prime was not observed")
	}
	_ = session.raw.Close()
	_ = session.h2.Close()
	return fixture
}

func (f *webH2HRRFixture) assertEmpty(t *testing.T, wantCalls int64) {
	t.Helper()
	f.client.mu.Lock()
	registered, current, selected := len(f.client.sessions), f.client.current, f.client.selected
	f.client.mu.Unlock()
	if f.calls.Load() != wantCalls || registered != 0 || current != nil || selected || f.destination.Load() != 0 {
		t.Fatalf("calls/sessions/current/selected/destination=%d/%d/%p/%t/%d", f.calls.Load(), registered, current, selected, f.destination.Load())
	}
}

func webH2HRRWaitForSecondHello(t *testing.T, fixture *webH2HRRFixture) {
	t.Helper()
	select {
	case <-fixture.waitingSecondHello:
	case <-time.After(time.Second):
		t.Fatal("TLS peer did not finish its HRR flight and wait for ClientHello 2")
	}
}

type webH2HRRRaw struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *webH2HRRRaw) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

type webH2HRRWarm struct {
	*webH2HRRRaw
	started          chan struct{}
	release          chan struct{}
	preface          chan struct{}
	readOnce         sync.Once
	releaseOnce      sync.Once
	blockPreface     bool
	clientHellos     int
	encryptedWrites  int
	secondHelloError error
}

func (c *webH2HRRWarm) Read(p []byte) (int, error) {
	c.readOnce.Do(func() {
		close(c.started)
		select {
		case <-c.release:
		case <-c.closed:
		}
	})
	return c.Conn.Read(p)
}

func (c *webH2HRRWarm) Write(p []byte) (int, error) {
	for records := p; len(records) >= 5; {
		length := 5 + int(binary.BigEndian.Uint16(records[3:5]))
		if length > len(records) {
			return 0, errors.New("test received fragmented outgoing TLS record")
		}
		if records[0] == 22 && length > 5 && records[5] == 1 {
			c.clientHellos++
			if c.clientHellos == 2 && c.secondHelloError != nil {
				return 0, c.secondHelloError
			}
		}
		if records[0] == 23 {
			c.encryptedWrites++
			// With no early_data, the first encrypted client record is TLS
			// Finished; the next is the H2 preface. Independently verify the
			// peer's completed, resumed HRR before canceling the blocked write.
			if c.blockPreface && c.encryptedWrites == 2 {
				close(c.preface)
				<-c.closed
				return 0, net.ErrClosed
			}
		}
		records = records[length:]
	}
	return c.Conn.Write(p)
}

func webH2HRRInstallWarm(t *testing.T, fixture *webH2HRRFixture) *webH2HRRWarm {
	t.Helper()
	warm := &webH2HRRWarm{started: make(chan struct{}), release: make(chan struct{}), preface: make(chan struct{})}
	fixture.client.dialer = transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if fixture.calls.Add(1) != 2 {
			return nil, errors.New("unexpected extra connection after HRR")
		}
		raw, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		warm.webH2HRRRaw = &webH2HRRRaw{Conn: raw, closed: make(chan struct{})}
		return warm, nil
	})
	return warm
}

func webH2HRRCheckWarmHRR(t *testing.T, fixture *webH2HRRFixture) {
	t.Helper()
	// Prime evidence was consumed before the warm initializer began, so only
	// this attempt can be present; no completion-order assumption is made.
	select {
	case attempt := <-fixture.attempts:
		peerCloseError := errors.Is(attempt.err, io.EOF) || errors.Is(attempt.err, syscall.ECONNRESET)
		if attempt.sequence != 1 || !attempt.hrr || !containsUint16(attempt.hello.extensions, 41) || !attempt.peerClosed || !peerCloseError {
			t.Fatalf("warm HRR was not a real client-closed HRR+PSK failure: sequence=%d HRR=%t PSK=%t peerClosed=%t err=%T/%v", attempt.sequence, attempt.hrr, containsUint16(attempt.hello.extensions, 41), attempt.peerClosed, attempt.err, attempt.err)
		}
		t.Log("real P256 HRR + populated PSK confirmed; physical peer closed before test cleanup")
	case <-time.After(2 * time.Second):
		t.Fatal("warm HRR attempt was not observed")
	}
}

func webH2HRROpenWorker(t *testing.T, client *WebH2Client, ctx context.Context, warm *webH2HRRWarm) <-chan error {
	t.Helper()
	return webH2HRRWorker(t, func() error {
		session, err := client.openSession(ctx)
		if session != nil {
			_ = session.raw.Close()
			_ = session.h2.Close()
			return errors.New("failed initialization unexpectedly returned a session")
		}
		return err
	}, func() { _ = client.Close(); warm.releaseOnce.Do(func() { close(warm.release) }) })
}

func webH2HRRWorker(t *testing.T, run func() error, stop func()) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	joined := make(chan struct{})
	t.Cleanup(func() {
		stop()
		select {
		case <-joined:
		case <-time.After(2 * time.Second):
			t.Error("HRR test worker did not join")
		}
	})
	go func() { defer close(joined); defer close(done); done <- run() }()
	return done
}

func webH2HRROtherTLSPeer(t *testing.T, ctx context.Context, serverTLS *tls.Config, observed chan<- *webH2HRRWireConn) (net.Conn, error) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	defer listener.Close()
	_ = listener.SetDeadline(time.Now().Add(time.Second))
	raw, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		return nil, err
	}
	peer, err := listener.Accept()
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	config := serverTLS.Clone()
	config.MinVersion, config.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	if len(config.NextProtos) == 0 {
		config.NextProtos = []string{webH2ALPN}
	}
	config.CurvePreferences = []tls.CurveID{tls.X25519}
	config.SessionTicketsDisabled = true
	wire := &webH2HRRWireConn{Conn: peer}
	if observed != nil {
		observed <- wire
	}
	serverCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	deadline, _ := serverCtx.Deadline()
	_ = peer.SetDeadline(deadline)
	webH2HRRWorker(t, func() error { return tls.Server(wire, config).HandshakeContext(serverCtx) }, func() { cancel(); _ = raw.Close(); _ = peer.Close() })
	return raw, nil
}
