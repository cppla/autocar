package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

func TestWebH2ResumptionFallbackInitializationSharesBudgetAndCancellation(t *testing.T) {
	for _, stage := range []string{"redial", "h2_preface"} {
		t.Run(stage, func(t *testing.T) {
			for _, mode := range []string{"handshake_timeout", "caller_cancel", "client_close"} {
				t.Run(mode, func(t *testing.T) {
					fixture := webH2FallbackPrime(t)
					const budget = 1500 * time.Millisecond
					fixture.client.handshakeTimeout = budget
					warm := webH2FallbackInstallWarm(t, fixture)
					atFallback := make(chan context.Context, 1)
					var fresh *webH2InitializationWire
					var serverDone <-chan error
					var verified atomic.Pointer[webH2InitializationWire]
					fixture.client.tlsConfig.VerifyPeerCertificate = func(_ [][]byte, _ [][]*x509.Certificate) error {
						if wire := verified.Load(); wire != nil {
							wire.verified.Store(true)
						}
						return nil
					}
					warm.fresh = func(ctx context.Context) (net.Conn, error) {
						if stage == "redial" {
							atFallback <- ctx
							<-ctx.Done()
							return nil, ctx.Err()
						}
						raw, peer := net.Pipe()
						freshWire := &webH2InitializationWire{Conn: raw, initializing: make(chan struct{}), closed: make(chan struct{})}
						verified.Store(freshWire)
						serverTLS := fixture.serverTLS.Clone()
						serverTLS.MinVersion, serverTLS.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
						serverTLS.NextProtos = []string{webH2ALPN}
						serverTLS.SessionTicketsDisabled = true
						serverCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
						deadline, _ := serverCtx.Deadline()
						_ = peer.SetDeadline(deadline)
						serverDone = webH2FallbackWorker(t, func() error {
							return tls.Server(peer, serverTLS).HandshakeContext(serverCtx)
						}, func() { cancel(); _ = raw.Close(); _ = peer.Close() })
						atFallback <- ctx
						return freshWire, nil
					}
					caller, cancel := context.WithCancelCause(context.Background())
					defer cancel(context.Canceled)
					openDone := webH2FallbackOpenWorker(t, fixture.client, caller, warm)
					firstRead := webH2FallbackReleaseWarm(t, warm, budget/3)
					var fallbackCtx context.Context
					select {
					case fallbackCtx = <-atFallback:
					case err := <-openDone:
						t.Fatalf("initializer did not enter real HRR fallback: %v", err)
					case <-time.After(2 * time.Second):
						t.Fatal("fallback redial was not reached")
					}
					deadline, ok := fallbackCtx.Deadline()
					// These causal timestamps bracket creation of the ORIGINAL
					// initialization context, independent of scheduler delays.
					// Waiting budget/3 before releasing the real HRR makes a
					// newly restarted full budget fall outside this window.
					if !ok || deadline.Before(warm.returned.Add(budget)) || deadline.After(firstRead.Add(budget)) {
						t.Fatalf("fallback deadline %v not in original budget window [%v,%v]", deadline, warm.returned.Add(budget), firstRead.Add(budget))
					}
					if stage == "h2_preface" {
						// The fresh pointer/worker are published by the dial callback
						// before its TLS exchange; wait for its actual H2 write.
						select {
						case <-verified.Load().initializing:
						case err := <-openDone:
							t.Fatalf("fallback did not reach H2 preface: %v", err)
						case <-time.After(2 * time.Second):
							t.Fatal("fresh TLS connection did not reach H2 preface")
						}
						fresh = verified.Load()
						select {
						case err := <-serverDone:
							if err != nil {
								t.Fatalf("fresh fallback TLS handshake: %v", err)
							}
						case <-time.After(2 * time.Second):
							t.Fatal("fresh fallback TLS worker did not report")
						}
						select {
						case <-fresh.closed:
							t.Fatal("old attempt's cleanup prematurely closed the fresh connection")
						default:
						}
					}
					want := error(context.DeadlineExceeded)
					switch mode {
					case "caller_cancel":
						want = errors.New("caller cancelled fallback initialization")
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
							t.Fatalf("fallback initialization error = %v, want %v", err, want)
						}
					case <-time.After(2 * time.Second):
						t.Fatal("fallback initialization ignored its cancellation/budget")
					}
					if stage == "h2_preface" {
						select {
						case <-fresh.closed:
						default:
							t.Fatal("failed fallback initializer retained its fresh raw connection")
						}
					}
					webH2FallbackCheckWarmHRR(t, fixture)
					fixture.assertEmpty(t, 3)
				})
			}
		})
	}
}

func TestWebH2ResumptionFallbackSecondFailureDoesNotLoop(t *testing.T) {
	for _, mode := range []string{"redial_error", "fresh_tls_certificate_error"} {
		t.Run(mode, func(t *testing.T) {
			fixture := webH2FallbackPrime(t)
			warm := webH2FallbackInstallWarm(t, fixture)
			fault := errors.New("fresh fallback dial failed")
			untrustedTLS, _ := webH2ResumptionTLSConfigs(t)
			warm.fresh = func(ctx context.Context) (net.Conn, error) {
				if mode == "redial_error" {
					return nil, fault
				}
				return webH2FallbackOtherTLSPeer(t, ctx, untrustedTLS, nil)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			openDone := webH2FallbackOpenWorker(t, fixture.client, ctx, warm)
			webH2FallbackReleaseWarm(t, warm, 0)
			select {
			case err := <-openDone:
				if mode == "redial_error" {
					if !errors.Is(err, fault) {
						t.Fatalf("redial failure = %v", err)
					}
				} else {
					var untrusted x509.UnknownAuthorityError
					if !errors.As(err, &untrusted) {
						t.Fatalf("fresh certificate failure = %v", err)
					}
				}
			case <-ctx.Done():
				t.Fatal("second initialization failure did not return")
			}
			webH2FallbackCheckWarmHRR(t, fixture)
			fixture.assertEmpty(t, 3)
		})
	}
}

func TestWebH2ResumptionFallbackDoesNotRetryOtherTLSErrors(t *testing.T) {
	for _, mode := range []string{"certificate", "alpn", "matching_text_without_hrr"} {
		t.Run(mode, func(t *testing.T) {
			fixture := webH2FallbackPrime(t)
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
			// Keep the pinned dependency error text independent of production's
			// classifier, so an old-production overlay can exercise this test.
			fault := errors.New("uTLS does not support reprocessing of PSK key triggered by HelloRetryRequest")
			if mode == "matching_text_without_hrr" {
				fixture.client.tlsConfig.VerifyPeerCertificate = func(_ [][]byte, _ [][]*x509.Certificate) error { return fault }
			}
			observed := make(chan *webH2HRRWireConn, 1)
			var raw *webH2FallbackRaw
			fixture.client.dialer = transport.DialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
				if fixture.calls.Add(1) != 2 {
					return nil, errors.New("unexpected retry for ordinary TLS failure")
				}
				conn, err := webH2FallbackOtherTLSPeer(t, ctx, serverTLS, observed)
				if err != nil {
					return nil, err
				}
				raw = &webH2FallbackRaw{Conn: conn, closed: make(chan struct{})}
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

type webH2FallbackFixture struct {
	client      *WebH2Client
	serverTLS   *tls.Config
	attempts    <-chan webH2HRRAttempt
	calls       atomic.Int64
	destination *atomic.Int64
}

// GET primes only TLS tickets and H2 initialization, deliberately bypassing
// CONNECT/app authentication. Healthy authenticated HRR tests live separately.
func webH2FallbackPrime(t *testing.T) *webH2FallbackFixture {
	t.Helper()
	serverTLS, config := webH2ResumptionTLSConfigs(t)
	address, attempts, requests, handlerDone, destination := webH2HRRServer(t, serverTLS, "unused.invalid:443", 2)
	config.ClientSessionCache = tls.NewLRUClientSessionCache(2)
	client, err := NewWebH2Client(WebH2ClientConfig{ServerAddress: address, Token: webTestToken, TLSConfig: config, HandshakeTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	fixture := &webH2FallbackFixture{client: client, serverTLS: serverTLS, attempts: attempts, destination: destination}
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

func (f *webH2FallbackFixture) assertEmpty(t *testing.T, wantCalls int64) {
	t.Helper()
	f.client.mu.Lock()
	registered, current, selected := len(f.client.sessions), f.client.current, f.client.selected
	f.client.mu.Unlock()
	if f.calls.Load() != wantCalls || registered != 0 || current != nil || selected || f.destination.Load() != 0 {
		t.Fatalf("calls/sessions/current/selected/destination=%d/%d/%p/%t/%d", f.calls.Load(), registered, current, selected, f.destination.Load())
	}
}

type webH2FallbackRaw struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *webH2FallbackRaw) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

type webH2FallbackWarm struct {
	*webH2FallbackRaw
	started     chan time.Time
	release     chan struct{}
	readOnce    sync.Once
	releaseOnce sync.Once
	returned    time.Time
	fresh       func(context.Context) (net.Conn, error)
}

func (c *webH2FallbackWarm) Read(p []byte) (int, error) {
	c.readOnce.Do(func() {
		c.started <- time.Now()
		select {
		case <-c.release:
		case <-c.closed:
		}
	})
	return c.Conn.Read(p)
}

func webH2FallbackInstallWarm(t *testing.T, fixture *webH2FallbackFixture) *webH2FallbackWarm {
	t.Helper()
	warm := &webH2FallbackWarm{started: make(chan time.Time, 1), release: make(chan struct{})}
	fixture.client.dialer = transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		switch fixture.calls.Add(1) {
		case 2:
			raw, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			warm.webH2FallbackRaw = &webH2FallbackRaw{Conn: raw, closed: make(chan struct{})}
			warm.returned = time.Now()
			return warm, nil
		case 3:
			select {
			case <-warm.closed:
			default:
				return nil, errors.New("fallback redial began before old raw Close completed")
			}
			return warm.fresh(ctx)
		default:
			return nil, errors.New("initializer exceeded its single fresh retry")
		}
	})
	return warm
}

func webH2FallbackReleaseWarm(t *testing.T, warm *webH2FallbackWarm, delay time.Duration) time.Time {
	t.Helper()
	var started time.Time
	select {
	case started = <-warm.started:
	case <-time.After(2 * time.Second):
		t.Fatal("warm HRR TLS read was not reached")
	}
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		<-timer.C
	}
	warm.releaseOnce.Do(func() { close(warm.release) })
	return started
}

func webH2FallbackCheckWarmHRR(t *testing.T, fixture *webH2FallbackFixture) {
	t.Helper()
	// Prime evidence was consumed before the warm initializer began, so only
	// this attempt can be present; no completion-order assumption is made.
	select {
	case attempt := <-fixture.attempts:
		peerCloseError := errors.Is(attempt.err, io.EOF) || errors.Is(attempt.err, syscall.ECONNRESET)
		if attempt.sequence != 1 || !attempt.hrr || !containsUint16(attempt.hello.extensions, 41) || !attempt.peerClosed || !peerCloseError {
			t.Fatalf("warm fallback was not a real client-closed HRR+PSK failure: sequence=%d HRR=%t PSK=%t peerClosed=%t err=%T/%v", attempt.sequence, attempt.hrr, containsUint16(attempt.hello.extensions, 41), attempt.peerClosed, attempt.err, attempt.err)
		}
		t.Log("real P256 HRR + populated PSK confirmed; old physical peer closure before test cleanup")
	case <-time.After(2 * time.Second):
		t.Fatal("warm HRR attempt was not observed")
	}
}

func webH2FallbackOpenWorker(t *testing.T, client *WebH2Client, ctx context.Context, warm *webH2FallbackWarm) <-chan error {
	t.Helper()
	return webH2FallbackWorker(t, func() error {
		session, err := client.openSession(ctx)
		if session != nil {
			_ = session.raw.Close()
			_ = session.h2.Close()
			return errors.New("failed initialization unexpectedly returned a session")
		}
		return err
	}, func() { _ = client.Close(); warm.releaseOnce.Do(func() { close(warm.release) }) })
}

func webH2FallbackWorker(t *testing.T, run func() error, stop func()) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	joined := make(chan struct{})
	t.Cleanup(func() {
		stop()
		select {
		case <-joined:
		case <-time.After(2 * time.Second):
			t.Error("fallback test worker did not join")
		}
	})
	go func() { defer close(joined); defer close(done); done <- run() }()
	return done
}

func webH2FallbackOtherTLSPeer(t *testing.T, ctx context.Context, serverTLS *tls.Config, observed chan<- *webH2HRRWireConn) (net.Conn, error) {
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
	webH2FallbackWorker(t, func() error { return tls.Server(wire, config).HandshakeContext(serverCtx) }, func() { cancel(); _ = raw.Close(); _ = peer.Close() })
	return raw, nil
}
