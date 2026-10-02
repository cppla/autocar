package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestChrome133ResumptionPolicyFactoryIsLazy(t *testing.T) {
	for _, test := range []struct {
		name     string
		disabled bool
		cache    bool
		wantID   utls.ClientHelloID
	}{
		{name: "enabled-cache", cache: true, wantID: utls.HelloCustom},
		{name: "nil-cache", wantID: utls.HelloChrome_133},
		// Supplying a cache cannot override SessionTicketsDisabled.
		{name: "tickets-disabled-with-cache", disabled: true, cache: true, wantID: utls.HelloChrome_133},
	} {
		t.Run(test.name, func(t *testing.T) {
			entropy := &webResumptionPolicyRand{}
			raw := &webResumptionPolicyConn{}
			config := &tls.Config{
				ServerName:             "cover.example",
				Rand:                   entropy,
				ClientSessionCache:     tls.NewLRUClientSessionCache(1),
				SessionTicketsDisabled: test.disabled,
			}
			var cache utls.ClientSessionCache
			if test.cache {
				cache = utls.NewLRUClientSessionCache(1)
			}
			client, err := newWebH2TLSClientConn(raw, config, FingerprintChrome133, cache)
			if err != nil {
				t.Fatal(err)
			}
			chrome, ok := client.(*webH2UTLSConn)
			if !ok {
				t.Fatalf("Chrome client type = %T", client)
			}
			// Check uTLS's exported selected profile, not the wrapper's private
			// preparation fields. No ClientHello has been built or sent yet.
			if !reflect.DeepEqual(chrome.ClientHelloID, test.wantID) {
				t.Fatalf("selected ClientHelloID = %v, want %v", chrome.ClientHelloID, test.wantID)
			}
			if entropy.reads.Load() != 0 {
				t.Fatalf("connection factory consumed entropy: %d reads", entropy.reads.Load())
			}
			raw.assertUntouched(t)
		})
	}
}

func TestChrome133ResumptionPolicyPreCancelledHandshakeRemainsReusable(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	serverTLS.MinVersion = tls.VersionTLS13
	serverTLS.MaxVersion = tls.VersionTLS13
	serverTLS.NextProtos = []string{webH2ALPN}
	// This fixture tests preparation/cancellation, not ticket issuance.
	serverTLS.SessionTicketsDisabled = true
	clientTLS.ClientSessionCache = tls.NewLRUClientSessionCache(1)
	entropy := &webResumptionPolicyRand{}
	clientTLS.Rand = entropy
	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()
	raw := &webResumptionPolicyConn{Conn: clientPipe}
	client, err := newWebH2TLSClientConn(raw, clientTLS, FingerprintChrome133, newWebH2UTLSSessionCache(clientTLS))
	if err != nil {
		t.Fatal(err)
	}
	preCancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.HandshakeContext(preCancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled handshake error = %v, want context.Canceled", err)
	}
	if entropy.reads.Load() != 0 {
		t.Fatalf("pre-cancelled handshake consumed entropy: %d reads", entropy.reads.Load())
	}
	raw.assertUntouched(t)

	// Reuse exactly the same connection with a live context and an actual TLS
	// peer. Success proves cancellation did not consume the preparation once.
	ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	deadline, _ := ctx.Deadline()
	_ = clientPipe.SetDeadline(deadline)
	_ = serverPipe.SetDeadline(deadline)
	serverDone := webResumptionPolicyRunHandshake(t, func() error {
		return tls.Server(serverPipe, serverTLS).HandshakeContext(ctx)
	}, clientPipe, serverPipe)
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatalf("live handshake after cancellation: %v", err)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server handshake: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("server handshake did not finish")
	}
	state := client.ConnectionState()
	if !state.HandshakeComplete || state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != webH2ALPN || len(state.VerifiedChains) == 0 {
		t.Fatalf("live handshake state = %+v", state)
	}
	if entropy.reads.Load() == 0 || raw.reads.Load() == 0 || raw.writes.Load() == 0 {
		t.Fatal("live handshake did not consume entropy and exchange TLS records")
	}
	reads, writes, randomReads := raw.reads.Load(), raw.writes.Load(), entropy.reads.Load()
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatalf("repeat completed handshake: %v", err)
	}
	if err := client.HandshakeContext(preCancelled); err != nil {
		t.Fatalf("completed handshake with cancelled context: %v", err)
	}
	if raw.reads.Load() != reads || raw.writes.Load() != writes || entropy.reads.Load() != randomReads {
		t.Fatal("repeat completed handshake performed preparation or socket I/O again")
	}
}

func TestChrome133ResumptionPolicyConcurrentPreCancellationDoesNotWaitForPeer(t *testing.T) {
	entropy := &webResumptionPolicyRand{}
	config := &tls.Config{
		ServerName:         "cover.example",
		Rand:               entropy,
		ClientSessionCache: tls.NewLRUClientSessionCache(1),
	}
	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()
	raw := &webResumptionPolicyConn{Conn: clientPipe, writeStarted: make(chan struct{}, 1)}
	client, err := newWebH2TLSClientConn(raw, config, FingerprintChrome133, newWebH2UTLSSessionCache(config))
	if err != nil {
		t.Fatal(err)
	}
	firstContext, cancelFirst := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelFirst()
	deadline, _ := firstContext.Deadline()
	_ = clientPipe.SetDeadline(deadline)
	firstDone := webResumptionPolicyRunHandshake(t, func() error {
		return client.HandshakeContext(firstContext)
	}, clientPipe, serverPipe)
	select {
	case <-raw.writeStarted:
		// No peer reads this pipe, so the first TLS write remains blocked.
	case <-firstContext.Done():
		t.Fatal("first handshake did not reach its TLS write")
	}
	reads, writes, randomReads := raw.reads.Load(), raw.writes.Load(), entropy.reads.Load()
	preCancelled, cancel := context.WithCancel(context.Background())
	cancel()
	secondDone := webResumptionPolicyRunHandshake(t, func() error {
		return client.HandshakeContext(preCancelled)
	}, clientPipe, serverPipe)
	secondReturned := false
	select {
	case err := <-secondDone:
		secondReturned = true
		if !errors.Is(err, context.Canceled) {
			t.Errorf("second pre-cancelled handshake error = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("pre-cancelled handshake waited for the blocked first handshake")
	}
	if raw.reads.Load() != reads || raw.writes.Load() != writes || entropy.reads.Load() != randomReads || raw.closes.Load() != 0 {
		t.Error("second pre-cancelled handshake touched entropy or the raw connection")
	}
	select {
	case err := <-firstDone:
		t.Errorf("first handshake unexpectedly finished without a peer: %v", err)
		firstDone = nil
	default:
	}
	// Unblock and join both workers even if the cancellation assertion fails.
	cancelFirst()
	_ = clientPipe.Close()
	_ = serverPipe.Close()
	if firstDone != nil {
		select {
		case <-firstDone:
		case <-time.After(time.Second):
			t.Error("first handshake did not join after cancellation")
		}
	}
	if !secondReturned {
		select {
		case <-secondDone:
		case <-time.After(time.Second):
			t.Error("second handshake did not join after cancellation")
		}
	}
}

func TestChrome133ResumptionPolicyPreparationErrorIsStableAndDoesNotTouchSocket(t *testing.T) {
	fault := errors.New("resumption-policy entropy fault")
	entropy := &webResumptionPolicyRand{fault: fault}
	raw := &webResumptionPolicyConn{}
	config := &tls.Config{
		ServerName:         "cover.example",
		Rand:               entropy,
		ClientSessionCache: tls.NewLRUClientSessionCache(1),
	}
	client, err := newWebH2TLSClientConn(raw, config, FingerprintChrome133, newWebH2UTLSSessionCache(config))
	if err != nil {
		t.Fatalf("factory eagerly prepared the handshake: %v", err)
	}
	if entropy.reads.Load() != 0 {
		t.Fatal("factory read failing entropy source")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	first := client.HandshakeContext(ctx)
	if first == nil || !strings.Contains(first.Error(), fault.Error()) {
		t.Fatalf("preparation error = %v, want entropy fault", first)
	}
	reads := entropy.reads.Load()
	if reads == 0 {
		t.Fatal("preparation did not reach the failing entropy source")
	}
	for attempt := 0; attempt < 3; attempt++ {
		if err := client.HandshakeContext(ctx); err == nil || err.Error() != first.Error() {
			t.Fatalf("repeat preparation error = %v, want stable %v", err, first)
		}
		if entropy.reads.Load() != reads {
			t.Fatal("repeat failed preparation consumed entropy again")
		}
		raw.assertUntouched(t)
	}
	if client.ConnectionState().HandshakeComplete {
		t.Fatal("failed preparation marked the handshake complete")
	}
}

func TestChrome133ResumptionPolicyStillVerifiesPeer(t *testing.T) {
	for _, name := range []string{"untrusted-roots", "wrong-server-name"} {
		t.Run(name, func(t *testing.T) {
			serverTLS, clientTLS := testTLSConfigs(t)
			serverTLS.MinVersion = tls.VersionTLS13
			serverTLS.MaxVersion = tls.VersionTLS13
			serverTLS.NextProtos = []string{webH2ALPN}
			clientTLS.ClientSessionCache = tls.NewLRUClientSessionCache(1)
			if name == "untrusted-roots" {
				clientTLS.RootCAs = x509.NewCertPool()
			} else {
				clientTLS.ServerName = "wrong.example"
			}
			// TCP buffering permits the verification alert and server flight
			// to cross without net.Pipe's synchronous-write deadlock.
			clientPipe, serverPipe := webResumptionPolicyTCPPair(t)
			defer clientPipe.Close()
			defer serverPipe.Close()
			raw := &webResumptionPolicyConn{Conn: clientPipe}
			client, err := newWebH2TLSClientConn(raw, clientTLS, FingerprintChrome133, newWebH2UTLSSessionCache(clientTLS))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			deadline, _ := ctx.Deadline()
			_ = clientPipe.SetDeadline(deadline)
			_ = serverPipe.SetDeadline(deadline)
			serverDone := webResumptionPolicyRunHandshake(t, func() error {
				return tls.Server(serverPipe, serverTLS).HandshakeContext(ctx)
			}, clientPipe, serverPipe)
			err = client.HandshakeContext(ctx)
			if name == "untrusted-roots" {
				var untrusted x509.UnknownAuthorityError
				if !errors.As(err, &untrusted) {
					t.Fatalf("untrusted-root handshake error = %v", err)
				}
			} else {
				var wrongName x509.HostnameError
				if !errors.As(err, &wrongName) {
					t.Fatalf("wrong-name handshake error = %v", err)
				}
			}
			if client.ConnectionState().HandshakeComplete {
				t.Fatal("certificate verification failure completed the handshake")
			}
			if raw.reads.Load() == 0 || raw.writes.Load() == 0 {
				t.Fatal("verification test did not exchange TLS records with its peer")
			}
			_ = clientPipe.Close()
			_ = serverPipe.Close()
			select {
			case <-serverDone:
			case <-time.After(time.Second):
				t.Fatal("rejected TLS peer did not join")
			}
		})
	}
}

func webResumptionPolicyTCPPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_ = listener.SetDeadline(time.Now().Add(time.Second))
	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept()
	if err != nil {
		_ = client.Close()
		t.Fatal(err)
	}
	return client, server
}

func webResumptionPolicyRunHandshake(t *testing.T, run func() error, clientPipe, serverPipe net.Conn) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	joined := make(chan struct{})
	// A buffered result can arrive before the worker's deferred cleanup.
	// Wait for a separate completion signal on success and Fatal paths.
	t.Cleanup(func() {
		_ = clientPipe.Close()
		_ = serverPipe.Close()
		select {
		case <-joined:
		case <-time.After(2 * time.Second):
			t.Error("TLS handshake worker did not join after closing both pipe ends")
		}
	})
	go func() {
		defer close(joined)
		defer close(done)
		done <- run()
	}()
	return done
}

type webResumptionPolicyRand struct {
	reads atomic.Int64
	fault error
}

func (r *webResumptionPolicyRand) Read(p []byte) (int, error) {
	r.reads.Add(1)
	if r.fault != nil {
		return 0, r.fault
	}
	return rand.Read(p)
}

// A nil underlying connection fails fast on unexpected I/O, without touching
// a socket. A real pipe lets the same counters observe a bounded TLS exchange.
type webResumptionPolicyConn struct {
	net.Conn
	reads        atomic.Int64
	writes       atomic.Int64
	closes       atomic.Int64
	writeStarted chan struct{}
}

func (c *webResumptionPolicyConn) Read(p []byte) (int, error) {
	c.reads.Add(1)
	if c.Conn == nil {
		return 0, io.ErrClosedPipe
	}
	return c.Conn.Read(p)
}

func (c *webResumptionPolicyConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	if c.writeStarted != nil {
		select {
		case c.writeStarted <- struct{}{}:
		default:
		}
	}
	if c.Conn == nil {
		return 0, io.ErrClosedPipe
	}
	return c.Conn.Write(p)
}

func (c *webResumptionPolicyConn) Close() error {
	c.closes.Add(1)
	if c.Conn == nil {
		return nil
	}
	return c.Conn.Close()
}

func (c *webResumptionPolicyConn) LocalAddr() net.Addr {
	if c.Conn == nil {
		return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	}
	return c.Conn.LocalAddr()
}

func (c *webResumptionPolicyConn) RemoteAddr() net.Addr {
	if c.Conn == nil {
		return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	}
	return c.Conn.RemoteAddr()
}

func (c *webResumptionPolicyConn) SetDeadline(deadline time.Time) error {
	if c.Conn == nil {
		return nil
	}
	return c.Conn.SetDeadline(deadline)
}

func (c *webResumptionPolicyConn) SetReadDeadline(deadline time.Time) error {
	if c.Conn == nil {
		return nil
	}
	return c.Conn.SetReadDeadline(deadline)
}

func (c *webResumptionPolicyConn) SetWriteDeadline(deadline time.Time) error {
	if c.Conn == nil {
		return nil
	}
	return c.Conn.SetWriteDeadline(deadline)
}

func (c *webResumptionPolicyConn) assertUntouched(t *testing.T) {
	t.Helper()
	if c.reads.Load() != 0 || c.writes.Load() != 0 || c.closes.Load() != 0 {
		t.Fatalf("raw connection touched: reads=%d writes=%d closes=%d", c.reads.Load(), c.writes.Load(), c.closes.Load())
	}
}
