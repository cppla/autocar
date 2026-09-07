package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

type webClientTestDialer struct {
	calls      atomic.Int64
	closeCalls atomic.Int64

	mu     sync.Mutex
	closed bool
	dial   func(context.Context, int64, string, string) (net.Conn, error)
}

type webClientTestPacketDialer struct {
	*webClientTestDialer
	packetCalls atomic.Int64
	packet      transport.PacketConn
}

func (d *webClientTestPacketDialer) DialPacket(context.Context) (transport.PacketConn, error) {
	d.packetCalls.Add(1)
	return d.packet, nil
}

type webClientTestPacketConn struct {
	sendErr error
}

func (c *webClientTestPacketConn) Send([]byte, string) error { return c.sendErr }
func (*webClientTestPacketConn) Receive() ([]byte, string, error) {
	return nil, "", net.ErrClosed
}
func (*webClientTestPacketConn) Close() error { return nil }

func (d *webClientTestDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	call := d.calls.Add(1)
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	return d.dial(ctx, call, network, address)
}

func (d *webClientTestDialer) Close() error {
	d.closeCalls.Add(1)
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()
	return nil
}

type webClientTestClock struct {
	nanos atomic.Int64
}

func newWebClientTestClock(at time.Time) *webClientTestClock {
	c := &webClientTestClock{}
	c.nanos.Store(at.UnixNano())
	return c
}

func (c *webClientTestClock) Now() time.Time {
	return time.Unix(0, c.nanos.Load())
}

func (c *webClientTestClock) Advance(delta time.Duration) {
	c.nanos.Add(int64(delta))
}

func newWebClientForTest(t *testing.T, primary, fallback *webClientTestDialer, timeout, cooldown time.Duration, now func() time.Time) *WebClient {
	t.Helper()
	client, err := newWebClientWithPaths(
		webClientPath{name: webAuthTransportH3, dialer: primary},
		webClientPath{name: webAuthTransportH2, dialer: fallback},
		timeout,
		cooldown,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func closedWebClientTestConn() net.Conn {
	client, peer := net.Pipe()
	_ = peer.Close()
	return client
}

func TestWebClientUsesH3FirstAndPublishesOnlySuccessfulSelection(t *testing.T) {
	primary := &webClientTestDialer{dial: func(_ context.Context, _ int64, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "example.com:443" {
			t.Fatalf("primary dial = %s/%s", network, address)
		}
		return closedWebClientTestConn(), nil
	}}
	fallback := &webClientTestDialer{dial: func(context.Context, int64, string, string) (net.Conn, error) {
		t.Fatal("fallback was called after a successful H3 CONNECT")
		return nil, errors.New("unreachable")
	}}
	client := newWebClientForTest(t, primary, fallback, time.Second, time.Minute, time.Now)

	if got := client.SelectedTransport(); got != "" {
		t.Fatalf("selection before success = %q, want blank", got)
	}
	if snapshot := client.Snapshot(); snapshot.SelectedTransport != "" ||
		snapshot.ClientPacing != "not-applicable" || snapshot.RelayPacing != "not-applicable" {
		t.Fatalf("snapshot before success = %+v", snapshot)
	}

	conn, err := client.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if got := primary.calls.Load(); got != 1 {
		t.Fatalf("H3 calls = %d, want 1", got)
	}
	if got := fallback.calls.Load(); got != 0 {
		t.Fatalf("H2 calls = %d, want 0", got)
	}
	if got := client.SelectedTransport(); got != webAuthTransportH3 {
		t.Fatalf("selection after H3 success = %q, want h3", got)
	}
	if snapshot := client.Snapshot(); snapshot.SelectedTransport != webAuthTransportH3 {
		t.Fatalf("snapshot after H3 success = %+v", snapshot)
	}
}

func TestWebClientEndToEndPrefersH3AndDetachesEstablishedStream(t *testing.T) {
	targetAddress, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	serverTLS, clientTLS := testTLSConfigs(t)
	server, err := ListenWeb(WebServerConfig{
		TCPAddress: "127.0.0.1:0",
		UDPAddress: "127.0.0.1:0",
		Token:      testToken,
		TLSConfig:  serverTLS,
		Cover:      http.NotFoundHandler(),
		Dialer: transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	serveCtx, cancelServe := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(serveCtx) }()
	t.Cleanup(func() {
		cancelServe()
		_ = server.Close()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("web server did not stop")
		}
	})

	client, err := NewWebClient(WebClientConfig{
		ServerAddress: server.TCPAddr().String(),
		Token:         testToken,
		TLSConfig:     clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	dialCtx, cancelDial := context.WithCancel(context.Background())
	conn, err := client.DialContext(dialCtx, "tcp", targetAddress)
	if err != nil {
		cancelDial()
		t.Fatal(err)
	}
	cancelDial()
	if err := completeExchange(conn, "web-auto-h3"); err != nil {
		t.Fatalf("H3 stream after dial-context cancellation: %v", err)
	}
	if got := client.SelectedTransport(); got != webAuthTransportH3 {
		t.Fatalf("selection = %q, want h3", got)
	}
	if snapshot := client.Snapshot(); snapshot.SelectedTransport != webAuthTransportH3 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	state := client.primary.dialer.(*WebH3Client)
	state.mu.Lock()
	negotiated := state.conn.ConnectionState().TLS.NegotiatedProtocol
	state.mu.Unlock()
	if negotiated != webAuthTransportH3 {
		t.Fatalf("primary negotiated ALPN = %q, want h3", negotiated)
	}
}

func TestWebClientEndToEndFallsBackToH2WithoutUDPListener(t *testing.T) {
	targetAddress, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	serverTLS, clientTLS := testTLSConfigs(t)
	server := startWebH2TestServer(t, WebH2ServerConfig{
		Address:   "127.0.0.1:0",
		Token:     testToken,
		TLSConfig: serverTLS,
		Cover:     http.NotFoundHandler(),
		Dialer: transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}),
	})
	client, err := NewWebClient(WebClientConfig{
		ServerAddress:         server.Addr().String(),
		Token:                 testToken,
		TLSConfig:             clientTLS,
		H3DialTimeout:         40 * time.Millisecond,
		PrimaryAttemptTimeout: 100 * time.Millisecond,
		FallbackCooldown:      time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	callerCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := client.DialContext(callerCtx, "tcp", targetAddress)
	if err != nil {
		t.Fatal(err)
	}
	if err := completeExchange(conn, "web-auto-h2"); err != nil {
		t.Fatal(err)
	}
	if callerCtx.Err() != nil {
		t.Fatalf("fallback exhausted caller context: %v", callerCtx.Err())
	}
	if got := client.SelectedTransport(); got != webAuthTransportH2 {
		t.Fatalf("selection = %q, want h2", got)
	}
}

func TestWebClientTransportFailureFallsBackAndObservesCooldown(t *testing.T) {
	clock := newWebClientTestClock(time.Unix(100, 0))
	primaryFailure := errors.New("UDP path unavailable")
	primary := &webClientTestDialer{dial: func(context.Context, int64, string, string) (net.Conn, error) {
		return nil, primaryFailure
	}}
	fallback := &webClientTestDialer{dial: func(context.Context, int64, string, string) (net.Conn, error) {
		return closedWebClientTestConn(), nil
	}}
	client := newWebClientForTest(t, primary, fallback, time.Second, time.Minute, clock.Now)

	for range 2 {
		conn, err := client.DialContext(context.Background(), "tcp", "example.com:443")
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}
	if got := primary.calls.Load(); got != 1 {
		t.Fatalf("H3 calls during cooldown = %d, want 1", got)
	}
	if got := fallback.calls.Load(); got != 2 {
		t.Fatalf("H2 calls = %d, want 2", got)
	}
	if got := client.SelectedTransport(); got != webAuthTransportH2 {
		t.Fatalf("selection = %q, want h2", got)
	}
}

func TestWebClientFailureUsesCooldownPolicy(t *testing.T) {
	clock := newWebClientTestClock(time.Unix(150, 0))
	primary := &webClientTestDialer{dial: func(_ context.Context, call int64, _, _ string) (net.Conn, error) {
		if call == 1 {
			return nil, errors.New("initial H3 failure")
		}
		return closedWebClientTestConn(), nil
	}}
	fallback := &webClientTestDialer{dial: func(context.Context, int64, string, string) (net.Conn, error) {
		return closedWebClientTestConn(), nil
	}}
	client := newWebClientForTest(t, primary, fallback, time.Second, time.Minute, clock.Now)
	client.cooldownAfterFailure = func(base time.Duration) time.Duration {
		if base != time.Minute {
			t.Fatalf("cooldown base = %s, want 1m", base)
		}
		return 75 * time.Second
	}

	connection, err := client.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if client.primaryCooldown != 75*time.Second {
		t.Fatalf("recorded cooldown = %s, want 75s", client.primaryCooldown)
	}

	clock.Advance(time.Minute)
	connection, err = client.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if got := primary.calls.Load(); got != 1 {
		t.Fatalf("H3 calls before jittered cooldown elapsed = %d, want 1", got)
	}

	clock.Advance(15 * time.Second)
	connection, err = client.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if got := primary.calls.Load(); got != 2 {
		t.Fatalf("H3 calls after jittered cooldown elapsed = %d, want 2", got)
	}
	if client.primaryCooldown != 0 {
		t.Fatalf("successful H3 probe retained cooldown %s", client.primaryCooldown)
	}
}

func TestJitterWebFallbackCooldownStaysWithinTwentyPercent(t *testing.T) {
	const base = 10 * time.Second
	minimum := base - base/webFallbackCooldownJitterDivisor
	maximum := base + base/webFallbackCooldownJitterDivisor
	for range 1024 {
		got := jitterWebFallbackCooldown(base)
		if got < minimum || got > maximum {
			t.Fatalf("jittered cooldown = %s, want %s..%s", got, minimum, maximum)
		}
	}
	if got := jitterWebFallbackCooldown(time.Nanosecond); got != time.Nanosecond {
		t.Fatalf("sub-jitter cooldown = %s, want 1ns", got)
	}
	span := base / webFallbackCooldownJitterDivisor
	rangeSize := int64(2*span) + 1
	if got := jitterWebFallbackCooldownWith(base, func(int64) int64 { return 0 }); got != minimum {
		t.Fatalf("minimum jitter = %s, want %s", got, minimum)
	}
	if got := jitterWebFallbackCooldownWith(base, func(limit int64) int64 {
		if limit != rangeSize {
			t.Fatalf("jitter range = %d, want %d", limit, rangeSize)
		}
		return limit - 1
	}); got != maximum {
		t.Fatalf("maximum jitter = %s, want %s", got, maximum)
	}
}

func TestNewWebClientUsesProductionCooldownJitter(t *testing.T) {
	_, clientTLS := testTLSConfigs(t)
	client, err := NewWebClient(WebClientConfig{
		ServerAddress: "127.0.0.1:443",
		Token:         testToken,
		TLSConfig:     clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if reflect.ValueOf(client.cooldownAfterFailure).Pointer() != reflect.ValueOf(jitterWebFallbackCooldown).Pointer() {
		t.Fatal("NewWebClient did not install the production cooldown jitter policy")
	}
}

func TestWebClientAuthenticatedH3ErrorNeverFallsBackAndRestoresCircuit(t *testing.T) {
	clock := newWebClientTestClock(time.Unix(200, 0))
	transportFailure := errors.New("H3 transport failed")
	targetFailure := &WebConnectError{Transport: webAuthTransportH3, StatusCode: 502}
	primary := &webClientTestDialer{dial: func(_ context.Context, call int64, _, _ string) (net.Conn, error) {
		switch call {
		case 1:
			return nil, transportFailure
		case 2:
			return nil, targetFailure
		default:
			return closedWebClientTestConn(), nil
		}
	}}
	fallback := &webClientTestDialer{dial: func(context.Context, int64, string, string) (net.Conn, error) {
		return closedWebClientTestConn(), nil
	}}
	client := newWebClientForTest(t, primary, fallback, time.Second, time.Minute, clock.Now)

	conn, err := client.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if got := client.SelectedTransport(); got != webAuthTransportH2 {
		t.Fatalf("initial fallback selection = %q, want h2", got)
	}

	clock.Advance(time.Minute)
	_, err = client.DialContext(context.Background(), "tcp", "example.com:443")
	var gotTargetFailure *WebConnectError
	if !errors.As(err, &gotTargetFailure) || gotTargetFailure != targetFailure {
		t.Fatalf("probe error = %v, want exact authenticated target error", err)
	}
	if got := fallback.calls.Load(); got != 1 {
		t.Fatalf("H2 calls after authenticated H3 error = %d, want 1", got)
	}
	if got := client.SelectedTransport(); got != webAuthTransportH2 {
		t.Fatalf("failed CONNECT changed selection to %q", got)
	}

	// The authenticated error proves H3 is healthy, so the next call tries H3
	// immediately instead of waiting through another cooldown.
	conn, err = client.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if got := primary.calls.Load(); got != 3 {
		t.Fatalf("H3 calls after authenticated health evidence = %d, want 3", got)
	}
	if got := fallback.calls.Load(); got != 1 {
		t.Fatalf("authenticated target error triggered H2; calls = %d", got)
	}
}

func TestWebClientCooldownAdmitsExactlyOneConcurrentH3Probe(t *testing.T) {
	clock := newWebClientTestClock(time.Unix(300, 0))
	probeEntered := make(chan struct{})
	releaseProbe := make(chan struct{})
	primary := &webClientTestDialer{dial: func(ctx context.Context, call int64, _, _ string) (net.Conn, error) {
		if call == 1 {
			return nil, errors.New("initial H3 failure")
		}
		if call != 2 {
			return nil, errors.New("more than one H3 recovery probe")
		}
		close(probeEntered)
		select {
		case <-releaseProbe:
			return closedWebClientTestConn(), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	fallback := &webClientTestDialer{dial: func(context.Context, int64, string, string) (net.Conn, error) {
		return closedWebClientTestConn(), nil
	}}
	client := newWebClientForTest(t, primary, fallback, time.Second, time.Minute, clock.Now)

	initial, err := client.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = initial.Close()
	clock.Advance(time.Minute)

	probeDone := make(chan error, 1)
	go func() {
		conn, dialErr := client.DialContext(context.Background(), "tcp", "example.com:443")
		if conn != nil {
			_ = conn.Close()
		}
		probeDone <- dialErr
	}()
	select {
	case <-probeEntered:
	case <-time.After(time.Second):
		t.Fatal("H3 recovery probe did not start")
	}

	const concurrent = 32
	start := make(chan struct{})
	errs := make(chan error, concurrent)
	var wg sync.WaitGroup
	for range concurrent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			conn, dialErr := client.DialContext(context.Background(), "tcp", "example.com:443")
			if conn != nil {
				_ = conn.Close()
			}
			errs <- dialErr
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent H2 fallback: %v", err)
		}
	}
	if got := primary.calls.Load(); got != 2 {
		t.Fatalf("H3 calls with probe in flight = %d, want 2", got)
	}
	if got := fallback.calls.Load(); got != 1+concurrent {
		t.Fatalf("H2 calls = %d, want %d", got, 1+concurrent)
	}

	close(releaseProbe)
	if err := <-probeDone; err != nil {
		t.Fatal(err)
	}
	if got := client.SelectedTransport(); got != webAuthTransportH3 {
		t.Fatalf("selection after recovered probe = %q, want h3", got)
	}
}

func TestWebClientLateOlderFailureDoesNotReopenRecoveredCircuit(t *testing.T) {
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	primary := &webClientTestDialer{dial: func(ctx context.Context, call int64, _, _ string) (net.Conn, error) {
		switch call {
		case 1:
			close(firstEntered)
			select {
			case <-releaseFirst:
				return nil, errors.New("late older transport failure")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		case 2, 3:
			return closedWebClientTestConn(), nil
		default:
			return nil, errors.New("unexpected primary call")
		}
	}}
	fallback := &webClientTestDialer{dial: func(context.Context, int64, string, string) (net.Conn, error) {
		return closedWebClientTestConn(), nil
	}}
	client := newWebClientForTest(t, primary, fallback, time.Second, time.Minute, time.Now)

	firstDone := make(chan error, 1)
	go func() {
		conn, err := client.DialContext(context.Background(), "tcp", "example.com:443")
		if conn != nil {
			_ = conn.Close()
		}
		firstDone <- err
	}()
	<-firstEntered

	newer, err := client.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = newer.Close()
	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatalf("older failed request did not get its H2 fallback: %v", err)
	}

	// The first attempt's late failure is older than the successful second
	// attempt, so it must not put subsequent calls into H2 cooldown.
	third, err := client.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = third.Close()
	if got := primary.calls.Load(); got != 3 {
		t.Fatalf("H3 calls = %d, want 3", got)
	}
	if got := fallback.calls.Load(); got != 1 {
		t.Fatalf("H2 calls = %d, want only the failed request's fallback", got)
	}
}

func TestWebClientAuthenticatedUDPSuccessClosesCircuitAgainstOlderTCPFailure(t *testing.T) {
	clock := newWebClientTestClock(time.Unix(400, 0))
	probeEntered := make(chan struct{})
	releaseProbe := make(chan struct{})
	basePrimary := &webClientTestDialer{dial: func(ctx context.Context, call int64, _, _ string) (net.Conn, error) {
		switch call {
		case 1:
			return nil, errors.New("initial H3 failure")
		case 2:
			close(probeEntered)
			select {
			case <-releaseProbe:
				return nil, errors.New("older recovery probe failure")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		case 3:
			return closedWebClientTestConn(), nil
		default:
			return nil, errors.New("unexpected primary call")
		}
	}}
	primary := &webClientTestPacketDialer{
		webClientTestDialer: basePrimary,
		packet:              &webClientTestPacketConn{},
	}
	fallback := &webClientTestDialer{dial: func(context.Context, int64, string, string) (net.Conn, error) {
		return closedWebClientTestConn(), nil
	}}
	client, err := newWebClientWithPaths(
		webClientPath{name: webAuthTransportH3, dialer: primary},
		webClientPath{name: webAuthTransportH2, dialer: fallback},
		time.Second,
		time.Minute,
		clock.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	initial, err := client.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = initial.Close()
	clock.Advance(time.Minute)

	probeDone := make(chan error, 1)
	go func() {
		connection, dialErr := client.DialContext(context.Background(), "tcp", "example.com:443")
		if connection != nil {
			_ = connection.Close()
		}
		probeDone <- dialErr
	}()
	select {
	case <-probeEntered:
	case <-time.After(time.Second):
		t.Fatal("H3 recovery probe did not start")
	}

	packet, err := client.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := packet.Send([]byte("healthy"), "example.com:53"); err != nil {
		t.Fatal(err)
	}
	_ = packet.Close()
	close(releaseProbe)
	if err := <-probeDone; err != nil {
		t.Fatal(err)
	}

	connection, err := client.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if got := basePrimary.calls.Load(); got != 3 {
		t.Fatalf("H3 calls after authenticated UDP health = %d, want 3", got)
	}
	if got := fallback.calls.Load(); got != 2 {
		t.Fatalf("H2 calls = %d, want initial and older failed attempts only", got)
	}
	if got := primary.packetCalls.Load(); got != 1 {
		t.Fatalf("H3 packet dials = %d, want 1", got)
	}
	if got := client.SelectedTransport(); got != webAuthTransportH3 {
		t.Fatalf("selection after recovered TCP = %q, want h3", got)
	}
}

func TestWebClientAuthenticatedUDPErrorClosesCircuitAgainstOlderTCPFailure(t *testing.T) {
	clock := newWebClientTestClock(time.Unix(500, 0))
	probeEntered := make(chan struct{})
	releaseProbe := make(chan struct{})
	targetFailure := &WebConnectError{Transport: webAuthTransportH3, StatusCode: http.StatusBadGateway}
	basePrimary := &webClientTestDialer{dial: func(ctx context.Context, call int64, _, _ string) (net.Conn, error) {
		switch call {
		case 1:
			return nil, errors.New("initial H3 failure")
		case 2:
			close(probeEntered)
			select {
			case <-releaseProbe:
				return nil, errors.New("older recovery probe failure")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		case 3:
			return closedWebClientTestConn(), nil
		default:
			return nil, errors.New("unexpected primary call")
		}
	}}
	primary := &webClientTestPacketDialer{
		webClientTestDialer: basePrimary,
		packet:              &webClientTestPacketConn{sendErr: targetFailure},
	}
	fallback := &webClientTestDialer{dial: func(context.Context, int64, string, string) (net.Conn, error) {
		return closedWebClientTestConn(), nil
	}}
	client, err := newWebClientWithPaths(
		webClientPath{name: webAuthTransportH3, dialer: primary},
		webClientPath{name: webAuthTransportH2, dialer: fallback},
		time.Second,
		time.Minute,
		clock.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	initial, err := client.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = initial.Close()
	clock.Advance(time.Minute)

	probeDone := make(chan error, 1)
	go func() {
		connection, dialErr := client.DialContext(context.Background(), "tcp", "example.com:443")
		if connection != nil {
			_ = connection.Close()
		}
		probeDone <- dialErr
	}()
	select {
	case <-probeEntered:
	case <-time.After(time.Second):
		t.Fatal("H3 recovery probe did not start")
	}

	packet, err := client.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	err = packet.Send([]byte("rejected target"), "example.com:53")
	var gotTargetFailure *WebConnectError
	if !errors.As(err, &gotTargetFailure) || gotTargetFailure != targetFailure {
		t.Fatalf("packet error = %v, want exact authenticated target error", err)
	}
	_ = packet.Close()
	if got := client.SelectedTransport(); got != webAuthTransportH2 {
		t.Fatalf("failed CONNECT-UDP changed selection to %q", got)
	}

	close(releaseProbe)
	if err := <-probeDone; err != nil {
		t.Fatal(err)
	}

	connection, err := client.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if got := basePrimary.calls.Load(); got != 3 {
		t.Fatalf("H3 calls after authenticated UDP target error = %d, want 3", got)
	}
	if got := fallback.calls.Load(); got != 2 {
		t.Fatalf("H2 calls = %d, want initial and older failed attempts only", got)
	}
	if got := primary.packetCalls.Load(); got != 1 {
		t.Fatalf("H3 packet dials = %d, want 1", got)
	}
}

func TestWebClientPrimaryTimeoutLeavesCallerContextForH2(t *testing.T) {
	primary := &webClientTestDialer{dial: func(ctx context.Context, _ int64, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	fallback := &webClientTestDialer{dial: func(context.Context, int64, string, string) (net.Conn, error) {
		return closedWebClientTestConn(), nil
	}}
	client := newWebClientForTest(t, primary, fallback, 20*time.Millisecond, time.Minute, time.Now)
	callerCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	conn, err := client.DialContext(callerCtx, "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if err := callerCtx.Err(); err != nil {
		t.Fatalf("primary budget consumed caller context: %v", err)
	}
	if got := client.SelectedTransport(); got != webAuthTransportH2 {
		t.Fatalf("selection = %q, want h2", got)
	}
}

func TestWebClientCallerCancellationDoesNotOpenCircuit(t *testing.T) {
	entered := make(chan struct{})
	primary := &webClientTestDialer{dial: func(ctx context.Context, call int64, _, _ string) (net.Conn, error) {
		if call == 1 {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return closedWebClientTestConn(), nil
	}}
	fallback := &webClientTestDialer{dial: func(context.Context, int64, string, string) (net.Conn, error) {
		return closedWebClientTestConn(), nil
	}}
	client := newWebClientForTest(t, primary, fallback, time.Second, time.Minute, time.Now)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := client.DialContext(ctx, "tcp", "example.com:443")
		done <- err
	}()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled dial error = %v, want context.Canceled", err)
	}
	if got := fallback.calls.Load(); got != 0 {
		t.Fatalf("caller cancellation triggered fallback %d times", got)
	}

	conn, err := client.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if got := primary.calls.Load(); got != 2 {
		t.Fatalf("H3 calls after caller cancellation = %d, want 2", got)
	}
	if got := fallback.calls.Load(); got != 0 {
		t.Fatalf("cancellation opened circuit; H2 calls = %d", got)
	}
}

func TestWebClientEstablishedStreamOutlivesDialContext(t *testing.T) {
	peerCh := make(chan net.Conn, 1)
	primary := &webClientTestDialer{dial: func(context.Context, int64, string, string) (net.Conn, error) {
		client, peer := net.Pipe()
		peerCh <- peer
		return client, nil
	}}
	fallback := &webClientTestDialer{dial: func(context.Context, int64, string, string) (net.Conn, error) {
		return nil, errors.New("unexpected fallback")
	}}
	client := newWebClientForTest(t, primary, fallback, time.Second, time.Minute, time.Now)
	dialCtx, cancelDial := context.WithCancel(context.Background())
	conn, err := client.DialContext(dialCtx, "tcp", "example.com:443")
	if err != nil {
		cancelDial()
		t.Fatal(err)
	}
	defer conn.Close()
	peer := <-peerCh
	defer peer.Close()
	cancelDial()

	peerErr := make(chan error, 1)
	go func() {
		payload := make([]byte, 4)
		if _, err := io.ReadFull(peer, payload); err != nil {
			peerErr <- err
			return
		}
		_, err := peer.Write(payload)
		peerErr <- err
	}()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write after dial-context cancellation: %v", err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatalf("read after dial-context cancellation: %v", err)
	}
	if string(response) != "ping" {
		t.Fatalf("response = %q, want ping", response)
	}
	if err := <-peerErr; err != nil {
		t.Fatal(err)
	}
}

func TestWebClientCloseInterruptsDialsAndIsConcurrentSafe(t *testing.T) {
	entered := make(chan struct{})
	primary := &webClientTestDialer{dial: func(ctx context.Context, _ int64, _, _ string) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	fallback := &webClientTestDialer{dial: func(context.Context, int64, string, string) (net.Conn, error) {
		return closedWebClientTestConn(), nil
	}}
	client, err := newWebClientWithPaths(
		webClientPath{name: webAuthTransportH3, dialer: primary},
		webClientPath{name: webAuthTransportH2, dialer: fallback},
		time.Second,
		time.Minute,
		time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}

	dialDone := make(chan error, 1)
	go func() {
		_, dialErr := client.DialContext(context.Background(), "tcp", "example.com:443")
		dialDone <- dialErr
	}()
	<-entered

	const closers = 16
	errs := make(chan error, closers)
	var wg sync.WaitGroup
	for range closers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- client.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("Close: %v", err)
		}
	}
	if err := <-dialDone; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("in-flight dial after Close = %v, want net.ErrClosed", err)
	}
	if got := primary.closeCalls.Load(); got != 1 {
		t.Fatalf("primary Close calls = %d, want 1", got)
	}
	if got := fallback.closeCalls.Load(); got != 1 {
		t.Fatalf("fallback Close calls = %d, want 1", got)
	}
	if _, err := client.DialContext(context.Background(), "tcp", "example.com:443"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("dial after Close = %v, want net.ErrClosed", err)
	}
}

func TestWebClientRejectsInvalidRequestBeforeEitherTransport(t *testing.T) {
	unexpected := func(context.Context, int64, string, string) (net.Conn, error) {
		return nil, errors.New("unexpected transport dial")
	}
	primary := &webClientTestDialer{dial: unexpected}
	fallback := &webClientTestDialer{dial: unexpected}
	client := newWebClientForTest(t, primary, fallback, time.Second, time.Minute, time.Now)

	for _, test := range []struct {
		network string
		address string
	}{
		{network: "udp", address: "example.com:443"},
		{network: "tcp4", address: "example.com:443"},
		{network: "tcp", address: "missing-port"},
	} {
		if _, err := client.DialContext(context.Background(), test.network, test.address); err == nil {
			t.Fatalf("DialContext(%q, %q) succeeded", test.network, test.address)
		}
	}
	if got := primary.calls.Load(); got != 0 {
		t.Fatalf("invalid requests reached H3 %d times", got)
	}
	if got := fallback.calls.Load(); got != 0 {
		t.Fatalf("invalid requests reached H2 %d times", got)
	}
}

func TestNewWebClientValidatesTimeoutsBeforeCreatingPaths(t *testing.T) {
	for _, config := range []WebClientConfig{
		{},
		{ServerAddress: "127.0.0.1:443", HandshakeTimeout: -1},
		{ServerAddress: "127.0.0.1:443", H3DialTimeout: -1},
		{ServerAddress: "127.0.0.1:443", H2DialTimeout: -1},
		{ServerAddress: "127.0.0.1:443", PrimaryAttemptTimeout: -1},
		{ServerAddress: "127.0.0.1:443", FallbackCooldown: -1},
	} {
		if client, err := NewWebClient(config); err == nil {
			_ = client.Close()
			t.Fatalf("NewWebClient(%+v) succeeded", config)
		}
	}
}
