package tunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/transport"
	quic "github.com/quic-go/quic-go"
)

const testToken = "correct horse battery staple"

func TestQUICStreamCloseUnblocksBlockedWrite(t *testing.T) {
	stream := &blockingQUICStream{
		writeStarted:  make(chan struct{}),
		writeCanceled: make(chan struct{}),
	}
	paceCtx, paceCancel := context.WithCancel(context.Background())
	conn := &quicStreamConn{stream: stream, paceCtx: paceCtx, paceCancel: paceCancel}
	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("blocked"))
		writeDone <- err
	}()
	select {
	case <-stream.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("Write did not start")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("blocked Write succeeded after aborting Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock Write")
	}
}

func TestQUICStreamPeerCancelUnblocksPacingWait(t *testing.T) {
	streamCtx, cancelStream := context.WithCancel(context.Background())
	stream := &blockingQUICStream{
		ctx:           streamCtx,
		writeStarted:  make(chan struct{}),
		writeCanceled: make(chan struct{}),
	}
	pacer := &blockingQUICWritePacer{started: make(chan struct{})}
	conn := newQUICStreamConnWithPacer(stream, nil, pacer)
	defer conn.Close()

	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("paced"))
		writeDone <- err
	}()
	select {
	case <-pacer.started:
	case <-time.After(time.Second):
		t.Fatal("pacing wait did not start")
	}

	// A peer STOP_SENDING cancels quic.Stream.Context without closing the
	// connection. The application-layer pacer must inherit that cancellation.
	cancelStream()
	select {
	case err := <-writeDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Write error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stream cancellation did not unblock pacing wait")
	}
	select {
	case <-stream.writeStarted:
		t.Fatal("Write reached the QUIC stream after its context was canceled")
	default:
	}
}

func TestQUICStreamUpdatedDeadlineInterruptsPendingPacingWait(t *testing.T) {
	stream := &recordingQUICStream{}
	pacer := &blockingQUICWritePacer{started: make(chan struct{})}
	conn := newQUICStreamConnWithPacer(stream, nil, pacer)
	defer conn.Close()

	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("paced"))
		writeDone <- err
	}()
	select {
	case <-pacer.started:
	case <-time.After(time.Second):
		t.Fatal("pacing wait did not start")
	}
	if err := conn.SetWriteDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-writeDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Write error = %v, want deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("updated write deadline did not interrupt pacing wait")
	}
	if len(stream.writes) != 0 {
		t.Fatalf("expired paced write reached stream: %v", stream.writes)
	}
}

func TestQUICStreamDeadlineChangeAfterAdmissionDoesNotChargeTwice(t *testing.T) {
	stream := &recordingQUICStream{}
	pacer := &deadlineChangingWritePacer{}
	conn := newQUICStreamConnWithPacer(stream, nil, pacer)
	pacer.change = func() {
		if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			t.Errorf("SetWriteDeadline: %v", err)
		}
	}

	written, err := conn.Write([]byte("admitted"))
	if err != nil {
		t.Fatal(err)
	}
	if written != len("admitted") {
		t.Fatalf("Write = %d bytes, want %d", written, len("admitted"))
	}
	if got := pacer.calls.Load(); got != 1 {
		t.Fatalf("pacer admission calls = %d, want 1", got)
	}
}

func TestQUICStreamPhysicallyChunksPacedWrites(t *testing.T) {
	stream := &recordingQUICStream{}
	pacer := &recordingQUICWritePacer{maxChunk: 10}
	conn := newQUICStreamConnWithPacer(stream, nil, pacer)

	written, err := conn.Write(make([]byte, 25))
	if err != nil {
		t.Fatal(err)
	}
	if written != 25 {
		t.Fatalf("Write = %d bytes, want 25", written)
	}
	want := []int{10, 10, 5}
	if !slices.Equal(pacer.waits, want) {
		t.Fatalf("pacer chunks = %v, want %v", pacer.waits, want)
	}
	if !slices.Equal(stream.writes, want) {
		t.Fatalf("physical stream writes = %v, want %v", stream.writes, want)
	}
}

func TestNewQUICStreamConnKeepsNilPacerNil(t *testing.T) {
	conn := newQUICStreamConn(&recordingQUICStream{}, nil, nil)
	defer conn.Close()
	if conn.pacer != nil {
		t.Fatalf("nil *connectionPacer became non-nil interface %T", conn.pacer)
	}
}

type blockingQUICStream struct {
	ctx           context.Context
	writeStarted  chan struct{}
	writeCanceled chan struct{}
	startOnce     sync.Once
	cancelOnce    sync.Once
}

func (s *blockingQUICStream) Read([]byte) (int, error) { return 0, io.EOF }
func (s *blockingQUICStream) Context() context.Context {
	if s.ctx == nil {
		return context.Background()
	}
	return s.ctx
}
func (s *blockingQUICStream) Write([]byte) (int, error) {
	s.startOnce.Do(func() { close(s.writeStarted) })
	<-s.writeCanceled
	return 0, net.ErrClosed
}
func (s *blockingQUICStream) Close() error                     { return nil }
func (s *blockingQUICStream) SetDeadline(time.Time) error      { return nil }
func (s *blockingQUICStream) SetReadDeadline(time.Time) error  { return nil }
func (s *blockingQUICStream) SetWriteDeadline(time.Time) error { return nil }
func (s *blockingQUICStream) CancelRead(quic.StreamErrorCode)  {}
func (s *blockingQUICStream) CancelWrite(quic.StreamErrorCode) {
	s.cancelOnce.Do(func() { close(s.writeCanceled) })
}

type blockingQUICWritePacer struct {
	started chan struct{}
	once    sync.Once
}

func (p *blockingQUICWritePacer) wait(ctx context.Context, _ int, _ *quic.Conn) error {
	p.once.Do(func() { close(p.started) })
	<-ctx.Done()
	return context.Cause(ctx)
}

func (p *blockingQUICWritePacer) maxChunkBytes() int { return 64 << 10 }

type recordingQUICStream struct {
	writes []int
}

func (s *recordingQUICStream) Read([]byte) (int, error) { return 0, io.EOF }
func (s *recordingQUICStream) Write(p []byte) (int, error) {
	s.writes = append(s.writes, len(p))
	return len(p), nil
}
func (s *recordingQUICStream) Close() error                     { return nil }
func (s *recordingQUICStream) Context() context.Context         { return context.Background() }
func (s *recordingQUICStream) SetDeadline(time.Time) error      { return nil }
func (s *recordingQUICStream) SetReadDeadline(time.Time) error  { return nil }
func (s *recordingQUICStream) SetWriteDeadline(time.Time) error { return nil }
func (s *recordingQUICStream) CancelRead(quic.StreamErrorCode)  {}
func (s *recordingQUICStream) CancelWrite(quic.StreamErrorCode) {}

type recordingQUICWritePacer struct {
	maxChunk int
	waits    []int
}

func (p *recordingQUICWritePacer) wait(_ context.Context, bytes int, _ *quic.Conn) error {
	p.waits = append(p.waits, bytes)
	return nil
}

func (p *recordingQUICWritePacer) maxChunkBytes() int { return p.maxChunk }

type deadlineChangingWritePacer struct {
	calls  atomic.Int64
	change func()
}

func (p *deadlineChangingWritePacer) wait(context.Context, int, *quic.Conn) error {
	if p.calls.Add(1) == 1 {
		p.change()
	}
	return nil
}

func (p *deadlineChangingWritePacer) maxChunkBytes() int { return 64 << 10 }

func TestQUICConcurrentStreamsAndReconnect(t *testing.T) {
	targetAddress, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	serverTLS, clientTLS := testTLSConfigs(t)
	var dials atomic.Int64
	dialer := transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		if address != targetAddress {
			t.Errorf("dial address = %q, want %q", address, targetAddress)
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	})
	server := startQUICServer(t, serverTLS, dialer, testToken)
	client, err := NewClient(ClientConfig{
		ServerAddress: server.Addr().String(),
		Token:         testToken,
		TLSConfig:     clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	const streams = 24
	var wg sync.WaitGroup
	errorsCh := make(chan error, streams)
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := exchange(client, targetAddress, "concurrent payload"); err != nil {
				errorsCh <- err
			}
		}()
	}
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Error(err)
	}
	if got := dials.Load(); got != streams {
		t.Fatalf("exit dials = %d, want %d", got, streams)
	}

	client.mu.Lock()
	oldConnection := client.conn
	client.mu.Unlock()
	if oldConnection == nil {
		t.Fatal("shared QUIC connection was not established")
	}
	state := oldConnection.ConnectionState()
	if state.TLS.Version != tls.VersionTLS13 || state.TLS.NegotiatedProtocol != protocol.ALPN || state.Used0RTT {
		t.Fatalf("unexpected QUIC security state: TLS=%#x ALPN=%q 0-RTT=%v", state.TLS.Version, state.TLS.NegotiatedProtocol, state.Used0RTT)
	}
	if err := oldConnection.CloseWithError(applicationShutdown, "test reconnect"); err != nil {
		t.Fatal(err)
	}
	if err := exchange(client, targetAddress, "after reconnect"); err != nil {
		t.Fatalf("exchange after reconnect: %v", err)
	}
	client.mu.Lock()
	newConnection := client.conn
	client.mu.Unlock()
	if newConnection == nil || newConnection == oldConnection {
		t.Fatal("client did not replace the closed QUIC connection")
	}
}

func TestSharedQUICDialSurvivesFirstCallerCancellation(t *testing.T) {
	_, clientTLS := testTLSConfigs(t)
	client, err := NewClient(ClientConfig{
		ServerAddress:   "127.0.0.1:4433",
		Token:           testToken,
		TLSConfig:       clientTLS,
		QUICDialTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	dialStarted := make(chan struct{})
	dialRelease := make(chan struct{})
	dialReturned := make(chan struct{})
	dialError := errors.New("controlled QUIC dial failure")
	var calls atomic.Int64
	client.dialQUIC = func(
		ctx context.Context,
		_ string,
		_ *tls.Config,
		_ *quic.Config,
	) (*quic.Conn, error) {
		calls.Add(1)
		close(dialStarted)
		defer close(dialReturned)
		select {
		case <-dialRelease:
			return nil, dialError
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
	}

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstResult := make(chan error, 1)
	go func() {
		_, err := client.connection(firstCtx)
		firstResult <- err
	}()
	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("shared QUIC dial did not start")
	}

	secondCtx, cancelSecond := context.WithTimeout(context.Background(), time.Second)
	defer cancelSecond()
	secondResult := make(chan error, 1)
	go func() {
		_, err := client.connection(secondCtx)
		secondResult <- err
	}()

	cancelFirst()
	if err := <-firstResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("first caller error = %v, want context.Canceled", err)
	}
	select {
	case <-dialReturned:
		t.Fatal("first caller cancellation terminated the shared QUIC dial")
	case <-time.After(25 * time.Millisecond):
	}

	close(dialRelease)
	if err := <-secondResult; !errors.Is(err, dialError) {
		t.Fatalf("second caller error = %v, want controlled dial failure", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("QUIC dial calls = %d, want one shared attempt", got)
	}
}

func TestTLSFallbackHalfCloseAndTLS13(t *testing.T) {
	targetAddress, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	serverTLS, clientTLS := testTLSConfigs(t)
	server := startTLSServer(t, serverTLS, &net.Dialer{}, testToken)
	client, err := NewTLSClient(TLSClientConfig{
		ServerAddress: server.Addr().String(),
		Token:         testToken,
		TLSConfig:     clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	conn, err := client.DialContext(context.Background(), "tcp", targetAddress)
	if err != nil {
		t.Fatal(err)
	}
	tracked, ok := conn.(*trackedTLSConn)
	if !ok {
		t.Fatalf("connection type = %T", conn)
	}
	state := tracked.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		t.Fatalf("TLS version = %#x", state.Version)
	}
	if state.NegotiatedProtocol != protocol.ALPN {
		t.Fatalf("ALPN = %q", state.NegotiatedProtocol)
	}
	if err := completeExchange(conn, "fallback payload"); err != nil {
		t.Fatal(err)
	}
}

func TestClientFallsBackWhenUDPIsUnavailable(t *testing.T) {
	targetAddress, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	serverTLS, clientTLS := testTLSConfigs(t)
	fallback := startTLSServer(t, serverTLS, &net.Dialer{}, testToken)

	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unusedQUICAddress := udp.LocalAddr().String()
	_ = udp.Close()
	client, err := NewClient(ClientConfig{
		ServerAddress:    unusedQUICAddress,
		FallbackAddress:  fallback.Addr().String(),
		Token:            testToken,
		TLSConfig:        clientTLS,
		QUICDialTimeout:  100 * time.Millisecond,
		HandshakeTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.fallbackCooldown != defaultFallbackCooldown {
		t.Fatalf("default fallback cooldown = %s, want %s", client.fallbackCooldown, defaultFallbackCooldown)
	}
	if err := exchange(client, targetAddress, "fallback after UDP timeout"); err != nil {
		t.Fatal(err)
	}
}

func TestFallbackCircuitBreakerAllowsOnlyOneConcurrentProbe(t *testing.T) {
	targetAddress, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	serverTLS, clientTLS := testTLSConfigs(t)
	fallback := startTLSServer(t, serverTLS, &net.Dialer{}, testToken)
	blackholeAddress := startUDPBlackhole(t)

	// Drive the cooldown transition below instead of assuming that all TLS
	// exchanges finish within a short wall-clock interval on a loaded runner.
	// The exact expiry boundary is checked separately with a supplied clock.
	const cooldown = time.Hour
	client, err := NewClient(ClientConfig{
		ServerAddress:    blackholeAddress,
		FallbackAddress:  fallback.Addr().String(),
		Token:            testToken,
		TLSConfig:        clientTLS,
		QUICDialTimeout:  60 * time.Millisecond,
		HandshakeTimeout: time.Second,
		FallbackCooldown: cooldown,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var attempts atomic.Int32
	probeReady := make(chan struct{})
	probeRelease := make(chan struct{})
	var releaseOnce sync.Once
	releaseProbe := func() { releaseOnce.Do(func() { close(probeRelease) }) }
	defer releaseProbe()
	realDialQUIC := client.dialQUIC
	client.dialQUIC = func(ctx context.Context, address string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
		attempt := attempts.Add(1)
		conn, err := realDialQUIC(ctx, address, tlsConfig, config)
		if attempt == 2 {
			// Keep the half-open probe pending after its real UDP attempt. Other
			// callers must finish via TLS before this failure is published; a
			// broken probe lock cannot hide behind a newly reopened cooldown.
			close(probeReady)
			select {
			case <-probeRelease:
			case <-client.ctx.Done():
			}
		}
		return conn, err
	}

	// Concurrent callers share the first failed handshake, which opens the
	// circuit, and all succeed through TLS. Count dial calls directly: UDP
	// source-port reuse or a delayed packet observer is not an attempt ID.
	runConcurrentExchanges(t, client, targetAddress, 20)
	initialAttempts := attempts.Load()
	if initialAttempts != 1 {
		t.Fatalf("initial QUIC attempts = %d, want 1", initialAttempts)
	}

	runConcurrentExchanges(t, client, targetAddress, 20)
	if got := attempts.Load(); got != initialAttempts {
		t.Fatalf("QUIC attempts during cooldown = %d, want %d", got, initialAttempts)
	}

	client.mu.Lock()
	client.primaryFailedAt = time.Now().Add(-cooldown)
	client.mu.Unlock()
	probeResult := make(chan error, 1)
	go func() { probeResult <- exchange(client, targetAddress, "half-open probe") }()
	select {
	case <-probeReady:
	case <-time.After(5 * time.Second):
		t.Fatal("half-open QUIC probe did not reach its real dial result")
	}
	runConcurrentExchanges(t, client, targetAddress, 30)
	if got, want := attempts.Load(), initialAttempts+1; got != want {
		t.Fatalf("QUIC attempts after cooldown = %d, want exactly one probe (%d)", got, want)
	}
	releaseProbe()
	if err := <-probeResult; err != nil {
		t.Fatalf("half-open probe did not fall back to TLS: %v", err)
	}
	if tryPrimary, _ := client.shouldTryPrimary(time.Now()); tryPrimary {
		t.Fatal("failed half-open probe did not reopen the cooldown")
	}
}

func TestFallbackCircuitBreakerCooldownBoundary(t *testing.T) {
	failedAt := time.Date(2026, time.September, 8, 0, 0, 0, 0, time.UTC)
	const cooldown = 250 * time.Millisecond
	client := &Client{
		primaryFailedAt:   failedAt,
		fallbackCooldown:  cooldown,
		primaryFailReason: ClientReasonQUICDialFailed,
	}
	if try, reason := client.shouldTryPrimary(failedAt.Add(cooldown - time.Nanosecond)); try || reason != ClientReasonQUICDialFailed {
		t.Fatalf("before expiry: try=%v reason=%q", try, reason)
	}
	if try, reason := client.shouldTryPrimary(failedAt.Add(cooldown)); !try || reason != "" {
		t.Fatalf("at expiry: try=%v reason=%q", try, reason)
	}
	if try, reason := client.shouldTryPrimary(failedAt.Add(2 * cooldown)); try || reason != ClientReasonQUICDialFailed {
		t.Fatalf("pending probe: try=%v reason=%q", try, reason)
	}
}

func TestExistingQUICStreamBlackholeFallsBackWithinPrimaryBudget(t *testing.T) {
	targetAddress, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	serverTLS, clientTLS := testTLSConfigs(t)
	primaryAddress := startQUICStreamBlackhole(t, serverTLS)
	fallback := startTLSServer(t, serverTLS, &net.Dialer{}, testToken)

	const primaryBudget = 250 * time.Millisecond
	client, err := NewClient(ClientConfig{
		ServerAddress:         primaryAddress,
		FallbackAddress:       fallback.Addr().String(),
		Token:                 testToken,
		TLSConfig:             clientTLS,
		QUICDialTimeout:       primaryBudget,
		PrimaryAttemptTimeout: primaryBudget,
		HandshakeTimeout:      5 * time.Second,
		FallbackCooldown:      time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// The first stream succeeds and proves that the second request is using an
	// already-established QUIC connection rather than timing out while dialing.
	warmCtx, warmCancel := context.WithTimeout(context.Background(), time.Second)
	warm, err := client.DialContext(warmCtx, "tcp", targetAddress)
	warmCancel()
	if err != nil {
		t.Fatalf("warm QUIC stream: %v", err)
	}
	_ = warm.Close()
	client.mu.Lock()
	warmConnection := client.conn
	client.mu.Unlock()
	if warmConnection == nil {
		t.Fatal("warm QUIC connection was not retained")
	}

	parentCtx, parentCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer parentCancel()
	started := time.Now()
	conn, err := client.DialContext(parentCtx, "tcp", targetAddress)
	if err != nil {
		t.Fatalf("auto fallback after stream blackhole: %v", err)
	}
	elapsed := time.Since(started)
	if elapsed < primaryBudget/2 {
		t.Fatalf("fallback occurred before blackhole budget elapsed: %s", elapsed)
	}
	if elapsed > time.Second {
		t.Fatalf("fallback consumed too much of parent context: %s", elapsed)
	}
	if err := completeExchange(conn, "stream blackhole fallback"); err != nil {
		t.Fatal(err)
	}
	if parentCtx.Err() != nil {
		t.Fatalf("fallback exhausted parent context: %v", parentCtx.Err())
	}
	client.mu.Lock()
	breakerOpened := !client.primaryFailedAt.IsZero()
	retainedConnection := client.conn
	client.mu.Unlock()
	if !breakerOpened {
		t.Fatal("stream blackhole did not open fallback circuit")
	}
	if retainedConnection != warmConnection {
		t.Fatal("a single timed-out stream invalidated the shared QUIC connection")
	}
}

func TestCanceledStreamPreservesSharedQUICConnectionAndCancelsRemoteDial(t *testing.T) {
	targetAddress, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	serverTLS, clientTLS := testTLSConfigs(t)

	slowStarted := make(chan struct{})
	slowCanceled := make(chan struct{})
	var startOnce sync.Once
	var cancelOnce sync.Once
	direct := &net.Dialer{}
	dialer := transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "slow.example:443" {
			return direct.DialContext(ctx, network, address)
		}
		startOnce.Do(func() { close(slowStarted) })
		<-ctx.Done()
		cancelOnce.Do(func() { close(slowCanceled) })
		return nil, context.Cause(ctx)
	})
	server, err := ListenQUIC(QUICServerConfig{
		Address:              "127.0.0.1:0",
		Token:                testToken,
		TLSConfig:            serverTLS,
		Dialer:               dialer,
		HandshakeTimeout:     time.Second,
		DialTimeout:          5 * time.Second,
		MaxConcurrentStreams: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	serverCtx, stopServer := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(serverCtx) }()
	t.Cleanup(func() {
		stopServer()
		_ = server.Close()
		if err := <-serveDone; err != nil {
			t.Errorf("QUIC Serve: %v", err)
		}
	})

	fallback := startTLSServer(t, serverTLS, direct, testToken)
	client, err := NewClient(ClientConfig{
		ServerAddress:    server.Addr().String(),
		FallbackAddress:  fallback.Addr().String(),
		Token:            testToken,
		TLSConfig:        clientTLS,
		QUICDialTimeout:  time.Second,
		TLSDialTimeout:   time.Second,
		HandshakeTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	longFlow, err := client.DialContext(context.Background(), "tcp", targetAddress)
	if err != nil {
		t.Fatalf("open long-lived QUIC flow: %v", err)
	}
	client.mu.Lock()
	shared := client.conn
	client.mu.Unlock()

	canceledCtx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		conn, err := client.DialContext(canceledCtx, "tcp", "slow.example:443")
		if conn != nil {
			_ = conn.Close()
		}
		result <- err
	}()
	select {
	case <-slowStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("slow remote dial did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled DialContext error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled DialContext did not return promptly")
	}
	select {
	case <-slowCanceled:
	case <-time.After(time.Second):
		t.Fatal("client stream reset did not cancel the relay destination dial")
	}

	client.mu.Lock()
	retained := client.conn
	breakerOpened := !client.primaryFailedAt.IsZero()
	client.mu.Unlock()
	if retained != shared || shared == nil {
		t.Fatal("canceling one stream replaced the shared QUIC connection")
	}
	if breakerOpened {
		t.Fatal("caller cancellation opened the fallback circuit")
	}
	if err := completeExchange(longFlow, "sibling survives cancellation"); err != nil {
		t.Fatalf("established sibling flow was disrupted: %v", err)
	}
}

func TestAuthenticationAndRemoteErrorsAreTypedAndSanitized(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	dialer := transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("secret internal resolver detail")
	})
	server := startQUICServer(t, serverTLS, dialer, testToken)
	fallback := startTLSServer(t, serverTLS, dialer, testToken)

	wrongTokenClient, err := NewClient(ClientConfig{
		ServerAddress:   server.Addr().String(),
		FallbackAddress: fallback.Addr().String(),
		Token:           "wrong-token-value",
		TLSConfig:       clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer wrongTokenClient.Close()
	_, err = wrongTokenClient.DialContext(context.Background(), "tcp", "example.com:443")
	var remoteErr *RemoteError
	if !errors.As(err, &remoteErr) || remoteErr.Status != protocol.StatusUnauthorized {
		t.Fatalf("authentication error = %v", err)
	}
	wrongTokenClient.mu.Lock()
	breakerOpened := !wrongTokenClient.primaryFailedAt.IsZero()
	wrongTokenClient.mu.Unlock()
	if breakerOpened {
		t.Fatal("RemoteError incorrectly opened the fallback circuit breaker")
	}

	client, err := NewClient(ClientConfig{
		ServerAddress: server.Addr().String(), Token: testToken, TLSConfig: clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = client.DialContext(context.Background(), "tcp", "example.com:443")
	if !errors.As(err, &remoteErr) || remoteErr.Status != protocol.StatusDialFailed {
		t.Fatalf("dial error = %v", err)
	}
	if strings.Contains(err.Error(), "secret internal") {
		t.Fatalf("remote error leaked internal detail: %v", err)
	}
}

func TestCertificateVerificationCannotBeDisabled(t *testing.T) {
	if _, err := NewClient(ClientConfig{
		ServerAddress: "127.0.0.1:443",
		Token:         testToken,
		TLSConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec -- must be rejected
	}); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("NewClient error = %v", err)
	}
	if _, err := NewTLSClient(TLSClientConfig{
		ServerAddress: "127.0.0.1:443",
		Token:         testToken,
		TLSConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec -- must be rejected
	}); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("NewTLSClient error = %v", err)
	}
}

func TestUntrustedServerCertificateIsRejected(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	_, untrustedClientTLS := testTLSConfigs(t)
	server := startTLSServer(t, serverTLS, &net.Dialer{}, testToken)
	client, err := NewTLSClient(TLSClientConfig{
		ServerAddress: server.Addr().String(),
		Token:         testToken,
		TLSConfig:     untrustedClientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = client.DialContext(context.Background(), "tcp", "example.com:443")
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("untrusted certificate error = %v", err)
	}
}

func TestHardenedQUICConfigDisablesReplayableFeaturesAndEnablesDatagrams(t *testing.T) {
	client := hardenedQUICClientConfig(&quic.Config{Allow0RTT: true, EnableDatagrams: true})
	if client.Allow0RTT || !client.EnableDatagrams || client.MaxIncomingStreams != -1 || client.MaxIncomingUniStreams != -1 {
		t.Fatalf("unsafe client QUIC config: %#v", client)
	}
	server := hardenedQUICServerConfig(&quic.Config{Allow0RTT: true, EnableDatagrams: true, MaxIncomingStreams: 9999}, 8)
	if server.Allow0RTT || !server.EnableDatagrams || server.MaxIncomingStreams != 8 || server.MaxIncomingUniStreams != -1 {
		t.Fatalf("unsafe server QUIC config: %#v", server)
	}
	if server.KeepAlivePeriod != 0 {
		t.Fatalf("server keepalive = %s; unauthenticated idle connections must not be kept alive", server.KeepAlivePeriod)
	}
}

func TestQUICConnectionLimitAndPreAuthenticationTimeout(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	server, err := ListenQUIC(QUICServerConfig{
		Address:          "127.0.0.1:0",
		Token:            testToken,
		TLSConfig:        serverTLS,
		HandshakeTimeout: 500 * time.Millisecond,
		MaxConnections:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		if err := <-serveDone; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})

	rawClientTLS, err := clientTLSConfig(clientTLS, server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	first, err := quic.DialAddr(context.Background(), server.Addr().String(), rawClientTLS.Clone(), hardenedQUICClientConfig(nil))
	if err != nil {
		t.Fatalf("first QUIC connection: %v", err)
	}
	defer first.CloseWithError(0, "test complete")

	second, secondErr := quic.DialAddr(context.Background(), server.Addr().String(), rawClientTLS.Clone(), hardenedQUICClientConfig(nil))
	if secondErr == nil {
		defer second.CloseWithError(0, "test complete")
		select {
		case <-second.Context().Done():
		case <-time.After(250 * time.Millisecond):
			t.Fatal("connection above MaxConnections was not rejected")
		}
	}
	select {
	case <-first.Context().Done():
		t.Fatal("first unauthenticated connection closed before its authentication deadline")
	default:
	}
	select {
	case <-first.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("unauthenticated QUIC connection survived its authentication deadline")
	}
}

func TestAuthenticatedQUICConnectionSurvivesPreAuthenticationTimeout(t *testing.T) {
	targetAddress, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	serverTLS, clientTLS := testTLSConfigs(t)
	server, err := ListenQUIC(QUICServerConfig{
		Address:          "127.0.0.1:0",
		Token:            testToken,
		TLSConfig:        serverTLS,
		Dialer:           &net.Dialer{},
		HandshakeTimeout: 100 * time.Millisecond,
		MaxConnections:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		if err := <-serveDone; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	client, err := NewClient(ClientConfig{
		ServerAddress:    server.Addr().String(),
		Token:            testToken,
		TLSConfig:        clientTLS,
		HandshakeTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, err := client.DialContext(context.Background(), "tcp", targetAddress)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)
	if err := completeExchange(conn, "authenticated connection remains live"); err != nil {
		t.Fatal(err)
	}
}

func TestQUICConnectionLimitValidation(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	if _, err := ListenQUIC(QUICServerConfig{
		Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS, MaxConnections: -1,
	}); err == nil {
		t.Fatal("negative MaxConnections was accepted")
	}
}

func TestClientValidatesBeforeNetworkIO(t *testing.T) {
	_, clientTLS := testTLSConfigs(t)
	client, err := NewClient(ClientConfig{
		ServerAddress: "127.0.0.1:1", Token: testToken, TLSConfig: clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, tc := range []struct{ network, address string }{
		{"udp", "example.com:53"},
		{"tcp", "missing-port"},
		{"tcp", ""},
	} {
		start := time.Now()
		if _, err := client.DialContext(context.Background(), tc.network, tc.address); err == nil {
			t.Fatalf("DialContext(%q, %q) succeeded", tc.network, tc.address)
		}
		if time.Since(start) > 100*time.Millisecond {
			t.Fatalf("invalid request unexpectedly performed network I/O")
		}
	}
}

func TestStreamHandshakeHonorsContextCancellation(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	blockingDialer := transport.DialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, context.Cause(ctx)
	})
	server := startTLSServer(t, serverTLS, blockingDialer, testToken)
	client, err := NewTLSClient(TLSClientConfig{
		ServerAddress:    server.Addr().String(),
		Token:            testToken,
		TLSConfig:        clientTLS,
		HandshakeTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = client.DialContext(ctx, "tcp", "example.com:443")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DialContext error = %v, want context deadline", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("context cancellation took %s", elapsed)
	}
}

func TestServerCloseAcceptLifecycleRace(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	t.Run("tls", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			server, err := ListenTLS(TLSServerConfig{
				Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			serveDone := make(chan error, 1)
			go func() { serveDone <- server.Serve(ctx) }()
			start := make(chan struct{})
			var racers sync.WaitGroup
			for j := 0; j < 4; j++ {
				racers.Add(1)
				go func() {
					defer racers.Done()
					<-start
					conn, _ := net.DialTimeout("tcp", server.Addr().String(), 100*time.Millisecond)
					if conn != nil {
						_ = conn.Close()
					}
				}()
			}
			close(start)
			_ = server.Close()
			cancel()
			racers.Wait()
			select {
			case err := <-serveDone:
				if err != nil {
					t.Fatalf("Serve iteration %d: %v", i, err)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("Serve iteration %d did not stop", i)
			}
		}
	})

	t.Run("quic", func(t *testing.T) {
		for i := 0; i < 30; i++ {
			server, err := ListenQUIC(QUICServerConfig{
				Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			serveDone := make(chan error, 1)
			go func() { serveDone <- server.Serve(ctx) }()
			client, err := NewClient(ClientConfig{
				ServerAddress: server.Addr().String(), Token: testToken, TLSConfig: clientTLS,
				QUICDialTimeout: 100 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			dialDone := make(chan struct{})
			go func() {
				defer close(dialDone)
				<-start
				conn, _ := client.DialContext(context.Background(), "tcp", "example.com:443")
				if conn != nil {
					_ = conn.Close()
				}
			}()
			close(start)
			_ = server.Close()
			_ = client.Close()
			cancel()
			<-dialDone
			select {
			case err := <-serveDone:
				if err != nil {
					t.Fatalf("Serve iteration %d: %v", i, err)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("Serve iteration %d did not stop", i)
			}
		}
	})
}

func exchange(dialer transport.Dialer, address, payload string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	return completeExchange(conn, payload)
}

func runConcurrentExchanges(t *testing.T, dialer transport.Dialer, address string, count int) {
	t.Helper()
	start := make(chan struct{})
	errorsCh := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := exchange(dialer, address, "circuit breaker"); err != nil {
				errorsCh <- err
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Error(err)
	}
}

func completeExchange(conn net.Conn, payload string) error {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, payload); err != nil {
		return err
	}
	closeWriter, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		return errors.New("connection doesn't support half-close")
	}
	if err := closeWriter.CloseWrite(); err != nil {
		return err
	}
	reply, err := io.ReadAll(conn)
	if err != nil {
		return err
	}
	if got, want := string(reply), "reply:"+payload; got != want {
		return errors.New("reply mismatch: got " + got + ", want " + want)
	}
	return nil
}

func startHalfCloseTarget(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				data, err := io.ReadAll(conn)
				if err == nil {
					_, _ = io.WriteString(conn, "reply:"+string(data))
				}
			}()
		}
	}()
	return listener.Addr().String(), func() {
		cancel()
		_ = listener.Close()
		wg.Wait()
		_ = ctx // retained to make cancellation intent explicit
	}
}

func startUDPBlackhole(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 64<<10)
		for {
			_, _, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = conn.Close()
		<-done
	})
	return conn.LocalAddr().String()
}

func startQUICStreamBlackhole(t *testing.T, tlsConfig *tls.Config) string {
	t.Helper()
	listener, err := quic.ListenAddr(
		"127.0.0.1:0",
		mustServerTLSConfig(t, tlsConfig),
		hardenedQUICServerConfig(nil, 8),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept(ctx)
		if err != nil {
			return
		}
		for streamNumber := 0; ; streamNumber++ {
			stream, err := conn.AcceptStream(ctx)
			if err != nil {
				return
			}
			request, err := protocol.ReadRequest(stream)
			if err != nil {
				stream.CancelRead(streamCanceled)
				stream.CancelWrite(streamCanceled)
				return
			}
			if streamNumber == 0 {
				if err := protocol.WriteResponse(stream, protocol.Response{
					Status: protocol.StatusOK,
					TxMode: request.TxMode, TxProfile: request.TxProfile,
					RxMode: protocol.PacingAdaptive, RxProfile: protocol.ProfileBalanced,
				}); err != nil {
					return
				}
				_ = stream.Close()
				continue
			}
			// Intentionally neither respond nor close. The client must bound this
			// established-stream black hole with its primary attempt budget.
			select {
			case <-ctx.Done():
			case <-conn.Context().Done():
			}
			return
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		<-done
	})
	return listener.Addr().String()
}

func mustServerTLSConfig(t *testing.T, input *tls.Config) *tls.Config {
	t.Helper()
	config, err := serverTLSConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func startQUICServer(t *testing.T, tlsConfig *tls.Config, dialer transport.Dialer, token string) *QUICServer {
	t.Helper()
	server, err := ListenQUIC(QUICServerConfig{
		Address: "127.0.0.1:0", Token: token, TLSConfig: tlsConfig, Dialer: dialer,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		if err := <-done; err != nil {
			t.Errorf("QUIC Serve: %v", err)
		}
	})
	return server
}

func startTLSServer(t *testing.T, tlsConfig *tls.Config, dialer transport.Dialer, token string) *TLSServer {
	t.Helper()
	server, err := ListenTLS(TLSServerConfig{
		Address: "127.0.0.1:0", Token: token, TLSConfig: tlsConfig, Dialer: dialer,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		if err := <-done; err != nil {
			t.Errorf("TLS Serve: %v", err)
		}
	})
	return server
}

func testTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "autocar test"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(parsed)
	return &tls.Config{Certificates: []tls.Certificate{certificate}}, &tls.Config{
		RootCAs: pool, ServerName: "127.0.0.1",
	}
}
