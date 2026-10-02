package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
	"github.com/cppla/autocar/internal/tunnel"
)

// Expose completion of one production serveConn worker without changing its
// protocol, reads, deadlines or context. Both ends use real loopback TCP and
// the accepted connection still passes through the ordinary managed listener.
type socksTCPForcedSetupFixture struct {
	server      *SOCKS5Server
	client      net.Conn
	handlerDone chan struct{}
}

func newSOCKSTCPForcedSetupFixture(t *testing.T, cfg Config) *socksTCPForcedSetupFixture {
	t.Helper()
	server, err := NewSOCKS5Server(cfg)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	managed, err := server.lifecycle.manage(listener)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	f := &socksTCPForcedSetupFixture{server: server, handlerDone: make(chan struct{})}
	acceptResult := make(chan error, 1)
	go func() {
		defer close(f.handlerDone)
		conn, err := managed.Accept()
		acceptResult <- err
		if err == nil {
			server.serveConn(conn)
		}
	}()
	t.Cleanup(func() {
		if f.client != nil {
			_ = f.client.Close()
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = server.Shutdown(ctx)
		awaitSOCKSTCPForcedSignal(t, f.handlerDone, "serveConn cleanup")
	})
	f.client = dialTCP(t, listener.Addr().String())
	select {
	case err := <-acceptResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SOCKS TCP fixture did not accept its client")
	}
	socksGreeting(t, f.client, nil)
	mustWrite(t, f.client, ipv4SOCKSRequest(socksCommandConnect, net.IPv4(127, 0, 0, 1), 443))
	return f
}

func awaitSOCKSTCPForcedSignal(t *testing.T, done <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Errorf("%s did not finish", label)
	}
}

func awaitSOCKSTCPForcedContext(t *testing.T, contexts <-chan context.Context) context.Context {
	t.Helper()
	select {
	case ctx := <-contexts:
		return ctx
	case <-time.After(2 * time.Second):
		t.Fatal("SOCKS TCP did not enter the caller DialContext")
		return nil
	}
}

func forceSOCKSTCPSetupShutdown(t *testing.T, f *socksTCPForcedSetupFixture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	err := f.server.Shutdown(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("forced Shutdown = %v, want deadline exceeded", err)
	}
	f.server.lifecycle.tracker.mu.Lock()
	held := len(f.server.lifecycle.tracker.conns)
	f.server.lifecycle.tracker.mu.Unlock()
	if held != 0 {
		t.Fatalf("forced Shutdown retained %d tracked connection slots", held)
	}
	_ = f.client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadAll(f.client); err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Fatalf("forced Shutdown did not close the downstream TCP connection: %v", err)
		}
	}
}

func requireSOCKSTCPForcedSetupCompletion(t *testing.T, ctx context.Context, dialDone, handlerDone <-chan struct{}) {
	t.Helper()
	// One budget covers the actual caller context, dial return and production
	// handler completion. It is much shorter than the native default 5s dial.
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	ctxDone := ctx.Done()
	for ctxDone != nil || dialDone != nil || handlerDone != nil {
		select {
		case <-ctxDone:
			ctxDone = nil
		case <-dialDone:
			dialDone = nil
		case <-handlerDone:
			handlerDone = nil
		case <-timer.C:
			t.Fatalf("forced setup remained active: context=%v dialPending=%t handlerPending=%t", ctx.Err(), dialDone != nil, handlerDone != nil)
		}
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("forced setup caller error = %v, want context canceled", ctx.Err())
	}
}

func newSOCKSTCPNativeBlackhole(t *testing.T) (*tunnel.Client, *net.UDPConn) {
	t.Helper()
	blackhole, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = blackhole.Close() })
	native, err := tunnel.NewClient(tunnel.ClientConfig{
		ServerAddress: blackhole.LocalAddr().String(),
		Token:         "local-socks-tcp-setup-regression-token",
		TLSConfig:     &tls.Config{ServerName: "localhost"},
		// Preserve the production default 5s shared physical-dial budget.
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = native.Close() })
	return native, blackhole
}

func readSOCKSTCPNativeInitial(t *testing.T, peer *net.UDPConn) (*net.UDPAddr, []byte) {
	t.Helper()
	if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 4096)
	n, source, err := peer.ReadFromUDP(packet)
	if err != nil || n < 1200 || packet[0]&0xc0 != 0xc0 {
		t.Fatalf("native QUIC Initial was not observed: bytes=%d error=%v", n, err)
	}
	// The public long-header destination CID identifies this particular
	// physical handshake without reaching into native Client internals. A
	// single-use client may legitimately use an empty source CID.
	destinationLength := int(packet[5])
	if destinationLength == 0 || 6+destinationLength >= n {
		t.Fatal("native Initial has no complete destination connection ID")
	}
	destinationID := bytes.Clone(packet[6 : 6+destinationLength])
	t.Logf("real native QUIC Initial: bytes=%d source=%s; shared dial budget remains 5s", n, source)
	return source, destinationID
}

func TestSOCKSTCPSetupAlreadyClosedSkipsDial(t *testing.T) {
	dialCalls := 0
	dialer := transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
		dialCalls++
		return nil, errors.New("closed SOCKS connection must not start a remote dial")
	})
	server, err := NewSOCKS5Server(Config{Dialer: dialer})
	if err != nil {
		t.Fatal(err)
	}
	local, remote := net.Pipe()
	t.Cleanup(func() { _ = remote.Close() })
	tracked := &trackedConn{Conn: local, tracker: server.lifecycle.tracker}
	if !server.lifecycle.tracker.add(tracked) {
		t.Fatal("fixture connection was not admitted")
	}
	if err := tracked.Close(); err != nil {
		t.Fatal(err)
	}
	server.serveConnect(tracked, socksRequest{command: socksCommandConnect, address: "127.0.0.1:443"})
	if dialCalls != 0 {
		t.Fatalf("already closed SOCKS TCP setup started %d remote dials", dialCalls)
	}
}

func TestSOCKSTCPSetupForcedShutdownCancelsDial(t *testing.T) {
	for _, mode := range []string{"context-aware pending dial", "real native QUIC blackhole"} {
		t.Run(mode, func(t *testing.T) {
			contexts := make(chan context.Context, 1)
			dialDone := make(chan struct{})
			release := make(chan struct{})
			var native *tunnel.Client
			var peer *net.UDPConn
			if mode == "real native QUIC blackhole" {
				native, peer = newSOCKSTCPNativeBlackhole(t)
			}
			dialer := transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
				defer close(dialDone)
				contexts <- ctx
				if native != nil {
					return native.DialContext(ctx, network, address)
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-release:
					return nil, errors.New("independent test cleanup release")
				}
			})
			f := newSOCKSTCPForcedSetupFixture(t, Config{Dialer: dialer, MaxConnections: 1})
			t.Cleanup(func() {
				// These are independent failure-cleanup paths, used only after
				// the assertions about frontend cancellation have completed.
				close(release)
				if native != nil {
					_ = native.Close()
				}
				awaitSOCKSTCPForcedSignal(t, dialDone, "caller dial cleanup")
			})
			ctx := awaitSOCKSTCPForcedContext(t, contexts)
			if peer != nil {
				readSOCKSTCPNativeInitial(t, peer)
			}
			if err := ctx.Err(); err != nil {
				t.Fatalf("setup context expired before Shutdown: %v", err)
			}
			forceSOCKSTCPSetupShutdown(t, f)
			requireSOCKSTCPForcedSetupCompletion(t, ctx, dialDone, f.handlerDone)
		})
	}
}

func TestSOCKSTCPSetupShutdownPreservesSharedNativeDial(t *testing.T) {
	native, peer := newSOCKSTCPNativeBlackhole(t)
	contexts := make(chan context.Context, 1)
	firstDialDone := make(chan struct{})
	dialer := transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		defer close(firstDialDone)
		contexts <- ctx
		return native.DialContext(ctx, network, address)
	})
	f := newSOCKSTCPForcedSetupFixture(t, Config{Dialer: dialer, MaxConnections: 1})
	firstCtx := awaitSOCKSTCPForcedContext(t, contexts)
	originalSource, originalDestinationID := readSOCKSTCPNativeInitial(t, peer)
	siblingCtx, cancelSibling := context.WithCancel(context.Background())
	siblingStarted, siblingDone := make(chan struct{}), make(chan struct{})
	siblingResult := make(chan error, 1)
	go func() {
		defer close(siblingDone)
		close(siblingStarted)
		conn, err := native.DialContext(siblingCtx, "tcp", "127.0.0.1:8443")
		if conn != nil {
			_ = conn.Close()
		}
		siblingResult <- err
	}()
	t.Cleanup(func() {
		cancelSibling()
		_ = native.Close()
		awaitSOCKSTCPForcedSignal(t, siblingDone, "independent native caller cleanup")
		awaitSOCKSTCPForcedSignal(t, firstDialDone, "frontend native caller cleanup")
	})
	awaitSOCKSTCPForcedSignal(t, siblingStarted, "independent native caller start")
	forceSOCKSTCPSetupShutdown(t, f)
	requireSOCKSTCPForcedSetupCompletion(t, firstCtx, firstDialDone, f.handlerDone)
	if err := siblingCtx.Err(); err != nil {
		t.Fatalf("frontend Shutdown canceled the independent caller context: %v", err)
	}
	select {
	case err := <-siblingResult:
		t.Fatalf("frontend Shutdown ended the independent native caller: %v", err)
	default:
	}

	// Drain any packets already queued when the first frontend finished. A
	// subsequently received packet from the same UDP source and destination CID
	// proves the existing physical handshake continued rather than restarting.
	if err := peer.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 4096)
	for {
		_, _, err := peer.ReadFromUDP(packet)
		if err == nil {
			continue
		}
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatal(err)
		}
		break
	}
	if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, nextSource, err := peer.ReadFromUDP(packet)
	if err != nil {
		t.Fatalf("shared physical QUIC dial stopped retransmitting after frontend Shutdown: %v", err)
	}
	if nextSource.String() != originalSource.String() {
		t.Fatalf("shared physical dial changed its UDP source: %s -> %s", originalSource, nextSource)
	}
	if n < 1200 || packet[0]&0xc0 != 0xc0 {
		t.Fatalf("shared dial retransmission is not a QUIC Initial: bytes=%d", n)
	}
	destinationLength := int(packet[5])
	if destinationLength == 0 || 6+destinationLength >= n {
		t.Fatal("shared Initial retransmission has an invalid connection-ID encoding")
	}
	nextDestinationID := packet[6 : 6+destinationLength]
	if !bytes.Equal(nextDestinationID, originalDestinationID) {
		t.Fatalf("shared physical dial restarted with a different destination connection ID: %x -> %x", originalDestinationID, nextDestinationID)
	}
	if err := siblingCtx.Err(); err != nil {
		t.Fatalf("independent caller context expired during the shared handshake: %v", err)
	}
	select {
	case err := <-siblingResult:
		t.Fatalf("independent caller stopped during the preserved shared handshake: %v", err)
	default:
	}
	t.Logf("after frontend cancellation, original QUIC handshake retransmitted %d bytes from %s with the same destination CID", n, nextSource)
	// Only now cancel this independent caller and verify its own wait returns,
	// before fixture cleanup closes the separately owned shared native Client.
	cancelSibling()
	select {
	case err := <-siblingResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("independent native caller cancellation = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("independent native caller did not cancel promptly")
	}
	awaitSOCKSTCPForcedSignal(t, siblingDone, "independently canceled native caller")
}
