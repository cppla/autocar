package tunnel

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/transport"
	quic "github.com/quic-go/quic-go"
)

func TestStreamAdmissionValidationAndCompatibility(t *testing.T) {
	for _, limit := range []int{-1, 0} {
		if admission, err := NewStreamAdmission(limit); err == nil || admission != nil {
			t.Fatalf("NewStreamAdmission(%d) = (%v, %v), want error", limit, admission, err)
		}
	}

	shared, err := NewStreamAdmission(1)
	if err != nil {
		t.Fatal(err)
	}
	first, err := newServerCoreWithAdmission(testToken, nil, 0, 0, 1, shared)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newServerCoreWithAdmission(testToken, nil, 0, 0, 0, shared)
	if err != nil {
		t.Fatal(err)
	}
	if first.sem != second.sem {
		t.Fatal("servers configured with one admission did not share its budget")
	}
	if !first.acquire() {
		t.Fatal("first shared admission failed")
	}
	if second.acquire() {
		t.Fatal("second server exceeded the shared stream limit")
	}
	first.release()
	if !second.acquire() {
		t.Fatal("released shared admission was not reusable")
	}
	second.release()

	legacyFirst, err := newServerCore(testToken, nil, 0, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	legacySecond, err := newServerCore(testToken, nil, 0, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if legacyFirst.sem == legacySecond.sem {
		t.Fatal("independently configured servers unexpectedly share a budget")
	}
	if !legacyFirst.acquire() || !legacySecond.acquire() {
		t.Fatal("independent server compatibility budgets interfered")
	}
	legacyFirst.release()
	legacySecond.release()
}

func TestStreamAdmissionRejectsInvalidConfiguration(t *testing.T) {
	shared, err := NewStreamAdmission(2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newServerCoreWithAdmission(testToken, nil, 0, 0, 1, shared); err == nil {
		t.Fatal("mismatched MaxConcurrentStreams and StreamAdmission were accepted")
	}
	if _, err := newServerCoreWithAdmission(testToken, nil, 0, 0, 0, &StreamAdmission{}); err == nil {
		t.Fatal("zero-value StreamAdmission was accepted")
	}
}

func TestQUICAndTLSShareGlobalStreamAdmission(t *testing.T) {
	targetAddress, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	serverTLS, clientTLS := testTLSConfigs(t)
	shared, err := NewStreamAdmission(1)
	if err != nil {
		t.Fatal(err)
	}

	dialStarted := make(chan struct{})
	releaseDials := make(chan struct{})
	var startedOnce sync.Once
	var dialCalls atomic.Int64
	direct := &net.Dialer{}
	blockingDialer := transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		dialCalls.Add(1)
		startedOnce.Do(func() { close(dialStarted) })
		select {
		case <-releaseDials:
			return direct.DialContext(ctx, network, address)
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
	})

	quicServer, err := ListenQUIC(QUICServerConfig{
		Address:              "127.0.0.1:0",
		Token:                testToken,
		TLSConfig:            serverTLS,
		Dialer:               blockingDialer,
		MaxConcurrentStreams: 1,
		StreamAdmission:      shared,
	})
	if err != nil {
		t.Fatal(err)
	}
	tlsServer, err := ListenTLS(TLSServerConfig{
		Address:              "127.0.0.1:0",
		Token:                testToken,
		TLSConfig:            serverTLS,
		Dialer:               blockingDialer,
		MaxConcurrentStreams: 1,
		StreamAdmission:      shared,
		MaxClientConnections: 1,
	})
	if err != nil {
		_ = quicServer.Close()
		t.Fatal(err)
	}

	serveCtx, stopServers := context.WithCancel(context.Background())
	quicDone := make(chan error, 1)
	tlsDone := make(chan error, 1)
	go func() { quicDone <- quicServer.Serve(serveCtx) }()
	go func() { tlsDone <- tlsServer.Serve(serveCtx) }()
	t.Cleanup(func() {
		stopServers()
		_ = quicServer.Close()
		_ = tlsServer.Close()
		for name, done := range map[string]<-chan error{"QUIC": quicDone, "TLS": tlsDone} {
			select {
			case serveErr := <-done:
				if serveErr != nil {
					t.Errorf("%s Serve: %v", name, serveErr)
				}
			case <-time.After(5 * time.Second):
				t.Errorf("%s Serve did not stop", name)
			}
		}
	})

	quicClient, err := NewClient(ClientConfig{
		ServerAddress: quicServer.Addr().String(),
		Token:         testToken,
		TLSConfig:     clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer quicClient.Close()
	tlsClient, err := NewTLSClient(TLSClientConfig{
		ServerAddress: tlsServer.Addr().String(),
		Token:         testToken,
		TLSConfig:     clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tlsClient.Close()

	quicResult := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		conn, dialErr := quicClient.DialContext(context.Background(), "tcp", targetAddress)
		quicResult <- struct {
			conn net.Conn
			err  error
		}{conn: conn, err: dialErr}
	}()
	select {
	case <-dialStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("QUIC stream did not reach the relay dialer")
	}
	if got := len(shared.sem); got != 1 {
		t.Fatalf("shared admission usage = %d, want 1", got)
	}

	tlsAttemptCtx, cancelTLSAttempt := context.WithTimeout(context.Background(), 2*time.Second)
	rejected, rejectedErr := tlsClient.DialContext(tlsAttemptCtx, "tcp", targetAddress)
	cancelTLSAttempt()
	if rejected != nil {
		_ = rejected.Close()
		t.Fatal("TLS fallback acquired a stream while the shared budget was full")
	}
	if rejectedErr == nil {
		t.Fatal("TLS fallback unexpectedly succeeded while the shared budget was full")
	}
	if got := dialCalls.Load(); got != 1 {
		t.Fatalf("relay destination dials while full = %d, want 1", got)
	}

	close(releaseDials)
	var quicConn net.Conn
	select {
	case result := <-quicResult:
		if result.err != nil {
			t.Fatalf("admitted QUIC stream: %v", result.err)
		}
		quicConn = result.conn
	case <-time.After(5 * time.Second):
		t.Fatal("admitted QUIC stream did not finish opening")
	}
	if err := quicConn.Close(); err != nil {
		t.Fatal(err)
	}
	waitForCondition(t, 5*time.Second, func() bool { return len(shared.sem) == 0 }, "shared stream release")

	if err := exchange(tlsClient, targetAddress, "shared admission released"); err != nil {
		t.Fatalf("TLS fallback after shared release: %v", err)
	}
	waitForCondition(t, 5*time.Second, func() bool { return len(shared.sem) == 0 }, "TLS stream release")
	if got := dialCalls.Load(); got != 2 {
		t.Fatalf("total relay destination dials = %d, want 2", got)
	}
}

func TestUnauthenticatedTLSConnectionDoesNotConsumeSharedStreamAdmission(t *testing.T) {
	targetAddress, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	serverTLS, clientTLS := testTLSConfigs(t)
	shared, err := NewStreamAdmission(1)
	if err != nil {
		t.Fatal(err)
	}

	quicServer, err := ListenQUIC(QUICServerConfig{
		Address:              "127.0.0.1:0",
		Token:                testToken,
		TLSConfig:            serverTLS,
		MaxConcurrentStreams: 1,
		StreamAdmission:      shared,
	})
	if err != nil {
		t.Fatal(err)
	}
	tlsServer, err := ListenTLS(TLSServerConfig{
		Address:              "127.0.0.1:0",
		Token:                testToken,
		TLSConfig:            serverTLS,
		HandshakeTimeout:     30 * time.Second,
		MaxConcurrentStreams: 1,
		StreamAdmission:      shared,
		MaxClientConnections: 1,
	})
	if err != nil {
		_ = quicServer.Close()
		t.Fatal(err)
	}

	serveCtx, stopServers := context.WithCancel(context.Background())
	quicDone := make(chan error, 1)
	tlsDone := make(chan error, 1)
	go func() { quicDone <- quicServer.Serve(serveCtx) }()
	go func() { tlsDone <- tlsServer.Serve(serveCtx) }()
	t.Cleanup(func() {
		stopServers()
		_ = quicServer.Close()
		_ = tlsServer.Close()
		for name, done := range map[string]<-chan error{"QUIC": quicDone, "TLS": tlsDone} {
			select {
			case serveErr := <-done:
				if serveErr != nil {
					t.Errorf("%s Serve: %v", name, serveErr)
				}
			case <-time.After(5 * time.Second):
				t.Errorf("%s Serve did not stop", name)
			}
		}
	})

	bareTLS, err := net.DialTimeout("tcp", tlsServer.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bareTLS.Close() })
	waitForCondition(t, 5*time.Second, func() bool {
		return len(tlsServer.connSem) == 1
	}, "unauthenticated TLS connection admission")
	if got := len(shared.sem); got != 0 {
		t.Fatalf("unauthenticated TLS connection consumed %d shared stream slots", got)
	}

	quicClient, err := NewClient(ClientConfig{
		ServerAddress: quicServer.Addr().String(),
		Token:         testToken,
		TLSConfig:     clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer quicClient.Close()
	if err := exchange(quicClient, targetAddress, "QUIC remains available"); err != nil {
		t.Fatalf("authenticated QUIC stream was blocked by bare TLS: %v", err)
	}
	waitForCondition(t, 5*time.Second, func() bool { return len(shared.sem) == 0 }, "QUIC stream release")
}

func TestUnauthenticatedQUICStreamsAreGloballyBounded(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	shared, err := NewStreamAdmission(1)
	if err != nil {
		t.Fatal(err)
	}
	server, err := ListenQUIC(QUICServerConfig{
		Address:              "127.0.0.1:0",
		Token:                testToken,
		TLSConfig:            serverTLS,
		HandshakeTimeout:     30 * time.Second,
		MaxConcurrentStreams: 1,
		StreamAdmission:      shared,
		MaxConnections:       2,
		MaxClientConnections: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	serveCtx, stopServer := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(serveCtx) }()
	t.Cleanup(func() {
		stopServer()
		_ = server.Close()
		select {
		case serveErr := <-serveDone:
			if serveErr != nil {
				t.Errorf("QUIC Serve: %v", serveErr)
			}
		case <-time.After(5 * time.Second):
			t.Error("QUIC Serve did not stop")
		}
	})

	rawClientTLS, err := clientTLSConfig(clientTLS, server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	connections := make([]*quic.Conn, 0, 2)
	for range 2 {
		conn, dialErr := quic.DialAddr(
			context.Background(),
			server.Addr().String(),
			rawClientTLS.Clone(),
			hardenedQUICClientConfig(nil),
		)
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		connections = append(connections, conn)
	}
	t.Cleanup(func() {
		for _, conn := range connections {
			_ = conn.CloseWithError(0, "test complete")
		}
	})

	first, err := connections[0].OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	waitForCondition(t, 5*time.Second, func() bool {
		return len(server.streamSem) == 1
	}, "unauthenticated QUIC stream admission")
	if got := len(shared.sem); got != 0 {
		t.Fatalf("unauthenticated QUIC stream consumed %d shared active slots", got)
	}

	second, err := connections[1].OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	if err := second.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	response, err := protocol.ReadResponse(second)
	if err != nil {
		t.Fatalf("read bounded-stream response: %v", err)
	}
	if response.Status != protocol.StatusBusy {
		t.Fatalf("bounded-stream status = %d, want %d", response.Status, protocol.StatusBusy)
	}
	if got := len(server.streamSem); got != 1 {
		t.Fatalf("QUIC pre-authentication stream usage = %d, want 1", got)
	}
	if got := len(shared.sem); got != 0 {
		t.Fatalf("rejected unauthenticated QUIC stream consumed %d shared active slots", got)
	}
}
