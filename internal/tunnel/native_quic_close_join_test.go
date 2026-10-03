package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/protocol"
	quic "github.com/quic-go/quic-go"
)

// The gate changes only when a real successful DialAddr result is handed back
// to the client. It does not fake a connection, a handshake, or admission.
// Cancellation can race the pinned QUIC dial's successful handshake select;
// the client must own and finish cleaning up that late result before Close.
func TestNativeQUICCloseJoinsLatePhysicalDial(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", mustServerTLSConfig(t, serverTLS), hardenedQUICServerConfig(nil, 2))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	client, err := NewClient(ClientConfig{ServerAddress: listener.Addr().String(), Token: testToken,
		TLSConfig: clientTLS, QUICDialTimeout: 2 * time.Second})
	if err != nil {
		cancel()
		_ = listener.Close()
		t.Fatal(err)
	}

	peerReady := make(chan *quic.Conn, 1)
	peerDone := make(chan struct{})
	peerErr := make(chan error, 1)
	go func() {
		defer close(peerDone)
		peer, err := listener.Accept(ctx)
		if err != nil {
			peerErr <- err
			return
		}
		peerReady <- peer
		<-peer.Context().Done()
		peerErr <- nil
	}()

	release := make(chan struct{})
	var releaseOnce sync.Once
	openGate := func() { releaseOnce.Do(func() { close(release) }) }
	dialReady := make(chan *quic.Conn, 1)
	dialReturned := make(chan struct{})
	realDial := client.dialQUIC
	client.dialQUIC = func(dialCtx context.Context, address string, tlsConfig *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		defer close(dialReturned)
		conn, err := realDial(dialCtx, address, tlsConfig, cfg)
		if err != nil {
			return nil, err
		}
		dialReady <- conn
		// Once the underlying call has succeeded it no longer owns the result.
		// This bounded gate models late return, not another cancellable dial.
		select {
		case <-release:
		case <-ctx.Done():
		}
		return conn, nil
	}
	callerDone := make(chan struct{})
	callerResult := make(chan error, 1)
	go func() {
		defer close(callerDone)
		conn, err := client.connection(ctx)
		if conn != nil {
			_ = conn.CloseWithError(applicationShutdown, "unexpected handoff")
		}
		callerResult <- err
	}()
	closeResults := make(chan error, 2)
	closeDone := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
	var closeStarted [2]bool
	var physical, peer *quic.Conn
	var attemptDone <-chan struct{}

	t.Cleanup(func() {
		// Release every synthetic wait before joining production Close. Exact
		// sockets are independently closed if a failed assertion left them live.
		openGate()
		cancel()
		if physical != nil {
			_ = physical.CloseWithError(applicationShutdown, "test cleanup")
		}
		if peer != nil {
			_ = peer.CloseWithError(applicationShutdown, "test cleanup")
		}
		_ = listener.Close()
		_ = client.Close()
		nativeQUICCloseJoinWait(t, dialReturned, "dial callback cleanup")
		if attemptDone != nil {
			nativeQUICCloseJoinWait(t, attemptDone, "physical attempt cleanup")
		}
		nativeQUICCloseJoinWait(t, callerDone, "caller cleanup")
		for index, started := range closeStarted {
			if started {
				nativeQUICCloseJoinWait(t, closeDone[index], "Close worker cleanup")
			}
		}
		nativeQUICCloseJoinWait(t, peerDone, "peer cleanup")
	})

	select {
	case physical = <-dialReady:
	case <-callerDone:
		t.Fatalf("real physical handshake failed: %v", <-callerResult)
	case <-ctx.Done():
		t.Fatal("real physical handshake did not complete")
	}
	select {
	case peer = <-peerReady:
	case <-peerDone:
		t.Fatalf("real peer Accept failed: %v", <-peerErr)
	case <-ctx.Done():
		t.Fatal("real peer did not accept the completed handshake")
	}
	state := physical.ConnectionState()
	if state.TLS.Version != tls.VersionTLS13 || state.TLS.NegotiatedProtocol != protocol.ALPN || state.Used0RTT {
		t.Fatalf("physical TLS=%#x ALPN=%q 0-RTT=%v", state.TLS.Version, state.TLS.NegotiatedProtocol, state.Used0RTT)
	}
	client.mu.Lock()
	if client.dialing != nil {
		attemptDone = client.dialing.done
	}
	unpublished := client.conn == nil
	client.mu.Unlock()
	if attemptDone == nil || !unpublished {
		t.Fatal("gate did not retain the actual unregistered physical attempt")
	}

	startClose := func(index int) {
		closeStarted[index] = true
		go func() {
			defer close(closeDone[index])
			closeResults <- client.Close()
		}()
	}
	startClose(0)
	select {
	case <-client.ctx.Done(): // The first Close has crossed its closed gate.
	case <-ctx.Done():
		t.Fatal("first Close did not cancel the client lifetime")
	}
	startClose(1)
	for index := range closeDone {
		select {
		case <-closeDone[index]:
			t.Errorf("Close worker %d returned before the late physical result could be cleaned up", index)
		case <-time.After(75 * time.Millisecond):
		}
	}
	if physical.Context().Err() != nil || peer.Context().Err() != nil {
		t.Error("independent cleanup or a caller closed the gated real physical result")
	}
	select {
	case <-attemptDone:
		t.Error("attempt completed while its real physical return was still gated")
	default:
	}

	openGate()
	for index := range closeDone {
		if !nativeQUICCloseJoinWait(t, closeDone[index], "Close completion") {
			return
		}
		if err := <-closeResults; err != nil {
			t.Errorf("Close returned %v", err)
		}
	}
	if !nativeQUICCloseJoinWait(t, dialReturned, "real dial callback") ||
		!nativeQUICCloseJoinWait(t, attemptDone, "physical attempt") ||
		!nativeQUICCloseJoinWait(t, callerDone, "connection caller") ||
		!nativeQUICCloseJoinWait(t, physical.Context().Done(), "physical close") ||
		!nativeQUICCloseJoinWait(t, peerDone, "actual peer close") {
		return
	}
	if err := <-callerResult; !errors.Is(err, net.ErrClosed) {
		t.Errorf("closed caller result=%v, want net.ErrClosed", err)
	}
	if err := <-peerErr; err != nil {
		t.Errorf("peer worker=%v", err)
	}
	client.mu.Lock()
	retained := client.conn != nil || client.dialing != nil
	client.mu.Unlock()
	if retained {
		t.Error("completed Close retained physical connection or dial attempt")
	}
	if _, err := client.DialContext(ctx, "tcp", "127.0.0.1:1"); !errors.Is(err, net.ErrClosed) {
		t.Errorf("future dial=%v, want net.ErrClosed", err)
	}
}

func nativeQUICCloseJoinWait(t *testing.T, done <-chan struct{}, phase string) bool {
	t.Helper()
	select {
	case <-done:
		return true
	case <-time.After(2 * time.Second):
		t.Errorf("%s did not join", phase)
		return false
	}
}
