package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/protocol"
)

// This context preserves the actual caller's values and cancellation channel.
// The only scheduling gate is its first Deadline return after trusted TLS
// verification. In the pinned implementation this occurs in openProtocol,
// after the TLS handshake and before that exchange's cancellation watcher.
type nativeTLSSetupGateContext struct {
	context.Context
	armed   atomic.Bool
	once    sync.Once
	entered chan struct{}
	release <-chan struct{}
}

func (c *nativeTLSSetupGateContext) Deadline() (time.Time, bool) {
	if c.armed.Load() {
		c.once.Do(func() {
			close(c.entered)
			select {
			case <-c.release:
			case <-c.Context.Done():
			}
		})
	}
	return c.Context.Deadline()
}

func TestNativeTLSCloseJoinsUnregisteredSetup(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	serverTLS = mustServerTLSConfig(t, serverTLS)
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := listener.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	release := make(chan struct{})
	var releaseOnce sync.Once
	openGate := func() { releaseOnce.Do(func() { close(release) }) }
	callerCtx := &nativeTLSSetupGateContext{Context: ctx, entered: make(chan struct{}), release: release}
	clientTLS.VerifyConnection = func(state tls.ConnectionState) error {
		if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != protocol.ALPN || len(state.VerifiedChains) == 0 {
			return errors.New("test: missing trusted TLS 1.3/native ALPN")
		}
		callerCtx.armed.Store(true)
		return nil
	}
	client, err := NewTLSClient(TLSClientConfig{ServerAddress: listener.Addr().String(), Token: testToken,
		TLSConfig: clientTLS, HandshakeTimeout: 2 * time.Second, DialTimeout: 2 * time.Second})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	type peerResult struct {
		conn *tls.Conn
		err  error
	}
	peerReady := make(chan peerResult, 1)
	peerRead := make(chan error, 1)
	peerEOF := make(chan error, 1)
	readStart := make(chan struct{})
	var readOnce sync.Once
	startRead := func() { readOnce.Do(func() { close(readStart) }) }
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		raw, err := listener.AcceptTCP()
		if err != nil {
			peerReady <- peerResult{err: err}
			return
		}
		defer raw.Close()
		conn := tls.Server(raw, serverTLS)
		err = conn.HandshakeContext(ctx)
		peerReady <- peerResult{conn: conn, err: err}
		if err != nil {
			return
		}
		select {
		case <-readStart:
		case <-ctx.Done():
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		var one [1]byte
		// Both TLS handshakes have completed, and the caller's Deadline gate
		// still precedes its first protocol write. Observe this empty raw socket
		// without making a TLS parser timeout that would be unsafe to recover.
		n, err := conn.NetConn().Read(one[:])
		if n != 0 {
			err = fmt.Errorf("test: gated pre-request phase unexpectedly read %d raw bytes", n)
		}
		peerRead <- err
		// The still-live socket is allowed while Close itself remains pending.
		// Do not manufacture peer closure: after setup is released, observe the
		// client's real socket Close by draining raw TCP to EOF. A canceled TLS
		// write can corrupt its record sequence, so this ownership test does not
		// require a graceful TLS close_notify after interrupted protocol setup.
		select {
		case <-release:
		case <-ctx.Done():
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = io.Copy(io.Discard, conn.NetConn())
		peerEOF <- err
	}()
	callerDone := make(chan struct{})
	callerResult := make(chan error, 1)
	go func() {
		defer close(callerDone)
		conn, err := client.DialContext(callerCtx, "tcp", listener.Addr().String())
		if conn != nil {
			_ = conn.Close()
			if err == nil {
				err = errors.New("test: unexpected stream handoff after client Close")
			}
		}
		callerResult <- err
	}()
	closeDone := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
	closeResults := make(chan error, 2)
	var closeStarted [2]bool
	var peer *tls.Conn
	t.Cleanup(func() {
		openGate()
		startRead()
		cancel()
		_ = listener.Close()
		if peer != nil {
			_ = peer.NetConn().Close()
		}
		_ = client.Close()
		nativeTLSCloseJoinWait(t, callerDone, "setup caller cleanup")
		for index, started := range closeStarted {
			if started {
				nativeTLSCloseJoinWait(t, closeDone[index], "Close cleanup")
			}
		}
		nativeTLSCloseJoinWait(t, peerDone, "peer cleanup")
	})
	select {
	case <-callerCtx.entered:
	case <-callerDone:
		t.Fatalf("setup did not reach post-TLS gate: %v", <-callerResult)
	case <-ctx.Done():
		t.Fatal("post-TLS setup gate not reached")
	}
	select {
	case ready := <-peerReady:
		peer = ready.conn
		if ready.err != nil {
			t.Fatal(ready.err)
		}
	case <-ctx.Done():
		t.Fatal("real TLS peer handshake did not complete")
	}
	state := peer.ConnectionState()
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != protocol.ALPN {
		t.Fatalf("actual peer TLS=%#x ALPN=%q", state.Version, state.NegotiatedProtocol)
	}
	client.mu.Lock()
	registered := len(client.conns)
	client.mu.Unlock()
	if registered != 0 || ctx.Err() != nil {
		t.Fatalf("gate retained registered=%d caller=%v", registered, ctx.Err())
	}
	for index := range closeDone {
		closeStarted[index] = true
		go func(index int) { defer close(closeDone[index]); closeResults <- client.Close() }(index)
		if index == 0 && !nativeTLSCloseJoinWait(t, client.ctx.Done(), "first Close closed gate") {
			return
		}
	}
	for index := range closeDone {
		select {
		case <-closeDone[index]:
			t.Errorf("Close %d returned before the actual unregistered TLS setup completed", index)
		case <-time.After(75 * time.Millisecond):
		}
	}
	startRead()
	select {
	case err := <-peerRead:
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Errorf("gated actual TLS socket read=%v, want a live-socket timeout", err)
		} else {
			t.Log("actual TLS peer remained live while post-handshake setup return was gated")
		}
	case <-ctx.Done():
		t.Error("actual peer closure was not observed")
	}
	if ctx.Err() != nil {
		t.Error("caller/fixture lifetime canceled before independent cleanup")
	}
	openGate()
	if !nativeTLSCloseJoinWait(t, callerDone, "setup caller") {
		return
	}
	if err := <-callerResult; err == nil {
		t.Error("closed client returned a successful setup")
	}
	for index := range closeDone {
		if !nativeTLSCloseJoinWait(t, closeDone[index], "Close completion") {
			return
		}
		if err := <-closeResults; err != nil {
			t.Errorf("Close=%v", err)
		}
	}
	if !nativeTLSCloseJoinWait(t, peerDone, "real peer completion") {
		return
	}
	select {
	case err := <-peerEOF:
		if err != nil {
			t.Errorf("actual TCP peer did not drain to EOF after setup cleanup: %v", err)
		}
	default:
		t.Error("real peer exited without recording post-release EOF")
	}
	if _, err := client.DialContext(ctx, "tcp", listener.Addr().String()); !errors.Is(err, net.ErrClosed) {
		t.Errorf("future dial=%v, want net.ErrClosed", err)
	}
	t.Log("trusted TLS1.3/native ALPN completed; setup gate preceded native request watcher, not an authenticated target exchange")
}

func TestNativeTLSCloseJoinsApplicationClose(t *testing.T) {
	f := newRelayOwnerFixture(t, "tls", "stalled", false)
	tracked := f.conn.(*trackedTLSConn)
	client := tracked.owner
	raw := tracked.NetConn().(*net.TCPConn)
	control, err := raw.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	var releaseOnce sync.Once
	openGate := func() { releaseOnce.Do(func() { close(release) }) }
	entered, controlDone := make(chan struct{}), make(chan struct{})
	controlResult := make(chan error, 1)
	appDone, ownerDone := make(chan struct{}), make(chan struct{})
	appResult, ownerResult := make(chan error, 1), make(chan error, 1)
	var appStarted, ownerStarted bool
	t.Cleanup(func() {
		openGate()
		nativeTLSCloseJoinWait(t, controlDone, "raw FD control cleanup")
		if appStarted {
			nativeTLSCloseJoinWait(t, appDone, "application Close cleanup")
		}
		if ownerStarted {
			nativeTLSCloseJoinWait(t, ownerDone, "client Close cleanup")
		}
	})
	go func() {
		defer close(controlDone)
		controlResult <- control.Control(func(uintptr) {
			// This is an actual socket FD reference, not a fake Close result.
			// netFD.Close cannot finish destroying it before Control returns.
			close(entered)
			<-release
		})
	}()
	if !nativeTLSCloseJoinWait(t, entered, "actual FD Control entry") {
		return
	}
	appStarted = true
	go func() { defer close(appDone); appResult <- tracked.Close() }()
	deadline, ticker := time.NewTimer(time.Second), time.NewTicker(10*time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		// No extra reader consumes tunnel bytes. The real TCP API witnesses
		// Close's closed-poller state while the held FD reference prevents return.
		if err := raw.SetReadDeadline(time.Now().Add(time.Second)); errors.Is(err, net.ErrClosed) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("actual raw Close did not reach its FD-reference wait")
		}
	}
	select {
	case <-appDone:
		t.Fatal("actual application Close completed before releasing its FD reference")
	default:
	}
	ownerStarted = true
	go func() { defer close(ownerDone); ownerResult <- client.Close() }()
	if !nativeTLSCloseJoinWait(t, client.ctx.Done(), "owner Close closed gate") {
		return
	}
	select {
	case <-ownerDone:
		t.Error("client Close returned before an actual application Close finished")
	case <-time.After(75 * time.Millisecond):
	}
	openGate()
	if !nativeTLSCloseJoinWait(t, controlDone, "raw FD Control completion") ||
		!nativeTLSCloseJoinWait(t, appDone, "application Close completion") ||
		!nativeTLSCloseJoinWait(t, ownerDone, "client Close completion") {
		return
	}
	for name, result := range map[string]<-chan error{"control": controlResult, "application": appResult, "owner": ownerResult} {
		if err := <-result; err != nil {
			t.Errorf("%s=%v", name, err)
		}
	}
	client.mu.Lock()
	registered := len(client.conns)
	client.mu.Unlock()
	if registered != 0 {
		t.Errorf("completed Close retains %d registered streams", registered)
	}
	t.Log("actual authenticated TLS target marker/ack preceded app Close; real FD-reference wait was independently released")
}

func nativeTLSCloseJoinWait(t *testing.T, done <-chan struct{}, phase string) bool {
	t.Helper()
	select {
	case <-done:
		return true
	case <-time.After(2 * time.Second):
		t.Errorf("%s did not join", phase)
		return false
	}
}

var _ context.Context = (*nativeTLSSetupGateContext)(nil)
