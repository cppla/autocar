package tunnel

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func receiveClientEvent(t *testing.T, events <-chan ClientEvent) ClientEvent {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for client event")
		return ClientEvent{}
	}
}

func TestAuthenticatedQUICSnapshotReportsDirectionalPacing(t *testing.T) {
	targetAddress, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	serverTLS, clientTLS := testTLSConfigs(t)
	server := startQUICServer(t, serverTLS, &net.Dialer{}, testToken)
	client, err := NewClient(ClientConfig{
		ServerAddress: server.Addr().String(), Token: testToken, TLSConfig: clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	conn, err := client.DialContext(ctx, "tcp", targetAddress)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	snapshot := client.Snapshot()
	if snapshot.SelectedTransport != "quic" || snapshot.ClientPacing != "adaptive-balanced" || snapshot.RelayPacing != "adaptive-balanced" {
		t.Fatalf("QUIC snapshot = %+v", snapshot)
	}
	if snapshot.ClientNegotiatedBytesPerSecond != 0 || snapshot.RelayNegotiatedBytesPerSecond != 0 || snapshot.LastEvent != nil {
		t.Fatalf("unexpected QUIC negotiation/event metadata: %+v", snapshot)
	}
}

func TestTLSSnapshotRequiresASuccessfulAuthenticatedStream(t *testing.T) {
	targetAddress, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	serverTLS, clientTLS := testTLSConfigs(t)
	server := startTLSServer(t, serverTLS, &net.Dialer{}, testToken)
	client, err := NewTLSClient(TLSClientConfig{
		ServerAddress: server.Addr().String(), Token: testToken, TLSConfig: clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if snapshot := client.Snapshot(); snapshot.SelectedTransport != "" || client.SelectedTransport() != "" {
		t.Fatalf("unused TLS client claimed a selected path: %+v", snapshot)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	conn, err := client.DialContext(ctx, "tcp", targetAddress)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if snapshot := client.Snapshot(); snapshot.SelectedTransport != "tls" ||
		snapshot.ClientPacing != "not-applicable" || snapshot.RelayPacing != "not-applicable" ||
		client.SelectedTransport() != "tls" {
		t.Fatalf("successful TLS snapshot = %+v", snapshot)
	}
}

func TestFallbackEventAndSnapshotRequireSuccessfulAuthenticatedTLSPath(t *testing.T) {
	targetAddress, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	serverTLS, clientTLS := testTLSConfigs(t)
	fallback := startTLSServer(t, serverTLS, &net.Dialer{}, testToken)

	unused, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	blockedQUICAddress := unused.LocalAddr().String()
	_ = unused.Close()

	events := make(chan ClientEvent, 4)
	const fallbackCooldown = 50 * time.Millisecond
	client, err := NewClient(ClientConfig{
		ServerAddress:         blockedQUICAddress,
		FallbackAddress:       fallback.Addr().String(),
		Token:                 testToken,
		TLSConfig:             clientTLS,
		QUICDialTimeout:       75 * time.Millisecond,
		PrimaryAttemptTimeout: 250 * time.Millisecond,
		HandshakeTimeout:      time.Second,
		FallbackCooldown:      fallbackCooldown,
		EventHandler:          func(event ClientEvent) { events <- event },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, dialErr := client.DialContext(ctx, "tcp", targetAddress)
		cancel()
		if dialErr != nil {
			t.Fatalf("fallback dial %d: %v", i+1, dialErr)
		}
		_ = conn.Close()
	}
	fallbackEvent := receiveClientEvent(t, events)
	if fallbackEvent.Kind != ClientEventFallback || fallbackEvent.Reason != ClientReasonQUICDialFailed || fallbackEvent.At.Location() != time.UTC {
		t.Fatalf("fallback event = %+v", fallbackEvent)
	}
	select {
	case unexpected := <-events:
		t.Fatalf("unexpected repeated fallback event: %+v", unexpected)
	default:
	}

	snapshot := client.Snapshot()
	if snapshot.SelectedTransport != "tls" || snapshot.ClientPacing != "tls-fallback" || snapshot.RelayPacing != "tls-fallback" {
		t.Fatalf("fallback snapshot = %+v", snapshot)
	}
	if snapshot.LastEvent == nil || *snapshot.LastEvent != fallbackEvent {
		t.Fatalf("snapshot event = %+v, want %+v", snapshot.LastEvent, fallbackEvent)
	}
	// Snapshot owns its event copy; callers cannot mutate live client state.
	snapshot.LastEvent.Reason = ClientReasonQUICCooldownActive
	if fresh := client.Snapshot(); fresh.LastEvent == nil || fresh.LastEvent.Reason != ClientReasonQUICDialFailed {
		t.Fatalf("snapshot leaked mutable event state: %+v", fresh)
	}

	primary, err := ListenQUIC(QUICServerConfig{
		Address: blockedQUICAddress, Token: testToken, TLSConfig: serverTLS, Dialer: &net.Dialer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	primaryCtx, stopPrimary := context.WithCancel(context.Background())
	primaryDone := make(chan error, 1)
	go func() { primaryDone <- primary.Serve(primaryCtx) }()
	defer func() {
		stopPrimary()
		_ = primary.Close()
		if serveErr := <-primaryDone; serveErr != nil {
			t.Errorf("serve recovered QUIC path: %v", serveErr)
		}
	}()
	time.Sleep(fallbackCooldown + 20*time.Millisecond)
	recoveryCtx, cancelRecovery := context.WithTimeout(context.Background(), 2*time.Second)
	recovered, err := client.DialContext(recoveryCtx, "tcp", targetAddress)
	cancelRecovery()
	if err != nil {
		t.Fatalf("recovered QUIC dial: %v", err)
	}
	_ = recovered.Close()
	recoveryEvent := receiveClientEvent(t, events)
	if recoveryEvent.Kind != ClientEventRecovery || recoveryEvent.Reason != ClientReasonQUICPathRestored {
		t.Fatalf("recovery event = %+v", recoveryEvent)
	}
	if recoveredSnapshot := client.Snapshot(); recoveredSnapshot.SelectedTransport != "quic" ||
		recoveredSnapshot.LastEvent == nil || recoveredSnapshot.LastEvent.Kind != ClientEventRecovery {
		t.Fatalf("recovered QUIC snapshot = %+v", recoveredSnapshot)
	}
}

func TestRecoveryEventIsEmittedOnceAndHandlerPanicsAreContained(t *testing.T) {
	noFallbackEvents := make(chan ClientEvent, 1)
	neverFellBack := &Client{eventHandler: func(event ClientEvent) { noFallbackEvents <- event }}
	neverFellBack.primaryFailed(time.Now(), ClientReasonQUICDialFailed)
	neverFellBack.primarySucceeded(clientPathMetadata{})
	if snapshot := neverFellBack.Snapshot(); snapshot.LastEvent != nil {
		t.Fatalf("QUIC retry without a successful TLS fallback emitted %+v", snapshot.LastEvent)
	}
	select {
	case event := <-noFallbackEvents:
		t.Fatalf("QUIC retry without a successful TLS fallback delivered %+v", event)
	default:
	}

	events := make(chan ClientEvent, 4)
	client := &Client{eventHandler: func(event ClientEvent) { events <- event }}
	client.primaryFailed(time.Now(), ClientReasonQUICStreamOpenFailed)
	client.recordFallback(ClientReasonQUICStreamOpenFailed)
	fallbackEvent := receiveClientEvent(t, events)
	client.primaryHealthy()
	if snapshot := client.Snapshot(); snapshot.SelectedTransport != "tls" || snapshot.LastEvent == nil || snapshot.LastEvent.Kind != ClientEventFallback {
		t.Fatalf("authenticated QUIC error changed selected transport: %+v", snapshot)
	}
	client.primarySucceeded(clientPathMetadata{})
	client.primarySucceeded(clientPathMetadata{})
	recoveryEvent := receiveClientEvent(t, events)
	if fallbackEvent.Kind != ClientEventFallback || fallbackEvent.Reason != ClientReasonQUICStreamOpenFailed ||
		recoveryEvent.Kind != ClientEventRecovery || recoveryEvent.Reason != ClientReasonQUICPathRestored {
		t.Fatalf("transport events = [%+v %+v]", fallbackEvent, recoveryEvent)
	}
	select {
	case unexpected := <-events:
		t.Fatalf("unexpected repeated recovery event: %+v", unexpected)
	default:
	}
	if snapshot := client.Snapshot(); snapshot.LastEvent == nil || snapshot.LastEvent.Kind != ClientEventRecovery {
		t.Fatalf("recovery snapshot = %+v", snapshot)
	}

	panicsContained := make(chan struct{}, 2)
	panicking := &Client{eventHandler: func(ClientEvent) {
		panicsContained <- struct{}{}
		panic("observer must not crash tunnel")
	}}
	panicking.primaryFailed(time.Now(), ClientReasonQUICDialFailed)
	panicking.recordFallback(ClientReasonQUICDialFailed)
	panicking.primarySucceeded(clientPathMetadata{})
	receiveClientEventSignal := func() {
		t.Helper()
		select {
		case <-panicsContained:
		case <-time.After(time.Second):
			t.Fatal("panicking client event handler stopped the dispatcher")
		}
	}
	receiveClientEventSignal()
	receiveClientEventSignal()
}

func TestLateFallbackCompletionUpdatesSelectionWithoutReopeningCircuit(t *testing.T) {
	events := make(chan ClientEvent, 4)
	client := &Client{
		fallbackCooldown: time.Millisecond,
		eventHandler:     func(event ClientEvent) { events <- event },
	}
	client.primaryFailed(time.Now().Add(-time.Second), ClientReasonQUICDialFailed)
	client.recordFallback(ClientReasonQUICDialFailed)
	if event := receiveClientEvent(t, events); event.Kind != ClientEventFallback {
		t.Fatalf("initial event = %+v", event)
	}

	// One caller becomes the recovery probe while a concurrent caller starts a
	// TLS fallback. The QUIC path can succeed before that TLS dial completes.
	if tryPrimary, _ := client.shouldTryPrimary(time.Now()); !tryPrimary {
		t.Fatal("cooldown probe was not admitted")
	}
	tryPrimary, lateFallbackReason := client.shouldTryPrimary(time.Now())
	if tryPrimary {
		t.Fatal("concurrent caller unexpectedly joined the cooldown probe")
	}
	client.primarySucceeded(clientPathMetadata{})
	client.recordFallback(lateFallbackReason)

	recovery := receiveClientEvent(t, events)
	lateFallback := receiveClientEvent(t, events)
	if recovery.Kind != ClientEventRecovery || lateFallback.Kind != ClientEventFallback {
		t.Fatalf("completion-order events = [%+v %+v]", recovery, lateFallback)
	}
	if snapshot := client.Snapshot(); snapshot.SelectedTransport != "tls" ||
		snapshot.LastEvent == nil || snapshot.LastEvent.Kind != ClientEventFallback {
		t.Fatalf("latest successful path snapshot = %+v", snapshot)
	}
	if tryPrimary, _ := client.shouldTryPrimary(time.Now()); !tryPrimary {
		t.Fatal("late TLS completion reopened the healthy QUIC circuit")
	}
}

func TestClientEventHandlerIsSerializedInTransitionOrder(t *testing.T) {
	var active atomic.Int32
	var maximumActive atomic.Int32
	enteredFallback := make(chan struct{})
	releaseFallback := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseFallback) }) })
	handledAll := make(chan struct{})
	var handled []ClientEventKind
	var client *Client
	client = &Client{eventHandler: func(event ClientEvent) {
		current := active.Add(1)
		for {
			maximum := maximumActive.Load()
			if current <= maximum || maximumActive.CompareAndSwap(maximum, current) {
				break
			}
		}
		// Callbacks run without c.mu, so reading authoritative state is safe.
		_ = client.Snapshot()
		if event.Kind == ClientEventFallback {
			close(enteredFallback)
			<-releaseFallback
		}
		handled = append(handled, event.Kind)
		active.Add(-1)
		if len(handled) == 2 {
			close(handledAll)
		}
	}}
	client.primaryFailed(time.Now(), ClientReasonQUICDialFailed)

	fallbackReturned := make(chan struct{})
	go func() {
		client.recordFallback(ClientReasonQUICDialFailed)
		close(fallbackReturned)
	}()
	select {
	case <-enteredFallback:
	case <-time.After(time.Second):
		t.Fatal("fallback callback did not start")
	}
	select {
	case <-fallbackReturned:
	case <-time.After(time.Second):
		t.Fatal("fallback state transition blocked on its callback")
	}

	recoveryReturned := make(chan struct{})
	go func() {
		client.primarySucceeded(clientPathMetadata{})
		close(recoveryReturned)
	}()
	select {
	case <-recoveryReturned:
	case <-time.After(time.Second):
		t.Fatal("a blocked callback prevented a concurrent state transition")
	}
	if got := active.Load(); got != 1 {
		t.Fatalf("active callbacks = %d, want 1", got)
	}
	releaseOnce.Do(func() { close(releaseFallback) })
	select {
	case <-handledAll:
	case <-time.After(time.Second):
		t.Fatal("event queue did not drain")
	}
	if maximumActive.Load() != 1 {
		t.Fatalf("maximum concurrent callbacks = %d, want 1", maximumActive.Load())
	}
	if len(handled) != 2 || handled[0] != ClientEventFallback || handled[1] != ClientEventRecovery {
		t.Fatalf("callback order = %v", handled)
	}
}

func TestClientEventQueueIsBoundedAndReleasesStorage(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	var first atomic.Bool
	var handled []ClientEventKind
	client := &Client{eventHandler: func(event ClientEvent) {
		if first.CompareAndSwap(false, true) {
			close(entered)
			<-release
		}
		handled = append(handled, event.Kind)
	}}

	client.primaryFailed(time.Now(), ClientReasonQUICDialFailed)
	client.recordFallback(ClientReasonQUICDialFailed)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first callback did not start")
	}

	for i := 0; i < maxPendingClientEvents*4; i++ {
		client.primarySucceeded(clientPathMetadata{})
		client.recordFallback(ClientReasonQUICCooldownActive)
	}
	client.eventMu.Lock()
	queued := len(client.eventQueue)
	capacity := cap(client.eventQueue)
	client.eventMu.Unlock()
	if queued != maxPendingClientEvents || capacity > maxPendingClientEvents {
		t.Fatalf("pending event queue len=%d cap=%d, want bounded at %d", queued, capacity, maxPendingClientEvents)
	}

	releaseOnce.Do(func() { close(release) })
	deadline := time.Now().Add(time.Second)
	for {
		client.eventMu.Lock()
		dispatching := client.eventDispatching
		queueIsNil := client.eventQueue == nil
		client.eventMu.Unlock()
		if !dispatching {
			if !queueIsNil {
				t.Fatal("drained event queue retained its backing storage")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("bounded event queue did not drain")
		}
		time.Sleep(time.Millisecond)
	}
	if len(handled) > maxPendingClientEvents+1 {
		t.Fatalf("handled %d events from bounded queue", len(handled))
	}
	if len(handled) == 0 || handled[len(handled)-1] != ClientEventFallback {
		t.Fatalf("coalesced callback order lost latest event: %v", handled)
	}
}
