package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"testing"
	"time"
)

// A live caller queued by the real peer's one-stream limit must receive the
// released slot on the original authenticated connection, not merely cancel
// cleanly while queued. This reuses the bounded owned-wire fixture unchanged.
func TestWebH2CapacityReleaseResumesQueuedAuthenticatedStream(t *testing.T) {
	f := newWebH2CapacityFixture(t)
	first := f.open()
	f.ack(first, []byte("hold first H2 capacity slot\x00\xff"))
	firstRequest := f.request(0)
	f.client.mu.Lock()
	session := f.client.current
	ready := session != nil && session.authState == webH2ClientAuthReady && session.auth != nil
	var authentication *webSessionClientAuth
	if ready {
		authentication = session.auth
	}
	f.client.mu.Unlock()
	if !ready {
		t.Fatal("first stream did not establish ready physical authentication")
	}
	state := session.conn.ConnectionState()
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != webH2ALPN || firstRequest.short || firstRequest.physical == nil {
		t.Fatalf("first stream TLS/ALPN/bootstrap=%#x/%q/%v", state.Version, state.NegotiatedProtocol, firstRequest.short)
	}
	observer := f.observe(session.h2)
	f.checkpoint(observer, false)

	caller, cancel := context.WithCancel(f.ctx)
	defer cancel()
	result := make(chan webH2CapacityDialResult, 1)
	joined := make(chan struct{})
	f.register(joined)
	go func() {
		defer close(joined)
		conn, err := f.client.DialContext(caller, "tcp", f.target.Addr().String())
		f.own(conn)
		result <- webH2CapacityDialResult{conn: conn, err: err}
	}()
	// This requires an actual request waiting for peer capacity. If an old
	// transport replacement is observed, retain the failure but continue the
	// real release/echo/independent-cleanup controls rather than abandon them.
	f.checkpoint(observer, true)
	if got := f.physicalDials.Load(); got != 1 {
		t.Errorf("live queued caller caused %d physical dials before release, want 1", got)
	}
	if got := f.entropy.nonceReads.Load(); got != 1 {
		t.Errorf("live queued caller generated %d full-auth nonces before release, want 1", got)
	}
	if got := f.requestCount(); got != 1 {
		t.Errorf("server handlers before release=%d, want only held first stream", got)
	}
	select {
	case <-joined:
		t.Error("second public DialContext finished before actual first stream capacity release")
	default:
	}
	if err := caller.Err(); err != nil {
		t.Fatalf("queued caller expired before capacity release: %v", err)
	}
	f.ack(first, []byte("first stream remains usable with a live waiter"))
	f.finish(first, nil)
	f.require(firstRequest.done, "first handler joined after actual FIN/capacity release")
	f.targetResult()

	f.require(joined, "live queued caller resumed after first stream release")
	second := <-result // Result publication precedes the joined channel close.
	if second.err != nil || second.conn == nil {
		t.Fatalf("released queued public DialContext: %v", second.err)
	}
	if err := second.conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	secondRequest := f.request(1)
	// Establishment cancellation is detached only after successful handoff.
	// Canceling now must not interrupt the complete payload or either FIN.
	cancel()
	payload := bytes.Repeat([]byte{'q', 'u', 'e', 'u', 'e', 'd', 0, 255}, 8192)
	f.finish(second.conn, payload)
	f.targetResult()
	f.require(secondRequest.done, "resumed second handler completed after full FIN echo")
	f.sameSession(session)
	f.client.mu.Lock()
	sameAuth := f.client.current == session && session.auth == authentication
	f.client.mu.Unlock()
	if !sameAuth {
		t.Error("capacity release replaced original physical session or authentication key")
	}
	requests := f.requestsSnapshot()
	if len(requests) != 2 {
		t.Errorf("server requests=%d, want full bootstrap then one short continuation", len(requests))
	} else if requests[0].physical != requests[1].physical || requests[0].short || !requests[1].short {
		t.Error("queued continuation did not preserve actual same-physical full/short authentication")
	}
	if got := f.physicalDials.Load(); got != 1 {
		t.Errorf("physical dials=%d after queued payload, want 1", got)
	}
	if got := f.entropy.nonceReads.Load(); got != 1 {
		t.Errorf("full-auth nonces=%d after queued payload, want 1", got)
	}
	if got := f.destinationDials.Load(); got != 2 {
		t.Errorf("actual target dials=%d, want 2", got)
	}
	if len(f.admission.sem) != 0 {
		t.Error("joined capacity-release handlers retained stream admission")
	}
	t.Log("real capacity=1 pending caller resumed on the original TLS13/h2 session; full/short auth, 64 KiB FIN echo, detached caller cancellation, and owned worker joins")
}
