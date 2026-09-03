package tunnel

import "time"

const maxPendingClientEvents = 16

// ClientEventKind identifies a low-cardinality transport transition. Events
// intentionally contain no relay address, destination, token, certificate, or
// raw error text so they are safe to pass to structured application logs.
type ClientEventKind string

const (
	ClientEventFallback ClientEventKind = "transport_fallback"
	ClientEventRecovery ClientEventKind = "transport_recovery"
)

// ClientEventReason is a stable, low-cardinality explanation for a transport
// transition. It is suitable for logs and metrics labels.
type ClientEventReason string

const (
	ClientReasonQUICDialFailed       ClientEventReason = "quic_dial_failed"
	ClientReasonQUICAttemptTimeout   ClientEventReason = "quic_attempt_timeout"
	ClientReasonQUICStreamOpenFailed ClientEventReason = "quic_stream_open_failed"
	ClientReasonQUICHandshakeFailed  ClientEventReason = "quic_stream_handshake_failed"
	ClientReasonQUICPacingRejected   ClientEventReason = "quic_pacing_negotiation_failed"
	ClientReasonQUICCooldownActive   ClientEventReason = "quic_cooldown_active"
	ClientReasonQUICPathRestored     ClientEventReason = "quic_path_restored"
)

// ClientEvent describes a concrete QUIC-to-TLS fallback or QUIC recovery.
// The event schema is deliberately closed and does not include user-controlled
// strings. At is UTC.
type ClientEvent struct {
	Kind   ClientEventKind   `json:"kind"`
	Reason ClientEventReason `json:"reason"`
	At     time.Time         `json:"at"`
}

// ClientEventHandler receives transport transitions asynchronously, serialized
// in state-commit order. The pending queue is bounded; if a handler stalls,
// intermediate transitions are coalesced while preserving the latest event.
// Snapshot remains authoritative. A panic is contained and cannot take down a
// tunnel. Delivery is best-effort: Client.Close does not wait for a handler,
// and a callback already in flight may return after Close. Implementations
// should return promptly so observations remain current.
type ClientEventHandler func(ClientEvent)

// ClientSnapshot is a concurrency-safe view of the most recently successfully
// opened path. A blank SelectedTransport means that no stream has succeeded yet.
// Rates are the negotiated directional fixed-rate ceilings in bytes per second;
// zero means that no fixed rate applies.
type ClientSnapshot struct {
	SelectedTransport              string       `json:"selected_transport"`
	ClientPacing                   string       `json:"client_pacing"`
	ClientNegotiatedBytesPerSecond uint64       `json:"client_negotiated_bytes_per_second"`
	RelayPacing                    string       `json:"relay_pacing"`
	RelayNegotiatedBytesPerSecond  uint64       `json:"relay_negotiated_bytes_per_second"`
	LastEvent                      *ClientEvent `json:"last_event,omitempty"`
}

// Snapshot reports the latest authenticated QUIC or fallback path without
// performing network I/O.
func (c *Client) Snapshot() ClientSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	snapshot := ClientSnapshot{
		SelectedTransport:              c.selectedTransport,
		ClientPacing:                   c.localMode,
		ClientNegotiatedBytesPerSecond: c.localRate,
		RelayPacing:                    c.remoteMode,
		RelayNegotiatedBytesPerSecond:  c.remoteRate,
	}
	if !c.lastEvent.At.IsZero() {
		event := c.lastEvent
		snapshot.LastEvent = &event
	}
	return snapshot
}

// Snapshot reports the explicit TLS transport. TLS carries no AutoCAR
// application pacing negotiation.
func (c *TLSClient) Snapshot() ClientSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	selected := ""
	if c.selected {
		selected = "tls"
	}
	return ClientSnapshot{
		SelectedTransport: selected,
		ClientPacing:      "not-applicable",
		RelayPacing:       "not-applicable",
	}
}

func emitClientEvent(handler ClientEventHandler, event ClientEvent) {
	if handler == nil {
		return
	}
	defer func() {
		_ = recover()
	}()
	handler(event)
}

// enqueueClientEvent is called while c.mu is held, which makes queue order
// identical to the order in which transition state is committed.
func (c *Client) enqueueClientEvent(event ClientEvent) bool {
	if c.eventHandler == nil {
		return false
	}
	c.eventMu.Lock()
	defer c.eventMu.Unlock()
	if c.eventQueue == nil {
		c.eventQueue = make([]ClientEvent, 0, maxPendingClientEvents)
	}
	if len(c.eventQueue) == maxPendingClientEvents {
		// Preserve already queued order and the latest known state without
		// allowing a stalled application callback to grow memory indefinitely.
		c.eventQueue[len(c.eventQueue)-1] = event
	} else {
		c.eventQueue = append(c.eventQueue, event)
	}
	if c.eventDispatching {
		return false
	}
	c.eventDispatching = true
	return true
}

func (c *Client) dispatchClientEvents() {
	for {
		c.eventMu.Lock()
		if len(c.eventQueue) == 0 {
			c.eventDispatching = false
			c.eventQueue = nil
			c.eventMu.Unlock()
			return
		}
		event := c.eventQueue[0]
		copy(c.eventQueue, c.eventQueue[1:])
		last := len(c.eventQueue) - 1
		c.eventQueue[last] = ClientEvent{}
		c.eventQueue = c.eventQueue[:last]
		c.eventMu.Unlock()
		emitClientEvent(c.eventHandler, event)
	}
}
