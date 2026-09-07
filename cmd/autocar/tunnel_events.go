package main

import (
	"log/slog"

	"github.com/cppla/autocar/internal/tunnel"
)

// logTunnelEvent deliberately records only closed-schema fields from the
// tunnel package. Relay addresses, targets, credentials and raw errors do not
// enter this event path.
func logTunnelEvent(event tunnel.ClientEvent) {
	attributes := []any{
		"event", event.Kind,
		"reason", event.Reason,
	}
	switch event.Kind {
	case tunnel.ClientEventFallback:
		if selected, ok := selectedTransportForEvent(event); ok {
			attributes = append(attributes, "selected_transport", selected)
		}
		slog.Warn("tunnel transport fallback", attributes...)
	case tunnel.ClientEventRecovery:
		if selected, ok := selectedTransportForEvent(event); ok {
			attributes = append(attributes, "selected_transport", selected)
		}
		slog.Info("tunnel transport recovered", attributes...)
	default:
		slog.Warn("unknown tunnel client event", attributes...)
	}
}

// selectedTransportForEvent labels only the closed native event schema. A
// future web-cover event must carry an explicit H2/H3 transition contract; an
// unknown reason is intentionally logged without a guessed transport.
func selectedTransportForEvent(event tunnel.ClientEvent) (string, bool) {
	switch event.Kind {
	case tunnel.ClientEventFallback:
		switch event.Reason {
		case tunnel.ClientReasonQUICDialFailed,
			tunnel.ClientReasonQUICAttemptTimeout,
			tunnel.ClientReasonQUICStreamOpenFailed,
			tunnel.ClientReasonQUICHandshakeFailed,
			tunnel.ClientReasonQUICPacingRejected,
			tunnel.ClientReasonQUICCooldownActive:
			return "tls", true
		}
	case tunnel.ClientEventRecovery:
		if event.Reason == tunnel.ClientReasonQUICPathRestored {
			return "quic", true
		}
	}
	return "", false
}
