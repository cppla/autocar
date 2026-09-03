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
		slog.Warn("tunnel transport fallback", append(attributes, "selected_transport", "tls")...)
	case tunnel.ClientEventRecovery:
		slog.Info("tunnel transport recovered", append(attributes, "selected_transport", "quic")...)
	default:
		slog.Warn("unknown tunnel client event", attributes...)
	}
}
