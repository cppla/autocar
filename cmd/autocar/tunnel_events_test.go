package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/cppla/autocar/internal/tunnel"
)

func TestLogTunnelEventDoesNotMislabelUnknownKindsAsRecovery(t *testing.T) {
	var output bytes.Buffer
	original := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(original) })

	logTunnelEvent(tunnel.ClientEvent{Kind: tunnel.ClientEventKind("future_event")})
	logged := output.String()
	if !strings.Contains(logged, "unknown tunnel client event") || !strings.Contains(logged, "future_event") {
		t.Fatalf("unknown event log = %q", logged)
	}
	if strings.Contains(logged, "transport recovered") || strings.Contains(logged, "selected_transport") {
		t.Fatalf("unknown event was mislabeled as a recovery: %q", logged)
	}
}

func TestLogTunnelEventDoesNotGuessWebFallbackTransport(t *testing.T) {
	var output bytes.Buffer
	original := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(original) })

	logTunnelEvent(tunnel.ClientEvent{
		Kind:   tunnel.ClientEventFallback,
		Reason: tunnel.ClientEventReason("h3_dial_failed"),
	})
	logged := output.String()
	if !strings.Contains(logged, "tunnel transport fallback") || !strings.Contains(logged, "h3_dial_failed") {
		t.Fatalf("web fallback log = %q", logged)
	}
	if strings.Contains(logged, "selected_transport") || strings.Contains(logged, `"tls"`) || strings.Contains(logged, `"quic"`) {
		t.Fatalf("web fallback was mislabeled as a native transport: %q", logged)
	}
}

func TestSelectedTransportForNativeEvents(t *testing.T) {
	selected, ok := selectedTransportForEvent(tunnel.ClientEvent{
		Kind:   tunnel.ClientEventFallback,
		Reason: tunnel.ClientReasonQUICDialFailed,
	})
	if !ok || selected != "tls" {
		t.Fatalf("native fallback selection = %q, %v", selected, ok)
	}
	selected, ok = selectedTransportForEvent(tunnel.ClientEvent{
		Kind:   tunnel.ClientEventRecovery,
		Reason: tunnel.ClientReasonQUICPathRestored,
	})
	if !ok || selected != "quic" {
		t.Fatalf("native recovery selection = %q, %v", selected, ok)
	}
}
