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
