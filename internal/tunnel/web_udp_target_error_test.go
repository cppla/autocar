package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"testing"

	"github.com/cppla/autocar/internal/transport"
)

func TestWebUDPRejectedFirstTargetPreservesBootstrapAndAdmission(t *testing.T) {
	echo := startWebUDPEcho(t)
	target := echo.String()
	resolver := newWebUDPTestResolver(map[string]netip.AddrPort{target: echo})
	server, client := startWebUDPTestPair(t, resolver, WebH3ServerConfig{
		MaxUDPSessions: 1, MaxClientUDPSessions: 1,
	}, WebH3ClientConfig{MaxUDPSessions: 1, MaxUDPDestinations: 1})
	packet, err := client.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	// The very first target establishes connection authentication but fails
	// resolution. Neither its global reservation nor its per-packet pending
	// slot may survive the failure, even at capacity one.
	err = packet.Send([]byte("not delivered"), "missing.example:53")
	var rejection *WebConnectError
	if !errors.Is(err, transport.ErrPacketTargetUnavailable) || !errors.As(err, &rejection) || rejection.StatusCode != http.StatusBadGateway {
		t.Fatalf("first target error = %v, want recoverable signed 502", err)
	}
	assertWebUDPEcho(t, packet, []byte("same association after rejected bootstrap target"), target)
	if resolver.count("missing.example:53") != 1 || resolver.count(target) != 1 {
		t.Fatal("failed send retried or healthy target was not opened once")
	}
	if err := packet.Close(); err != nil {
		t.Fatal(err)
	}
	handler := server.server.Handler.(*webTunnelHandler)
	eventuallyWebUDP(t, func() bool { return len(client.udpSlots) == 0 && len(handler.udp.slots) == 0 }, "UDP admission leaked after target rejection and close")
}

func TestWebUDPTargetSendErrorScopeAndCause(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		drop bool
	}{
		{"destination_capacity", ErrUDPDestinationCapacity, true},
		{"session_capacity", ErrUDPSessionCapacity, true},
		{"signed_destination_failure", &WebConnectError{Transport: webAuthTransportH3, StatusCode: http.StatusBadGateway}, true},
		{"signed_admission_failure", &WebConnectError{Transport: webAuthTransportH3, StatusCode: http.StatusServiceUnavailable}, true},
		{"bad_request", &WebConnectError{Transport: webAuthTransportH3, StatusCode: http.StatusBadRequest}, false},
		{"unauthorized", &WebConnectError{Transport: webAuthTransportH3, StatusCode: http.StatusUnauthorized}, false},
		{"unknown_signed_status", &WebConnectError{Transport: webAuthTransportH3, StatusCode: http.StatusInternalServerError}, false},
		{"closed", net.ErrClosed, false},
		{"canceled", context.Canceled, false},
		{"deadline", context.DeadlineExceeded, false},
		{"unsigned_status_text", errors.New("HTTP status 502"), false},
		{"authentication", errors.New("server authentication failed"), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			wrapped := fmt.Errorf("opening target: %w", test.err)
			got := webUDPTargetSendError(wrapped)
			if errors.Is(got, transport.ErrPacketTargetUnavailable) != test.drop {
				t.Fatalf("recoverable=%t, want %t: %v", errors.Is(got, transport.ErrPacketTargetUnavailable), test.drop, got)
			}
			if !errors.Is(got, test.err) {
				t.Fatal("underlying cause was lost")
			}
			var original, retained *WebConnectError
			if errors.As(wrapped, &original) && (!errors.As(got, &retained) || retained != original) {
				t.Fatal("authenticated status identity was lost")
			}
			if !test.drop && got != wrapped {
				t.Fatal("terminal error identity changed")
			}
		})
	}
}
