package tunnel

import (
	"context"
	"net/netip"
	"testing"
)

func TestResolveNativeQUICAddress(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address string
		want    string
		zone    string
		mapped  bool
		empty   bool
	}{
		{name: "ipv4", address: "127.0.0.1:443", want: "[::ffff:127.0.0.1]:443", mapped: true},
		{name: "ipv6", address: "[::1]:443", want: "[::1]:443"},
		{name: "ipv6_canonical", address: "[2001:DB8:0:0:0:0:0:1]:443", want: "[2001:db8::1]:443"},
		{name: "mapped_ipv6", address: "[::ffff:127.0.0.1]:443", want: "[::ffff:127.0.0.1]:443", mapped: true},
		{name: "ipv6_zone", address: "[fe80::1%audit-zone]:443", want: "[fe80::1%audit-zone]:443", zone: "audit-zone"},
		{name: "mapped_ipv6_zone", address: "[::ffff:127.0.0.1%audit-zone]:443", want: "[::ffff:127.0.0.1%audit-zone]:443", zone: "audit-zone", mapped: true},
		{name: "empty_host", address: ":443", want: ":443", empty: true},
		{name: "empty_address", address: "", want: ":0", empty: true},
		// This uses a literal IP and the standard local UDP service name;
		// neither an external hostname nor an interface is resolved.
		{name: "named_port", address: "127.0.0.1:domain", want: "[::ffff:127.0.0.1]:53", mapped: true},
		{name: "ipv4_zero_port", address: "127.0.0.1:0", want: "[::ffff:127.0.0.1]:0", mapped: true},
		{name: "ipv6_zero_port", address: "[::1]:0", want: "[::1]:0"},
		{name: "empty_host_zero_port", address: ":0", want: ":0", empty: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveNativeQUICAddress(tc.address)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("numeric authority = %q, want %q", got, tc.want)
			}
			if tc.empty {
				return
			}
			// Literal parsing proves that the second DialAddr resolution need
			// not perform DNS. In particular IPv4%zone is not a valid literal.
			endpoint, err := netip.ParseAddrPort(got)
			if err != nil {
				t.Fatalf("resolved authority is not a literal endpoint: %v", err)
			}
			if endpoint.Addr().Zone() != tc.zone || endpoint.Addr().Is4In6() != tc.mapped {
				t.Errorf("family/zone changed: endpoint=%v mapped=%t zone=%q", endpoint, endpoint.Addr().Is4In6(), endpoint.Addr().Zone())
			}
		})
	}
	for _, tc := range []struct{ name, address string }{
		{"missing_port", "127.0.0.1"},
		{"unbracketed_ipv6", "::1:443"},
		{"high_port", "127.0.0.1:65536"},
		{"negative_port", "127.0.0.1:-1"},
		{"extra_port_separator", "127.0.0.1:443:1"},
		{"missing_ipv6_bracket", "[::1:443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveNativeQUICAddress(tc.address)
			if err == nil || got != "" {
				t.Errorf("malformed address resolved: got=%q err=%v", got, err)
			}
		})
	}
}

func TestDialNativeQUICAddrRejectsNilTLS(t *testing.T) {
	// The default NewClient path always supplies a verifying TLS config.
	// This private-wrapper boundary is rejected before allocating a socket,
	// without dialing or observing any external peer.
	conn, err := dialNativeQUICAddr(context.Background(), "127.0.0.1:1", nil, nil)
	if conn != nil || err == nil || err.Error() != "quic: tls.Config not set" {
		if conn != nil {
			_ = conn.CloseWithError(applicationShutdown, "unexpected nil TLS result")
		}
		t.Fatalf("nil TLS result: conn=%v err=%v", conn, err)
	}
}
