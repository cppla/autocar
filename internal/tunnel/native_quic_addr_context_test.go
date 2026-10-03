package tunnel

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestSelectNativeQUICAddress(t *testing.T) {
	v4 := net.IPAddr{IP: net.IP{192, 0, 2, 1}}
	v4Other := net.IPAddr{IP: net.IP{192, 0, 2, 2}}
	mapped := net.IPAddr{IP: net.ParseIP("::ffff:192.0.2.3")}
	v6 := net.IPAddr{IP: net.ParseIP("2001:db8::1")}
	v6Other := net.IPAddr{IP: net.ParseIP("2001:db8::2")}
	zoned := net.IPAddr{IP: net.ParseIP("fe80::1"), Zone: "audit-zone"}
	unspecified := net.IPAddr{IP: net.IPv6unspecified}
	unspecifiedZoned := net.IPAddr{IP: net.IPv6unspecified, Zone: "audit-zone"}
	v4Zero := net.IPAddr{IP: net.IPv4zero}
	for _, tc := range []struct {
		name      string
		address   string
		addresses []net.IPAddr
		want      net.IPAddr
	}{
		{"dns_ipv6_first_prefers_ipv4", "relay.invalid:443", []net.IPAddr{v6, v4, v4Other}, v4},
		{"dns_ipv4_first_stays_ipv4", "relay.invalid:443", []net.IPAddr{v4, v6}, v4},
		{"bracketed_hostname_prefers_ipv6", "[relay.invalid]:443", []net.IPAddr{v4, v6, v6Other}, v6},
		{"dns_ipv6_only_uses_first", "relay.invalid:443", []net.IPAddr{v6, v6Other}, v6},
		{"bracketed_ipv4_only_uses_first", "[relay.invalid]:443", []net.IPAddr{v4, v4Other}, v4},
		{"mapped_ipv6_classified_as_ipv4", "relay.invalid:443", []net.IPAddr{v6, mapped, v4}, mapped},
		{"bracketed_mapped_then_ipv6", "[relay.invalid]:443", []net.IPAddr{mapped, v6}, v6},
		{"selected_ipv6_zone_preserved", "[relay.invalid]:443", []net.IPAddr{v4, zoned}, zoned},
		{"single_unspecified_dns_uses_ipv4_zero", "relay.invalid:443", []net.IPAddr{unspecified}, v4Zero},
		{"single_unspecified_bracket_keeps_ipv6", "[::]:443", []net.IPAddr{unspecified}, unspecified},
		{"single_unspecified_zone_dns_uses_ipv4_zero", "relay.invalid:443", []net.IPAddr{unspecifiedZoned}, v4Zero},
		{"single_unspecified_bracket_zone_preserved", "[::%audit-zone]:443", []net.IPAddr{unspecifiedZoned}, unspecifiedZoned},
		{"multiple_ipv6_do_not_add_ipv4_zero", "relay.invalid:443", []net.IPAddr{unspecified, v6}, unspecified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addresses := nativeQUICAddrContextCloneAddresses(tc.addresses)
			before := nativeQUICAddrContextCloneAddresses(addresses)
			got := selectNativeQUICAddress(tc.address, addresses)
			nativeQUICAddrContextAssertAddress(t, "selection", got, tc.want)
			for i := range addresses {
				nativeQUICAddrContextAssertAddress(t, "unchanged input", addresses[i], before[i])
			}
		})
	}
	t.Run("backing_array_nonmutation", func(t *testing.T) {
		// An append of the compatibility IPv4 address must not overwrite a
		// resolver's spare capacity, even when the visible slice has length 1.
		backing := []net.IPAddr{
			{IP: append(net.IP(nil), net.IPv6unspecified...), Zone: "audit-zone"},
			{IP: append(net.IP(nil), v6Other.IP...), Zone: "unselected-capacity"},
		}
		before := nativeQUICAddrContextCloneAddresses(backing)
		got := selectNativeQUICAddress("relay.invalid:443", backing[:1])
		nativeQUICAddrContextAssertAddress(t, "selection", got, v4Zero)
		for i := range backing {
			nativeQUICAddrContextAssertAddress(t, "unchanged backing array", backing[i], before[i])
		}
	})
}

func TestResolveNativeQUICAddressHonorsContext(t *testing.T) {
	for _, tc := range []struct{ name, address string }{
		{"canceled_ipv4", "127.0.0.1:443"},
		{"canceled_ipv6_zone", "[fe80::1%audit-zone]:443"},
		{"canceled_empty_host", ":443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			cause := errors.New("private native relay-resolution cancellation")
			cancel(cause)
			got, err := resolveNativeQUICAddress(ctx, tc.address)
			if got != "" || err != cause {
				t.Fatalf("canceled resolution = (%q, %v), want empty address and exact caller cause", got, err)
			}
		})
	}
	t.Run("expired_standard_context", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		got, err := resolveNativeQUICAddress(ctx, "127.0.0.1:443")
		if got != "" || err != context.DeadlineExceeded {
			t.Fatalf("expired resolution = (%q, %v), want empty address and DeadlineExceeded", got, err)
		}
	})
	t.Run("elapsed_deadline_before_publication", func(t *testing.T) {
		// Model only the timer-publication window: Deadline is fixed and
		// elapsed, while the inherited Err/Done still report a live parent.
		// The literal address makes this a no-DNS boundary control.
		ctx := nativeQUICAddrContextUnpublishedDeadline{
			Context: context.Background(), deadline: time.Now().Add(-time.Second),
		}
		if ctx.Err() != nil || ctx.Done() != nil || context.Cause(ctx) != nil {
			t.Fatal("fixture published cancellation before the resolver call")
		}
		got, err := resolveNativeQUICAddress(ctx, "127.0.0.1:443")
		if got != "" || err != context.DeadlineExceeded {
			t.Fatalf("elapsed resolution = (%q, %v), want empty address and DeadlineExceeded", got, err)
		}
	})
	t.Run("nil_context", func(t *testing.T) {
		got, err := resolveNativeQUICAddress(nil, "127.0.0.1:443")
		if got != "" || err == nil || err.Error() != "tunnel: nil relay resolution context" {
			t.Fatalf("nil context resolution = (%q, %v), want explicit nil-context error", got, err)
		}
	})
}

type nativeQUICAddrContextUnpublishedDeadline struct {
	context.Context
	deadline time.Time
}

func (c nativeQUICAddrContextUnpublishedDeadline) Deadline() (time.Time, bool) {
	return c.deadline, true
}

func nativeQUICAddrContextCloneAddresses(addresses []net.IPAddr) []net.IPAddr {
	cloned := make([]net.IPAddr, len(addresses))
	for i, address := range addresses {
		cloned[i] = net.IPAddr{IP: append(net.IP(nil), address.IP...), Zone: address.Zone}
	}
	return cloned
}

func nativeQUICAddrContextAssertAddress(t *testing.T, label string, got, want net.IPAddr) {
	t.Helper()
	// IP.Equal intentionally folds IPv4 and IPv4-mapped IPv6 together;
	// exact bytes also prove the resolver's representation is preserved.
	if !bytes.Equal(got.IP, want.IP) || got.Zone != want.Zone {
		t.Errorf("%s = (IP %x, zone %q), want (IP %x, zone %q)", label, []byte(got.IP), got.Zone, []byte(want.IP), want.Zone)
	}
}
