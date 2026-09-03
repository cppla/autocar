package security

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type resolverCall struct {
	network string
	host    string
}

type fakeResolver struct {
	addresses []netip.Addr
	err       error
	calls     []resolverCall
}

type rotatingResolver struct {
	mu      sync.Mutex
	answers [][]netip.Addr
	calls   []resolverCall
}

func (r *rotatingResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, resolverCall{network: network, host: host})
	index := len(r.calls) - 1
	if index >= len(r.answers) {
		index = len(r.answers) - 1
	}
	return append([]netip.Addr(nil), r.answers[index]...), nil
}

func (r *fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	r.calls = append(r.calls, resolverCall{network: network, host: host})
	return append([]netip.Addr(nil), r.addresses...), r.err
}

type dialCall struct {
	network string
	address string
}

type recordingDialer struct {
	mu        sync.Mutex
	calls     []dialCall
	fail      map[string]error
	connected []net.Conn
}

type blackholedIPv6Dialer struct {
	calls chan dialCall
}

type boundedConcurrencyDialer struct {
	current atomic.Int32
	peak    atomic.Int32
}

func (d *boundedConcurrencyDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	current := d.current.Add(1)
	defer d.current.Add(-1)
	for peak := d.peak.Load(); current > peak && !d.peak.CompareAndSwap(peak, current); peak = d.peak.Load() {
	}

	timer := time.NewTimer(5 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-timer.C:
		return nil, errors.New("unreachable")
	}
}

func (d *blackholedIPv6Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.calls <- dialCall{network: network, address: address}
	if network == "tcp6" {
		<-ctx.Done()
		return nil, context.Cause(ctx)
	}
	client, peer := net.Pipe()
	_ = peer.Close()
	return client, nil
}

func (d *recordingDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, dialCall{network: network, address: address})
	if err := d.fail[address]; err != nil {
		return nil, err
	}
	client, peer := net.Pipe()
	_ = peer.Close()
	d.connected = append(d.connected, client)
	return client, nil
}

func TestSafeDialerDefaultDeniedPorts(t *testing.T) {
	for _, port := range DefaultDeniedPorts() {
		t.Run("port "+formatPort(port), func(t *testing.T) {
			resolver := &fakeResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
			dialer := &recordingDialer{}
			safe := NewSafeDialer(SafeDialerOptions{Resolver: resolver, Dialer: dialer})
			_, err := safe.DialContext(context.Background(), "tcp", net.JoinHostPort("mail.example", formatPort(port)))
			if !errors.Is(err, ErrDeniedPort) {
				t.Fatalf("port %d error = %v", port, err)
			}
			if len(resolver.calls) != 0 || len(dialer.calls) != 0 {
				t.Fatal("denied port caused resolution or dialing")
			}
		})
	}
}

func TestSafeDialerCustomDeniedPorts(t *testing.T) {
	resolver := &fakeResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	dialer := &recordingDialer{}
	safe := NewSafeDialer(SafeDialerOptions{Resolver: resolver, Dialer: dialer, DeniedPorts: []uint16{8080}})
	if _, err := safe.DialContext(context.Background(), "tcp", "example.com:8080"); !errors.Is(err, ErrDeniedPort) {
		t.Fatalf("custom denied port error = %v", err)
	}
	conn, err := safe.DialContext(context.Background(), "tcp", "example.com:25")
	if err != nil {
		t.Fatalf("explicit list did not replace default: %v", err)
	}
	_ = conn.Close()
}

func TestSafeDialerRejectsUnsafeAddresses(t *testing.T) {
	addresses := []string{
		"0.0.0.0", "0.0.0.1", "127.0.0.1", "10.0.0.1", "168.63.129.16", "169.254.169.254", "192.0.2.1", "198.18.0.1",
		"198.51.100.1", "203.0.113.1", "224.0.0.1", "100.64.0.1", "240.0.0.1", "255.255.255.255",
		"::", "::1", "::192.0.2.1", "64:ff9b::7f00:1", "64:ff9b:1::1", "100::1", "100:0:0:1::1", "2001::1",
		"2001:db8::1", "2002:7f00:1::1", "3fff::1", "5f00::1", "fec0::1", "fe80::1", "ff02::1", "fd00::1",
	}
	for _, address := range addresses {
		t.Run(address, func(t *testing.T) {
			dialer := &recordingDialer{}
			safe := NewSafeDialer(SafeDialerOptions{Dialer: dialer})
			_, err := safe.DialContext(context.Background(), "tcp", net.JoinHostPort(address, "443"))
			if !errors.Is(err, ErrUnsafeAddress) {
				t.Fatalf("error = %v", err)
			}
			if len(dialer.calls) != 0 {
				t.Fatalf("unsafe address dialed: %v", dialer.calls)
			}
		})
	}
}

func TestSafeDialerAllowPrivateDoesNotAllowLocalSpecialAddresses(t *testing.T) {
	for _, address := range []string{"10.1.2.3", "fd00::1", "100.64.1.2"} {
		t.Run("allows "+address, func(t *testing.T) {
			dialer := &recordingDialer{}
			safe := NewSafeDialer(SafeDialerOptions{Dialer: dialer, AllowPrivate: true})
			conn, err := safe.DialContext(context.Background(), "tcp", net.JoinHostPort(address, "443"))
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
			if len(dialer.calls) != 1 {
				t.Fatalf("calls = %v", dialer.calls)
			}
		})
	}
	for _, address := range []string{
		"127.0.0.1", "169.254.169.254", "192.0.2.1", "198.18.0.1", "240.0.0.1",
		"::1", "64:ff9b::a00:1", "2001:db8::1", "2002:a00:1::1", "fe80::1", "ff02::1",
	} {
		t.Run("still rejects "+address, func(t *testing.T) {
			dialer := &recordingDialer{}
			safe := NewSafeDialer(SafeDialerOptions{Dialer: dialer, AllowPrivate: true})
			_, err := safe.DialContext(context.Background(), "tcp", net.JoinHostPort(address, "443"))
			if !errors.Is(err, ErrUnsafeAddress) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestSafeDialerAdditionalDeniedPrefixes(t *testing.T) {
	dialer := &recordingDialer{}
	safe := NewSafeDialer(SafeDialerOptions{
		Dialer:         dialer,
		DeniedPrefixes: []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")},
	})
	_, err := safe.DialContext(context.Background(), "tcp", "8.8.8.8:443")
	if !errors.Is(err, ErrUnsafeAddress) {
		t.Fatalf("custom prefix error = %v", err)
	}
	if len(dialer.calls) != 0 {
		t.Fatalf("custom-denied address was dialed: %v", dialer.calls)
	}
}

func TestSafeDialerNormalizesIPv4MappedDeniedPrefixesForTCPAndUDP(t *testing.T) {
	mapped := netip.MustParsePrefix("::ffff:8.8.8.0/120")

	t.Run("TCP", func(t *testing.T) {
		resolver := &fakeResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
		dialer := &recordingDialer{}
		safe := NewSafeDialer(SafeDialerOptions{
			Resolver: resolver, Dialer: dialer, DeniedPrefixes: []netip.Prefix{mapped},
		})
		if _, err := safe.DialContext(context.Background(), "tcp", "dns.example:443"); !errors.Is(err, ErrUnsafeAddress) {
			t.Fatalf("mapped-prefix TCP error = %v", err)
		}
		if len(dialer.calls) != 0 {
			t.Fatalf("mapped-prefix TCP destination was dialed: %v", dialer.calls)
		}
	})

	t.Run("UDP", func(t *testing.T) {
		resolver := &fakeResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
		safe := NewSafeDialer(SafeDialerOptions{
			Resolver: resolver, DeniedPrefixes: []netip.Prefix{mapped},
		})
		if _, err := safe.ResolveUDPContext(context.Background(), "dns.example:53"); !errors.Is(err, ErrUnsafeAddress) {
			t.Fatalf("mapped-prefix UDP error = %v", err)
		}
	})
}

func TestSafeDialerFailsClosedOnInvalidDeniedPrefixes(t *testing.T) {
	tests := []struct {
		name   string
		prefix netip.Prefix
	}{
		{name: "mapped prefix shorter than 96 bits", prefix: netip.MustParsePrefix("::ffff:8.8.8.8/95")},
		{name: "canonical overlapping prefix shorter than 96 bits", prefix: netip.MustParsePrefix("::fffe:0:0/95")},
		{name: "zero value", prefix: netip.Prefix{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := &fakeResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
			dialer := &recordingDialer{}
			safe := NewSafeDialer(SafeDialerOptions{
				Resolver: resolver, Dialer: dialer, DeniedPrefixes: []netip.Prefix{test.prefix},
			})

			if _, err := safe.DialContext(context.Background(), "tcp", "dns.example:443"); err == nil {
				t.Fatal("TCP dial accepted an invalid deny policy")
			}
			if _, err := safe.ResolveUDPContext(context.Background(), "dns.example:53"); err == nil {
				t.Fatal("UDP resolution accepted an invalid deny policy")
			}
			if len(resolver.calls) != 0 {
				t.Fatalf("invalid deny policy caused DNS resolution: %v", resolver.calls)
			}
			if len(dialer.calls) != 0 {
				t.Fatalf("invalid deny policy caused dialing: %v", dialer.calls)
			}
		})
	}
}

func TestSafeDialerResolvesThenDialsOnlyNumericApprovedIP(t *testing.T) {
	resolver := &fakeResolver{addresses: []netip.Addr{
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("8.8.8.8"),
	}}
	dialer := &recordingDialer{}
	safe := NewSafeDialer(SafeDialerOptions{Resolver: resolver, Dialer: dialer})
	conn, err := safe.DialContext(context.Background(), "tcp", "dns.example:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if !reflect.DeepEqual(resolver.calls, []resolverCall{{network: "ip", host: "dns.example"}}) {
		t.Fatalf("resolver calls = %v", resolver.calls)
	}
	want := []dialCall{{network: "tcp4", address: "8.8.8.8:443"}}
	if !reflect.DeepEqual(dialer.calls, want) {
		t.Fatalf("dialer calls = %v, want %v", dialer.calls, want)
	}
}

func TestSafeDialerSupportsIPv6AndAddressFallback(t *testing.T) {
	resolver := &fakeResolver{addresses: []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("2606:4700:4700::1111"),
	}}
	dialer := &recordingDialer{fail: map[string]error{"1.1.1.1:443": errors.New("unreachable")}}
	safe := NewSafeDialer(SafeDialerOptions{Resolver: resolver, Dialer: dialer})
	conn, err := safe.DialContext(context.Background(), "tcp", "cloudflare.example:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	want := []dialCall{
		{network: "tcp4", address: "1.1.1.1:443"},
		{network: "tcp6", address: "[2606:4700:4700::1111]:443"},
	}
	if !reflect.DeepEqual(dialer.calls, want) {
		t.Fatalf("dialer calls = %v, want %v", dialer.calls, want)
	}
}

func TestSafeDialerRacesApprovedAddressFamilies(t *testing.T) {
	resolver := &fakeResolver{addresses: []netip.Addr{
		netip.MustParseAddr("2606:4700:4700::1111"),
		netip.MustParseAddr("1.1.1.1"),
	}}
	dialer := &blackholedIPv6Dialer{calls: make(chan dialCall, 2)}
	safe := NewSafeDialer(SafeDialerOptions{
		Resolver:             resolver,
		Dialer:               dialer,
		AddressFallbackDelay: 20 * time.Millisecond,
	})
	started := time.Now()
	conn, err := safe.DialContext(context.Background(), "tcp", "dualstack.example:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("IPv4 fallback waited for the blackholed IPv6 attempt: %s", elapsed)
	}
	first := <-dialer.calls
	second := <-dialer.calls
	if first.network != "tcp6" || second.network != "tcp4" {
		t.Fatalf("dial order = %v, %v; want staggered IPv6 then IPv4", first, second)
	}
}

func TestInterleaveAddressFamilies(t *testing.T) {
	input := []netip.Addr{
		netip.MustParseAddr("2606:4700::1"),
		netip.MustParseAddr("2606:4700::2"),
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("8.8.8.8"),
	}
	want := []netip.Addr{input[0], input[2], input[1], input[3]}
	if got := interleaveAddressFamilies(input); !reflect.DeepEqual(got, want) {
		t.Fatalf("interleaved addresses = %v, want %v", got, want)
	}
}

func TestSafeDialerBoundsResolverResults(t *testing.T) {
	resolver := &fakeResolver{addresses: make([]netip.Addr, maxResolverResults+1)}
	for i := range resolver.addresses {
		resolver.addresses[i] = netip.MustParseAddr("1.1.1.1")
	}
	dialer := &recordingDialer{}
	safe := NewSafeDialer(SafeDialerOptions{Resolver: resolver, Dialer: dialer})
	if _, err := safe.DialContext(context.Background(), "tcp", "too-many.example:443"); err == nil {
		t.Fatal("oversized DNS result set was accepted")
	}
	if len(dialer.calls) != 0 {
		t.Fatalf("oversized DNS result set caused dialing: %v", dialer.calls)
	}
}

func TestSafeDialerBoundsConcurrentAddressAttempts(t *testing.T) {
	addresses := make([]netip.Addr, 32)
	for i := range addresses {
		addresses[i] = netip.AddrFrom4([4]byte{11, 0, 0, byte(i + 1)})
	}
	dialer := &boundedConcurrencyDialer{}
	safe := NewSafeDialer(SafeDialerOptions{
		Resolver:             &fakeResolver{addresses: addresses},
		Dialer:               dialer,
		AddressFallbackDelay: time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := safe.DialContext(ctx, "tcp", "many.example:443"); err == nil {
		t.Fatal("all failed address attempts returned no error")
	}
	if peak := dialer.peak.Load(); peak != 2 {
		t.Fatalf("peak concurrent address attempts = %d, want exactly 2", peak)
	}
}

func TestSafeDialerHonorsAddressFamily(t *testing.T) {
	resolver := &fakeResolver{addresses: []netip.Addr{
		netip.MustParseAddr("2606:4700:4700::1111"),
		netip.MustParseAddr("1.1.1.1"),
	}}
	dialer := &recordingDialer{}
	safe := NewSafeDialer(SafeDialerOptions{Resolver: resolver, Dialer: dialer})
	conn, err := safe.DialContext(context.Background(), "tcp4", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if !reflect.DeepEqual(resolver.calls, []resolverCall{{network: "ip4", host: "example.com"}}) {
		t.Fatalf("resolver calls = %v", resolver.calls)
	}
	if !reflect.DeepEqual(dialer.calls, []dialCall{{network: "tcp4", address: "1.1.1.1:443"}}) {
		t.Fatalf("dialer calls = %v", dialer.calls)
	}
}

func TestSafeDialerLiteralSkipsDNS(t *testing.T) {
	resolver := &fakeResolver{err: errors.New("must not resolve")}
	dialer := &recordingDialer{}
	safe := NewSafeDialer(SafeDialerOptions{Resolver: resolver, Dialer: dialer})
	conn, err := safe.DialContext(context.Background(), "tcp6", "[2606:4700:4700::1111]:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if len(resolver.calls) != 0 {
		t.Fatalf("literal caused DNS lookup: %v", resolver.calls)
	}
}

func TestSafeDialerErrors(t *testing.T) {
	tests := []struct {
		name    string
		network string
		address string
		want    error
	}{
		{"UDP", "udp", "8.8.8.8:53", ErrUnsupportedNetwork},
		{"missing port", "tcp", "example.com", nil},
		{"service port", "tcp", "example.com:https", nil},
		{"zero port", "tcp", "example.com:0", nil},
		{"empty host", "tcp", ":443", nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			safe := NewSafeDialer(SafeDialerOptions{})
			_, err := safe.DialContext(context.Background(), test.network, test.address)
			if err == nil {
				t.Fatal("expected error")
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	var nilDialer *SafeDialer
	if _, err := nilDialer.DialContext(context.Background(), "tcp", "8.8.8.8:443"); err == nil {
		t.Fatal("nil SafeDialer did not error")
	}
	if _, err := NewSafeDialer(SafeDialerOptions{}).DialContext(nil, "tcp", "8.8.8.8:443"); err == nil {
		t.Fatal("nil dial context did not error")
	}
}

func TestSafeDialerResolutionFailures(t *testing.T) {
	for _, resolver := range []*fakeResolver{
		{err: errors.New("DNS failure")},
		{},
		{addresses: []netip.Addr{{}}},
		{addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}},
	} {
		dialer := &recordingDialer{}
		safe := NewSafeDialer(SafeDialerOptions{Resolver: resolver, Dialer: dialer})
		if _, err := safe.DialContext(context.Background(), "tcp", "example.com:443"); err == nil {
			t.Fatal("expected resolution/policy error")
		}
		if len(dialer.calls) != 0 {
			t.Fatalf("resolution failure caused dialing: %v", dialer.calls)
		}
	}
}

func TestSafeDialerChecksCanceledContextBeforeDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resolver := &fakeResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	dialer := &recordingDialer{}
	safe := NewSafeDialer(SafeDialerOptions{Resolver: resolver, Dialer: dialer})
	_, err := safe.DialContext(ctx, "tcp", "example.com:443")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	if len(dialer.calls) != 0 {
		t.Fatalf("canceled context caused dialing: %v", dialer.calls)
	}
}

func TestSafeDialerResolveUDPReturnsOnlyApprovedNumericAddresses(t *testing.T) {
	resolver := &fakeResolver{addresses: []netip.Addr{
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("2606:4700:4700::1111"),
		netip.MustParseAddr("8.8.8.8"),
	}}
	safe := NewSafeDialer(SafeDialerOptions{Resolver: resolver})
	addresses, err := safe.ResolveUDPContext(context.Background(), "dns.example:53")
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.AddrPort{
		netip.MustParseAddrPort("8.8.8.8:53"),
		netip.MustParseAddrPort("[2606:4700:4700::1111]:53"),
	}
	if !reflect.DeepEqual(addresses, want) {
		t.Fatalf("UDP addresses = %v, want %v", addresses, want)
	}
	if !reflect.DeepEqual(resolver.calls, []resolverCall{{network: "ip", host: "dns.example"}}) {
		t.Fatalf("resolver calls = %v", resolver.calls)
	}
}

func TestSafeDialerResolveUDPRejectsDeniedPortBeforeDNS(t *testing.T) {
	resolver := &fakeResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	safe := NewSafeDialer(SafeDialerOptions{Resolver: resolver})
	if _, err := safe.ResolveUDPContext(context.Background(), "mail.example:465"); !errors.Is(err, ErrDeniedPort) {
		t.Fatalf("denied UDP port error = %v", err)
	}
	if len(resolver.calls) != 0 {
		t.Fatalf("denied UDP port caused DNS resolution: %v", resolver.calls)
	}
}

func TestSafeDialerResolveUDPRejectsUnsafeResolution(t *testing.T) {
	resolver := &fakeResolver{addresses: []netip.Addr{
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("169.254.169.254"),
	}}
	safe := NewSafeDialer(SafeDialerOptions{Resolver: resolver, AllowPrivate: true})
	if _, err := safe.ResolveUDPContext(context.Background(), "internal.example:53"); !errors.Is(err, ErrUnsafeAddress) {
		t.Fatalf("unsafe UDP resolution error = %v", err)
	}
}

func TestSafeDialerResolveUDPNumericLiteralSkipsDNS(t *testing.T) {
	resolver := &fakeResolver{err: errors.New("must not resolve")}
	safe := NewSafeDialer(SafeDialerOptions{Resolver: resolver})
	addresses, err := safe.ResolveUDPContext(context.Background(), "[2606:4700:4700::1111]:443")
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.AddrPort{netip.MustParseAddrPort("[2606:4700:4700::1111]:443")}
	if !reflect.DeepEqual(addresses, want) {
		t.Fatalf("literal UDP addresses = %v, want %v", addresses, want)
	}
	if len(resolver.calls) != 0 {
		t.Fatalf("numeric UDP literal caused DNS resolution: %v", resolver.calls)
	}
}

func TestSafeDialerResolveUDPFreezesDNSAnswerAgainstRebinding(t *testing.T) {
	resolver := &rotatingResolver{answers: [][]netip.Addr{
		{netip.MustParseAddr("8.8.8.8")},
		{netip.MustParseAddr("127.0.0.1")},
	}}
	safe := NewSafeDialer(SafeDialerOptions{Resolver: resolver})
	addresses, err := safe.ResolveUDPContext(context.Background(), "rebinding.example:53")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(addresses, []netip.AddrPort{netip.MustParseAddrPort("8.8.8.8:53")}) {
		t.Fatalf("frozen numeric answer = %v", addresses)
	}
	resolver.mu.Lock()
	calls := append([]resolverCall(nil), resolver.calls...)
	resolver.mu.Unlock()
	if len(calls) != 1 {
		t.Fatalf("ResolveUDPContext performed %d lookups, want exactly 1", len(calls))
	}
}

func formatPort(port uint16) string {
	const digits = "0123456789"
	if port == 0 {
		return "0"
	}
	var buf [5]byte
	i := len(buf)
	for port != 0 {
		i--
		buf[i] = digits[port%10]
		port /= 10
	}
	return string(buf[i:])
}
