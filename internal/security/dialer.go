package security

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const (
	defaultAddressFallbackDelay = 250 * time.Millisecond
	maxResolverResults          = 256
)

var (
	// ErrDeniedPort indicates that outbound policy blocked a destination port.
	ErrDeniedPort = errors.New("security: destination port is denied")
	// ErrUnsafeAddress indicates that all resolved destination addresses were
	// local, private (without opt-in), or otherwise unsafe.
	ErrUnsafeAddress = errors.New("security: destination address is unsafe")
	// ErrUnsupportedNetwork indicates a request for anything other than TCP.
	ErrUnsupportedNetwork = errors.New("security: unsupported network")
)

var carrierGradeNAT = netip.MustParsePrefix("100.64.0.0/10")

// deniedSpecialUsePrefixes contains IANA special-purpose ranges that Go's
// netip.Addr.IsGlobalUnicast may still classify as unicast. They are not
// ordinary public destinations and several translation/tunneling ranges can
// otherwise turn an apparently safe IPv6 literal into access to an IPv4
// address behind the relay. Private-use and CGNAT ranges are handled
// separately because operators may explicitly opt in to those.
//
// Keep this list in sync with the IANA IPv4 and IPv6 Special-Purpose Address
// Registries. Blocking an obscure special-purpose anycast is preferable to
// weakening the relay's default SSRF boundary.
var deniedSpecialUsePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	// Azure's virtual platform address is numerically public but exposes host
	// control-plane services and must not be reachable through a generic relay.
	netip.MustParsePrefix("168.63.129.16/32"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("100:0:0:1::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fec0::/10"),
}

// Resolver is the subset of net.Resolver used by SafeDialer.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// ContextDialer is implemented by net.Dialer and transport.DialFunc.
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// SafeDialerOptions configures egress destination policy.
type SafeDialerOptions struct {
	Resolver Resolver
	Dialer   ContextDialer

	// AllowPrivate permits RFC1918 IPv4, ULA IPv6, and CGNAT addresses. It
	// never permits loopback, link-local, multicast, unspecified, translation,
	// documentation, benchmarking, reserved, or other special-use addresses.
	AllowPrivate bool

	// DeniedPorts is the exact outbound port denylist. Nil selects the secure
	// default (25, 465, and 587); an explicitly empty slice clears it.
	DeniedPorts []uint16

	// DeniedPrefixes adds deployment-specific addresses (for example, a cloud
	// provider control plane) to the built-in special-use denylist.
	DeniedPrefixes []netip.Prefix

	// AddressFallbackDelay staggers approved IPv6/IPv4 numeric dial attempts,
	// preserving Happy Eyeballs without allowing the underlying dialer to
	// resolve the hostname again. Zero selects 250 ms.
	AddressFallbackDelay time.Duration
}

// SafeDialer resolves destinations itself, validates every returned address,
// and gives the underlying dialer only numeric IP literals. Consequently a
// second DNS lookup cannot redirect an approved hostname to a local service.
type SafeDialer struct {
	resolver      Resolver
	dialer        ContextDialer
	allowPrivate  bool
	deniedPorts   map[uint16]struct{}
	deniedNets    []netip.Prefix
	fallbackDelay time.Duration
}

// NewSafeDialer constructs an immutable, concurrency-safe outbound dialer.
func NewSafeDialer(opts SafeDialerOptions) *SafeDialer {
	resolver := opts.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dialer := opts.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	}

	ports := opts.DeniedPorts
	if ports == nil {
		ports = []uint16{25, 465, 587}
	}
	denied := make(map[uint16]struct{}, len(ports))
	for _, port := range ports {
		// Port zero is never a valid SplitHostPort destination. Silently
		// ignoring it keeps construction infallible without weakening policy.
		if port != 0 {
			denied[port] = struct{}{}
		}
	}
	deniedNets := make([]netip.Prefix, 0, len(opts.DeniedPrefixes))
	for _, prefix := range opts.DeniedPrefixes {
		if prefix.IsValid() {
			deniedNets = append(deniedNets, prefix.Masked())
		}
	}
	fallbackDelay := opts.AddressFallbackDelay
	if fallbackDelay <= 0 {
		fallbackDelay = defaultAddressFallbackDelay
	}

	return &SafeDialer{
		resolver:      resolver,
		dialer:        dialer,
		allowPrivate:  opts.AllowPrivate,
		deniedPorts:   denied,
		deniedNets:    deniedNets,
		fallbackDelay: fallbackDelay,
	}
}

// DefaultDeniedPorts returns a fresh copy of the default egress denylist.
func DefaultDeniedPorts() []uint16 {
	return []uint16{25, 465, 587}
}

// DialContext implements a transport-compatible TCP dialer.
func (d *SafeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d == nil {
		return nil, errors.New("security: nil SafeDialer")
	}
	if ctx == nil {
		return nil, errors.New("security: nil dial context")
	}
	lookupNetwork, err := resolverNetwork(network)
	if err != nil {
		return nil, err
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("security: invalid destination %q: %w", address, err)
	}
	if host == "" {
		return nil, errors.New("security: destination host is required")
	}
	portNumber, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || portNumber == 0 {
		return nil, fmt.Errorf("security: destination port %q is not a number from 1 to 65535", portText)
	}
	port := uint16(portNumber)
	deniedPorts := d.deniedPorts
	if deniedPorts == nil {
		deniedPorts = map[uint16]struct{}{25: {}, 465: {}, 587: {}}
	}
	if _, denied := deniedPorts[port]; denied {
		return nil, fmt.Errorf("%w: %d", ErrDeniedPort, port)
	}

	addresses, err := d.resolve(ctx, lookupNetwork, host)
	if err != nil {
		return nil, err
	}

	unsafeCount := 0
	candidates := make([]netip.Addr, 0, len(addresses))
	for _, addr := range addresses {
		addr = addr.Unmap()
		if !matchesNetwork(addr, network) {
			continue
		}
		if err := validateDestinationIP(addr, d.allowPrivate); err != nil {
			unsafeCount++
			continue
		}
		if matchesDeniedPrefix(addr, d.deniedNets) {
			unsafeCount++
			continue
		}
		candidates = append(candidates, addr)
	}

	if len(candidates) != 0 {
		return d.dialApproved(ctx, portText, interleaveAddressFamilies(candidates))
	}
	if unsafeCount != 0 {
		return nil, fmt.Errorf("%w: %s resolved only to prohibited addresses", ErrUnsafeAddress, host)
	}
	return nil, fmt.Errorf("security: %s has no addresses matching %s", host, network)
}

func (d *SafeDialer) resolve(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if literal, err := netip.ParseAddr(host); err == nil {
		if literal.Zone() != "" {
			return nil, fmt.Errorf("%w: scoped IP literals are prohibited", ErrUnsafeAddress)
		}
		return []netip.Addr{literal.Unmap()}, nil
	}
	if strings.ContainsAny(host, "\x00\r\n") {
		return nil, errors.New("security: destination host contains invalid characters")
	}
	resolver := d.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addresses, err := resolver.LookupNetIP(ctx, network, host)
	if err != nil {
		return nil, fmt.Errorf("security: resolve %s: %w", host, err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("security: resolve %s: no addresses", host)
	}
	if len(addresses) > maxResolverResults {
		return nil, fmt.Errorf("security: resolve %s: too many addresses (maximum %d)", host, maxResolverResults)
	}

	unique := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, addr := range addresses {
		if !addr.IsValid() || addr.Zone() != "" {
			continue
		}
		addr = addr.Unmap()
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		unique = append(unique, addr)
	}
	if len(unique) == 0 {
		return nil, fmt.Errorf("security: resolve %s: no valid addresses", host)
	}
	return unique, nil
}

type addressDialResult struct {
	conn net.Conn
	err  error
}

func (d *SafeDialer) dialApproved(ctx context.Context, portText string, addresses []netip.Addr) (net.Conn, error) {
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	baseDialer := d.dialer
	if baseDialer == nil {
		baseDialer = &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	}
	dialCtx, cancel := context.WithCancel(ctx)
	results := make(chan addressDialResult, 2)
	delayStep := d.fallbackDelay
	if delayStep <= 0 {
		delayStep = defaultAddressFallbackDelay
	}

	next := 0
	inFlight := 0
	startNext := func() {
		addr := addresses[next]
		next++
		inFlight++
		go func() {
			if err := context.Cause(dialCtx); err != nil {
				results <- addressDialResult{err: err}
				return
			}
			numericAddress := net.JoinHostPort(addr.String(), portText)
			conn, err := baseDialer.DialContext(dialCtx, ipNetwork(addr), numericAddress)
			if err != nil {
				results <- addressDialResult{err: fmt.Errorf("dial %s: %w", numericAddress, err)}
				return
			}
			if dialCtx.Err() != nil {
				_ = conn.Close()
				results <- addressDialResult{err: context.Cause(dialCtx)}
				return
			}
			results <- addressDialResult{conn: conn}
		}()
	}

	drain := func(count int) {
		go func() {
			for range count {
				result := <-results
				if result.conn != nil {
					_ = result.conn.Close()
				}
			}
		}()
	}
	var timer *time.Timer
	var timerC <-chan time.Time
	stopTimer := func() {
		if timer != nil {
			timer.Stop()
		}
		timer = nil
		timerC = nil
	}
	armTimer := func() {
		if inFlight == 1 && next < len(addresses) && timerC == nil {
			timer = time.NewTimer(delayStep)
			timerC = timer.C
		}
	}

	// At most two numeric attempts are live at once. This retains Happy
	// Eyeballs behavior without multiplying one authenticated stream into a
	// goroutine for every DNS answer.
	startNext()
	armTimer()
	var dialErrors []error
	for inFlight > 0 {
		select {
		case result := <-results:
			inFlight--
			if result.conn != nil {
				if err := context.Cause(ctx); err != nil {
					_ = result.conn.Close()
					cancel()
					stopTimer()
					drain(inFlight)
					return nil, err
				}
				cancel()
				stopTimer()
				drain(inFlight)
				return result.conn, nil
			}
			if result.err != nil {
				dialErrors = append(dialErrors, result.err)
			}
			// A fast failure advances immediately. Reset the stagger relative to
			// the replacement attempt instead of pre-scheduling every address.
			stopTimer()
			if next < len(addresses) {
				startNext()
			}
			armTimer()
		case <-timerC:
			stopTimer()
			if next < len(addresses) && inFlight < 2 {
				startNext()
			}
			armTimer()
		case <-ctx.Done():
			cancel()
			stopTimer()
			drain(inFlight)
			return nil, context.Cause(ctx)
		}
	}
	cancel()
	if len(dialErrors) != 0 {
		return nil, errors.Join(dialErrors...)
	}
	return nil, errors.New("security: all approved destination addresses failed")
}

func interleaveAddressFamilies(addresses []netip.Addr) []netip.Addr {
	if len(addresses) < 2 {
		return append([]netip.Addr(nil), addresses...)
	}
	var v4, v6 []netip.Addr
	for _, addr := range addresses {
		if addr.Is4() {
			v4 = append(v4, addr)
		} else {
			v6 = append(v6, addr)
		}
	}
	wantV4 := addresses[0].Is4()
	ordered := make([]netip.Addr, 0, len(addresses))
	for len(v4) != 0 || len(v6) != 0 {
		if wantV4 && len(v4) != 0 {
			ordered = append(ordered, v4[0])
			v4 = v4[1:]
		} else if !wantV4 && len(v6) != 0 {
			ordered = append(ordered, v6[0])
			v6 = v6[1:]
		} else if len(v4) != 0 {
			ordered = append(ordered, v4[0])
			v4 = v4[1:]
		} else {
			ordered = append(ordered, v6[0])
			v6 = v6[1:]
		}
		wantV4 = !wantV4
	}
	return ordered
}

func resolverNetwork(network string) (string, error) {
	switch network {
	case "tcp":
		return "ip", nil
	case "tcp4":
		return "ip4", nil
	case "tcp6":
		return "ip6", nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedNetwork, network)
	}
}

func matchesNetwork(addr netip.Addr, network string) bool {
	switch network {
	case "tcp4":
		return addr.Is4()
	case "tcp6":
		return addr.Is6()
	default:
		return true
	}
}

func ipNetwork(addr netip.Addr) string {
	if addr.Is4() {
		return "tcp4"
	}
	return "tcp6"
}

func validateDestinationIP(addr netip.Addr, allowPrivate bool) error {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() {
		return fmt.Errorf("%w: unspecified address", ErrUnsafeAddress)
	}
	if addr.IsLoopback() {
		return fmt.Errorf("%w: loopback address", ErrUnsafeAddress)
	}
	if addr.IsLinkLocalUnicast() {
		return fmt.Errorf("%w: link-local address", ErrUnsafeAddress)
	}
	if addr.IsMulticast() {
		return fmt.Errorf("%w: multicast address", ErrUnsafeAddress)
	}
	if !addr.IsGlobalUnicast() {
		return fmt.Errorf("%w: non-unicast address", ErrUnsafeAddress)
	}
	for _, prefix := range deniedSpecialUsePrefixes {
		if prefix.Contains(addr) {
			return fmt.Errorf("%w: special-use address", ErrUnsafeAddress)
		}
	}
	if (addr.IsPrivate() || carrierGradeNAT.Contains(addr)) && !allowPrivate {
		return fmt.Errorf("%w: private address", ErrUnsafeAddress)
	}
	return nil
}

func matchesDeniedPrefix(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
