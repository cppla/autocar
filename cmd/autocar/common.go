package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cppla/autocar/internal/accel"
	"github.com/cppla/autocar/internal/config"
	"github.com/cppla/autocar/internal/security"
	"github.com/cppla/autocar/internal/transport"
	"github.com/cppla/autocar/internal/tunnel"
)

type tunnelFlags struct {
	server         string
	fallback       string
	mode           string
	serverName     string
	caFile         string
	systemRoots    bool
	clientCert     string
	clientKey      string
	tokenFile      string
	dialTimeout    time.Duration
	primaryTimeout time.Duration
	openTimeout    time.Duration
	fallbackTTL    time.Duration
	pacing         string
	pacingProfile  string
	uploadMbps     uint64
	downloadMbps   uint64
	eventHandler   tunnel.ClientEventHandler
}

func addTunnelFlags(fs *flag.FlagSet, flags *tunnelFlags) {
	fs.StringVar(&flags.server, "server", "", "relay host:port (required)")
	fs.StringVar(&flags.fallback, "fallback-server", "", "TCP/TLS relay host:port; defaults to --server")
	fs.StringVar(&flags.mode, "transport", "auto", "transport: auto, quic, or tls")
	fs.StringVar(&flags.serverName, "server-name", "", "TLS certificate DNS name; defaults to relay host")
	fs.StringVar(&flags.caFile, "ca", "", "PEM trust anchor for the relay certificate")
	fs.BoolVar(&flags.systemRoots, "system-roots", false, "trust the operating-system CA set instead of --ca")
	fs.StringVar(&flags.clientCert, "client-cert", "", "optional mTLS client certificate PEM")
	fs.StringVar(&flags.clientKey, "client-key", "", "optional mTLS client private key PEM")
	fs.StringVar(&flags.tokenFile, "token-file", "", "0600 shared-token file; otherwise AUTOCAR_TOKEN")
	fs.DurationVar(&flags.dialTimeout, "dial-timeout", 5*time.Second, "QUIC/TLS network dial timeout")
	fs.DurationVar(&flags.primaryTimeout, "quic-attempt-timeout", 5*time.Second, "entire QUIC phase budget before auto-mode TLS fallback")
	fs.DurationVar(&flags.openTimeout, "open-timeout", 15*time.Second, "overall remote stream open timeout")
	fs.DurationVar(&flags.fallbackTTL, "fallback-cooldown", 30*time.Second, "time to prefer TLS after a QUIC path failure")
	fs.StringVar(&flags.pacing, "pacing", "adaptive", "QUIC application pacing: adaptive, reno, or fixed-rate")
	fs.StringVar(&flags.pacingProfile, "pacing-profile", "balanced", "adaptive pacing profile: conservative, balanced, or aggressive")
	fs.Uint64Var(&flags.uploadMbps, "upload-mbps", 0, "client-to-relay fixed pacing rate in Mbit/s")
	fs.Uint64Var(&flags.downloadMbps, "download-mbps", 0, "relay-to-client fixed pacing rate in Mbit/s")
}

type closeDialer interface {
	transport.Dialer
	Close() error
}

func buildTunnelDialer(flags tunnelFlags) (closeDialer, error) {
	if flags.server == "" {
		return nil, errors.New("--server is required")
	}
	mode := strings.ToLower(strings.TrimSpace(flags.mode))
	if mode != "auto" && mode != "quic" && mode != "tls" {
		return nil, fmt.Errorf("invalid --transport %q; want auto, quic, or tls", flags.mode)
	}
	if flags.dialTimeout <= 0 || flags.openTimeout <= 0 {
		return nil, errors.New("--dial-timeout and --open-timeout must be positive")
	}
	if mode == "auto" && (flags.primaryTimeout <= 0 || flags.primaryTimeout >= flags.openTimeout) {
		return nil, errors.New("auto mode requires 0 < --quic-attempt-timeout < --open-timeout so TLS fallback retains time")
	}
	if mode != "auto" && flags.fallback != "" {
		return nil, errors.New("--fallback-server is valid only with --transport=auto")
	}
	if flags.caFile != "" && flags.systemRoots {
		return nil, errors.New("--ca and --system-roots are mutually exclusive")
	}
	if flags.caFile == "" && !flags.systemRoots {
		return nil, errors.New("set --ca to a pinned/private CA, or explicitly use --system-roots")
	}
	if (flags.clientCert == "") != (flags.clientKey == "") {
		return nil, errors.New("--client-cert and --client-key must be supplied together")
	}

	host, _, err := net.SplitHostPort(flags.server)
	if err != nil || host == "" {
		return nil, fmt.Errorf("invalid --server %q; want host:port", flags.server)
	}
	serverName := flags.serverName
	if serverName == "" {
		serverName = host
	}

	var roots *x509.CertPool
	if flags.systemRoots {
		roots, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system roots: %w", err)
		}
	} else {
		roots, err = security.LoadCertPool(flags.caFile)
		if err != nil {
			return nil, err
		}
	}
	var certificates []tls.Certificate
	if flags.clientCert != "" {
		certificate, err := security.LoadKeyPair(flags.clientCert, flags.clientKey)
		if err != nil {
			return nil, err
		}
		certificates = []tls.Certificate{certificate}
	}
	tlsConfig, err := security.NewClientTLSConfig(security.ClientTLSOptions{
		ServerName:   serverName,
		RootCAs:      roots,
		Certificates: certificates,
	})
	if err != nil {
		return nil, err
	}
	token, err := config.LoadSecret(flags.tokenFile, "AUTOCAR_TOKEN")
	if err != nil {
		return nil, err
	}

	upload, err := megabitsToBytesPerSecond(flags.uploadMbps)
	if err != nil {
		return nil, fmt.Errorf("--upload-mbps: %w", err)
	}
	download, err := megabitsToBytesPerSecond(flags.downloadMbps)
	if err != nil {
		return nil, fmt.Errorf("--download-mbps: %w", err)
	}
	pacing, err := newPacingConfig(flags.pacing, flags.pacingProfile)
	if err != nil {
		return nil, err
	}
	if err := validateClientRates(pacing.Mode, upload, download); err != nil {
		return nil, err
	}
	if err := validateClientPacingTransport(mode, pacing.Mode); err != nil {
		return nil, err
	}
	eventHandler := flags.eventHandler
	if eventHandler == nil {
		eventHandler = logTunnelEvent
	}

	switch mode {
	case "quic":
		return tunnel.NewClient(tunnel.ClientConfig{
			ServerAddress:    flags.server,
			Token:            token,
			TLSConfig:        tlsConfig,
			HandshakeTimeout: flags.openTimeout,
			QUICDialTimeout:  flags.dialTimeout,
			Pacing:           pacing,
			MaxTx:            upload,
			MaxRx:            download,
			EventHandler:     eventHandler,
		})
	case "tls":
		return tunnel.NewTLSClient(tunnel.TLSClientConfig{
			ServerAddress:    flags.server,
			Token:            token,
			TLSConfig:        tlsConfig,
			HandshakeTimeout: flags.openTimeout,
			DialTimeout:      flags.dialTimeout,
		})
	case "auto":
		fallback := flags.fallback
		if fallback == "" {
			fallback = flags.server
		}
		return tunnel.NewClient(tunnel.ClientConfig{
			ServerAddress:         flags.server,
			FallbackAddress:       fallback,
			Token:                 token,
			TLSConfig:             tlsConfig,
			HandshakeTimeout:      flags.openTimeout,
			QUICDialTimeout:       flags.dialTimeout,
			TLSDialTimeout:        flags.dialTimeout,
			PrimaryAttemptTimeout: flags.primaryTimeout,
			FallbackCooldown:      flags.fallbackTTL,
			Pacing:                pacing,
			MaxTx:                 upload,
			MaxRx:                 download,
			EventHandler:          eventHandler,
		})
	default:
		panic("unreachable transport mode")
	}
}

func newPacingConfig(modeText, profileText string) (tunnel.PacingConfig, error) {
	mode := accel.Mode(strings.ToLower(strings.TrimSpace(modeText)))
	if mode == "" {
		mode = accel.ModeAdaptive
	}
	switch mode {
	case accel.ModeAdaptive, accel.ModeReno, accel.ModeFixedRate:
	default:
		return tunnel.PacingConfig{}, fmt.Errorf(
			"invalid --pacing %q; want adaptive, reno, or fixed-rate",
			modeText,
		)
	}

	profile := accel.Profile(strings.ToLower(strings.TrimSpace(profileText)))
	if profile == "" {
		profile = accel.ProfileBalanced
	}
	switch profile {
	case accel.ProfileConservative, accel.ProfileBalanced, accel.ProfileAggressive:
	default:
		return tunnel.PacingConfig{}, fmt.Errorf(
			"invalid --pacing-profile %q; want conservative, balanced, or aggressive",
			profileText,
		)
	}
	return tunnel.PacingConfig{Mode: mode, Profile: profile}, nil
}

func validateClientRates(mode accel.Mode, upload, download uint64) error {
	if mode == accel.ModeFixedRate {
		if upload == 0 || download == 0 {
			return errors.New("--pacing=fixed-rate requires nonzero --upload-mbps and --download-mbps")
		}
		return nil
	}
	if upload != 0 || download != 0 {
		return errors.New("--upload-mbps and --download-mbps require --pacing=fixed-rate")
	}
	return nil
}

func validateClientPacingTransport(transportMode string, pacingMode accel.Mode) error {
	if transportMode == "tls" && pacingMode == accel.ModeFixedRate {
		return errors.New("--pacing=fixed-rate requires --transport=quic or --transport=auto")
	}
	return nil
}

func megabitsToBytesPerSecond(value uint64) (uint64, error) {
	const bitsPerMegabit = uint64(1_000_000)
	if value > ^uint64(0)/bitsPerMegabit {
		return 0, errors.New("value is too large")
	}
	return value * bitsPerMegabit / 8, nil
}

func parseDeniedPorts(value string) ([]uint16, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "none") {
		return []uint16{}, nil
	}
	parts := strings.Split(value, ",")
	ports := make([]uint16, 0, len(parts))
	seen := make(map[uint16]struct{}, len(parts))
	for _, part := range parts {
		number, err := strconv.ParseUint(strings.TrimSpace(part), 10, 16)
		if err != nil || number == 0 {
			return nil, fmt.Errorf("invalid denied port %q", part)
		}
		port := uint16(number)
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	return ports, nil
}

func parseDeniedPrefixes(value string) ([]netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "none") {
		return []netip.Prefix{}, nil
	}
	parts := strings.Split(value, ",")
	prefixes := make([]netip.Prefix, 0, len(parts))
	seen := make(map[netip.Prefix]struct{}, len(parts))
	for _, part := range parts {
		text := strings.TrimSpace(part)
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			if address, addressErr := netip.ParseAddr(text); addressErr == nil && address.Zone() == "" {
				prefix = netip.PrefixFrom(address.Unmap(), address.Unmap().BitLen())
			} else {
				return nil, fmt.Errorf("invalid denied CIDR %q", part)
			}
		}
		prefix, err = security.NormalizeDeniedPrefix(prefix)
		if err != nil {
			return nil, fmt.Errorf("invalid denied CIDR %q: %w", part, err)
		}
		if _, exists := seen[prefix]; exists {
			continue
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func ensureSafeLocalListener(address string, authenticated bool) error {
	loopback, err := isLoopbackListener(address)
	if err != nil {
		return err
	}
	if authenticated {
		return nil
	}
	if !loopback {
		return fmt.Errorf("refusing unauthenticated non-loopback listener %q", address)
	}
	return nil
}

// ensureProtectedPlaintextListener prevents SOCKS5 username/password and HTTP
// Basic credentials from being exposed on a network interface by accident.
// Both protocols carry those credentials in cleartext; operators who already
// provide a trusted outer network can make a deliberate, visible exception.
func ensureProtectedPlaintextListener(address string, allowPublicPlaintext bool) error {
	loopback, err := isLoopbackListener(address)
	if err != nil {
		return err
	}
	if loopback || allowPublicPlaintext {
		return nil
	}
	return fmt.Errorf("refusing plaintext SOCKS5/HTTP listener %q outside loopback; use HTTPS proxy or explicitly set --allow-public-plaintext", address)
}

func isLoopbackListener(address string) (bool, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false, fmt.Errorf("invalid listen address %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback(), nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
