package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cppla/autocar/internal/config"
	"github.com/cppla/autocar/internal/hy2"
	"github.com/cppla/autocar/internal/security"
	"github.com/cppla/autocar/internal/transport"
	"github.com/cppla/autocar/internal/tunnel"
)

type tunnelFlags struct {
	server                  string
	fallback                string
	mode                    string
	serverName              string
	caFile                  string
	systemRoots             bool
	clientCert              string
	clientKey               string
	tokenFile               string
	dialTimeout             time.Duration
	primaryTimeout          time.Duration
	openTimeout             time.Duration
	fallbackTTL             time.Duration
	congestion              string
	bbrProfile              string
	uploadMbps              uint64
	downloadMbps            uint64
	disableLossCompensation bool
	fastOpen                bool
	obfsPasswordFile        string
	disableChromeParrot     bool
	maxPendingOpens         int
}

func addTunnelFlags(fs *flag.FlagSet, flags *tunnelFlags) {
	fs.StringVar(&flags.server, "server", "", "relay host:port (required)")
	fs.StringVar(&flags.fallback, "fallback-server", "", "TCP/TLS relay host:port; defaults to --server")
	fs.StringVar(&flags.mode, "transport", "auto", "transport: auto, hy2 (or quic), legacy-quic, or tls")
	fs.StringVar(&flags.serverName, "server-name", "", "TLS certificate DNS name; defaults to relay host")
	fs.StringVar(&flags.caFile, "ca", "", "PEM trust anchor for the relay certificate")
	fs.BoolVar(&flags.systemRoots, "system-roots", false, "trust the operating-system CA set instead of --ca")
	fs.StringVar(&flags.clientCert, "client-cert", "", "optional mTLS client certificate PEM")
	fs.StringVar(&flags.clientKey, "client-key", "", "optional mTLS client private key PEM")
	fs.StringVar(&flags.tokenFile, "token-file", "", "0600 shared-token file; otherwise AUTOCAR_TOKEN")
	fs.DurationVar(&flags.dialTimeout, "dial-timeout", 5*time.Second, "legacy QUIC/TLS network dial timeout")
	fs.DurationVar(&flags.primaryTimeout, "quic-attempt-timeout", 5*time.Second, "entire QUIC phase budget before auto-mode TLS fallback")
	fs.DurationVar(&flags.openTimeout, "open-timeout", 15*time.Second, "overall remote stream open timeout")
	fs.DurationVar(&flags.fallbackTTL, "fallback-cooldown", 30*time.Second, "time to prefer TLS after a QUIC path failure")
	fs.StringVar(&flags.congestion, "congestion", hy2.CongestionBBR, "QUIC congestion controller: bbr or reno; configured bandwidth selects Brutal")
	fs.StringVar(&flags.bbrProfile, "bbr-profile", hy2.BBRStandard, "BBR profile: conservative, standard, or aggressive")
	fs.Uint64Var(&flags.uploadMbps, "upload-mbps", 0, "known client upload capacity in Mbit/s; nonzero requests negotiated Brutal")
	fs.Uint64Var(&flags.downloadMbps, "download-mbps", 0, "known client download capacity in Mbit/s; nonzero requests negotiated Brutal")
	fs.BoolVar(&flags.disableLossCompensation, "disable-loss-compensation", false, "disable Brutal ACK/loss-rate compensation")
	fs.BoolVar(&flags.fastOpen, "fast-open", false, "return before the exit dial response (lower setup latency, weaker immediate error reporting)")
	fs.StringVar(&flags.obfsPasswordFile, "obfs-password-file", "", "0600 Salamander password file; otherwise optional AUTOCAR_OBFS_PASSWORD")
	fs.BoolVar(&flags.disableChromeParrot, "disable-chrome-parrot", false, "disable Hysteria's Chrome QUIC fingerprint (diagnostics or Ed25519 relay certificates)")
	fs.IntVar(&flags.maxPendingOpens, "max-pending-opens", 256, "maximum in-flight Hysteria TCP stream opens")
}

type closeDialer interface {
	transport.Dialer
	Close() error
}

func buildTunnelDialer(flags tunnelFlags) (closeDialer, error) {
	if flags.server == "" {
		return nil, errors.New("--server is required")
	}
	mode := strings.ToLower(flags.mode)
	if mode != "auto" && mode != "hy2" && mode != "quic" && mode != "legacy-quic" && mode != "tls" {
		return nil, fmt.Errorf("invalid --transport %q; want auto, hy2, quic, legacy-quic, or tls", flags.mode)
	}
	if flags.dialTimeout <= 0 || flags.openTimeout <= 0 {
		return nil, errors.New("--dial-timeout and --open-timeout must be positive")
	}
	if flags.maxPendingOpens <= 0 || flags.maxPendingOpens > 65536 {
		return nil, errors.New("--max-pending-opens must be between 1 and 65536")
	}
	if mode == "auto" && (flags.primaryTimeout <= 0 || flags.primaryTimeout >= flags.openTimeout) {
		return nil, errors.New("auto mode requires 0 < --quic-attempt-timeout < --open-timeout so TLS fallback retains time")
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
	obfuscationKey, err := loadOptionalSecret(flags.obfsPasswordFile, "AUTOCAR_OBFS_PASSWORD", 16)
	if err != nil {
		return nil, fmt.Errorf("load obfuscation password: %w", err)
	}
	newAcceleratedClient := func() (*hy2.Client, error) {
		return hy2.NewClient(hy2.ClientConfig{
			ServerAddress:           flags.server,
			Token:                   token,
			TLSConfig:               tlsConfig,
			Congestion:              flags.congestion,
			BBRProfile:              flags.bbrProfile,
			MaxTx:                   upload,
			MaxRx:                   download,
			DisableLossCompensation: flags.disableLossCompensation,
			FastOpen:                flags.fastOpen,
			ObfuscationKey:          obfuscationKey,
			DisableChromeParrot:     flags.disableChromeParrot,
			MaxPendingOpens:         flags.maxPendingOpens,
		})
	}

	switch mode {
	case "hy2", "quic":
		return newAcceleratedClient()
	case "legacy-quic":
		return tunnel.NewClient(tunnel.ClientConfig{
			ServerAddress:    flags.server,
			Token:            token,
			TLSConfig:        tlsConfig,
			HandshakeTimeout: flags.openTimeout,
			QUICDialTimeout:  flags.dialTimeout,
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
		primary, err := newAcceleratedClient()
		if err != nil {
			return nil, err
		}
		fallbackDialer, err := tunnel.NewTLSClient(tunnel.TLSClientConfig{
			ServerAddress:    fallback,
			Token:            token,
			TLSConfig:        tlsConfig,
			HandshakeTimeout: flags.openTimeout,
			DialTimeout:      flags.dialTimeout,
		})
		if err != nil {
			_ = primary.Close()
			return nil, err
		}
		auto, err := hy2.NewAutoClient(hy2.AutoConfig{
			Primary:        primary,
			Fallback:       fallbackDialer,
			AttemptTimeout: flags.primaryTimeout,
			Cooldown:       flags.fallbackTTL,
			OnFallback: func(primaryErr error) {
				slog.Warn("QUIC path unavailable; using authenticated TLS fallback",
					"error", primaryErr,
					"cooldown", flags.fallbackTTL)
			},
		})
		if err != nil {
			_ = primary.Close()
			_ = fallbackDialer.Close()
			return nil, err
		}
		return auto, nil
	default:
		panic("unreachable transport mode")
	}
}

func megabitsToBytesPerSecond(value uint64) (uint64, error) {
	const bitsPerMegabit = uint64(1_000_000)
	if value > ^uint64(0)/bitsPerMegabit {
		return 0, errors.New("value is too large")
	}
	return value * bitsPerMegabit / 8, nil
}

func loadOptionalSecret(path, envName string, minimumLength int) ([]byte, error) {
	if path == "" && os.Getenv(envName) == "" {
		return nil, nil
	}
	value, err := config.LoadSecret(path, envName)
	if err != nil {
		return nil, err
	}
	if len(value) < minimumLength {
		return nil, fmt.Errorf("secret must be at least %d bytes", minimumLength)
	}
	return []byte(value), nil
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
		prefix = prefix.Masked()
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
