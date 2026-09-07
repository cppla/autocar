package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cppla/autocar/internal/accel"
	"github.com/cppla/autocar/internal/config"
	"github.com/cppla/autocar/internal/cover"
	"github.com/cppla/autocar/internal/security"
	"github.com/cppla/autocar/internal/tunnel"
)

func runServer(parent context.Context, args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	serverProtocolText := fs.String("protocol", "native", "relay protocol: native or web")
	listen := fs.String("listen", ":443", "primary UDP listen address")
	tcpListen := fs.String("tcp-listen", "", "TCP listener address; defaults to --listen")
	disableFallback := fs.Bool("disable-tcp-fallback", false, "disable the TCP/TLS fallback listener")
	coverRoot := fs.String("cover-root", "", "web protocol: directory served as the public cover origin")
	coverUpstream := fs.String("cover-upstream", "", "web protocol: fixed http(s) origin used as the public cover")
	certFile := fs.String("cert", "", "server certificate PEM (required)")
	keyFile := fs.String("key", "", "server private key PEM (required)")
	clientCAFile := fs.String("client-ca", "", "optional PEM CA that enables mandatory mTLS")
	tokenFile := fs.String("token-file", "", "0600 shared-token file; otherwise AUTOCAR_TOKEN")
	allowPrivate := fs.Bool("allow-private", false, "allow RFC1918/ULA/CGNAT destinations (loopback remains blocked)")
	deniedPortsText := fs.String("deny-ports", "25,465,587", "comma-separated denied destination ports, or none")
	deniedCIDRsText := fs.String("deny-cidrs", "", "additional comma-separated denied destination CIDRs/IPs")
	maxStreams := fs.Int("max-streams", 1024, "maximum active tunnel streams")
	maxConnections := fs.Int("max-connections", 256, "global maximum accepted relay connections")
	maxClientConnections := fs.Int("max-client-connections", 32, "maximum relay connections per source IPv4 or IPv6 /64")
	maxClientFallbackConnections := fs.Int("max-client-fallback-connections", 0, "native protocol: maximum TLS fallback connections per source IPv4 or IPv6 /64; zero uses min(32, --max-streams)")
	maxUDPSessions := fs.Int("max-udp-sessions", 256, "maximum live UDP associations across all QUIC clients")
	maxClientUDPSessions := fs.Int("max-client-udp-sessions", 32, "maximum live UDP associations per source IPv4 or IPv6 /64")
	maxUDPDestinations := fs.Int("max-udp-destinations", 64, "maximum numeric destinations authorized per UDP association")
	udpReceiveQueue := fs.Int("udp-receive-queue", 32, "maximum complete datagrams waiting in each bounded UDP receive/send queue")
	udpReassemblyTTL := fs.Duration("udp-reassembly-ttl", 5*time.Second, "native protocol: lifetime of an incomplete fragmented UDP message")
	maxUDPReassemblyMessages := fs.Int("max-udp-reassembly-messages", 64, "native protocol: maximum incomplete UDP messages per QUIC connection")
	maxUDPReassemblyBytes := fs.Int("max-udp-reassembly-bytes", 256<<10, "native protocol: maximum bytes buffered for UDP reassembly per QUIC connection")
	pacingText := fs.String("pacing", "adaptive", "native protocol application pacing: adaptive, reno, or fixed-rate")
	pacingProfileText := fs.String("pacing-profile", "balanced", "native protocol adaptive pacing profile: conservative, balanced, or aggressive")
	maxUploadMbps := fs.Uint64("max-upload-mbps", 0, "native protocol: maximum client-to-relay fixed pacing rate in Mbit/s")
	maxDownloadMbps := fs.Uint64("max-download-mbps", 0, "native protocol: maximum relay-to-client fixed pacing rate in Mbit/s")
	allowClientRates := fs.Bool("allow-client-rates", false, "native protocol: allow authenticated clients to request rates within server maxima")
	dialTimeout := fs.Duration("dial-timeout", 4*time.Second, "remote destination dial timeout")
	handshakeTimeout := fs.Duration("handshake-timeout", 10*time.Second, "authentication and initial stream-open timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	serverProtocol := strings.ToLower(strings.TrimSpace(*serverProtocolText))
	if err := validateServerProtocolOptions(serverProtocol, *clientCAFile, *coverRoot, *coverUpstream, *disableFallback); err != nil {
		return err
	}
	if *certFile == "" || *keyFile == "" {
		return errors.New("--cert and --key are required")
	}
	if *maxStreams <= 0 {
		return errors.New("--max-streams must be positive")
	}
	if *maxConnections <= 0 {
		return errors.New("--max-connections must be positive")
	}
	if *maxClientConnections <= 0 || *maxClientConnections > *maxConnections {
		return errors.New("--max-client-connections must be positive and no greater than --max-connections")
	}
	if !*disableFallback && (*maxClientFallbackConnections < 0 || *maxClientFallbackConnections > *maxStreams) {
		return errors.New("--max-client-fallback-connections must be zero or positive and no greater than --max-streams")
	}
	if serverProtocol == "web" && *maxClientFallbackConnections != 0 {
		return errors.New("--max-client-fallback-connections is valid only with --protocol=native; web H2/H3 share --max-client-connections")
	}
	if err := validateServerUDPLimits(serverUDPLimits{
		maxSessions:           *maxUDPSessions,
		maxClientSessions:     *maxClientUDPSessions,
		maxDestinations:       *maxUDPDestinations,
		receiveQueue:          *udpReceiveQueue,
		reassemblyTTL:         *udpReassemblyTTL,
		maxReassemblyMessages: *maxUDPReassemblyMessages,
		maxReassemblyBytes:    *maxUDPReassemblyBytes,
	}); err != nil {
		return err
	}
	if *tcpListen == "" {
		*tcpListen = *listen
	}
	pacing, err := newPacingConfig(*pacingText, *pacingProfileText)
	if err != nil {
		return err
	}
	maxUpload, err := megabitsToBytesPerSecond(*maxUploadMbps)
	if err != nil {
		return fmt.Errorf("--max-upload-mbps: %w", err)
	}
	maxDownload, err := megabitsToBytesPerSecond(*maxDownloadMbps)
	if err != nil {
		return fmt.Errorf("--max-download-mbps: %w", err)
	}
	if err := validateServerRates(pacing.Mode, *allowClientRates, maxUpload, maxDownload); err != nil {
		return err
	}
	if serverProtocol == "web" {
		if err := validateWebServerNativeOnlyOptions(
			pacing,
			*allowClientRates,
			maxUpload,
			maxDownload,
			*udpReassemblyTTL,
			*maxUDPReassemblyMessages,
			*maxUDPReassemblyBytes,
		); err != nil {
			return err
		}
	}

	token, err := config.LoadSecret(*tokenFile, "AUTOCAR_TOKEN")
	if err != nil {
		return err
	}
	certificate, err := security.LoadKeyPair(*certFile, *keyFile)
	if err != nil {
		return err
	}
	var clientCAPEM []byte
	if *clientCAFile != "" {
		clientCAPEM, err = os.ReadFile(*clientCAFile)
		if err != nil {
			return fmt.Errorf("read client CA: %w", err)
		}
	}
	tlsConfig, err := security.NewServerTLSConfig(security.ServerTLSOptions{
		Certificates: []tls.Certificate{certificate},
		ClientCAPEM:  clientCAPEM,
	})
	if err != nil {
		return err
	}
	deniedPorts, err := parseDeniedPorts(*deniedPortsText)
	if err != nil {
		return err
	}
	deniedPrefixes, err := parseDeniedPrefixes(*deniedCIDRsText)
	if err != nil {
		return err
	}
	safeDialer := security.NewSafeDialer(security.SafeDialerOptions{
		AllowPrivate:   *allowPrivate,
		DeniedPorts:    deniedPorts,
		DeniedPrefixes: deniedPrefixes,
		Dialer: &net.Dialer{
			Timeout:   *dialTimeout,
			KeepAlive: 30 * time.Second,
		},
	})
	streamAdmission, err := tunnel.NewStreamAdmission(*maxStreams)
	if err != nil {
		return fmt.Errorf("configure stream admission: %w", err)
	}
	if serverProtocol == "web" {
		coverHandler, err := buildCoverHandler(*coverRoot, *coverUpstream)
		if err != nil {
			return err
		}
		webServer, err := tunnel.ListenWeb(tunnel.WebServerConfig{
			TCPAddress:           *tcpListen,
			UDPAddress:           *listen,
			Token:                token,
			TLSConfig:            tlsConfig,
			Cover:                coverHandler,
			Dialer:               safeDialer,
			HandshakeTimeout:     *handshakeTimeout,
			DialTimeout:          *dialTimeout,
			MaxConcurrentStreams: *maxStreams,
			StreamAdmission:      streamAdmission,
			MaxConnections:       *maxConnections,
			MaxClientConnections: *maxClientConnections,
			MaxUDPSessions:       *maxUDPSessions,
			MaxClientUDPSessions: *maxClientUDPSessions,
			MaxUDPDestinations:   *maxUDPDestinations,
			UDPReceiveQueue:      *udpReceiveQueue,
		})
		if err != nil {
			return err
		}
		defer webServer.Close()
		slog.Info("relay listener started", "protocol", "web", "transport", "h3", "address", webServer.UDPAddr().String())
		slog.Info("relay listener started", "protocol", "web", "transport", "h2", "address", webServer.TCPAddr().String())
		if err := webServer.Serve(parent); err != nil {
			return err
		}
		slog.Info("relay stopped", "protocol", "web", "reason", contextReason(parent))
		return nil
	}

	quicServer, err := tunnel.ListenQUIC(tunnel.QUICServerConfig{
		Address:                  *listen,
		Token:                    token,
		TLSConfig:                tlsConfig,
		Dialer:                   safeDialer,
		Pacing:                   pacing,
		MaxTx:                    maxDownload,
		MaxRx:                    maxUpload,
		AllowClientRates:         *allowClientRates,
		HandshakeTimeout:         *handshakeTimeout,
		DialTimeout:              *dialTimeout,
		MaxConcurrentStreams:     *maxStreams,
		StreamAdmission:          streamAdmission,
		MaxConnections:           *maxConnections,
		MaxClientConnections:     *maxClientConnections,
		MaxUDPSessions:           *maxUDPSessions,
		MaxClientUDPSessions:     *maxClientUDPSessions,
		MaxUDPDestinations:       *maxUDPDestinations,
		UDPReceiveQueue:          *udpReceiveQueue,
		UDPReassemblyTTL:         *udpReassemblyTTL,
		MaxUDPReassemblyMessages: *maxUDPReassemblyMessages,
		MaxUDPReassemblyBytes:    *maxUDPReassemblyBytes,
	})
	if err != nil {
		return err
	}
	defer quicServer.Close()

	var tlsServer *tunnel.TLSServer
	if !*disableFallback {
		tlsServer, err = tunnel.ListenTLS(tunnel.TLSServerConfig{
			Address:              *tcpListen,
			Token:                token,
			TLSConfig:            tlsConfig,
			Dialer:               safeDialer,
			HandshakeTimeout:     *handshakeTimeout,
			DialTimeout:          *dialTimeout,
			MaxConcurrentStreams: *maxStreams,
			StreamAdmission:      streamAdmission,
			MaxClientConnections: *maxClientFallbackConnections,
		})
		if err != nil {
			return err
		}
		defer tlsServer.Close()
	}

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	errorsCh := make(chan error, 2)
	var wg sync.WaitGroup
	start := func(name, address string, serve func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slog.Info("relay listener started", "transport", name, "address", address)
			if err := serve(ctx); err != nil && ctx.Err() == nil {
				select {
				case errorsCh <- fmt.Errorf("%s listener: %w", name, err):
				default:
				}
				cancel()
			}
		}()
	}
	start("quic", quicServer.Addr().String(), quicServer.Serve)
	if tlsServer != nil {
		start("tls", tlsServer.Addr().String(), tlsServer.Serve)
	}

	<-ctx.Done()
	_ = quicServer.Close()
	if tlsServer != nil {
		_ = tlsServer.Close()
	}
	wg.Wait()
	select {
	case err := <-errorsCh:
		return err
	default:
	}
	if parent.Err() != nil && !errors.Is(parent.Err(), context.Canceled) {
		return parent.Err()
	}
	slog.Info("relay stopped", "reason", contextReason(ctx))
	return nil
}

func validateServerProtocolOptions(protocolMode, clientCAFile, coverRoot, coverUpstream string, disableFallback bool) error {
	switch protocolMode {
	case "native":
		if strings.TrimSpace(coverRoot) != "" || strings.TrimSpace(coverUpstream) != "" {
			return errors.New("--cover-root and --cover-upstream require --protocol=web")
		}
		return nil
	case "web":
	default:
		return fmt.Errorf("invalid --protocol %q; want native or web", protocolMode)
	}

	if strings.TrimSpace(clientCAFile) != "" {
		return errors.New("--client-ca is incompatible with --protocol=web because the cover origin must remain publicly reachable")
	}
	if disableFallback {
		return errors.New("--disable-tcp-fallback is incompatible with --protocol=web because HTTP/2 is the TCP fallback")
	}
	hasRoot := strings.TrimSpace(coverRoot) != ""
	hasUpstream := strings.TrimSpace(coverUpstream) != ""
	if hasRoot == hasUpstream {
		return errors.New("--protocol=web requires exactly one of --cover-root or --cover-upstream")
	}
	return nil
}

func buildCoverHandler(root, upstream string) (http.Handler, error) {
	if strings.TrimSpace(root) != "" {
		handler, err := cover.NewStaticHandler(root)
		if err != nil {
			return nil, fmt.Errorf("configure static cover: %w", err)
		}
		return handler, nil
	}
	origin, err := url.Parse(strings.TrimSpace(upstream))
	if err != nil {
		return nil, fmt.Errorf("parse --cover-upstream: %w", err)
	}
	handler, err := cover.NewReverseProxyHandler(origin, nil)
	if err != nil {
		return nil, fmt.Errorf("configure upstream cover: %w", err)
	}
	return handler, nil
}

func contextReason(ctx context.Context) string {
	if cause := context.Cause(ctx); cause != nil {
		return strings.TrimSpace(cause.Error())
	}
	return "completed"
}

type serverUDPLimits struct {
	maxSessions           int
	maxClientSessions     int
	maxDestinations       int
	receiveQueue          int
	reassemblyTTL         time.Duration
	maxReassemblyMessages int
	maxReassemblyBytes    int
}

func validateServerUDPLimits(limits serverUDPLimits) error {
	positiveCounts := []struct {
		name  string
		value int
	}{
		{"--max-udp-sessions", limits.maxSessions},
		{"--max-client-udp-sessions", limits.maxClientSessions},
		{"--max-udp-destinations", limits.maxDestinations},
		{"--udp-receive-queue", limits.receiveQueue},
		{"--max-udp-reassembly-messages", limits.maxReassemblyMessages},
		{"--max-udp-reassembly-bytes", limits.maxReassemblyBytes},
	}
	for _, limit := range positiveCounts {
		if limit.value <= 0 {
			return fmt.Errorf("%s must be positive", limit.name)
		}
	}
	if limits.reassemblyTTL <= 0 {
		return errors.New("--udp-reassembly-ttl must be positive")
	}
	if limits.maxClientSessions > limits.maxSessions {
		return errors.New("--max-client-udp-sessions must be no greater than --max-udp-sessions")
	}
	return nil
}

func validateServerRates(mode accel.Mode, allowClientRates bool, maxUpload, maxDownload uint64) error {
	if (mode == accel.ModeFixedRate || allowClientRates) && (maxUpload == 0 || maxDownload == 0) {
		return errors.New("fixed-rate pacing and --allow-client-rates require nonzero --max-upload-mbps and --max-download-mbps")
	}
	if mode != accel.ModeFixedRate && !allowClientRates && (maxUpload != 0 || maxDownload != 0) {
		return errors.New("server rate maxima require --pacing=fixed-rate or --allow-client-rates")
	}
	return nil
}

func validateWebServerNativeOnlyOptions(
	pacing tunnel.PacingConfig,
	allowClientRates bool,
	maxUpload, maxDownload uint64,
	reassemblyTTL time.Duration,
	maxReassemblyMessages, maxReassemblyBytes int,
) error {
	if pacing.Mode != accel.ModeAdaptive || pacing.Profile != accel.ProfileBalanced ||
		allowClientRates || maxUpload != 0 || maxDownload != 0 {
		return errors.New("--protocol=web does not support native pacing or rate flags")
	}
	if reassemblyTTL != 5*time.Second || maxReassemblyMessages != 64 || maxReassemblyBytes != 256<<10 {
		return errors.New("--protocol=web uses RFC 9298 datagrams and does not support native UDP reassembly flags")
	}
	return nil
}
