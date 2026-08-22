package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cppla/autocar/internal/config"
	"github.com/cppla/autocar/internal/hy2"
	"github.com/cppla/autocar/internal/security"
	"github.com/cppla/autocar/internal/tunnel"
)

func runServer(parent context.Context, args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	listen := fs.String("listen", ":443", "QUIC UDP listen address")
	quicEngine := fs.String("quic-engine", "hy2", "UDP engine: hy2 or legacy")
	tcpListen := fs.String("tcp-listen", "", "TLS/TCP fallback address; defaults to --listen")
	disableFallback := fs.Bool("disable-tcp-fallback", false, "disable the TCP/TLS fallback listener")
	certFile := fs.String("cert", "", "server certificate PEM (required)")
	keyFile := fs.String("key", "", "server private key PEM (required)")
	clientCAFile := fs.String("client-ca", "", "optional PEM CA that enables mandatory mTLS")
	tokenFile := fs.String("token-file", "", "0600 shared-token file; otherwise AUTOCAR_TOKEN")
	allowPrivate := fs.Bool("allow-private", false, "allow RFC1918/ULA/CGNAT destinations (loopback remains blocked)")
	deniedPortsText := fs.String("deny-ports", "25,465,587", "comma-separated denied destination ports, or none")
	deniedCIDRsText := fs.String("deny-cidrs", "", "additional comma-separated denied destination CIDRs/IPs")
	maxStreams := fs.Int("max-streams", 1024, "maximum incoming streams per QUIC connection (legacy/TLS use a listener-wide bound)")
	maxUniStreams := fs.Int("max-uni-streams", 8, "maximum incoming unidirectional streams per Hysteria QUIC connection")
	maxConnections := fs.Int("max-connections", 256, "global maximum accepted QUIC sessions, including unauthenticated cover traffic")
	maxClientConnections := fs.Int("max-client-connections", 32, "maximum accepted QUIC sessions per source IPv4 or IPv6 /64 across authenticated and cover traffic")
	maxClientFallbackConnections := fs.Int("max-client-fallback-connections", 0, "maximum TLS fallback connections per source IPv4 or IPv6 /64; zero uses min(32, --max-streams)")
	maxOutboundTCP := fs.Int("max-outbound-tcp", 1024, "global maximum active Hysteria exit TCP connections")
	maxOutboundUDP := fs.Int("max-outbound-udp", 256, "global maximum active Hysteria UDP sessions")
	maxClientTCPHandlers := fs.Int("max-client-tcp-handlers", 128, "maximum Hysteria TCP handlers per source IPv4 or IPv6 /64 across QUIC connections")
	maxClientUDPSessions := fs.Int("max-client-udp-sessions", 64, "maximum Hysteria UDP sessions per authenticated source IPv4 or IPv6 /64 across QUIC connections")
	congestion := fs.String("congestion", hy2.CongestionBBR, "QUIC congestion controller: bbr or reno")
	bbrProfile := fs.String("bbr-profile", hy2.BBRStandard, "BBR profile: conservative, standard, or aggressive")
	maxUploadMbps := fs.Uint64("max-upload-mbps", 0, "maximum negotiated Brutal upload target in Mbit/s; zero is automatic BBR")
	maxDownloadMbps := fs.Uint64("max-download-mbps", 0, "maximum negotiated Brutal download target in Mbit/s; zero is automatic BBR")
	allowClientBandwidth := fs.Bool("allow-client-bandwidth", false, "explicitly allow finite client hints to negotiate Brutal (requires both server ceilings)")
	disableLossCompensation := fs.Bool("disable-loss-compensation", false, "disable Brutal ACK/loss-rate compensation")
	disableUDP := fs.Bool("disable-udp", false, "disable QUIC DATAGRAM and SOCKS5 UDP ASSOCIATE")
	udpIdleTimeout := fs.Duration("udp-idle-timeout", 60*time.Second, "idle timeout for each UDP association")
	obfsPasswordFile := fs.String("obfs-password-file", "", "0600 Salamander password file; otherwise optional AUTOCAR_OBFS_PASSWORD")
	masqueradeName := fs.String("masquerade-name", "", "neutral site name returned to unauthenticated HTTP/3 probes")
	dialTimeout := fs.Duration("dial-timeout", 4*time.Second, "remote destination dial timeout")
	handshakeTimeout := fs.Duration("handshake-timeout", 10*time.Second, "authentication and initial stream-open timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *certFile == "" || *keyFile == "" {
		return errors.New("--cert and --key are required")
	}
	if *maxStreams <= 0 {
		return errors.New("--max-streams must be positive")
	}
	if *maxUniStreams < 3 || *maxUniStreams > 1024 {
		return errors.New("--max-uni-streams must be between 3 and 1024")
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
	if *maxOutboundTCP <= 0 || *maxOutboundUDP <= 0 {
		return errors.New("--max-outbound-tcp and --max-outbound-udp must be positive")
	}
	if *maxClientTCPHandlers <= 0 || *maxClientTCPHandlers > *maxOutboundTCP {
		return errors.New("--max-client-tcp-handlers must be positive and no greater than --max-outbound-tcp")
	}
	if *maxClientUDPSessions <= 0 || *maxClientUDPSessions > *maxOutboundUDP {
		return errors.New("--max-client-udp-sessions must be positive and no greater than --max-outbound-udp")
	}
	if *allowClientBandwidth && (*maxUploadMbps == 0 || *maxDownloadMbps == 0) {
		return errors.New("--allow-client-bandwidth requires nonzero --max-upload-mbps and --max-download-mbps")
	}
	if *udpIdleTimeout < 2*time.Second || *udpIdleTimeout > 10*time.Minute {
		return errors.New("--udp-idle-timeout must be between 2s and 10m")
	}
	engine := strings.ToLower(strings.TrimSpace(*quicEngine))
	if engine != "hy2" && engine != "legacy" {
		return errors.New("--quic-engine must be hy2 or legacy")
	}
	if *tcpListen == "" {
		*tcpListen = *listen
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

	type udpRelay interface {
		Addr() net.Addr
		Serve(context.Context) error
		Close() error
	}
	var quicServer udpRelay
	if engine == "legacy" {
		if *obfsPasswordFile != "" || os.Getenv("AUTOCAR_OBFS_PASSWORD") != "" {
			return errors.New("Salamander obfuscation requires --quic-engine=hy2")
		}
		legacyServer, listenErr := tunnel.ListenQUIC(tunnel.QUICServerConfig{
			Address:              *listen,
			Token:                token,
			TLSConfig:            tlsConfig,
			Dialer:               safeDialer,
			HandshakeTimeout:     *handshakeTimeout,
			DialTimeout:          *dialTimeout,
			MaxConcurrentStreams: *maxStreams,
			MaxConnections:       *maxConnections,
		})
		if listenErr != nil {
			return listenErr
		}
		quicServer = legacyServer
	} else {
		maxUpload, conversionErr := megabitsToBytesPerSecond(*maxUploadMbps)
		if conversionErr != nil {
			return fmt.Errorf("--max-upload-mbps: %w", conversionErr)
		}
		maxDownload, conversionErr := megabitsToBytesPerSecond(*maxDownloadMbps)
		if conversionErr != nil {
			return fmt.Errorf("--max-download-mbps: %w", conversionErr)
		}
		obfuscationKey, secretErr := loadOptionalSecret(*obfsPasswordFile, "AUTOCAR_OBFS_PASSWORD", 16)
		if secretErr != nil {
			return fmt.Errorf("load obfuscation password: %w", secretErr)
		}
		acceleratedServer, listenErr := hy2.Listen(hy2.ServerConfig{
			Address:                 *listen,
			Token:                   token,
			TLSConfig:               tlsConfig,
			Dialer:                  safeDialer,
			Congestion:              *congestion,
			BBRProfile:              *bbrProfile,
			MaxTx:                   maxDownload,
			MaxRx:                   maxUpload,
			AllowClientBandwidth:    *allowClientBandwidth,
			DisableLossCompensation: *disableLossCompensation,
			DisableUDP:              *disableUDP,
			ObfuscationKey:          obfuscationKey,
			UDPIdleTimeout:          *udpIdleTimeout,
			DialTimeout:             *dialTimeout,
			MaxConcurrentStreams:    *maxStreams,
			MaxIncomingUniStreams:   *maxUniStreams,
			MaxConnections:          *maxConnections,
			MaxClientConnections:    *maxClientConnections,
			MaxOutboundTCP:          *maxOutboundTCP,
			MaxOutboundUDP:          *maxOutboundUDP,
			MaxClientTCPHandlers:    *maxClientTCPHandlers,
			MaxClientUDPSessions:    *maxClientUDPSessions,
			TCPRequestTimeout:       *handshakeTimeout,
			AuthenticationTimeout:   *handshakeTimeout,
			MasqueradeHandler:       hy2.NewCoverHandler(*masqueradeName),
		})
		if listenErr != nil {
			return listenErr
		}
		quicServer = acceleratedServer
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
	start(engine, quicServer.Addr().String(), quicServer.Serve)
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
	slog.Info("relay stopped", "reason", strings.TrimSpace(context.Cause(ctx).Error()))
	return nil
}
