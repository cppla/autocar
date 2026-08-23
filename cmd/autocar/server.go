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

	"github.com/cppla/autocar/internal/accel"
	"github.com/cppla/autocar/internal/config"
	"github.com/cppla/autocar/internal/security"
	"github.com/cppla/autocar/internal/tunnel"
)

func runServer(parent context.Context, args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	listen := fs.String("listen", ":443", "QUIC UDP listen address")
	tcpListen := fs.String("tcp-listen", "", "TLS/TCP fallback address; defaults to --listen")
	disableFallback := fs.Bool("disable-tcp-fallback", false, "disable the TCP/TLS fallback listener")
	certFile := fs.String("cert", "", "server certificate PEM (required)")
	keyFile := fs.String("key", "", "server private key PEM (required)")
	clientCAFile := fs.String("client-ca", "", "optional PEM CA that enables mandatory mTLS")
	tokenFile := fs.String("token-file", "", "0600 shared-token file; otherwise AUTOCAR_TOKEN")
	allowPrivate := fs.Bool("allow-private", false, "allow RFC1918/ULA/CGNAT destinations (loopback remains blocked)")
	deniedPortsText := fs.String("deny-ports", "25,465,587", "comma-separated denied destination ports, or none")
	deniedCIDRsText := fs.String("deny-cidrs", "", "additional comma-separated denied destination CIDRs/IPs")
	maxStreams := fs.Int("max-streams", 1024, "maximum active tunnel streams")
	maxConnections := fs.Int("max-connections", 256, "global maximum accepted QUIC sessions")
	maxClientConnections := fs.Int("max-client-connections", 32, "maximum QUIC sessions per source IPv4 or IPv6 /64")
	maxClientFallbackConnections := fs.Int("max-client-fallback-connections", 0, "maximum TLS fallback connections per source IPv4 or IPv6 /64; zero uses min(32, --max-streams)")
	pacingText := fs.String("pacing", "adaptive", "application pacing: adaptive, reno, or fixed-rate")
	pacingProfileText := fs.String("pacing-profile", "balanced", "adaptive pacing profile: conservative, balanced, or aggressive")
	maxUploadMbps := fs.Uint64("max-upload-mbps", 0, "maximum client-to-relay fixed pacing rate in Mbit/s")
	maxDownloadMbps := fs.Uint64("max-download-mbps", 0, "maximum relay-to-client fixed pacing rate in Mbit/s")
	allowClientRates := fs.Bool("allow-client-rates", false, "allow authenticated clients to request fixed rates within both server maxima")
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
	if *maxConnections <= 0 {
		return errors.New("--max-connections must be positive")
	}
	if *maxClientConnections <= 0 || *maxClientConnections > *maxConnections {
		return errors.New("--max-client-connections must be positive and no greater than --max-connections")
	}
	if !*disableFallback && (*maxClientFallbackConnections < 0 || *maxClientFallbackConnections > *maxStreams) {
		return errors.New("--max-client-fallback-connections must be zero or positive and no greater than --max-streams")
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

	quicServer, err := tunnel.ListenQUIC(tunnel.QUICServerConfig{
		Address:              *listen,
		Token:                token,
		TLSConfig:            tlsConfig,
		Dialer:               safeDialer,
		Pacing:               pacing,
		MaxTx:                maxDownload,
		MaxRx:                maxUpload,
		AllowClientRates:     *allowClientRates,
		HandshakeTimeout:     *handshakeTimeout,
		DialTimeout:          *dialTimeout,
		MaxConcurrentStreams: *maxStreams,
		MaxConnections:       *maxConnections,
		MaxClientConnections: *maxClientConnections,
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
	slog.Info("relay stopped", "reason", strings.TrimSpace(context.Cause(ctx).Error()))
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
