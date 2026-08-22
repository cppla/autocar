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
	maxStreams := fs.Int("max-streams", 1024, "maximum concurrent streams per transport listener")
	maxConnections := fs.Int("max-connections", 256, "maximum accepted QUIC connections")
	dialTimeout := fs.Duration("dial-timeout", 4*time.Second, "remote destination dial timeout")
	handshakeTimeout := fs.Duration("handshake-timeout", 10*time.Second, "per-stream authentication/open timeout")
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

	quicServer, err := tunnel.ListenQUIC(tunnel.QUICServerConfig{
		Address:              *listen,
		Token:                token,
		TLSConfig:            tlsConfig,
		Dialer:               safeDialer,
		HandshakeTimeout:     *handshakeTimeout,
		DialTimeout:          *dialTimeout,
		MaxConcurrentStreams: *maxStreams,
		MaxConnections:       *maxConnections,
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
