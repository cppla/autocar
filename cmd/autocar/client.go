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
	"github.com/cppla/autocar/internal/proxy"
	"github.com/cppla/autocar/internal/security"
)

type proxyServer interface {
	Serve(net.Listener) error
	Shutdown(context.Context) error
}

func runClient(parent context.Context, args []string) error {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	var tf tunnelFlags
	addTunnelFlags(fs, &tf)
	socksAddress := fs.String("socks", "127.0.0.1:1080", "local SOCKS5 address; empty disables")
	httpAddress := fs.String("http", "127.0.0.1:8080", "local HTTP proxy address; empty disables")
	httpsAddress := fs.String("https", "", "local HTTPS proxy address; empty disables")
	proxyCert := fs.String("proxy-cert", "", "HTTPS proxy listener certificate PEM")
	proxyKey := fs.String("proxy-key", "", "HTTPS proxy listener private key PEM")
	proxyUser := fs.String("proxy-user", os.Getenv("AUTOCAR_PROXY_USER"), "local proxy username")
	proxyPasswordFile := fs.String("proxy-password-file", "", "0600 local proxy password file; otherwise AUTOCAR_PROXY_PASSWORD")
	allowPublicPlaintext := fs.Bool("allow-public-plaintext", false, "allow SOCKS5/HTTP outside loopback despite cleartext local credentials")
	maxConnections := fs.Int("max-connections", 1024, "maximum clients per local proxy listener")
	idleTimeout := fs.Duration("idle-timeout", 5*time.Minute, "local proxy idle timeout")
	shutdownTimeout := fs.Duration("shutdown-timeout", 10*time.Second, "graceful shutdown timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *socksAddress == "" && *httpAddress == "" && *httpsAddress == "" {
		return errors.New("at least one of --socks, --http, or --https must be enabled")
	}
	if *maxConnections <= 0 {
		return errors.New("--max-connections must be positive")
	}
	if (*proxyCert == "") != (*proxyKey == "") {
		return errors.New("--proxy-cert and --proxy-key must be supplied together")
	}
	if *httpsAddress != "" && *proxyCert == "" {
		return errors.New("--https requires --proxy-cert and --proxy-key")
	}

	var authenticator proxy.Authenticator
	if *proxyUser != "" {
		password, err := config.LoadSecret(*proxyPasswordFile, "AUTOCAR_PROXY_PASSWORD")
		if err != nil {
			return err
		}
		if err := validateProxyCredentials(*proxyUser, password, *socksAddress != ""); err != nil {
			return err
		}
		authenticator = proxy.StaticAuthenticator(*proxyUser, password)
	} else if *proxyPasswordFile != "" || os.Getenv("AUTOCAR_PROXY_PASSWORD") != "" {
		return errors.New("proxy password was supplied without --proxy-user")
	}
	authenticated := authenticator != nil
	for _, address := range []string{*socksAddress, *httpAddress, *httpsAddress} {
		if address != "" {
			if err := ensureSafeLocalListener(address, authenticated); err != nil {
				return err
			}
		}
	}
	for _, address := range []string{*socksAddress, *httpAddress} {
		if address != "" {
			if err := ensureProtectedPlaintextListener(address, *allowPublicPlaintext); err != nil {
				return err
			}
		}
	}

	dialer, err := buildTunnelDialer(tf)
	if err != nil {
		return err
	}
	defer dialer.Close()
	proxyConfig := proxy.Config{
		Dialer:           dialer,
		Authenticator:    authenticator,
		HandshakeTimeout: tf.openTimeout,
		DialTimeout:      tf.openTimeout,
		IdleTimeout:      *idleTimeout,
		MaxConnections:   *maxConnections,
	}

	type runningServer struct {
		name     string
		server   proxyServer
		listener net.Listener
	}
	var servers []runningServer
	closePrepared := func() {
		for _, item := range servers {
			_ = item.listener.Close()
		}
	}
	if *socksAddress != "" {
		listener, err := net.Listen("tcp", *socksAddress)
		if err != nil {
			return fmt.Errorf("listen SOCKS5: %w", err)
		}
		server, err := proxy.NewSOCKS5Server(proxyConfig)
		if err != nil {
			listener.Close()
			return err
		}
		servers = append(servers, runningServer{"socks5", server, listener})
	}
	if *httpAddress != "" {
		listener, err := net.Listen("tcp", *httpAddress)
		if err != nil {
			closePrepared()
			return fmt.Errorf("listen HTTP proxy: %w", err)
		}
		server, err := proxy.NewHTTPServer(proxyConfig)
		if err != nil {
			listener.Close()
			closePrepared()
			return err
		}
		servers = append(servers, runningServer{"http", server, listener})
	}
	if *httpsAddress != "" {
		listener, err := net.Listen("tcp", *httpsAddress)
		if err != nil {
			closePrepared()
			return fmt.Errorf("listen HTTPS proxy: %w", err)
		}
		certificate, err := security.LoadKeyPair(*proxyCert, *proxyKey)
		if err != nil {
			listener.Close()
			closePrepared()
			return err
		}
		listener = tls.NewListener(listener, &tls.Config{
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{certificate},
			NextProtos:   []string{"http/1.1"},
		})
		server, err := proxy.NewHTTPServer(proxyConfig)
		if err != nil {
			listener.Close()
			closePrepared()
			return err
		}
		servers = append(servers, runningServer{"https", server, listener})
	}

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	errorsCh := make(chan error, len(servers))
	var wg sync.WaitGroup
	for _, item := range servers {
		item := item
		wg.Add(1)
		go func() {
			defer wg.Done()
			slog.Info("local proxy started", "type", item.name, "address", item.listener.Addr().String(), "transport", strings.ToLower(tf.mode))
			if err := item.server.Serve(item.listener); err != nil && ctx.Err() == nil {
				select {
				case errorsCh <- fmt.Errorf("%s proxy: %w", item.name, err):
				default:
				}
				cancel()
			}
		}()
	}

	<-ctx.Done()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), *shutdownTimeout)
	defer shutdownCancel()
	for _, item := range servers {
		_ = item.server.Shutdown(shutdownCtx)
	}
	wg.Wait()
	select {
	case err := <-errorsCh:
		return err
	default:
	}
	slog.Info("client stopped")
	return nil
}

func validateProxyCredentials(username, password string, socksEnabled bool) error {
	if len(password) < 16 {
		return errors.New("local proxy password must be at least 16 bytes")
	}
	// RFC 1929 encodes both lengths in one byte. HTTP Basic itself allows
	// longer values, so apply this compatibility bound only when SOCKS is on.
	if socksEnabled && (len(username) > 255 || len(password) > 255) {
		return errors.New("SOCKS5 proxy username and password must each be at most 255 bytes")
	}
	return nil
}
