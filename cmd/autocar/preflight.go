package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/cppla/autocar/internal/protocol"
)

// Offline checks deliberately do not use LookupPort or Resolve* functions.
// Named services remain supported during normal startup; --check requires
// numeric ports so even host-specific service resolvers cannot perform I/O.
func checkLocalAddress(option, address string, remote bool) (uint16, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil || (remote && host == "") {
		return 0, fmt.Errorf("%s: invalid address; want host:port", option)
	}
	if strings.ContainsAny(host, "\x00\r\n\t /\\@?#") {
		return 0, fmt.Errorf("%s: invalid host syntax", option)
	}
	if strings.Contains(host, ":") {
		if _, err := netip.ParseAddr(host); err != nil {
			return 0, fmt.Errorf("%s: invalid IPv6 address", option)
		}
	}
	if portText == "" || strings.IndexFunc(portText, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, fmt.Errorf("%s: --check requires a numeric port to avoid service-name resolution", option)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || (remote && port == 0) {
		if remote {
			return 0, fmt.Errorf("%s: port must be between 1 and 65535", option)
		}
		return 0, fmt.Errorf("%s: port must be between 0 and 65535", option)
	}
	return uint16(port), nil
}

func checkClientAddresses(flags tunnelFlags, socks, http, https string) error {
	if _, err := checkLocalAddress("--server", flags.server, true); err != nil {
		return err
	}
	if flags.fallback != "" {
		if _, err := checkLocalAddress("--fallback-server", flags.fallback, true); err != nil {
			return err
		}
	}
	for _, endpoint := range []struct{ option, address string }{
		{"--socks", socks}, {"--http", http}, {"--https", https},
	} {
		if endpoint.address != "" {
			if _, err := checkLocalAddress(endpoint.option, endpoint.address, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkServerAddresses(mode, udp, tcp string, disableFallback bool) error {
	udpPort, err := checkLocalAddress("--listen", udp, false)
	if err != nil {
		return err
	}
	if disableFallback {
		return nil
	}
	tcpPort, err := checkLocalAddress("--tcp-listen", tcp, false)
	if err != nil {
		return err
	}
	// ListenWeb uses the fixed port when either side requests an ephemeral
	// port, or binds TCP first when both are zero. No bind is attempted here.
	if mode == "web" && udpPort != 0 && tcpPort != 0 && udpPort != tcpPort {
		return errors.New("web TCP and UDP ports must match")
	}
	return nil
}

// These bounds mirror the transport constructors, which cannot be invoked
// for a server without binding sockets. Use them on both the check and normal
// startup paths, before any listener is prepared.
func validateServerLocalLimits(token string, handshakeTimeout, dialTimeout time.Duration, maxUpload, maxDownload uint64) error {
	if len(token) < protocol.MinTokenLength || len(token) > protocol.MaxTokenLength {
		return fmt.Errorf("tunnel: token length must be between %d and %d bytes", protocol.MinTokenLength, protocol.MaxTokenLength)
	}
	if handshakeTimeout < 0 || dialTimeout < 0 {
		return errors.New("--handshake-timeout and --dial-timeout must not be negative")
	}
	if maxUpload > protocol.MaxRate || maxDownload > protocol.MaxRate {
		return errors.New("tunnel: pacing rate exceeds protocol maximum")
	}
	return nil
}

func reportLocalConfigurationCheck(command string) {
	slog.Info("local configuration check passed", "command", command,
		"scope", "local configuration only; no DNS lookup, network connection, listener binding, or file modification performed",
		"not_verified", "network reachability, remote certificate identity, port availability, or cover upstream health")
}
