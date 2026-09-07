package tunnel

import (
	"crypto/tls"
	"errors"
)

func webClientTLSConfig(input *tls.Config, address string, protocols ...string) (*tls.Config, error) {
	if len(protocols) == 0 {
		return nil, errors.New("tunnel: web-cover client requires an HTTP ALPN")
	}
	cfg, err := clientTLSConfig(input, address)
	if err != nil {
		return nil, err
	}
	cfg.NextProtos = append([]string(nil), protocols...)
	return cfg, nil
}

func webServerTLSConfig(input *tls.Config, protocols ...string) (*tls.Config, error) {
	if len(protocols) == 0 {
		return nil, errors.New("tunnel: web-cover server requires an HTTP ALPN")
	}
	// serverTLSConfig intentionally treats GetConfigForClient only as a
	// certificate selector and discards every other field from its result. Wrap
	// the caller's selector before that hardening layer so an attempted dynamic
	// mTLS policy is rejected explicitly instead of being silently ignored.
	prepared := input
	if input != nil && input.GetConfigForClient != nil {
		prepared = input.Clone()
		selector := input.GetConfigForClient
		prepared.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			selected, err := selector(hello)
			if err != nil || selected == nil {
				return selected, err
			}
			if selected.ClientAuth != tls.NoClientCert || selected.ClientCAs != nil {
				return nil, errors.New("tunnel: web-cover certificate selector enabled TLS client authentication")
			}
			return selected, nil
		}
	}
	cfg, err := serverTLSConfig(prepared)
	if err != nil {
		return nil, err
	}
	// The public origin accepts the ordinary HTTPS compatibility floor used by
	// browsers and active website probes. Authenticated tunnel requests remain
	// TLS 1.3-only in webTunnelHandler; TLS 1.2 requests are always cover traffic.
	cfg.MinVersion = tls.VersionTLS12
	cfg.MaxVersion = tls.VersionTLS13
	if cfg.ClientAuth != tls.NoClientCert || cfg.ClientCAs != nil {
		return nil, errors.New("tunnel: web-cover cannot require a TLS client certificate")
	}
	webProtocols := append([]string(nil), protocols...)
	cfg.NextProtos = webProtocols
	// serverTLSConfig deliberately owns protocol policy in its certificate
	// callback. Reassert the web ALPN after that callback so a dynamic
	// certificate selector cannot silently restore the native autocar/2 ALPN or
	// enable mTLS for an otherwise public cover origin.
	selector := cfg.GetConfigForClient
	if selector != nil {
		cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			selected, err := selector(hello)
			if err != nil || selected == nil {
				return selected, err
			}
			selected = selected.Clone()
			if selected.ClientAuth != tls.NoClientCert || selected.ClientCAs != nil {
				return nil, errors.New("tunnel: web-cover certificate selector enabled TLS client authentication")
			}
			selected.NextProtos = append([]string(nil), webProtocols...)
			selected.MinVersion = tls.VersionTLS12
			selected.MaxVersion = tls.VersionTLS13
			return selected, nil
		}
	}
	return cfg, nil
}
