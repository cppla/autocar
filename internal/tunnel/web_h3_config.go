package tunnel

import (
	"time"

	"github.com/apernet/quic-go"
)

const (
	// HTTP/3 needs one control stream and two QPACK streams in each direction.
	// AutoCAR doesn't enable server push or WebTransport, so accepting more
	// peer-created unidirectional streams only increases unauthenticated state.
	webH3RequiredIncomingUniStreams int64 = 3

	// Keep one connection's unauthenticated request concurrency at the x/net
	// HTTP/2 server default. The global authenticated stream budget remains a
	// separate, shared H2/H3 limit.
	defaultWebMaxStreamsPerConnection = 250

	webH3MaxIdleTimeout             = 90 * time.Second
	webH3MaxKeepAlivePeriod         = 30 * time.Second
	webH3InitialStreamWindow uint64 = 1 << 20
	webH3MaxStreamWindow     uint64 = 16 << 20
	webH3InitialConnWindow   uint64 = 2 << 20
	webH3MaxConnWindow       uint64 = 64 << 20
)

// hardenedWebH3ServerConfig owns the resource and replay-sensitive QUIC
// policy used by the pre-created listener. In particular, http3.Server fields
// cannot retroactively harden a listener passed to ServeListener.
func hardenedWebH3ServerConfig(input *quic.Config, maxStreams int, handshakeTimeout time.Duration) *quic.Config {
	originalSelector := func(*quic.ClientInfo) (*quic.Config, error) { return nil, nil }
	if input != nil && input.GetConfigForClient != nil {
		originalSelector = input.GetConfigForClient
	}
	configuredSelector := input != nil && input.GetConfigForClient != nil
	cfg := hardenWebH3ServerConfig(input, maxStreams, handshakeTimeout)
	if configuredSelector {
		cfg.GetConfigForClient = func(info *quic.ClientInfo) (*quic.Config, error) {
			selected, err := originalSelector(info)
			if err != nil {
				return nil, err
			}
			// A nil dynamic config means library defaults. Harden those defaults
			// too, rather than letting a callback bypass the listener policy.
			return hardenWebH3ServerConfig(selected, maxStreams, handshakeTimeout), nil
		}
	}
	return cfg
}

func hardenWebH3ServerConfig(input *quic.Config, maxStreams int, handshakeTimeout time.Duration) *quic.Config {
	cfg := cloneQUICConfig(input)
	cfg.GetConfigForClient = nil
	cfg.Allow0RTT = false
	cfg.EnableDatagrams = true
	// ChromeParrot is a client-only wire profile. The public cover server keeps
	// ordinary server behavior even if a caller reuses a client config.
	cfg.ChromeParrot = false
	cfg.HandshakeIdleTimeout = boundedPositiveDuration(cfg.HandshakeIdleTimeout, handshakeTimeout)
	cfg.MaxIdleTimeout = boundedPositiveDuration(cfg.MaxIdleTimeout, webH3MaxIdleTimeout)
	// A server keepalive would retain unauthenticated cover connections.
	cfg.KeepAlivePeriod = 0

	perConnection := min(maxStreams, defaultWebMaxStreamsPerConnection)
	if cfg.MaxIncomingStreams <= 0 || cfg.MaxIncomingStreams > int64(perConnection) {
		cfg.MaxIncomingStreams = int64(perConnection)
	}
	cfg.MaxIncomingUniStreams = webH3RequiredIncomingUniStreams
	hardenWebH3ReceiveWindows(cfg)
	return cfg
}

func hardenedWebH3ClientConfig(input *quic.Config, handshakeTimeout time.Duration, profile H3FingerprintProfile) *quic.Config {
	cfg := cloneQUICConfig(input)
	// HTTP/3 servers don't initiate bidirectional request streams. The three
	// unidirectional streams cover control and QPACK; pushes aren't used.
	cfg.MaxIncomingStreams = -1
	cfg.MaxIncomingUniStreams = webH3RequiredIncomingUniStreams
	cfg.Allow0RTT = false
	cfg.EnableDatagrams = true
	cfg.ChromeParrot = profile == H3FingerprintChrome202608
	cfg.HandshakeIdleTimeout = boundedPositiveDuration(cfg.HandshakeIdleTimeout, handshakeTimeout)
	cfg.MaxIdleTimeout = boundedPositiveDuration(cfg.MaxIdleTimeout, webH3MaxIdleTimeout)
	// A deterministic keepalive interval is a strong long-lived-flow marker.
	// The browser-shaped profile therefore owns this setting and disables it.
	// The native rollback profile preserves an explicit caller value, bounded
	// to avoid retaining dead paths indefinitely.
	if cfg.ChromeParrot {
		// The pinned Chrome transport-parameter image advertises QUIC v1 in its
		// version_information parameter. Keep the packet version and that image
		// coherent even if a caller supplied a v2-only debug configuration.
		cfg.Versions = []quic.Version{quic.Version1}
		cfg.KeepAlivePeriod = 0
	} else if cfg.KeepAlivePeriod > webH3MaxKeepAlivePeriod {
		cfg.KeepAlivePeriod = webH3MaxKeepAlivePeriod
	}
	hardenWebH3ReceiveWindows(cfg)
	return cfg
}

func cloneQUICConfig(input *quic.Config) *quic.Config {
	if input == nil {
		return &quic.Config{}
	}
	return input.Clone()
}

func boundedPositiveDuration(configured, maximum time.Duration) time.Duration {
	if configured <= 0 || configured > maximum {
		return maximum
	}
	return configured
}

func hardenWebH3ReceiveWindows(cfg *quic.Config) {
	cfg.MaxStreamReceiveWindow = boundedQUICWindow(cfg.MaxStreamReceiveWindow, webH3MaxStreamWindow, webH3MaxStreamWindow)
	cfg.InitialStreamReceiveWindow = boundedQUICWindow(cfg.InitialStreamReceiveWindow, webH3InitialStreamWindow, webH3InitialStreamWindow)
	cfg.MaxConnectionReceiveWindow = boundedQUICWindow(cfg.MaxConnectionReceiveWindow, webH3MaxConnWindow, webH3MaxConnWindow)
	cfg.InitialConnectionReceiveWindow = boundedQUICWindow(cfg.InitialConnectionReceiveWindow, webH3InitialConnWindow, webH3InitialConnWindow)
}

func boundedQUICWindow(configured, fallback, maximum uint64) uint64 {
	if configured == 0 {
		configured = fallback
	}
	if configured > maximum {
		return maximum
	}
	return configured
}
