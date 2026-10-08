package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	utls "github.com/refraction-networking/utls"
)

// FingerprintProfile names the TLS ClientHello profile used by the TCP web
// transport. Profile names are deliberately versioned: chrome-133 means the
// fixed Chrome 133 reference shipped by uTLS v1.8.2, not "current Chrome".
type FingerprintProfile string

const (
	// FingerprintChrome133 is the audited Chrome 133 ClientHello reference from
	// uTLS v1.8.2. It is the default for web-cover HTTP/2 connections.
	FingerprintChrome133 FingerprintProfile = "chrome-133"

	// FingerprintNative uses Go's crypto/tls ClientHello. It is retained for
	// tests and protocol debugging, not as an anti-fingerprinting profile.
	FingerprintNative FingerprintProfile = "native"
)

func normalizeFingerprintProfile(profile FingerprintProfile) (FingerprintProfile, error) {
	switch profile {
	case "", FingerprintChrome133:
		return FingerprintChrome133, nil
	case FingerprintNative:
		return FingerprintNative, nil
	default:
		return "", fmt.Errorf("tunnel: unsupported web-cover HTTP/2 fingerprint profile %q; supported profiles are %q and %q", profile, FingerprintChrome133, FingerprintNative)
	}
}

// H3FingerprintProfile names the complete QUIC Initial and TLS ClientHello
// profile used by the UDP web transport. It is separate from FingerprintProfile
// because a browser-shaped QUIC handshake also owns transport parameters,
// connection IDs and Initial packetization, not just TLS extensions.
type H3FingerprintProfile string

const (
	// H3FingerprintChrome202610 is the fixed Chrome QUIC profile provided by
	// the audited github.com/apernet/quic-go revision dated 2026-10-04. The
	// version in the name is immutable; it never means "whatever Chrome does
	// today". It is the default for web-cover HTTP/3 connections.
	H3FingerprintChrome202610 H3FingerprintProfile = "chrome-2026-10"

	// H3FingerprintChrome202608 identifies the retired August 2026 profile.
	// Deprecated: this profile is rejected, not aliased to a different wire
	// image. Explicitly migrate to H3FingerprintChrome202610 or native.
	H3FingerprintChrome202608 H3FingerprintProfile = "chrome-2026-08"

	// H3FingerprintNative uses the QUIC library's ordinary Go handshake. It is
	// retained as an explicit interoperability and rollback profile.
	H3FingerprintNative H3FingerprintProfile = "native"
)

// ErrH3FingerprintProfileRetired reports an explicitly selected historical
// profile whose immutable wire image is no longer provided by the dependency.
var ErrH3FingerprintProfileRetired = errors.New("tunnel: HTTP/3 fingerprint profile chrome-2026-08 is retired; explicitly set --h3-fingerprint=chrome-2026-10 (new handshake profile) or --h3-fingerprint=native (ordinary Go handshake)")

func normalizeH3FingerprintProfile(profile H3FingerprintProfile) (H3FingerprintProfile, error) {
	switch profile {
	case "", H3FingerprintChrome202610:
		return H3FingerprintChrome202610, nil
	case H3FingerprintChrome202608:
		return "", ErrH3FingerprintProfileRetired
	case H3FingerprintNative:
		return H3FingerprintNative, nil
	default:
		return "", fmt.Errorf("tunnel: unsupported web-cover HTTP/3 fingerprint profile %q; supported profiles are %q and %q", profile, H3FingerprintChrome202610, H3FingerprintNative)
	}
}

// webH2TLSClientConn keeps the rest of the HTTP/2 transport independent of
// the TLS implementation while exposing the standard-library state shape used
// by diagnostics and tests.
type webH2TLSClientConn interface {
	net.Conn
	HandshakeContext(context.Context) error
	ConnectionState() tls.ConnectionState
}

var errWebH2PSKHelloRetryRequest = errors.New("tunnel: cached H2 TLS session requires an unsupported HelloRetryRequest")

// This diagnostic is private to the pinned uTLS v1.8.2 implementation. It has
// no exported error type; recognize its exact text AND completed HRR state,
// never arbitrary certificate, entropy or I/O errors with similar text.
const webH2UnsupportedPSKHRR = "uTLS does not support reprocessing of PSK key triggered by HelloRetryRequest"

func webH2UnsupportedPSKHelloRetryRequest(err error, state utls.PubClientHandshakeState) bool {
	if err == nil || err.Error() != webH2UnsupportedPSKHRR || state.Hello == nil || state.ServerHello == nil {
		return false
	}
	hello, server := state.Hello, state.ServerHello
	hrrRandom := [...]byte{ // RFC 8446 section 4.1.3.
		0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
		0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
		0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
		0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
	}
	if server.SupportedVersion != utls.VersionTLS13 || !bytes.Equal(server.Random, hrrRandom[:]) ||
		len(hello.PskIdentities) == 0 || len(hello.PskBinders) != len(hello.PskIdentities) {
		return false
	}
	if server.SelectedGroup != 0 {
		// uTLS reaches the unsupported-PSK diagnostic only after generating
		// and installing the requested share. This excludes an entropy error
		// with the same text during HRR key generation.
		return len(hello.KeyShares) == 1 && hello.KeyShares[0].Group == server.SelectedGroup
	}
	return len(server.Cookie) > 0
}

func newWebH2TLSClientConn(raw net.Conn, config *tls.Config, profile FingerprintProfile, sessionCache utls.ClientSessionCache) (webH2TLSClientConn, error) {
	if raw == nil {
		return nil, errors.New("tunnel: nil web-cover HTTP/2 TCP connection")
	}
	if config == nil {
		return nil, errors.New("tunnel: nil web-cover HTTP/2 TLS config")
	}
	switch profile {
	case FingerprintChrome133:
		utlsConfig, err := chrome133UTLSConfig(config, sessionCache)
		if err != nil {
			return nil, err
		}
		// The fixed cold profile has no pre_shared_key extension. Use a fresh
		// custom copy when resumption is enabled so uTLS can populate its own
		// PSK identity and binder, without changing the empty-cache wire shape.
		resume := utlsConfig.ClientSessionCache != nil && !utlsConfig.SessionTicketsDisabled
		hello := utls.HelloChrome_133
		if resume {
			hello = utls.HelloCustom
		}
		return &webH2UTLSConn{
			UConn:            utls.UClient(raw, utlsConfig, hello),
			prepareChrome133: resume,
		}, nil
	case FingerprintNative:
		return tls.Client(raw, config.Clone()), nil
	default:
		return nil, fmt.Errorf("tunnel: unsupported web-cover HTTP/2 fingerprint profile %q", profile)
	}
}

// chrome133UTLSConfig translates the security-relevant client subset from the
// already hardened crypto/tls configuration. uTLS and crypto/tls intentionally
// use distinct Config and Certificate types, so this conversion stays explicit
// and fail-closed for callbacks that cannot be preserved exactly.
func chrome133UTLSConfig(input *tls.Config, sessionCache utls.ClientSessionCache) (*utls.Config, error) {
	if input == nil {
		return nil, errors.New("tunnel: nil web-cover HTTP/2 TLS config")
	}
	if input.InsecureSkipVerify {
		return nil, errors.New("tunnel: InsecureSkipVerify is forbidden")
	}
	if input.GetClientCertificate != nil {
		return nil, errors.New("tunnel: chrome-133 fingerprint profile does not support dynamic GetClientCertificate; configure static client Certificates or use the native test/debug profile")
	}
	if input.VerifyConnection != nil {
		return nil, errors.New("tunnel: chrome-133 fingerprint profile cannot preserve crypto/tls VerifyConnection exactly; use VerifyPeerCertificate or the native test/debug profile")
	}

	certificates := make([]utls.Certificate, len(input.Certificates))
	for i := range input.Certificates {
		certificates[i] = cloneCertificateForUTLS(input.Certificates[i])
	}
	var roots = input.RootCAs
	if roots != nil {
		roots = roots.Clone()
	}

	return &utls.Config{
		Rand:                        input.Rand,
		Time:                        input.Time,
		Certificates:                certificates,
		VerifyPeerCertificate:       input.VerifyPeerCertificate,
		RootCAs:                     roots,
		ServerName:                  input.ServerName,
		NextProtos:                  []string{webH2ALPN, webHTTP11ALPN},
		InsecureSkipVerify:          false,
		MinVersion:                  utls.VersionTLS13,
		MaxVersion:                  utls.VersionTLS13,
		SessionTicketsDisabled:      input.SessionTicketsDisabled,
		ClientSessionCache:          sessionCache,
		OmitEmptyPsk:                true,
		DynamicRecordSizingDisabled: input.DynamicRecordSizingDisabled,
		KeyLogWriter:                input.KeyLogWriter,
	}, nil
}

// newWebH2UTLSSessionCache mirrors the caller's resumption policy, while
// keeping one uTLS-native cache for the entire WebH2Client lifetime. The
// standard library and uTLS session state types are intentionally distinct,
// so their cache contents cannot be shared safely.
func newWebH2UTLSSessionCache(input *tls.Config) utls.ClientSessionCache {
	if input == nil || input.SessionTicketsDisabled || input.ClientSessionCache == nil {
		return nil
	}
	return utls.NewLRUClientSessionCache(64)
}

func cloneCertificateForUTLS(input tls.Certificate) utls.Certificate {
	chain := make([][]byte, len(input.Certificate))
	for i := range input.Certificate {
		chain[i] = append([]byte(nil), input.Certificate[i]...)
	}
	signatures := make([]utls.SignatureScheme, len(input.SupportedSignatureAlgorithms))
	for i, signature := range input.SupportedSignatureAlgorithms {
		signatures[i] = utls.SignatureScheme(signature)
	}
	scts := make([][]byte, len(input.SignedCertificateTimestamps))
	for i := range input.SignedCertificateTimestamps {
		scts[i] = append([]byte(nil), input.SignedCertificateTimestamps[i]...)
	}
	return utls.Certificate{
		Certificate:                  chain,
		PrivateKey:                   input.PrivateKey,
		SupportedSignatureAlgorithms: signatures,
		OCSPStaple:                   append([]byte(nil), input.OCSPStaple...),
		SignedCertificateTimestamps:  scts,
		Leaf:                         input.Leaf,
	}
}

type webH2UTLSConn struct {
	*utls.UConn
	prepareChrome133  bool
	prepareOnce       sync.Once
	prepareErr        error
	handshakeComplete atomic.Bool
}

// HandshakeContext enforces the application's TLS 1.3-only policy after the
// fixed browser ClientHello is applied. The Chrome 133 wire profile advertises
// its historical TLS 1.2 compatibility; uTLS therefore cannot express the
// stricter application policy in the visible supported_versions extension
// without ceasing to be that profile. Failing before any HTTP bytes are sent
// keeps the policy fail-closed even if a future caller forgets a second check.
func (c *webH2UTLSConn) HandshakeContext(ctx context.Context) error {
	if c.prepareChrome133 {
		if !c.handshakeComplete.Load() {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		c.prepareOnce.Do(func() {
			// ApplyPreset generates entropy and key shares: keep it inside the
			// caller's handshake budget rather than in the connection factory.
			// Each connection owns the extension pointers mutated by uTLS.
			spec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
			if err == nil {
				// TLS 1.3 requires this extension to be last. OmitEmptyPsk
				// suppresses it until a valid cached session is available.
				spec.Extensions = append(spec.Extensions, &utls.UtlsPreSharedKeyExtension{})
				err = c.UConn.ApplyPreset(&spec)
			}
			c.prepareErr = err
		})
		if c.prepareErr != nil {
			return c.prepareErr
		}
		if !c.handshakeComplete.Load() {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
	}
	if err := c.UConn.HandshakeContext(ctx); err != nil {
		if c.prepareChrome133 && err.Error() == webH2UnsupportedPSKHRR && webH2UnsupportedPSKHelloRetryRequest(err, c.UConn.HandshakeState) {
			return fmt.Errorf("%w: %w", errWebH2PSKHelloRetryRequest, err)
		}
		return err
	}
	if c.UConn.ConnectionState().Version != utls.VersionTLS13 {
		return errors.New("tunnel: web-cover HTTP/2 connection did not negotiate TLS 1.3")
	}
	c.handshakeComplete.Store(true)
	return nil
}

// ConnectionState exposes the verification and negotiation fields shared by
// uTLS and crypto/tls. The wrapper is private; callers cannot mistake this
// projection for a crypto/tls connection or use it to export key material.
func (c *webH2UTLSConn) ConnectionState() tls.ConnectionState {
	state := c.UConn.ConnectionState()
	return tls.ConnectionState{
		Version:                     state.Version,
		HandshakeComplete:           state.HandshakeComplete,
		DidResume:                   state.DidResume,
		CipherSuite:                 state.CipherSuite,
		NegotiatedProtocol:          state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  state.NegotiatedProtocolIsMutual,
		ServerName:                  state.ServerName,
		PeerCertificates:            state.PeerCertificates,
		VerifiedChains:              state.VerifiedChains,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse,
		TLSUnique:                   state.TLSUnique,
		ECHAccepted:                 state.ECHAccepted,
	}
}
