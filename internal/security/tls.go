// Package security contains the secure-by-default TLS, authentication, and
// outbound dialing primitives used by autocar.
package security

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

// ALPN is the protocol identifier negotiated by every autocar TLS session.
const ALPN = "autocar/2"

const maxTLSMaterialSize = 4 << 20

// ClientTLSOptions configures a TLS client. A server name and an explicit
// trust store are deliberately mandatory: autocar never silently falls back
// to an insecure verifier or to an ambient, host-dependent trust policy.
type ClientTLSOptions struct {
	// ServerName is verified against the certificate's DNS or IP SAN.
	ServerName string

	// CAPEM contains one or more PEM-encoded trust anchors. It is appended to
	// RootCAs when both are supplied.
	CAPEM []byte
	// RootCAs is an optional explicit trust store. The pool is cloned before
	// use, so later callers cannot mutate the returned TLS configuration by
	// changing this pool.
	RootCAs *x509.CertPool

	// Certificates contains optional client certificates for mTLS.
	Certificates []tls.Certificate
}

// NewClientTLSConfig builds a TLS 1.3-only client configuration that performs
// normal certificate-chain and hostname verification. InsecureSkipVerify is
// intentionally not exposed as an option.
func NewClientTLSConfig(opts ClientTLSOptions) (*tls.Config, error) {
	serverName := normalizeServerName(opts.ServerName)
	if serverName == "" {
		return nil, errors.New("security: TLS server name is required")
	}
	if strings.ContainsAny(serverName, "\x00\r\n") {
		return nil, errors.New("security: TLS server name contains invalid characters")
	}

	roots, err := explicitCertPool(opts.RootCAs, opts.CAPEM)
	if err != nil {
		return nil, fmt.Errorf("security: client trust store: %w", err)
	}
	if roots == nil {
		return nil, errors.New("security: an explicit CA is required")
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		ServerName:   serverName,
		RootCAs:      roots,
		Certificates: cloneCertificates(opts.Certificates),
		NextProtos:   []string{ALPN},
		// The TCP fallback creates one TLS connection per proxied flow. Session
		// resumption amortizes certificate/signature work while still performing
		// a normal TLS 1.3 handshake; AutoCAR never sends application 0-RTT data.
		ClientSessionCache: tls.NewLRUClientSessionCache(64),
		InsecureSkipVerify: false,
	}, nil
}

// ServerTLSOptions configures a TLS server. Supplying ClientCAPEM or ClientCAs
// enables mTLS and requires every peer to present a certificate chaining to
// that explicit client CA set.
type ServerTLSOptions struct {
	Certificates []tls.Certificate

	ClientCAPEM []byte
	ClientCAs   *x509.CertPool
}

// NewServerTLSConfig builds a TLS 1.3-only server configuration. When a client
// CA is supplied it enables strict mutual TLS (RequireAndVerifyClientCert).
func NewServerTLSConfig(opts ServerTLSOptions) (*tls.Config, error) {
	if len(opts.Certificates) == 0 {
		return nil, errors.New("security: at least one server certificate is required")
	}

	clientCAs, err := optionalCertPool(opts.ClientCAs, opts.ClientCAPEM)
	if err != nil {
		return nil, fmt.Errorf("security: client trust store: %w", err)
	}

	clientAuth := tls.NoClientCert
	if clientCAs != nil {
		clientAuth = tls.RequireAndVerifyClientCert
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: cloneCertificates(opts.Certificates),
		NextProtos:   []string{ALPN},
		ClientAuth:   clientAuth,
		ClientCAs:    clientCAs,
	}, nil
}

// CertPoolFromPEM parses one or more PEM certificates into a new trust store.
func CertPoolFromPEM(caPEM []byte) (*x509.CertPool, error) {
	if len(caPEM) == 0 {
		return nil, errors.New("empty CA PEM")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("PEM contains no valid certificates")
	}
	return pool, nil
}

// LoadCertPool reads PEM trust anchors from path.
func LoadCertPool(path string) (*x509.CertPool, error) {
	caPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	pool, err := CertPoolFromPEM(caPEM)
	if err != nil {
		return nil, fmt.Errorf("parse CA file: %w", err)
	}
	return pool, nil
}

// LoadKeyPair loads a PEM certificate and private key suitable for the TLS
// option types in this package.
func LoadKeyPair(certFile, keyFile string) (tls.Certificate, error) {
	key, err := os.Open(keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("open TLS private key: %w", err)
	}
	defer key.Close()
	info, err := key.Stat()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("stat TLS private key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return tls.Certificate{}, errors.New("security: TLS private key is not a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		return tls.Certificate{}, fmt.Errorf("security: TLS private key %q permissions are %04o; want 0600", keyFile, info.Mode().Perm())
	}
	if info.Size() > maxTLSMaterialSize {
		return tls.Certificate{}, fmt.Errorf("security: TLS private key exceeds %d bytes", maxTLSMaterialSize)
	}
	keyPEM, err := io.ReadAll(io.LimitReader(key, maxTLSMaterialSize+1))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read TLS private key: %w", err)
	}
	if len(keyPEM) > maxTLSMaterialSize {
		return tls.Certificate{}, fmt.Errorf("security: TLS private key exceeds %d bytes", maxTLSMaterialSize)
	}
	certFileHandle, err := os.Open(certFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("open TLS certificate: %w", err)
	}
	defer certFileHandle.Close()
	certInfo, err := certFileHandle.Stat()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("stat TLS certificate: %w", err)
	}
	if !certInfo.Mode().IsRegular() {
		return tls.Certificate{}, errors.New("security: TLS certificate is not a regular file")
	}
	if certInfo.Size() > maxTLSMaterialSize {
		return tls.Certificate{}, fmt.Errorf("security: TLS certificate exceeds %d bytes", maxTLSMaterialSize)
	}
	certPEM, err := io.ReadAll(io.LimitReader(certFileHandle, maxTLSMaterialSize+1))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read TLS certificate: %w", err)
	}
	if len(certPEM) > maxTLSMaterialSize {
		return tls.Certificate{}, fmt.Errorf("security: TLS certificate exceeds %d bytes", maxTLSMaterialSize)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load TLS key pair: %w", err)
	}
	return cert, nil
}

func explicitCertPool(base *x509.CertPool, caPEM []byte) (*x509.CertPool, error) {
	if base == nil && len(caPEM) == 0 {
		return nil, nil
	}
	return optionalCertPool(base, caPEM)
}

func optionalCertPool(base *x509.CertPool, caPEM []byte) (*x509.CertPool, error) {
	var pool *x509.CertPool
	if base != nil {
		pool = base.Clone()
	}
	if len(caPEM) != 0 {
		if pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("PEM contains no valid certificates")
		}
	}
	return pool, nil
}

func cloneCertificates(in []tls.Certificate) []tls.Certificate {
	if len(in) == 0 {
		return nil
	}
	return append([]tls.Certificate(nil), in...)
}

func normalizeServerName(name string) string {
	name = strings.TrimSpace(name)
	if strings.HasPrefix(name, "[") && strings.HasSuffix(name, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(name, "["), "]")
	}
	return name
}
