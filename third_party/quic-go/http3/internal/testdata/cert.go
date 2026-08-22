package testdata

import (
	"crypto/tls"
	"crypto/x509"

	quictestdata "github.com/apernet/quic-go/internal/testdata"
)

// GetCertificatePaths returns the paths to certificate and key
func GetCertificatePaths() (string, string) {
	return quictestdata.GetCertificatePaths()
}

// GetTLSConfig returns a TLS config for localhost.
func GetTLSConfig() *tls.Config {
	return quictestdata.GetTLSConfig()
}

// AddRootCA adds the root CA certificate to a cert pool
func AddRootCA(certPool *x509.CertPool) {
	quictestdata.AddRootCA(certPool)
}

// GetRootCA returns an x509.CertPool containing (only) the CA certificate
func GetRootCA() *x509.CertPool {
	return quictestdata.GetRootCA()
}
