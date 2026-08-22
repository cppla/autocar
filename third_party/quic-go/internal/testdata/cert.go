package testdata

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	certificateOnce sync.Once
	certificatePath string
	privateKeyPath  string
	rootCAPEM       []byte
	certificateErr  error
)

// GetCertificatePaths returns the paths to certificate and key
func GetCertificatePaths() (string, string) {
	ensureCertificate()
	return certificatePath, privateKeyPath
}

// GetTLSConfig returns a TLS config for localhost.
func GetTLSConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair(GetCertificatePaths())
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}
}

// AddRootCA adds the root CA certificate to a cert pool
func AddRootCA(certPool *x509.CertPool) {
	ensureCertificate()
	if ok := certPool.AppendCertsFromPEM(rootCAPEM); !ok {
		panic("could not add root certificate to pool")
	}
}

// GetRootCA returns an x509.CertPool containing (only) the CA certificate
func GetRootCA() *x509.CertPool {
	pool := x509.NewCertPool()
	AddRootCA(pool)
	return pool
}

func ensureCertificate() {
	certificateOnce.Do(generateCertificate)
	if certificateErr != nil {
		panic(certificateErr)
	}
}

func generateCertificate() {
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		certificateErr = fmt.Errorf("generate test CA key: %w", err)
		return
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{Organization: []string{"quic-go test CA"}},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		certificateErr = fmt.Errorf("create test CA certificate: %w", err)
		return
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		certificateErr = fmt.Errorf("generate test leaf key: %w", err)
		return
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{Organization: []string{"quic-go test server"}},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		certificateErr = fmt.Errorf("create test leaf certificate: %w", err)
		return
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		certificateErr = fmt.Errorf("marshal test leaf key: %w", err)
		return
	}
	rootCAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	leafPEM = append(leafPEM, rootCAPEM...)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tempDir, err := os.MkdirTemp("", "quic-go-test-cert-")
	if err != nil {
		certificateErr = fmt.Errorf("create test certificate directory: %w", err)
		return
	}
	certificatePath = filepath.Join(tempDir, "cert.pem")
	privateKeyPath = filepath.Join(tempDir, "priv.key")
	if err := os.WriteFile(certificatePath, leafPEM, 0o600); err != nil {
		certificateErr = fmt.Errorf("write test certificate: %w", err)
		return
	}
	if err := os.WriteFile(privateKeyPath, keyPEM, 0o600); err != nil {
		certificateErr = fmt.Errorf("write test private key: %w", err)
	}
}

func randomSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		panic(fmt.Errorf("generate test certificate serial: %w", err))
	}
	return serial
}
