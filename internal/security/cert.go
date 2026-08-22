package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultCertificateValidity = 365 * 24 * time.Hour
	maximumCertificateValidity = 5 * 365 * 24 * time.Hour
)

// CertificateOptions controls self-signed ECDSA certificate generation.
type CertificateOptions struct {
	// Hosts is the complete set of DNS names and IP addresses placed in the
	// certificate SAN extension. At least one host is required.
	Hosts []string

	// ValidFor defaults to one year and may not exceed five years.
	ValidFor time.Duration

	// CommonName defaults to the first SAN. Verification still uses SANs.
	CommonName string
	// Organization defaults to "autocar".
	Organization string
}

// GenerateSelfSignedCertificate creates an ECDSA P-256 key and a self-signed
// certificate usable for both server and client authentication. Private key
// bytes are PKCS#8 PEM; callers persisting them themselves must use mode 0600.
func GenerateSelfSignedCertificate(opts CertificateOptions) (certPEM, keyPEM []byte, err error) {
	dnsNames, ipAddresses, normalizedHosts, err := parseCertificateHosts(opts.Hosts)
	if err != nil {
		return nil, nil, err
	}

	validFor := opts.ValidFor
	if validFor == 0 {
		validFor = defaultCertificateValidity
	}
	if validFor < time.Hour || validFor > maximumCertificateValidity {
		return nil, nil, fmt.Errorf("security: certificate validity must be between 1 hour and %s", maximumCertificateValidity)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("security: generate ECDSA key: %w", err)
	}

	serialBytes := make([]byte, 16)
	if _, err := rand.Read(serialBytes); err != nil {
		return nil, nil, fmt.Errorf("security: generate certificate serial: %w", err)
	}
	serial := new(big.Int).SetBytes(serialBytes)
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}

	commonName := strings.TrimSpace(opts.CommonName)
	if commonName == "" {
		commonName = normalizedHosts[0]
	}
	organization := strings.TrimSpace(opts.Organization)
	if organization == "" {
		organization = "autocar"
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("security: marshal public key: %w", err)
	}
	subjectKeyID := sha256.Sum256(publicKeyDER)

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{organization},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
		SubjectKeyId:          append([]byte(nil), subjectKeyID[:20]...),
		AuthorityKeyId:        append([]byte(nil), subjectKeyID[:20]...),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("security: create certificate: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("security: marshal private key: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	return certPEM, keyPEM, nil
}

// WriteSelfSignedCertificate generates and atomically writes a certificate and
// private key. The key is always installed with mode 0600, even when replacing
// a pre-existing file; the certificate is installed with mode 0644.
func WriteSelfSignedCertificate(certFile, keyFile string, opts CertificateOptions) error {
	if strings.TrimSpace(certFile) == "" || strings.TrimSpace(keyFile) == "" {
		return errors.New("security: certificate and key paths are required")
	}
	if filepath.Clean(certFile) == filepath.Clean(keyFile) {
		return errors.New("security: certificate and key paths must be different")
	}

	certPEM, keyPEM, err := GenerateSelfSignedCertificate(opts)
	if err != nil {
		return err
	}

	// Write both temporary files before replacing either destination. Install
	// the private key first so a failure can never leave a new certificate
	// pointing at an old, unrelated key.
	keyTemp, err := prepareAtomicFile(keyFile, keyPEM, 0o600)
	if err != nil {
		return fmt.Errorf("security: prepare private key: %w", err)
	}
	defer os.Remove(keyTemp)
	certTemp, err := prepareAtomicFile(certFile, certPEM, 0o644)
	if err != nil {
		return fmt.Errorf("security: prepare certificate: %w", err)
	}
	defer os.Remove(certTemp)

	if err := os.Rename(keyTemp, keyFile); err != nil {
		return fmt.Errorf("security: install private key: %w", err)
	}
	if err := os.Chmod(keyFile, 0o600); err != nil {
		return fmt.Errorf("security: secure private key permissions: %w", err)
	}
	if err := os.Rename(certTemp, certFile); err != nil {
		return fmt.Errorf("security: install certificate: %w", err)
	}
	return nil
}

func prepareAtomicFile(destination string, data []byte, mode os.FileMode) (path string, err error) {
	dir := filepath.Dir(destination)
	base := filepath.Base(destination)
	f, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return "", err
	}
	path = f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(path)
		}
	}()

	if err := f.Chmod(mode); err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	ok = true
	return path, nil
}

func parseCertificateHosts(hosts []string) (dnsNames []string, ipAddresses []net.IP, normalized []string, err error) {
	if len(hosts) == 0 {
		return nil, nil, nil, errors.New("security: at least one certificate SAN is required")
	}

	seen := make(map[string]struct{}, len(hosts))
	for _, rawHost := range hosts {
		host := normalizeServerName(rawHost)
		if host == "" {
			return nil, nil, nil, errors.New("security: certificate SAN cannot be empty")
		}
		if strings.ContainsAny(host, "\x00\r\n") {
			return nil, nil, nil, fmt.Errorf("security: invalid certificate SAN %q", rawHost)
		}

		if addr, parseErr := netip.ParseAddr(host); parseErr == nil {
			if addr.Zone() != "" {
				return nil, nil, nil, fmt.Errorf("security: certificate IP SAN cannot contain a zone: %q", rawHost)
			}
			addr = addr.Unmap()
			key := "ip:" + addr.String()
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			ipAddresses = append(ipAddresses, net.IP(addr.AsSlice()))
			normalized = append(normalized, addr.String())
			continue
		}

		if err := validateDNSName(host); err != nil {
			return nil, nil, nil, fmt.Errorf("security: invalid DNS SAN %q: %w", rawHost, err)
		}
		canonical := strings.ToLower(strings.TrimSuffix(host, "."))
		key := "dns:" + canonical
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		dnsNames = append(dnsNames, canonical)
		normalized = append(normalized, canonical)
	}
	if len(normalized) == 0 {
		return nil, nil, nil, errors.New("security: at least one certificate SAN is required")
	}
	return dnsNames, ipAddresses, normalized, nil
}

func validateDNSName(name string) error {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return errors.New("DNS name is empty or too long")
	}
	labels := strings.Split(name, ".")
	for i, label := range labels {
		if label == "*" && i == 0 {
			continue
		}
		if label == "" || len(label) > 63 {
			return errors.New("DNS label is empty or too long")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("DNS label starts or ends with a hyphen")
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return fmt.Errorf("unsupported DNS character %q", r)
		}
	}
	return nil
}
