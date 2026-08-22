package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateSelfSignedCertificate(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedCertificate(CertificateOptions{
		Hosts:        []string{"Tunnel.Example", "192.0.2.7", "[2001:db8::7]", "tunnel.example"},
		ValidFor:     24 * time.Hour,
		Organization: "autocar test",
	})
	if err != nil {
		t.Fatal(err)
	}
	cert := parseCertificate(t, certPEM)

	if cert.Subject.CommonName != "tunnel.example" {
		t.Fatalf("CommonName = %q", cert.Subject.CommonName)
	}
	if got := cert.Subject.Organization; len(got) != 1 || got[0] != "autocar test" {
		t.Fatalf("Organization = %v", got)
	}
	if got := cert.DNSNames; len(got) != 1 || got[0] != "tunnel.example" {
		t.Fatalf("DNSNames = %v", got)
	}
	if len(cert.IPAddresses) != 2 || !cert.IPAddresses[0].Equal(net.ParseIP("192.0.2.7")) || !cert.IPAddresses[1].Equal(net.ParseIP("2001:db8::7")) {
		t.Fatalf("IPAddresses = %v", cert.IPAddresses)
	}
	if err := cert.VerifyHostname("tunnel.example"); err != nil {
		t.Fatalf("DNS SAN did not verify: %v", err)
	}
	if err := cert.VerifyHostname("192.0.2.7"); err != nil {
		t.Fatalf("IP SAN did not verify: %v", err)
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Fatalf("certificate is not self-signed: %v", err)
	}
	if !cert.NotBefore.Before(time.Now()) || cert.NotAfter.Sub(cert.NotBefore) < 24*time.Hour {
		t.Fatalf("unexpected validity: %s through %s", cert.NotBefore, cert.NotAfter)
	}
	if len(cert.ExtKeyUsage) != 2 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || cert.ExtKeyUsage[1] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("ExtKeyUsage = %v", cert.ExtKeyUsage)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("invalid private key PEM")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaKey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok || ecdsaKey.Curve != elliptic.P256() {
		t.Fatalf("key is %T on unexpected curve", parsedKey)
	}
}

func TestGenerateSelfSignedCertificateDefaults(t *testing.T) {
	certPEM, _, err := GenerateSelfSignedCertificate(CertificateOptions{Hosts: []string{"node.example"}})
	if err != nil {
		t.Fatal(err)
	}
	cert := parseCertificate(t, certPEM)
	remaining := time.Until(cert.NotAfter)
	if remaining < 364*24*time.Hour || remaining > 366*24*time.Hour {
		t.Fatalf("default validity remaining = %s", remaining)
	}
	if got := cert.Subject.Organization; len(got) != 1 || got[0] != "autocar" {
		t.Fatalf("default Organization = %v", got)
	}
}

func TestGenerateSelfSignedCertificateRejectsInvalidOptions(t *testing.T) {
	tests := []struct {
		name string
		opts CertificateOptions
	}{
		{"no SANs", CertificateOptions{}},
		{"empty SAN", CertificateOptions{Hosts: []string{""}}},
		{"bad DNS character", CertificateOptions{Hosts: []string{"bad_name.example"}}},
		{"DNS port", CertificateOptions{Hosts: []string{"example.com:443"}}},
		{"zoned IPv6", CertificateOptions{Hosts: []string{"fe80::1%eth0"}}},
		{"too short", CertificateOptions{Hosts: []string{"a.example"}, ValidFor: time.Minute}},
		{"too long", CertificateOptions{Hosts: []string{"a.example"}, ValidFor: maximumCertificateValidity + time.Hour}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := GenerateSelfSignedCertificate(test.opts); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestWriteSelfSignedCertificateUsesSecurePermissionsAndMatchingPair(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	if err := os.WriteFile(keyFile, []byte("old insecure key"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyFile, 0o666); err != nil {
		t.Fatal(err)
	}

	err := WriteSelfSignedCertificate(certFile, keyFile, CertificateOptions{Hosts: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("private key mode = %o, want 600", got)
	}
	certInfo, err := os.Stat(certFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := certInfo.Mode().Perm(); got != 0o644 {
		t.Fatalf("certificate mode = %o, want 644", got)
	}
	if _, err := LoadKeyPair(certFile, keyFile); err != nil {
		t.Fatalf("written certificate and key do not match: %v", err)
	}
}

func TestWriteSelfSignedCertificateRejectsSamePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "same.pem")
	if err := WriteSelfSignedCertificate(path, path, CertificateOptions{Hosts: []string{"node.example"}}); err == nil {
		t.Fatal("expected same-path error")
	}
}

func parseCertificate(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
