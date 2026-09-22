package security

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestTLSFileLoadersEnforceSizeAndTypeBounds(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedCertificate(CertificateOptions{Hosts: []string{"relay.invalid"}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "valid.crt"), filepath.Join(dir, "valid.key")
	for path, contents := range map[string][]byte{certPath: certPEM, keyPath: keyPEM} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct {
		name     string
		contents []byte
		load     func(string) error
	}{
		{"CA", certPEM, func(path string) error { _, err := LoadCertPool(path); return err }},
		{"certificate", certPEM, func(path string) error { _, err := LoadKeyPair(path, keyPath); return err }},
		{"private key", keyPEM, func(path string) error { _, err := LoadKeyPair(certPath, path); return err }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.load(t.TempDir()); err == nil || !strings.Contains(err.Error(), "regular file") {
				t.Fatalf("directory accepted: %v", err)
			}
			missing := filepath.Join(t.TempDir(), "missing")
			if err := test.load(missing); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("missing file lost its error category: %v", err)
			}
			for _, size := range []int{maxTLSMaterialSize, maxTLSMaterialSize + 1} {
				path := filepath.Join(t.TempDir(), "bounded.pem")
				contents := bytes.Repeat([]byte(" "), size)
				copy(contents, test.contents)
				if err := os.WriteFile(path, contents, 0o600); err != nil {
					t.Fatal(err)
				}
				err := test.load(path)
				if size == maxTLSMaterialSize {
					if err != nil {
						t.Fatalf("valid material exactly at limit rejected: %v", err)
					}
				} else if err == nil || !strings.Contains(err.Error(), "exceeds") {
					t.Fatalf("oversized material accepted: %v", err)
				}
			}
		})
	}
}

func TestLoadCertPoolRejectsEmptyAndMalformedFiles(t *testing.T) {
	for _, contents := range []string{"", "not a PEM certificate"} {
		path := filepath.Join(t.TempDir(), "ca.pem")
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCertPool(path); err == nil || !strings.Contains(err.Error(), "parse CA file") {
			t.Fatalf("bad CA file lost its parse error: %v", err)
		}
	}
}

func TestTLSFileLoadersPreservePublicAndPrivatePermissions(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedCertificate(CertificateOptions{Hosts: []string{"relay.invalid"}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "public.crt"), filepath.Join(dir, "private.key")
	if err := os.WriteFile(certPath, append(append([]byte(nil), certPEM...), certPEM...), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCertPool(certPath); err != nil {
		t.Fatalf("publicly readable CA bundle rejected: %v", err)
	}
	if _, err := LoadKeyPair(certPath, keyPath); err != nil {
		t.Fatalf("public certificate/private key rejected: %v", err)
	}
	if runtime.GOOS == "windows" {
		return // Windows deployments use ACLs, not Unix permission bits.
	}
	for _, mode := range []os.FileMode{0o644, 0o400} {
		if err := os.Chmod(keyPath, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadKeyPair(certPath, keyPath); err == nil || !strings.Contains(err.Error(), "permissions") {
			t.Fatalf("private key mode %04o changed existing 0600-only policy: %v", mode, err)
		}
	}
}

func TestTLSFileLoadersAllowRegularFileSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks can require Windows privileges")
	}
	certPEM, keyPEM, err := GenerateSelfSignedCertificate(CertificateOptions{Hosts: []string{"relay.invalid"}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, contents := range map[string][]byte{"cert.pem": certPEM, "key.pem": keyPEM} {
		if err := os.WriteFile(filepath.Join(dir, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(name, filepath.Join(dir, name+".link")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadCertPool(filepath.Join(dir, "cert.pem.link")); err != nil {
		t.Fatalf("symlink to regular CA rejected: %v", err)
	}
	if _, err := LoadKeyPair(filepath.Join(dir, "cert.pem.link"), filepath.Join(dir, "key.pem.link")); err != nil {
		t.Fatalf("symlinks to regular key pair rejected: %v", err)
	}
}
