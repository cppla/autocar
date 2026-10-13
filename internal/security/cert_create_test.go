package security

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCreateSelfSignedCertificate(t *testing.T) {
	directory := t.TempDir()
	certFile, keyFile := filepath.Join(directory, "server.crt"), filepath.Join(directory, "server.key")
	if err := CreateSelfSignedCertificate(certFile, keyFile, CertificateOptions{Hosts: []string{"relay.example"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyPair(certFile, keyFile); err != nil {
		t.Fatalf("created certificate and key do not match: %v", err)
	}
	if runtime.GOOS != "windows" {
		for path, want := range map[string]os.FileMode{certFile: 0o644, keyFile: 0o600} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != want {
				t.Fatalf("output %s: info=%v, error=%v; want mode %04o", path, info, err, want)
			}
		}
	}
}

func TestCreateSelfSignedCertificatePreservesExistingOutputs(t *testing.T) {
	for _, existing := range []string{"certificate", "key", "both", "certificate directory", "key directory", "certificate symlink", "key symlink"} {
		t.Run(existing, func(t *testing.T) {
			directory := t.TempDir()
			certFile, keyFile := filepath.Join(directory, "server.crt"), filepath.Join(directory, "server.key")
			paths := []string{certFile}
			if existing == "key" || existing == "key directory" || existing == "key symlink" {
				paths = []string{keyFile}
			} else if existing == "both" {
				paths = append(paths, keyFile)
			}
			before := make(map[string]os.FileInfo)
			for _, path := range paths {
				var err error
				switch existing {
				case "certificate directory", "key directory":
					err = os.Mkdir(path, 0o700)
				case "certificate symlink", "key symlink":
					err = os.Symlink("missing-target", path)
					if err != nil && runtime.GOOS == "windows" {
						t.Skipf("symlink unavailable: %v", err)
					}
				default:
					err = os.WriteFile(path, []byte("existing output"), 0o600)
				}
				if err != nil {
					t.Fatal(err)
				}
				before[path], err = os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := CreateSelfSignedCertificate(certFile, keyFile, CertificateOptions{Hosts: []string{"relay.example"}}); !errors.Is(err, os.ErrExist) {
				t.Fatalf("create with existing output: %v, want ErrExist", err)
			}
			for _, path := range []string{certFile, keyFile} {
				after, err := os.Lstat(path)
				if original, exists := before[path]; exists {
					if err != nil || !os.SameFile(original, after) {
						t.Fatalf("existing output was replaced: %s, %v", path, err)
					}
					if original.Mode().IsRegular() {
						contents, err := os.ReadFile(path)
						if err != nil || string(contents) != "existing output" {
							t.Fatalf("existing contents changed: %q, %v", contents, err)
						}
					}
				} else if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("failed operation created another output: %s, %v", path, err)
				}
			}
		})
	}
}

func TestCreateCertificatePairCleansOwnKeyAfterCertificateConflict(t *testing.T) {
	directory := t.TempDir()
	certFile, keyFile := filepath.Join(directory, "server.crt"), filepath.Join(directory, "server.key")
	cert, key, err := GenerateSelfSignedCertificate(CertificateOptions{Hosts: []string{"relay.example"}})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate another process creating the certificate after the public
	// helper's preflight. Publication must still refuse it and clean our key.
	if err := os.WriteFile(certFile, []byte("another process owns this certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := createCertificatePair(certFile, keyFile, cert, key); !errors.Is(err, os.ErrExist) {
		t.Fatalf("certificate conflict: %v, want ErrExist", err)
	}
	contents, err := os.ReadFile(certFile)
	if err != nil || string(contents) != "another process owns this certificate" {
		t.Fatalf("conflicting certificate changed: %q, %v", contents, err)
	}
	if _, err := os.Lstat(keyFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed pair left its private key: %v", err)
	}
}

func TestCertificateCleanupPreservesReplacedOutput(t *testing.T) {
	for _, replacement := range []string{"file", "symlink"} {
		t.Run(replacement, func(t *testing.T) {
			directory := t.TempDir()
			path, moved := filepath.Join(directory, "output"), filepath.Join(directory, "moved")
			created, err := createCertificateFile(path, []byte("owned contents"), 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(path, moved); err != nil {
				t.Fatal(err)
			}
			if replacement == "symlink" {
				if err := os.Symlink(moved, path); err != nil {
					if runtime.GOOS == "windows" {
						t.Skipf("symlink unavailable: %v", err)
					}
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte("someone else's output"), 0o600); err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := removeCreatedCertificateFile(path, created); err != nil {
				t.Fatal(err)
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) {
				t.Fatalf("cleanup removed or replaced someone else's output: %v", err)
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, contents) {
				t.Fatalf("replacement contents changed: %q, %v", got, err)
			}
		})
	}
}

func TestCreateSelfSignedCertificateRejectsAliasedOutputs(t *testing.T) {
	for _, alias := range []string{"same", "case", "relative", "symlink parent"} {
		t.Run(alias, func(t *testing.T) {
			directory := t.TempDir()
			certFile := filepath.Join(directory, "shared.pem")
			keyFile := certFile
			switch alias {
			case "case":
				keyFile = filepath.Join(directory, "SHARED.PEM")
			case "relative":
				t.Chdir(directory)
				keyFile = "shared.pem"
			case "symlink parent":
				link := filepath.Join(t.TempDir(), "parent")
				if err := os.Symlink(directory, link); err != nil {
					if runtime.GOOS == "windows" {
						t.Skipf("symlink unavailable: %v", err)
					}
					t.Fatal(err)
				}
				keyFile = filepath.Join(link, "shared.pem")
			}
			if err := CreateSelfSignedCertificate(certFile, keyFile, CertificateOptions{Hosts: []string{"relay.example"}}); err == nil {
				t.Fatal("aliased output paths were accepted")
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 0 {
				t.Fatalf("rejected paths left output files: %v, %v", entries, err)
			}
		})
	}
}

func TestCreateSelfSignedCertificateWindowsDriveRelativePaths(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows drive-relative paths")
	}
	directory := t.TempDir()
	volume := filepath.VolumeName(directory)
	if len(volume) != 2 || volume[1] != ':' {
		t.Skip("temporary directory does not have a drive-letter volume")
	}
	t.Chdir(directory)
	if err := CreateSelfSignedCertificate(volume+"server.crt", volume+"server.key", CertificateOptions{Hosts: []string{"relay.example"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyPair(filepath.Join(directory, "server.crt"), filepath.Join(directory, "server.key")); err != nil {
		t.Fatal(err)
	}
}
