package security

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteSelfSignedCertificateRejectsAliasedPaths(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, aliasKind := range []string{"absolute-relative", "symlink-parent", "case-only"} {
		for _, existing := range []bool{false, true} {
			state := "missing"
			if existing {
				state = "existing"
			}
			t.Run(aliasKind+"/"+state, func(t *testing.T) {
				directory := t.TempDir()
				target := filepath.Join(directory, "shared.pem")
				var alias string
				switch aliasKind {
				case "absolute-relative":
					alias, err = filepath.Rel(workingDirectory, target)
					if err != nil {
						t.Skipf("cannot express temporary target relative to working directory: %v", err)
					}
				case "symlink-parent":
					link := filepath.Join(t.TempDir(), "parent-link")
					if err := os.Symlink(directory, link); err != nil {
						if runtime.GOOS == "windows" {
							t.Skipf("directory symlink unavailable: %v", err)
						}
						t.Fatal(err)
					}
					alias = filepath.Join(link, "shared.pem")
				case "case-only":
					alias = filepath.Join(directory, "SHARED.PEM")
				}
				original := []byte("existing destination must stay unchanged\n")
				if existing {
					if err := os.WriteFile(target, original, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if err := WriteSelfSignedCertificate(target, alias, CertificateOptions{Hosts: []string{"node.example"}}); err == nil {
					t.Error("aliased certificate and private-key destinations were accepted")
				}
				if existing {
					got, err := os.ReadFile(target)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, original) {
						t.Error("existing destination was overwritten")
					}
				} else if _, err := os.Lstat(target); !os.IsNotExist(err) {
					t.Errorf("rejected aliases must not create a destination; stat error: %v", err)
				}
				entries, err := os.ReadDir(directory)
				if err != nil {
					t.Fatal(err)
				}
				wantEntries := 0
				if existing {
					wantEntries = 1
				}
				if len(entries) != wantEntries {
					t.Errorf("rejected aliases left %d directory entries, want %d", len(entries), wantEntries)
				}
			})
		}
	}
}

func TestWriteSelfSignedCertificateAllowsSameBasenameInDifferentDirectories(t *testing.T) {
	certFile := filepath.Join(t.TempDir(), "same.pem")
	keyFile := filepath.Join(t.TempDir(), "same.pem")
	if err := WriteSelfSignedCertificate(certFile, keyFile, CertificateOptions{Hosts: []string{"node.example"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyPair(certFile, keyFile); err != nil {
		t.Fatalf("different destinations must contain a usable certificate and key: %v", err)
	}
}
