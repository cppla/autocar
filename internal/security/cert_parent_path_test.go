package security

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCertificateTemporaryFileUsesActualDestinationParent(t *testing.T) {
	for _, relative := range []bool{false, true} {
		name := "absolute"
		if relative {
			name = "relative"
		}
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			deploy := filepath.Join(base, "deploy")
			site := filepath.Join(base, "site")
			for _, directory := range []string{deploy, filepath.Join(site, "release")} {
				if err := os.MkdirAll(directory, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			link := filepath.Join(deploy, "current")
			if err := os.Symlink(filepath.Join(site, "release"), link); err != nil {
				if runtime.GOOS == "windows" {
					t.Skipf("directory symlink unavailable: %v", err)
				}
				t.Fatal(err)
			}
			parent := link + string(os.PathSeparator) + ".." + string(os.PathSeparator)
			if relative {
				t.Chdir(base)
				parent = "deploy" + string(os.PathSeparator) + "current" + string(os.PathSeparator) + ".." + string(os.PathSeparator)
			}
			certFile, keyFile := parent+"server.crt", parent+"server.key"
			temporary, err := prepareAtomicFile(keyFile, []byte("temporary key fixture"), 0o600)
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(temporary)
			temporaryParent, _ := filepath.Split(temporary)
			wantParent, err := os.Stat(parent)
			if err != nil {
				t.Fatal(err)
			}
			gotParent, err := os.Stat(temporaryParent)
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(wantParent, gotParent) {
				t.Fatal("temporary file was created outside the actual destination parent")
			}
			// This assertion needs only one filesystem, while preventing the
			// cross-device rename failure that misplaced temporary files cause.
			contents, err := os.ReadFile(parent + filepath.Base(temporary))
			if err != nil || string(contents) != "temporary key fixture" {
				t.Fatalf("read temporary file through destination parent: %q, %v", contents, err)
			}
			if err := WriteSelfSignedCertificate(certFile, keyFile, CertificateOptions{Hosts: []string{"relay.example"}}); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadKeyPair(certFile, keyFile); err != nil {
				t.Fatalf("installed certificate and key do not match: %v", err)
			}
		})
	}
}

func TestCertificateTemporaryFileForBareFilenameUsesWorkingDirectory(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	temporary, err := prepareAtomicFile("server.key", []byte("key fixture"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(temporary)
	info, err := os.Stat(temporary)
	if err != nil {
		t.Fatal(err)
	}
	local, err := os.Stat(filepath.Join(directory, filepath.Base(temporary)))
	if err != nil || !os.SameFile(info, local) {
		t.Fatalf("temporary file is not in the working directory: %v", err)
	}
}

func TestCertificateTemporaryFileForDriveRelativeFilename(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows drive-relative filename")
	}
	directory := t.TempDir()
	volume := filepath.VolumeName(directory)
	if len(volume) != 2 || volume[1] != ':' {
		t.Skip("temporary directory does not have a drive-letter volume")
	}
	t.Chdir(directory)
	temporary, err := prepareAtomicFile(volume+"server.key", []byte("key fixture"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(temporary)
	info, err := os.Stat(temporary)
	if err != nil {
		t.Fatal(err)
	}
	local, err := os.Stat(filepath.Join(directory, filepath.Base(temporary)))
	if err != nil || !os.SameFile(info, local) {
		t.Fatalf("temporary file is not in the drive's working directory: %v", err)
	}
	certFile, keyFile := volume+"server.crt", volume+"server.key"
	if err := WriteSelfSignedCertificate(certFile, keyFile, CertificateOptions{Hosts: []string{"relay.example"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyPair(filepath.Join(directory, "server.crt"), filepath.Join(directory, "server.key")); err != nil {
		t.Fatalf("installed certificate and key do not match: %v", err)
	}
}
