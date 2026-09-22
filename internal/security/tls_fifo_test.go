//go:build linux || darwin

package security

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestTLSFileLoadersRejectFIFOWithoutBlocking(t *testing.T) {
	if role := os.Getenv("AUTOCAR_TEST_TLS_FIFO_ROLE"); role != "" {
		var err error
		path := os.Getenv("AUTOCAR_TEST_TLS_FIFO_PATH")
		switch role {
		case "CA":
			_, err = LoadCertPool(path)
		case "certificate":
			_, err = LoadKeyPair(path, os.Getenv("AUTOCAR_TEST_TLS_FIFO_KEY"))
		case "private key":
			_, err = LoadKeyPair(os.Getenv("AUTOCAR_TEST_TLS_FIFO_CERT"), path)
		default:
			t.Fatalf("unknown child role %q", role)
		}
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("FIFO was not rejected as a non-regular file: %v", err)
		}
		return
	}

	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "valid.crt"), filepath.Join(dir, "valid.key")
	if err := WriteSelfSignedCertificate(certPath, keyPath, CertificateOptions{Hosts: []string{"relay.invalid"}}); err != nil {
		t.Fatal(err)
	}
	fifoPath := filepath.Join(dir, "unopened.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "fifo.link")
	if err := os.Symlink(fifoPath, linkPath); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"CA", "certificate", "private key"} {
		for _, path := range []string{fifoPath, linkPath} {
			t.Run(role+"/"+filepath.Base(path), func(t *testing.T) {
				// A regressed loader would block before it can inspect the FIFO.
				// Keep it in a deadline-controlled child, never an unkillable test
				// goroutine. No process writes to or streams data through the FIFO.
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTLSFileLoadersRejectFIFOWithoutBlocking$", "-test.count=1")
				command.WaitDelay = time.Second
				command.Env = append(os.Environ(),
					"AUTOCAR_TEST_TLS_FIFO_ROLE="+role,
					"AUTOCAR_TEST_TLS_FIFO_PATH="+path,
					"AUTOCAR_TEST_TLS_FIFO_CERT="+certPath,
					"AUTOCAR_TEST_TLS_FIFO_KEY="+keyPath,
				)
				output, err := command.CombinedOutput()
				if ctx.Err() != nil {
					t.Fatalf("FIFO loader blocked past child deadline: %v", ctx.Err())
				}
				if err != nil {
					t.Fatalf("FIFO loader child failed: %v\n%s", err, output)
				}
			})
		}
	}
}
