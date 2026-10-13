package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestCertConcurrentProcesses(t *testing.T) {
	for _, scenario := range []string{"same pair", "relative paths", "shared certificate"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			const processes = 4
			type child struct {
				command *exec.Cmd
				input   io.WriteCloser
				output  *bufio.Reader
				stderr  bytes.Buffer
				key     string
			}
			children := make([]child, processes)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			for index := range children {
				current := &children[index]
				certFile, keyFile := filepath.Join(directory, "server.crt"), filepath.Join(directory, "server.key")
				if scenario == "shared certificate" {
					keyFile = filepath.Join(directory, fmt.Sprintf("server-%d.key", index))
				}
				current.key = keyFile
				if scenario == "relative paths" {
					certFile, keyFile = filepath.Base(certFile), filepath.Base(keyFile)
				}
				command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCertConcurrentProcessHelper$")
				command.Dir = directory
				command.Env = append(os.Environ(),
					"AUTOCAR_CERT_TEST_CHILD=1", "AUTOCAR_CERT_TEST_CERT="+certFile, "AUTOCAR_CERT_TEST_KEY="+keyFile)
				command.Stderr = &current.stderr
				current.command = command
				var err error
				current.input, err = command.StdinPipe()
				if err != nil {
					t.Fatal(err)
				}
				output, err := command.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				current.output = bufio.NewReader(output)
				if err := command.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					_ = command.Process.Kill()
					_ = current.input.Close()
					if command.ProcessState == nil {
						_ = command.Wait()
					}
				})
			}
			// Every process has passed preflight and reached certificate
			// generation before any can publish. Old check-then-rename code
			// deterministically lets every process report success here.
			for index := range children {
				line, err := children[index].output.ReadString('\n')
				if err != nil || line != "ready\n" {
					t.Fatalf("child %d did not reach generation gate: %q, %v", index, line, err)
				}
			}
			for index := range children {
				if _, err := io.WriteString(children[index].input, "go\n"); err != nil {
					t.Fatal(err)
				}
				_ = children[index].input.Close()
			}
			successes, winner := 0, -1
			for index := range children {
				current := &children[index]
				_, _ = io.Copy(io.Discard, current.output)
				if err := current.command.Wait(); err == nil {
					successes++
					winner = index
				} else if current.command.ProcessState == nil || current.command.ProcessState.ExitCode() != 1 {
					t.Fatalf("child %d failed unexpectedly: %v; %s", index, err, current.stderr.String())
				}
			}
			if successes != 1 {
				t.Fatalf("successful certificate commands = %d, want exactly one", successes)
			}
			if _, err := tls.LoadX509KeyPair(filepath.Join(directory, "server.crt"), children[winner].key); err != nil {
				t.Fatalf("winner's certificate and private key do not match: %v", err)
			}
			if scenario == "shared certificate" {
				for index := range children {
					if index == winner {
						continue
					}
					if _, err := os.Lstat(children[index].key); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("losing process %d left its key: %v", index, err)
					}
				}
			}
		})
	}
}

func TestCertConcurrentProcessHelper(t *testing.T) {
	if os.Getenv("AUTOCAR_CERT_TEST_CHILD") != "1" {
		return
	}
	// Only delay randomness in this isolated child. Always delegate to the
	// original cryptographic source; generated keys remain normally verified.
	rand.Reader = &certificateRandomGate{source: rand.Reader}
	err := runCert([]string{"--hosts", "relay.example", "--cert", os.Getenv("AUTOCAR_CERT_TEST_CERT"), "--key", os.Getenv("AUTOCAR_CERT_TEST_KEY")})
	if err == nil {
		os.Exit(0)
	}
	if errors.Is(err, os.ErrExist) {
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}

type certificateRandomGate struct {
	source io.Reader
	once   sync.Once
	err    error
}

func (g *certificateRandomGate) Read(buffer []byte) (int, error) {
	g.once.Do(func() {
		_, g.err = io.WriteString(os.Stdout, "ready\n")
		if g.err == nil {
			var start [1]byte
			_, g.err = io.ReadFull(os.Stdin, start[:])
		}
	})
	if g.err != nil {
		return 0, g.err
	}
	return g.source.Read(buffer)
}
