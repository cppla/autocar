package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredentialCommandsRejectPositionalArgumentsBeforeWriting(t *testing.T) {
	const unexpected = "private-unexpected-argument"
	for _, command := range []string{"token", "cert", "init"} {
		for _, suffix := range [][]string{
			{unexpected}, {"--", unexpected}, {unexpected, "--unknown-option"},
		} {
			t.Run(command+"/"+strings.Join(suffix, " "), func(t *testing.T) {
				directory := t.TempDir()
				var args, outputs []string
				switch command {
				case "token":
					outputs = []string{filepath.Join(directory, "token")}
					args = []string{"token", "--out", outputs[0]}
				case "cert":
					outputs = []string{filepath.Join(directory, "cert.pem"), filepath.Join(directory, "key.pem")}
					args = []string{"cert", "--hosts", "relay.invalid", "--cert", outputs[0], "--key", outputs[1]}
				case "init":
					outputs = []string{filepath.Join(directory, "bundle")}
					args = []string{"init", "--server", "relay.invalid:443", "--out", outputs[0]}
				}
				err := run(context.Background(), append(args, suffix...))
				if err == nil || !strings.Contains(err.Error(), "positional arguments") {
					t.Errorf("want positional argument rejection, got %v", err)
				}
				if err != nil && strings.Contains(err.Error(), unexpected) {
					t.Error("error disclosed the unexpected argument value")
				}
				for _, path := range outputs {
					if _, err := os.Lstat(path); !os.IsNotExist(err) {
						t.Errorf("output %s was created or could not be checked: %v", filepath.Base(path), err)
					}
				}
			})
		}
	}
}

func TestBenchmarkCommandsRejectPositionalArgumentsBeforeStartup(t *testing.T) {
	// Invalid required settings make the unfixed baseline return before any
	// listener or network connection. Argument rejection must precede those
	// semantic checks, not be inferred from a downstream startup failure.
	for _, args := range [][]string{
		{"bench-server", "--listen", "invalid-listener", "unexpected"},
		{"bench-server", "--listen", "invalid-listener", "--", "unexpected"},
		{"bench-client", "--target=", "unexpected"},
		{"bench-client", "--target=", "--", "unexpected"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			err := run(context.Background(), args)
			if err == nil || !strings.Contains(err.Error(), "positional arguments") {
				t.Fatalf("want argument rejection before startup validation, got %v", err)
			}
		})
	}
}
