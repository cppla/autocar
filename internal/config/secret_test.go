package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadSecretFromEnvironment(t *testing.T) {
	t.Setenv("AUTOCAR_TEST_SECRET", "  correct horse  \n")
	got, err := LoadSecret("", "AUTOCAR_TEST_SECRET")
	if err != nil {
		t.Fatal(err)
	}
	if got != "correct horse" {
		t.Fatalf("got %q", got)
	}
}

func TestLoadSecretFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSecret(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != "value" {
		t.Fatalf("got %q", got)
	}
}

func TestLoadSecretRejectsLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("value"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadSecret(path, "")
	if err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("expected permissions error, got %v", err)
	}
}

func TestLoadSecretRejectsEmpty(t *testing.T) {
	t.Setenv("AUTOCAR_TEST_SECRET", "")
	if _, err := LoadSecret("", "AUTOCAR_TEST_SECRET"); err == nil {
		t.Fatal("expected error")
	}
}
