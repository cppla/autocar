package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func makeCommandPathSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("creating symlinks requires Windows privileges: %v", err)
		}
		t.Fatal(err)
	}
}

func TestCommandConfigPreservesFilesystemTraversal(t *testing.T) {
	for _, option := range []string{"ca", "client-cert", "client-key", "token-file", "proxy-cert", "proxy-key", "proxy-password-file", "cert", "key", "client-ca", "cover-root"} {
		for _, source := range []string{"config-path", "relative-config-path", "relative-value", "absolute-value"} {
			t.Run(option+"/"+source, func(t *testing.T) {
				base := t.TempDir()
				real := filepath.Join(base, "real")
				if err := os.MkdirAll(filepath.Join(real, "child"), 0o700); err != nil {
					t.Fatal(err)
				}
				makeCommandPathSymlink(t, filepath.Join(real, "child"), filepath.Join(base, "link"))
				for dir, text := range map[string]string{base: "unintended file", real: "intended file"} {
					if err := os.WriteFile(filepath.Join(dir, "item"), []byte(text), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				configPath := filepath.Join(base, "connection.json")
				value := "link" + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "item"
				want, err := os.ReadFile(base + string(os.PathSeparator) + value)
				if err != nil {
					t.Fatal(err)
				}
				switch source {
				case "config-path", "relative-config-path":
					configPath = base + string(os.PathSeparator) + "link" + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "connection.json"
					value = "item"
				case "absolute-value":
					value = base + string(os.PathSeparator) + value
				}
				data, err := json.Marshal(map[string]string{option: value})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(configPath, data, 0o600); err != nil {
					t.Fatal(err)
				}
				if source == "relative-config-path" {
					t.Chdir(base)
					configPath = "link" + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "connection.json"
				}
				fs := flag.NewFlagSet("test", flag.ContinueOnError)
				got := fs.String(option, "", "")
				if err := parseFlagsWithConfig(fs, []string{"--config", configPath}); err != nil {
					t.Fatal(err)
				}
				contents, err := os.ReadFile(*got)
				if err != nil || string(contents) != string(want) {
					t.Fatalf("native path contains %q; config option selected %q, err=%v", want, contents, err)
				}
			})
		}
	}
}

func TestCommandConfigRelativeTraversalAndCLIOverride(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(real, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	makeCommandPathSymlink(t, filepath.Join(real, "child"), filepath.Join(base, "link"))
	rawParent := base + string(os.PathSeparator) + "link" + string(os.PathSeparator) + ".." + string(os.PathSeparator)
	if err := os.WriteFile(rawParent+"connection.json", []byte(`{"ca":"missing/../ca.pem"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{base, real} {
		if err := os.WriteFile(filepath.Join(dir, "ca.pem"), []byte("must not bypass missing component"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, wantErr := os.Stat(rawParent + "missing/../ca.pem")
	if wantErr != nil && !os.IsNotExist(wantErr) {
		t.Fatal(wantErr)
	}
	t.Chdir(base)
	configPath := "link" + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "connection.json"
	for _, override := range []bool{false, true} {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		ca := fs.String("ca", "", "")
		args := []string{"--config", configPath}
		if override {
			args = append(args, "--ca", "cli-relative.pem")
		}
		if err := parseFlagsWithConfig(fs, args); err != nil {
			t.Fatal(err)
		}
		if override {
			if *ca != "cli-relative.pem" {
				t.Fatalf("CLI path changed: %q", *ca)
			}
		} else {
			got, err := os.Stat(*ca)
			if (os.IsNotExist(wantErr) && !os.IsNotExist(err)) || (wantErr == nil && (err != nil || !os.SameFile(want, got))) {
				t.Fatalf("missing component resolution differs from native path: native=%v, parsed=%v", wantErr, err)
			}
		}
	}
}

func TestCommandConfigFinalSymlinkUsesContainingDirectory(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(t.TempDir(), "target.json")
	if err := os.WriteFile(target, []byte(`{"ca":"anchor.pem"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(base, "linked.json")
	makeCommandPathSymlink(t, target, configPath)
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	ca := fs.String("ca", "", "")
	if err := parseFlagsWithConfig(fs, []string{"--config", configPath}); err != nil {
		t.Fatal(err)
	}
	if *ca != filepath.Join(base, "anchor.pem") {
		t.Fatalf("reference must use config symlink's containing directory: %q", *ca)
	}
}
