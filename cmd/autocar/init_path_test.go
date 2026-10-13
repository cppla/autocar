package main

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestInitOutputPreservesFilesystemTraversal(t *testing.T) {
	for _, existingAlternate := range []bool{false, true} {
		for _, protocol := range []string{"web", "native"} {
			t.Run(protocol+"/alternate-exists="+map[bool]string{false: "false", true: "true"}[existingAlternate], func(t *testing.T) {
				base := t.TempDir()
				real := filepath.Join(base, "real")
				if err := os.MkdirAll(filepath.Join(real, "child"), 0o700); err != nil {
					t.Fatal(err)
				}
				makeCommandPathSymlink(t, filepath.Join(real, "child"), filepath.Join(base, "link"))
				rawParent := base + string(os.PathSeparator) + "link" + string(os.PathSeparator) + ".." + string(os.PathSeparator)
				parentInfo, err := os.Stat(rawParent)
				if err != nil {
					t.Fatal(err)
				}
				realInfo, err := os.Stat(real)
				if err != nil {
					t.Fatal(err)
				}
				actual := filepath.Join(real, "bundle")
				alternate := filepath.Join(base, "bundle")
				if !os.SameFile(parentInfo, realInfo) {
					// Windows may resolve .. lexically. Match the directory
					// the native filesystem actually reserves in either case.
					actual, alternate = alternate, actual
				}
				if existingAlternate {
					if err := os.Mkdir(alternate, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				out := rawParent + "bundle"
				args := []string{"--server=relay.example:443", "--protocol", protocol, "--out", out}
				if err := runInitWith(args, io.Discard); err != nil {
					t.Fatal(err)
				}
				before := snapshotInitBundle(t, actual)
				for _, name := range []string{"server/server.key", "server/server.json", "client/relay-token", "client/client.json"} {
					if _, ok := before[name]; !ok {
						t.Fatalf("bundle missing %s in actual output directory", name)
					}
				}
				if err := runInitWith(args, io.Discard); err == nil {
					t.Fatal("reused an existing output directory")
				}
				if !reflect.DeepEqual(before, snapshotInitBundle(t, actual)) {
					t.Fatal("retry changed existing bundle")
				}
				entries, err := os.ReadDir(alternate)
				if existingAlternate {
					if err != nil || len(entries) != 0 {
						t.Fatalf("pre-existing alternate directory received writes: %v, %v", entries, err)
					}
				} else if !os.IsNotExist(err) {
					t.Fatalf("alternate output directory was created: %v", err)
				}
			})
		}
	}
}
