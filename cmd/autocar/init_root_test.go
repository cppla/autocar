package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestInitBundleRemainsBoundAfterDirectoryRename(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not allow renaming a directory with an open root handle")
	}
	if runtime.GOOS == "plan9" || runtime.GOOS == "js" {
		t.Skip("os.Root does not track directory renames on this platform")
	}
	base := t.TempDir()
	original, moved := filepath.Join(base, "original"), filepath.Join(base, "moved")
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(original)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeInitBundleRoot(root, []initBundleFile{{"server/item", []byte("kept in reserved directory")}}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(moved, "server", "item"))
	if err != nil || string(got) != "kept in reserved directory" {
		t.Fatalf("reserved directory lost bundle: %q, %v", got, err)
	}
	entries, err := os.ReadDir(original)
	if err != nil || len(entries) != 0 {
		t.Fatalf("replacement directory received writes: %v, %v", entries, err)
	}
}
