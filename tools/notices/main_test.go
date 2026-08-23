package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadNoticesFindsAndSortsRootFiles(t *testing.T) {
	directory := t.TempDir()
	for name, content := range map[string]string{
		"NOTICE":        "notice\r\n",
		"LICENSE-MIT":   "license\n",
		"PATENTS.txt":   "patents\n",
		"README.md":     "not a notice\n",
		"UNLICENSED.md": "not a notice\n",
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	notices, err := readNotices(directory)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"LICENSE-MIT", "NOTICE", "PATENTS.txt"}
	if len(notices) != len(want) {
		t.Fatalf("notice count = %d, want %d", len(notices), len(want))
	}
	for index := range want {
		if notices[index].Name != want[index] {
			t.Fatalf("notice[%d] = %q, want %q", index, notices[index].Name, want[index])
		}
		if strings.Contains(notices[index].Text, "\r") || !strings.HasSuffix(notices[index].Text, "\n") {
			t.Fatalf("notice text was not normalized: %q", notices[index].Text)
		}
		if len(notices[index].SHA256) != 64 {
			t.Fatalf("SHA-256 = %q", notices[index].SHA256)
		}
	}
}

func TestReplacementLabelIsCheckoutIndependent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	inside := filepath.Join(root, "third_party", "module")
	outside := filepath.Join(t.TempDir(), "module")

	if got := replacementLabel(root, &listedModule{Path: inside}); got != "./third_party/module" {
		t.Fatalf("inside replacement = %q", got)
	}
	if got := replacementLabel(root, &listedModule{Path: outside}); got != "local replacement" {
		t.Fatalf("outside replacement = %q", got)
	}
	if got := replacementLabel(root, &listedModule{Path: "example.com/module", Version: "v1.2.3"}); got != "example.com/module v1.2.3" {
		t.Fatalf("module replacement = %q", got)
	}
}

func TestRenderUsesSafeMarkdownFenceAndReplacementMetadata(t *testing.T) {
	generated, err := render([]dependency{{
		Path:        "example.com/dependency",
		Version:     "v1.0.0",
		Replacement: "./third_party/dependency",
		Notices: []noticeFile{{
			Name:   "LICENSE",
			Text:   "contains ``` fence\n",
			SHA256: strings.Repeat("a", 64),
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	text := string(generated)
	for _, required := range []string{"````text", "example.com/dependency", "./third_party/dependency"} {
		if !strings.Contains(text, required) {
			t.Fatalf("generated notice does not contain %q", required)
		}
	}
}

func TestReadNoticesRejectsMissingLicense(t *testing.T) {
	if _, err := readNotices(t.TempDir()); err == nil {
		t.Fatal("module without a root license was accepted")
	}
}
