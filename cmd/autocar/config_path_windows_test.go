package main

import (
	"encoding/json"
	"flag"
	"path/filepath"
	"testing"
)

func TestCommandConfigWindowsPathKinds(t *testing.T) {
	for _, path := range []string{`C:anchor.pem`, `C:\anchor.pem`, `\anchor.pem`, `/anchor.pem`, `\\server\share\anchor.pem`, `\\?\C:\anchor.pem`} {
		data, err := json.Marshal(map[string]string{"ca": path})
		if err != nil {
			t.Fatal(err)
		}
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		ca := fs.String("ca", "", "")
		if err := parseFlagsWithConfig(fs, []string{"--config", writeTestCommandConfig(t, string(data))}); err != nil {
			t.Fatal(err)
		}
		if *ca != path {
			t.Errorf("volume/root scoped reference changed: %q became %q", path, *ca)
		}
	}
	for _, path := range []string{`anchor.pem`, `nested\anchor.pem`, `link\..\anchor.pem`} {
		if !configRelativePath(path) {
			t.Errorf("relative path classified as volume/root scoped: %q", path)
		}
	}
	for _, test := range []struct{ config, parent, joined string }{
		{`C:config.json`, `C:`, `C:link\..\anchor.pem`},
		{`C:dir\config.json`, `C:dir\`, `C:dir\link\..\anchor.pem`},
		{`\dir\config.json`, `\dir\`, `\dir\link\..\anchor.pem`},
		{`C:\dir\config.json`, `C:\dir\`, `C:\dir\link\..\anchor.pem`},
		{`\\server\share\config.json`, `\\server\share\`, `\\server\share\link\..\anchor.pem`},
	} {
		parent, err := commandConfigDirectory(test.config)
		if err != nil || parent != test.parent {
			t.Fatalf("parent(%q) = %q, %v; want %q", test.config, parent, err, test.parent)
		}
		if got := appendUncleanPath(parent, `link\..\anchor.pem`); got != test.joined {
			t.Errorf("joined path = %q; want %q", got, test.joined)
		}
	}
	// Unlike a bare drive, the root of a UNC share requires a separator.
	if got := appendUncleanPath(`\\server\share`, "anchor.pem"); got != filepath.FromSlash(`\\server\share\anchor.pem`) {
		t.Errorf("UNC root append = %q", got)
	}
}
