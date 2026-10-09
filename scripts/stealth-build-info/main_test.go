package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
	"time"
)

func fixtureBuildInfo(spec binarySpec) *debug.BuildInfo {
	info := &debug.BuildInfo{
		GoVersion: "go1.27.2",
		Path:      spec.path,
		Main:      debug.Module{Path: "github.com/cppla/autocar", Version: "(devel)"},
		Settings: []debug.BuildSetting{
			{Key: "GOOS", Value: "linux"},
			{Key: "GOARCH", Value: "arm64"},
		},
	}
	for _, path := range spec.modules {
		info.Deps = append(info.Deps, &debug.Module{Path: path, Version: "v0.63.0", Sum: fixtureSum(path)})
	}
	return info
}

func fixtureSum(value string) string {
	hash := sha256.Sum256([]byte(value))
	return "h1:" + base64.StdEncoding.EncodeToString(hash[:])
}

func TestInspectBuildInfoReplacement(t *testing.T) {
	info := fixtureBuildInfo(autocarSpec)
	info.Deps[1].Replace = &debug.Module{
		Path: "github.com/cppla/quic-go", Version: "v0.63.1-0.20261009040133-c1cae948af15", Sum: fixtureSum("fork-quic"),
	}
	info.Deps[2].Replace = &debug.Module{
		Path: "github.com/cppla/utls", Version: "v0.0.0-20261009031926-14c2a4cb1403", Sum: fixtureSum("fork-utls"),
	}
	// The original module checksum can be absent when Go records a replacement.
	info.Deps[1].Sum, info.Deps[2].Sum = "", ""
	// Output order is fixed, not dependent on the build-info dependency ordering.
	slices.Reverse(info.Deps)
	got, err := inspectBuildInfo(info, autocarSpec)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Modules) != 3 || got.Package != autocarSpec.path || got.GoVersion != "go1.27.2" || got.GOOS != "linux" || got.GOARCH != "arm64" {
		t.Fatalf("unexpected binary provenance: %+v", got)
	}
	for i, path := range selectedModules {
		if got.Modules[i].ModulePath != path || got.Modules[i].RequestedVersion != "v0.63.0" {
			t.Fatalf("unexpected requested module: %+v", got.Modules[i])
		}
	}
	if got.Modules[0].Replaced || got.Modules[0].SourcePath != officialQUIC || got.Modules[0].SourceVersion != "v0.63.0" {
		t.Fatalf("native module must be unreplaced: %+v", got.Modules[0])
	}
	for i, original := range []*debug.Module{info.Deps[1], info.Deps[0]} {
		module := got.Modules[i+1]
		if !module.Replaced || module.SourcePath != original.Replace.Path || module.SourceVersion != original.Replace.Version || module.SourceSum != original.Replace.Sum {
			t.Fatalf("replacement provenance lost: %+v", module)
		}
	}
}

func TestInspectBuildInfoAllowedSourceForms(t *testing.T) {
	for _, path := range []string{adapterQUIC, uTLS} {
		t.Run(path, func(t *testing.T) {
			dep := &debug.Module{Path: path, Version: "v1.2.3", Sum: fixtureSum("original")}
			original, err := inspectModule(dep)
			if err != nil || original.Replaced || original.SourcePath != path || original.SourceSum != dep.Sum {
				t.Fatalf("original source: %+v, %v", original, err)
			}
			dep.Replace = &debug.Module{Path: path, Version: "v1.2.4", Sum: fixtureSum("new-version")}
			replaced, err := inspectModule(dep)
			if err != nil || !replaced.Replaced || replaced.SourcePath != path || replaced.SourceVersion != "v1.2.4" {
				t.Fatalf("same-path version replacement: %+v, %v", replaced, err)
			}
		})
	}
}

func TestInspectBuildInfoRejectsInvalidMetadata(t *testing.T) {
	tests := []struct {
		name string
		edit func(*debug.BuildInfo)
	}{
		{"wrong package", func(b *debug.BuildInfo) { b.Path = "private-secret/path" }},
		{"missing Go version", func(b *debug.BuildInfo) { b.GoVersion = "" }},
		{"development Go version", func(b *debug.BuildInfo) { b.GoVersion = "devel go1.28-secret" }},
		{"missing GOOS", func(b *debug.BuildInfo) { b.Settings = b.Settings[1:] }},
		{"missing GOARCH", func(b *debug.BuildInfo) { b.Settings = b.Settings[:1] }},
		{"duplicate GOOS", func(b *debug.BuildInfo) { b.Settings = append(b.Settings, b.Settings[0]) }},
		{"duplicate GOARCH", func(b *debug.BuildInfo) { b.Settings = append(b.Settings, b.Settings[1]) }},
		{"empty target", func(b *debug.BuildInfo) { b.Settings[0].Value = "" }},
		{"unsafe target", func(b *debug.BuildInfo) { b.Settings[1].Value = "secret/../../path" }},
		{"missing dependency", func(b *debug.BuildInfo) { b.Deps = b.Deps[:2] }},
		{"duplicate dependency", func(b *debug.BuildInfo) { b.Deps = append(b.Deps, b.Deps[0]) }},
		{"nil dependency", func(b *debug.BuildInfo) { b.Deps = append(b.Deps, nil) }},
		{"unversioned request", func(b *debug.BuildInfo) { b.Deps[1].Version = "" }},
		{"development request", func(b *debug.BuildInfo) { b.Deps[1].Version = "(devel)" }},
		{"invalid requested version", func(b *debug.BuildInfo) { b.Deps[1].Version = "v1.2-secret" }},
		{"missing source sum", func(b *debug.BuildInfo) { b.Deps[0].Sum = "" }},
		{"malformed source sum", func(b *debug.BuildInfo) { b.Deps[0].Sum = "h1:secret" }},
		{"wrong-size source sum", func(b *debug.BuildInfo) { b.Deps[0].Sum = "h1:c2VjcmV0" }},
		{"sum with newline", func(b *debug.BuildInfo) { b.Deps[0].Sum += "\n" }},
		{"native replacement", func(b *debug.BuildInfo) {
			b.Deps[0].Replace = &debug.Module{Path: officialQUIC, Version: "v0.63.1", Sum: fixtureSum("native")}
		}},
		{"local replacement", func(b *debug.BuildInfo) { b.Deps[1].Replace = &debug.Module{Path: "/private/secret/quic-go"} }},
		{"relative replacement", func(b *debug.BuildInfo) { b.Deps[1].Replace = &debug.Module{Path: "../secret"} }},
		{"unversioned replacement", func(b *debug.BuildInfo) {
			b.Deps[1].Replace = &debug.Module{Path: "github.com/cppla/quic-go", Sum: fixtureSum("fork")}
		}},
		{"development replacement", func(b *debug.BuildInfo) {
			b.Deps[1].Replace = &debug.Module{Path: "github.com/cppla/quic-go", Version: "(devel)", Sum: fixtureSum("fork")}
		}},
		{"replacement missing sum", func(b *debug.BuildInfo) {
			b.Deps[1].Replace = &debug.Module{Path: "github.com/cppla/quic-go", Version: "v0.63.1"}
		}},
		{"unexpected replacement source", func(b *debug.BuildInfo) {
			b.Deps[1].Replace = &debug.Module{Path: "github.com/private-secret/quic-go", Version: "v0.63.1", Sum: fixtureSum("fork")}
		}},
		{"nested replacement", func(b *debug.BuildInfo) {
			b.Deps[1].Replace = &debug.Module{Path: adapterQUIC, Version: "v0.63.1", Sum: fixtureSum("fork"), Replace: &debug.Module{Path: "private-secret"}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info := fixtureBuildInfo(autocarSpec)
			test.edit(info)
			got, err := inspectBuildInfo(info, autocarSpec)
			if err == nil {
				t.Fatalf("accepted invalid metadata: %+v", got)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("error exposed metadata: %v", err)
			}
		})
	}
	if _, err := inspectBuildInfo(nil, autocarSpec); err == nil {
		t.Fatal("accepted nil build info")
	}
}

func TestControlRequiresOnlyOfficialSelectedDependency(t *testing.T) {
	info := fixtureBuildInfo(controlSpec)
	got, err := inspectBuildInfo(info, controlSpec)
	if err != nil || len(got.Modules) != 1 || got.Modules[0].ModulePath != officialQUIC {
		t.Fatalf("invalid control result: %+v, %v", got, err)
	}
	info.Deps = append(info.Deps, &debug.Module{Path: adapterQUIC, Version: "v0.63.1", Sum: fixtureSum("unexpected")})
	if _, err := inspectBuildInfo(info, controlSpec); err == nil {
		t.Fatal("accepted adapter-linked control binary")
	}
}

func TestProvenanceRedactsEverythingOutsideAllowlist(t *testing.T) {
	info := fixtureBuildInfo(autocarSpec)
	info.Main = debug.Module{Path: "/private/secret/main", Version: "secret-main-version", Sum: "secret-main-sum"}
	info.Deps = append(info.Deps, &debug.Module{Path: "secret-unrelated-module", Version: "secret-version", Replace: &debug.Module{Path: "/secret/local/path"}})
	info.Settings = append(info.Settings,
		debug.BuildSetting{Key: "-ldflags", Value: "-X secret-token=secret-value"},
		debug.BuildSetting{Key: "vcs.revision", Value: "secret-revision"},
		debug.BuildSetting{Key: "vcs.modified", Value: "true"},
		debug.BuildSetting{Key: "secret-setting", Value: "secret-setting-value"},
	)
	autocar, err := inspectBuildInfo(info, autocarSpec)
	if err != nil {
		t.Fatal(err)
	}
	control, err := inspectBuildInfo(fixtureBuildInfo(controlSpec), controlSpec)
	if err != nil {
		t.Fatal(err)
	}
	autocar.BinarySHA256, control.BinarySHA256 = strings.Repeat("a", 64), strings.Repeat("b", 64)
	report, err := makeProvenance(autocar, control)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, excluded := range []string{"secret", "argv", "ldflags", "vcs", "Main", "Settings"} {
		if bytes.Contains(data, []byte(excluded)) {
			t.Fatalf("output exposed %q: %s", excluded, data)
		}
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	assertKeys(t, decoded, "schema_version", "kind", "autocar", "control")
	if string(decoded["schema_version"]) != "1" || string(decoded["kind"]) != `"autocar-pilot-build-provenance"` {
		t.Fatalf("wrong schema: %s", data)
	}
	for _, name := range []string{"autocar", "control"} {
		var binary map[string]json.RawMessage
		if err := json.Unmarshal(decoded[name], &binary); err != nil {
			t.Fatal(err)
		}
		assertKeys(t, binary, "binary_sha256", "go_version", "goos", "goarch", "package", "modules")
		var modules []map[string]json.RawMessage
		if err := json.Unmarshal(binary["modules"], &modules); err != nil {
			t.Fatal(err)
		}
		for _, module := range modules {
			assertKeys(t, module, "module_path", "requested_version", "source_path", "source_version", "source_sum", "replaced")
		}
	}
}

func assertKeys(t *testing.T, value map[string]json.RawMessage, want ...string) {
	t.Helper()
	got := make([]string, 0, len(value))
	for key := range value {
		got = append(got, key)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected keys: got %v, want %v", got, want)
	}
}

func TestProvenanceRequiresMatchingCompilerAndTarget(t *testing.T) {
	autocar, err := inspectBuildInfo(fixtureBuildInfo(autocarSpec), autocarSpec)
	if err != nil {
		t.Fatal(err)
	}
	control, err := inspectBuildInfo(fixtureBuildInfo(controlSpec), controlSpec)
	if err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*binaryProvenance){
		func(b *binaryProvenance) { b.GOOS = "darwin" },
		func(b *binaryProvenance) { b.GOARCH = "amd64" },
		func(b *binaryProvenance) { b.GoVersion = "go1.27.3" },
	} {
		changed := control
		edit(&changed)
		if _, err := makeProvenance(autocar, changed); err == nil {
			t.Fatal("accepted mismatched binaries")
		}
	}
}

func TestRunRejectsArgumentsWithoutLeakingValues(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"--secret-flag=secret-value"},
		{"--autocar", "secret-first", "--autocar", "secret-second", "--control", "secret-control"},
		{"--autocar", "secret-first", "--control", "secret-control", "secret-positional"},
		{"--autocar", "secret-first"},
		{"--autocar", "", "--control", "secret-control"},
		{"--autocar", "/nonexistent/secret-binary", "--control", "secret-control"},
	} {
		var output bytes.Buffer
		err := run(args, &output)
		if err == nil || output.Len() != 0 {
			t.Fatalf("invalid CLI emitted output or succeeded: %q, %v", output.String(), err)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatalf("error exposed arguments: %v", err)
		}
	}
}

func TestReadBinaryRejectsInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	for _, test := range []struct {
		name string
		data []byte
	}{{"empty-secret", nil}, {"invalid-secret", []byte("not a Go binary")}} {
		path := filepath.Join(dir, test.name)
		if err := os.WriteFile(path, test.data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readBinary(path); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("invalid file accepted or path leaked: %v", err)
		}
	}
	if _, _, err := readBinary(dir); err == nil {
		t.Fatal("accepted directory")
	}
	large := filepath.Join(dir, "oversized-secret")
	file, err := os.Create(large)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxBinaryBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readBinary(large); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("oversized file accepted or path leaked: %v", err)
	}
	t.Run("symlink", func(t *testing.T) {
		link := filepath.Join(dir, "linked-secret")
		if err := os.Symlink(filepath.Join(dir, "invalid-secret"), link); err != nil {
			t.Skip("platform does not allow creating test symlink")
		}
		if _, _, err := readBinary(link); err == nil {
			t.Fatal("accepted symlink")
		}
	})
}

func TestReadRealCompiledBinaryOfflineWithoutExecuting(t *testing.T) {
	dir := t.TempDir()
	commandDir := filepath.Join(dir, "cmd", "autocar")
	if err := os.MkdirAll(commandDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module github.com/cppla/autocar\n\ngo 1.27.2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "must-not-run")
	source := fmt.Sprintf("package main\nimport \"os\"\nfunc main() { _ = os.WriteFile(%q, []byte(\"executed\"), 0600); panic(\"must not execute\") }\n", marker)
	if err := os.WriteFile(filepath.Join(commandDir, "main.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "fixture-binary")
	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
	if runtime.GOOS == "windows" {
		goBinary += ".exe"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, goBinary, "build", "-trimpath", "-ldflags=-s -w", "-o", binary, "./cmd/autocar")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOWORK=off", "GOFLAGS=", "GOENV=off", "CGO_ENABLED=0", "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("offline fixture build failed: %v\n%s", err, output)
	}
	info, hash, err := readBinary(binary)
	if err != nil {
		t.Fatal(err)
	}
	if info.Path != autocarSpec.path || !goVersionPattern.MatchString(info.GoVersion) || info.Main.Version != "(devel)" {
		t.Fatalf("wrong real build metadata: %+v", info)
	}
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	wantHash := sha256.Sum256(data)
	if hash != hex.EncodeToString(wantHash[:]) {
		t.Fatal("binary hash does not cover the actual file")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("fixture was executed or marker inspection failed: %v", err)
	}
	// This offline standard-library-only fixture must not masquerade as a pilot
	// binary: a correct command path alone cannot satisfy dependency validation.
	if _, err := inspectBinary(binary, autocarSpec); err == nil {
		t.Fatal("accepted binary missing required dependencies")
	}
}
