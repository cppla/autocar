// Command stealth-build-info reads, but never runs, two pilot binaries and
// emits a deliberately small allowlist of their Go build provenance.
package main

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime/debug"
	"strings"
)

const (
	maxBinaryBytes = 128 << 20
	officialQUIC   = "github.com/quic-go/quic-go"
	adapterQUIC    = "github.com/apernet/quic-go"
	uTLS           = "github.com/refraction-networking/utls"
)

var (
	goVersionPattern = regexp.MustCompile(`^go[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:(?:rc|beta)[0-9]+)?$`)
	targetPattern    = regexp.MustCompile(`^[a-z0-9]+$`)
	versionPattern   = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	selectedModules  = []string{officialQUIC, adapterQUIC, uTLS}
)

type moduleProvenance struct {
	ModulePath       string `json:"module_path"`
	RequestedVersion string `json:"requested_version"`
	SourcePath       string `json:"source_path"`
	SourceVersion    string `json:"source_version"`
	SourceSum        string `json:"source_sum"`
	Replaced         bool   `json:"replaced"`
}

type binaryProvenance struct {
	BinarySHA256 string             `json:"binary_sha256"`
	GoVersion    string             `json:"go_version"`
	GOOS         string             `json:"goos"`
	GOARCH       string             `json:"goarch"`
	Package      string             `json:"package"`
	Modules      []moduleProvenance `json:"modules"`
}

type provenance struct {
	SchemaVersion int              `json:"schema_version"`
	Kind          string           `json:"kind"`
	Autocar       binaryProvenance `json:"autocar"`
	Control       binaryProvenance `json:"control"`
}

type binarySpec struct {
	path    string
	modules []string
}

var (
	autocarSpec = binarySpec{"github.com/cppla/autocar/cmd/autocar", selectedModules}
	controlSpec = binarySpec{"github.com/cppla/autocar/scripts/stealth-pilot", []string{officialQUIC}}
)

// A repeat is rejected rather than silently selecting the last path supplied.
type uniquePathFlag struct {
	value string
	set   bool
}

func (f *uniquePathFlag) String() string { return "" }

func (f *uniquePathFlag) Set(value string) error {
	if f.set {
		return errors.New("duplicate flag")
	}
	f.value, f.set = value, true
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "stealth-build-info:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	var autocarPath, controlPath uniquePathFlag
	flags := flag.NewFlagSet("stealth-build-info", flag.ContinueOnError)
	// flag's default errors can echo argv, including sensitive paths or values.
	flags.SetOutput(io.Discard)
	flags.Var(&autocarPath, "autocar", "AutoCAR binary")
	flags.Var(&controlPath, "control", "control binary")
	if err := flags.Parse(args); err != nil {
		return errors.New("invalid arguments; require --autocar <file> --control <file>")
	}
	if flags.NArg() != 0 || autocarPath.value == "" || controlPath.value == "" {
		return errors.New("require --autocar <file> --control <file>, without positional arguments")
	}
	autocar, err := inspectBinary(autocarPath.value, autocarSpec)
	if err != nil {
		return fmt.Errorf("autocar: %w", err)
	}
	control, err := inspectBinary(controlPath.value, controlSpec)
	if err != nil {
		return fmt.Errorf("control: %w", err)
	}
	report, err := makeProvenance(autocar, control)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(stdout).Encode(report); err != nil {
		return errors.New("cannot write provenance JSON")
	}
	return nil
}

func makeProvenance(autocar, control binaryProvenance) (provenance, error) {
	if autocar.GOOS != control.GOOS || autocar.GOARCH != control.GOARCH {
		return provenance{}, errors.New("binary targets do not match")
	}
	if autocar.GoVersion != control.GoVersion {
		return provenance{}, errors.New("binary Go versions do not match")
	}
	return provenance{SchemaVersion: 1, Kind: "autocar-pilot-build-provenance", Autocar: autocar, Control: control}, nil
}

func inspectBinary(path string, spec binarySpec) (binaryProvenance, error) {
	info, hash, err := readBinary(path)
	if err != nil {
		return binaryProvenance{}, err
	}
	result, err := inspectBuildInfo(info, spec)
	if err != nil {
		return binaryProvenance{}, err
	}
	result.BinarySHA256 = hash
	return result, nil
}

func readBinary(path string) (*debug.BuildInfo, string, error) {
	// Check before opening, so ordinary FIFO/device/directory inputs cannot block
	// the reader. Symlinks are rejected too: callers must provide a regular file.
	before, err := os.Lstat(path)
	if err != nil {
		return nil, "", errors.New("cannot inspect binary")
	}
	if !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maxBinaryBytes {
		return nil, "", errors.New("binary must be a nonempty regular file of at most 128 MiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, "", errors.New("cannot open binary")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() || opened.Size() != before.Size() {
		return nil, "", errors.New("binary changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBinaryBytes+1))
	if err != nil || int64(len(data)) != opened.Size() || len(data) > maxBinaryBytes {
		return nil, "", errors.New("cannot read stable bounded binary")
	}
	info, err := buildinfo.Read(bytes.NewReader(data))
	if err != nil {
		return nil, "", errors.New("binary has no readable Go build information")
	}
	hash := sha256.Sum256(data)
	return info, hex.EncodeToString(hash[:]), nil
}

func inspectBuildInfo(info *debug.BuildInfo, spec binarySpec) (binaryProvenance, error) {
	if info == nil || info.Path != spec.path {
		return binaryProvenance{}, errors.New("unexpected command package")
	}
	if !goVersionPattern.MatchString(info.GoVersion) {
		return binaryProvenance{}, errors.New("invalid or development Go version")
	}
	result := binaryProvenance{GoVersion: info.GoVersion, Package: info.Path}
	target := make(map[string]string, 2)
	for _, setting := range info.Settings {
		if setting.Key != "GOOS" && setting.Key != "GOARCH" {
			continue
		}
		if _, exists := target[setting.Key]; exists || !targetPattern.MatchString(setting.Value) {
			return binaryProvenance{}, errors.New("invalid or duplicate target build setting")
		}
		target[setting.Key] = setting.Value
	}
	result.GOOS, result.GOARCH = target["GOOS"], target["GOARCH"]
	if result.GOOS == "" || result.GOARCH == "" {
		return binaryProvenance{}, errors.New("missing target build setting")
	}

	selected := make(map[string]*debug.Module, len(spec.modules))
	for _, dep := range info.Deps {
		if dep == nil {
			return binaryProvenance{}, errors.New("invalid dependency build information")
		}
		for _, path := range selectedModules {
			if dep.Path != path {
				continue
			}
			if _, exists := selected[path]; exists {
				return binaryProvenance{}, errors.New("duplicate selected dependency")
			}
			selected[path] = dep
		}
	}
	if len(selected) != len(spec.modules) {
		return binaryProvenance{}, errors.New("missing or unexpected selected dependency")
	}
	for _, path := range spec.modules {
		dep, exists := selected[path]
		if !exists {
			return binaryProvenance{}, errors.New("missing selected dependency")
		}
		module, err := inspectModule(dep)
		if err != nil {
			return binaryProvenance{}, err
		}
		result.Modules = append(result.Modules, module)
	}
	return result, nil
}

func inspectModule(dep *debug.Module) (moduleProvenance, error) {
	if !versionPattern.MatchString(dep.Version) {
		return moduleProvenance{}, errors.New("selected dependency has no valid requested version")
	}
	source := dep
	if dep.Replace != nil {
		if dep.Path == officialQUIC {
			return moduleProvenance{}, errors.New("official QUIC dependency must not be replaced")
		}
		source = dep.Replace
		if source.Replace != nil {
			return moduleProvenance{}, errors.New("nested dependency replacement is unsupported")
		}
	}
	allowedSource := source.Path == dep.Path ||
		(dep.Path == adapterQUIC && source.Path == "github.com/cppla/quic-go") ||
		(dep.Path == uTLS && source.Path == "github.com/cppla/utls")
	if !allowedSource || !versionPattern.MatchString(source.Version) {
		return moduleProvenance{}, errors.New("selected dependency has an unsupported or unversioned source")
	}
	if !strings.HasPrefix(source.Sum, "h1:") {
		return moduleProvenance{}, errors.New("selected dependency has no valid source sum")
	}
	sum, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(source.Sum, "h1:"))
	if err != nil || len(sum) != sha256.Size || "h1:"+base64.StdEncoding.EncodeToString(sum) != source.Sum {
		return moduleProvenance{}, errors.New("selected dependency has no valid source sum")
	}
	return moduleProvenance{
		ModulePath: dep.Path, RequestedVersion: dep.Version,
		SourcePath: source.Path, SourceVersion: source.Version, SourceSum: source.Sum,
		Replaced: dep.Replace != nil,
	}, nil
}
