// Command notices generates THIRD_PARTY_NOTICES.md from the modules that are
// actually present in AutoCAR's linked package graph.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

const defaultOutput = "THIRD_PARTY_NOTICES.md"

type listedPackage struct {
	Module *listedModule `json:"Module"`
}

type listedModule struct {
	Path    string        `json:"Path"`
	Version string        `json:"Version"`
	Dir     string        `json:"Dir"`
	Main    bool          `json:"Main"`
	Replace *listedModule `json:"Replace"`
}

type dependency struct {
	Path        string
	Version     string
	Replacement string
	Dir         string
	Notices     []noticeFile
}

type noticeFile struct {
	Name   string
	Text   string
	SHA256 string
}

func main() {
	var (
		check  = flag.Bool("check", false, "verify that the output file is current")
		output = flag.String("out", defaultOutput, "output path, relative to the main module")
		target = flag.String("target", "./cmd/autocar", "Go package whose linked dependencies are inspected")
	)
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "notices: unexpected positional arguments")
		os.Exit(2)
	}

	if err := run(context.Background(), *target, *output, *check); err != nil {
		fmt.Fprintln(os.Stderr, "notices:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, target, output string, check bool) error {
	root, err := moduleRoot(ctx)
	if err != nil {
		return err
	}
	dependencies, err := collectDependencies(ctx, root, target)
	if err != nil {
		return err
	}
	generated, err := render(dependencies)
	if err != nil {
		return err
	}

	outputPath := output
	if !filepath.IsAbs(outputPath) {
		outputPath = filepath.Join(root, outputPath)
	}
	if check {
		current, readErr := os.ReadFile(outputPath)
		if readErr != nil {
			return fmt.Errorf("read %s: %w", filepath.Base(outputPath), readErr)
		}
		if !bytes.Equal(current, generated) {
			return fmt.Errorf("%s is stale; run `go run ./tools/notices`", filepath.Base(outputPath))
		}
		fmt.Printf("%s is current (%d linked modules)\n", filepath.Base(outputPath), len(dependencies))
		return nil
	}
	if err := os.WriteFile(outputPath, generated, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(outputPath), err)
	}
	fmt.Printf("wrote %s (%d linked modules)\n", filepath.Base(outputPath), len(dependencies))
	return nil
}

func moduleRoot(ctx context.Context) (string, error) {
	command := exec.CommandContext(ctx, "go", "env", "GOMOD")
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("locate main module: %w", err)
	}
	goMod := strings.TrimSpace(string(output))
	if goMod == "" || goMod == os.DevNull {
		return "", errors.New("not running in a Go module")
	}
	return filepath.Dir(goMod), nil
}

func collectDependencies(ctx context.Context, root, target string) ([]dependency, error) {
	command := exec.CommandContext(ctx, "go", "list", "-deps", "-json", target)
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("go list %s: %s", target, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, fmt.Errorf("go list %s: %w", target, err)
	}

	unique := make(map[string]dependency)
	decoder := json.NewDecoder(bytes.NewReader(output))
	for {
		var pkg listedPackage
		if err := decoder.Decode(&pkg); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("decode go list output: %w", err)
		}
		if pkg.Module == nil || pkg.Module.Main {
			continue
		}

		item, err := dependencyFromModule(root, pkg.Module)
		if err != nil {
			return nil, err
		}
		key := item.Path + "\x00" + item.Version + "\x00" + item.Replacement
		if previous, ok := unique[key]; ok {
			if previous.Dir != item.Dir {
				return nil, fmt.Errorf("module %s resolved to multiple directories", item.Path)
			}
			continue
		}
		unique[key] = item
	}

	dependencies := make([]dependency, 0, len(unique))
	for _, item := range unique {
		notices, err := readNotices(item.Dir)
		if err != nil {
			return nil, fmt.Errorf("module %s: %w", item.Path, err)
		}
		item.Notices = notices
		dependencies = append(dependencies, item)
	}
	sort.Slice(dependencies, func(i, j int) bool {
		if dependencies[i].Path != dependencies[j].Path {
			return dependencies[i].Path < dependencies[j].Path
		}
		if dependencies[i].Version != dependencies[j].Version {
			return dependencies[i].Version < dependencies[j].Version
		}
		return dependencies[i].Replacement < dependencies[j].Replacement
	})
	if len(dependencies) == 0 {
		return nil, errors.New("no non-main modules found in linked package graph")
	}
	return dependencies, nil
}

func dependencyFromModule(root string, module *listedModule) (dependency, error) {
	item := dependency{Path: module.Path, Version: module.Version, Dir: module.Dir}
	if module.Replace != nil {
		item.Dir = module.Replace.Dir
		item.Replacement = replacementLabel(root, module.Replace)
	}
	if item.Path == "" {
		return dependency{}, errors.New("go list returned a module without a path")
	}
	if item.Dir == "" {
		return dependency{}, fmt.Errorf("module %s has no resolved source directory", item.Path)
	}
	return item, nil
}

func replacementLabel(root string, replacement *listedModule) string {
	if replacement == nil {
		return ""
	}
	path := filepath.ToSlash(replacement.Path)
	if filepath.IsAbs(replacement.Path) {
		if relative, err := filepath.Rel(root, replacement.Path); err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			path = "./" + filepath.ToSlash(relative)
		} else {
			path = "local replacement"
		}
	}
	if replacement.Version != "" {
		return strings.TrimSpace(path + " " + replacement.Version)
	}
	return path
}

func readNotices(dir string) ([]noticeFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read module root: %w", err)
	}
	var names []string
	for _, entry := range entries {
		if !isNoticeName(entry.Name()) {
			continue
		}
		info, err := os.Stat(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", entry.Name(), err)
		}
		if info.Mode().IsRegular() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, errors.New("no root LICENSE, COPYING, NOTICE, or PATENTS file found")
	}

	notices := make([]noticeFile, 0, len(names))
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		if !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
			return nil, fmt.Errorf("%s is not a UTF-8 text file", name)
		}
		digest := sha256.Sum256(raw)
		notices = append(notices, noticeFile{
			Name:   name,
			Text:   normalizeNewlines(string(raw)),
			SHA256: hex.EncodeToString(digest[:]),
		})
	}
	return notices, nil
}

func isNoticeName(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range []string{"license", "copying", "notice", "patents"} {
		if lower == prefix || strings.HasPrefix(lower, prefix+".") || strings.HasPrefix(lower, prefix+"-") || strings.HasPrefix(lower, prefix+"_") {
			return true
		}
	}
	return false
}

func normalizeNewlines(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	return strings.TrimRight(value, "\n") + "\n"
}

func render(dependencies []dependency) ([]byte, error) {
	var output bytes.Buffer
	output.WriteString("# Third-party notices\n\n")
	output.WriteString("> Generated by `go run ./tools/notices`; do not edit by hand. CI verifies this file against the linked build graph.\n\n")
	output.WriteString("AutoCAR itself is licensed under the repository's `LICENSE`. The sections below reproduce every root-level license, notice, and patent file from each non-main Go module reached by `go list -deps -json ./cmd/autocar`. A module-level replacement is recorded so the notice always describes the source that is actually compiled.\n\n")
	output.WriteString("The SHA-256 value is calculated from the upstream file's original bytes; line endings in the displayed copy are normalized for Markdown.\n")

	for _, item := range dependencies {
		if item.Path == "" || len(item.Notices) == 0 {
			return nil, errors.New("cannot render incomplete dependency metadata")
		}
		fmt.Fprintf(&output, "\n## `%s`", item.Path)
		if item.Version != "" {
			fmt.Fprintf(&output, " `%s`", item.Version)
		}
		output.WriteString("\n\n")
		if item.Replacement != "" {
			fmt.Fprintf(&output, "Effective source replacement: `%s`.\n\n", item.Replacement)
		}
		for _, notice := range item.Notices {
			fmt.Fprintf(&output, "### `%s`\n\nSHA-256: `%s`\n\n", notice.Name, notice.SHA256)
			fence := markdownFence(notice.Text)
			fmt.Fprintf(&output, "%stext\n%s%s\n", fence, notice.Text, fence)
		}
	}

	return output.Bytes(), nil
}

func markdownFence(value string) string {
	longest, current := 0, 0
	for _, character := range value {
		if character == '`' {
			current++
			if current > longest {
				longest = current
			}
		} else {
			current = 0
		}
	}
	length := 3
	if longest >= length {
		length = longest + 1
	}
	return strings.Repeat("`", length)
}
