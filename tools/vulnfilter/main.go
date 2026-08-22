// Command vulnfilter validates govulncheck's streaming JSON output.
//
// It fails on every reachable vulnerability except GO-2026-5288 when the
// finding is for the pinned Hysteria core v2.12.1. The upstream reviewed GHSA
// marks only versions <= 2.8.1 affected, while the automatically generated Go
// report currently says that every version is affected:
//
//	https://github.com/advisories/GHSA-9fw6-xgg2-mq9q
//	https://pkg.go.dev/vuln/GO-2026-5288
//
// scripts/govulncheck.sh adds a source guard that also forbids enabling the
// vulnerable sniff feature while this narrowly scoped exception exists.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

const (
	mainModule           = "github.com/cppla/autocar"
	allowedAdvisory      = "GO-2026-5288"
	allowedModule        = "github.com/apernet/hysteria/core/v2"
	allowedModuleVersion = "v2.12.1"
)

type event struct {
	Config  *json.RawMessage `json:"config,omitempty"`
	SBOM    *json.RawMessage `json:"SBOM,omitempty"`
	Finding *finding         `json:"finding,omitempty"`
}

type finding struct {
	OSV   string  `json:"osv"`
	Trace []frame `json:"trace"`
}

type frame struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Package  string `json:"package"`
	Function string `json:"function"`
}

func main() {
	if err := validate(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "vulnerability scan:", err)
		os.Exit(1)
	}
}

func validate(input io.Reader, output io.Writer) error {
	decoder := json.NewDecoder(input)
	seenConfig := false
	seenSBOM := false
	reachable := make(map[string][]finding)
	moduleOnly := make(map[string]struct{})
	for {
		var item event
		err := decoder.Decode(&item)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("decode govulncheck JSON: %w", err)
		}
		seenConfig = seenConfig || item.Config != nil
		seenSBOM = seenSBOM || item.SBOM != nil
		if item.Finding == nil || item.Finding.OSV == "" {
			continue
		}
		if isReachable(*item.Finding) {
			reachable[item.Finding.OSV] = append(reachable[item.Finding.OSV], *item.Finding)
		} else {
			moduleOnly[item.Finding.OSV] = struct{}{}
		}
	}
	if !seenConfig || !seenSBOM {
		return errors.New("incomplete govulncheck stream (missing config or SBOM)")
	}

	delete(moduleOnly, allowedAdvisory)
	if len(moduleOnly) != 0 {
		fmt.Fprintf(output, "govulncheck: non-reachable module advisories: %s\n", strings.Join(sortedKeys(moduleOnly), ", "))
	}

	var unexpected []string
	for id, findings := range reachable {
		if id == allowedAdvisory && exactAllowedVersion(findings) {
			fmt.Fprintf(output, "govulncheck: %s suppressed only for %s %s (upstream GHSA affects <= 2.8.1; sniff disabled)\n", id, allowedModule, allowedModuleVersion)
			continue
		}
		unexpected = append(unexpected, id)
	}
	if len(unexpected) != 0 {
		sort.Strings(unexpected)
		return fmt.Errorf("reachable vulnerabilities: %s", strings.Join(unexpected, ", "))
	}
	fmt.Fprintln(output, "govulncheck: no unsuppressed reachable vulnerabilities")
	return nil
}

func isReachable(item finding) bool {
	for _, step := range item.Trace {
		if step.Module == mainModule && step.Package != "" && step.Function != "" {
			return true
		}
	}
	return false
}

func exactAllowedVersion(findings []finding) bool {
	foundModule := false
	for _, item := range findings {
		for _, step := range item.Trace {
			if step.Module != allowedModule {
				continue
			}
			foundModule = true
			if step.Version != allowedModuleVersion {
				return false
			}
		}
	}
	return foundModule
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
