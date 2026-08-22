package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestValidateAllowsOnlyPinnedFalsePositive(t *testing.T) {
	stream := `{"config":{}}
{"SBOM":{}}
{"finding":{"osv":"GO-2026-5288","trace":[{"module":"github.com/apernet/hysteria/core/v2","version":"v2.12.1","package":"github.com/apernet/hysteria/core/v2/server","function":"NewServer"},{"module":"github.com/cppla/autocar","package":"github.com/cppla/autocar/internal/hy2","function":"Listen"}]}}
{"finding":{"osv":"GO-MODULE-ONLY","trace":[{"module":"example.invalid/dependency","version":"v1.0.0"}]}}`
	var output bytes.Buffer
	if err := validate(strings.NewReader(stream), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), allowedAdvisory) || !strings.Contains(output.String(), "GO-MODULE-ONLY") {
		t.Fatalf("output = %q", output.String())
	}
}

func TestValidateRejectsUnexpectedReachableFinding(t *testing.T) {
	stream := `{"config":{}}{"SBOM":{}}{"finding":{"osv":"GO-NEW","trace":[{"module":"bad.example/mod","version":"v1.0.0","package":"bad.example/mod/p","function":"Bad"},{"module":"github.com/cppla/autocar","package":"github.com/cppla/autocar/cmd/autocar","function":"main"}]}}`
	if err := validate(strings.NewReader(stream), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "GO-NEW") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateRejectsAllowedIDAtAnotherVersion(t *testing.T) {
	stream := `{"config":{}}{"SBOM":{}}{"finding":{"osv":"GO-2026-5288","trace":[{"module":"github.com/apernet/hysteria/core/v2","version":"v2.8.1","package":"github.com/apernet/hysteria/core/v2/server","function":"NewServer"},{"module":"github.com/cppla/autocar","package":"github.com/cppla/autocar/internal/hy2","function":"Listen"}]}}`
	if err := validate(strings.NewReader(stream), &bytes.Buffer{}); err == nil {
		t.Fatal("affected Hysteria version was suppressed")
	}
}

func TestValidateRejectsIncompleteOrMalformedStream(t *testing.T) {
	for _, stream := range []string{`{"config":{}}`, `{"config":{}} nope`} {
		if err := validate(strings.NewReader(stream), &bytes.Buffer{}); err == nil {
			t.Fatalf("stream %q was accepted", stream)
		}
	}
}
