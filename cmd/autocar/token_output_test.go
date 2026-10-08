package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestTokenCommandRejectsClosedStdout(t *testing.T) {
	closed, err := os.CreateTemp(t.TempDir(), "closed-stdout")
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}

	err = runTokenWith(nil, closed)
	if err == nil || commandExitCode(err) != 1 {
		t.Fatal("token reported success despite closed stdout")
	}
}

type tokenOutputFailure struct {
	short bool
	calls int
}

func (w *tokenOutputFailure) Write(p []byte) (int, error) {
	w.calls++
	if w.short {
		return len(p) - 1, nil
	}
	return 0, fmt.Errorf("private writer diagnostic with credential: %s", p)
}

func TestTokenCommandRejectsOutputFailureWithoutLeakingSecrets(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(strconv.FormatBool(short), func(t *testing.T) {
			output := &tokenOutputFailure{short: short}
			err := runTokenWith(nil, output)
			if err == nil || commandExitCode(err) != 1 {
				t.Fatal("failed or incomplete credential output must fail the command")
			}
			if err.Error() != "could not write token to stdout" {
				t.Fatal("output failure did not return the fixed, secret-free diagnostic")
			}
			if output.calls != 1 {
				t.Fatalf("output calls = %d, want one attempt without retry", output.calls)
			}
		})
	}
}

func TestTokenCommandStdoutFormat(t *testing.T) {
	for _, size := range []int{16, 32, 128} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			var output strings.Builder
			if err := runTokenWith([]string{"--bytes", strconv.Itoa(size)}, &output); err != nil {
				t.Fatal(err)
			}
			value := output.String()
			if !strings.HasSuffix(value, "\n") || strings.Count(value, "\n") != 1 {
				t.Fatal("stdout must contain exactly one newline-terminated token")
			}
			decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSuffix(value, "\n"))
			if err != nil || len(decoded) != size {
				t.Fatal("stdout token is not the requested raw URL-safe base64 payload")
			}
		})
	}
}

func TestTokenCommandFileDoesNotWriteStdout(t *testing.T) {
	output := &tokenOutputFailure{}
	path := filepath.Join(t.TempDir(), "token")
	if err := runTokenWith([]string{"--out", path}, output); err != nil {
		t.Fatal(err)
	}
	if output.calls != 0 {
		t.Fatal("file output unexpectedly also wrote the credential to stdout")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
