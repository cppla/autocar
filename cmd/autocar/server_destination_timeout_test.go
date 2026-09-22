package main

import (
	"context"
	"flag"
	"io"
	"strings"
	"testing"
	"time"
)

func TestServerDestinationWriteTimeoutCLIAndCheck(t *testing.T) {
	clearPreflightEnvironment(t)
	files := newPreflightFiles(t)
	dnsCalls := denyPreflightDNS(t)
	for _, mode := range []string{"native", "web"} {
		for _, value := range []string{"", "0s", "37ms", "8m"} {
			t.Run(mode+"/"+value, func(t *testing.T) {
				args := append(files.serverArgs(), "--protocol", mode)
				if mode == "web" {
					args = append(args, "--cover-root", files.cover)
				}
				if value != "" {
					args = append(args, "--destination-write-timeout", value)
				}
				if err := runServer(context.Background(), args); err != nil {
					t.Fatal(err)
				}
			})
		}
		for _, check := range []string{"true", "false"} {
			args := append(files.serverArgs(), "--protocol", mode, "--check="+check, "--destination-write-timeout=-1s")
			if mode == "web" {
				args = append(args, "--cover-root", files.cover)
			}
			if err := runServer(context.Background(), args); err == nil || !strings.Contains(err.Error(), "--destination-write-timeout") {
				t.Fatalf("%s check=%s accepted negative timeout: %v", mode, check, err)
			}
		}
	}
	if got := dnsCalls.Load(); got != 0 {
		t.Fatalf("local timeout checks attempted %d DNS operations", got)
	}
}

func TestServerDestinationWriteTimeoutJSON(t *testing.T) {
	clearPreflightEnvironment(t)
	files := newPreflightFiles(t)
	for _, mode := range []string{"native", "web"} {
		for _, value := range []string{`"0s"`, `"37ms"`, `"-1s"`, `0`, `300`, `true`, `"bad-duration"`} {
			t.Run(mode+"/"+value, func(t *testing.T) {
				path := writeTestCommandConfig(t, `{"destination-write-timeout":`+value+`}`)
				args := append(files.serverArgs(), "--protocol", mode, "--config", path)
				if mode == "web" {
					args = append(args, "--cover-root", files.cover)
				}
				err := runServer(context.Background(), args)
				valid := value == `"0s"` || value == `"37ms"`
				if (err == nil) != valid {
					t.Fatalf("duration %s: error=%v valid=%t", value, err, valid)
				}
			})
		}
	}
}

func TestDestinationWriteTimeoutConfigPrecedence(t *testing.T) {
	path := writeTestCommandConfig(t, `{"destination-write-timeout":"37s"}`)
	for _, test := range []struct {
		args []string
		want time.Duration
	}{
		{nil, 5 * time.Minute},
		{[]string{"--config", path}, 37 * time.Second},
		{[]string{"--config", path, "--destination-write-timeout=9s"}, 9 * time.Second},
		{[]string{"--config", path, "--destination-write-timeout=0s"}, 0},
	} {
		fs := flag.NewFlagSet("server", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		value := fs.Duration("destination-write-timeout", 5*time.Minute, "")
		if err := parseFlagsWithConfig(fs, test.args); err != nil {
			t.Fatal(err)
		}
		if *value != test.want {
			t.Fatalf("timeout=%s want=%s", *value, test.want)
		}
	}
	for _, value := range []string{`0`, `"invalid"`} {
		path := writeTestCommandConfig(t, `{"destination-write-timeout":`+value+`}`)
		fs := flag.NewFlagSet("server", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		fs.Duration("destination-write-timeout", 5*time.Minute, "")
		if err := parseFlagsWithConfig(fs, []string{"--config", path, "--destination-write-timeout=9s"}); err == nil {
			t.Fatal("invalid config type/format was hidden by CLI override")
		}
	}
}

func TestDestinationWriteTimeoutConfigIsServerOnly(t *testing.T) {
	path := writeTestCommandConfig(t, `{"destination-write-timeout":"30s"}`)
	if err := runClient(context.Background(), []string{"--config", path}); err == nil || !strings.Contains(err.Error(), "unknown or unsupported config option") {
		t.Fatalf("client accepted the server-only destination timeout: %v", err)
	}
}
