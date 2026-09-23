package main

import (
	"context"
	"flag"
	"io"
	"strings"
	"testing"
	"time"
)

func TestH2WriteTimeoutFlagAndConfig(t *testing.T) {
	for _, test := range []struct {
		name   string
		config string
		args   []string
		want   time.Duration
	}{
		{name: "default", want: 30 * time.Second},
		{name: "CLI", args: []string{"--h2-write-timeout=90s"}, want: 90 * time.Second},
		{name: "zero selects default", args: []string{"--h2-write-timeout=0"}, want: 0},
		{name: "JSON", config: `{"h2-write-timeout":"2m"}`, want: 2 * time.Minute},
		{name: "CLI overrides JSON", config: `{"h2-write-timeout":"2m"}`, args: []string{"--h2-write-timeout=45s"}, want: 45 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			var flags tunnelFlags
			addTunnelFlags(fs, &flags)
			args := test.args
			if test.config != "" {
				args = append([]string{"--config", writeTestCommandConfig(t, test.config)}, args...)
			}
			if err := parseFlagsWithConfig(fs, args); err != nil {
				t.Fatal(err)
			}
			if flags.h2WriteTimeout != test.want {
				t.Fatalf("H2 write timeout = %v, want %v", flags.h2WriteTimeout, test.want)
			}
			if flags.openTimeout != 15*time.Second || flags.dialTimeout != 5*time.Second {
				t.Fatal("H2 write timeout changed unrelated setup timeouts")
			}
		})
	}
}

func TestH2WriteTimeoutConfigRejectsMalformedValues(t *testing.T) {
	for _, value := range []string{`12`, `null`, `"secret-invalid-duration"`} {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var flags tunnelFlags
		addTunnelFlags(fs, &flags)
		path := writeTestCommandConfig(t, `{"h2-write-timeout":`+value+`}`)
		err := parseFlagsWithConfig(fs, []string{"--config", path, "--h2-write-timeout=30s"})
		if err == nil || strings.Contains(err.Error(), "secret-invalid-duration") {
			t.Fatalf("malformed duration must fail without leaking its value: %v", err)
		}
	}
}

func TestH2WriteTimeoutPreflight(t *testing.T) {
	clearPreflightEnvironment(t)
	files := newPreflightFiles(t)
	dnsCalls := denyPreflightDNS(t)
	for _, mode := range []string{"h2", "web-auto"} {
		for _, value := range []string{"0", "125ms", "2m", "-1s"} {
			t.Run(mode+"/"+value, func(t *testing.T) {
				args := append(files.clientArgs(), "--transport", mode, "--h2-write-timeout="+value)
				err := runClient(context.Background(), args)
				if value == "-1s" {
					if err == nil || !strings.Contains(err.Error(), "--h2-write-timeout") {
						t.Fatalf("negative timeout error = %v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	if got := dnsCalls.Load(); got != 0 {
		t.Fatalf("offline H2 checks attempted %d DNS connections", got)
	}
}

func TestH2WriteTimeoutHelp(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var output strings.Builder
	fs.SetOutput(&output)
	var flags tunnelFlags
	addTunnelFlags(fs, &flags)
	fs.PrintDefaults()
	for _, want := range []string{"h2-write-timeout", "h2/web-auto only", "0 uses 30s", "not an idle or per-stream timeout"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("help omitted %q", want)
		}
	}
}
