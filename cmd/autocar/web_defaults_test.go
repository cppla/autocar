package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"testing"

	"github.com/cppla/autocar/internal/tunnel"
)

func TestTunnelTransportDefaultAndExplicitNativeCompatibility(t *testing.T) {
	for _, test := range []struct {
		name, config, want string
		args               []string
	}{
		{name: "omitted", want: "web-auto"},
		{name: "empty config", config: `{}`, want: "web-auto"},
		{name: "native CLI", args: []string{"--transport=auto"}, want: "auto"},
		{name: "native config", config: `{"transport":"auto"}`, want: "auto"},
		{name: "CLI overrides native config", config: `{"transport":"auto"}`, args: []string{"--transport=web-auto"}, want: "web-auto"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fs := flag.NewFlagSet("client", flag.ContinueOnError)
			var flags tunnelFlags
			addTunnelFlags(fs, &flags)
			args := test.args
			if test.config != "" {
				args = append([]string{"--config", writeTestCommandConfig(t, test.config)}, args...)
			}
			if err := parseFlagsWithConfig(fs, args); err != nil {
				t.Fatal(err)
			}
			if flags.mode != test.want {
				t.Fatalf("transport=%q want=%q", flags.mode, test.want)
			}
		})
	}
}

func TestServerExplicitNativeConfigurationSurvivesDefaultChange(t *testing.T) {
	clearPreflightEnvironment(t)
	files := newPreflightFiles(t)
	for _, args := range [][]string{
		{"--protocol=native"},
		{"--config", writeTestCommandConfig(t, `{"protocol":"native"}`)},
		{"--config", writeTestCommandConfig(t, `{"protocol":"web"}`), "--protocol=native"},
	} {
		if err := runServer(context.Background(), append(files.serverArgs(), args...)); err != nil {
			t.Fatalf("explicit native configuration %v: %v", args, err)
		}
	}
}

func TestDoctorDefaultsToWebAuto(t *testing.T) {
	dialer := &fakeDoctorDialer{snapshot: tunnel.ClientSnapshot{
		SelectedTransport: "h3", ClientPacing: "not-applicable", RelayPacing: "not-applicable",
	}}
	var stdout, stderr bytes.Buffer
	err := runDoctorWith(context.Background(), []string{"--target", "target.invalid:443", "--json"}, &stdout, &stderr, func(flags tunnelFlags) (closeDialer, error) {
		if flags.mode != "web-auto" {
			t.Fatalf("doctor default transport=%q", flags.mode)
		}
		return dialer, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var result doctorResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.RequestedTransport != "web-auto" || result.SelectedTransport != "h3" || !dialer.closed {
		t.Fatalf("default doctor result=%+v closed=%t", result, dialer.closed)
	}
}
