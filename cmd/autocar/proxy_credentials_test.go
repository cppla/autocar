package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestValidateProxyCredentialsHTTPCompatibility(t *testing.T) {
	const password = "diagnostic:password:with:colons"
	for _, test := range []struct {
		name, username            string
		socksEnabled, httpEnabled bool
		wantErr                   bool
	}{
		{name: "HTTP colon username", username: "user:name", httpEnabled: true, wantErr: true},
		{name: "combined colon username", username: "user:name", socksEnabled: true, httpEnabled: true, wantErr: true},
		{name: "SOCKS-only colon username", username: "user:name", socksEnabled: true},
		{name: "HTTP colon password", username: "user", httpEnabled: true},
		{name: "combined colon password", username: "user", socksEnabled: true, httpEnabled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateProxyCredentials(test.username, password, test.socksEnabled, test.httpEnabled)
			if (err != nil) != test.wantErr {
				t.Fatalf("credential validation error = %v, want error=%t", err, test.wantErr)
			}
			if err != nil && (strings.Contains(err.Error(), test.username) || strings.Contains(err.Error(), password)) {
				t.Fatal("credential validation disclosed a credential value")
			}
		})
	}
}

func TestClientRejectsHTTPColonUsernameBeforeStartup(t *testing.T) {
	clearPreflightEnvironment(t)
	t.Setenv("AUTOCAR_PROXY_PASSWORD", "diagnostic:password:with:colons")
	files := newPreflightFiles(t)
	dnsCalls := denyPreflightDNS(t)
	for _, check := range []bool{false, true} {
		mode := "startup"
		if check {
			mode = "check"
		}
		for _, test := range []struct {
			name string
			args []string
		}{
			{name: "default HTTP and SOCKS"},
			{name: "HTTP only", args: []string{"--socks="}},
			{name: "HTTPS only", args: []string{"--socks=", "--http=", "--https=127.0.0.1:8443", "--proxy-cert", files.cert, "--proxy-key", files.key}},
		} {
			t.Run(mode+"/"+test.name, func(t *testing.T) {
				// Drop the helper's --check for the startup variant. The
				// incompatible credentials must fail before binding or dialing.
				args := append(files.clientArgs()[1:], "--proxy-user=user:name")
				args = append(args, test.args...)
				if check {
					args = append(args, "--check")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				err := runClient(ctx, args)
				if err == nil || err.Error() != "local proxy username must not contain ':' when HTTP or HTTPS is enabled" {
					t.Fatalf("client error = %v, want HTTP username compatibility error", err)
				}
			})
		}
	}
	if dnsCalls.Load() != 0 {
		t.Fatal("invalid local credentials triggered DNS")
	}
}

func TestClientCheckPreservesColonCredentialCompatibility(t *testing.T) {
	clearPreflightEnvironment(t)
	t.Setenv("AUTOCAR_PROXY_PASSWORD", "diagnostic:password:with:colons")
	files := newPreflightFiles(t)
	dnsCalls := denyPreflightDNS(t)
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "SOCKS-only colon username", args: []string{"--http=", "--proxy-user=user:name"}},
		{name: "HTTP colon password", args: []string{"--socks=", "--proxy-user=user"}},
		{name: "HTTPS colon password", args: []string{"--socks=", "--http=", "--https=127.0.0.1:8443", "--proxy-user=user", "--proxy-cert", files.cert, "--proxy-key", files.key}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := runClient(context.Background(), append(files.clientArgs(), test.args...)); err != nil {
				t.Fatalf("compatible local credentials rejected: %v", err)
			}
		})
	}
	if dnsCalls.Load() != 0 {
		t.Fatal("local credential checks triggered DNS")
	}
}
