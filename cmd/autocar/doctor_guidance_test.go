package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/tunnel"
)

func TestDoctorFailureGuidanceUsesTypedCausesAndRedactsDetails(t *testing.T) {
	const private = "private-token-and-host /private/customer/credential"
	certificate := &x509.Certificate{}
	tests := []struct {
		name      string
		code      string
		cause     error
		diagnosis string
		hintPart  string
	}{
		{"arguments", "invalid_arguments", errors.New(private), "arguments", "--help"},
		{"missing config", "invalid_arguments", &os.PathError{Op: "stat", Path: private, Err: os.ErrNotExist}, "config_file_missing", "--config"},
		{"config permission", "invalid_arguments", &os.PathError{Op: "open", Path: private, Err: os.ErrPermission}, "config_file_permission", "--config"},
		{"target", "invalid_target", errors.New(private), "target", "--target"},
		{"missing file", "configuration_failed", &os.PathError{Op: "open", Path: private, Err: os.ErrNotExist}, "file_missing", "paths"},
		{"file permission", "configuration_failed", &os.PathError{Op: "open", Path: private, Err: os.ErrPermission}, "file_permission", "world-readable"},
		{"untyped configuration", "configuration_failed", errors.New(private), "configuration", "--token-file"},
		{"cancel", "probe_failed", context.Canceled, "canceled", "canceled"},
		{"certificate trust", "probe_failed", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{Cert: certificate}}, "certificate_trust", "--ca"},
		{"certificate hostname", "probe_failed", x509.HostnameError{Certificate: certificate, Host: private}, "certificate_name", "--server-name"},
		{"certificate dates", "probe_failed", x509.CertificateInvalidError{Cert: certificate, Reason: x509.Expired, Detail: private}, "certificate_time", "clocks"},
		{"certificate usage", "probe_failed", x509.CertificateInvalidError{Cert: certificate, Reason: x509.IncompatibleUsage, Detail: private}, "certificate_invalid", "server usage"},
		{"authentication", "probe_failed", &tunnel.RemoteError{Status: protocol.StatusUnauthorized, Message: private}, "authentication_rejected", "same token"},
		{"remote target", "probe_failed", &tunnel.RemoteError{Status: protocol.StatusDialFailed, Message: private}, "target_open_failed", "from the relay"},
		{"remote capacity", "probe_failed", &tunnel.RemoteError{Status: protocol.StatusBusy, Message: private}, "relay_busy", "capacity"},
		{"remote internal", "probe_failed", &tunnel.RemoteError{Status: protocol.StatusInternal, Message: private}, "relay_rejected", "relay logs"},
		{"web rejection", "probe_failed", &tunnel.WebConnectError{Transport: private, StatusCode: 502}, "web_connect_rejected", "authenticated web relay"},
		{"dns", "probe_failed", &net.DNSError{Err: private, Name: private, Server: private, IsNotFound: true}, "dns", "DNS resolver"},
		{"dns timeout stays dns", "probe_failed", &net.DNSError{Err: private, Name: private, IsTimeout: true}, "dns", "DNS resolver"},
		{"context timeout", "probe_failed", context.DeadlineExceeded, "timeout", "--open-timeout"},
		{"network timeout", "probe_failed", &net.OpError{Op: private, Net: "tcp", Err: os.ErrDeadlineExceeded}, "timeout", "--open-timeout"},
		{"refused", "probe_failed", &net.OpError{Op: private, Net: "tcp", Err: syscall.ECONNREFUSED}, "connection_refused", "listening"},
		{"wrong protocol", "probe_failed", protocol.ErrBadMagic, "protocol_mismatch", "matching native or web"},
		{"wrong version", "probe_failed", protocol.ErrBadVersion, "protocol_mismatch", "compatible versions"},
		{"untyped error is not classified by text", "probe_failed", errors.New("x509: unknown authority; unauthorized; connection refused " + private), "unclassified", "could not be classified safely"},
		{"metadata", "metadata_unavailable", errors.New(private), "internal", "version"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Wrapping must preserve type classification but must not make any
			// source-provided text observable, including in the main error.
			cause := fmt.Errorf("%s: %w", private, test.cause)
			for _, jsonOutput := range []bool{false, true} {
				var stdout bytes.Buffer
				err := doctorFail(&stdout, jsonOutput, doctorExitProbeFailure, test.code, cause, time.Millisecond)
				if err == nil || commandExitCode(err) != doctorExitProbeFailure {
					t.Fatalf("exit=%d err=%v", commandExitCode(err), err)
				}
				if strings.Contains(stdout.String()+err.Error(), private) || errors.Is(err, cause) {
					t.Fatalf("failure leaked or retained a private cause: stdout=%q err=%v", stdout.String(), err)
				}
				if jsonOutput {
					var failure doctorFailure
					if decodeErr := json.Unmarshal(stdout.Bytes(), &failure); decodeErr != nil {
						t.Fatal(decodeErr)
					}
					if failure.Code != test.code || failure.Error != doctorFailureMessage(test.code) || err.Error() != failure.Error {
						t.Fatalf("existing code/error contract changed: %+v err=%v", failure, err)
					}
					if failure.Diagnosis != test.diagnosis || !strings.Contains(failure.Hint, test.hintPart) {
						t.Fatalf("failure=%+v, want diagnosis=%q hint containing %q", failure, test.diagnosis, test.hintPart)
					}
				} else if stdout.Len() != 0 || !strings.Contains(err.Error(), "["+test.diagnosis+"]") || !strings.Contains(err.Error(), test.hintPart) {
					t.Fatalf("human guidance stdout=%q err=%v", stdout.String(), err)
				}
			}
		})
	}
}

func TestDoctorHumanFailuresDoNotEchoArgumentsOrCauses(t *testing.T) {
	const private = "/private/customer/token-secret"
	tests := []struct {
		name string
		args []string
	}{
		{"invalid flag value", []string{"--dial-timeout=" + private}},
		{"unknown flag", []string{"--" + private}},
		{"configuration", []string{"--target", "example.com:443"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := runDoctorWith(context.Background(), test.args, &stdout, &stderr, func(tunnelFlags) (closeDialer, error) {
				return nil, &os.PathError{Op: "open", Path: private, Err: os.ErrPermission}
			})
			if err == nil || commandExitCode(err) != doctorExitUsageFailure || !strings.Contains(err.Error(), "hint:") {
				t.Fatalf("exit=%d err=%v", commandExitCode(err), err)
			}
			if strings.Contains(stdout.String()+stderr.String()+err.Error(), private) {
				t.Fatalf("private input was echoed: stdout=%q stderr=%q err=%v", stdout.String(), stderr.String(), err)
			}
		})
	}
}

func TestDoctorHumanHelpStillPrintsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := runDoctorWith(context.Background(), []string{"--help"}, &stdout, &stderr, nil)
	if !errors.Is(err, flag.ErrHelp) || stdout.Len() != 0 || !strings.Contains(stderr.String(), "Usage of doctor:") || !strings.Contains(stderr.String(), "-target") {
		t.Fatalf("stdout=%q stderr=%q err=%v", stdout.String(), stderr.String(), err)
	}
}

func TestDoctorConfigJSONAndCommandLineOverrides(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "doctor.json")
	if err := os.WriteFile(configFile, []byte(`{"server":"config.example:443","transport":"quic","target":"config-target.example:443","json":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, probeFailure := range []bool{false, true} {
		for _, overrideJSON := range []bool{false, true} {
			name := fmt.Sprintf("failure=%t/json-overridden=%t", probeFailure, overrideJSON)
			t.Run(name, func(t *testing.T) {
				args := []string{"--config", configFile, "--server", "cli.example:443", "--target", "cli-target.example:8443"}
				if overrideJSON {
					args = append(args, "--json=false")
				}
				dialer := &fakeDoctorDialer{snapshot: tunnel.ClientSnapshot{SelectedTransport: "quic"}}
				if probeFailure {
					dialer.dialErr = &tunnel.RemoteError{Status: protocol.StatusUnauthorized, Message: "private token"}
				}
				var stdout, stderr bytes.Buffer
				err := runDoctorWith(context.Background(), args, &stdout, &stderr, func(tf tunnelFlags) (closeDialer, error) {
					if tf.server != "cli.example:443" || tf.mode != "quic" {
						t.Fatalf("CLI/config flags = %+v", tf)
					}
					return dialer, nil
				})
				if (err != nil) != probeFailure || dialer.target != "cli-target.example:8443" || stderr.Len() != 0 {
					t.Fatalf("err=%v target=%q stderr=%q", err, dialer.target, stderr.String())
				}
				if !overrideJSON {
					if !json.Valid(stdout.Bytes()) {
						t.Fatalf("config JSON=true was not respected: %q", stdout.String())
					}
					if probeFailure {
						var failure doctorFailure
						if decodeErr := json.Unmarshal(stdout.Bytes(), &failure); decodeErr != nil || failure.Diagnosis != "authentication_rejected" {
							t.Fatalf("failure=%+v decode=%v", failure, decodeErr)
						}
					}
				} else if probeFailure {
					if stdout.Len() != 0 || !strings.Contains(err.Error(), "hint:") {
						t.Fatalf("CLI JSON=false failure: stdout=%q err=%v", stdout.String(), err)
					}
				} else if !strings.Contains(stdout.String(), "Authenticated relay TCP probe: OK") {
					t.Fatalf("CLI JSON=false success: stdout=%q", stdout.String())
				}
			})
		}
	}
}

type privateDoctorOutputFailure struct{}

func (privateDoctorOutputFailure) Write([]byte) (int, error) {
	return 0, errors.New("private output /private/customer/token")
}

func TestDoctorOutputFailuresDoNotLeakWriterErrors(t *testing.T) {
	for _, err := range []error{
		doctorFail(privateDoctorOutputFailure{}, true, doctorExitProbeFailure, "probe_failed", errors.New("private cause"), 0),
		writeDoctorJSON(privateDoctorOutputFailure{}, doctorResult{}),
		writeDoctorHuman(privateDoctorOutputFailure{}, doctorResult{}),
	} {
		if err == nil || strings.Contains(err.Error(), "private") {
			t.Fatalf("writer error was not redacted: %v", err)
		}
	}
}
