package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/tunnel"
)

const (
	doctorExitProbeFailure = 1
	doctorExitUsageFailure = 2
)

type doctorResult struct {
	Status                         string              `json:"status"`
	Probe                          string              `json:"probe"`
	RequestedTransport             string              `json:"requested_transport"`
	SelectedTransport              string              `json:"selected_transport"`
	ClientPacing                   string              `json:"client_pacing"`
	ClientNegotiatedBytesPerSecond uint64              `json:"client_negotiated_bytes_per_second"`
	RelayPacing                    string              `json:"relay_pacing"`
	RelayNegotiatedBytesPerSecond  uint64              `json:"relay_negotiated_bytes_per_second"`
	ElapsedMilliseconds            float64             `json:"elapsed_ms"`
	LastTransportEvent             *tunnel.ClientEvent `json:"last_transport_event,omitempty"`
}

type doctorFailure struct {
	Status              string  `json:"status"`
	Code                string  `json:"code"`
	Error               string  `json:"error"`
	ElapsedMilliseconds float64 `json:"elapsed_ms,omitempty"`
}

type doctorDialerBuilder func(tunnelFlags) (closeDialer, error)

type doctorSnapshotReporter interface {
	Snapshot() tunnel.ClientSnapshot
}

func runDoctor(parent context.Context, args []string) error {
	return runDoctorWith(parent, args, os.Stdout, os.Stderr, buildTunnelDialer)
}

func runDoctorWith(parent context.Context, args []string, stdout, stderr io.Writer, build doctorDialerBuilder) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	effectiveJSON := doctorJSONRequested(args)
	if effectiveJSON {
		// JSON mode keeps flag package diagnostics (which can echo arbitrary
		// arguments) out of stderr and returns the closed failure schema below.
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	var tf tunnelFlags
	addTunnelFlags(fs, &tf)
	target := fs.String("target", "", "TCP target host:port to open through the authenticated relay (required)")
	jsonOutput := fs.Bool("json", false, "emit machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if effectiveJSON {
				// The pre-scan suppresses FlagSet output to keep malformed JSON-mode
				// arguments out of diagnostics. Help is static and safe, so restore
				// the normal human-readable command help instead of succeeding
				// silently for `doctor --json -h`.
				fmt.Fprintln(stderr, "Usage of doctor:")
				fs.SetOutput(stderr)
				fs.PrintDefaults()
			}
			return err
		}
		return doctorFail(stdout, effectiveJSON, doctorExitUsageFailure, "invalid_arguments", err, 0)
	}
	if fs.NArg() != 0 {
		return doctorFail(stdout, effectiveJSON, doctorExitUsageFailure, "invalid_arguments", errors.New("doctor does not accept positional arguments"), 0)
	}
	normalizedTarget := strings.TrimSpace(*target)
	if err := validateDoctorTarget(normalizedTarget); err != nil {
		return doctorFail(stdout, effectiveJSON, doctorExitUsageFailure, "invalid_target", err, 0)
	}
	if build == nil {
		return doctorFail(stdout, effectiveJSON, doctorExitProbeFailure, "internal_error", errors.New("tunnel dialer builder is unavailable"), 0)
	}

	dialer, err := build(tf)
	if err != nil {
		return doctorFail(stdout, effectiveJSON, doctorExitUsageFailure, "configuration_failed", fmt.Errorf("configure authenticated tunnel: %w", err), 0)
	}
	defer dialer.Close()

	probeCtx, cancel := context.WithTimeout(parent, tf.openTimeout)
	started := time.Now()
	conn, err := dialer.DialContext(probeCtx, "tcp", normalizedTarget)
	elapsed := time.Since(started)
	cancel()
	if err != nil {
		return doctorFail(stdout, effectiveJSON, doctorExitProbeFailure, "probe_failed", fmt.Errorf("authenticated tunnel TCP open failed: %w", err), elapsed)
	}
	if conn == nil {
		return doctorFail(stdout, effectiveJSON, doctorExitProbeFailure, "probe_failed", errors.New("authenticated tunnel returned no TCP connection"), elapsed)
	}
	_ = conn.Close()

	reporter, ok := dialer.(doctorSnapshotReporter)
	if !ok {
		return doctorFail(stdout, effectiveJSON, doctorExitProbeFailure, "metadata_unavailable", errors.New("authenticated tunnel opened but did not expose transport metadata"), elapsed)
	}
	snapshot := reporter.Snapshot()
	if snapshot.SelectedTransport == "" {
		return doctorFail(stdout, effectiveJSON, doctorExitProbeFailure, "metadata_unavailable", errors.New("authenticated tunnel opened but selected transport is unknown"), elapsed)
	}
	result := doctorResult{
		Status:                         "ok",
		Probe:                          "authenticated_tcp_open",
		RequestedTransport:             strings.ToLower(strings.TrimSpace(tf.mode)),
		SelectedTransport:              snapshot.SelectedTransport,
		ClientPacing:                   snapshot.ClientPacing,
		ClientNegotiatedBytesPerSecond: snapshot.ClientNegotiatedBytesPerSecond,
		RelayPacing:                    snapshot.RelayPacing,
		RelayNegotiatedBytesPerSecond:  snapshot.RelayNegotiatedBytesPerSecond,
		ElapsedMilliseconds:            durationMilliseconds(elapsed),
		LastTransportEvent:             snapshot.LastEvent,
	}
	// Failure handling remains fail-closed when an affirmative JSON flag was
	// swallowed by another argument or lies beyond flag's stopping point. Once
	// the probe succeeds, flag's actual last-value-wins result controls output.
	effectiveJSON = *jsonOutput
	if effectiveJSON {
		return writeDoctorJSON(stdout, result)
	}
	return writeDoctorHuman(stdout, result)
}

// doctorJSONRequested is a privacy-oriented parse-error pre-scan. Any
// syntactically affirmative JSON flag opts into redacted diagnostics, even if
// another malformed argument makes flag.Parse stop before reaching it or a
// string flag consumes it as a value. Explicit false values never override an
// affirmative flag during this safety scan. The actual flag value controls a
// successful result.
func doctorJSONRequested(args []string) bool {
	for _, argument := range args {
		switch argument {
		case "--json", "-json":
			return true
		}
		name, value, found := strings.Cut(argument, "=")
		if !found || (name != "--json" && name != "-json") {
			continue
		}
		parsed, err := strconv.ParseBool(value)
		if err != nil || parsed {
			return true
		}
	}
	return false
}

func validateDoctorTarget(target string) error {
	if target == "" {
		return errors.New("--target is required")
	}
	if len(target) > protocol.MaxAddressLength {
		return fmt.Errorf("invalid --target; address exceeds %d bytes", protocol.MaxAddressLength)
	}
	if strings.ContainsAny(target, "\x00\r\n\t") {
		return errors.New("invalid --target; control characters are not allowed")
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(host) != host {
		return errors.New("invalid --target; want host:port (IPv6 addresses must use brackets)")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return errors.New("invalid --target; port must be an integer from 1 through 65535")
	}
	return nil
}

func doctorFail(stdout io.Writer, jsonOutput bool, exitCode int, code string, err error, elapsed time.Duration) error {
	if jsonOutput {
		publicError := doctorFailureMessage(code)
		failure := doctorFailure{
			Status:              "failed",
			Code:                code,
			Error:               publicError,
			ElapsedMilliseconds: durationMilliseconds(elapsed),
		}
		if encodeErr := writeDoctorJSON(stdout, failure); encodeErr != nil {
			return withExitCode(exitCode, fmt.Errorf("%s: %w", publicError, encodeErr))
		}
		// JSON is a privacy-preserving automation contract. Keep raw transport
		// errors, remote messages and local filesystem paths out of both the JSON
		// document and the top-level error subsequently logged by main.
		return withExitCode(exitCode, errors.New(publicError))
	}
	return withExitCode(exitCode, err)
}

func doctorFailureMessage(code string) string {
	switch code {
	case "invalid_arguments":
		return "invalid doctor arguments"
	case "invalid_target":
		return "target must be a valid host:port"
	case "configuration_failed":
		return "local tunnel configuration failed"
	case "probe_failed":
		return "authenticated tunnel TCP open failed"
	case "metadata_unavailable":
		return "authenticated tunnel opened but transport metadata is unavailable"
	case "internal_error":
		return "doctor internal error"
	default:
		return "doctor failed"
	}
}

func writeDoctorJSON(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("write doctor JSON: %w", err)
	}
	return nil
}

func writeDoctorHuman(output io.Writer, result doctorResult) error {
	if _, err := fmt.Fprintf(output,
		"Authenticated relay TCP probe: OK\n"+
			"  requested transport: %s\n"+
			"  selected transport:  %s\n"+
			"  client pacing:        %s (%d bytes/s)\n"+
			"  relay pacing:         %s (%d bytes/s)\n"+
			"  elapsed:              %.3f ms\n",
		result.RequestedTransport,
		result.SelectedTransport,
		result.ClientPacing,
		result.ClientNegotiatedBytesPerSecond,
		result.RelayPacing,
		result.RelayNegotiatedBytesPerSecond,
		result.ElapsedMilliseconds,
	); err != nil {
		return fmt.Errorf("write doctor output: %w", err)
	}
	if result.LastTransportEvent != nil {
		if _, err := fmt.Fprintf(output, "  transport event:      %s (%s)\n", result.LastTransportEvent.Kind, result.LastTransportEvent.Reason); err != nil {
			return fmt.Errorf("write doctor output: %w", err)
		}
	}
	return nil
}

func durationMilliseconds(value time.Duration) float64 {
	return float64(value) / float64(time.Millisecond)
}
