package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
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
	Diagnosis           string  `json:"diagnosis"`
	Hint                string  `json:"hint"`
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
	// Flag diagnostics can echo arbitrary arguments, including credentials or
	// paths. Both output modes use static failure text; help is restored below.
	fs.SetOutput(io.Discard)
	var tf tunnelFlags
	addTunnelFlags(fs, &tf)
	target := fs.String("target", "", "TCP target host:port to open through the authenticated relay (required)")
	jsonOutput := fs.Bool("json", false, "emit machine-readable JSON")
	parseErr := parseFlagsWithConfig(fs, args)
	effectiveJSON = effectiveJSON || *jsonOutput
	if err := parseErr; err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, "Usage of doctor:")
			fs.SetOutput(stderr)
			fs.PrintDefaults()
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
	publicError := doctorFailureMessage(code)
	diagnosis, hint := doctorFailureGuidance(code, err)
	if jsonOutput {
		failure := doctorFailure{
			Status:              "failed",
			Code:                code,
			Error:               publicError,
			Diagnosis:           diagnosis,
			Hint:                hint,
			ElapsedMilliseconds: durationMilliseconds(elapsed),
		}
		if encodeErr := writeDoctorJSON(stdout, failure); encodeErr != nil {
			return withExitCode(exitCode, fmt.Errorf("%s: %w", publicError, encodeErr))
		}
		// Preserve the existing JSON code/error and top-level error contract.
		return withExitCode(exitCode, errors.New(publicError))
	}
	// Never wrap the raw cause: main logs this error, and remote messages or
	// filesystem errors can contain private information in either output mode.
	return withExitCode(exitCode, fmt.Errorf("%s [%s]\n  hint: %s", publicError, diagnosis, hint))
}

// doctorFailureGuidance returns only closed, static text. Typed causes can
// narrow the next step; unstructured messages must not be parsed or echoed.
func doctorFailureGuidance(code string, err error) (string, string) {
	switch code {
	case "invalid_arguments":
		if errors.Is(err, os.ErrNotExist) {
			return "config_file_missing", "Check that the --config file exists and its path is correct."
		}
		if errors.Is(err, os.ErrPermission) {
			return "config_file_permission", "Ensure the current user can read the --config file and access its directory; do not make credential files world-readable."
		}
		return "arguments", "Run autocar doctor --help; check option names, values, and any configuration file. Positional arguments are not supported."
	case "invalid_target":
		return "target", "Set --target to a reachable TCP host:port; use [IPv6-address]:port for IPv6 and a numeric port from 1 to 65535."
	case "metadata_unavailable", "internal_error":
		return "internal", "Check autocar version on both ends and use a matching supported release. If this persists, report the doctor code and version without credentials."
	case "configuration_failed":
		if errors.Is(err, os.ErrNotExist) {
			return "file_missing", "Check that configured CA, token, and optional client certificate/key files exist and their paths are correct."
		}
		if errors.Is(err, os.ErrPermission) {
			return "file_permission", "Ensure the current user can read configured credential files. Keep token and private-key files private; do not make them world-readable."
		}
		return "configuration", "Check --server host:port, --transport, exactly one of --ca or --system-roots, and --token-file or AUTOCAR_TOKEN. Use doctor --help to check timeout and pacing options."
	}

	if errors.Is(err, context.Canceled) {
		return "canceled", "The probe was canceled. Run it again when you want to check the connection."
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return "certificate_trust", "Use the correct relay CA with --ca, or --system-roots for a publicly trusted certificate. Verify the CA through a trusted channel; do not disable certificate verification."
	}
	var hostnameError x509.HostnameError
	if errors.As(err, &hostnameError) {
		return "certificate_name", "Check that --server-name matches a DNS name or IP in the relay certificate. Connecting to an IP may require the certificate's DNS name; do not disable certificate verification."
	}
	var certificateError x509.CertificateInvalidError
	if errors.As(err, &certificateError) {
		if certificateError.Reason == x509.Expired {
			return "certificate_time", "Check the client and relay clocks and the certificate validity dates; renew an expired certificate before retrying."
		}
		return "certificate_invalid", "Check the relay certificate chain, server usage, and CA configuration; install a valid certificate instead of disabling verification."
	}
	var remoteError *tunnel.RemoteError
	if errors.As(err, &remoteError) {
		switch remoteError.Status {
		case protocol.StatusUnauthorized:
			return "authentication_rejected", "Ensure both ends use the same token from --token-file or AUTOCAR_TOKEN. Verify it locally without printing or sharing the token."
		case protocol.StatusDialFailed:
			return "target_open_failed", "The relay could not open the target. Check target DNS, port, and reachability from the relay, then its outbound policy and logs."
		case protocol.StatusBusy:
			return "relay_busy", "The relay reported a capacity limit. Check active connections, stream limits, and relay load before retrying."
		default:
			return "relay_rejected", "The relay rejected the request. Check matching versions, the target and outbound policy, and relay logs without sharing credentials."
		}
	}
	var webError *tunnel.WebConnectError
	if errors.As(err, &webError) {
		return "web_connect_rejected", "The authenticated web relay rejected CONNECT. Check target reachability, outbound policy, relay capacity, and relay logs."
	}
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		return "dns", "Check the relay hostname and the client's DNS resolver. If using a separate fallback relay, check its hostname too."
	}
	var networkError net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &networkError) && networkError.Timeout() {
		return "timeout", "Check relay and target reachability, firewall rules, and relay load. Check --dial-timeout and --open-timeout; auto modes also need --quic-attempt-timeout smaller than --open-timeout."
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection_refused", "Check the relay address and port, confirm the server is listening on the required transport, and check firewall reject rules."
	}
	if errors.Is(err, protocol.ErrBadMagic) || errors.Is(err, protocol.ErrBadVersion) || errors.Is(err, protocol.ErrBadKind) {
		return "protocol_mismatch", "Confirm the port serves AutoCAR and both ends use matching native or web modes and compatible versions."
	}
	return "unclassified", "Check relay address, certificate, matching modes and tokens, TCP/UDP firewall rules, and target reachability from the relay. For web mode, also check the public origin and matching versions. The cause could not be classified safely."
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
		return errors.New("write doctor JSON failed")
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
		return errors.New("write doctor output failed")
	}
	if result.LastTransportEvent != nil {
		if _, err := fmt.Fprintf(output, "  transport event:      %s (%s)\n", result.LastTransportEvent.Kind, result.LastTransportEvent.Reason); err != nil {
			return errors.New("write doctor output failed")
		}
	}
	return nil
}

func durationMilliseconds(value time.Duration) float64 {
	return float64(value) / float64(time.Millisecond)
}
