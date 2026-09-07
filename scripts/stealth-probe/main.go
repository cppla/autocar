// Command stealth-probe provides independent, reproducible black-box probes for
// AutoCAR's web-cover transport. It intentionally lives outside cmd/autocar so
// release binaries do not contain test-only credential generation or lab
// forwarding code.
package main

import (
	"bufio"
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cppla/autocar/internal/cover"
	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/tunnel"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

const (
	webAuthVersion       = byte(1)
	webAuthKeyInfo       = "autocar web-cover auth v1"
	webAuthTranscript    = "autocar web-cover request v1"
	webAuthPaddingOffset = 45
	webAuthMinPadding    = 206
	webAuthMaxPadding    = 1453
	webAuthMinTicket     = webAuthPaddingOffset + webAuthMinPadding + sha256.Size
	defaultRequestLimit  = 1 << 20
	defaultRequestTimout = 8 * time.Second
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "active":
		err = runActive(os.Args[2:])
	case "cover-server":
		err = runCoverServer(os.Args[2:])
	case "origin":
		err = runOrigin(os.Args[2:])
	case "echo-server":
		err = runEchoServer(os.Args[2:])
	case "gateway":
		err = runGateway(os.Args[2:])
	case "transition":
		err = runTransition(os.Args[2:])
	case "fetch":
		err = runFetch(os.Args[2:])
	case "gateway-control":
		err = runGatewayControl(os.Args[2:])
	case "help", "-h", "--help":
		usage()
		return
	default:
		usage()
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		log.Printf("stealth-probe: %v", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `stealth-probe - AutoCAR web-cover release-gate helper

Commands:
  active        compare H1/H2/H3 probe responses with a cover-only control
  cover-server  serve the same reverse-proxied cover over H1/H2/H3
  origin        serve deterministic ordinary cover content over plain HTTP
  echo-server   serve a counted TCP echo target and an HTTP count endpoint
  gateway       forward TCP while independently blackholing/forwarding UDP
  transition    prove one WebClient transitions H3 -> H2 -> H3
	  fetch         perform one direct or HTTP-proxied request
	  gateway-control change or inspect a lab gateway's UDP state`)
}

type responseEvidence struct {
	OK         bool        `json:"ok"`
	Protocol   string      `json:"protocol,omitempty"`
	TLSVersion string      `json:"tls_version,omitempty"`
	ALPN       string      `json:"alpn,omitempty"`
	Status     int         `json:"status,omitempty"`
	Headers    []string    `json:"headers,omitempty"`
	BodySHA256 string      `json:"body_sha256,omitempty"`
	BodyBytes  int         `json:"body_bytes,omitempty"`
	LatencyMS  float64     `json:"latency_ms"`
	ErrorClass string      `json:"error_class,omitempty"`
	Body       []byte      `json:"-"`
	RawHeaders http.Header `json:"-"`
}

type activeRecord struct {
	Type       string            `json:"type"`
	Product    string            `json:"product"`
	Iteration  int               `json:"iteration"`
	Protocol   string            `json:"protocol"`
	Probe      string            `json:"probe"`
	First      string            `json:"first,omitempty"`
	Relay      responseEvidence  `json:"relay"`
	Control    *responseEvidence `json:"control,omitempty"`
	Equivalent *bool             `json:"equivalent,omitempty"`
	MarkerLeak []string          `json:"marker_leak,omitempty"`
	Passed     bool              `json:"passed"`
	Detail     string            `json:"detail,omitempty"`
}

type activeSummary struct {
	Type                string `json:"type"`
	Status              string `json:"status"`
	Product             string `json:"product"`
	Seed                int64  `json:"seed"`
	Iterations          int    `json:"iterations"`
	ProbeRecords        int    `json:"probe_records"`
	EquivalentRecords   int    `json:"equivalent_records"`
	FailedRecords       int    `json:"failed_records"`
	MarkerLeaks         int    `json:"marker_leaks"`
	NegativeDialDelta   int64  `json:"negative_dial_delta"`
	AuthenticatedDials  int64  `json:"authenticated_dials,omitempty"`
	MinimumReleaseRuns  int    `json:"minimum_release_runs"`
	ReleaseSampleSizeOK bool   `json:"release_sample_size_ok"`
}

type activeOptions struct {
	product      string
	relay        string
	control      string
	serverName   string
	caFile       string
	tokenFile    string
	target       string
	dialCountURL string
	output       string
	iterations   int
	seed         int64
	releaseGate  bool
	isolatedLab  bool
	protocols    string
	allowNets    stringListFlag
	quietWindow  time.Duration
}

func runActive(args []string) error {
	fs := flag.NewFlagSet("active", flag.ContinueOnError)
	var opts activeOptions
	fs.StringVar(&opts.product, "product", "autocar", "autocar or hysteria2")
	fs.StringVar(&opts.relay, "relay", "", "relay host:port")
	fs.StringVar(&opts.control, "control", "", "cover-only control host:port")
	fs.StringVar(&opts.serverName, "server-name", "", "TLS SNI and certificate name")
	fs.StringVar(&opts.caFile, "ca", "", "PEM trust anchor")
	fs.StringVar(&opts.tokenFile, "token-file", "", "AutoCAR token file (autocar only)")
	fs.StringVar(&opts.target, "target", "", "counted echo target host:port (autocar only)")
	fs.StringVar(&opts.dialCountURL, "dial-count-url", "", "echo target count endpoint (autocar only)")
	fs.StringVar(&opts.output, "output", "", "JSONL evidence output (required)")
	fs.IntVar(&opts.iterations, "iterations", 1, "independent new-connection repetitions")
	fs.Int64Var(&opts.seed, "seed", 20260904, "request ordering seed")
	fs.BoolVar(&opts.releaseGate, "release-gate", false, "require at least 100 iterations")
	fs.BoolVar(&opts.isolatedLab, "isolated-lab", false, "confirm and enforce private/loopback lab endpoints")
	fs.StringVar(&opts.protocols, "protocols", "h1,h2,h3", "comma-separated compatibility protocols")
	fs.Var(&opts.allowNets, "allow-net", "repeatable exact private/loopback IP or CIDR allowed in the isolated lab")
	fs.DurationVar(&opts.quietWindow, "negative-quiet-window", 100*time.Millisecond, "per-request no-dial observation window")
	if err := fs.Parse(args); err != nil {
		return err
	}
	opts.product = strings.ToLower(strings.TrimSpace(opts.product))
	if opts.product != "autocar" && opts.product != "hysteria2" {
		return errors.New("--product must be autocar or hysteria2")
	}
	for name, value := range map[string]string{
		"--relay": opts.relay, "--control": opts.control, "--server-name": opts.serverName,
		"--ca": opts.caFile, "--output": opts.output,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if opts.iterations < 1 {
		return errors.New("--iterations must be positive")
	}
	if !opts.isolatedLab {
		return errors.New("active compatibility checks require --isolated-lab")
	}
	if opts.quietWindow <= 0 {
		return errors.New("--negative-quiet-window must be positive")
	}
	if opts.releaseGate && opts.quietWindow < 100*time.Millisecond {
		return errors.New("--release-gate requires --negative-quiet-window >= 100ms")
	}
	allowlist, err := parseIsolatedAllowlist(opts.allowNets)
	if err != nil {
		return err
	}
	for name, endpoint := range map[string]*string{"relay": &opts.relay, "control": &opts.control} {
		frozen, freezeErr := freezeIsolatedHostPort(*endpoint, allowlist)
		if freezeErr != nil {
			return fmt.Errorf("%s endpoint: %w", name, freezeErr)
		}
		*endpoint = frozen
	}
	if opts.releaseGate && opts.iterations < 100 {
		return errors.New("--release-gate requires --iterations >= 100")
	}
	protocols, err := parseProbeProtocols(opts.protocols)
	if err != nil {
		return err
	}
	if opts.releaseGate && strings.Join(protocols, ",") != "h1,h2,h3" {
		return errors.New("--release-gate requires --protocols=h1,h2,h3")
	}
	if opts.product == "autocar" {
		for name, value := range map[string]string{
			"--token-file": opts.tokenFile, "--target": opts.target, "--dial-count-url": opts.dialCountURL,
		} {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("%s is required for --product=autocar", name)
			}
		}
		frozenTarget, freezeErr := freezeIsolatedHostPort(opts.target, allowlist)
		if freezeErr != nil {
			return fmt.Errorf("target endpoint: %w", freezeErr)
		}
		opts.target = frozenTarget
		frozenCountURL, freezeErr := freezeIsolatedURL(opts.dialCountURL, allowlist)
		if freezeErr != nil {
			return fmt.Errorf("dial-count endpoint: %w", freezeErr)
		}
		opts.dialCountURL = frozenCountURL
	}

	baseTLS, err := loadClientTLS(opts.caFile, opts.serverName)
	if err != nil {
		return err
	}
	var token string
	if opts.product == "autocar" {
		token, err = readSecret(opts.tokenFile)
		if err != nil {
			return err
		}
	}
	out, err := os.OpenFile(opts.output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open evidence output: %w", err)
	}
	defer out.Close()
	encoder := json.NewEncoder(out)
	rng := newLockedRand(opts.seed)

	summary := activeSummary{
		Type: "summary", Product: opts.product, Seed: opts.seed, Iterations: opts.iterations,
		MinimumReleaseRuns: 100, ReleaseSampleSizeOK: opts.iterations >= 100,
	}
	writeRecord := func(record activeRecord) error {
		summary.ProbeRecords++
		if record.Equivalent != nil && *record.Equivalent {
			summary.EquivalentRecords++
		}
		if !record.Passed {
			summary.FailedRecords++
		}
		summary.MarkerLeaks += len(record.MarkerLeak)
		return encoder.Encode(record)
	}

	negativeStart := int64(0)
	if opts.product == "autocar" {
		negativeStart, err = readDialCount(opts.dialCountURL)
		if err != nil {
			return err
		}
	}

	for iteration := 1; iteration <= opts.iterations; iteration++ {
		for _, protocolName := range protocols {
			probes := genericProbes(opts.product, protocolName, iteration, opts.target)
			for _, probe := range probes {
				before := int64(0)
				countNoDial := opts.product == "autocar" && isNoDialProbe(probe)
				if countNoDial {
					before, err = readDialCount(opts.dialCountURL)
					if err != nil {
						return err
					}
				}
				record := runProbePair(opts, baseTLS, rng, iteration, protocolName, probe)
				if countNoDial {
					after, stable, countErr := confirmDialCountStable(opts.dialCountURL, before, opts.quietWindow)
					if countErr != nil {
						return countErr
					}
					if !stable {
						record.Passed = false
						record.Detail = fmt.Sprintf("unauthenticated request opened the counted target: before=%d after=%d quiet_window=%s", before, after, opts.quietWindow)
					}
				}
				if err := writeRecord(record); err != nil {
					return err
				}
			}
		}
	}

	if opts.product == "autocar" {
		negativeEnd, countErr := readDialCount(opts.dialCountURL)
		if countErr != nil {
			return countErr
		}
		summary.NegativeDialDelta = negativeEnd - negativeStart
		if summary.NegativeDialDelta != 0 {
			summary.FailedRecords++
			if err := encoder.Encode(map[string]any{
				"type": "invariant", "name": "negative_probes_do_not_dial", "passed": false,
				"before": negativeStart, "after": negativeEnd,
			}); err != nil {
				return err
			}
		}

		for iteration := 1; iteration <= opts.iterations; iteration++ {
			for _, protocolName := range []string{"h2", "h3"} {
				before, countErr := readDialCount(opts.dialCountURL)
				if countErr != nil {
					return countErr
				}
				bearer, ticketErr := makeWebBearer(token, protocolName, opts.target, time.Now(), rand.Reader)
				if ticketErr != nil {
					return ticketErr
				}
				valid := probeSpec{name: "authenticated-connect", method: http.MethodConnect, authority: opts.target, header: bearer}
				validEvidence := performProbe(protocolName, opts.relay, opts.serverName, baseTLS, valid)
				afterValid, countErr := waitDialCount(opts.dialCountURL, before+1, 2*time.Second)
				if countErr != nil {
					return countErr
				}
				validPassed := validEvidence.OK && validEvidence.Status == http.StatusOK && afterValid == before+1
				validRecord := activeRecord{
					Type: "probe", Product: opts.product, Iteration: iteration, Protocol: protocolName,
					Probe: valid.name, Relay: validEvidence, Passed: validPassed,
				}
				validRecord.MarkerLeak = responseMarkerLeaks(opts.product, validEvidence, bearer)
				if !validPassed {
					validRecord.Detail = fmt.Sprintf("authenticated CONNECT status/count mismatch: before=%d after=%d", before, afterValid)
				}
				if err := writeRecord(validRecord); err != nil {
					return err
				}
				summary.AuthenticatedDials += afterValid - before

				replay := probeSpec{name: "replayed-connect", method: http.MethodConnect, authority: opts.target, header: bearer}
				record := runProbePair(opts, baseTLS, rng, iteration, protocolName, replay)
				afterReplay, stable, countErr := confirmDialCountStable(opts.dialCountURL, afterValid, opts.quietWindow)
				if countErr != nil {
					return countErr
				}
				if !stable {
					record.Passed = false
					record.Detail = fmt.Sprintf("replayed credential opened the counted target: before=%d after=%d quiet_window=%s", afterValid, afterReplay, opts.quietWindow)
				}
				if err := writeRecord(record); err != nil {
					return err
				}
			}
		}
	}

	if summary.FailedRecords == 0 && summary.MarkerLeaks == 0 && (!opts.releaseGate || summary.ReleaseSampleSizeOK) {
		summary.Status = "pass"
	} else {
		summary.Status = "fail"
	}
	if err := encoder.Encode(summary); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	printed, _ := json.Marshal(summary)
	fmt.Println(string(printed))
	if summary.Status != "pass" {
		return fmt.Errorf("active-probe gate failed with %d failed records and %d marker leaks", summary.FailedRecords, summary.MarkerLeaks)
	}
	return nil
}

func parseProbeProtocols(value string) ([]string, error) {
	requested := make(map[string]bool)
	for _, item := range strings.Split(value, ",") {
		item = strings.ToLower(strings.TrimSpace(item))
		if item != "h1" && item != "h2" && item != "h3" {
			return nil, fmt.Errorf("unsupported compatibility protocol %q", item)
		}
		requested[item] = true
	}
	var result []string
	for _, item := range []string{"h1", "h2", "h3"} {
		if requested[item] {
			result = append(result, item)
		}
	}
	if len(result) == 0 {
		return nil, errors.New("--protocols must select at least one protocol")
	}
	return result, nil
}

type probeSpec struct {
	name      string
	method    string
	path      string
	authority string
	header    string
	headers   http.Header
}

func genericProbes(product, protocolName string, iteration int, countedTarget string) []probeSpec {
	probes := []probeSpec{
		{name: "get", method: http.MethodGet, path: fmt.Sprintf("/news/%d?q=web", iteration)},
		{name: "head", method: http.MethodHead, path: "/assets/site.css"},
		{name: "post", method: http.MethodPost, path: "/forms/probe"},
		{name: "options", method: http.MethodOptions, path: "/"},
	}
	if product == "autocar" {
		wrong := "Bearer " + strings.Repeat("A", base64.RawURLEncoding.EncodedLen(webAuthMinTicket))
		probes = append(probes,
			probeSpec{name: "connect-missing", method: http.MethodConnect, authority: countedTarget},
			probeSpec{name: "connect-wrong", method: http.MethodConnect, authority: countedTarget, header: wrong},
			probeSpec{
				name: "legacy-hysteria-auth", method: http.MethodPost, path: "/auth", authority: "hysteria",
				headers: http.Header{"Hysteria-Auth": {"wrong"}, "Hysteria-CC-RX": {"0"}, "Hysteria-Padding": {"padding"}},
			},
		)
	} else {
		probes = append(probes,
			probeSpec{name: "hysteria-auth-missing", method: http.MethodPost, path: "/auth", authority: "hysteria"},
			probeSpec{
				name: "hysteria-auth-wrong", method: http.MethodPost, path: "/auth", authority: "hysteria",
				headers: http.Header{"Hysteria-Auth": {"wrong"}, "Hysteria-CC-RX": {"0"}, "Hysteria-Padding": {"padding"}},
			},
		)
	}
	_ = protocolName
	return probes
}

func isNoDialProbe(probe probeSpec) bool {
	return probe.name == "connect-missing" || probe.name == "connect-wrong"
}

func runProbePair(opts activeOptions, baseTLS *tls.Config, rng *lockedRand, iteration int, protocolName string, probe probeSpec) activeRecord {
	firstRelay := rng.Intn(2) == 0
	var relay, control responseEvidence
	if firstRelay {
		relay = performProbe(protocolName, opts.relay, opts.serverName, baseTLS, probe)
		control = performProbe(protocolName, opts.control, opts.serverName, baseTLS, probe)
	} else {
		control = performProbe(protocolName, opts.control, opts.serverName, baseTLS, probe)
		relay = performProbe(protocolName, opts.relay, opts.serverName, baseTLS, probe)
	}
	equivalent := evidenceEquivalent(relay, control)
	leaks := responseMarkerLeaks(opts.product, relay, probe.header)
	passed := relay.OK && control.OK && equivalent && len(leaks) == 0 && relay.Protocol == strings.ToUpper(protocolName)
	detail := ""
	if !passed {
		detail = "relay response must be successful, marker-free, protocol-correct, and semantically identical to the cover-only control"
	}
	return activeRecord{
		Type: "probe", Product: opts.product, Iteration: iteration, Protocol: protocolName,
		Probe: probe.name, First: map[bool]string{true: "relay", false: "control"}[firstRelay],
		Relay: relay, Control: &control, Equivalent: &equivalent, MarkerLeak: leaks, Passed: passed, Detail: detail,
	}
}

func performProbe(protocolName, endpoint, serverName string, baseTLS *tls.Config, probe probeSpec) responseEvidence {
	ctx, cancel := context.WithTimeout(context.Background(), defaultRequestTimout)
	defer cancel()
	started := time.Now()
	var response *http.Response
	var err error
	switch protocolName {
	case "h1":
		response, err = requestH1(ctx, endpoint, serverName, baseTLS, probe)
	case "h2":
		response, err = requestH2(ctx, endpoint, serverName, baseTLS, probe)
	case "h3":
		response, err = requestH3(ctx, endpoint, serverName, baseTLS, probe)
	default:
		err = errors.New("unsupported protocol")
	}
	evidence := responseEvidence{LatencyMS: float64(time.Since(started).Microseconds()) / 1000}
	if err != nil {
		evidence.ErrorClass = classifyRequestError(err)
		return evidence
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, defaultRequestLimit+1))
	if readErr != nil {
		evidence.ErrorClass = "response_read_failed"
		return evidence
	}
	if len(body) > defaultRequestLimit {
		evidence.ErrorClass = "response_too_large"
		return evidence
	}
	evidence.OK = true
	evidence.Protocol = fmt.Sprintf("H%d", response.ProtoMajor)
	evidence.Status = response.StatusCode
	evidence.Headers = canonicalHeaders(response.Header)
	evidence.RawHeaders = response.Header.Clone()
	evidence.BodyBytes = len(body)
	sum := sha256.Sum256(body)
	evidence.BodySHA256 = hex.EncodeToString(sum[:])
	evidence.Body = body
	if response.TLS != nil {
		evidence.TLSVersion = tlsVersionName(response.TLS.Version)
		evidence.ALPN = response.TLS.NegotiatedProtocol
	}
	return evidence
}

func requestH1(ctx context.Context, endpoint, serverName string, baseTLS *tls.Config, probe probeSpec) (*http.Response, error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, err
	}
	tlsConfig := baseTLS.Clone()
	tlsConfig.ServerName = serverName
	tlsConfig.NextProtos = []string{"http/1.1"}
	conn := tls.Client(raw, tlsConfig)
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	target := probe.path
	if target == "" {
		target = "/"
	}
	host := serverName
	if probe.authority != "" {
		host = probe.authority
	}
	if probe.method == http.MethodConnect {
		target = host
	}
	var request strings.Builder
	fmt.Fprintf(&request, "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n", probe.method, target, host)
	if probe.header != "" {
		fmt.Fprintf(&request, "Proxy-Authorization: %s\r\n", probe.header)
	}
	for _, name := range sortedHeaderKeys(probe.headers) {
		for _, value := range probe.headers.Values(name) {
			fmt.Fprintf(&request, "%s: %s\r\n", name, value)
		}
	}
	request.WriteString("Content-Length: 0\r\n\r\n")
	if _, err := io.WriteString(conn, request.String()); err != nil {
		conn.Close()
		return nil, err
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: probe.method})
	if err != nil {
		conn.Close()
		return nil, err
	}
	state := conn.ConnectionState()
	response.TLS = &state
	response.Body = &closeReadCloser{ReadCloser: response.Body, close: conn.Close}
	return response, nil
}

func requestH2(ctx context.Context, endpoint, serverName string, baseTLS *tls.Config, probe probeSpec) (*http.Response, error) {
	tlsConfig := baseTLS.Clone()
	tlsConfig.ServerName = serverName
	tlsConfig.NextProtos = []string{"h2"}
	transport := &http2.Transport{
		TLSClientConfig: tlsConfig,
		DialTLSContext: func(ctx context.Context, network, _ string, cfg *tls.Config) (net.Conn, error) {
			raw, err := (&net.Dialer{}).DialContext(ctx, network, endpoint)
			if err != nil {
				return nil, err
			}
			conn := tls.Client(raw, cfg.Clone())
			if err := conn.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return conn, nil
		},
	}
	request, err := newProbeRequest(ctx, endpoint, serverName, probe)
	if err != nil {
		return nil, err
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}
	response.Body = &closeReadCloser{ReadCloser: response.Body, close: func() error {
		transport.CloseIdleConnections()
		return nil
	}}
	return response, nil
}

func requestH3(ctx context.Context, endpoint, serverName string, baseTLS *tls.Config, probe probeSpec) (*http.Response, error) {
	tlsConfig := baseTLS.Clone()
	tlsConfig.ServerName = serverName
	tlsConfig.NextProtos = []string{http3.NextProtoH3}
	transport := &http3.Transport{
		TLSClientConfig: tlsConfig,
		Dial: func(ctx context.Context, _ string, cfg *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, endpoint, cfg.Clone(), quicConfig.Clone())
		},
	}
	request, err := newProbeRequest(ctx, endpoint, serverName, probe)
	if err != nil {
		return nil, err
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	response.Body = &closeReadCloser{ReadCloser: response.Body, close: transport.Close}
	return response, nil
}

func newProbeRequest(ctx context.Context, endpoint, serverName string, probe probeSpec) (*http.Request, error) {
	path := probe.path
	if path == "" && probe.method != http.MethodConnect {
		path = "/"
	}
	parsed, err := url.Parse("https://" + endpoint + path)
	if err != nil {
		return nil, err
	}
	request := (&http.Request{
		Method: probe.method, URL: parsed, Host: serverName, Header: make(http.Header), Body: http.NoBody,
	}).WithContext(ctx)
	if probe.authority != "" {
		request.Host = probe.authority
	}
	request.Header.Set("User-Agent", "Mozilla/5.0")
	request.Header.Set("Accept", "*/*")
	if probe.header != "" {
		request.Header.Set("Proxy-Authorization", probe.header)
	}
	for name, values := range probe.headers {
		request.Header[name] = append([]string(nil), values...)
	}
	return request, nil
}

type closeReadCloser struct {
	io.ReadCloser
	close func() error
	once  sync.Once
}

func (c *closeReadCloser) Close() error {
	var result error
	c.once.Do(func() { result = errors.Join(c.ReadCloser.Close(), c.close()) })
	return result
}

func canonicalHeaders(headers http.Header) []string {
	ignored := map[string]bool{
		"Date": true,
		// Request IDs are explicitly excluded from semantic equivalence. The
		// fixture origin does not emit one, but real comparison origins may.
		"X-Request-Id": true,
		"Traceparent":  true,
	}
	var result []string
	for name, values := range headers {
		canonical := http.CanonicalHeaderKey(name)
		if ignored[canonical] {
			continue
		}
		if canonical == "Proxy-Authentication-Info" {
			// The response proof is a credential-derived MAC and authenticated
			// padding. Preserve only header presence in evidence; never serialize
			// its value into the JSONL artifact.
			for range values {
				result = append(result, "proxy-authentication-info:<redacted>")
			}
			continue
		}
		copied := append([]string(nil), values...)
		sort.Strings(copied)
		for _, value := range copied {
			result = append(result, strings.ToLower(canonical)+":"+strings.TrimSpace(value))
		}
	}
	sort.Strings(result)
	return result
}

func evidenceEquivalent(left, right responseEvidence) bool {
	if !left.OK || !right.OK {
		return false
	}
	return left.Protocol == right.Protocol && left.TLSVersion == right.TLSVersion && left.ALPN == right.ALPN &&
		left.Status == right.Status && left.BodySHA256 == right.BodySHA256 && left.BodyBytes == right.BodyBytes &&
		strings.Join(left.Headers, "\n") == strings.Join(right.Headers, "\n")
}

func responseMarkerLeaks(product string, evidence responseEvidence, credential string) []string {
	if !evidence.OK {
		return nil
	}
	text := strings.ToLower(strings.Join(evidence.Headers, "\n") + "\n" + string(evidence.Body) + "\n" + evidence.ALPN)
	candidates := []struct{ name, value string }{
		{"autocar", "autocar"}, {"native_alpn", "autocar/2"},
	}
	if product == "hysteria2" {
		candidates = append(candidates, struct{ name, value string }{"hysteria2", "hysteria"})
	}
	if credential != "" {
		candidates = append(candidates, struct{ name, value string }{"credential_echo", strings.ToLower(credential)})
	}
	var leaks []string
	for _, candidate := range candidates {
		if candidate.value != "" && strings.Contains(text, candidate.value) {
			leaks = append(leaks, candidate.name)
		}
	}
	return leaks
}

func classifyRequestError(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "network_or_protocol_error"
	}
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func makeWebBearer(token, transportName, authority string, now time.Time, random io.Reader) (string, error) {
	if transportName != "h2" && transportName != "h3" {
		return "", errors.New("ticket transport must be h2 or h3")
	}
	if len(token) < protocol.MinTokenLength || len(token) > protocol.MaxTokenLength || authority == "" {
		return "", errors.New("ticket token and authority are required")
	}
	key, err := hkdf.Key(sha256.New, []byte(token), nil, webAuthKeyInfo, sha256.Size)
	if err != nil {
		return "", err
	}
	var nonce [16]byte
	if _, err := io.ReadFull(random, nonce[:]); err != nil {
		return "", err
	}
	paddingLength, err := sampleWebAuthPaddingLength(random)
	if err != nil {
		return "", err
	}
	padding := make([]byte, paddingLength)
	if _, err := io.ReadFull(random, padding); err != nil {
		return "", err
	}
	timestamp := now.Unix()
	mac := hmac.New(sha256.New, key)
	for _, field := range []string{webAuthTranscript, transportName, http.MethodConnect, "", authority, ""} {
		writeAuthField(mac, field)
	}
	var claims [42]byte
	binary.BigEndian.PutUint64(claims[0:8], uint64(timestamp))
	copy(claims[8:24], nonce[:])
	// mode, profile, maxTx and maxRx remain their valid zero values.
	_, _ = mac.Write(claims[:])
	_, _ = mac.Write([]byte{webAuthVersion})
	var encodedPaddingLength [2]byte
	binary.BigEndian.PutUint16(encodedPaddingLength[:], uint16(len(padding)))
	_, _ = mac.Write(encodedPaddingLength[:])
	_, _ = mac.Write(padding)
	digest := mac.Sum(nil)
	ticket := make([]byte, webAuthPaddingOffset+len(padding)+sha256.Size)
	ticket[0] = webAuthVersion
	binary.BigEndian.PutUint64(ticket[1:9], uint64(timestamp))
	copy(ticket[9:25], nonce[:])
	binary.BigEndian.PutUint16(ticket[43:webAuthPaddingOffset], uint16(len(padding)))
	copy(ticket[webAuthPaddingOffset:], padding)
	copy(ticket[webAuthPaddingOffset+len(padding):], digest)
	return "Bearer " + base64.RawURLEncoding.EncodeToString(ticket), nil
}

func sampleWebAuthPaddingLength(random io.Reader) (int, error) {
	const sampleCount = webAuthMaxPadding - webAuthMinPadding + 1
	first, err := sampleWebAuthUniform16(random, sampleCount)
	if err != nil {
		return 0, err
	}
	second, err := sampleWebAuthUniform16(random, sampleCount)
	if err != nil {
		return 0, err
	}
	return webAuthMinPadding + (first+second)/2, nil
}

func sampleWebAuthUniform16(random io.Reader, size int) (int, error) {
	const sourceValues = 1 << 16
	limit := sourceValues - sourceValues%size
	var sample [2]byte
	for {
		if _, err := io.ReadFull(random, sample[:]); err != nil {
			return 0, err
		}
		value := int(binary.BigEndian.Uint16(sample[:]))
		if value < limit {
			return value % size, nil
		}
	}
}

func writeAuthField(writer io.Writer, value string) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	_, _ = writer.Write(size[:])
	_, _ = io.WriteString(writer, value)
}

func runOrigin(args []string) error {
	fs := flag.NewFlagSet("origin", flag.ContinueOnError)
	listen := fs.String("listen", ":8080", "plain HTTP listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Vary", "Accept-Encoding")
		w.Header().Set("X-Site", "ordinary-cover")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = io.WriteString(w, "Method Not Allowed\n")
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "ordinary cover: %s\n", r.URL.RequestURI())
	})
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	return serveHTTPUntilSignal(server)
}

func runCoverServer(args []string) error {
	fs := flag.NewFlagSet("cover-server", flag.ContinueOnError)
	listen := fs.String("listen", ":8443", "shared numeric TCP/UDP listen address")
	certFile := fs.String("cert", "", "TLS certificate")
	keyFile := fs.String("key", "", "TLS private key")
	originText := fs.String("origin", "", "fixed http(s) cover origin")
	altSvcMaxAge := fs.Int("alt-svc-max-age", 0, "optional Alt-Svc ma value used by the compared server")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *certFile == "" || *keyFile == "" || *originText == "" {
		return errors.New("--cert, --key and --origin are required")
	}
	origin, err := url.Parse(*originText)
	if err != nil {
		return err
	}
	handler, err := cover.NewReverseProxyHandler(origin, nil)
	if err != nil {
		return err
	}
	certificate, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return err
	}
	tcpListener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	_, port, err := net.SplitHostPort(tcpListener.Addr().String())
	if err != nil {
		tcpListener.Close()
		return err
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		tcpListener.Close()
		return err
	}
	packet, err := net.ListenPacket("udp", net.JoinHostPort(host, port))
	if err != nil {
		tcpListener.Close()
		return err
	}
	if *altSvcMaxAge < 0 {
		tcpListener.Close()
		packet.Close()
		return errors.New("--alt-svc-max-age cannot be negative")
	}
	altSvc := `h3=":` + port + `"`
	if *altSvcMaxAge > 0 {
		altSvc += "; ma=" + strconv.Itoa(*altSvcMaxAge)
	}
	tcpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", altSvc)
		handler.ServeHTTP(w, r)
	})
	tcpTLS := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h2", "http/1.1"},
	}
	tcpServer := &http.Server{Handler: tcpHandler, TLSConfig: tcpTLS, ReadHeaderTimeout: 5 * time.Second}
	if err := http2.ConfigureServer(tcpServer, &http2.Server{}); err != nil {
		tcpListener.Close()
		packet.Close()
		return err
	}
	h3TLS := tcpTLS.Clone()
	h3TLS.NextProtos = []string{http3.NextProtoH3}
	h3Server := &http3.Server{TLSConfig: h3TLS, Handler: handler}

	errCh := make(chan error, 2)
	go func() { errCh <- tcpServer.Serve(tls.NewListener(tcpListener, tcpTLS)) }()
	go func() { errCh <- h3Server.Serve(packet) }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
	case err := <-errCh:
		if !benignServerError(err) {
			_ = h3Server.Close()
			_ = tcpServer.Close()
			return err
		}
	}
	_ = h3Server.Close()
	_ = packet.Close()
	_ = tcpServer.Close()
	_ = tcpListener.Close()
	return nil
}

func runEchoServer(args []string) error {
	fs := flag.NewFlagSet("echo-server", flag.ContinueOnError)
	listen := fs.String("listen", ":9000", "TCP echo listen address")
	metrics := fs.String("metrics", ":9001", "HTTP count endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	var accepted atomic.Int64
	metricsServer := &http.Server{Addr: *metrics, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int64{"accepted": accepted.Load()})
	})}
	go func() { _ = metricsServer.ListenAndServe() }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
		_ = metricsServer.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		accepted.Add(1)
		go func() {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}()
	}
}

type gatewayMetrics struct {
	UDPEnabled   bool  `json:"udp_enabled"`
	TCPAccepted  int64 `json:"tcp_accepted"`
	UDPReceived  int64 `json:"udp_received"`
	UDPDropped   int64 `json:"udp_dropped"`
	UDPForwarded int64 `json:"udp_forwarded"`
	UDPReplies   int64 `json:"udp_replies"`
}

type gateway struct {
	backendTCP   string
	backendUDP   *net.UDPAddr
	packet       net.PacketConn
	enabled      atomic.Bool
	tcpAccepted  atomic.Int64
	udpReceived  atomic.Int64
	udpDropped   atomic.Int64
	udpForwarded atomic.Int64
	udpReplies   atomic.Int64
	mu           sync.Mutex
	sessions     map[string]*gatewayUDPSession
}

type gatewayUDPSession struct {
	client net.Addr
	conn   *net.UDPConn
	lastNS atomic.Int64
}

func runGateway(args []string) error {
	fs := flag.NewFlagSet("gateway", flag.ContinueOnError)
	listen := fs.String("listen", ":9443", "shared numeric TCP/UDP listen address")
	backend := fs.String("backend", "", "backend host:port")
	control := fs.String("control", ":9090", "HTTP control listen address")
	udpEnabled := fs.Bool("udp-enabled", false, "initial UDP forwarding state")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *backend == "" {
		return errors.New("--backend is required")
	}
	backendUDP, err := net.ResolveUDPAddr("udp", *backend)
	if err != nil {
		return err
	}
	tcpListener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	packet, err := net.ListenPacket("udp", *listen)
	if err != nil {
		tcpListener.Close()
		return err
	}
	g := &gateway{backendTCP: *backend, backendUDP: backendUDP, packet: packet, sessions: make(map[string]*gatewayUDPSession)}
	g.enabled.Store(*udpEnabled)
	controlServer := &http.Server{Addr: *control, Handler: g.controlHandler()}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 3)
	go func() { errCh <- g.serveTCP(ctx, tcpListener) }()
	go func() { errCh <- g.serveUDP(ctx) }()
	go func() { errCh <- controlServer.ListenAndServe() }()
	select {
	case <-ctx.Done():
	case err := <-errCh:
		if !benignServerError(err) {
			stop()
			_ = tcpListener.Close()
			_ = packet.Close()
			_ = controlServer.Close()
			g.closeSessions()
			return err
		}
	}
	_ = tcpListener.Close()
	_ = packet.Close()
	_ = controlServer.Close()
	g.closeSessions()
	return nil
}

func (g *gateway) serveTCP(ctx context.Context, listener net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		client, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		g.tcpAccepted.Add(1)
		go func() {
			defer client.Close()
			backend, err := net.DialTimeout("tcp", g.backendTCP, 5*time.Second)
			if err != nil {
				return
			}
			defer backend.Close()
			done := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(backend, client); done <- struct{}{} }()
			go func() { _, _ = io.Copy(client, backend); done <- struct{}{} }()
			<-done
		}()
	}
}

func (g *gateway) serveUDP(ctx context.Context) error {
	buffer := make([]byte, 64<<10)
	for {
		n, client, err := g.packet.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		g.udpReceived.Add(1)
		if !g.enabled.Load() {
			g.udpDropped.Add(1)
			continue
		}
		session, err := g.session(client)
		if err != nil {
			continue
		}
		session.lastNS.Store(time.Now().UnixNano())
		if _, err := session.conn.Write(buffer[:n]); err == nil {
			g.udpForwarded.Add(1)
		}
	}
}

func (g *gateway) session(client net.Addr) (*gatewayUDPSession, error) {
	key := client.String()
	g.mu.Lock()
	defer g.mu.Unlock()
	if session := g.sessions[key]; session != nil {
		return session, nil
	}
	conn, err := net.DialUDP("udp", nil, g.backendUDP)
	if err != nil {
		return nil, err
	}
	session := &gatewayUDPSession{client: cloneAddr(client), conn: conn}
	session.lastNS.Store(time.Now().UnixNano())
	g.sessions[key] = session
	go g.copyUDPReplies(key, session)
	return session, nil
}

func (g *gateway) copyUDPReplies(key string, session *gatewayUDPSession) {
	buffer := make([]byte, 64<<10)
	for {
		n, err := session.conn.Read(buffer)
		if err != nil {
			break
		}
		if _, err := g.packet.WriteTo(buffer[:n], session.client); err != nil {
			break
		}
		g.udpReplies.Add(1)
	}
	g.mu.Lock()
	if g.sessions[key] == session {
		delete(g.sessions, key)
	}
	g.mu.Unlock()
}

func (g *gateway) controlHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/state", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(g.metrics())
	})
	mux.HandleFunc("/enable-udp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		g.enabled.Store(true)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(g.metrics())
	})
	mux.HandleFunc("/disable-udp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		g.enabled.Store(false)
		g.closeSessions()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(g.metrics())
	})
	return mux
}

func (g *gateway) metrics() gatewayMetrics {
	return gatewayMetrics{
		UDPEnabled: g.enabled.Load(), TCPAccepted: g.tcpAccepted.Load(), UDPReceived: g.udpReceived.Load(),
		UDPDropped: g.udpDropped.Load(), UDPForwarded: g.udpForwarded.Load(), UDPReplies: g.udpReplies.Load(),
	}
}

func (g *gateway) closeSessions() {
	g.mu.Lock()
	sessions := g.sessions
	g.sessions = make(map[string]*gatewayUDPSession)
	g.mu.Unlock()
	for _, session := range sessions {
		_ = session.conn.Close()
	}
}

func cloneAddr(address net.Addr) net.Addr {
	switch value := address.(type) {
	case *net.UDPAddr:
		return &net.UDPAddr{IP: append(net.IP(nil), value.IP...), Port: value.Port, Zone: value.Zone}
	default:
		return address
	}
}

type transitionEvidence struct {
	Type          string          `json:"type"`
	Status        string          `json:"status"`
	Paths         []string        `json:"paths"`
	Before        gatewayMetrics  `json:"before"`
	AfterFallback gatewayMetrics  `json:"after_fallback"`
	AfterRecovery gatewayMetrics  `json:"after_recovery"`
	Checks        map[string]bool `json:"checks"`
	PrimaryMS     int64           `json:"primary_attempt_timeout_ms"`
	CooldownMS    int64           `json:"fallback_cooldown_ms"`
}

func runTransition(args []string) error {
	fs := flag.NewFlagSet("transition", flag.ContinueOnError)
	var allowNets stringListFlag
	server := fs.String("server", "", "gateway host:port")
	serverName := fs.String("server-name", "", "TLS certificate name")
	caFile := fs.String("ca", "", "PEM trust anchor")
	tokenFile := fs.String("token-file", "", "AutoCAR token file")
	target := fs.String("target", "", "TCP echo target host:port")
	controlURL := fs.String("gateway-control", "", "gateway HTTP control base URL")
	output := fs.String("output", "", "JSON evidence output")
	isolatedLab := fs.Bool("isolated-lab", false, "confirm and enforce private/loopback lab endpoints")
	primaryTimeout := fs.Duration("primary-timeout", 800*time.Millisecond, "H3 attempt budget")
	cooldown := fs.Duration("fallback-cooldown", 1200*time.Millisecond, "H2 preference period")
	fs.Var(&allowNets, "allow-net", "repeatable exact private/loopback IP or CIDR allowed in the isolated lab")
	if err := fs.Parse(args); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"--server": *server, "--server-name": *serverName, "--ca": *caFile, "--token-file": *tokenFile,
		"--target": *target, "--gateway-control": *controlURL, "--output": *output,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if *primaryTimeout <= 0 || *cooldown <= 0 {
		return errors.New("timeouts must be positive")
	}
	if !*isolatedLab {
		return errors.New("transport transition checks require --isolated-lab")
	}
	allowlist, err := parseIsolatedAllowlist(allowNets)
	if err != nil {
		return err
	}
	frozenServer, err := freezeIsolatedHostPort(*server, allowlist)
	if err != nil {
		return fmt.Errorf("server endpoint: %w", err)
	}
	*server = frozenServer
	frozenTarget, err := freezeIsolatedHostPort(*target, allowlist)
	if err != nil {
		return fmt.Errorf("target endpoint: %w", err)
	}
	*target = frozenTarget
	frozenControlURL, err := freezeIsolatedURL(*controlURL, allowlist)
	if err != nil {
		return fmt.Errorf("gateway control endpoint: %w", err)
	}
	*controlURL = frozenControlURL
	tlsConfig, err := loadClientTLS(*caFile, *serverName)
	if err != nil {
		return err
	}
	token, err := readSecret(*tokenFile)
	if err != nil {
		return err
	}
	client, err := tunnel.NewWebClient(tunnel.WebClientConfig{
		ServerAddress: *server, Token: token, TLSConfig: tlsConfig,
		HandshakeTimeout: 5 * time.Second, H3DialTimeout: 5 * time.Second, H2DialTimeout: 5 * time.Second,
		PrimaryAttemptTimeout: *primaryTimeout, FallbackCooldown: *cooldown,
	})
	if err != nil {
		return err
	}
	defer client.Close()
	before, err := readGatewayMetrics(strings.TrimRight(*controlURL, "/") + "/state")
	if err != nil {
		return err
	}
	if before.UDPEnabled {
		return errors.New("gateway UDP must initially be disabled")
	}
	paths := make([]string, 0, 3)
	for i := 0; i < 2; i++ {
		if err := tunnelEcho(client, *target, fmt.Sprintf("fallback-%d", i)); err != nil {
			return err
		}
		paths = append(paths, client.SelectedTransport())
	}
	afterFallback, err := readGatewayMetrics(strings.TrimRight(*controlURL, "/") + "/state")
	if err != nil {
		return err
	}
	if _, err := postGateway(strings.TrimRight(*controlURL, "/") + "/enable-udp"); err != nil {
		return err
	}
	// WebClient applies up to +20% production jitter to the configured base.
	// Wait 25% plus a scheduling margin so this transition probe observes the
	// recovery window for any accepted test cooldown.
	time.Sleep(*cooldown + *cooldown/4 + 20*time.Millisecond)
	if err := tunnelEcho(client, *target, "recovered"); err != nil {
		return err
	}
	paths = append(paths, client.SelectedTransport())
	afterRecovery, err := readGatewayMetrics(strings.TrimRight(*controlURL, "/") + "/state")
	if err != nil {
		return err
	}
	checks := map[string]bool{
		"fallback_is_h2":        len(paths) >= 2 && paths[0] == "h2" && paths[1] == "h2",
		"recovery_is_h3":        len(paths) == 3 && paths[2] == "h3",
		"udp_attempt_observed":  afterFallback.UDPReceived > before.UDPReceived && afterFallback.UDPDropped > before.UDPDropped,
		"tcp_fallback_observed": afterFallback.TCPAccepted > before.TCPAccepted,
		"udp_forward_observed":  afterRecovery.UDPForwarded > afterFallback.UDPForwarded && afterRecovery.UDPReplies > afterFallback.UDPReplies,
	}
	status := "pass"
	for _, passed := range checks {
		if !passed {
			status = "fail"
		}
	}
	evidence := transitionEvidence{
		Type: "transport_transition", Status: status, Paths: paths, Before: before,
		AfterFallback: afterFallback, AfterRecovery: afterRecovery, Checks: checks,
		PrimaryMS: primaryTimeout.Milliseconds(), CooldownMS: cooldown.Milliseconds(),
	}
	if err := writeJSONFile(*output, evidence); err != nil {
		return err
	}
	encoded, _ := json.Marshal(evidence)
	fmt.Println(string(encoded))
	if status != "pass" {
		return errors.New("H3-to-H2-to-H3 transition gate failed")
	}
	return nil
}

func tunnelEcho(client *tunnel.WebClient, target, payload string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(conn, payload); err != nil {
		return err
	}
	buffer := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buffer); err != nil {
		return err
	}
	if string(buffer) != payload {
		return errors.New("echo payload mismatch")
	}
	return nil
}

func runFetch(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	proxyText := fs.String("proxy", "", "optional HTTP proxy URL")
	urlText := fs.String("url", "", "request URL")
	timeout := fs.Duration("timeout", 5*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *urlText == "" {
		return errors.New("--url is required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if *proxyText != "" {
		proxyURL, err := url.Parse(*proxyText)
		if err != nil {
			return err
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	client := &http.Client{Transport: transport, Timeout: *timeout}
	response, err := client.Get(*urlText)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, defaultRequestLimit+1))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || len(body) > defaultRequestLimit {
		return fmt.Errorf("unexpected response status/body: %d/%d", response.StatusCode, len(body))
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": response.StatusCode, "bytes": len(body)})
}

func runGatewayControl(args []string) error {
	fs := flag.NewFlagSet("gateway-control", flag.ContinueOnError)
	base := fs.String("url", "", "gateway control base URL")
	action := fs.String("action", "state", "state, enable, or disable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *base == "" {
		return errors.New("--url is required")
	}
	var (
		metrics gatewayMetrics
		err     error
	)
	switch *action {
	case "state":
		metrics, err = readGatewayMetrics(strings.TrimRight(*base, "/") + "/state")
	case "enable":
		metrics, err = postGateway(strings.TrimRight(*base, "/") + "/enable-udp")
	case "disable":
		metrics, err = postGateway(strings.TrimRight(*base, "/") + "/disable-udp")
	default:
		return errors.New("--action must be state, enable, or disable")
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(metrics)
}

func readGatewayMetrics(endpoint string) (gatewayMetrics, error) {
	var result gatewayMetrics
	response, err := (&http.Client{Timeout: 3 * time.Second}).Get(endpoint)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result, fmt.Errorf("gateway state status %d", response.StatusCode)
	}
	return result, json.NewDecoder(response.Body).Decode(&result)
}

func postGateway(endpoint string) (gatewayMetrics, error) {
	var result gatewayMetrics
	request, _ := http.NewRequest(http.MethodPost, endpoint, nil)
	response, err := (&http.Client{Timeout: 3 * time.Second}).Do(request)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result, fmt.Errorf("gateway control status %d", response.StatusCode)
	}
	return result, json.NewDecoder(response.Body).Decode(&result)
}

func readDialCount(endpoint string) (int64, error) {
	response, err := (&http.Client{Timeout: 3 * time.Second}).Get(endpoint)
	if err != nil {
		return 0, fmt.Errorf("read destination count: %w", err)
	}
	defer response.Body.Close()
	var payload struct {
		Accepted int64 `json:"accepted"`
	}
	if response.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("destination count status %d", response.StatusCode)
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return 0, err
	}
	return payload.Accepted, nil
}

func waitDialCount(endpoint string, want int64, timeout time.Duration) (int64, error) {
	deadline := time.Now().Add(timeout)
	for {
		got, err := readDialCount(endpoint)
		if err != nil {
			return 0, err
		}
		if got >= want || time.Now().After(deadline) {
			return got, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func confirmDialCountStable(endpoint string, want int64, quietWindow time.Duration) (int64, bool, error) {
	deadline := time.Now().Add(quietWindow)
	for {
		got, err := readDialCount(endpoint)
		if err != nil {
			return 0, false, err
		}
		if got != want {
			return got, false, nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return got, true, nil
		}
		if remaining > 20*time.Millisecond {
			remaining = 20 * time.Millisecond
		}
		time.Sleep(remaining)
	}
}

func loadClientTLS(caFile, serverName string) (*tls.Config, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("CA file contains no certificate")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: roots, ServerName: serverName,
	}, nil
}

func readSecret(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	secret := strings.TrimSpace(string(data))
	if secret == "" {
		return "", errors.New("secret file is empty")
	}
	return secret, nil
}

type stringListFlag []string

func (values *stringListFlag) String() string {
	return strings.Join(*values, ",")
}

func (values *stringListFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("allowlist entry must not be empty")
	}
	*values = append(*values, value)
	return nil
}

type isolatedAllowlist struct {
	prefixes []netip.Prefix
}

var isolatedAddressRoots = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
}

func parseIsolatedAllowlist(values []string) (isolatedAllowlist, error) {
	if len(values) == 0 {
		return isolatedAllowlist{}, errors.New("at least one --allow-net IP or CIDR is required")
	}
	result := isolatedAllowlist{prefixes: make([]netip.Prefix, 0, len(values))}
	seen := make(map[netip.Prefix]bool)
	for _, value := range values {
		prefix, err := parseIsolatedPrefix(value)
		if err != nil {
			return isolatedAllowlist{}, fmt.Errorf("invalid --allow-net %q: %w", value, err)
		}
		if !seen[prefix] {
			seen[prefix] = true
			result.prefixes = append(result.prefixes, prefix)
		}
	}
	return result, nil
}

func parseIsolatedPrefix(value string) (netip.Prefix, error) {
	if address, err := netip.ParseAddr(value); err == nil {
		address = address.Unmap()
		prefix := netip.PrefixFrom(address, address.BitLen())
		if !isContainedInIsolatedRoot(prefix) {
			return netip.Prefix{}, errors.New("address is not private or loopback")
		}
		return prefix, nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, errors.New("expected an IP address or CIDR")
	}
	if prefix.Addr().Is4In6() {
		return netip.Prefix{}, errors.New("IPv4-mapped IPv6 prefixes are not accepted")
	}
	prefix = prefix.Masked()
	if !isContainedInIsolatedRoot(prefix) {
		return netip.Prefix{}, errors.New("CIDR must be fully contained in private or loopback space")
	}
	return prefix, nil
}

func isContainedInIsolatedRoot(prefix netip.Prefix) bool {
	for _, root := range isolatedAddressRoots {
		if root.Addr().BitLen() == prefix.Addr().BitLen() && prefix.Bits() >= root.Bits() && root.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

func (allowlist isolatedAllowlist) contains(address netip.Addr) bool {
	address = address.Unmap()
	for _, prefix := range allowlist.prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func freezeIsolatedURL(rawURL string, allowlist isolatedAllowlist) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return "", errors.New("invalid URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("URL scheme must be http or https")
	}
	if parsed.User != nil {
		return "", errors.New("URL userinfo is not allowed")
	}
	frozen, err := freezeIsolatedHostPort(parsed.Host, allowlist)
	if err != nil {
		return "", err
	}
	parsed.Host = frozen
	return parsed.String(), nil
}

func freezeIsolatedHostPort(endpoint string, allowlist isolatedAllowlist) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" || port == "" {
		return "", errors.New("expected host:port")
	}
	addresses, err := net.LookupIP(host)
	if err != nil || len(addresses) == 0 {
		return "", errors.New("host did not resolve inside the lab")
	}
	approved := make([]string, 0, len(addresses))
	seen := make(map[string]bool)
	for _, address := range addresses {
		parsed, parseErr := netip.ParseAddr(address.String())
		if parseErr != nil {
			return "", fmt.Errorf("unparseable resolved address %q", address.String())
		}
		parsed = parsed.Unmap()
		if parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() {
			return "", fmt.Errorf("link-local address %s is outside the isolated-lab scope", parsed)
		}
		if !isContainedInIsolatedRoot(netip.PrefixFrom(parsed, parsed.BitLen())) {
			return "", fmt.Errorf("public address %s is outside the isolated-lab scope", parsed)
		}
		if !allowlist.contains(parsed) {
			return "", fmt.Errorf("address %s is not in the explicit isolated-lab allowlist", parsed)
		}
		text := parsed.String()
		if !seen[text] {
			seen[text] = true
			approved = append(approved, text)
		}
	}
	sort.Strings(approved)
	return net.JoinHostPort(approved[0], port), nil
}

func serveHTTPUntilSignal(server *http.Server) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()
	select {
	case <-ctx.Done():
		_ = server.Close()
		return nil
	case err := <-errCh:
		if benignServerError(err) {
			return nil
		}
		return err
	}
}

func benignServerError(err error) bool {
	return err == nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed)
}

func writeJSONFile(path string, value any) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encodeErr := encoder.Encode(value)
	return errors.Join(encodeErr, file.Close())
}

func sortedHeaderKeys(header http.Header) []string {
	keys := make([]string, 0, len(header))
	for key := range header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

type lockedRand struct {
	mu sync.Mutex
	r  *mathRand
}

// mathRand is the narrow method set needed here. Keeping it behind a lock
// makes it explicit that future parallel probes must retain deterministic
// ordering.
type mathRand struct{ state uint64 }

func newLockedRand(seed int64) *lockedRand {
	state := uint64(seed)
	if state == 0 {
		state = 0x9e3779b97f4a7c15
	}
	return &lockedRand{r: &mathRand{state: state}}
}

func (r *lockedRand) Intn(n int) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	// xorshift64* is sufficient for deterministic request ordering; it is not
	// used for credentials or any security decision.
	r.r.state ^= r.r.state >> 12
	r.r.state ^= r.r.state << 25
	r.r.state ^= r.r.state >> 27
	return int((r.r.state * 2685821657736338717) % uint64(n))
}

func parsePort(address net.Addr) (int, error) {
	_, portText, err := net.SplitHostPort(address.String())
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(portText)
}

var _ = parsePort
