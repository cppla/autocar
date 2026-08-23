package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/cppla/autocar/internal/netbench"
	"github.com/cppla/autocar/internal/transport"
)

func runBenchServer(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("bench-server", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:9000", "TCP listen address")
	allowPublic := fs.Bool("allow-public-benchmark", false, "allow an unauthenticated benchmark listener outside loopback")
	maxBytes := fs.Int64("max-bytes", 64<<20, "maximum bytes per transfer")
	maxConnections := fs.Int("max-connections", 16, "maximum concurrent transfers")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *maxBytes <= 0 || *maxConnections <= 0 {
		return errors.New("benchmark limits must be positive")
	}
	if err := ensureSafeBenchmarkListener(*listen, *allowPublic); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Fprintf(os.Stderr, "benchmark server listening on %s\n", listener.Addr())
	return (&netbench.Server{MaxBytes: *maxBytes, MaxConnections: *maxConnections}).Serve(ctx, listener)
}

func ensureSafeBenchmarkListener(address string, allowPublic bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid benchmark listen address %q: %w", address, err)
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	if allowPublic {
		return nil
	}
	return fmt.Errorf("refusing unauthenticated benchmark listener %q outside loopback; explicitly set --allow-public-benchmark and restrict it with a firewall", address)
}

type benchOutput struct {
	Mode                              string    `json:"mode"`
	Transport                         string    `json:"transport"`
	SelectedTransport                 string    `json:"selected_transport"`
	TunnelSenderEndpoint              string    `json:"tunnel_sender_endpoint,omitempty"`
	LocalTxAcceleration               string    `json:"local_tx_acceleration,omitempty"`
	LocalNegotiatedTxBytesSec         uint64    `json:"local_negotiated_tx_bytes_per_second,omitempty"`
	PayloadSenderAcceleration         string    `json:"payload_sender_acceleration,omitempty"`
	PayloadSenderNegotiatedTxBytesSec uint64    `json:"payload_sender_negotiated_tx_bytes_per_second,omitempty"`
	Target                            string    `json:"target"`
	Bytes                             int64     `json:"bytes_per_iteration"`
	Iterations                        int       `json:"iterations"`
	MedianMbps                        float64   `json:"median_mbps"`
	P05Mbps                           float64   `json:"p05_mbps"`
	P95Mbps                           float64   `json:"p95_mbps"`
	MedianDurationMS                  float64   `json:"median_duration_ms"`
	P95DurationMS                     float64   `json:"p95_duration_ms"`
	Results                           []float64 `json:"results_mbps"`
	DurationsMS                       []float64 `json:"durations_ms"`
}

type accelerationReporter interface {
	AccelerationMode() string
	NegotiatedTx() uint64
}

type remoteAccelerationReporter interface {
	RemoteTxAcceleration() string
	RemoteNegotiatedTx() uint64
}

type selectedTransportReporter interface {
	SelectedTransport() string
}

func runBenchClient(parent context.Context, args []string) error {
	fs := flag.NewFlagSet("bench-client", flag.ContinueOnError)
	var tf tunnelFlags
	addTunnelFlags(fs, &tf)
	target := fs.String("target", "", "benchmark server host:port (required)")
	modeText := fs.String("mode", "download", "download or upload")
	size := fs.Int64("bytes", 8<<20, "payload bytes per iteration")
	iterations := fs.Int("iterations", 5, "measured iterations")
	warmup := fs.Int("warmup", 1, "unmeasured warmup iterations")
	timeout := fs.Duration("timeout", 2*time.Minute, "timeout per transfer")
	jsonOutput := fs.Bool("json", false, "emit machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" {
		return errors.New("--target is required")
	}
	if *size <= 0 || *iterations <= 0 || *warmup < 0 {
		return errors.New("--bytes and --iterations must be positive; --warmup cannot be negative")
	}
	var mode byte
	switch strings.ToLower(*modeText) {
	case "download":
		mode = netbench.ModeDownload
	case "upload":
		mode = netbench.ModeUpload
	default:
		return errors.New("--mode must be download or upload")
	}

	var dialer transport.Dialer
	var closer interface{ Close() error }
	transportName := strings.ToLower(tf.mode)
	if transportName == "direct" {
		dialer = transport.DialFunc((&net.Dialer{Timeout: tf.dialTimeout, KeepAlive: 30 * time.Second}).DialContext)
	} else {
		built, err := buildTunnelDialer(tf)
		if err != nil {
			return err
		}
		dialer = built
		closer = built
	}
	if closer != nil {
		defer closer.Close()
	}

	results := make([]float64, 0, *iterations)
	durations := make([]float64, 0, *iterations)
	var measuredMetadata benchmarkAccelerationMetadata
	metadataObserved := false
	for i := 0; i < *warmup+*iterations; i++ {
		ctx, cancel := context.WithTimeout(parent, *timeout)
		result, err := netbench.Run(ctx, dialer, *target, mode, *size)
		cancel()
		if err != nil {
			return fmt.Errorf("iteration %d: %w", i+1, err)
		}
		if i >= *warmup {
			results = append(results, result.Mbps())
			durations = append(durations, float64(result.Duration)/float64(time.Millisecond))
			currentMetadata, currentObserved := readAccelerationMetadata(mode, dialer)
			if len(results) == 1 {
				measuredMetadata = currentMetadata
				metadataObserved = currentObserved
			} else if currentObserved != metadataObserved || currentMetadata != measuredMetadata {
				return errors.New("benchmark selected transport or sender metadata changed between measured iterations; use an explicit transport or run each path separately")
			}
		}
	}
	sorted := append([]float64(nil), results...)
	sort.Float64s(sorted)
	sortedDurations := append([]float64(nil), durations...)
	sort.Float64s(sortedDurations)
	median := percentile(sorted, 0.5)
	p05 := percentile(sorted, 0.05)
	p95 := percentile(sorted, 0.95)
	output := benchOutput{
		Mode:              strings.ToLower(*modeText),
		Transport:         transportName,
		SelectedTransport: transportName,
		Target:            *target,
		Bytes:             *size,
		Iterations:        *iterations,
		MedianMbps:        median,
		P05Mbps:           p05,
		P95Mbps:           p95,
		MedianDurationMS:  percentile(sortedDurations, 0.5),
		P95DurationMS:     percentile(sortedDurations, 0.95),
		Results:           results,
		DurationsMS:       durations,
	}
	if metadataObserved {
		measuredMetadata.apply(&output)
	}
	if *jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(output)
	}
	policy := ""
	if output.SelectedTransport != output.Transport {
		policy = ", policy " + output.Transport
	}
	fmt.Printf("%s via %s%s: median %.2f Mbit/s, p05 %.2f Mbit/s, p95 %.1f ms (%d x %d bytes)\n",
		output.Mode, output.SelectedTransport, policy, output.MedianMbps, output.P05Mbps, output.P95DurationMS, output.Iterations, output.Bytes)
	return nil
}

type benchmarkAccelerationMetadata struct {
	selectedTransport                 string
	tunnelSenderEndpoint              string
	localTxAcceleration               string
	localNegotiatedTxBytesSec         uint64
	payloadSenderAcceleration         string
	payloadSenderNegotiatedTxBytesSec uint64
}

func readAccelerationMetadata(mode byte, dialer transport.Dialer) (benchmarkAccelerationMetadata, bool) {
	local, hasLocal := dialer.(accelerationReporter)
	remote, hasRemote := dialer.(remoteAccelerationReporter)
	selected, hasSelected := dialer.(selectedTransportReporter)
	if !hasLocal && !hasRemote && !hasSelected {
		return benchmarkAccelerationMetadata{}, false
	}
	metadata := benchmarkAccelerationMetadata{}
	if hasSelected {
		metadata.selectedTransport = selected.SelectedTransport()
	}
	if hasLocal {
		metadata.localTxAcceleration = local.AccelerationMode()
		metadata.localNegotiatedTxBytesSec = local.NegotiatedTx()
	}
	if mode == netbench.ModeUpload {
		metadata.tunnelSenderEndpoint = "client"
		if hasLocal {
			metadata.payloadSenderAcceleration = metadata.localTxAcceleration
			metadata.payloadSenderNegotiatedTxBytesSec = metadata.localNegotiatedTxBytesSec
		}
		return metadata, true
	}
	metadata.tunnelSenderEndpoint = "relay"
	if hasRemote {
		metadata.payloadSenderAcceleration = remote.RemoteTxAcceleration()
		metadata.payloadSenderNegotiatedTxBytesSec = remote.RemoteNegotiatedTx()
	}
	return metadata, true
}

func (m benchmarkAccelerationMetadata) apply(output *benchOutput) {
	if m.selectedTransport != "" {
		output.SelectedTransport = m.selectedTransport
	}
	output.TunnelSenderEndpoint = m.tunnelSenderEndpoint
	output.LocalTxAcceleration = m.localTxAcceleration
	output.LocalNegotiatedTxBytesSec = m.localNegotiatedTxBytesSec
	output.PayloadSenderAcceleration = m.payloadSenderAcceleration
	output.PayloadSenderNegotiatedTxBytesSec = m.payloadSenderNegotiatedTxBytesSec
}

func populateAccelerationMetadata(output *benchOutput, mode byte, dialer transport.Dialer) {
	metadata, ok := readAccelerationMetadata(mode, dialer)
	if ok {
		metadata.apply(output)
	}
}

func percentile(sorted []float64, fraction float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	index := int(float64(len(sorted)-1)*fraction + 0.5)
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}
