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
	Mode       string    `json:"mode"`
	Transport  string    `json:"transport"`
	Target     string    `json:"target"`
	Bytes      int64     `json:"bytes_per_iteration"`
	Iterations int       `json:"iterations"`
	MedianMbps float64   `json:"median_mbps"`
	P95Mbps    float64   `json:"p95_mbps"`
	Results    []float64 `json:"results_mbps"`
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
	for i := 0; i < *warmup+*iterations; i++ {
		ctx, cancel := context.WithTimeout(parent, *timeout)
		result, err := netbench.Run(ctx, dialer, *target, mode, *size)
		cancel()
		if err != nil {
			return fmt.Errorf("iteration %d: %w", i+1, err)
		}
		if i >= *warmup {
			results = append(results, result.Mbps())
		}
	}
	sorted := append([]float64(nil), results...)
	sort.Float64s(sorted)
	median := percentile(sorted, 0.5)
	p95 := percentile(sorted, 0.95)
	output := benchOutput{
		Mode:       strings.ToLower(*modeText),
		Transport:  transportName,
		Target:     *target,
		Bytes:      *size,
		Iterations: *iterations,
		MedianMbps: median,
		P95Mbps:    p95,
		Results:    results,
	}
	if *jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(output)
	}
	fmt.Printf("%s via %s: median %.2f Mbit/s, p95 %.2f Mbit/s (%d x %d bytes)\n",
		output.Mode, output.Transport, output.MedianMbps, output.P95Mbps, output.Iterations, output.Bytes)
	return nil
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
