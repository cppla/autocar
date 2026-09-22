// Command browser-connection-fixture is a bounded, loopback-only diagnostic
// origin for observing physical HTTP/3 connection reuse. It is not a proxy,
// browser emulator, or formal packet-capture corpus generator.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cppla/autocar/internal/security"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const fixtureHTML = "<!doctype html><html><head><meta charset=utf-8><link rel=icon href=\"data:,\"><title>Connection diagnostic</title></head><body>Local HTTP/3 connection diagnostic.</body></html>\n"

type options struct {
	listen, cert, key           string
	duration                    time.Duration
	maxRequests, maxConnections int
}

func parseOptions(args []string, stderr io.Writer) (options, error) {
	var opts options
	fs := flag.NewFlagSet("browser-connection-fixture", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.listen, "listen", "127.0.0.1:0", "127.0.0.1 or [::1] with numeric UDP port; zero selects a free port")
	fs.StringVar(&opts.cert, "cert", "", "existing certificate PEM (required)")
	fs.StringVar(&opts.key, "key", "", "existing private key PEM (required)")
	fs.DurationVar(&opts.duration, "duration", 180*time.Second, "run duration, greater than zero and at most 600s")
	fs.IntVar(&opts.maxRequests, "max-requests", 64, "maximum handled requests, 1..64")
	fs.IntVar(&opts.maxConnections, "max-connections", 32, "maximum admitted physical connections over this run, 1..32")
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if fs.NArg() != 0 {
		return opts, errors.New("positional arguments are not supported")
	}
	if err := validateListen(opts.listen); err != nil {
		return opts, err
	}
	if opts.cert == "" || opts.key == "" {
		return opts, errors.New("--cert and --key are required; this fixture never generates credentials")
	}
	if opts.duration <= 0 || opts.duration > 600*time.Second {
		return opts, errors.New("--duration must be greater than zero and at most 600s")
	}
	if opts.maxRequests < 1 || opts.maxRequests > 64 || opts.maxConnections < 1 || opts.maxConnections > 32 {
		return opts, errors.New("request/connection budgets must be in 1..64 and 1..32 respectively")
	}
	return opts, nil
}

func validateListen(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("--listen must be 127.0.0.1:numeric-port or [::1]:numeric-port")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || (ip != netip.MustParseAddr("127.0.0.1") && ip != netip.IPv6Loopback()) {
		return errors.New("--listen permits only the exact numeric addresses 127.0.0.1 and ::1")
	}
	if port == "" {
		return errors.New("--listen requires a numeric port")
	}
	for _, digit := range port {
		if digit < '0' || digit > '9' {
			return errors.New("--listen requires a numeric port")
		}
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return errors.New("--listen port must be in 0..65535")
	}
	return nil
}

type jsonLog struct {
	mu  sync.Mutex
	out io.Writer
}

func (log *jsonLog) write(value any) error {
	log.mu.Lock()
	defer log.mu.Unlock()
	return json.NewEncoder(log.out).Encode(value)
}

type connectionKey struct{}

type requestRecord struct {
	Kind         string `json:"kind"`
	ConnectionID uint64 `json:"connection_id"`
	Path         string `json:"path"`
	Trial        string `json:"trial"`
	Protocol     string `json:"protocol"`
}

type fixture struct {
	log         *jsonLog
	maxRequests uint64
	requests    atomic.Uint64
	connections atomic.Uint64
	stop        context.CancelFunc
}

func validTrial(value string) bool {
	if len(value) < 1 || len(value) > 32 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func (f *fixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if f.requests.Add(1) > f.maxRequests {
		http.Error(w, "request budget exhausted", http.StatusTooManyRequests)
		return
	}
	id, _ := r.Context().Value(connectionKey{}).(uint64)
	path := "<other>"
	if r.URL.Path == "/" || r.URL.Path == "/probe" {
		path = r.URL.Path
	}
	trial := ""
	query, queryErr := url.ParseQuery(r.URL.RawQuery)
	queryValid := queryErr == nil && len(r.URL.RawQuery) <= 128
	if path == "/probe" {
		values := query["trial"]
		queryValid = queryValid && len(query) == 1 && len(values) == 1 && validTrial(values[0])
		if queryValid {
			trial = values[0]
		}
	} else {
		queryValid = queryValid && r.URL.RawQuery == ""
	}
	// Never log arbitrary URL text, query values, headers, or peer addresses.
	if err := f.log.write(requestRecord{"request", id, path, trial, "HTTP/3.0"}); err != nil {
		f.stop()
		http.Error(w, "diagnostic output unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("X-Diagnostic-Connection-ID", strconv.FormatUint(id, 10))
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// The fixture accepts no request bodies. Closing the stream cancels any
	// unread body; QUIC receive windows independently bound buffered input.
	if r.ContentLength > 0 || len(r.TransferEncoding) != 0 {
		http.Error(w, "request bodies are not accepted", http.StatusBadRequest)
		return
	}
	// HTTP/3 GETs commonly omit content-length and arrive as -1 even with no
	// body. Read at most one byte with a stream deadline to distinguish EOF
	// from an actual body without accepting unbounded or stalled input.
	if r.ContentLength < 0 {
		if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			http.Error(w, "request stream deadline unavailable", http.StatusServiceUnavailable)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1))
		if err != nil || len(body) != 0 {
			http.Error(w, "request bodies are not accepted", http.StatusBadRequest)
			return
		}
	}
	if path == "<other>" {
		http.NotFound(w, r)
		return
	}
	if !queryValid {
		http.Error(w, "invalid diagnostic query", http.StatusBadRequest)
		return
	}
	if path == "/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; connect-src 'self'; img-src data:")
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, fixtureHTML)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		_ = json.NewEncoder(w).Encode(struct {
			ConnectionID uint64 `json:"connection_id"`
			Protocol     string `json:"protocol"`
		}{id, "HTTP/3.0"})
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	opts, err := parseOptions(args, stderr)
	if err != nil {
		return err
	}
	certificate, err := security.LoadKeyPair(opts.cert, opts.key)
	if err != nil {
		return errors.New("could not load the existing certificate/private key")
	}
	ctx, cancel := context.WithTimeout(ctx, opts.duration)
	defer cancel()
	packet, err := net.ListenPacket("udp", opts.listen)
	if err != nil {
		return errors.New("could not bind the loopback UDP listener")
	}
	defer packet.Close()
	f := &fixture{log: &jsonLog{out: stdout}, maxRequests: uint64(opts.maxRequests), stop: cancel}
	server := &http3.Server{
		Handler: f, MaxHeaderBytes: 4096, IdleTimeout: 30 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			Certificates: []tls.Certificate{certificate}, NextProtos: []string{http3.NextProtoH3}},
		QUICConfig: &quic.Config{HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 30 * time.Second,
			MaxIncomingStreams: 8, MaxIncomingUniStreams: 3,
			InitialStreamReceiveWindow: 16 << 10, MaxStreamReceiveWindow: 16 << 10,
			InitialConnectionReceiveWindow: 128 << 10, MaxConnectionReceiveWindow: 128 << 10},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			id := f.connections.Add(1)
			if id > uint64(opts.maxConnections) {
				_ = conn.CloseWithError(0x100, "connection budget exhausted")
			}
			return context.WithValue(ctx, connectionKey{}, id)
		},
	}
	listener, err := quic.Listen(packet, http3.ConfigureTLSConfig(server.TLSConfig), server.QUICConfig)
	if err != nil {
		return errors.New("could not initialize the HTTP/3 QUIC listener")
	}
	defer listener.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() { done <- server.ServeListener(listener) }()
	if err := f.log.write(struct {
		Kind    string `json:"kind"`
		Address string `json:"address"`
	}{"ready", packet.LocalAddr().String()}); err != nil {
		return errors.New("could not write diagnostic startup record")
	}
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return errors.New("HTTP/3 diagnostic listener stopped unexpectedly")
		}
	case <-ctx.Done():
		shutdown, stop := context.WithTimeout(context.Background(), 2*time.Second)
		_ = server.Shutdown(shutdown)
		stop()
		_ = server.Close()
		_ = packet.Close()
		<-done
	}
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "fixture:", err)
		os.Exit(1)
	}
}
