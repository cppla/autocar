// Command stealth-pilot supplies the deliberately small, isolated workloads
// used by scripts/stealth-pilot.sh. It is a calibration helper, not a release
// benchmark and not a browser emulator.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	maxFixtureBytes              = 1 << 20
	requestTimeout               = 30 * time.Second
	defaultIdle                  = 1200 * time.Millisecond
	bootstrapHTML                = "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"autocar-stealth-bootstrap\" content=\"v1\"><link rel=\"icon\" href=\"data:,\"><title>AutoCAR Stealth Fixture</title></head><body></body></html>\n"
	uploadReceiptBytes           = 32
	interactiveRounds            = 8
	interactiveUploadBytes       = 256
	interactiveDownloadBytes     = 512
	payloadDomainUpload          = 1
	payloadDomainUploadReceipt   = 2
	payloadDomainInteractiveUp   = 3
	payloadDomainInteractiveDown = 4
	supportedWorkloads           = "idle, download_1k, download_128k, download_1m, upload_1m, parallel_20, or interactive"
)

type doer interface {
	Do(*http.Request) (*http.Response, error)
}

// proxyKeepAliveDoer makes the local HTTP/1.1 proxy connection semantics
// explicit.  The pinned Hysteria 2 forward proxy keeps a client connection
// alive only when this hop-by-hop header is present, whereas net/http assumes
// persistence by default.  Apply this wrapper to both proxy products so their
// application workload is identical; neither direct H3 nor browser cover
// traffic uses it.
type proxyKeepAliveDoer struct {
	inner doer
}

func (d proxyKeepAliveDoer) Do(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	clone.Header.Set("Proxy-Connection", "keep-alive")
	return d.inner.Do(clone)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "stealth-pilot:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("a command is required")
	}
	switch args[0] {
	case "serve-origin":
		return runServeOrigin(ctx, args[1:])
	case "serve-h3":
		return runServeH3(ctx, args[1:])
	case "h3-workload":
		return runH3Workload(ctx, args[1:])
	case "proxy-workload":
		return runProxyWorkload(ctx, args[1:])
	case "probe-http":
		return runProbeHTTP(ctx, args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func fixtureHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if len(r.Header.Values("Proxy-Connection")) != 0 {
			http.Error(w, "proxy hop header reached the origin", http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/" {
			serveFixtureBootstrap(w, r)
			return
		}
		if r.URL.Path == "/health" {
			if !allowFixtureMethods(w, r, http.MethodGet, http.MethodHead) {
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			if r.Method != http.MethodHead {
				_, _ = io.WriteString(w, "ok\n")
			}
			return
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/bytes/"):
			serveFixtureDownload(w, r)
		case strings.HasPrefix(r.URL.Path, "/upload/"):
			serveFixtureUpload(w, r)
		case strings.HasPrefix(r.URL.Path, "/exchange/"):
			serveFixtureExchange(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func serveFixtureBootstrap(w http.ResponseWriter, r *http.Request) {
	if !allowFixtureMethods(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(bootstrapHTML)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, bootstrapHTML)
	}
}

func allowFixtureMethods(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	for _, method := range methods {
		if r.Method == method {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(methods, ", "))
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func serveFixtureDownload(w http.ResponseWriter, r *http.Request) {
	if !allowFixtureMethods(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	size, err := fixtureSize(r.URL.Path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	writeFixtureBody(w, r.Method, fixtureBody(size))
}

func serveFixtureUpload(w http.ResponseWriter, r *http.Request) {
	if !allowFixtureMethods(w, r, http.MethodPost) {
		return
	}
	size, err := fixturePathSize(r.URL.Path, "/upload/")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	seed, requestIndex, err := fixtureCoordinates(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := verifyFixtureRequestBody(r, seededFixtureBody(size, seed, requestIndex, payloadDomainUpload)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	receipt := seededFixtureBody(uploadReceiptBytes, seed, requestIndex, payloadDomainUploadReceipt)
	writeFixtureBody(w, r.Method, receipt)
}

func serveFixtureExchange(w http.ResponseWriter, r *http.Request) {
	if !allowFixtureMethods(w, r, http.MethodPost) {
		return
	}
	uploadSize, downloadSize, err := fixturePathSizes(r.URL.Path, "/exchange/")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	seed, requestIndex, err := fixtureCoordinates(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	upload := seededFixtureBody(uploadSize, seed, requestIndex, payloadDomainInteractiveUp)
	if err := verifyFixtureRequestBody(r, upload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	download := seededFixtureBody(downloadSize, seed, requestIndex, payloadDomainInteractiveDown)
	writeFixtureBody(w, r.Method, download)
}

func fixtureCoordinates(r *http.Request) (int64, int, error) {
	query := r.URL.Query()
	if len(query) != 2 || len(query["seed"]) != 1 || len(query["request"]) != 1 {
		return 0, 0, errors.New("fixture requires exactly one seed and request query value")
	}
	seed, err := strconv.ParseInt(query["seed"][0], 10, 64)
	if err != nil {
		return 0, 0, errors.New("fixture seed must be a base-10 int64")
	}
	requestIndex, err := strconv.Atoi(query["request"][0])
	if err != nil || requestIndex < 0 || requestIndex > 1_000_000 {
		return 0, 0, errors.New("fixture request must be in 0..1000000")
	}
	return seed, requestIndex, nil
}

func verifyFixtureRequestBody(r *http.Request, expected []byte) error {
	if r.Header.Get("Content-Type") != "application/octet-stream" {
		return errors.New("fixture request must use application/octet-stream")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(len(expected))+1))
	if err != nil {
		return fmt.Errorf("read fixture request: %w", err)
	}
	if !bytes.Equal(body, expected) {
		return errors.New("fixture request payload mismatch")
	}
	return nil
}

func writeFixtureBody(w http.ResponseWriter, method string, body []byte) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if method != http.MethodHead && len(body) != 0 {
		_, _ = w.Write(body)
	}
}

func fixtureSize(path string) (int, error) {
	return fixturePathSize(path, "/bytes/")
}

func fixturePathSize(path, prefix string) (int, error) {
	if !strings.HasPrefix(path, prefix) {
		return 0, errors.New("not a fixture path")
	}
	text := strings.TrimPrefix(path, prefix)
	if text == "" || strings.Contains(text, "/") {
		return 0, errors.New("invalid fixture size")
	}
	size, err := strconv.Atoi(text)
	if err != nil || size < 0 || size > maxFixtureBytes {
		return 0, errors.New("invalid fixture size")
	}
	return size, nil
}

func fixturePathSizes(path, prefix string) (int, int, error) {
	if !strings.HasPrefix(path, prefix) {
		return 0, 0, errors.New("not a fixture path")
	}
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	if len(parts) != 2 {
		return 0, 0, errors.New("invalid fixture sizes")
	}
	first, err := fixturePathSize(prefix+parts[0], prefix)
	if err != nil {
		return 0, 0, errors.New("invalid fixture sizes")
	}
	second, err := fixturePathSize(prefix+parts[1], prefix)
	if err != nil {
		return 0, 0, errors.New("invalid fixture sizes")
	}
	return first, second, nil
}

func fixtureBody(size int) []byte {
	body := make([]byte, size)
	for index := range body {
		body[index] = byte((index*31 + 17) % 251)
	}
	return body
}

// seededFixtureBody is intentionally stable across processes and Go versions.
// The domain separates uploaded bytes, upload receipts, and the two directions
// of an interactive exchange even when their seed, request index, and size match.
func seededFixtureBody(size int, seed int64, requestIndex int, domain uint64) []byte {
	body := make([]byte, size)
	state := uint64(seed) ^ (uint64(requestIndex)+1)*0x9e3779b97f4a7c15 ^ domain*0xd1b54a32d192ed03
	for index := range body {
		state += 0x9e3779b97f4a7c15
		value := state
		value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9
		value = (value ^ (value >> 27)) * 0x94d049bb133111eb
		value ^= value >> 31
		body[index] = byte(value >> 56)
	}
	return body
}

func runServeOrigin(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("serve-origin", flag.ContinueOnError)
	listen := flags.String("listen", ":8080", "container-local HTTP listen address")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := validateContainerListen(*listen); err != nil {
		return err
	}
	server := &http.Server{
		Addr:              *listen,
		Handler:           fixtureHandler(),
		ReadHeaderTimeout: 3 * time.Second,
		IdleTimeout:       15 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	err := server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}

func runServeH3(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("serve-h3", flag.ContinueOnError)
	listen := flags.String("listen", ":8443", "container-local UDP listen address")
	certFile := flags.String("cert", "", "TLS certificate")
	keyFile := flags.String("key", "", "TLS private key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := validateContainerListen(*listen); err != nil {
		return err
	}
	if *certFile == "" || *keyFile == "" {
		return errors.New("--cert and --key are required")
	}
	certificate, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return fmt.Errorf("load H3 certificate: %w", err)
	}
	packet, err := net.ListenPacket("udp", *listen)
	if err != nil {
		return fmt.Errorf("listen H3 UDP: %w", err)
	}
	defer packet.Close()
	server := &http3.Server{
		Handler: fixtureHandler(),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{certificate},
			NextProtos:   []string{http3.NextProtoH3},
		},
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			MaxIdleTimeout:       15 * time.Second,
		},
	}
	go func() {
		<-ctx.Done()
		_ = server.Close()
	}()
	err = server.Serve(packet)
	if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func runH3Workload(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("h3-workload", flag.ContinueOnError)
	server := flags.String("server", "", "numeric RFC1918 server host:port")
	serverName := flags.String("server-name", "", "TLS certificate DNS name")
	caFile := flags.String("ca", "", "PEM trust anchor")
	workload := flags.String("workload", "", supportedWorkloads)
	seed := flags.Int64("seed", 0, "sample seed")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := validateRFC1918HostPort(*server); err != nil {
		return fmt.Errorf("--server: %w", err)
	}
	if *serverName == "" || *caFile == "" {
		return errors.New("--server-name and --ca are required")
	}
	roots, err := loadRoots(*caFile)
	if err != nil {
		return err
	}
	baseURL, tlsConfig := h3WorkloadRoute(*server, *serverName, roots)
	transport := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			MaxIdleTimeout:       15 * time.Second,
		},
		Dial: func(dialCtx context.Context, _ string, config *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(dialCtx, *server, config.Clone(), quicConfig.Clone())
		},
	}
	defer transport.Close()
	client := &http.Client{Transport: transport}
	return executeWorkload(ctx, client, baseURL, *workload, *seed, defaultIdle)
}

func h3WorkloadRoute(
	server, serverName string, roots *x509.CertPool,
) (string, *tls.Config) {
	return "https://" + server, &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		ServerName: serverName,
		RootCAs:    roots,
		NextProtos: []string{http3.NextProtoH3},
	}
}

func runProxyWorkload(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("proxy-workload", flag.ContinueOnError)
	clientKind := flags.String("client", "", "autocar or hysteria2")
	clientBin := flags.String("client-bin", "", "fixed in-container client binary")
	clientConfig := flags.String("client-config", "", "Hysteria client configuration")
	proxyListen := flags.String("proxy-listen", "127.0.0.1:18080", "loopback HTTP proxy listen address")
	server := flags.String("server", "", "numeric RFC1918 relay host:port")
	serverName := flags.String("server-name", "", "AutoCAR TLS certificate DNS name")
	caFile := flags.String("ca", "", "AutoCAR PEM trust anchor")
	tokenFile := flags.String("token-file", "", "AutoCAR shared token")
	origin := flags.String("origin", "", "numeric RFC1918 HTTP origin URL")
	workload := flags.String("workload", "", supportedWorkloads)
	seed := flags.Int64("seed", 0, "sample seed")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := validateRFC1918HostPort(*server); err != nil {
		return fmt.Errorf("--server: %w", err)
	}
	if err := validateLoopbackHostPort(*proxyListen); err != nil {
		return fmt.Errorf("--proxy-listen: %w", err)
	}
	if err := validatePrivateHTTPURL(*origin); err != nil {
		return fmt.Errorf("--origin: %w", err)
	}
	var commandArgs []string
	switch *clientKind {
	case "autocar":
		if *clientBin != "/autocar" {
			return errors.New("the AutoCAR pilot client must be /autocar")
		}
		if *serverName == "" || *caFile == "" || *tokenFile == "" {
			return errors.New("AutoCAR requires --server-name, --ca, and --token-file")
		}
		commandArgs = []string{
			"client", "--server", *server, "--transport", "h3",
			"--h3-fingerprint", "chrome-2026-08", "--server-name", *serverName,
			"--ca", *caFile, "--token-file", *tokenFile, "--socks", "",
			"--http", *proxyListen, "--dial-timeout", "4s", "--open-timeout", "12s",
			"--idle-timeout", "20s", "--max-connections", "128",
		}
	case "hysteria2":
		if *clientBin != "/hysteria" || *clientConfig != "/pilot/hysteria-client.yaml" {
			return errors.New("the Hysteria pilot requires fixed /hysteria and /pilot/hysteria-client.yaml paths")
		}
		commandArgs = hysteriaClientCommandArgs(*clientConfig)
	default:
		return errors.New("--client must be autocar or hysteria2")
	}
	child := exec.Command(*clientBin, commandArgs...)
	child.Env = append(os.Environ(), "HOME=/tmp", "XDG_CACHE_HOME=/tmp")
	child.Stdout = os.Stderr
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		return fmt.Errorf("start %s client: %w", *clientKind, err)
	}
	exited := make(chan error, 1)
	go func() { exited <- child.Wait() }()
	defer stopChild(child, exited)
	if err := waitForListener(ctx, *proxyListen, exited, 8*time.Second); err != nil {
		return fmt.Errorf("wait for %s proxy: %w", *clientKind, err)
	}
	proxyURL := &url.URL{Scheme: "http", Host: *proxyListen}
	transport := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL),
		DisableCompression:  true,
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 32,
		MaxConnsPerHost:     32,
		IdleConnTimeout:     15 * time.Second,
	}
	defer transport.CloseIdleConnections()
	client := proxyKeepAliveDoer{inner: &http.Client{Transport: transport}}
	return executeWorkload(ctx, client, *origin, *workload, *seed, defaultIdle)
}

func hysteriaClientCommandArgs(config string) []string {
	return []string{"client", "--disable-update-check", "-c", config}
}

// executeWorkload maps each preregistered label to a fixed request pattern.
// upload_1m is one verified 1 MiB POST with a 32-byte receipt. Interactive is
// eight ordered exchanges, each carrying 256 bytes up and 512 bytes down.  All
// labels first perform the same captured bootstrap navigation as the browser
// control so the three products have an equivalent application request prefix.
func executeWorkload(ctx context.Context, client doer, baseURL, workload string, seed int64, idle time.Duration) error {
	if !isSupportedWorkload(workload) {
		return fmt.Errorf("unsupported pilot workload %q", workload)
	}
	bootstrap := func() error {
		requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		defer cancel()
		endpoint := fmt.Sprintf(
			"%s/?autocar_browser_sample=%d", strings.TrimRight(baseURL, "/"), seed,
		)
		req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		req.Header.Set("Cache-Control", "no-cache")
		response, err := client.Do(req)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected bootstrap response status %d", response.StatusCode)
		}
		if response.Header.Get("Content-Type") != "text/html; charset=utf-8" {
			return fmt.Errorf("unexpected bootstrap content type %q", response.Header.Get("Content-Type"))
		}
		if response.ContentLength != int64(len(bootstrapHTML)) {
			return fmt.Errorf(
				"bootstrap content length %d, want %d", response.ContentLength, len(bootstrapHTML),
			)
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, int64(len(bootstrapHTML))+1))
		if err != nil {
			return err
		}
		if !bytes.Equal(body, []byte(bootstrapHTML)) {
			return errors.New("bootstrap response payload mismatch")
		}
		return nil
	}
	if err := bootstrap(); err != nil {
		return fmt.Errorf("bootstrap workload session: %w", err)
	}
	request := func(method, path string, index int, requestBody, expectedBody []byte) error {
		requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		defer cancel()
		endpoint := fmt.Sprintf("%s%s?seed=%d&request=%d", strings.TrimRight(baseURL, "/"), path, seed, index)
		var body io.Reader
		if requestBody != nil {
			body = bytes.NewReader(requestBody)
		}
		req, err := http.NewRequestWithContext(requestCtx, method, endpoint, body)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/octet-stream")
		req.Header.Set("Cache-Control", "no-cache")
		if requestBody != nil {
			req.Header.Set("Content-Type", "application/octet-stream")
		}
		response, err := client.Do(req)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected response status %d", response.StatusCode)
		}
		bodyBytes, err := io.ReadAll(io.LimitReader(response.Body, int64(len(expectedBody))+1))
		if err != nil {
			return err
		}
		if len(bodyBytes) != len(expectedBody) {
			return fmt.Errorf("response length %d, want %d", len(bodyBytes), len(expectedBody))
		}
		if !bytes.Equal(bodyBytes, expectedBody) {
			return errors.New("response payload mismatch")
		}
		return nil
	}
	download := func(index, size int) error {
		return request(http.MethodGet, fmt.Sprintf("/bytes/%d", size), index, nil, fixtureBody(size))
	}
	upload := func(index, size int) error {
		body := seededFixtureBody(size, seed, index, payloadDomainUpload)
		receipt := seededFixtureBody(uploadReceiptBytes, seed, index, payloadDomainUploadReceipt)
		return request(http.MethodPost, fmt.Sprintf("/upload/%d", size), index, body, receipt)
	}
	exchange := func(index, uploadSize, downloadSize int) error {
		body := seededFixtureBody(uploadSize, seed, index, payloadDomainInteractiveUp)
		response := seededFixtureBody(downloadSize, seed, index, payloadDomainInteractiveDown)
		path := fmt.Sprintf("/exchange/%d/%d", uploadSize, downloadSize)
		return request(http.MethodPost, path, index, body, response)
	}
	switch workload {
	case "idle":
		if err := download(0, 0); err != nil {
			return fmt.Errorf("open idle session: %w", err)
		}
		timer := time.NewTimer(idle)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	case "download_1k":
		return download(0, 1<<10)
	case "download_128k":
		return download(0, 128<<10)
	case "download_1m":
		return download(0, 1<<20)
	case "upload_1m":
		return upload(0, 1<<20)
	case "parallel_20":
		start := make(chan struct{})
		errorsCh := make(chan error, 20)
		var wait sync.WaitGroup
		for index := 0; index < 20; index++ {
			index := index
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				if err := download(index, 1<<10); err != nil {
					errorsCh <- fmt.Errorf("parallel request %d: %w", index, err)
				}
			}()
		}
		close(start)
		wait.Wait()
		close(errorsCh)
		var joined error
		for err := range errorsCh {
			joined = errors.Join(joined, err)
		}
		return joined
	case "interactive":
		for index := 0; index < interactiveRounds; index++ {
			if err := exchange(index, interactiveUploadBytes, interactiveDownloadBytes); err != nil {
				return fmt.Errorf("interactive exchange %d: %w", index, err)
			}
		}
		return nil
	default:
		panic("validated workload was not dispatched")
	}
}

func isSupportedWorkload(workload string) bool {
	switch workload {
	case "idle", "download_1k", "download_128k", "download_1m", "upload_1m", "parallel_20", "interactive":
		return true
	default:
		return false
	}
}

func runProbeHTTP(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("probe-http", flag.ContinueOnError)
	endpoint := flags.String("url", "", "numeric RFC1918 HTTP URL")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := validatePrivateHTTPProbeURL(*endpoint); err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, *endpoint, nil)
	if err != nil {
		return err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("probe returned %d", response.StatusCode)
	}
	return nil
}

func loadRoots(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("CA file contains no certificate")
	}
	return pool, nil
}

func waitForListener(ctx context.Context, address string, exited <-chan error, timeout time.Duration) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(40 * time.Millisecond)
	defer ticker.Stop()
	for {
		connection, err := net.DialTimeout("tcp", address, 80*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return nil
		}
		select {
		case err := <-exited:
			return fmt.Errorf("client exited before readiness: %w", err)
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("listener readiness timeout")
		case <-ticker.C:
		}
	}
}

func stopChild(command *exec.Cmd, exited <-chan error) {
	if command.Process == nil {
		return
	}
	_ = command.Process.Signal(syscall.SIGTERM)
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	select {
	case <-exited:
	case <-timer.C:
		_ = command.Process.Kill()
		<-exited
	}
}

func validateContainerListen(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil || port == "" {
		return errors.New("listen address must be :port or 0.0.0.0:port")
	}
	if host != "" && host != "0.0.0.0" {
		return errors.New("listen host must be empty or 0.0.0.0")
	}
	return validatePort(port)
}

func validateRFC1918HostPort(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return errors.New("endpoint must be numeric host:port")
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil || !isRFC1918(ip.To4()) {
		return errors.New("endpoint must use an RFC1918 IPv4 address")
	}
	return validatePort(port)
}

func validateLoopbackHostPort(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return errors.New("endpoint must be numeric host:port")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("endpoint must use a loopback IP")
	}
	return validatePort(port)
}

func validatePrivateHTTPURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("URL must be an origin-only http://RFC1918-IP:port value")
	}
	if err := validateRFC1918HostPort(parsed.Host); err != nil {
		return err
	}
	return nil
}

func validatePrivateHTTPProbeURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("probe URL must be http://RFC1918-IP:port/path")
	}
	if err := validateRFC1918HostPort(parsed.Host); err != nil {
		return err
	}
	if parsed.Path == "" || !strings.HasPrefix(parsed.Path, "/") {
		return errors.New("probe URL requires an absolute path")
	}
	return nil
}

func validatePort(value string) error {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("port must be in 1..65535")
	}
	return nil
}

func isRFC1918(ip net.IP) bool {
	return ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) || (ip[0] == 192 && ip[1] == 168)
}
