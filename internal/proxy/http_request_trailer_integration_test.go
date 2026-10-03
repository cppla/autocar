package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

// This regression uses raw owned TCP on both sides. The origin must
// have consumed the first complete body chunk before the visitor sends EOF and
// the two trailing fields. It does not simulate a prepopulated request map.
func TestHTTPForwardRequestTrailersStream(t *testing.T) {
	for _, mode := range []string{"direct", "proxy", "proxy_filters_late_fields"} {
		t.Run(mode, func(t *testing.T) {
			httpRequestTrailerRun(t, mode)
		})
	}
}

func TestHTTPForwardRequestTrailersVisitorCancellation(t *testing.T) {
	httpRequestTrailerRun(t, "proxy_canceled_upload")
}

func httpRequestTrailerRun(t *testing.T, mode string) {
	t.Helper()
	payload := bytes.Repeat([]byte("streamed-trailer-body\n"), 3277)
	payload = payload[:64<<10]
	sum := sha256.Sum256(payload)
	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	firstBody := make(chan struct{})
	originDone := make(chan struct{})
	type observation struct {
		body     []byte
		headers  http.Header
		trailers http.Header
		status   int
		err      error
	}
	observed := make(chan observation, 1)
	var originMu sync.Mutex
	var originConn net.Conn
	originClosed := false
	var visitor net.Conn
	var proxyServer *HTTPServer
	var proxyListener net.Listener
	var proxyDone chan struct{}
	var proxyResult chan error
	var handlerEntered, handlerDone chan struct{}
	// Register independent cleanup before launching any owned worker.
	t.Cleanup(func() {
		if visitor != nil {
			_ = visitor.Close()
		}
		originMu.Lock()
		originClosed = true
		owned := originConn
		originMu.Unlock()
		_ = origin.Close()
		if owned != nil {
			_ = owned.Close()
		}
		if proxyServer != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			err := proxyServer.Shutdown(ctx)
			cancel()
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("proxy cleanup shutdown: %v", err)
			}
		}
		if proxyListener != nil {
			_ = proxyListener.Close()
		}
		auditTrailerJoin(t, originDone, "origin worker")
		if proxyDone != nil {
			auditTrailerJoin(t, proxyDone, "proxy Serve")
			select {
			case <-handlerEntered:
				auditTrailerJoin(t, handlerDone, "proxy handler")
			default:
			}
			select {
			case err := <-proxyResult:
				if err != nil {
					t.Errorf("proxy Serve: %v", err)
				}
			default:
				t.Error("joined proxy Serve has no result")
			}
		}
	})
	go func() {
		defer close(originDone)
		result := observation{}
		defer func() { observed <- result }()
		conn, err := origin.Accept()
		if err != nil {
			result.err = err
			return
		}
		originMu.Lock()
		if originClosed {
			originMu.Unlock()
			_ = conn.Close()
			result.err = net.ErrClosed
			return
		}
		originConn = conn
		originMu.Unlock()
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			result.err = err
			return
		}
		defer request.Body.Close()
		result.headers = request.Header.Clone()
		first := make([]byte, len(payload))
		if _, err := io.ReadFull(request.Body, first); err != nil {
			result.err = err
			return
		}
		close(firstBody)
		rest, err := io.ReadAll(request.Body)
		result.body = append(first, rest...)
		result.trailers = request.Trailer.Clone()
		if err != nil {
			result.err = err
			return
		}
		result.status = http.StatusUnprocessableEntity
		if bytes.Equal(result.body, payload) && result.trailers.Get("Content-Digest") == digest && result.trailers.Get("X-Upload-End") == "complete" {
			result.status = http.StatusOK
		}
		_, result.err = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok", result.status, http.StatusText(result.status))
	}()
	address := origin.Addr().String()
	requestTarget := "/upload"
	if mode != "direct" {
		proxyServer, err = NewHTTPServer(Config{Dialer: transport.DialFunc(func(ctx context.Context, network, target string) (net.Conn, error) {
			if network != "tcp" || target != origin.Addr().String() {
				return nil, fmt.Errorf("diagnostic rejected non-owned target %q %q", network, target)
			}
			return (&net.Dialer{}).DialContext(ctx, network, target)
		})})
		if err != nil {
			t.Fatal(err)
		}
		handlerEntered, handlerDone = make(chan struct{}), make(chan struct{})
		originalHandler := proxyServer.server.Handler
		proxyServer.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(handlerEntered)
			defer close(handlerDone)
			originalHandler.ServeHTTP(w, r)
		})
		proxyListener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		proxyDone, proxyResult = make(chan struct{}), make(chan error, 1)
		go func() {
			defer close(proxyDone)
			proxyResult <- proxyServer.Serve(proxyListener)
		}()
		address = proxyListener.Addr().String()
		requestTarget = "http://" + origin.Addr().String() + "/upload"
	}
	visitor, err = net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = visitor.SetDeadline(time.Now().Add(3 * time.Second))
	declared := "Content-Digest, X-Upload-End"
	connection := "close"
	extraHeaders := ""
	if mode == "proxy_filters_late_fields" {
		// Go's H1 parser accepts these adversarial fields. Authentication
		// and hop fields are not claimed to be valid end-to-end trailers.
		declared += ", Connection, X-Initial-Nominated, X-Late-Nominated, Proxy-Authorization, Proxy-Authenticate, Proxy-Authentication-Info, Proxy-Connection, Te"
		connection += ", X-Initial-Nominated"
		extraHeaders = "Authorization: Bearer website-dummy\r\nProxy-Authorization: Basic proxy-dummy\r\nX-Initial-Nominated: header-dummy\r\n"
	}
	firstWire := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nTrailer: %s\r\nConnection: %s\r\n%s\r\n%x\r\n", requestTarget, origin.Addr(), declared, connection, extraHeaders, len(payload))
	if err := auditTrailerWriteAll(visitor, append(append([]byte(firstWire), payload...), []byte("\r\n")...)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstBody:
		t.Logf("origin consumed first %d bytes before visitor EOF/trailers", len(payload))
	case <-originDone:
		t.Fatal("origin ended before first-body witness")
	case <-time.After(2 * time.Second):
		t.Fatal("origin first-body witness timeout")
	}
	if mode == "proxy_canceled_upload" {
		// This explicit visitor closure, not fixture cleanup, is the
		// cancellation event while the source Body still awaits EOF.
		if err := visitor.Close(); err != nil {
			t.Fatal(err)
		}
		if !auditTrailerJoin(t, originDone, "canceled origin worker") || !auditTrailerJoin(t, handlerDone, "canceled proxy handler") {
			t.FailNow()
		}
		result := <-observed
		if !errors.Is(result.err, io.EOF) && !errors.Is(result.err, io.ErrUnexpectedEOF) {
			t.Errorf("visitor closure did not interrupt origin body with EOF: %v", result.err)
		}
		if !bytes.Equal(result.body, payload) {
			t.Errorf("canceled origin first body bytes=%d want=%d", len(result.body), len(payload))
		}
		t.Logf("explicit visitor Close joined origin and proxy handler before cleanup: bytes=%d error=%v", len(result.body), result.err)
		return
	}
	lastWire := "0\r\nContent-Digest: " + digest + "\r\nX-Upload-End: complete\r\n"
	if mode == "proxy_filters_late_fields" {
		lastWire += "Connection: X-Late-Nominated\r\nX-Initial-Nominated: initial-dummy\r\nX-Late-Nominated: late-dummy\r\nProxy-Authorization: Basic trailer-dummy\r\nProxy-Authenticate: Basic dummy\r\nProxy-Authentication-Info: dummy\r\nProxy-Connection: keep-alive\r\nTe: trailers\r\n"
	}
	if err := auditTrailerWriteAll(visitor, []byte(lastWire+"\r\n")); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(visitor), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || string(body) != "ok" {
		t.Fatalf("response body=%q read=%v close=%v", body, readErr, closeErr)
	}
	if !auditTrailerJoin(t, originDone, "completed origin worker") {
		t.FailNow()
	}
	result := <-observed // buffered and published before originDone closes
	gotSum := sha256.Sum256(result.body)
	t.Logf("status=%d bodyBytes=%d sha256=%x trailers=%v originError=%v", response.StatusCode, len(result.body), gotSum, result.trailers, result.err)
	if result.err != nil || !bytes.Equal(result.body, payload) {
		t.Fatalf("origin body integrity error=%v bytes=%d", result.err, len(result.body))
	}
	if response.StatusCode != http.StatusOK || result.trailers.Get("Content-Digest") != digest || result.trailers.Get("X-Upload-End") != "complete" {
		t.Errorf("streamed request trailers lost: status=%d Content-Digest=%q X-Upload-End=%q", response.StatusCode, result.trailers.Get("Content-Digest"), result.trailers.Get("X-Upload-End"))
	}
	if mode == "proxy_filters_late_fields" {
		for _, key := range []string{"Connection", "X-Initial-Nominated", "X-Late-Nominated", "Proxy-Authorization", "Proxy-Authenticate", "Proxy-Authentication-Info", "Proxy-Connection", "Te"} {
			for field := range result.trailers {
				if strings.EqualFold(field, key) {
					// The initial declaration is already on the wire before the
					// late Connection nomination appears at EOF. Streaming can
					// filter all values, but cannot retract that declaration.
					if key == "X-Late-Nominated" && len(result.trailers[field]) == 0 {
						continue
					}
					t.Errorf("unsafe trailer declaration/value reached origin: %s=%v", field, result.trailers[field])
				}
			}
		}
		if result.headers.Get("Authorization") != "Bearer website-dummy" || result.headers.Get("Proxy-Authorization") != "" || result.headers.Get("X-Initial-Nominated") != "" {
			t.Errorf("request header policy changed/leaked: %v", result.headers)
		}
	}
}

func auditTrailerWriteAll(conn net.Conn, data []byte) error {
	for len(data) != 0 {
		n, err := conn.Write(data)
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func auditTrailerJoin(t *testing.T, done <-chan struct{}, what string) bool {
	t.Helper()
	select {
	case <-done:
		return true
	case <-time.After(2 * time.Second):
		t.Errorf("%s failed to join", what)
		return false
	}
}
