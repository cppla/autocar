package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPForwardRejectsTruncatedChunkedResponse(t *testing.T) {
	for _, size := range []int{32, 64 << 10} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			payload := bytes.Repeat([]byte("x"), size)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				// Send a complete data chunk but omit the terminal zero chunk.
				// The body length is unknown, so a proxy that returns normally
				// after a copy error can falsely turn this into a complete reply.
				_, _ = fmt.Fprintf(rw, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n", len(payload))
				_, _ = rw.Write(payload)
				_, _ = rw.WriteString("\r\n")
				_ = rw.Flush()
			}))
			defer origin.Close()
			server, proxyURL, stop := startHTTPProxy(t, Config{Dialer: directDialer()})
			defer stop(server)
			client := proxyHTTPClient(t, proxyURL, nil)
			defer client.CloseIdleConnections()
			response, err := client.Get(origin.URL)
			if err != nil {
				t.Fatalf("read streamed response headers: %v", err)
			}
			defer response.Body.Close()
			got, err := io.ReadAll(response.Body)
			if !errors.Is(err, io.ErrUnexpectedEOF) || response.StatusCode != http.StatusOK || !bytes.Equal(got, payload) {
				t.Fatalf("truncated chunked response: status=%d bytes=%d error=%v; want 200, %d bytes and unexpected EOF", response.StatusCode, len(got), err, size)
			}
		})
	}
}

func TestHTTPForwardStreamsBeforeOriginCompletes(t *testing.T) {
	for _, kind := range []string{"unknown length", "event stream with known length"} {
		t.Run(kind, func(t *testing.T) {
			const first = "data: first\n\n"
			const last = "data: last\n\n"
			release := make(chan struct{})
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if kind == "event stream with known length" {
					w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
					w.Header().Set("Content-Length", fmt.Sprint(len(first)+len(last)))
				}
				_, _ = io.WriteString(w, first)
				w.(http.Flusher).Flush()
				select {
				case <-release:
					_, _ = io.WriteString(w, last)
				case <-r.Context().Done():
				}
			}))
			defer origin.Close()
			server, proxyURL, stop := startHTTPProxy(t, Config{Dialer: directDialer()})
			defer stop(server)
			client := proxyHTTPClient(t, proxyURL, nil)
			client.Timeout = 2 * time.Second
			defer client.CloseIdleConnections()
			response, err := client.Get(origin.URL)
			if err != nil {
				t.Fatalf("receive response while origin remains open: %v", err)
			}
			defer response.Body.Close()
			prefix := make([]byte, len(first))
			if _, err := io.ReadFull(response.Body, prefix); err != nil {
				t.Fatalf("read first event before releasing origin: %v", err)
			}
			if string(prefix) != first {
				t.Fatalf("first event = %q", prefix)
			}
			close(release)
			rest, err := io.ReadAll(response.Body)
			if err != nil || string(rest) != last {
				t.Fatalf("remaining stream = %q, %v", rest, err)
			}
		})
	}
}

func TestHTTPForwardCompleteChunkedResponseWithTrailers(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Trailer", "X-Body-Complete")
		_, _ = io.WriteString(w, "first")
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, "last")
		w.Header().Set("X-Body-Complete", "yes")
	}))
	defer origin.Close()
	server, proxyURL, stop := startHTTPProxy(t, Config{Dialer: directDialer()})
	defer stop(server)
	client := proxyHTTPClient(t, proxyURL, nil)
	defer client.CloseIdleConnections()
	response, err := client.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "firstlast" || response.Trailer.Get("X-Body-Complete") != "yes" {
		t.Fatalf("complete response body=%q trailer=%v error=%v", body, response.Trailer, err)
	}
}
