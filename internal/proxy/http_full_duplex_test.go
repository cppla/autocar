package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPForwardResponseBeforeUploadCompletes(t *testing.T) {
	for _, framing := range []string{"content-length", "chunked"} {
		for _, route := range []string{"direct", "proxy"} {
			t.Run(framing+"/"+route, func(t *testing.T) {
				originDone := make(chan error, 1)
				origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var result error
					defer func() { originDone <- result }()
					if result = http.NewResponseController(w).EnableFullDuplex(); result != nil {
						return
					}
					prefix := make([]byte, 3)
					if _, result = io.ReadFull(r.Body, prefix); result != nil {
						return
					}
					if string(prefix) != "abc" {
						result = fmt.Errorf("upload prefix = %q, want abc", prefix)
						return
					}
					w.Header().Set("Content-Type", "text/event-stream")
					if _, result = io.WriteString(w, "accepted\n"); result != nil {
						return
					}
					if result = http.NewResponseController(w).Flush(); result != nil {
						return
					}
					rest, err := io.ReadAll(r.Body)
					if err != nil || string(rest) != "def" {
						result = fmt.Errorf("upload remainder = %q, error = %v; want def and nil", rest, err)
						return
					}
					_, result = io.WriteString(w, "done\n")
				}))
				defer origin.Close()
				originURL, err := url.Parse(origin.URL)
				if err != nil {
					t.Fatal(err)
				}
				address, target := originURL.Host, "/"
				if route == "proxy" {
					server, proxyAddress, stop := startHTTPProxy(t, Config{Dialer: directDialer(), IdleTimeout: 5 * time.Second})
					defer stop(server)
					proxyURL, err := url.Parse(proxyAddress)
					if err != nil {
						t.Fatal(err)
					}
					address, target = proxyURL.Host, origin.URL+"/"
				}
				client, err := net.DialTimeout("tcp", address, 3*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatal(err)
				}
				header, prefix, suffix := "Content-Length: 6", "abc", "def"
				if framing == "chunked" {
					header, prefix, suffix = "Transfer-Encoding: chunked", "3\r\nabc\r\n", "3\r\ndef\r\n0\r\n\r\n"
				}
				if _, err := fmt.Fprintf(client, "POST %s HTTP/1.1\r\nHost: %s\r\n%s\r\n\r\n%s", target, originURL.Host, header, prefix); err != nil {
					t.Fatal(err)
				}
				// The remaining request bytes are withheld until the first response
				// event arrives. Draining the request before responding deadlocks.
				response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodPost})
				if err != nil {
					t.Fatalf("response before upload completes: %v", err)
				}
				defer response.Body.Close()
				if response.StatusCode != http.StatusOK {
					t.Fatalf("response status = %d, want 200", response.StatusCode)
				}
				progress := make([]byte, len("accepted\n"))
				if _, err := io.ReadFull(response.Body, progress); err != nil || string(progress) != "accepted\n" {
					t.Fatalf("progress before upload completes = %q, error = %v", progress, err)
				}
				if _, err := io.WriteString(client, suffix); err != nil {
					t.Fatal(err)
				}
				rest, err := io.ReadAll(response.Body)
				if err != nil || string(rest) != "done\n" {
					t.Fatalf("final response = %q, error = %v; want done and nil", rest, err)
				}
				select {
				case err := <-originDone:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("origin did not finish reading the complete upload")
				}
			})
		}
	}
}

func TestHTTPForwardFullDuplexWriterCompatibility(t *testing.T) {
	fixtureErr := errors.New("full duplex fixture failure")
	for _, test := range []struct {
		name       string
		err        error
		wantStatus int
	}{
		{name: "enabled", wantStatus: http.StatusOK},
		{name: "unsupported", err: fmt.Errorf("wrapped: %w", http.ErrNotSupported), wantStatus: http.StatusOK},
		{name: "failure", err: fixtureErr, wantStatus: http.StatusInternalServerError},
	} {
		t.Run(test.name, func(t *testing.T) {
			var originCalls atomic.Int64
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				originCalls.Add(1)
				_, _ = io.Copy(w, r.Body)
			}))
			defer origin.Close()
			server, err := NewHTTPServer(Config{Dialer: directDialer()})
			if err != nil {
				t.Fatal(err)
			}
			defer server.transport.CloseIdleConnections()
			request := httptest.NewRequest(http.MethodPost, origin.URL, strings.NewReader("body"))
			recorder := httptest.NewRecorder()
			writer := &httpFullDuplexTestWriter{ResponseWriter: recorder, err: test.err}
			server.ServeHTTP(writer, request)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, test.wantStatus)
			}
			if test.wantStatus == http.StatusOK {
				if recorder.Body.String() != "body" || originCalls.Load() != 1 {
					t.Fatalf("forwarded body = %q, origin calls = %d", recorder.Body.String(), originCalls.Load())
				}
			} else if originCalls.Load() != 0 {
				t.Fatal("dialed origin after failing to configure the response writer")
			}
		})
	}
}

type httpFullDuplexTestWriter struct {
	http.ResponseWriter
	err error
}

func (w *httpFullDuplexTestWriter) EnableFullDuplex() error { return w.err }
