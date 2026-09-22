package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPForwardActiveBodiesSurviveIdleTimeout(t *testing.T) {
	const idle = 200 * time.Millisecond
	const chunks = 16
	const interval = idle / 5
	for _, direction := range []string{"download", "upload"} {
		t.Run(direction, func(t *testing.T) {
			chunk := bytes.Repeat([]byte("a"), 16)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if direction == "upload" {
					got, err := io.ReadAll(r.Body)
					if err != nil || !bytes.Equal(got, bytes.Repeat(chunk, chunks)) {
						http.Error(w, "incomplete upload", http.StatusBadRequest)
						return
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				w.Header().Set("Content-Length", fmt.Sprint(chunks*len(chunk)))
				for range chunks {
					if _, err := w.Write(chunk); err != nil {
						return
					}
					w.(http.Flusher).Flush()
					select {
					case <-r.Context().Done():
						return
					case <-time.After(interval):
					}
				}
			}))
			defer origin.Close()
			server, proxyURL, stop := startHTTPProxy(t, Config{Dialer: directDialer(), IdleTimeout: idle})
			defer stop(server)
			client := proxyHTTPClient(t, proxyURL, nil)
			defer client.CloseIdleConnections()
			method := http.MethodGet
			var body io.Reader
			if direction == "upload" {
				method = http.MethodPost
				reader, writer := io.Pipe()
				defer reader.Close()
				defer writer.Close()
				body = reader
				done := make(chan struct{})
				t.Cleanup(func() {
					select {
					case <-done:
					case <-time.After(time.Second):
						t.Error("upload writer did not stop")
					}
				})
				go func() {
					defer close(done)
					defer writer.Close()
					for range chunks {
						if _, err := writer.Write(chunk); err != nil {
							return
						}
						time.Sleep(interval)
					}
				}()
			}
			request, err := http.NewRequest(method, origin.URL, body)
			if err != nil {
				t.Fatal(err)
			}
			if direction == "upload" {
				request.ContentLength = int64(chunks * len(chunk))
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			got, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("read active %s: %v (%d bytes)", direction, err, len(got))
			}
			wantStatus := http.StatusNoContent
			if direction == "download" {
				wantStatus = http.StatusOK
				if !bytes.Equal(got, bytes.Repeat(chunk, chunks)) {
					t.Errorf("active download = %d bytes, want %d", len(got), chunks*len(chunk))
				}
			}
			if response.StatusCode != wantStatus {
				t.Fatalf("active %s status = %d, want %d: %s", direction, response.StatusCode, wantStatus, got)
			}
		})
	}
}

func TestHTTPActivityPreservesExternalReadDeadline(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	conn := &trackedConn{Conn: local}
	conn.setActivityTimeout(time.Hour)
	// net/http uses this past deadline to stop its disconnect reader before
	// hijacking a CONNECT. Neither forwarded body data nor writes may undo it.
	if err := conn.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := conn.refreshReadActivity(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		done <- err
	}()
	select {
	case err := <-done:
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("read error = %v, want preserved deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("activity extended net/http's external read deadline")
	}
}

func TestHTTPActivityDoesNotExtendBlockedWrite(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	conn := &trackedConn{Conn: local}
	conn.setActivityTimeout(100 * time.Millisecond)
	done := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("blocked"))
		done <- err
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	limit := time.NewTimer(time.Second)
	defer limit.Stop()
	for {
		select {
		case <-ticker.C:
			if err := conn.refreshReadActivity(); err != nil {
				t.Fatal(err)
			}
		case err := <-done:
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				t.Fatalf("write error = %v, want stall timeout", err)
			}
			return
		case <-limit.C:
			t.Fatal("read activity kept a blocked client write alive")
		}
	}
}
