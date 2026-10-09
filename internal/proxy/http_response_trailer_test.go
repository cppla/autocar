package proxy

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestHTTPForwardResponseTrailers(t *testing.T) {
	for _, mode := range []string{"declared", "undeclared", "mixed"} {
		for _, body := range []string{"body", ""} {
			name := mode + "/body"
			if body == "" {
				name = mode + "/empty"
			}
			t.Run(name, func(t *testing.T) {
				want := make(http.Header)
				if mode != "undeclared" {
					want["X-Declared"] = []string{"first", "second"}
				}
				if mode != "declared" {
					want["X-Undeclared"] = []string{"late-first", "late-second"}
				}
				origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					if mode != "undeclared" {
						w.Header().Set("Trailer", "X-Declared")
					}
					_, _ = io.WriteString(w, body)
					// Flush even an empty body so late metadata cannot become
					// ordinary headers or an inferred Content-Length response.
					w.(http.Flusher).Flush()
					for field, values := range want {
						if field == "X-Undeclared" {
							field = http.TrailerPrefix + field
						}
						w.Header()[field] = append([]string(nil), values...)
					}
				}))
				defer origin.Close()
				server, proxyURL, stop := startHTTPProxy(t, Config{Dialer: directDialer()})
				defer stop(server)
				client := proxyHTTPClient(t, proxyURL, nil)
				defer client.CloseIdleConnections()
				for _, route := range []struct {
					name   string
					client *http.Client
				}{{"direct", origin.Client()}, {"proxy", client}} {
					t.Run(route.name, func(t *testing.T) {
						response, err := route.client.Get(origin.URL)
						if err != nil {
							t.Fatal(err)
						}
						defer response.Body.Close()
						for field := range want {
							if len(response.Header.Values(field)) != 0 || len(response.Trailer.Values(field)) != 0 {
								t.Fatalf("trailer %s published before body EOF: headers=%v trailers=%v", field, response.Header, response.Trailer)
							}
						}
						got, err := io.ReadAll(response.Body)
						if err != nil || string(got) != body || response.StatusCode != http.StatusOK {
							t.Fatalf("response: status=%d body=%q error=%v", response.StatusCode, got, err)
						}
						if !reflect.DeepEqual(response.Trailer, want) {
							t.Fatalf("trailers=%v, want %v", response.Trailer, want)
						}
					})
				}
			})
		}
	}
}

func TestHTTPForwardResponseTrailerPolicy(t *testing.T) {
	// The raw origin deliberately sends fields net/http's ResponseWriter
	// refuses to emit, but which its response parser accepts as trailers.
	unsafe := []string{
		"Authorization", "Host", "If-Match", "Content-Type", "Content-Length",
		"Transfer-Encoding", "Trailer", "Keep-Alive", "Te", "Upgrade",
		"Proxy-Authorization", "Proxy-Authenticate", "Proxy-Authentication-Info", "Proxy-Connection",
	}
	declared := []string{"X-End", "X-Initial-Hop", "X-Late-Hop"}
	for _, field := range unsafe {
		// These three declarations are rejected by the upstream parser;
		// send them only in the terminal trailer block instead.
		if field != "Content-Length" && field != "Transfer-Encoding" && field != "Trailer" {
			declared = append(declared, field)
		}
	}
	var wire strings.Builder
	wire.WriteString("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n")
	wire.WriteString("Connection: x-INITIAL-hop, X-Initial-Undeclared\r\n")
	// If this declared field is blocked only at EOF, its ordinary header
	// value must not be mistaken for a trailer by the downstream writer.
	wire.WriteString("X-Late-Hop: initial-header-must-not-become-trailer\r\n")
	wire.WriteString("Trailer: " + strings.Join(declared, ", ") + "\r\n\r\n")
	wire.WriteString("4\r\nbody\r\n0\r\nX-End: declared-control\r\nX-Late-End: undeclared-control\r\n")
	wire.WriteString("Connection: x-LATE-hop, X-Late-Undeclared\r\n")
	blocked := append([]string{"X-Initial-Hop", "X-Initial-Undeclared", "X-Late-Hop", "X-Late-Undeclared"}, unsafe...)
	for _, field := range blocked {
		wire.WriteString(field + ": must-not-forward\r\n")
	}
	wire.WriteString("\r\n")
	origin := httpResponseTrailerOrigin(t, wire.String())
	defer origin.Close()
	server, proxyURL, stop := startHTTPProxy(t, Config{Dialer: directDialer()})
	defer stop(server)
	client := proxyHTTPClient(t, proxyURL, nil)
	defer client.CloseIdleConnections()
	for _, route := range []struct {
		name   string
		client *http.Client
	}{{"direct", origin.Client()}, {"proxy", client}} {
		t.Run(route.name, func(t *testing.T) {
			response, err := route.client.Get(origin.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			initialTrailers := response.Trailer.Clone()
			body, err := io.ReadAll(response.Body)
			if err != nil || string(body) != "body" || response.StatusCode != http.StatusOK {
				t.Fatalf("response: status=%d body=%q error=%v", response.StatusCode, body, err)
			}
			for field, want := range map[string]string{"X-End": "declared-control", "X-Late-End": "undeclared-control"} {
				if got := response.Trailer.Get(field); got != want {
					t.Errorf("control trailer %s=%q, want %q", field, got, want)
				}
			}
			for _, field := range blocked {
				got := response.Trailer.Get(field)
				if route.name == "direct" {
					if got != "must-not-forward" {
						t.Errorf("origin control trailer %s=%q", field, got)
					}
				} else {
					wantHeader := ""
					if field == "X-Late-Hop" {
						// This ordinary header was sent before the terminal
						// Connection nomination became available.
						wantHeader = "initial-header-must-not-become-trailer"
					}
					if got != "" || response.Header.Get(field) != wantHeader {
						t.Errorf("blocked %s: header=%q, want %q; trailer=%q, want empty", field, response.Header.Get(field), wantHeader, got)
					}
				}
			}
			if route.name == "proxy" {
				for _, field := range append([]string{"X-Initial-Hop"}, unsafe...) {
					if _, ok := initialTrailers[http.CanonicalHeaderKey(field)]; ok {
						t.Errorf("blocked trailer %s announced in response headers", field)
					}
				}
				if response.Header.Get("Connection") != "" || response.Trailer.Get("Connection") != "" {
					t.Errorf("Connection leaked: headers=%v trailers=%v", response.Header, response.Trailer)
				}
			}
		})
	}
}

func TestHTTPForwardResponseTrailersRequireCompleteBody(t *testing.T) {
	for _, ending := range []struct {
		name string
		wire string
	}{
		{"missing_terminal_chunk", ""},
		{"incomplete_trailer_block", "0\r\nX-End: must-not-publish\r\nX-Late-End: must-not-publish\r\n"},
	} {
		t.Run(ending.name, func(t *testing.T) {
			origin := httpResponseTrailerOrigin(t, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n4\r\nbody\r\n"+ending.wire)
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
			if !errors.Is(err, io.ErrUnexpectedEOF) || string(body) != "body" || response.StatusCode != http.StatusOK {
				t.Fatalf("incomplete response: status=%d body=%q error=%v", response.StatusCode, body, err)
			}
			for _, field := range []string{"X-End", "X-Late-End"} {
				if response.Header.Get(field) != "" || response.Trailer.Get(field) != "" {
					t.Errorf("trailer %s published after incomplete body: headers=%v trailers=%v", field, response.Header, response.Trailer)
				}
			}
		})
	}
}

func httpResponseTrailerOrigin(t *testing.T, wire string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		if _, err := rw.WriteString(wire); err != nil {
			t.Error(err)
			return
		}
		if err := rw.Flush(); err != nil {
			t.Error(err)
		}
	}))
}
