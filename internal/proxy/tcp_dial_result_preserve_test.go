package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

// Embed the concrete TCP connection to retain its real half-close methods.
// Only full Close is observed; reads, writes and deadlines remain unmodified.
type tcpDialPreserveObservedConn struct {
	*net.TCPConn
	closes atomic.Int64
	closed chan struct{}
	once   sync.Once
}

func (c *tcpDialPreserveObservedConn) Close() error {
	c.closes.Add(1)
	err := c.TCPConn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

func TestTCPDialSuccessfulResultPreservesTunnel(t *testing.T) {
	for _, frontend := range []string{"socks", "http-connect"} {
		t.Run(frontend, func(t *testing.T) {
			upstream, origin := tcpConnPair(t)
			defer upstream.Close()
			defer origin.Close()
			_ = origin.SetDeadline(time.Now().Add(3 * time.Second))
			observed := &tcpDialPreserveObservedConn{TCPConn: upstream.(*net.TCPConn), closed: make(chan struct{})}
			dialer := transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
				return observed, nil
			})
			var client net.Conn
			payload := bytes.Repeat([]byte("\x16\x03\x01 early bytes\x00\xff"), 256)
			var reader io.Reader
			if frontend == "socks" {
				server, address, stop := startSOCKS5(t, Config{Dialer: dialer})
				defer stop(server)
				client = dialTCP(t, address)
				defer client.Close()
				socksGreeting(t, client, nil)
				request := domainSOCKSRequest(socksCommandConnect, "example.invalid", 443)
				mustWrite(t, client, append(request, payload...))
				if reply := readSOCKSReply(t, client); reply != socksReplySucceeded {
					t.Fatalf("healthy SOCKS reply = %d", reply)
				}
				reader = client
			} else {
				server, proxyURL, stop := startHTTPProxy(t, Config{Dialer: dialer})
				defer stop(server)
				client = dialTCP(t, strings.TrimPrefix(proxyURL, "http://"))
				defer client.Close()
				request := []byte("CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\n\r\n")
				mustWrite(t, client, append(request, payload...))
				buffered := bufio.NewReader(client)
				status, err := buffered.ReadString('\n')
				if err != nil || !strings.Contains(status, " 200 ") {
					t.Fatalf("healthy CONNECT status = %q, %v", status, err)
				}
				for {
					line, err := buffered.ReadString('\n')
					if err != nil {
						t.Fatal(err)
					}
					if line == "\r\n" {
						break
					}
				}
				reader = buffered
			}
			if err := client.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(origin)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("origin early payload = %d/%d bytes, equal=%t, error=%v", len(got), len(payload), bytes.Equal(got, payload), err)
			}
			if got := observed.closes.Load(); got != 0 {
				t.Fatalf("successful dial result was fully closed %d times before the reverse reply", got)
			}
			reply := []byte("reverse reply after the complete early upload and EOF")
			mustWrite(t, origin, reply)
			if err := origin.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err = io.ReadAll(reader)
			if err != nil || !bytes.Equal(got, reply) {
				t.Fatalf("reverse reply = %q, %v", got, err)
			}
			select {
			case <-observed.closed:
			case <-time.After(time.Second):
				t.Fatal("completed tunnel did not release its successful dial result")
			}
		})
	}
}

func TestTCPDialSuccessfulResultPreservesHTTPReuse(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "origin reply "+r.URL.Path)
	}))
	defer origin.Close()
	var dialCalls atomic.Int64
	dialed := make(chan *tcpDialPreserveObservedConn, 4)
	dialer := transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		dialCalls.Add(1)
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		observed := &tcpDialPreserveObservedConn{TCPConn: conn.(*net.TCPConn), closed: make(chan struct{})}
		dialed <- observed
		return observed, nil
	})
	server, proxyURL, stop := startHTTPProxy(t, Config{Dialer: dialer})
	defer stop(server)
	client := proxyHTTPClient(t, proxyURL, nil)
	defer client.CloseIdleConnections()
	var first *tcpDialPreserveObservedConn
	for _, path := range []string{"/first", "/second"} {
		response, err := client.Get(origin.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if response.StatusCode != http.StatusOK || string(body) != "origin reply "+path || readErr != nil || closeErr != nil {
			t.Fatalf("forward response = %d/%q, read=%v close=%v", response.StatusCode, body, readErr, closeErr)
		}
		if first == nil {
			select {
			case first = <-dialed:
			case <-time.After(time.Second):
				t.Fatal("successful forward request has no observed upstream dial")
			}
		}
		if got := first.closes.Load(); got != 0 {
			t.Fatalf("healthy reusable origin connection was prematurely closed %d times", got)
		}
	}
	if got := dialCalls.Load(); got != 1 {
		t.Fatalf("two healthy requests used %d origin dials, want one reusable connection", got)
	}
}

func TestTCPDialNilResultFailsClosed(t *testing.T) {
	dialer := transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, nil
	})
	t.Run("socks", func(t *testing.T) {
		server, address, stop := startSOCKS5(t, Config{Dialer: dialer})
		defer stop(server)
		client := dialTCP(t, address)
		defer client.Close()
		socksGreeting(t, client, nil)
		mustWrite(t, client, domainSOCKSRequest(socksCommandConnect, "example.invalid", 443))
		if reply := readSOCKSReply(t, client); reply != socksReplyGeneralFailure {
			t.Fatalf("nil/nil dial result SOCKS reply = %d, want general failure", reply)
		}
	})
	t.Run("http-core", func(t *testing.T) {
		server, err := NewHTTPServer(Config{Dialer: dialer})
		if err != nil {
			t.Fatal(err)
		}
		conn, err := server.dialContext(context.Background(), "tcp", "example.invalid:443")
		if conn != nil || err == nil {
			t.Fatalf("nil/nil upstream result was not rejected: conn=%T error=%v", conn, err)
		}
	})
	for _, method := range []string{http.MethodConnect, http.MethodGet} {
		t.Run("http-"+method, func(t *testing.T) {
			server, proxyURL, stop := startHTTPProxy(t, Config{Dialer: dialer})
			defer stop(server)
			client := dialTCP(t, strings.TrimPrefix(proxyURL, "http://"))
			defer client.Close()
			target := "example.invalid:443"
			if method == http.MethodGet {
				target = "http://example.invalid/resource"
			}
			mustWrite(t, client, []byte(fmt.Sprintf("%s %s HTTP/1.1\r\nHost: example.invalid\r\nConnection: close\r\n\r\n", method, target)))
			response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: method})
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusBadGateway {
				t.Fatalf("nil/nil result HTTP %s status = %d, want 502", method, response.StatusCode)
			}
			if _, err := io.ReadAll(response.Body); err != nil {
				t.Fatalf("failed %s response body: %v", method, err)
			}
		})
	}
}
