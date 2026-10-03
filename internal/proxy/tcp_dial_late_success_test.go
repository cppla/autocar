package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

// A custom dialer may finish establishing a socket after its caller's deadline.
// Return an actual TCP endpoint only after observing that deadline, rather than
// sleeping and hoping to race the timer. Cleanup closes the underlying socket
// without changing the independently observed production Close count.
func TestTCPDialLateSuccessRejectedByFrontends(t *testing.T) {
	for _, frontend := range []string{"socks-connect", "http-connect", "http-forward"} {
		t.Run(frontend, func(t *testing.T) {
			var requests atomic.Int32
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				_, _ = io.WriteString(w, "unexpected late request")
			}))
			t.Cleanup(origin.Close)
			target := strings.TrimPrefix(origin.URL, "http://")
			conn, err := net.DialTimeout("tcp", target, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			owned := &tcpDialErrorOwnedConn{Conn: conn, closeError: errors.New("late-result close error")}
			t.Cleanup(func() { _ = conn.Close() })
			returned := make(chan error, 1)
			var calls atomic.Int32
			dialer := transport.DialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
				if calls.Add(1) != 1 {
					return nil, errors.New("unexpected repeated fixture dial")
				}
				<-ctx.Done()
				returned <- ctx.Err()
				return owned, nil
			})
			cfg := Config{Dialer: dialer, DialTimeout: 25 * time.Millisecond, HandshakeTimeout: time.Second, IdleTimeout: time.Second, MaxConnections: 1}
			var client net.Conn
			var tracker *connTracker
			rejected := true
			if frontend == "socks-connect" {
				server, address, stop := startSOCKS5(t, cfg)
				t.Cleanup(func() { stop(server) })
				tracker = server.lifecycle.tracker
				client = dialTCP(t, address)
				t.Cleanup(func() { _ = client.Close() })
				socksGreeting(t, client, nil)
				host, port := splitAddress(t, target)
				mustWrite(t, client, domainSOCKSRequest(socksCommandConnect, host, port))
				if got := readSOCKSReply(t, client); got != socksReplyTTLExpired {
					rejected = false
					t.Errorf("late success SOCKS reply = %d, want timeout reply %d", got, socksReplyTTLExpired)
				}
			} else {
				server, proxyURL, stop := startHTTPProxy(t, cfg)
				t.Cleanup(func() { stop(server) })
				tracker = server.lifecycle.tracker
				client = dialTCP(t, strings.TrimPrefix(proxyURL, "http://"))
				t.Cleanup(func() { _ = client.Close() })
				method, requestTarget := http.MethodConnect, target
				if frontend == "http-forward" {
					method, requestTarget = http.MethodGet, origin.URL+"/late"
				}
				mustWrite(t, client, []byte(fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", method, requestTarget, target)))
				response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: method})
				if err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != http.StatusGatewayTimeout {
					rejected = false
					t.Errorf("late success HTTP status = %d, want 504", response.StatusCode)
				}
				// On the unfixed CONNECT path, the 200 body is the live tunnel;
				// do not block reading it merely to report the failed assertion.
				if method != http.MethodConnect || response.StatusCode != http.StatusOK {
					if _, err := io.ReadAll(response.Body); err != nil {
						t.Error("failure response body: ", err)
					}
				}
				_ = response.Body.Close()
			}
			select {
			case err := <-returned:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("fixture dial context = %v, want deadline exceeded", err)
				}
			case <-time.After(time.Second):
				t.Fatal("custom dial did not return after its deadline")
			}
			// Release a regressed successful relay before waiting for its slot.
			_ = client.Close()
			if !rejected {
				_ = conn.Close()
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := tracker.wait(ctx); err != nil {
				t.Fatal("late result retained the frontend slot: ", err)
			}
			if got := owned.closeCalls.Load(); got != 1 {
				t.Errorf("late result Close calls = %d, want exactly one", got)
			}
			if got := calls.Load(); got != 1 {
				t.Errorf("custom dial calls = %d, want one", got)
			}
			if got := requests.Load(); got != 0 {
				t.Errorf("origin received %d requests on an expired dial result", got)
			}
		})
	}
}
