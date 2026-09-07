package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/cppla/autocar/internal/transport"
)

func TestWebSessionConcurrentShortTickets(t *testing.T) {
	for _, mode := range []string{"h2", "h3", "h3-mixed-udp"} {
		t.Run(mode, func(t *testing.T) {
			serverTLS, clientTLS := testTLSConfigs(t)
			target := startWebTCPEcho(t)
			var dials, covers atomic.Int32
			cover := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				covers.Add(1)
				http.NotFound(w, r)
			})
			var client transport.Dialer
			var h3Client *WebH3Client
			var auth *webSessionClientAuth
			var sameConnection func() bool
			udpTarget := "concurrency.example:443"
			if mode == "h2" {
				server := startWebH2TestServer(t, WebH2ServerConfig{
					Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
					Dialer: countingDialer{dials: &dials}, Cover: cover,
				})
				h2, err := NewWebH2Client(WebH2ClientConfig{
					ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
					HandshakeTimeout: 10 * time.Second,
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = h2.Close() })
				client = h2
				if err := exchangeWebSessionEcho(client, target); err != nil {
					t.Fatal(err)
				}
				h2.mu.Lock()
				session := h2.current
				auth = session.auth
				h2.mu.Unlock()
				sameConnection = func() bool {
					h2.mu.Lock()
					defer h2.mu.Unlock()
					return h2.current == session && session.opening == 0
				}
			} else {
				udpEcho := startWebUDPEcho(t)
				udpTarget = fmt.Sprintf("concurrency.example:%d", udpEcho.Port())
				server, err := ListenWebH3(WebH3ServerConfig{
					Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
					Dialer: countingDialer{dials: &dials}, Cover: cover,
					UDPResolver:    newWebUDPTestResolver(map[string]netip.AddrPort{udpTarget: udpEcho}),
					MaxUDPSessions: 250, MaxClientUDPSessions: 250,
				})
				if err != nil {
					t.Fatal(err)
				}
				serveWebH3ForTest(t, server)
				h3Client, err = NewWebH3Client(WebH3ClientConfig{
					ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
					HandshakeTimeout: 10 * time.Second,
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = h3Client.Close() })
				client = h3Client
				if err := exchangeWebSessionEcho(client, target); err != nil {
					t.Fatal(err)
				}
				h3Client.mu.Lock()
				connection := h3Client.conn
				auth = h3Client.conns[connection].auth
				h3Client.mu.Unlock()
				sameConnection = func() bool {
					h3Client.mu.Lock()
					defer h3Client.mu.Unlock()
					return h3Client.conn == connection
				}
			}
			const streams = 250
			for round := range 3 {
				start := make(chan struct{})
				failures := make(chan error, streams)
				var wg sync.WaitGroup
				for i := range streams {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
						defer cancel()
						if mode == "h3-mixed-udp" && i%2 != 0 {
							opened, err := h3Client.openConnectUDPSession(ctx, udpTarget)
							if err != nil {
								failures <- err
								return
							}
							defer opened.stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
							defer opened.stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
							if err := opened.stream.SendDatagram([]byte{0, 'u'}); err != nil {
								failures <- err
								return
							}
							payload, err := opened.stream.ReceiveDatagram(ctx)
							if err != nil || string(payload) != "\x00u" {
								failures <- fmt.Errorf("UDP echo=%q: %v", payload, err)
							}
							return
						}
						conn, err := client.DialContext(ctx, "tcp", target)
						if err != nil {
							failures <- err
							return
						}
						defer conn.Close()
						_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
						if _, err := conn.Write([]byte{'t'}); err != nil {
							failures <- err
							return
						}
						var payload [1]byte
						if _, err := io.ReadFull(conn, payload[:]); err != nil || payload[0] != 't' {
							failures <- fmt.Errorf("TCP echo=%q: %v", payload, err)
						}
					}()
				}
				close(start)
				wg.Wait()
				close(failures)
				for err := range failures {
					t.Errorf("round %d: %v", round, err)
				}
				if t.Failed() {
					t.FailNow()
				}
				if !sameConnection() {
					t.Fatal("concurrent requests replaced the authenticated physical connection or leaked reservations")
				}
				auth.mu.Lock()
				pending := len(auth.pending)
				auth.mu.Unlock()
				if pending != 0 || covers.Load() != 0 {
					t.Fatalf("pending auth=%d cover requests=%d, want zero", pending, covers.Load())
				}
			}
			wantDials := int32(1 + streams*3)
			if mode == "h3-mixed-udp" {
				wantDials = 1 + streams/2*3
			}
			if dials.Load() != wantDials {
				t.Fatalf("destination TCP dials=%d, want %d", dials.Load(), wantDials)
			}
		})
	}
}

func TestWebSessionCanceledTicketWaitDoesNotCloseSibling(t *testing.T) {
	for _, mode := range []string{"h2", "h3", "h3-udp"} {
		t.Run(mode, func(t *testing.T) {
			serverTLS, clientTLS := testTLSConfigs(t)
			target := startWebTCPEcho(t)
			var dials atomic.Int32
			var client transport.Dialer
			var auth *webSessionClientAuth
			var open func(context.Context) error
			if mode == "h2" {
				server := startWebH2TestServer(t, WebH2ServerConfig{
					Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
					Dialer: countingDialer{dials: &dials}, Cover: http.NotFoundHandler(),
				})
				h2, err := NewWebH2Client(WebH2ClientConfig{
					ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = h2.Close() })
				client = h2
				defer func() {
					h2.mu.Lock()
					defer h2.mu.Unlock()
					if h2.current == nil || h2.current.opening != 0 || h2.current.h2.State().StreamsReserved != 0 {
						t.Error("canceled authentication wait leaked an H2 session reservation")
					}
				}()
			} else {
				server, err := ListenWebH3(WebH3ServerConfig{
					Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
					Dialer: countingDialer{dials: &dials}, Cover: http.NotFoundHandler(),
				})
				if err != nil {
					t.Fatal(err)
				}
				serveWebH3ForTest(t, server)
				h3, err := NewWebH3Client(WebH3ClientConfig{
					ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = h3.Close() })
				client = h3
				if mode == "h3-udp" {
					open = func(ctx context.Context) error {
						opened, err := h3.openConnectUDPSession(ctx, "wait.example:443")
						if opened != nil {
							opened.stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
							opened.stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
						}
						return err
					}
				}
			}
			sibling, err := client.DialContext(context.Background(), "tcp", target)
			if err != nil {
				t.Fatal(err)
			}
			defer sibling.Close()
			if h2, ok := client.(*WebH2Client); ok {
				h2.mu.Lock()
				auth = h2.current.auth
				h2.mu.Unlock()
			} else {
				h3 := client.(*WebH3Client)
				h3.mu.Lock()
				auth = h3.conns[h3.conn].auth
				h3.mu.Unlock()
			}
			if open == nil {
				open = func(ctx context.Context) error {
					conn, err := client.DialContext(ctx, "tcp", target)
					if conn != nil {
						_ = conn.Close()
					}
					return err
				}
			}
			var exchanges []webSessionExchange
			for range webSessionReplayWindowBits {
				_, exchange, err := auth.authorization(context.Background(), webAuthTestBinding)
				if err != nil {
					t.Fatal(err)
				}
				exchanges = append(exchanges, exchange)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			err = open(ctx)
			cancel()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("blocked opening error = %v", err)
			}
			for _, exchange := range exchanges {
				auth.complete(exchange)
			}
			if err := exchangeWebSessionEcho(client, target); err != nil {
				t.Fatal(err)
			}
			assertWebSessionSiblingEcho(t, sibling)
			if dials.Load() != 2 {
				t.Fatalf("blocked ticket reached destination: dials=%d", dials.Load())
			}
		})
	}
}

func exchangeWebSessionEcho(client transport.Dialer, target string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("echo")); err != nil {
		return err
	}
	var response [4]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil || string(response[:]) != "echo" {
		return fmt.Errorf("echo=%q: %v", response, err)
	}
	return nil
}

func assertWebSessionSiblingEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte("alive")); err != nil {
		t.Fatalf("sibling write: %v", err)
	}
	var response [5]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil || string(response[:]) != "alive" {
		t.Fatalf("sibling echo=%q err=%v", response, err)
	}
}
