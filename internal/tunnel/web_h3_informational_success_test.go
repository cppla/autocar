package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

type webH3InfoSuccessResponse struct {
	proof     string
	bearerLen int
}

func webH3InfoSuccessServer(t *testing.T, dialer transport.Dialer, resolver UDPResolver) (*WebH3Server, *webTunnelHandler, <-chan webH3InfoSuccessResponse, *webH3InformationalClient) {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	server, err := ListenWebH3(WebH3ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
		Cover: http.NotFoundHandler(), Dialer: dialer, UDPResolver: resolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := server.server.Handler.(*webTunnelHandler)
	responses := make(chan webH3InfoSuccessResponse, 2)
	server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, status := range []int{100, 102, 103} {
			w.Header().Set("Link", "</ordinary.css>; rel=preload")
			w.WriteHeader(status)
			clear(w.Header())
		}
		handler.ServeHTTP(w, r)
		responses <- webH3InfoSuccessResponse{proof: w.Header().Get(webAuthResponseHeader), bearerLen: len(r.Header.Get("Proxy-Authorization"))}
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		_ = server.Close()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("successful informational server Serve: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("successful informational server Serve did not join")
		}
	})
	client := newWebH3InformationalClient(t, "h3-tcp", server.Addr().String(), clientTLS, time.Second)
	return server, handler, responses, client
}

func webH3InfoSuccessWait(t *testing.T, done <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Errorf("%s did not join", label)
	}
}

// Exactly two real destination connections, processed sequentially by one
// owned worker. Every socket I/O has a deadline and cleanup independently
// closes both the listener and any currently accepted connection before join.
func webH3InfoSuccessTCPOrigin(t *testing.T) (string, <-chan error) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var current *net.TCPConn
	closed := false
	results := make(chan error, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 2 {
			if err := listener.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				results <- err
				return
			}
			conn, err := listener.AcceptTCP()
			if err != nil {
				results <- err
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				_ = conn.Close()
				return
			}
			current = conn
			mu.Unlock()
			err = conn.SetDeadline(time.Now().Add(2 * time.Second))
			var payload []byte
			if err == nil {
				payload, err = io.ReadAll(conn)
			}
			if err == nil {
				_, err = io.Copy(conn, bytes.NewReader(append([]byte("reply:"), payload...)))
			}
			if err == nil {
				err = conn.CloseWrite()
			}
			_ = conn.Close()
			mu.Lock()
			current = nil
			mu.Unlock()
			results <- err
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		closed = true
		if current != nil {
			_ = current.Close()
		}
		mu.Unlock()
		webH3InfoSuccessWait(t, done, "real TCP destination worker")
	})
	return listener.Addr().String(), results
}

func webH3InfoSuccessHandler(t *testing.T, responses <-chan webH3InfoSuccessResponse) webH3InfoSuccessResponse {
	t.Helper()
	select {
	case response := <-responses:
		if response.proof == "" {
			t.Error("successful original handler omitted its final proof")
		}
		return response
	case <-time.After(2 * time.Second):
		t.Fatal("successful original handler did not join")
		return webH3InfoSuccessResponse{}
	}
}

func TestWebH3InformationalTCP200FullPayloadAndReuse(t *testing.T) {
	target, targetResults := webH3InfoSuccessTCPOrigin(t)
	dialer := transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != target {
			return nil, errors.New("unexpected informational success destination")
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	})
	_, handler, responses, client := webH3InfoSuccessServer(t, dialer, nil)
	var first any
	var bootstrapLen int
	for request := range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, err := client.h3.DialContext(ctx, "tcp", target)
		cancel() // Successful stream ownership must already be detached.
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		payload := bytes.Repeat([]byte(fmt.Sprintf("informational-tcp-%d|", request)), 1024)
		if _, err := io.Copy(conn, bytes.NewReader(payload)); err != nil {
			t.Fatal(err)
		}
		if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(conn)
		_ = conn.Close()
		if err != nil || !bytes.Equal(got, append([]byte("reply:"), payload...)) {
			t.Fatalf("real TCP response bytes=%d err=%v, want exact %d-byte reply", len(got), err, len(payload)+6)
		}
		response := webH3InfoSuccessHandler(t, responses)
		select {
		case err := <-targetResults:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("real TCP destination did not complete")
		}
		session, ready := client.session()
		if !ready || len(handler.core.sem) != 0 {
			t.Error("successful TCP response lost authentication or retained admission")
		}
		if request == 0 {
			first, bootstrapLen = session, response.bearerLen
		} else if session != first || response.bearerLen >= bootstrapLen {
			t.Error("second successful TCP CONNECT replaced physical session or used another full ticket")
		}
	}
	if got := client.entropy.nonceReads.Load(); got != 1 {
		t.Errorf("successful TCP full bootstrap tickets=%d, want one", got)
	}
}

func webH3InfoSuccessUDPOrigin(t *testing.T) netip.AddrPort {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var buf [2048]byte
		for range 2 {
			if socket.SetDeadline(time.Now().Add(2*time.Second)) != nil {
				return
			}
			n, source, err := socket.ReadFromUDPAddrPort(buf[:])
			if err != nil {
				return
			}
			if _, err := socket.WriteToUDPAddrPort(buf[:n], source); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = socket.Close()
		webH3InfoSuccessWait(t, done, "real UDP destination worker")
	})
	return socket.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestWebH3InformationalUDP200EchoAndReuse(t *testing.T) {
	endpoint := webH3InfoSuccessUDPOrigin(t)
	targets := []string{fmt.Sprintf("first.example:%d", endpoint.Port()), fmt.Sprintf("second.example:%d", endpoint.Port())}
	resolver := UDPResolverFunc(func(_ context.Context, address string) ([]netip.AddrPort, error) {
		if address != targets[0] && address != targets[1] {
			return nil, errors.New("unexpected informational success UDP target")
		}
		return []netip.AddrPort{endpoint}, nil
	})
	dialer := transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("TCP destination is not expected in UDP success control")
	})
	_, handler, responses, client := webH3InfoSuccessServer(t, dialer, resolver)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	packet, err := client.h3.DialPacket(ctx)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packet.Close() })
	var first any
	for request, target := range targets {
		payload := []byte(fmt.Sprintf("real informational UDP echo %d", request))
		if err := packet.Send(payload, target); err != nil {
			t.Fatal(err)
		}
		type reply struct {
			payload []byte
			target  string
			err     error
		}
		result := make(chan reply, 1)
		done := make(chan struct{})
		go func() {
			defer close(done)
			payload, target, err := packet.Receive()
			result <- reply{payload, target, err}
		}()
		t.Cleanup(func() {
			_ = packet.Close()
			webH3InfoSuccessWait(t, done, "UDP Receive worker")
		})
		select {
		case got := <-result:
			if got.err != nil || got.target != target || !bytes.Equal(got.payload, payload) {
				t.Fatalf("real UDP reply=%q target=%q err=%v", got.payload, got.target, got.err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("real UDP reply timed out")
		}
		webH3InfoSuccessWait(t, done, "completed UDP Receive worker")
		session, ready := client.session()
		if !ready {
			t.Error("successful UDP target lost ready physical authentication")
		}
		if request == 0 {
			first = session
		} else if session != first {
			t.Error("second successful UDP CONNECT used a replacement physical session")
		}
	}
	if err := packet.Close(); err != nil {
		t.Fatal(err)
	}
	bootstrap := webH3InfoSuccessHandler(t, responses)
	continuation := webH3InfoSuccessHandler(t, responses)
	if continuation.bearerLen >= bootstrap.bearerLen {
		// Handler completion order need not match stream creation order.
		bootstrap, continuation = continuation, bootstrap
	}
	if continuation.bearerLen >= bootstrap.bearerLen || client.entropy.nonceReads.Load() != 1 {
		t.Error("successful UDP streams did not use one bootstrap and one shorter continuation")
	}
	if len(client.h3.udpSlots) != 0 || len(handler.core.sem) != 0 || len(handler.udp.slots) != 0 {
		t.Error("closed successful UDP targets retained client or server admission")
	}
}
