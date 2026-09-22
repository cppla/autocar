package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/proxy"
	"github.com/cppla/autocar/internal/transport"
	"github.com/cppla/autocar/internal/tunnel"
)

// A completed upload must not leave a write-deadline timer armed on the H2
// stream, and its quiet read direction must not expire an active download.
// Unlike an echo or a half-close test, both directions stay open throughout.
func TestHTTPConnectWebH2ActiveDownloadSurvivesIdleTimeout(t *testing.T) {
	const idleTimeout = 250 * time.Millisecond
	const interval = 50 * time.Millisecond
	request := []byte("go!")
	chunk := []byte("download-chunk\x00\xff")
	payload := bytes.Repeat(chunk, 16)
	dialer := startActivityWebH2Client(t)

	for _, pipelined := range []bool{false, true} {
		name := "request_after_connect"
		if pipelined {
			name = "request_with_connect"
		}
		t.Run(name, func(t *testing.T) {
			target, targetResult := startActivityDownloadTarget(t, request, chunk, 16, interval)
			proxyAddress := startActivityHTTPProxy(t, dialer, idleTimeout)
			conn := dialWithDeadline(t, proxyAddress)
			defer conn.Close()
			head := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
			initial := []byte(head)
			if pipelined {
				initial = append(initial, request...)
			}
			started := time.Now()
			writeFull(t, conn, initial)
			reader := bufio.NewReader(conn)
			status, err := reader.ReadString('\n')
			if err != nil || !strings.Contains(status, " 200 ") {
				t.Fatalf("CONNECT response = %q, err = %v", status, err)
			}
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					t.Fatalf("read CONNECT headers: %v", err)
				}
				if line == "\r\n" {
					break
				}
			}
			if !pipelined {
				writeFull(t, conn, request)
			}

			got := make([]byte, len(payload))
			n, err := io.ReadFull(reader, got)
			if err != nil {
				t.Fatalf("active H2 download stopped after %d/%d bytes and %s: %v", n, len(got), time.Since(started), err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("download payload differs from target bytes")
			}
			if elapsed := time.Since(started); elapsed <= 2*idleTimeout {
				t.Fatalf("download lasted %s, want more than two idle intervals", elapsed)
			}
			// The upload side must still work after the long download, without
			// relying on EOF or CloseWrite to complete either direction.
			writeFull(t, conn, []byte("!"))
			select {
			case err := <-targetResult:
				if err != nil {
					t.Fatalf("target exchange: %v", err)
				}
			case <-time.After(operationTimeout):
				t.Fatal("target did not receive final acknowledgment")
			}
		})
	}
}

func startActivityWebH2Client(t *testing.T) *tunnel.WebH2Client {
	t.Helper()
	material := newTLSMaterial(t)
	server, err := tunnel.ListenWebH2(tunnel.WebH2ServerConfig{
		Address: "127.0.0.1:0", Token: testToken, TLSConfig: material.server,
		Cover: http.NotFoundHandler(), Dialer: &net.Dialer{Timeout: operationTimeout},
		HandshakeTimeout: operationTimeout, DialTimeout: operationTimeout,
	})
	if err != nil {
		t.Fatalf("listen activity-test H2 relay: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		waitForServe(t, "activity-test H2 relay", done)
	})
	client, err := tunnel.NewWebH2Client(tunnel.WebH2ClientConfig{
		ServerAddress: server.Addr().String(), Token: testToken, TLSConfig: material.client,
		HandshakeTimeout: operationTimeout, DialTimeout: operationTimeout,
	})
	if err != nil {
		t.Fatalf("create activity-test H2 client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func startActivityHTTPProxy(t *testing.T, dialer transport.Dialer, idleTimeout time.Duration) string {
	t.Helper()
	server, err := proxy.NewHTTPServer(proxy.Config{
		Dialer: dialer, HandshakeTimeout: operationTimeout, DialTimeout: operationTimeout,
		IdleTimeout: idleTimeout, MaxConnections: 4,
	})
	if err != nil {
		t.Fatalf("create activity-test HTTP proxy: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen activity-test HTTP proxy: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil && !isExpectedClose(err) {
			t.Errorf("shut down activity-test HTTP proxy: %v", err)
		}
		waitForServe(t, "activity-test HTTP proxy", done)
	})
	return listener.Addr().String()
}

func startActivityDownloadTarget(t *testing.T, request, chunk []byte, count int, interval time.Duration) (string, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen activity-test target: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		result <- func() error {
			conn, err := listener.Accept()
			if err != nil {
				return err
			}
			defer conn.Close()
			stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
			defer stop()
			if err := conn.SetDeadline(time.Now().Add(operationTimeout)); err != nil {
				return err
			}
			got := make([]byte, len(request))
			if _, err := io.ReadFull(conn, got); err != nil {
				return fmt.Errorf("read initial request: %w", err)
			}
			if !bytes.Equal(got, request) {
				return fmt.Errorf("initial request = %q, want %q", got, request)
			}
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for range count {
				select {
				case <-ticker.C:
				case <-ctx.Done():
					return ctx.Err()
				}
				if n, err := conn.Write(chunk); err != nil {
					return fmt.Errorf("write download chunk: %w", err)
				} else if n != len(chunk) {
					return io.ErrShortWrite
				}
			}
			ack := make([]byte, 1)
			if _, err := io.ReadFull(conn, ack); err != nil {
				return fmt.Errorf("read final acknowledgment: %w", err)
			}
			if ack[0] != '!' {
				return fmt.Errorf("final acknowledgment = %q", ack)
			}
			return nil
		}()
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		select {
		case <-stopped:
		case <-time.After(operationTimeout):
			t.Error("activity-test target did not stop")
		}
	})
	return listener.Addr().String(), result
}
