package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/security"
	quic "github.com/quic-go/quic-go"
)

func TestNativeServerMaxConnectionsIncludesTLSFallback(t *testing.T) {
	clearPreflightEnvironment(t)
	files := newPreflightFiles(t)
	addresses := make(chan nativeListenerAddress, 2)
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(&nativeAddressHandler{addresses: addresses}))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var serverErr error
	go func() {
		defer close(done)
		serverErr = runServer(ctx, []string{
			"--protocol=native", "--listen=127.0.0.1:0", "--tcp-listen=127.0.0.1:0",
			"--cert", files.cert, "--key", files.key, "--token-file", files.token,
			"--max-connections=1", "--max-client-connections=1", "--max-streams=3",
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
			if serverErr != nil {
				t.Errorf("server shutdown: %v", serverErr)
			}
		case <-time.After(3 * time.Second):
			t.Error("server did not stop")
		}
	})
	listeners := make(map[string]string)
	for len(listeners) < 2 {
		select {
		case listener := <-addresses:
			listeners[listener.transport] = listener.address
		case <-done:
			t.Fatalf("server failed before listening: %v", serverErr)
		case <-time.After(3 * time.Second):
			t.Fatal("native listeners did not start")
		}
	}
	roots, err := security.LoadCertPool(files.cert)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS := &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "relay.invalid",
		NextProtos: []string{protocol.ALPN},
	}
	dialTLS := func() (*tls.Conn, error) {
		return tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", listeners["tls"], clientTLS.Clone())
	}
	first, err := dialTLS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	// A verified handshake proves the accepted TLS connection is holding the
	// connection budget, even though it has not consumed an active stream.
	second, err := dialTLS()
	if second != nil {
		_ = second.Close()
	}
	if err == nil {
		t.Fatal("--max-connections=1 admitted a second TLS fallback connection with --max-streams=3")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatalf("second TLS connection timed out instead of being rejected: %v", err)
	}
	quicCtx, stopQUIC := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopQUIC()
	q, err := quic.DialAddr(quicCtx, listeners["quic"], clientTLS.Clone(), nil)
	if q != nil {
		defer q.CloseWithError(0, "test cleanup")
		select {
		case <-q.Context().Done():
			err = context.Cause(q.Context())
		case <-quicCtx.Done():
			t.Fatal("QUIC was admitted while TLS held the global connection budget")
		}
	}
	var appErr *quic.ApplicationError
	if !errors.As(err, &appErr) || appErr.ErrorMessage != "connection limit reached" {
		t.Fatalf("QUIC rejection = %v, want global connection limit", err)
	}
	_ = first.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		replacement, err := dialTLS()
		if err == nil {
			_ = replacement.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("TLS connection slot was not returned after close: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type nativeListenerAddress struct {
	transport string
	address   string
}

type nativeAddressHandler struct {
	addresses chan<- nativeListenerAddress
}

func (h *nativeAddressHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *nativeAddressHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *nativeAddressHandler) WithGroup(string) slog.Handler            { return h }
func (h *nativeAddressHandler) Handle(_ context.Context, record slog.Record) error {
	if record.Message != "relay listener started" {
		return nil
	}
	var listener nativeListenerAddress
	record.Attrs(func(attribute slog.Attr) bool {
		switch attribute.Key {
		case "transport":
			listener.transport = attribute.Value.String()
		case "address":
			listener.address = attribute.Value.String()
		}
		return true
	})
	select {
	case h.addresses <- listener:
	default:
	}
	return nil
}
