package tunnel

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestTLSServerClientConnectionLimitValidationAndDefaults(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)

	for _, test := range []struct {
		name       string
		streams    int
		clients    int
		wantClient int
	}{
		{name: "default below 32", streams: 2, wantClient: 2},
		{name: "default capped at 32", streams: 64, wantClient: 32},
		{name: "explicit", streams: 4, clients: 3, wantClient: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, err := ListenTLS(TLSServerConfig{
				Address:              "127.0.0.1:0",
				Token:                testToken,
				TLSConfig:            serverTLS,
				MaxConcurrentStreams: test.streams,
				MaxClientConnections: test.clients,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			if got := server.clients.limit; got != test.wantClient {
				t.Fatalf("client connection limit = %d, want %d", got, test.wantClient)
			}
		})
	}

	for _, test := range []struct {
		name    string
		streams int
		clients int
	}{
		{name: "negative", streams: 4, clients: -1},
		{name: "exceeds global limit", streams: 2, clients: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, err := ListenTLS(TLSServerConfig{
				Address:              "127.0.0.1:0",
				Token:                testToken,
				TLSConfig:            serverTLS,
				MaxConcurrentStreams: test.streams,
				MaxClientConnections: test.clients,
			})
			if server != nil {
				_ = server.Close()
			}
			if err == nil {
				t.Fatal("invalid client connection limit was accepted")
			}
		})
	}
}

func TestTLSSourceConnectionLimiter(t *testing.T) {
	limiter := newSourceConnectionLimiter(1)
	first := tlsSourceKey(&net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1000})
	same := tlsSourceKey(&net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 2000})
	other := tlsSourceKey(&net.TCPAddr{IP: net.ParseIP("192.0.2.11"), Port: 1000})
	if first != same {
		t.Fatalf("IPv4 source key varies by port: %q != %q", first, same)
	}
	if first == other {
		t.Fatalf("distinct IPv4 sources share key %q", first)
	}
	if !limiter.acquire(first) {
		t.Fatal("first source acquisition failed")
	}
	if limiter.acquire(same) {
		t.Fatal("same source exceeded its limit")
	}
	if !limiter.acquire(other) {
		t.Fatal("different source was incorrectly limited")
	}
	if got := limiter.count(first); got != 1 {
		t.Fatalf("first source count = %d, want 1", got)
	}
	limiter.release(first)
	if got := limiter.count(first); got != 0 {
		t.Fatalf("released source count = %d, want 0", got)
	}
	if !limiter.acquire(first) {
		t.Fatal("released source slot was not reusable")
	}
}

func TestTLSSourceKeyUsesIPv6Prefix(t *testing.T) {
	first := tlsSourceKey(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2::1"), Port: 1000})
	samePrefix := tlsSourceKey(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2::ffff"), Port: 2000})
	otherPrefix := tlsSourceKey(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:3::1"), Port: 1000})
	if first != samePrefix {
		t.Fatalf("IPv6 addresses in one /64 have different keys: %q != %q", first, samePrefix)
	}
	if first == otherPrefix {
		t.Fatalf("distinct IPv6 /64 prefixes share key %q", first)
	}
}

func TestTLSSourceKeyFailsClosed(t *testing.T) {
	for _, address := range []net.Addr{
		nil,
		testTLSAddr("unparseable-one:1234"),
		testTLSAddr("unparseable-two:5678"),
	} {
		if got := tlsSourceKey(address); got != "" {
			t.Fatalf("unknown address %v received separate source key %q", address, got)
		}
	}
}

type testTLSAddr string

func (a testTLSAddr) Network() string { return "test" }
func (a testTLSAddr) String() string  { return string(a) }

func TestTLSServerClientLimitAcrossAcceptedConnections(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	server, err := ListenTLS(TLSServerConfig{
		Address:              "127.0.0.1:0",
		Token:                testToken,
		TLSConfig:            serverTLS,
		HandshakeTimeout:     30 * time.Second,
		MaxConcurrentStreams: 2,
		MaxClientConnections: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("TLS Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("TLS Serve did not stop")
		}
	})

	dialFrom := func(sourceIP string) net.Conn {
		t.Helper()
		dialer := net.Dialer{
			Timeout:   2 * time.Second,
			LocalAddr: &net.TCPAddr{IP: net.ParseIP(sourceIP)},
		}
		conn, err := dialer.Dial("tcp", server.Addr().String())
		if err != nil {
			t.Fatalf("dial from %s: %v", sourceIP, err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}

	first := dialFrom("127.0.0.1")
	firstKey := tlsSourceKey(first.LocalAddr())
	waitForTLSLimitState(t, "first connection admission", func() bool {
		return server.clients.count(firstKey) == 1 && len(server.core.sem) == 1
	})

	rejected := dialFrom("127.0.0.1")
	if err := rejected.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if _, err := rejected.Read(buffer); err == nil {
		t.Fatal("second connection from the same source remained open")
	} else if netError, ok := err.(net.Error); ok && netError.Timeout() {
		t.Fatal("second connection from the same source was not rejected")
	}
	waitForTLSLimitState(t, "same-source rejection rollback", func() bool {
		return server.clients.count(firstKey) == 1 && len(server.core.sem) == 1
	})

	different := dialFrom("127.0.0.2")
	differentKey := tlsSourceKey(different.LocalAddr())
	if differentKey == firstKey {
		t.Fatalf("different loopback sources share key %q", firstKey)
	}
	waitForTLSLimitState(t, "different-source admission", func() bool {
		return server.clients.count(differentKey) == 1 && len(server.core.sem) == 2
	})

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	waitForTLSLimitState(t, "first connection release", func() bool {
		return server.clients.count(firstKey) == 0 && len(server.core.sem) == 1
	})

	replacement := dialFrom("127.0.0.1")
	waitForTLSLimitState(t, "released slot reuse", func() bool {
		return server.clients.count(firstKey) == 1 && len(server.core.sem) == 2
	})

	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
	if err := different.Close(); err != nil {
		t.Fatal(err)
	}
	waitForTLSLimitState(t, "all connection releases", func() bool {
		return server.clients.count(firstKey) == 0 &&
			server.clients.count(differentKey) == 0 && len(server.core.sem) == 0
	})
}

func waitForTLSLimitState(t *testing.T, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", description)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
