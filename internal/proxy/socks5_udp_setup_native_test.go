package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
	"github.com/cppla/autocar/internal/tunnel"
)

func TestSOCKS5UDPAbortedNativeSetupReleasesAdmission(t *testing.T) {
	// The real native client sends to a bound loopback UDP socket that never
	// answers. No fabricated transport error or shared-dial cancellation is
	// used to release the SOCKS caller; only its control TCP connection closes.
	blackhole, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = blackhole.Close() })
	const upstreamTimeout = 5 * time.Second
	native, err := tunnel.NewClient(tunnel.ClientConfig{
		ServerAddress:   blackhole.LocalAddr().String(),
		Token:           "local-native-setup-regression-token",
		TLSConfig:       &tls.Config{ServerName: "localhost"},
		QUICDialTimeout: upstreamTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = native.Close() })
	started, done := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	dialer := testPacketDialer{
		Dialer: native,
		dialPacket: func(ctx context.Context) (transport.PacketConn, error) {
			close(started)
			defer close(done)
			packet, err := native.DialPacket(ctx)
			result <- err
			return packet, err
		},
	}
	server, address, stopProxy := startSOCKS5(t, Config{
		Dialer: dialer, MaxConnections: 1, DialTimeout: 2 * upstreamTimeout,
	})
	t.Cleanup(func() {
		// Only fixture teardown closes the native client and its client-owned
		// shared physical dial. Join the observed caller and proxy Serve too.
		_ = native.Close()
		stopProxy(server)
		select {
		case <-started:
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("native packet setup did not finish during cleanup")
			}
		default:
		}
	})
	control := dialTCP(t, address)
	t.Cleanup(func() { _ = control.Close() })
	socksGreeting(t, control, nil)
	mustWrite(t, control, ipv4SOCKSRequest(socksCommandUDP, net.IPv4zero, 0))
	if err := blackhole.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	initial := make([]byte, 4096)
	n, _, err := blackhole.ReadFromUDP(initial)
	if err != nil {
		t.Fatalf("native QUIC Initial did not reach the loopback peer: %v", err)
	}
	if n < 1200 || initial[0]&0xc0 != 0xc0 {
		t.Fatalf("unexpected first native QUIC datagram: size=%d header=%x", n, initial[:1])
	}
	if err := control.Close(); err != nil {
		t.Fatal(err)
	}
	// One completion budget covers both caller cancellation and normal
	// admission cleanup. It is well below the untouched 5s upstream timeout.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("aborted SOCKS native setup error=%v, want caller cancellation", err)
		}
	case <-ctx.Done():
		t.Fatal("closed SOCKS control did not cancel its native setup wait")
	}
	if err := server.lifecycle.tracker.wait(ctx); err != nil {
		t.Fatal("aborted native setup retained the only SOCKS admission slot")
	}
	replacement := dialTCP(t, address)
	t.Cleanup(func() { _ = replacement.Close() })
	socksGreeting(t, replacement, nil)
}
