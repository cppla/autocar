package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

func TestSOCKSUDPSetupControlCloseCancelsDial(t *testing.T) {
	for _, halfClose := range []bool{false, true} {
		t.Run(fmt.Sprintf("half-close=%v", halfClose), func(t *testing.T) {
			entered := make(chan context.Context, 1)
			returned := make(chan struct{})
			abort := make(chan struct{})
			dial := func(ctx context.Context) (transport.PacketConn, error) {
				defer close(returned)
				entered <- ctx
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-abort:
					return nil, errors.New("fixture cleanup")
				}
			}
			server, control, address := startSOCKSUDPSetup(t, dial, 5*time.Second, nil)
			t.Cleanup(func() { close(abort); awaitSOCKSUDPSetupSignal(t, returned, "dial cleanup") })
			ctx := awaitSOCKSUDPSetupContext(t, entered)
			if halfClose {
				if err := control.(*net.TCPConn).CloseWrite(); err != nil {
					t.Fatal(err)
				}
			} else {
				_ = control.Close()
			}
			awaitSOCKSUDPSetupSignal(t, ctx.Done(), "control EOF cancellation")
			if !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatalf("setup error = %v, want canceled", ctx.Err())
			}
			awaitSOCKSUDPSetupSignal(t, returned, "canceled dial return")
			awaitSOCKSUDPSetupIdle(t, server)
			if halfClose {
				_ = control.SetReadDeadline(time.Now().Add(time.Second))
				reply, err := io.ReadAll(control)
				if err != nil {
					t.Fatal(err)
				}
				if len(reply) >= 2 && reply[1] == socksReplySucceeded {
					t.Fatal("canceled setup returned success")
				}
			}
			// MaxConnections=1: completion, not merely a canceled dial context,
			// must release admission for the next legitimate SOCKS greeting.
			fresh := dialTCP(t, address)
			defer fresh.Close()
			socksGreeting(t, fresh, nil)
		})
	}
}

func TestSOCKSUDPSetupLatePacketClosesExactlyOnce(t *testing.T) {
	for _, ordering := range []string{"canceled first", "success first", "race"} {
		for iteration := range 4 {
			t.Run(fmt.Sprintf("%s/%d", ordering, iteration), func(t *testing.T) {
				packet := newSOCKSUDPSetupCountedPacket(t)
				entered := make(chan context.Context, 1)
				gate := make(chan struct{})
				release := sync.OnceFunc(func() { close(gate) })
				dial := func(ctx context.Context) (transport.PacketConn, error) {
					entered <- ctx
					<-gate
					// Deliberately allow success to win a cancellation race.
					return packet, nil
				}
				server, control, _ := startSOCKSUDPSetup(t, dial, 5*time.Second, nil)
				t.Cleanup(release)
				ctx := awaitSOCKSUDPSetupContext(t, entered)
				switch ordering {
				case "canceled first":
					_ = control.Close()
					awaitSOCKSUDPSetupSignal(t, ctx.Done(), "late-success cancellation")
					release()
				case "success first":
					release()
					if reply, _ := readSOCKSReplyAddress(t, control); reply != socksReplySucceeded {
						t.Fatalf("reply = %d", reply)
					}
					_ = control.Close()
				case "race":
					closed := make(chan struct{})
					go func() { _ = control.Close(); close(closed) }()
					release()
					awaitSOCKSUDPSetupSignal(t, closed, "control closer")
				}
				awaitSOCKSUDPSetupIdle(t, server)
				if got := packet.closes.Load(); got != 1 {
					t.Fatalf("packet Close calls = %d, want 1", got)
				}
			})
		}
	}
}

func TestSOCKSUDPSetupSuccessDetachesContext(t *testing.T) {
	target, stopEcho := startUDPEcho(t)
	t.Cleanup(stopEcho)
	raw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	packet := &socksUDPSetupCountedPacket{PacketConn: &directPacketConn{UDPConn: raw}}
	entered := make(chan context.Context, 1)
	server, control, _ := startSOCKSUDPSetup(t, func(ctx context.Context) (transport.PacketConn, error) {
		entered <- ctx
		return packet, nil
	}, 300*time.Millisecond, nil)
	ctx := awaitSOCKSUDPSetupContext(t, entered)
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("setup context has no dial deadline")
	}
	reply, relay := readSOCKSReplyAddress(t, control)
	if reply != socksReplySucceeded {
		t.Fatalf("reply = %d", reply)
	}
	awaitSOCKSUDPSetupSignal(t, ctx.Done(), "successful setup timer cancellation")
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("setup ended by %v instead of prompt cancellation", ctx.Err())
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	assertSOCKSUDPSetupEcho(t, udp, relay, target, "before original setup deadline")
	if remaining := time.Until(deadline.Add(50 * time.Millisecond)); remaining > 0 {
		time.Sleep(remaining)
	}
	if packet.closes.Load() != 0 {
		t.Fatal("successful setup cancellation closed the packet connection")
	}
	assertSOCKSUDPSetupEcho(t, udp, relay, target, "after original setup deadline")
	_ = control.Close()
	awaitSOCKSUDPSetupIdle(t, server)
	if got := packet.closes.Load(); got != 1 {
		t.Fatalf("packet Close calls = %d, want 1", got)
	}
}

func TestSOCKSUDPSetupFailureWithLiveControl(t *testing.T) {
	for _, mode := range []string{"error", "nil", "packet and error"} {
		t.Run(mode, func(t *testing.T) {
			packet := newSOCKSUDPSetupCountedPacket(t)
			var calls atomic.Int32
			dial := func(context.Context) (transport.PacketConn, error) {
				calls.Add(1)
				switch mode {
				case "error":
					return nil, errors.New("fixture packet dial failed")
				case "nil":
					return nil, nil
				default:
					return packet, errors.New("fixture packet dial failed after allocation")
				}
			}
			wantReply, wantCalls, wantCloses := byte(socksReplyGeneralFailure), int32(1), int32(0)
			if mode == "packet and error" {
				wantCloses = 1
			}
			server, control, _ := startSOCKSUDPSetup(t, dial, 5*time.Second, nil)
			if reply, _ := readSOCKSReplyAddress(t, control); reply != wantReply {
				t.Fatalf("reply=%d, want %d", reply, wantReply)
			}
			// Keep the peer open. The server must stop and join its early reader
			// on this failure path without needing the client to close TCP.
			awaitSOCKSUDPSetupIdle(t, server)
			_ = control.SetReadDeadline(time.Now().Add(time.Second))
			if n, err := control.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("failure connection read=%d,%v, want EOF", n, err)
			}
			if calls.Load() != wantCalls || packet.closes.Load() != wantCloses || packet.receives.Load() != 0 {
				t.Fatalf("dial/close/Receive calls=%d/%d/%d, want %d/%d/0", calls.Load(), packet.closes.Load(), packet.receives.Load(), wantCalls, wantCloses)
			}
		})
	}
}

func TestSOCKSUDPSetupOrdinaryCleanupJoinsPacketWorker(t *testing.T) {
	packet := &socksUDPSetupSlowReceive{
		recordingPacketConn: newRecordingPacketConn(),
		receiving:           make(chan struct{}), stopping: make(chan struct{}), release: make(chan struct{}),
	}
	t.Cleanup(func() { _ = packet.Close() })
	release := sync.OnceFunc(func() { close(packet.release) })
	server, control, _ := startSOCKSUDPSetup(t, func(context.Context) (transport.PacketConn, error) {
		return packet, nil
	}, 5*time.Second, nil)
	t.Cleanup(release)
	if reply, _ := readSOCKSReplyAddress(t, control); reply != socksReplySucceeded {
		t.Fatalf("reply = %d", reply)
	}
	awaitSOCKSUDPSetupSignal(t, packet.receiving, "packet reader entry")
	_ = control.Close()
	awaitSOCKSUDPSetupSignal(t, packet.stopping, "packet reader interruption")
	// Ordinary control EOF must not release admission while an interrupted
	// packet worker is still unwinding. Forced Shutdown has a different contract.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := server.lifecycle.tracker.wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("admission removed before packet worker joined: %v", err)
	}
	release()
	awaitSOCKSUDPSetupIdle(t, server)
}

func TestSOCKSUDPSetupForcedShutdownCancelsDial(t *testing.T) {
	entered := make(chan context.Context, 1)
	returned, abort := make(chan struct{}), make(chan struct{})
	server, _, _ := startSOCKSUDPSetup(t, func(ctx context.Context) (transport.PacketConn, error) {
		defer close(returned)
		entered <- ctx
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-abort:
			return nil, errors.New("fixture cleanup")
		}
	}, 5*time.Second, nil)
	t.Cleanup(func() { close(abort); awaitSOCKSUDPSetupSignal(t, returned, "shutdown dial cleanup") })
	ctx := awaitSOCKSUDPSetupContext(t, entered)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v, want deadline exceeded", err)
	}
	awaitSOCKSUDPSetupSignal(t, ctx.Done(), "forced shutdown cancellation")
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("setup error = %v, want canceled", ctx.Err())
	}
	// Forced shutdown removes tracking before the handler necessarily exits.
	// Check the controlled dial's own receipt, not tracker-zero alone.
	awaitSOCKSUDPSetupSignal(t, returned, "forced shutdown dial return")
}

func startSOCKSUDPSetup(t *testing.T, dial func(context.Context) (transport.PacketConn, error), timeout time.Duration, request []byte) (*SOCKS5Server, net.Conn, string) {
	t.Helper()
	server, address, stop := startSOCKS5(t, Config{
		Dialer:      testPacketDialer{Dialer: directDialer(), dialPacket: dial},
		DialTimeout: timeout, MaxConnections: 1,
	})
	t.Cleanup(func() { stop(server) })
	control := dialTCP(t, address)
	t.Cleanup(func() { _ = control.Close() })
	socksGreeting(t, control, nil)
	if request == nil {
		request = ipv4SOCKSRequest(socksCommandUDP, net.IPv4zero, 0)
	}
	mustWrite(t, control, request)
	return server, control, address
}

func awaitSOCKSUDPSetupSignal(t *testing.T, done <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func awaitSOCKSUDPSetupContext(t *testing.T, entered <-chan context.Context) context.Context {
	t.Helper()
	select {
	case ctx := <-entered:
		return ctx
	case <-time.After(time.Second):
		t.Fatal("packet dialer was not entered")
		return nil
	}
}

func awaitSOCKSUDPSetupIdle(t *testing.T, server *SOCKS5Server) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.lifecycle.tracker.wait(ctx); err != nil {
		t.Fatalf("setup retained admission: %v", err)
	}
}

func assertSOCKSUDPSetupEcho(t *testing.T, client *net.UDPConn, relay *net.UDPAddr, target, payload string) {
	t.Helper()
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	writeTargetErrorDatagram(t, client, relay, target, payload)
	buffer := make([]byte, 512)
	n, source, err := client.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	got, address, err := parseSOCKSUDPDatagram(buffer[:n])
	if err != nil || string(got) != payload || address != target || !source.IP.Equal(relay.IP) || source.Port != relay.Port {
		t.Fatalf("UDP echo source=%v payload=%q target=%q error=%v", source, got, address, err)
	}
}

type socksUDPSetupCountedPacket struct {
	transport.PacketConn
	closes, receives atomic.Int32
}

func newSOCKSUDPSetupCountedPacket(t *testing.T) *socksUDPSetupCountedPacket {
	t.Helper()
	inner := newRecordingPacketConn()
	t.Cleanup(func() { _ = inner.Close() })
	return &socksUDPSetupCountedPacket{PacketConn: inner}
}

func (c *socksUDPSetupCountedPacket) Close() error { c.closes.Add(1); return c.PacketConn.Close() }
func (c *socksUDPSetupCountedPacket) Receive() ([]byte, string, error) {
	c.receives.Add(1)
	return c.PacketConn.Receive()
}

type socksUDPSetupSlowReceive struct {
	*recordingPacketConn
	receiving, stopping, release chan struct{}
}

func (c *socksUDPSetupSlowReceive) Receive() ([]byte, string, error) {
	close(c.receiving)
	<-c.closed
	close(c.stopping)
	<-c.release
	return nil, "", net.ErrClosed
}
