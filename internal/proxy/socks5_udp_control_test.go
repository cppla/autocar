package proxy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

func TestSOCKSUDPControlReaderOutlivesSetupContext(t *testing.T) {
	for _, stop := range []string{"peer close", "cleanup deadline"} {
		t.Run(stop, func(t *testing.T) {
			control, peer := net.Pipe()
			ctx, cancel := context.WithCancel(context.Background())
			done := watchSOCKSUDPControl(control, cancel)
			t.Cleanup(func() {
				cancel()
				_ = control.Close()
				_ = peer.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("control reader did not join")
				}
			})

			// Successful setup cancels the timer, not the control reader. Pipe
			// writes complete only after all extra control bytes are consumed.
			cancel()
			if !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatal("setup context was not canceled")
			}
			if err := peer.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			mustWrite(t, peer, []byte("ignored UDP control bytes"))
			select {
			case <-done:
				t.Fatal("setup cancellation or extra bytes stopped the reader")
			default:
			}
			if stop == "peer close" {
				_ = peer.Close()
			} else {
				_ = control.SetReadDeadline(time.Now())
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("control reader did not stop")
			}
		})
	}
}

func TestSOCKSUDPControlCancelsEndpointLookup(t *testing.T) {
	control, peer := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	controlDone := watchSOCKSUDPControl(control, cancel)
	lookupStarted := make(chan struct{})
	lookupDone := make(chan struct{})
	var lookupErr error
	go func() {
		defer close(lookupDone)
		_, lookupErr = validateUDPAssociateRequest(ctx, socksRequest{
			addressType: socksAddressDomain, host: "client.invalid",
		}, net.IPv4(127, 0, 0, 1), func(ctx context.Context, _ string) ([]net.IPAddr, error) {
			close(lookupStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		})
	}()
	t.Cleanup(func() {
		cancel()
		_ = control.Close()
		_ = peer.Close()
		for _, done := range []<-chan struct{}{controlDone, lookupDone} {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("control/lookup worker did not join")
			}
		}
	})
	select {
	case <-lookupStarted:
	case <-time.After(time.Second):
		t.Fatal("endpoint lookup did not start")
	}
	_ = peer.Close()
	select {
	case <-lookupDone:
		if !errors.Is(lookupErr, context.Canceled) {
			t.Fatalf("lookup error = %v, want context canceled", lookupErr)
		}
	case <-time.After(time.Second):
		t.Fatal("control EOF did not interrupt the context-aware endpoint lookup")
	}
}

func TestSOCKS5UDPControlReaderStartsAfterCompleteRequest(t *testing.T) {
	packet := newRecordingPacketConn()
	dialer := testPacketDialer{
		Dialer: directDialer(),
		dialPacket: func(context.Context) (transport.PacketConn, error) {
			return packet, nil
		},
	}
	server, address, stop := startSOCKS5(t, Config{Dialer: dialer})
	defer stop(server)
	control := dialTCP(t, address)
	defer control.Close()
	socksGreeting(t, control, nil)
	// Fragment both the address and port. An earlier reader must not steal
	// these bytes from the parser. No timing/scheduler assumptions are needed.
	request := ipv4SOCKSRequest(socksCommandUDP, net.IPv4(127, 0, 0, 1), 53001)
	for _, value := range request {
		mustWrite(t, control, []byte{value})
	}
	if reply, _ := readSOCKSReplyAddress(t, control); reply != socksReplySucceeded {
		t.Fatalf("fragmented request reply = %d, want success", reply)
	}
	mustWrite(t, control, []byte("extra control bytes"))
	_ = control.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.lifecycle.tracker.wait(ctx); err != nil {
		t.Fatalf("control EOF did not release the association: %v", err)
	}
	select {
	case <-packet.closed:
	default:
		t.Fatal("upstream packet connection remained open")
	}
}

func TestSOCKSUDPSetupReplyStallJoinsControlReader(t *testing.T) {
	for _, mode := range []string{"validation failure", "dial failure", "success"} {
		t.Run(mode, func(t *testing.T) {
			packet := newRecordingPacketConn()
			t.Cleanup(func() { _ = packet.Close() })
			server, err := NewSOCKS5Server(Config{
				Dialer: testPacketDialer{
					Dialer: directDialer(),
					dialPacket: func(context.Context) (transport.PacketConn, error) {
						if mode == "dial failure" {
							return packet, errors.New("fixture dial failure")
						}
						return packet, nil
					},
				},
				HandshakeTimeout: 50 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			control, peer := net.Pipe()
			done := make(chan struct{})
			request := socksRequest{addressType: socksAddressIPv4, host: "0.0.0.0"}
			if mode == "validation failure" {
				request.host = "192.0.2.1"
			}
			go func() {
				defer close(done)
				server.serveUDPAssociate(socksUDPControlAddressConn{control}, request)
			}()
			t.Cleanup(func() {
				_ = control.Close()
				_ = peer.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("setup handler did not join")
				}
			})
			// The peer never reads. Only a real write deadline can release the
			// pipe reply; returning also requires joining the still-open reader.
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("stalled setup reply retained the handler/control reader")
			}
			if mode != "validation failure" {
				select {
				case <-packet.closed:
				default:
					t.Fatal("stalled reply retained the returned packet connection")
				}
			}
		})
	}
}

// Only addressing is supplied by the fixture; reads, writes and deadlines
// are the real pipe operations. No transport error is injected.
type socksUDPControlAddressConn struct{ net.Conn }

func (socksUDPControlAddressConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}
}

func (socksUDPControlAddressConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53001}
}
