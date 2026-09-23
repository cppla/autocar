package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

func TestSOCKS5UDPAssociateSurvivesWrappedTargetError(t *testing.T) {
	upstream := newTargetErrorPacketConn(fmt.Errorf("lazy target open: %w", errors.Join(
		transport.ErrPacketTargetUnavailable, errors.New("fixture target refusal"),
	)))
	_, client, relay := startTargetErrorAssociation(t, upstream)
	assertTargetErrorAssociationEcho(t, upstream, client, relay, "before target failure")
	writeTargetErrorDatagram(t, client, relay, "unavailable.invalid:53", "drop only this packet")
	select {
	case <-upstream.rejected:
	case <-time.After(time.Second):
		t.Fatal("unavailable target did not reach the upstream")
	}

	assertTargetErrorAssociationEcho(t, upstream, client, relay, "after target failure")
	if got := upstream.rejections.Load(); got != 1 {
		t.Fatalf("failed packet was retried %d times, want one attempt", got)
	}
	select {
	case <-upstream.closed:
		t.Fatal("recoverable target error closed the upstream association")
	default:
	}
}

func TestSOCKS5UDPAssociateSendFailureRemainsTerminal(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "unknown", err: errors.New("fixture upstream failure")},
		{name: "canceled", err: fmt.Errorf("send interrupted: %w", context.Canceled)},
		{name: "deadline", err: fmt.Errorf("send interrupted: %w", context.DeadlineExceeded)},
		{name: "closed", err: fmt.Errorf("send interrupted: %w", net.ErrClosed)},
	} {
		t.Run(test.name, func(t *testing.T) {
			upstream := newTargetErrorPacketConn(test.err)
			control, client, relay := startTargetErrorAssociation(t, upstream)
			writeTargetErrorDatagram(t, client, relay, "unavailable.invalid:53", "terminal packet")
			select {
			case <-upstream.closed:
			case <-time.After(time.Second):
				t.Fatal("terminal send error left the upstream association open")
			}
			if err := control.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if n, err := control.Read(make([]byte, 1)); n != 0 || err == nil {
				t.Fatalf("terminal send error did not close the control connection: n=%d err=%v", n, err)
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("control connection only timed out instead of closing")
			}
			if got := upstream.rejections.Load(); got != 1 {
				t.Fatalf("terminal packet attempts=%d, want one", got)
			}
		})
	}
}

type targetErrorPacketConn struct {
	*recordingPacketConn
	err        error
	rejected   chan struct{}
	rejectOnce sync.Once
	rejections atomic.Int32
}

func newTargetErrorPacketConn(err error) *targetErrorPacketConn {
	return &targetErrorPacketConn{
		recordingPacketConn: newRecordingPacketConn(),
		err:                 err,
		rejected:            make(chan struct{}),
	}
}

func (c *targetErrorPacketConn) Send(payload []byte, address string) error {
	if address == "unavailable.invalid:53" {
		c.rejections.Add(1)
		c.rejectOnce.Do(func() { close(c.rejected) })
		return c.err
	}
	return c.recordingPacketConn.Send(payload, address)
}

func startTargetErrorAssociation(t *testing.T, upstream transport.PacketConn) (net.Conn, *net.UDPConn, *net.UDPAddr) {
	t.Helper()
	dialer := testPacketDialer{
		Dialer: directDialer(),
		dialPacket: func(context.Context) (transport.PacketConn, error) {
			return upstream, nil
		},
	}
	server, address, stop := startSOCKS5(t, Config{Dialer: dialer})
	t.Cleanup(func() { stop(server) })
	control := dialTCP(t, address)
	t.Cleanup(func() { _ = control.Close() })
	socksGreeting(t, control, nil)
	mustWrite(t, control, ipv4SOCKSRequest(socksCommandUDP, net.IPv4zero, 0))
	reply, relay := readSOCKSReplyAddress(t, control)
	if reply != socksReplySucceeded {
		t.Fatalf("UDP association reply=%d, want success", reply)
	}
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return control, client, relay
}

func writeTargetErrorDatagram(t *testing.T, client *net.UDPConn, relay *net.UDPAddr, target, payload string) {
	t.Helper()
	packet, err := buildSOCKSUDPDatagram([]byte(payload), target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteToUDP(packet, relay); err != nil {
		t.Fatal(err)
	}
}

func assertTargetErrorAssociationEcho(t *testing.T, upstream *targetErrorPacketConn, client *net.UDPConn, relay *net.UDPAddr, payload string) {
	t.Helper()
	const target = "192.0.2.7:5353"
	writeTargetErrorDatagram(t, client, relay, target, payload)
	select {
	case sent := <-upstream.sends:
		if string(sent.payload) != payload || sent.address != target {
			t.Fatalf("upstream packet=%q to %q, want %q to %q", sent.payload, sent.address, payload, target)
		}
	case <-time.After(time.Second):
		t.Fatal("valid datagram did not reach upstream on the same association")
	}
	upstream.incoming <- packetRecord{payload: []byte(payload), address: target}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 256)
	n, source, err := client.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !source.IP.Equal(relay.IP) || source.Port != relay.Port {
		t.Fatalf("response source=%v, want relay %v", source, relay)
	}
	got, address, err := parseSOCKSUDPDatagram(buffer[:n])
	if err != nil || string(got) != payload || address != target {
		t.Fatalf("response=%q from %q, error=%v", got, address, err)
	}
}
