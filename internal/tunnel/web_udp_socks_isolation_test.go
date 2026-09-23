package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/proxy"
	"github.com/cppla/autocar/internal/transport"
)

func TestWebH3SOCKSUDPAssociationSurvivesRejectedTarget(t *testing.T) {
	for _, status := range []int{http.StatusBadGateway, http.StatusServiceUnavailable} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			echo := startWebUDPEcho(t)
			good := "good.example:" + strconv.Itoa(int(echo.Port()))
			resolver := newWebUDPTestResolver(map[string]netip.AddrPort{good: echo})
			limit := 4
			if status == http.StatusServiceUnavailable {
				// The healthy target occupies the only server admission slot.
				// A second target must be rejected before its resolver is called.
				limit = 1
			}
			_, client := startWebUDPTestPair(t, resolver, WebH3ServerConfig{
				MaxUDPSessions: limit, MaxClientUDPSessions: limit,
			}, WebH3ClientConfig{MaxUDPSessions: 4, MaxUDPDestinations: 4})
			observed := &webSOCKSUDPErrorDialer{WebH3Client: client, errors: make(chan error, 1)}
			control, udp, relay := startWebSOCKSUDPIsolationClient(t, observed)
			packet := webSOCKSUDPDomainPacket("good.example", echo.Port(), []byte("before rejection"))
			webSOCKSUDPIsolationEcho(t, udp, relay, packet)
			physical := webH3SelectedSession(t, client)

			bad := webSOCKSUDPDomainPacket("missing.example", 19001, []byte("reject only this target"))
			if _, err := udp.WriteToUDP(bad, relay); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-observed.errors:
				var rejected *WebConnectError
				if !errors.As(err, &rejected) || rejected.StatusCode != status {
					t.Fatalf("target rejection=%v, want authenticated %d", err, status)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("target rejection did not reach the real SOCKS frontend")
			}
			// A target rejection must not close the association's existing TCP
			// control channel. There is no application data on this channel.
			_ = control.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			var one [1]byte
			_, err := control.Read(one[:])
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				t.Fatalf("target %d ended the SOCKS association: control Read=%v", status, err)
			}
			_ = control.SetReadDeadline(time.Time{})
			packet = webSOCKSUDPDomainPacket("good.example", echo.Port(), []byte("after rejection"))
			webSOCKSUDPIsolationEcho(t, udp, relay, packet)
			if got := webH3SelectedSession(t, client); got != physical || physical.conn.Context().Err() != nil {
				t.Fatal("healthy traffic did not reuse the original physical H3 connection")
			}
			if resolver.count(good) != 1 || len(client.udpSlots) != 1 {
				t.Fatal("healthy target was reopened or rejected target leaked admission")
			}
			wantBadResolutions := 1
			if status == http.StatusServiceUnavailable {
				wantBadResolutions = 0
			}
			if got := resolver.count("missing.example:19001"); got != wantBadResolutions {
				t.Fatalf("rejected target resolver calls=%d, want %d without retry", got, wantBadResolutions)
			}
		})
	}
}

// Observe real Send errors without changing their classification, retries,
// payload limit, or PacketConn lifetime.
type webSOCKSUDPErrorDialer struct {
	*WebH3Client
	errors chan error
}

func (d *webSOCKSUDPErrorDialer) DialPacket(ctx context.Context) (transport.PacketConn, error) {
	packet, err := d.WebH3Client.DialPacket(ctx)
	if err != nil {
		return nil, err
	}
	return &webSOCKSUDPErrorPacket{PacketConn: packet, errors: d.errors}, nil
}

type webSOCKSUDPErrorPacket struct {
	transport.PacketConn
	errors chan error
}

func (p *webSOCKSUDPErrorPacket) Send(payload []byte, address string) error {
	err := p.PacketConn.Send(payload, address)
	if err != nil {
		select {
		case p.errors <- err:
		default:
		}
	}
	return err
}

func (p *webSOCKSUDPErrorPacket) MaxPayloadSize() int {
	return p.PacketConn.(transport.PacketPayloadSizer).MaxPayloadSize()
}

func startWebSOCKSUDPIsolationClient(t *testing.T, dialer transport.Dialer) (net.Conn, *net.UDPConn, *net.UDPAddr) {
	t.Helper()
	server, err := proxy.NewSOCKS5Server(proxy.Config{Dialer: dialer, IdleTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		_ = listener.Close()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("SOCKS server did not stop")
		}
	})
	control, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	_ = control.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := control.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(control, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		t.Fatalf("SOCKS greeting=%v err=%v", greeting, err)
	}
	if _, err := control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(control, reply[:]); err != nil || !bytes.Equal(reply[:4], []byte{5, 0, 0, 1}) {
		t.Fatalf("SOCKS associate=%v err=%v", reply, err)
	}
	_ = control.SetDeadline(time.Time{})
	relay := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(binary.BigEndian.Uint16(reply[8:]))}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	return control, udp, relay
}

func webSOCKSUDPIsolationEcho(t *testing.T, udp *net.UDPConn, relay *net.UDPAddr, packet []byte) {
	t.Helper()
	_ = udp.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := udp.WriteToUDP(packet, relay); err != nil {
		t.Fatal(err)
	}
	var response [256]byte
	n, source, err := udp.ReadFromUDP(response[:])
	if err != nil || !bytes.Equal(response[:n], packet) || source.String() != relay.String() {
		t.Fatalf("SOCKS UDP echo=%x source=%v err=%v", response[:n], source, err)
	}
}

func webSOCKSUDPDomainPacket(host string, port uint16, payload []byte) []byte {
	packet := append([]byte{0, 0, 0, 3, byte(len(host))}, host...)
	packet = binary.BigEndian.AppendUint16(packet, port)
	return append(packet, payload...)
}
