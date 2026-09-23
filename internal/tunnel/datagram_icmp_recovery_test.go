package tunnel

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

// A closed destination must not silently retire an otherwise usable native UDP
// association. Operating systems differ in whether an unconnected socket sees
// asynchronous ICMP errors: this tests continuity, not delivery of a particular
// ICMP message or errno, and never injects a synthetic socket error.
func TestQUICDatagramClosedPortPreservesAssociation(t *testing.T) {
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	echoAddress := echo.LocalAddr().String()
	receipts := make(chan udpEchoReceipt, 4)
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		buffer := make([]byte, 256)
		for {
			n, source, err := echo.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			select {
			case receipts <- udpEchoReceipt{payload: append([]byte(nil), buffer[:n]...), source: source}:
			default:
			}
			if _, err := echo.WriteToUDPAddrPort(buffer[:n], source); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = echo.Close()
		select {
		case <-echoDone:
		case <-time.After(time.Second):
			t.Error("UDP echo worker did not stop")
		}
	})

	var closedAddress atomic.Value
	closedAddress.Store("")
	var closedRequests atomic.Int32
	resolvedClosed := make(chan struct{}, 1)
	numeric := numericUDPResolver()
	resolver := UDPResolverFunc(func(ctx context.Context, address string) ([]netip.AddrPort, error) {
		endpoints, err := numeric.ResolveUDPContext(ctx, address)
		if err == nil && address == closedAddress.Load().(string) {
			closedRequests.Add(1)
			select {
			case resolvedClosed <- struct{}{}:
			default:
			}
		}
		return endpoints, err
	})
	serverTLS, clientTLS := testTLSConfigs(t)
	server, err := ListenQUIC(QUICServerConfig{
		Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
		UDPResolver: resolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx) }()
	var client *Client
	var packet transport.PacketConn
	var receivers sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		stopped := make(chan error, 1)
		go func() {
			if packet != nil {
				_ = packet.Close()
			}
			if client != nil {
				_ = client.Close()
			}
			closeErr := server.Close()
			serveErr := <-serveDone
			receivers.Wait()
			if errors.Is(closeErr, net.ErrClosed) {
				closeErr = nil
			}
			stopped <- errors.Join(closeErr, serveErr)
		}()
		select {
		case err := <-stopped:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("native UDP fixture did not stop")
		}
	})
	client, err = NewClient(ClientConfig{ServerAddress: server.Addr().String(), Token: testToken, TLSConfig: clientTLS})
	if err != nil {
		t.Fatal(err)
	}
	packet, err = client.DialPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var originalSource netip.AddrPort
	checkEcho := func(payload []byte) {
		t.Helper()
		if err := packet.Send(payload, echoAddress); err != nil {
			t.Fatal(err)
		}
		received := make(chan packetReceiveResult, 1)
		receivers.Add(1)
		go func() {
			defer receivers.Done()
			data, address, err := packet.Receive()
			received <- packetReceiveResult{payload: data, address: address, err: err}
		}()
		timer := time.NewTimer(time.Second)
		defer timer.Stop()
		select {
		case result := <-received:
			if result.err != nil || !bytes.Equal(result.payload, payload) || result.address != echoAddress {
				t.Fatalf("same-association echo mismatch: payload=%q address=%q error=%v", result.payload, result.address, result.err)
			}
		case <-timer.C:
			t.Fatal("same native UDP association stopped receiving healthy replies")
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		select {
		case receipt := <-receipts:
			if !bytes.Equal(receipt.payload, payload) {
				t.Fatalf("healthy endpoint received wrong payload: %q", receipt.payload)
			}
			if originalSource.IsValid() && receipt.source != originalSource {
				t.Fatalf("relay replaced its UDP socket: %s -> %s", originalSource, receipt.source)
			}
			originalSource = receipt.source
		default:
			t.Fatal("healthy response arrived without an echo receipt")
		}
	}
	checkEcho([]byte("healthy before closed port"))

	// Allocate only after every fixture/association socket is established, so
	// the relay itself cannot reuse this just-released ephemeral port. Rebind
	// between rounds to narrow the remaining unrelated-process reuse window.
	guard, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if guard != nil {
			_ = guard.Close()
		}
	})
	closedEndpoint := guard.LocalAddr().(*net.UDPAddr)
	closedAddress.Store(closedEndpoint.String())
	for round := 0; round < 3; round++ {
		before := closedRequests.Load()
		if err := guard.Close(); err != nil {
			t.Fatal(err)
		}
		guard = nil
		for index := 0; index < 8; index++ {
			if err := packet.Send([]byte{byte(round), byte(index)}, closedEndpoint.String()); err != nil {
				t.Fatal(err)
			}
		}
		for closedRequests.Load() == before {
			select {
			case <-resolvedClosed:
			case <-ctx.Done():
				t.Fatal("no closed-port request reached the relay")
			}
		}
		// Give naturally generated local errors an opportunity to arrive.
		// Their existence or delivery is intentionally not an oracle.
		timer := time.NewTimer(40 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			t.Fatal(ctx.Err())
		}
		// Keep the destination closed until the healthy reply arrives. The
		// relay processes requests serially, so this also places its observed
		// closed-destination write attempt before reopening the guard socket.
		checkEcho([]byte{byte(round), 'o', 'k'})
		guard, err = net.ListenUDP("udp4", closedEndpoint)
		if isWebTestAddressInUse(err) {
			t.Skip("closed-port fixture became inconclusive: another socket reused the port")
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("%s: native association retained its UDP source and healthy echo; %d closed-destination requests resolved; no claim that ICMP reached the unconnected socket", runtime.GOOS, closedRequests.Load())
}
