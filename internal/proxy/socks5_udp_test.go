package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

func TestSOCKS5UDPAssociateRoundTrip(t *testing.T) {
	echoAddress, stopEcho := startUDPEcho(t)
	defer stopEcho()

	dialer := testPacketDialer{
		Dialer: directDialer(),
		dialPacket: func(context.Context) (transport.PacketConn, error) {
			conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				return nil, err
			}
			return &directPacketConn{UDPConn: conn}, nil
		},
	}
	server, proxyAddress, stopProxy := startSOCKS5(t, Config{Dialer: dialer})
	defer stopProxy(server)

	control := dialTCP(t, proxyAddress)
	defer control.Close()
	socksGreeting(t, control, nil)
	mustWrite(t, control, ipv4SOCKSRequest(socksCommandUDP, net.IPv4zero, 0))
	reply, relayAddress := readSOCKSReplyAddress(t, control)
	if reply != socksReplySucceeded {
		t.Fatalf("reply = %d, want success", reply)
	}
	if relayAddress.Port == 0 || !relayAddress.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("UDP relay address = %v, want loopback with a nonzero port", relayAddress)
	}

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte("autocar UDP associate")
	packet, err := buildSOCKSUDPDatagram(payload, echoAddress)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteToUDP(packet, relayAddress); err != nil {
		t.Fatal(err)
	}

	buffer := make([]byte, maxUDPDatagramSize)
	n, source, err := client.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !source.IP.Equal(relayAddress.IP) || source.Port != relayAddress.Port {
		t.Fatalf("response source = %v, want %v", source, relayAddress)
	}
	got, gotSource, err := parseSOCKSUDPDatagram(buffer[:n])
	if err != nil {
		t.Fatal(err)
	}
	if gotSource != echoAddress {
		t.Fatalf("encapsulated source = %q, want %q", gotSource, echoAddress)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
}

func TestSOCKS5UDPAssociateDropsFragmentsAndWrongSourcePort(t *testing.T) {
	packetConn := newRecordingPacketConn()
	dialer := testPacketDialer{
		Dialer: directDialer(),
		dialPacket: func(context.Context) (transport.PacketConn, error) {
			return packetConn, nil
		},
	}
	server, proxyAddress, stopProxy := startSOCKS5(t, Config{Dialer: dialer})
	defer stopProxy(server)

	allowed, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer allowed.Close()
	wrongPort, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer wrongPort.Close()

	control := dialTCP(t, proxyAddress)
	defer control.Close()
	socksGreeting(t, control, nil)
	mustWrite(t, control, ipv4SOCKSRequest(
		socksCommandUDP,
		net.IPv4zero,
		uint16(allowed.LocalAddr().(*net.UDPAddr).Port),
	))
	reply, relayAddress := readSOCKSReplyAddress(t, control)
	if reply != socksReplySucceeded {
		t.Fatalf("reply = %d, want success", reply)
	}

	valid, err := buildSOCKSUDPDatagram([]byte("accepted"), "example.com:53")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongPort.WriteToUDP(valid, relayAddress); err != nil {
		t.Fatal(err)
	}
	assertNoPacketSend(t, packetConn.sends)

	fragmented := append([]byte(nil), valid...)
	fragmented[2] = 1
	if _, err := allowed.WriteToUDP(fragmented, relayAddress); err != nil {
		t.Fatal(err)
	}
	assertNoPacketSend(t, packetConn.sends)

	if _, err := allowed.WriteToUDP(valid, relayAddress); err != nil {
		t.Fatal(err)
	}
	select {
	case sent := <-packetConn.sends:
		if sent.address != "example.com:53" || string(sent.payload) != "accepted" {
			t.Fatalf("upstream send = %#v", sent)
		}
	case <-time.After(time.Second):
		t.Fatal("valid datagram was not sent upstream")
	}

	packetConn.incoming <- packetRecord{payload: []byte("response"), address: "192.0.2.9:5353"}
	_ = allowed.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 128)
	n, _, err := allowed.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	payload, source, err := parseSOCKSUDPDatagram(buffer[:n])
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "response" || source != "192.0.2.9:5353" {
		t.Fatalf("downstream packet = %q from %q", payload, source)
	}
}

func TestSOCKS5UDPAssociateSurvivesUpstreamQueuePressure(t *testing.T) {
	recorded := newRecordingPacketConn()
	upstream := &queueFullOncePacketConn{
		recordingPacketConn: recorded,
		firstRejected:       make(chan struct{}),
	}
	dialer := testPacketDialer{
		Dialer: directDialer(),
		dialPacket: func(context.Context) (transport.PacketConn, error) {
			return upstream, nil
		},
	}
	server, proxyAddress, stopProxy := startSOCKS5(t, Config{Dialer: dialer})
	defer stopProxy(server)

	control := dialTCP(t, proxyAddress)
	defer control.Close()
	socksGreeting(t, control, nil)
	mustWrite(t, control, ipv4SOCKSRequest(socksCommandUDP, net.IPv4zero, 0))
	reply, relayAddress := readSOCKSReplyAddress(t, control)
	if reply != socksReplySucceeded {
		t.Fatalf("reply = %d, want success", reply)
	}

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	first, err := buildSOCKSUDPDatagram([]byte("dropped under pressure"), "example.com:53")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteToUDP(first, relayAddress); err != nil {
		t.Fatal(err)
	}
	select {
	case <-upstream.firstRejected:
	case <-time.After(time.Second):
		t.Fatal("first datagram did not encounter queue pressure")
	}

	second, err := buildSOCKSUDPDatagram([]byte("association survived"), "example.com:53")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteToUDP(second, relayAddress); err != nil {
		t.Fatal(err)
	}
	select {
	case sent := <-recorded.sends:
		if string(sent.payload) != "association survived" {
			t.Fatalf("second upstream payload = %q", sent.payload)
		}
	case <-time.After(time.Second):
		t.Fatal("queue pressure tore down the UDP association")
	}
}

func TestSOCKS5UDPAssociateHonorsTransportPayloadLimit(t *testing.T) {
	recorded := newRecordingPacketConn()
	upstream := &limitedPacketConn{recordingPacketConn: recorded, limit: 4}
	dialer := testPacketDialer{
		Dialer: directDialer(),
		dialPacket: func(context.Context) (transport.PacketConn, error) {
			return upstream, nil
		},
	}
	server, proxyAddress, stopProxy := startSOCKS5(t, Config{Dialer: dialer})
	defer stopProxy(server)

	control := dialTCP(t, proxyAddress)
	defer control.Close()
	socksGreeting(t, control, nil)
	mustWrite(t, control, ipv4SOCKSRequest(socksCommandUDP, net.IPv4zero, 0))
	reply, relayAddress := readSOCKSReplyAddress(t, control)
	if reply != socksReplySucceeded {
		t.Fatalf("reply = %d, want success", reply)
	}
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	oversized, err := buildSOCKSUDPDatagram([]byte("12345"), "example.com:53")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteToUDP(oversized, relayAddress); err != nil {
		t.Fatal(err)
	}
	assertNoPacketSend(t, recorded.sends)

	valid, err := buildSOCKSUDPDatagram([]byte("1234"), "example.com:53")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteToUDP(valid, relayAddress); err != nil {
		t.Fatal(err)
	}
	select {
	case sent := <-recorded.sends:
		if string(sent.payload) != "1234" || sent.address != "example.com:53" {
			t.Fatalf("upstream send = %#v", sent)
		}
	case <-time.After(time.Second):
		t.Fatal("valid datagram was not sent after oversized datagram")
	}
}

func TestSOCKS5UDPAssociateRejectsMismatchedRequestedAddressBeforeUpstream(t *testing.T) {
	dialCalled := make(chan struct{}, 1)
	dialer := testPacketDialer{
		Dialer: directDialer(),
		dialPacket: func(context.Context) (transport.PacketConn, error) {
			dialCalled <- struct{}{}
			return newRecordingPacketConn(), nil
		},
	}
	server, proxyAddress, stopProxy := startSOCKS5(t, Config{Dialer: dialer})
	defer stopProxy(server)

	control := dialTCP(t, proxyAddress)
	defer control.Close()
	socksGreeting(t, control, nil)
	mustWrite(t, control, ipv4SOCKSRequest(socksCommandUDP, net.ParseIP("192.0.2.44"), 5353))
	reply, _ := readSOCKSReplyAddress(t, control)
	if reply != socksReplyNotAllowed {
		t.Fatalf("reply = %d, want not allowed", reply)
	}
	select {
	case <-dialCalled:
		t.Fatal("invalid UDP ASSOCIATE request allocated an upstream session")
	default:
	}
}

func TestSOCKS5UDPAssociateShutdownClosesPacketConn(t *testing.T) {
	packetConn := newRecordingPacketConn()
	dialer := testPacketDialer{
		Dialer: directDialer(),
		dialPacket: func(context.Context) (transport.PacketConn, error) {
			return packetConn, nil
		},
	}
	server, proxyAddress, stopProxy := startSOCKS5(t, Config{Dialer: dialer})
	defer stopProxy(server)
	control := dialTCP(t, proxyAddress)
	defer control.Close()
	socksGreeting(t, control, nil)
	mustWrite(t, control, ipv4SOCKSRequest(socksCommandUDP, net.IPv4zero, 0))
	if reply, _ := readSOCKSReplyAddress(t, control); reply != socksReplySucceeded {
		t.Fatalf("reply = %d, want success", reply)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := server.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown error = %v, want deadline exceeded", err)
	}
	select {
	case <-packetConn.closed:
	case <-time.After(time.Second):
		t.Fatal("packet connection was not closed by forced shutdown")
	}
	_ = control.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := control.Read(make([]byte, 1)); err == nil {
		t.Fatal("control connection remained open after forced shutdown")
	}
}

func TestSOCKS5UDPAssociateIdleTimeout(t *testing.T) {
	packetConn := newRecordingPacketConn()
	dialer := testPacketDialer{
		Dialer: directDialer(),
		dialPacket: func(context.Context) (transport.PacketConn, error) {
			return packetConn, nil
		},
	}
	server, proxyAddress, stopProxy := startSOCKS5(t, Config{
		Dialer:      dialer,
		IdleTimeout: 30 * time.Millisecond,
	})
	defer stopProxy(server)
	control := dialTCP(t, proxyAddress)
	defer control.Close()
	socksGreeting(t, control, nil)
	mustWrite(t, control, ipv4SOCKSRequest(socksCommandUDP, net.IPv4zero, 0))
	if reply, _ := readSOCKSReplyAddress(t, control); reply != socksReplySucceeded {
		t.Fatalf("reply = %d, want success", reply)
	}
	select {
	case <-packetConn.closed:
	case <-time.After(time.Second):
		t.Fatal("idle UDP association did not close")
	}
	_ = control.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := control.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle UDP control connection remained open")
	}
}

func TestSOCKSUDPClientEndpointSourceRestrictions(t *testing.T) {
	endpoint := &socksUDPClientEndpoint{peerIP: net.ParseIP("192.0.2.1")}
	if endpoint.accept(&net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 1000}) {
		t.Fatal("accepted a datagram from a different IP")
	}
	if !endpoint.accept(&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1000}) {
		t.Fatal("rejected first valid source")
	}
	if endpoint.accept(&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1001}) {
		t.Fatal("accepted a different source port after locking")
	}
}

func TestValidateUDPAssociateRequestAddressAndPortSemantics(t *testing.T) {
	domainLookup := func(_ context.Context, host string) ([]net.IPAddr, error) {
		switch host {
		case "client.example":
			return []net.IPAddr{
				{IP: net.ParseIP("2001:db8::99")},
				{IP: net.ParseIP("192.0.2.10")},
			}, nil
		case "other.example":
			return []net.IPAddr{{IP: net.ParseIP("192.0.2.11")}}, nil
		default:
			return nil, &net.DNSError{Name: host, Err: "test lookup failure"}
		}
	}
	tests := []struct {
		name      string
		request   []byte
		peerIP    net.IP
		wantPort  int
		wantReply byte
	}{
		{
			name:     "IPv4 concrete address and port",
			request:  ipv4SOCKSRequest(socksCommandUDP, net.ParseIP("192.0.2.10"), 5300),
			peerIP:   net.ParseIP("192.0.2.10"),
			wantPort: 5300,
		},
		{
			name:     "IPv4 unspecified dynamic port",
			request:  ipv4SOCKSRequest(socksCommandUDP, net.IPv4zero, 0),
			peerIP:   net.ParseIP("192.0.2.10"),
			wantPort: 0,
		},
		{
			name:      "IPv4 address mismatch",
			request:   ipv4SOCKSRequest(socksCommandUDP, net.ParseIP("192.0.2.11"), 5300),
			peerIP:    net.ParseIP("192.0.2.10"),
			wantReply: socksReplyNotAllowed,
		},
		{
			name:     "IPv6 concrete address and port",
			request:  ipv6SOCKSRequest(socksCommandUDP, net.ParseIP("2001:db8::10"), 5353),
			peerIP:   net.ParseIP("2001:db8::10"),
			wantPort: 5353,
		},
		{
			name:     "IPv6 unspecified dynamic port",
			request:  ipv6SOCKSRequest(socksCommandUDP, net.IPv6zero, 0),
			peerIP:   net.ParseIP("2001:db8::10"),
			wantPort: 0,
		},
		{
			name:      "IPv6 address mismatch",
			request:   ipv6SOCKSRequest(socksCommandUDP, net.ParseIP("2001:db8::11"), 5353),
			peerIP:    net.ParseIP("2001:db8::10"),
			wantReply: socksReplyNotAllowed,
		},
		{
			name:     "domain resolves to control peer",
			request:  domainSOCKSRequest(socksCommandUDP, "client.example", 6000),
			peerIP:   net.ParseIP("192.0.2.10"),
			wantPort: 6000,
		},
		{
			name:      "domain resolves elsewhere",
			request:   domainSOCKSRequest(socksCommandUDP, "other.example", 6000),
			peerIP:    net.ParseIP("192.0.2.10"),
			wantReply: socksReplyNotAllowed,
		},
		{
			name:      "domain lookup failure",
			request:   domainSOCKSRequest(socksCommandUDP, "missing.example", 6000),
			peerIP:    net.ParseIP("192.0.2.10"),
			wantReply: socksReplyHostUnreachable,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := readSOCKSRequest(bytes.NewReader(test.request))
			if err != nil {
				t.Fatal(err)
			}
			port, err := validateUDPAssociateRequest(context.Background(), request, test.peerIP, domainLookup)
			if test.wantReply == 0 {
				if err != nil || port != test.wantPort {
					t.Fatalf("port=%d error=%v, want port %d", port, err, test.wantPort)
				}
				return
			}
			var protocolErr *socksProtocolError
			if !errors.As(err, &protocolErr) || protocolErr.reply != test.wantReply {
				t.Fatalf("error = %v, want SOCKS reply %d", err, test.wantReply)
			}
		})
	}
}

func TestSOCKSUDPDatagramAddressTypesAndLimits(t *testing.T) {
	for _, address := range []string{"192.0.2.1:53", "[2001:db8::1]:443", "example.com:5353"} {
		t.Run(address, func(t *testing.T) {
			packet, err := buildSOCKSUDPDatagram([]byte("data"), address)
			if err != nil {
				t.Fatal(err)
			}
			payload, gotAddress, err := parseSOCKSUDPDatagram(packet)
			if err != nil {
				t.Fatal(err)
			}
			if string(payload) != "data" || gotAddress != address {
				t.Fatalf("round trip = %q to %q", payload, gotAddress)
			}
		})
	}

	maximumPayload := make([]byte, maxUDPDatagramSize-10) // IPv4 header is 10 bytes.
	if _, err := buildSOCKSUDPDatagram(maximumPayload, "192.0.2.1:53"); err != nil {
		t.Fatalf("maximum-size datagram: %v", err)
	}
	if _, err := buildSOCKSUDPDatagram(append(maximumPayload, 0), "192.0.2.1:53"); err == nil {
		t.Fatal("oversize datagram was accepted")
	}
}

func TestParseSOCKSUDPDatagramRejectsMalformedPackets(t *testing.T) {
	valid, err := buildSOCKSUDPDatagram([]byte("x"), "192.0.2.1:53")
	if err != nil {
		t.Fatal(err)
	}
	fragmented := append([]byte(nil), valid...)
	fragmented[2] = 1
	if _, _, err := parseSOCKSUDPDatagram(fragmented); !errors.Is(err, errSOCKSUDPFragmented) {
		t.Fatalf("fragment error = %v", err)
	}
	for _, packet := range [][]byte{
		nil,
		{0, 0, 0},
		{1, 0, 0, socksAddressIPv4, 127, 0, 0, 1, 0, 53},
		{0, 0, 0, 0xff, 0, 53},
		{0, 0, 0, socksAddressIPv4, 127, 0, 0, 1, 0, 0},
	} {
		if _, _, err := parseSOCKSUDPDatagram(packet); err == nil {
			t.Fatalf("malformed packet %v was accepted", packet)
		}
	}
}

func TestReadSOCKSUDPRequestAllowsZeroPort(t *testing.T) {
	request, err := readSOCKSRequest(bytes.NewReader(ipv4SOCKSRequest(
		socksCommandUDP,
		net.IPv4zero,
		0,
	)))
	if err != nil {
		t.Fatal(err)
	}
	if request.address != "0.0.0.0:0" {
		t.Fatalf("address = %q", request.address)
	}
	if request.addressType != socksAddressIPv4 || request.host != "0.0.0.0" || request.port != 0 {
		t.Fatalf("parsed UDP endpoint = type %d host %q port %d", request.addressType, request.host, request.port)
	}
	if _, err := readSOCKSRequest(bytes.NewReader(ipv4SOCKSRequest(
		socksCommandConnect,
		net.IPv4zero,
		0,
	))); err == nil {
		t.Fatal("CONNECT with port zero was accepted")
	}
}

func ipv6SOCKSRequest(command byte, ip net.IP, port uint16) []byte {
	request := []byte{socksVersion, command, 0, socksAddressIPv6}
	request = append(request, ip.To16()...)
	return binary.BigEndian.AppendUint16(request, port)
}

func FuzzParseSOCKSUDPDatagram(f *testing.F) {
	seed, _ := buildSOCKSUDPDatagram([]byte("payload"), "example.com:53")
	f.Add(seed)
	f.Add([]byte{0, 0, 0, socksAddressIPv4, 127, 0, 0, 1, 0, 53})
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, _, _ = parseSOCKSUDPDatagram(packet)
	})
}

type testPacketDialer struct {
	transport.Dialer
	dialPacket func(context.Context) (transport.PacketConn, error)
}

func (d testPacketDialer) DialPacket(ctx context.Context) (transport.PacketConn, error) {
	return d.dialPacket(ctx)
}

type directPacketConn struct {
	*net.UDPConn
}

func (c *directPacketConn) Send(payload []byte, address string) error {
	target, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return err
	}
	_, err = c.WriteToUDP(payload, target)
	return err
}

func (c *directPacketConn) Receive() ([]byte, string, error) {
	buffer := make([]byte, maxUDPDatagramSize)
	n, source, err := c.ReadFromUDP(buffer)
	if err != nil {
		return nil, "", err
	}
	return buffer[:n], source.String(), nil
}

type packetRecord struct {
	payload []byte
	address string
}

type recordingPacketConn struct {
	sends    chan packetRecord
	incoming chan packetRecord
	closed   chan struct{}
	once     sync.Once
}

type limitedPacketConn struct {
	*recordingPacketConn
	limit int
}

type queueFullOncePacketConn struct {
	*recordingPacketConn
	attempts      atomic.Int64
	firstRejected chan struct{}
}

func (c *queueFullOncePacketConn) Send(payload []byte, address string) error {
	if c.attempts.Add(1) == 1 {
		close(c.firstRejected)
		return transport.ErrPacketQueueFull
	}
	return c.recordingPacketConn.Send(payload, address)
}

func (c *limitedPacketConn) MaxPayloadSize() int { return c.limit }

func newRecordingPacketConn() *recordingPacketConn {
	return &recordingPacketConn{
		sends:    make(chan packetRecord, 8),
		incoming: make(chan packetRecord, 8),
		closed:   make(chan struct{}),
	}
}

func (c *recordingPacketConn) Send(payload []byte, address string) error {
	record := packetRecord{payload: append([]byte(nil), payload...), address: address}
	select {
	case c.sends <- record:
		return nil
	case <-c.closed:
		return net.ErrClosed
	}
}

func (c *recordingPacketConn) Receive() ([]byte, string, error) {
	select {
	case packet := <-c.incoming:
		return append([]byte(nil), packet.payload...), packet.address, nil
	case <-c.closed:
		return nil, "", net.ErrClosed
	}
}

func (c *recordingPacketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func startUDPEcho(t *testing.T) (string, func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, maxUDPDatagramSize)
		for {
			n, source, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buffer[:n], source)
		}
	}()
	return conn.LocalAddr().String(), func() {
		_ = conn.Close()
		<-done
	}
}

func ipv4SOCKSRequest(command byte, ip net.IP, port uint16) []byte {
	request := []byte{socksVersion, command, 0, socksAddressIPv4}
	request = append(request, ip.To4()...)
	return append(request, byte(port>>8), byte(port))
}

func readSOCKSReplyAddress(t *testing.T, reader io.Reader) (byte, *net.UDPAddr) {
	t.Helper()
	buffered, ok := reader.(*bufio.Reader)
	if !ok {
		buffered = bufio.NewReader(reader)
	}
	header := make([]byte, 4)
	mustReadFull(t, buffered, header)
	if header[0] != socksVersion || header[2] != 0 {
		t.Fatalf("invalid SOCKS reply header %v", header)
	}
	host, err := readSOCKSHost(buffered, header[3])
	if err != nil {
		t.Fatal(err)
	}
	portBytes := make([]byte, 2)
	mustReadFull(t, buffered, portBytes)
	port := int(portBytes[0])<<8 | int(portBytes[1])
	return header[1], &net.UDPAddr{IP: net.ParseIP(host), Port: port}
}

func assertNoPacketSend(t *testing.T, sends <-chan packetRecord) {
	t.Helper()
	select {
	case packet := <-sends:
		t.Fatalf("unexpected upstream packet %#v", packet)
	case <-time.After(50 * time.Millisecond):
	}
}
