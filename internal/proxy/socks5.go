package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

const (
	socksVersion = 5

	socksMethodNoAuth       = 0x00
	socksMethodUserPassword = 0x02
	socksMethodNone         = 0xff

	socksCommandConnect = 0x01
	socksCommandBind    = 0x02
	socksCommandUDP     = 0x03

	socksAddressIPv4   = 0x01
	socksAddressDomain = 0x03
	socksAddressIPv6   = 0x04

	socksReplySucceeded          = 0x00
	socksReplyGeneralFailure     = 0x01
	socksReplyNotAllowed         = 0x02
	socksReplyNetworkUnreachable = 0x03
	socksReplyHostUnreachable    = 0x04
	socksReplyConnectionRefused  = 0x05
	socksReplyTTLExpired         = 0x06
	socksReplyCommandUnsupported = 0x07
	socksReplyAddressUnsupported = 0x08

	userPasswordVersion = 0x01

	maxUDPDatagramSize = 65507
)

var errSOCKSUDPFragmented = errors.New("socks5: fragmented UDP datagram")

// SOCKS5Server is an RFC 1928 CONNECT and, when the configured transport also
// implements transport.PacketDialer, UDP ASSOCIATE proxy. BIND is unsupported.
type SOCKS5Server struct {
	cfg       serverConfig
	lifecycle *serverLifecycle
}

// NewSOCKS5Server validates cfg and creates a SOCKS5 server.
func NewSOCKS5Server(cfg Config) (*SOCKS5Server, error) {
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &SOCKS5Server{
		cfg:       normalized,
		lifecycle: newServerLifecycle(normalized.maxConnections),
	}, nil
}

// Serve accepts connections until listener is closed or Shutdown is called.
func (s *SOCKS5Server) Serve(listener net.Listener) error {
	managed, err := s.lifecycle.manage(listener)
	if err != nil {
		return err
	}
	for {
		conn, acceptErr := managed.Accept()
		if acceptErr != nil {
			if errors.Is(acceptErr, net.ErrClosed) {
				return nil
			}
			return acceptErr
		}
		go s.serveConn(conn)
	}
}

// Shutdown stops accepting new clients and waits for active proxied
// connections. When ctx expires, remaining connections are forcibly closed.
func (s *SOCKS5Server) Shutdown(ctx context.Context) error {
	return s.lifecycle.shutdown(ctx)
}

func (s *SOCKS5Server) serveConn(client net.Conn) {
	defer client.Close()
	if s.cfg.handshakeTimeout > 0 {
		_ = client.SetDeadline(time.Now().Add(s.cfg.handshakeTimeout))
	}

	if err := s.negotiate(client); err != nil {
		return
	}
	request, err := readSOCKSRequest(client)
	if err != nil {
		var protocolErr *socksProtocolError
		if errors.As(err, &protocolErr) {
			_ = writeSOCKSReply(client, protocolErr.reply, nil)
		}
		return
	}
	if request.command == socksCommandBind {
		_ = writeSOCKSReply(client, socksReplyCommandUnsupported, nil)
		return
	}
	if request.command == socksCommandUDP && s.cfg.packetDialer == nil {
		_ = writeSOCKSReply(client, socksReplyCommandUnsupported, nil)
		return
	}
	if request.command != socksCommandConnect && request.command != socksCommandUDP {
		_ = writeSOCKSReply(client, socksReplyCommandUnsupported, nil)
		return
	}
	// The slow-client deadline has served its purpose once the full request is
	// parsed. Remote dialing has its own timeout and must not accidentally be
	// shortened by the handshake deadline.
	_ = client.SetDeadline(time.Time{})
	if request.command == socksCommandUDP {
		s.serveUDPAssociate(client, request)
		return
	}
	s.serveConnect(client, request)
}

func (s *SOCKS5Server) serveConnect(client net.Conn, request socksRequest) {
	ctx := context.Background()
	cancel := func() {}
	if s.cfg.dialTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, s.cfg.dialTimeout)
	}
	upstream, err := s.cfg.dialer.DialContext(ctx, "tcp", request.address)
	cancel()
	if s.cfg.handshakeTimeout > 0 {
		_ = client.SetWriteDeadline(time.Now().Add(s.cfg.handshakeTimeout))
	}
	if err != nil {
		_ = writeSOCKSReply(client, socksReplyForError(err), nil)
		return
	}
	defer upstream.Close()
	// The tunnel Dialer exposes the ingress-to-relay socket address, not the
	// exit node's actual outbound bind address. RFC 1928 permits an unspecified
	// BND.ADDR when it is unknown; returning the relay socket would be
	// misleading and can break clients that inspect it.
	if err := writeSOCKSReply(client, socksReplySucceeded, nil); err != nil {
		return
	}
	_ = client.SetWriteDeadline(time.Time{})
	_ = relay(client, upstream, s.cfg.idleTimeout)
}

func (s *SOCKS5Server) serveUDPAssociate(client net.Conn, request socksRequest) {
	ctx := context.Background()
	cancel := func() {}
	if s.cfg.dialTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, s.cfg.dialTimeout)
	}
	defer cancel()

	peerIP, err := addressIP(client.RemoteAddr())
	if err != nil {
		_ = writeSOCKSReply(client, socksReplyGeneralFailure, nil)
		return
	}
	requestedPort, err := validateUDPAssociateRequest(ctx, request, peerIP, net.DefaultResolver.LookupIPAddr)
	if err != nil {
		reply := byte(socksReplyGeneralFailure)
		var protocolErr *socksProtocolError
		if errors.As(err, &protocolErr) {
			reply = protocolErr.reply
		}
		_ = writeSOCKSReply(client, reply, nil)
		return
	}

	udpConn, err := listenSOCKSUDP(client)
	if err != nil {
		_ = writeSOCKSReply(client, socksReplyGeneralFailure, nil)
		return
	}
	defer udpConn.Close()

	upstream, err := s.cfg.packetDialer.DialPacket(ctx)
	if err != nil || upstream == nil {
		if err == nil {
			err = errors.New("socks5: packet dialer returned a nil connection")
		}
		_ = writeSOCKSReply(client, socksReplyForError(err), nil)
		return
	}
	upstream = &closeOncePacketConn{PacketConn: upstream}
	defer upstream.Close()
	cancel()

	if s.cfg.handshakeTimeout > 0 {
		_ = client.SetWriteDeadline(time.Now().Add(s.cfg.handshakeTimeout))
	}
	if err := writeSOCKSReply(client, socksReplySucceeded, udpConn.LocalAddr()); err != nil {
		return
	}
	_ = client.SetWriteDeadline(time.Time{})

	endpoint := &socksUDPClientEndpoint{
		peerIP:        peerIP,
		requestedPort: requestedPort,
	}
	runSOCKSUDPAssociation(client, udpConn, upstream, endpoint, s.cfg.idleTimeout)
}

type lookupIPFunc func(context.Context, string) ([]net.IPAddr, error)

// validateUDPAssociateRequest applies the RFC 1928 meaning of DST.ADDR and
// DST.PORT: they describe the endpoint from which the client expects to send
// UDP packets. An unspecified address selects the TCP control connection's
// peer. A concrete IP, or the resolved address set for a domain, is accepted
// only when it includes that same peer. The data path independently checks the
// actual packet source and pins a zero port on the first valid datagram.
func validateUDPAssociateRequest(
	ctx context.Context,
	request socksRequest,
	peerIP net.IP,
	lookupIP lookupIPFunc,
) (int, error) {
	if peerIP == nil {
		return 0, &socksProtocolError{
			reply: socksReplyGeneralFailure,
			err:   errors.New("socks5: missing UDP control peer IP"),
		}
	}

	switch request.addressType {
	case socksAddressIPv4, socksAddressIPv6:
		requestedIP := net.ParseIP(request.host)
		if requestedIP == nil {
			return 0, &socksProtocolError{
				reply: socksReplyAddressUnsupported,
				err:   errors.New("socks5: invalid UDP associate IP"),
			}
		}
		if !requestedIP.IsUnspecified() && !requestedIP.Equal(peerIP) {
			return 0, &socksProtocolError{
				reply: socksReplyNotAllowed,
				err:   errors.New("socks5: UDP associate address does not match the control peer"),
			}
		}
	case socksAddressDomain:
		if lookupIP == nil {
			return 0, &socksProtocolError{
				reply: socksReplyHostUnreachable,
				err:   errors.New("socks5: no resolver for UDP associate domain"),
			}
		}
		addresses, err := lookupIP(ctx, request.host)
		if err != nil {
			return 0, &socksProtocolError{
				reply: socksReplyHostUnreachable,
				err:   fmt.Errorf("socks5: resolve UDP associate domain: %w", err),
			}
		}
		matched := false
		for _, address := range addresses {
			if address.IP.Equal(peerIP) {
				matched = true
				break
			}
		}
		if !matched {
			return 0, &socksProtocolError{
				reply: socksReplyNotAllowed,
				err:   errors.New("socks5: UDP associate domain does not resolve to the control peer"),
			}
		}
	default:
		return 0, &socksProtocolError{
			reply: socksReplyAddressUnsupported,
			err:   errors.New("socks5: unsupported UDP associate address type"),
		}
	}
	return int(request.port), nil
}

func listenSOCKSUDP(client net.Conn) (*net.UDPConn, error) {
	localIP, err := addressIP(client.LocalAddr())
	if err != nil {
		return nil, err
	}
	if ip4 := localIP.To4(); ip4 != nil {
		return net.ListenUDP("udp4", &net.UDPAddr{IP: ip4})
	}
	ip16 := localIP.To16()
	if ip16 == nil {
		return nil, errors.New("socks5: TCP listener has no IP address")
	}
	return net.ListenUDP("udp6", &net.UDPAddr{IP: ip16})
}

func addressIP(address net.Addr) (net.IP, error) {
	switch value := address.(type) {
	case *net.TCPAddr:
		if value.IP != nil {
			return append(net.IP(nil), value.IP...), nil
		}
	case *net.UDPAddr:
		if value.IP != nil {
			return append(net.IP(nil), value.IP...), nil
		}
	}
	if address == nil {
		return nil, errors.New("socks5: missing socket address")
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, errors.New("socks5: socket address is not an IP address")
	}
	return ip, nil
}

type socksUDPClientEndpoint struct {
	mu            sync.RWMutex
	peerIP        net.IP
	requestedPort int
	address       *net.UDPAddr
}

type closeOncePacketConn struct {
	transport.PacketConn
	once sync.Once
	err  error
}

func (c *closeOncePacketConn) Close() error {
	c.once.Do(func() { c.err = c.PacketConn.Close() })
	return c.err
}

func (c *closeOncePacketConn) MaxPayloadSize() int {
	if sized, ok := c.PacketConn.(transport.PacketPayloadSizer); ok {
		return sized.MaxPayloadSize()
	}
	return 0
}

// accept records the first valid source port when the UDP ASSOCIATE request
// specified port zero. Every datagram must originate from the control TCP
// connection's peer IP, preventing the relay from becoming an open UDP proxy.
func (e *socksUDPClientEndpoint) accept(address *net.UDPAddr) bool {
	if address == nil || !address.IP.Equal(e.peerIP) {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.requestedPort != 0 && address.Port != e.requestedPort {
		return false
	}
	if e.address == nil {
		e.address = &net.UDPAddr{
			IP:   append(net.IP(nil), address.IP...),
			Port: address.Port,
			Zone: address.Zone,
		}
		return true
	}
	return address.Port == e.address.Port && address.Zone == e.address.Zone
}

func (e *socksUDPClientEndpoint) current() *net.UDPAddr {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.address == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   append(net.IP(nil), e.address.IP...),
		Port: e.address.Port,
		Zone: e.address.Zone,
	}
}

func runSOCKSUDPAssociation(
	control net.Conn,
	local *net.UDPConn,
	upstream transport.PacketConn,
	endpoint *socksUDPClientEndpoint,
	idleTimeout time.Duration,
) {
	maxPayloadSize := maxUDPDatagramSize
	if sized, ok := upstream.(transport.PacketPayloadSizer); ok {
		if limit := sized.MaxPayloadSize(); limit > 0 && limit < maxPayloadSize {
			maxPayloadSize = limit
		}
	}
	finished := make(chan struct{}, 3)
	activity := make(chan struct{}, 1)
	signalActivity := func() {
		select {
		case activity <- struct{}{}:
		default:
		}
	}
	finish := func() { finished <- struct{}{} }

	go func() {
		defer finish()
		// One extra byte lets us detect and drop oversized IPv6 UDP payloads
		// instead of forwarding a silently truncated 65,507-byte prefix.
		buffer := make([]byte, maxUDPDatagramSize+1)
		for {
			n, source, err := local.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			payload, target, err := parseSOCKSUDPDatagram(buffer[:n])
			if err != nil || len(payload) > maxPayloadSize || !endpoint.accept(source) {
				continue
			}
			if err := upstream.Send(payload, target); err != nil {
				if errors.Is(err, transport.ErrPacketQueueFull) {
					// QUIC DATAGRAM is unreliable. Local queue pressure drops this
					// packet, not the authenticated UDP association.
					signalActivity()
					continue
				}
				return
			}
			signalActivity()
		}
	}()

	go func() {
		defer finish()
		for {
			payload, source, err := upstream.Receive()
			if err != nil {
				return
			}
			clientAddress := endpoint.current()
			if clientAddress == nil {
				// An unsolicited upstream packet cannot be routed safely before
				// the client's source endpoint has been validated.
				continue
			}
			packet, err := buildSOCKSUDPDatagram(payload, source)
			if err != nil {
				continue
			}
			if _, err := local.WriteToUDP(packet, clientAddress); err != nil {
				return
			}
			signalActivity()
		}
	}()

	go func() {
		defer finish()
		buffer := make([]byte, 1)
		for {
			if _, err := control.Read(buffer); err != nil {
				return
			}
		}
	}()

	var timer *time.Timer
	var idle <-chan time.Time
	if idleTimeout > 0 {
		timer = time.NewTimer(idleTimeout)
		idle = timer.C
		defer timer.Stop()
	}
	completed := 0
wait:
	for {
		select {
		case <-finished:
			completed++
			break wait
		case <-activity:
			if timer != nil {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(idleTimeout)
			}
		case <-idle:
			break wait
		}
	}

	// Closing both packet endpoints interrupts their blocking reads. A read
	// deadline interrupts the control watcher without removing the connection
	// from lifecycle tracking before all association goroutines have exited.
	_ = local.Close()
	_ = upstream.Close()
	_ = control.SetReadDeadline(time.Now())
	for completed < 3 {
		<-finished
		completed++
	}
}

func (s *SOCKS5Server) negotiate(conn net.Conn) error {
	methods, err := readSOCKSGreeting(conn)
	if err != nil {
		return err
	}
	wanted := byte(socksMethodNoAuth)
	if s.cfg.authenticator != nil {
		wanted = socksMethodUserPassword
	}
	if !containsByte(methods, wanted) {
		_ = writeFull(conn, []byte{socksVersion, socksMethodNone})
		return errors.New("socks5: no acceptable authentication method")
	}
	if err := writeFull(conn, []byte{socksVersion, wanted}); err != nil {
		return err
	}
	if wanted == socksMethodNoAuth {
		return nil
	}
	username, password, err := readUserPasswordRequest(conn)
	if err != nil {
		_ = writeFull(conn, []byte{userPasswordVersion, 0x01})
		return err
	}
	ctx := context.Background()
	if s.cfg.handshakeTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.cfg.handshakeTimeout)
		defer cancel()
	}
	if !s.cfg.authenticator.Authenticate(ctx, username, password) {
		_ = writeFull(conn, []byte{userPasswordVersion, 0x01})
		return errors.New("socks5: authentication failed")
	}
	return writeFull(conn, []byte{userPasswordVersion, 0x00})
}

func readSOCKSGreeting(r io.Reader) ([]byte, error) {
	header := [2]byte{}
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	if header[0] != socksVersion {
		return nil, fmt.Errorf("socks5: unsupported version %d", header[0])
	}
	if header[1] == 0 {
		return nil, errors.New("socks5: empty authentication method list")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(r, methods); err != nil {
		return nil, err
	}
	return methods, nil
}

func readUserPasswordRequest(r io.Reader) (string, string, error) {
	header := [2]byte{}
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return "", "", err
	}
	if header[0] != userPasswordVersion {
		return "", "", fmt.Errorf("socks5: unsupported username/password version %d", header[0])
	}
	if header[1] == 0 {
		return "", "", errors.New("socks5: empty username")
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(r, username); err != nil {
		return "", "", err
	}
	passwordLength := [1]byte{}
	if _, err := io.ReadFull(r, passwordLength[:]); err != nil {
		return "", "", err
	}
	if passwordLength[0] == 0 {
		return "", "", errors.New("socks5: empty password")
	}
	password := make([]byte, int(passwordLength[0]))
	if _, err := io.ReadFull(r, password); err != nil {
		return "", "", err
	}
	return string(username), string(password), nil
}

type socksRequest struct {
	command     byte
	addressType byte
	host        string
	port        uint16
	address     string
}

type socksProtocolError struct {
	reply byte
	err   error
}

func (e *socksProtocolError) Error() string { return e.err.Error() }
func (e *socksProtocolError) Unwrap() error { return e.err }

func readSOCKSRequest(r io.Reader) (socksRequest, error) {
	header := [4]byte{}
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return socksRequest{}, err
	}
	if header[0] != socksVersion {
		return socksRequest{}, &socksProtocolError{
			reply: socksReplyGeneralFailure,
			err:   fmt.Errorf("socks5: unsupported request version %d", header[0]),
		}
	}
	if header[2] != 0 {
		return socksRequest{}, &socksProtocolError{
			reply: socksReplyGeneralFailure,
			err:   errors.New("socks5: nonzero reserved byte"),
		}
	}

	host, err := readSOCKSHost(r, header[3])
	if err != nil {
		return socksRequest{}, err
	}
	portBytes := [2]byte{}
	if _, err := io.ReadFull(r, portBytes[:]); err != nil {
		return socksRequest{}, err
	}
	port := binary.BigEndian.Uint16(portBytes[:])
	if port == 0 && header[1] != socksCommandUDP {
		return socksRequest{}, &socksProtocolError{
			reply: socksReplyAddressUnsupported,
			err:   errors.New("socks5: zero destination port"),
		}
	}
	return socksRequest{
		command:     header[1],
		addressType: header[3],
		host:        host,
		port:        port,
		address:     net.JoinHostPort(host, fmt.Sprintf("%d", port)),
	}, nil
}

func readSOCKSHost(r io.Reader, addressType byte) (string, error) {
	switch addressType {
	case socksAddressIPv4:
		buffer := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(r, buffer); err != nil {
			return "", err
		}
		return net.IP(buffer).String(), nil
	case socksAddressIPv6:
		buffer := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(r, buffer); err != nil {
			return "", err
		}
		return net.IP(buffer).String(), nil
	case socksAddressDomain:
		length := [1]byte{}
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return "", err
		}
		if length[0] == 0 {
			return "", &socksProtocolError{
				reply: socksReplyAddressUnsupported,
				err:   errors.New("socks5: empty destination host"),
			}
		}
		buffer := make([]byte, int(length[0]))
		if _, err := io.ReadFull(r, buffer); err != nil {
			return "", err
		}
		for _, b := range buffer {
			if b <= 0x20 || b == 0x7f {
				return "", &socksProtocolError{
					reply: socksReplyAddressUnsupported,
					err:   errors.New("socks5: invalid destination host"),
				}
			}
		}
		return string(buffer), nil
	default:
		return "", &socksProtocolError{
			reply: socksReplyAddressUnsupported,
			err:   fmt.Errorf("socks5: unsupported address type %d", addressType),
		}
	}
}

func parseSOCKSUDPDatagram(packet []byte) ([]byte, string, error) {
	if len(packet) > maxUDPDatagramSize {
		return nil, "", errors.New("socks5: UDP datagram exceeds maximum size")
	}
	if len(packet) < 4 {
		return nil, "", io.ErrUnexpectedEOF
	}
	if packet[0] != 0 || packet[1] != 0 {
		return nil, "", errors.New("socks5: nonzero UDP reserved field")
	}
	if packet[2] != 0 {
		return nil, "", errSOCKSUDPFragmented
	}

	reader := bytes.NewReader(packet[4:])
	host, err := readSOCKSHost(reader, packet[3])
	if err != nil {
		return nil, "", err
	}
	portBytes := [2]byte{}
	if _, err := io.ReadFull(reader, portBytes[:]); err != nil {
		return nil, "", err
	}
	port := binary.BigEndian.Uint16(portBytes[:])
	if port == 0 {
		return nil, "", errors.New("socks5: zero UDP destination port")
	}
	payloadOffset := len(packet) - reader.Len()
	return packet[payloadOffset:], net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func buildSOCKSUDPDatagram(payload []byte, address string) ([]byte, error) {
	host, portString, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("socks5: invalid UDP source port")
	}

	packet := make([]byte, 4, 4+net.IPv6len+2+len(payload))
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			packet[3] = socksAddressIPv4
			packet = append(packet, ip4...)
		} else {
			ip16 := ip.To16()
			if ip16 == nil {
				return nil, errors.New("socks5: invalid UDP source IP")
			}
			packet[3] = socksAddressIPv6
			packet = append(packet, ip16...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("socks5: invalid UDP source host length")
		}
		for _, value := range []byte(host) {
			if value <= 0x20 || value == 0x7f {
				return nil, errors.New("socks5: invalid UDP source host")
			}
		}
		packet[3] = socksAddressDomain
		packet = append(packet, byte(len(host)))
		packet = append(packet, host...)
	}
	packet = binary.BigEndian.AppendUint16(packet, uint16(port))
	if len(packet)+len(payload) > maxUDPDatagramSize {
		return nil, errors.New("socks5: UDP datagram exceeds maximum size")
	}
	packet = append(packet, payload...)
	return packet, nil
}

func writeSOCKSReply(w io.Writer, reply byte, address net.Addr) error {
	ip := net.IPv4zero
	port := 0
	if address != nil {
		if tcpAddress, ok := address.(*net.TCPAddr); ok {
			ip = tcpAddress.IP
			port = tcpAddress.Port
		} else if host, portString, err := net.SplitHostPort(address.String()); err == nil {
			if parsed := net.ParseIP(host); parsed != nil {
				ip = parsed
			}
			_, _ = fmt.Sscanf(portString, "%d", &port)
		}
	}

	var response []byte
	if ip4 := ip.To4(); ip4 != nil {
		response = make([]byte, 4+net.IPv4len+2)
		response[3] = socksAddressIPv4
		copy(response[4:], ip4)
	} else {
		ip16 := ip.To16()
		if ip16 == nil {
			ip16 = net.IPv6zero
		}
		response = make([]byte, 4+net.IPv6len+2)
		response[3] = socksAddressIPv6
		copy(response[4:], ip16)
	}
	response[0] = socksVersion
	response[1] = reply
	binary.BigEndian.PutUint16(response[len(response)-2:], uint16(port))
	return writeFull(w, response)
}

func writeFull(w io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := w.Write(payload)
		if written < 0 || written > len(payload) {
			return errors.New("proxy: invalid write count")
		}
		payload = payload[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func socksReplyForError(err error) byte {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return socksReplyConnectionRefused
	case errors.Is(err, syscall.ENETUNREACH):
		return socksReplyNetworkUnreachable
	case errors.Is(err, syscall.EHOSTUNREACH):
		return socksReplyHostUnreachable
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return socksReplyTTLExpired
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return socksReplyHostUnreachable
	}
	return socksReplyGeneralFailure
}

func containsByte(values []byte, wanted byte) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
