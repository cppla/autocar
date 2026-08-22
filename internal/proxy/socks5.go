package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"
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
)

// SOCKS5Server is an RFC 1928 CONNECT proxy. BIND and UDP ASSOCIATE receive a
// standards-compliant "command not supported" response.
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
	if request.command != socksCommandConnect {
		_ = writeSOCKSReply(client, socksReplyCommandUnsupported, nil)
		return
	}
	// The slow-client deadline has served its purpose once the full request is
	// parsed. Remote dialing has its own timeout and must not accidentally be
	// shortened by the handshake deadline.
	_ = client.SetDeadline(time.Time{})

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
	command byte
	address string
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
	if port == 0 {
		return socksRequest{}, &socksProtocolError{
			reply: socksReplyAddressUnsupported,
			err:   errors.New("socks5: zero destination port"),
		}
	}
	return socksRequest{
		command: header[1],
		address: net.JoinHostPort(host, fmt.Sprintf("%d", port)),
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
