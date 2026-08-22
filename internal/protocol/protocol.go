// Package protocol implements the small, bounded wire protocol used on every
// AutoCar tunnel stream.
//
// The protocol is deliberately boring: one CONNECT request, one response and
// then an unframed byte stream.  QUIC and TLS provide confidentiality,
// integrity, replay protection and framing; this package does not attempt to
// invent cryptography of its own.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	// ALPN is the TLS application protocol negotiated by both the QUIC and the
	// TCP+TLS transports. Changing the wire format requires a new ALPN.
	ALPN = "autocar/1"

	Version = 1

	MinTokenLength   = 16
	MaxTokenLength   = 1024
	MaxAddressLength = 1024
	MaxMessageLength = 1024
)

const (
	magic        uint32 = 0x4155544f // "AUTO"
	headerSize          = 12
	kindConnect  byte   = 1
	kindResponse byte   = 2
)

// Network is the TCP network requested from the exit node.
type Network uint16

const (
	NetworkTCP  Network = 1
	NetworkTCP4 Network = 2
	NetworkTCP6 Network = 3
)

func (n Network) String() string {
	switch n {
	case NetworkTCP:
		return "tcp"
	case NetworkTCP4:
		return "tcp4"
	case NetworkTCP6:
		return "tcp6"
	default:
		return ""
	}
}

// ParseNetwork converts a net.Dial-compatible TCP network to its wire value.
func ParseNetwork(network string) (Network, error) {
	switch network {
	case "tcp":
		return NetworkTCP, nil
	case "tcp4":
		return NetworkTCP4, nil
	case "tcp6":
		return NetworkTCP6, nil
	default:
		return 0, fmt.Errorf("protocol: unsupported network %q", network)
	}
}

// Status is returned before a stream switches to raw byte relay mode.
type Status uint16

const (
	StatusOK           Status = 0
	StatusBadRequest   Status = 1
	StatusUnauthorized Status = 2
	StatusDialFailed   Status = 3
	StatusBusy         Status = 4
	StatusInternal     Status = 5
)

func (s Status) valid() bool {
	return s <= StatusInternal
}

// Request asks the exit node to establish one TCP connection.
type Request struct {
	Network Network
	Token   []byte
	Address string
}

// Response reports whether the exit connection was established.
type Response struct {
	Status  Status
	Message string
}

var (
	ErrBadMagic      = errors.New("protocol: bad magic")
	ErrBadVersion    = errors.New("protocol: unsupported version")
	ErrBadKind       = errors.New("protocol: unexpected message kind")
	ErrBadReserved   = errors.New("protocol: reserved field is non-zero")
	ErrInvalidLength = errors.New("protocol: invalid field length")
	ErrBadNetwork    = errors.New("protocol: invalid network")
	ErrBadStatus     = errors.New("protocol: invalid response status")
	ErrBadAddress    = errors.New("protocol: invalid address")
)

// WriteRequest writes a complete request. It never writes a partially
// validated request.
func WriteRequest(w io.Writer, req Request) error {
	if req.Network.String() == "" {
		return ErrBadNetwork
	}
	if err := validateToken(req.Token); err != nil {
		return err
	}
	if err := validateAddress(req.Address); err != nil {
		return err
	}

	header := makeHeader(kindConnect, uint16(req.Network), len(req.Token), len(req.Address))
	return writeAll(w, header[:], req.Token, []byte(req.Address))
}

// ReadRequest reads and validates one complete request. All attacker-controlled
// lengths are checked before allocating.
func ReadRequest(r io.Reader) (Request, error) {
	h, err := readHeader(r, kindConnect)
	if err != nil {
		return Request{}, err
	}
	network := Network(h.flags)
	if network.String() == "" {
		return Request{}, ErrBadNetwork
	}
	if h.length1 < MinTokenLength || h.length1 > MaxTokenLength || h.length2 == 0 || h.length2 > MaxAddressLength {
		return Request{}, ErrInvalidLength
	}

	buf := make([]byte, h.length1+h.length2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return Request{}, fmt.Errorf("protocol: read request body: %w", err)
	}
	token := append([]byte(nil), buf[:h.length1]...)
	addressBytes := buf[h.length1:]
	if containsNUL(addressBytes) {
		return Request{}, ErrBadAddress
	}
	address := string(addressBytes)
	if err := validateAddress(address); err != nil {
		return Request{}, err
	}
	return Request{Network: network, Token: token, Address: address}, nil
}

// WriteResponse writes a complete response.
func WriteResponse(w io.Writer, response Response) error {
	if !response.Status.valid() {
		return ErrBadStatus
	}
	if len(response.Message) > MaxMessageLength || containsNUL([]byte(response.Message)) {
		return ErrInvalidLength
	}
	header := makeHeader(kindResponse, uint16(response.Status), len(response.Message), 0)
	return writeAll(w, header[:], []byte(response.Message))
}

// ReadResponse reads and validates one complete response.
func ReadResponse(r io.Reader) (Response, error) {
	h, err := readHeader(r, kindResponse)
	if err != nil {
		return Response{}, err
	}
	status := Status(h.flags)
	if !status.valid() {
		return Response{}, ErrBadStatus
	}
	if h.length1 > MaxMessageLength {
		return Response{}, ErrInvalidLength
	}
	if h.length2 != 0 {
		return Response{}, ErrBadReserved
	}
	message := make([]byte, h.length1)
	if _, err := io.ReadFull(r, message); err != nil {
		return Response{}, fmt.Errorf("protocol: read response body: %w", err)
	}
	if containsNUL(message) {
		return Response{}, ErrInvalidLength
	}
	return Response{Status: status, Message: string(message)}, nil
}

type header struct {
	flags   uint16
	length1 int
	length2 int
}

func makeHeader(kind byte, flags uint16, length1, length2 int) [headerSize]byte {
	var h [headerSize]byte
	binary.BigEndian.PutUint32(h[0:4], magic)
	h[4] = Version
	h[5] = kind
	binary.BigEndian.PutUint16(h[6:8], flags)
	binary.BigEndian.PutUint16(h[8:10], uint16(length1))
	binary.BigEndian.PutUint16(h[10:12], uint16(length2))
	return h
}

func readHeader(r io.Reader, wantKind byte) (header, error) {
	var raw [headerSize]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return header{}, fmt.Errorf("protocol: read header: %w", err)
	}
	if binary.BigEndian.Uint32(raw[0:4]) != magic {
		return header{}, ErrBadMagic
	}
	if raw[4] != Version {
		return header{}, ErrBadVersion
	}
	if raw[5] != wantKind {
		return header{}, ErrBadKind
	}
	return header{
		flags:   binary.BigEndian.Uint16(raw[6:8]),
		length1: int(binary.BigEndian.Uint16(raw[8:10])),
		length2: int(binary.BigEndian.Uint16(raw[10:12])),
	}, nil
}

func validateToken(token []byte) error {
	if len(token) < MinTokenLength || len(token) > MaxTokenLength {
		return ErrInvalidLength
	}
	return nil
}

func validateAddress(address string) error {
	if len(address) == 0 || len(address) > MaxAddressLength || containsNUL([]byte(address)) {
		return ErrBadAddress
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return ErrBadAddress
	}
	return nil
}

func containsNUL(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return true
		}
	}
	return false
}

func writeAll(w io.Writer, parts ...[]byte) error {
	for _, part := range parts {
		for len(part) > 0 {
			n, err := w.Write(part)
			if n > 0 {
				part = part[n:]
			}
			if err != nil {
				return fmt.Errorf("protocol: write message: %w", err)
			}
			if n == 0 {
				return io.ErrShortWrite
			}
		}
	}
	return nil
}
