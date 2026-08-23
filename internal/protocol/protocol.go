// Package protocol implements the small, bounded wire protocol used on every
// AutoCAR tunnel stream.
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
	// TCP+TLS transports. Version 2 is AutoCAR's native protocol and is not wire
	// compatible with Hysteria or with the original AutoCAR v1 format.
	ALPN = "autocar/2"

	Version = 2

	MinTokenLength   = 16
	MaxTokenLength   = 1024
	MaxAddressLength = 1024
	MaxMessageLength = 1024
	// MaxRate is a defensive wire bound in bytes per second. Configuration uses
	// a lower operational ceiling, but the parser must reject absurd peer input
	// before it reaches arithmetic in a sender.
	MaxRate = uint64(1_000_000_000_000)
)

const (
	magic        uint32 = 0x4155544f // "AUTO"
	headerSize          = 36
	kindConnect  byte   = 1
	kindResponse byte   = 2
)

// Network is the TCP network requested from the exit node.
type Network uint16

const (
	NetworkTCP  Network = 1
	NetworkTCP4 Network = 2
	NetworkTCP6 Network = 3
	// NetworkUDP opens a connection-scoped QUIC DATAGRAM association. Its
	// request has an empty address and a non-zero SessionID; each datagram names
	// and validates its own destination.
	NetworkUDP Network = 4
)

func (n Network) String() string {
	switch n {
	case NetworkTCP:
		return "tcp"
	case NetworkTCP4:
		return "tcp4"
	case NetworkTCP6:
		return "tcp6"
	case NetworkUDP:
		return "udp"
	default:
		return ""
	}
}

// PacingMode identifies the application-layer sender policy actually selected
// by an endpoint. It is diagnostic protocol state, not a claim about the
// underlying QUIC congestion controller.
type PacingMode byte

const (
	PacingUnspecified PacingMode = iota
	PacingAdaptive
	PacingReno
	PacingFixedRate
)

func (m PacingMode) valid() bool { return m <= PacingFixedRate }

// PacingProfile identifies the adaptive policy's gain/response profile.
type PacingProfile byte

const (
	ProfileUnspecified PacingProfile = iota
	ProfileConservative
	ProfileBalanced
	ProfileAggressive
)

func (p PacingProfile) valid() bool { return p <= ProfileAggressive }

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
	// MaxTx and MaxRx are optional fixed-rate hints in bytes per second. Zero
	// selects adaptive/baseline operation for that direction. The relay may
	// ignore or lower either value and reports the effective values in Response.
	MaxTx     uint64
	MaxRx     uint64
	SessionID uint32
	TxMode    PacingMode
	TxProfile PacingProfile
}

// Response reports whether the exit connection was established.
type Response struct {
	Status  Status
	Message string
	// MaxTx is the effective request-initiator -> responder rate. MaxRx is the
	// effective responder -> request-initiator rate. Both are zero unless
	// fixed-rate pacing was explicitly negotiated.
	MaxTx     uint64
	MaxRx     uint64
	SessionID uint32
	TxMode    PacingMode
	TxProfile PacingProfile
	RxMode    PacingMode
	RxProfile PacingProfile
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
	ErrBadRate       = errors.New("protocol: invalid rate")
	ErrBadSession    = errors.New("protocol: invalid session")
	ErrBadPacing     = errors.New("protocol: invalid pacing metadata")
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
	if req.MaxTx > MaxRate || req.MaxRx > MaxRate {
		return ErrBadRate
	}
	if !req.TxMode.valid() || !req.TxProfile.valid() {
		return ErrBadPacing
	}
	if req.Network == NetworkUDP {
		if req.Address != "" || req.SessionID == 0 {
			return ErrBadSession
		}
	} else {
		if req.SessionID != 0 {
			return ErrBadSession
		}
		if err := validateAddress(req.Address); err != nil {
			return err
		}
	}

	header := makeHeader(
		kindConnect, uint16(req.Network), len(req.Token), len(req.Address),
		req.MaxTx, req.MaxRx, req.SessionID,
		req.TxMode, req.TxProfile, PacingUnspecified, ProfileUnspecified,
	)
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
	if h.length1 < MinTokenLength || h.length1 > MaxTokenLength || h.length2 > MaxAddressLength {
		return Request{}, ErrInvalidLength
	}
	if h.value1 > MaxRate || h.value2 > MaxRate {
		return Request{}, ErrBadRate
	}
	if !h.txMode.valid() || !h.txProfile.valid() ||
		h.rxMode != PacingUnspecified || h.rxProfile != ProfileUnspecified {
		return Request{}, ErrBadPacing
	}
	if network == NetworkUDP {
		if h.length2 != 0 || h.sessionID == 0 {
			return Request{}, ErrBadSession
		}
	} else if h.length2 == 0 || h.sessionID != 0 {
		return Request{}, ErrBadSession
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
	if network != NetworkUDP {
		if err := validateAddress(address); err != nil {
			return Request{}, err
		}
	}
	return Request{
		Network: network, Token: token, Address: address,
		MaxTx: h.value1, MaxRx: h.value2, SessionID: h.sessionID,
		TxMode: h.txMode, TxProfile: h.txProfile,
	}, nil
}

// WriteResponse writes a complete response.
func WriteResponse(w io.Writer, response Response) error {
	if !response.Status.valid() {
		return ErrBadStatus
	}
	if len(response.Message) > MaxMessageLength || containsNUL([]byte(response.Message)) {
		return ErrInvalidLength
	}
	if response.MaxTx > MaxRate || response.MaxRx > MaxRate {
		return ErrBadRate
	}
	if !response.TxMode.valid() || !response.TxProfile.valid() ||
		!response.RxMode.valid() || !response.RxProfile.valid() {
		return ErrBadPacing
	}
	if response.SessionID != 0 && response.Status != StatusOK {
		return ErrBadSession
	}
	header := makeHeader(
		kindResponse, uint16(response.Status), len(response.Message), 0,
		response.MaxTx, response.MaxRx, response.SessionID,
		response.TxMode, response.TxProfile, response.RxMode, response.RxProfile,
	)
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
	if h.value1 > MaxRate || h.value2 > MaxRate {
		return Response{}, ErrBadRate
	}
	if !h.txMode.valid() || !h.txProfile.valid() ||
		!h.rxMode.valid() || !h.rxProfile.valid() {
		return Response{}, ErrBadPacing
	}
	if h.sessionID != 0 && status != StatusOK {
		return Response{}, ErrBadSession
	}
	return Response{
		Status: status, Message: string(message),
		MaxTx: h.value1, MaxRx: h.value2, SessionID: h.sessionID,
		TxMode: h.txMode, TxProfile: h.txProfile,
		RxMode: h.rxMode, RxProfile: h.rxProfile,
	}, nil
}

type header struct {
	flags     uint16
	length1   int
	length2   int
	value1    uint64
	value2    uint64
	sessionID uint32
	txMode    PacingMode
	txProfile PacingProfile
	rxMode    PacingMode
	rxProfile PacingProfile
}

func makeHeader(
	kind byte,
	flags uint16,
	length1, length2 int,
	value1, value2 uint64,
	sessionID uint32,
	txMode PacingMode,
	txProfile PacingProfile,
	rxMode PacingMode,
	rxProfile PacingProfile,
) [headerSize]byte {
	var h [headerSize]byte
	binary.BigEndian.PutUint32(h[0:4], magic)
	h[4] = Version
	h[5] = kind
	binary.BigEndian.PutUint16(h[6:8], flags)
	binary.BigEndian.PutUint16(h[8:10], uint16(length1))
	binary.BigEndian.PutUint16(h[10:12], uint16(length2))
	binary.BigEndian.PutUint64(h[12:20], value1)
	binary.BigEndian.PutUint64(h[20:28], value2)
	binary.BigEndian.PutUint32(h[28:32], sessionID)
	h[32] = byte(txMode)
	h[33] = byte(txProfile)
	h[34] = byte(rxMode)
	h[35] = byte(rxProfile)
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
		flags:     binary.BigEndian.Uint16(raw[6:8]),
		length1:   int(binary.BigEndian.Uint16(raw[8:10])),
		length2:   int(binary.BigEndian.Uint16(raw[10:12])),
		value1:    binary.BigEndian.Uint64(raw[12:20]),
		value2:    binary.BigEndian.Uint64(raw[20:28]),
		sessionID: binary.BigEndian.Uint32(raw[28:32]),
		txMode:    PacingMode(raw[32]),
		txProfile: PacingProfile(raw[33]),
		rxMode:    PacingMode(raw[34]),
		rxProfile: PacingProfile(raw[35]),
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
