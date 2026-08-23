// Package datagram implements AutoCAR's bounded QUIC DATAGRAM wire format.
//
// The format is intentionally independent from the stream protocol. Every
// fragment carries its address so that a fragment can never inherit routing
// metadata from an unrelated message.
package datagram

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cppla/autocar/internal/protocol"
)

const (
	// WireVersion identifies the first AutoCAR DATAGRAM format.
	WireVersion uint8 = 1

	// HeaderSize is the fixed wire header size. The header is followed by the
	// address bytes and then by the fragment payload.
	HeaderSize = 20

	// MaxPayloadSize is the largest logical UDP payload AutoCAR will accept.
	MaxPayloadSize = 4096

	// MaxFragments prevents a tiny frame budget from amplifying one logical
	// datagram into thousands of allocations. Normal QUIC path sizes need only
	// a handful of fragments for MaxPayloadSize.
	MaxFragments = 256

	// MinFrameSize is the smallest useful caller-provided frame budget: a
	// header, the shortest valid host:port ("a:1"), and one payload byte.
	MinFrameSize = HeaderSize + 4

	// MaxFrameSize is the largest useful frame. Larger budgets cannot encode
	// additional AutoCAR data and are rejected to keep parser memory bounded.
	MaxFrameSize = HeaderSize + protocol.MaxAddressLength + MaxPayloadSize
)

const (
	wireMagic uint32 = 0x41434447 // "ACDG"

	offsetVersion       = 4
	offsetFlags         = 5
	offsetSessionID     = 6
	offsetMessageID     = 10
	offsetFragmentIndex = 14
	offsetFragmentCount = 16
	offsetAddressLength = 18
)

// Flags describe properties that must be identical for all fragments of a
// message.
type Flags uint8

const (
	// FlagResponse marks the return direction. Without it, Address is the UDP
	// destination requested by the client. With it, Address is the remote
	// source reported by the exit. Keeping this bit in the reassembly identity
	// prevents simultaneous request and response message IDs from colliding.
	FlagResponse Flags = 1 << iota

	knownFlags = FlagResponse
)

// Message is one complete logical UDP datagram.
type Message struct {
	Flags     Flags
	SessionID uint32
	MessageID uint32
	Address   string
	Payload   []byte
}

// Fragment is one parsed wire fragment. Payload is owned by the Fragment and
// does not alias the input passed to Parse.
type Fragment struct {
	Flags         Flags
	SessionID     uint32
	MessageID     uint32
	FragmentIndex uint16
	FragmentCount uint16
	Address       string
	Payload       []byte
}

var (
	ErrBadMagic        = errors.New("datagram: bad magic")
	ErrBadVersion      = errors.New("datagram: unsupported version")
	ErrBadFlags        = errors.New("datagram: unsupported flags")
	ErrInvalidSession  = errors.New("datagram: session ID must be non-zero")
	ErrInvalidFragment = errors.New("datagram: invalid fragment metadata")
	ErrInvalidAddress  = errors.New("datagram: invalid address")
	ErrPayloadTooLarge = errors.New("datagram: logical payload is too large")
	ErrFrameSize       = errors.New("datagram: unsafe frame size")
)

// Encode validates message completely and splits it into frames no larger
// than maxFrameSize. Address is repeated in every frame by design.
func Encode(message Message, maxFrameSize int) ([][]byte, error) {
	if err := validateFlags(message.Flags); err != nil {
		return nil, err
	}
	if message.SessionID == 0 {
		return nil, ErrInvalidSession
	}
	if err := validateAddress(message.Address); err != nil {
		return nil, err
	}
	if len(message.Payload) > MaxPayloadSize {
		return nil, ErrPayloadTooLarge
	}
	if maxFrameSize < MinFrameSize || maxFrameSize > MaxFrameSize {
		return nil, ErrFrameSize
	}

	payloadPerFrame := maxFrameSize - HeaderSize - len(message.Address)
	if payloadPerFrame < 1 {
		return nil, ErrFrameSize
	}

	fragmentCount := 1
	if len(message.Payload) > 0 {
		fragmentCount = (len(message.Payload) + payloadPerFrame - 1) / payloadPerFrame
	}
	if fragmentCount > MaxFragments {
		return nil, ErrFrameSize
	}

	frames := make([][]byte, 0, fragmentCount)
	for index := 0; index < fragmentCount; index++ {
		start := index * payloadPerFrame
		end := start + payloadPerFrame
		if end > len(message.Payload) {
			end = len(message.Payload)
		}
		frames = append(frames, encodeFragment(message, uint16(index), uint16(fragmentCount), message.Payload[start:end]))
	}
	return frames, nil
}

func encodeFragment(message Message, index, count uint16, payload []byte) []byte {
	frame := make([]byte, HeaderSize+len(message.Address)+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], wireMagic)
	frame[offsetVersion] = WireVersion
	frame[offsetFlags] = byte(message.Flags)
	binary.BigEndian.PutUint32(frame[offsetSessionID:offsetMessageID], message.SessionID)
	binary.BigEndian.PutUint32(frame[offsetMessageID:offsetFragmentIndex], message.MessageID)
	binary.BigEndian.PutUint16(frame[offsetFragmentIndex:offsetFragmentCount], index)
	binary.BigEndian.PutUint16(frame[offsetFragmentCount:offsetAddressLength], count)
	binary.BigEndian.PutUint16(frame[offsetAddressLength:HeaderSize], uint16(len(message.Address)))
	copy(frame[HeaderSize:], message.Address)
	copy(frame[HeaderSize+len(message.Address):], payload)
	return frame
}

// Parse validates and copies one complete frame. Every attacker-controlled
// length and count is bounded before the address or payload is allocated.
func Parse(frame []byte) (Fragment, error) {
	if len(frame) < HeaderSize || len(frame) > MaxFrameSize {
		return Fragment{}, ErrFrameSize
	}
	if binary.BigEndian.Uint32(frame[0:4]) != wireMagic {
		return Fragment{}, ErrBadMagic
	}
	if frame[offsetVersion] != WireVersion {
		return Fragment{}, ErrBadVersion
	}
	flags := Flags(frame[offsetFlags])
	if err := validateFlags(flags); err != nil {
		return Fragment{}, err
	}

	sessionID := binary.BigEndian.Uint32(frame[offsetSessionID:offsetMessageID])
	if sessionID == 0 {
		return Fragment{}, ErrInvalidSession
	}
	messageID := binary.BigEndian.Uint32(frame[offsetMessageID:offsetFragmentIndex])
	fragmentIndex := binary.BigEndian.Uint16(frame[offsetFragmentIndex:offsetFragmentCount])
	fragmentCount := binary.BigEndian.Uint16(frame[offsetFragmentCount:offsetAddressLength])
	if fragmentCount == 0 || int(fragmentCount) > MaxFragments || fragmentIndex >= fragmentCount {
		return Fragment{}, ErrInvalidFragment
	}

	addressLength := int(binary.BigEndian.Uint16(frame[offsetAddressLength:HeaderSize]))
	if addressLength == 0 || addressLength > protocol.MaxAddressLength || addressLength > len(frame)-HeaderSize {
		return Fragment{}, ErrInvalidAddress
	}
	payloadLength := len(frame) - HeaderSize - addressLength
	if payloadLength > MaxPayloadSize {
		return Fragment{}, ErrPayloadTooLarge
	}
	if fragmentCount > 1 && payloadLength == 0 {
		return Fragment{}, ErrInvalidFragment
	}

	addressBytes := frame[HeaderSize : HeaderSize+addressLength]
	if bytes.IndexByte(addressBytes, 0) >= 0 || !utf8.Valid(addressBytes) {
		return Fragment{}, ErrInvalidAddress
	}
	address := string(addressBytes)
	if err := validateAddress(address); err != nil {
		return Fragment{}, err
	}

	payload := make([]byte, payloadLength)
	copy(payload, frame[HeaderSize+addressLength:])
	return Fragment{
		Flags:         flags,
		SessionID:     sessionID,
		MessageID:     messageID,
		FragmentIndex: fragmentIndex,
		FragmentCount: fragmentCount,
		Address:       address,
		Payload:       payload,
	}, nil
}

func validateFragment(fragment Fragment) error {
	if err := validateFlags(fragment.Flags); err != nil {
		return err
	}
	if fragment.SessionID == 0 {
		return ErrInvalidSession
	}
	if fragment.FragmentCount == 0 || int(fragment.FragmentCount) > MaxFragments || fragment.FragmentIndex >= fragment.FragmentCount {
		return ErrInvalidFragment
	}
	if fragment.FragmentCount > 1 && len(fragment.Payload) == 0 {
		return ErrInvalidFragment
	}
	if len(fragment.Payload) > MaxPayloadSize {
		return ErrPayloadTooLarge
	}
	return validateAddress(fragment.Address)
}

func validateFlags(flags Flags) error {
	if flags&^knownFlags != 0 {
		return ErrBadFlags
	}
	return nil
}

func validateAddress(address string) error {
	if len(address) == 0 || len(address) > protocol.MaxAddressLength || !utf8.ValidString(address) {
		return ErrInvalidAddress
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" || strings.ContainsAny(host, "/\\") {
		return ErrInvalidAddress
	}
	for _, r := range host {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return ErrInvalidAddress
		}
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return ErrInvalidAddress
	}
	return nil
}
