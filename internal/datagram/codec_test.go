package datagram

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/cppla/autocar/internal/protocol"
)

func TestEncodeParseRoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte("autocar"), 173)
	message := Message{
		Flags:     FlagResponse,
		SessionID: 17,
		MessageID: 0,
		Address:   "[2001:db8::1]:443",
		Payload:   payload,
	}
	maxFrameSize := HeaderSize + len(message.Address) + 79
	frames, err := Encode(message, maxFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) < 2 {
		t.Fatalf("expected fragmentation, got %d frame", len(frames))
	}

	var assembled []byte
	for index, frame := range frames {
		if len(frame) > maxFrameSize {
			t.Fatalf("frame %d has size %d, limit %d", index, len(frame), maxFrameSize)
		}
		fragment, err := Parse(frame)
		if err != nil {
			t.Fatalf("parse frame %d: %v", index, err)
		}
		if fragment.Flags != message.Flags || fragment.SessionID != message.SessionID || fragment.MessageID != message.MessageID {
			t.Fatalf("frame %d identity mismatch: %+v", index, fragment)
		}
		if fragment.FragmentIndex != uint16(index) || fragment.FragmentCount != uint16(len(frames)) {
			t.Fatalf("frame %d fragment metadata mismatch: %d/%d", index, fragment.FragmentIndex, fragment.FragmentCount)
		}
		if fragment.Address != message.Address {
			t.Fatalf("frame %d address = %q", index, fragment.Address)
		}
		assembled = append(assembled, fragment.Payload...)
	}
	if !bytes.Equal(assembled, payload) {
		t.Fatal("round-trip payload mismatch")
	}
}

func TestEncodeEmptyPayload(t *testing.T) {
	frames, err := Encode(Message{SessionID: 1, MessageID: 9, Address: "a:1"}, MinFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 {
		t.Fatalf("got %d frames", len(frames))
	}
	fragment, err := Parse(frames[0])
	if err != nil {
		t.Fatal(err)
	}
	if fragment.FragmentCount != 1 || fragment.FragmentIndex != 0 || len(fragment.Payload) != 0 {
		t.Fatalf("unexpected empty fragment: %+v", fragment)
	}
}

func TestEncodeMaximumBounds(t *testing.T) {
	address := strings.Repeat("a", protocol.MaxAddressLength-2) + ":1"
	payload := bytes.Repeat([]byte{0x5a}, MaxPayloadSize)
	frames, err := Encode(Message{SessionID: 1, Address: address, Payload: payload}, MaxFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 || len(frames[0]) != MaxFrameSize {
		t.Fatalf("maximum frame mismatch: count=%d size=%d", len(frames), len(frames[0]))
	}
	fragment, err := Parse(frames[0])
	if err != nil {
		t.Fatal(err)
	}
	if fragment.Address != address || !bytes.Equal(fragment.Payload, payload) {
		t.Fatal("maximum-sized message did not round trip")
	}
}

func TestParseOwnsPayload(t *testing.T) {
	frames, err := Encode(Message{SessionID: 1, Address: "a:1", Payload: []byte("payload")}, 128)
	if err != nil {
		t.Fatal(err)
	}
	fragment, err := Parse(frames[0])
	if err != nil {
		t.Fatal(err)
	}
	frames[0][len(frames[0])-1] ^= 0xff
	if string(fragment.Payload) != "payload" {
		t.Fatalf("parsed payload aliases input: %q", fragment.Payload)
	}
}

func TestEncodeValidation(t *testing.T) {
	valid := Message{SessionID: 1, MessageID: 2, Address: "example.com:443", Payload: []byte("x")}
	tests := []struct {
		name      string
		message   Message
		frameSize int
		want      error
	}{
		{name: "unknown flags", message: withMessage(valid, func(m *Message) { m.Flags = Flags(0x80) }), frameSize: 128, want: ErrBadFlags},
		{name: "zero session", message: withMessage(valid, func(m *Message) { m.SessionID = 0 }), frameSize: 128, want: ErrInvalidSession},
		{name: "large payload", message: withMessage(valid, func(m *Message) { m.Payload = make([]byte, MaxPayloadSize+1) }), frameSize: MaxFrameSize, want: ErrPayloadTooLarge},
		{name: "small frame", message: valid, frameSize: MinFrameSize - 1, want: ErrFrameSize},
		{name: "large frame", message: valid, frameSize: MaxFrameSize + 1, want: ErrFrameSize},
		{name: "no payload room", message: withMessage(valid, func(m *Message) { m.Address = strings.Repeat("a", 100) + ":1" }), frameSize: 64, want: ErrFrameSize},
		{name: "fragment amplification", message: withMessage(valid, func(m *Message) { m.Address = "a:1"; m.Payload = make([]byte, MaxPayloadSize) }), frameSize: MinFrameSize, want: ErrFrameSize},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Encode(test.message, test.frameSize)
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestAddressValidation(t *testing.T) {
	for _, address := range []string{"example.com:443", "127.0.0.1:53", "[2001:db8::1]:65535", "[fe80::1%eth0]:80"} {
		t.Run("valid_"+address, func(t *testing.T) {
			if _, err := Encode(Message{SessionID: 1, Address: address}, MaxFrameSize); err != nil {
				t.Fatalf("valid address rejected: %v", err)
			}
		})
	}

	invalid := []string{
		"", "example.com", ":80", "example.com:", "example.com:0",
		"example.com:65536", "example.com:http", "bad host:80", "bad/host:80",
		"a:\x00", strings.Repeat("a", protocol.MaxAddressLength) + ":1",
	}
	for _, address := range invalid {
		t.Run("invalid_"+address, func(t *testing.T) {
			_, err := Encode(Message{SessionID: 1, Address: address}, MaxFrameSize)
			if !errors.Is(err, ErrInvalidAddress) {
				t.Fatalf("address %q: got %v", address, err)
			}
		})
	}
}

func TestParseValidation(t *testing.T) {
	seedFrames, err := Encode(Message{SessionID: 7, MessageID: 8, Address: "a:1", Payload: []byte("x")}, 128)
	if err != nil {
		t.Fatal(err)
	}
	seed := seedFrames[0]

	tests := []struct {
		name   string
		mutate func([]byte) []byte
		want   error
	}{
		{name: "short", mutate: func(b []byte) []byte { return b[:HeaderSize-1] }, want: ErrFrameSize},
		{name: "large frame", mutate: func(b []byte) []byte { return append(b, make([]byte, MaxFrameSize+1-len(b))...) }, want: ErrFrameSize},
		{name: "magic", mutate: func(b []byte) []byte { b[0] ^= 1; return b }, want: ErrBadMagic},
		{name: "version", mutate: func(b []byte) []byte { b[offsetVersion]++; return b }, want: ErrBadVersion},
		{name: "flags", mutate: func(b []byte) []byte { b[offsetFlags] = 0x80; return b }, want: ErrBadFlags},
		{name: "session", mutate: func(b []byte) []byte { binary.BigEndian.PutUint32(b[offsetSessionID:offsetMessageID], 0); return b }, want: ErrInvalidSession},
		{name: "zero fragments", mutate: func(b []byte) []byte {
			binary.BigEndian.PutUint16(b[offsetFragmentCount:offsetAddressLength], 0)
			return b
		}, want: ErrInvalidFragment},
		{name: "too many fragments", mutate: func(b []byte) []byte {
			binary.BigEndian.PutUint16(b[offsetFragmentCount:offsetAddressLength], MaxFragments+1)
			return b
		}, want: ErrInvalidFragment},
		{name: "index outside count", mutate: func(b []byte) []byte {
			binary.BigEndian.PutUint16(b[offsetFragmentIndex:offsetFragmentCount], 1)
			return b
		}, want: ErrInvalidFragment},
		{name: "empty address", mutate: func(b []byte) []byte { binary.BigEndian.PutUint16(b[offsetAddressLength:HeaderSize], 0); return b }, want: ErrInvalidAddress},
		{name: "large address", mutate: func(b []byte) []byte {
			binary.BigEndian.PutUint16(b[offsetAddressLength:HeaderSize], protocol.MaxAddressLength+1)
			return b
		}, want: ErrInvalidAddress},
		{name: "truncated address", mutate: func(b []byte) []byte { binary.BigEndian.PutUint16(b[offsetAddressLength:HeaderSize], 100); return b }, want: ErrInvalidAddress},
		{name: "bad address", mutate: func(b []byte) []byte { copy(b[HeaderSize:HeaderSize+3], "a:0"); return b }, want: ErrInvalidAddress},
		{name: "nul address", mutate: func(b []byte) []byte { b[HeaderSize] = 0; return b }, want: ErrInvalidAddress},
		{name: "invalid UTF-8 address", mutate: func(b []byte) []byte { b[HeaderSize] = 0xff; return b }, want: ErrInvalidAddress},
		{name: "empty fragmented payload", mutate: func(b []byte) []byte {
			binary.BigEndian.PutUint16(b[offsetFragmentCount:offsetAddressLength], 2)
			return b[:len(b)-1]
		}, want: ErrInvalidFragment},
		{name: "large payload", mutate: func(b []byte) []byte { return append(b[:HeaderSize+3], make([]byte, MaxPayloadSize+1)...) }, want: ErrPayloadTooLarge},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := append([]byte(nil), seed...)
			_, err := Parse(test.mutate(input))
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func withMessage(message Message, mutate func(*Message)) Message {
	mutate(&message)
	return message
}

func FuzzParse(f *testing.F) {
	frames, _ := Encode(Message{SessionID: 1, MessageID: 2, Address: "example.com:443", Payload: []byte("seed")}, 128)
	f.Add(frames[0])
	f.Add([]byte("ACDG"))
	f.Fuzz(func(t *testing.T, input []byte) {
		fragment, err := Parse(input)
		if err != nil {
			return
		}
		if fragment.SessionID == 0 || fragment.FragmentCount == 0 || fragment.FragmentIndex >= fragment.FragmentCount {
			t.Fatalf("parser accepted invalid fragment: %+v", fragment)
		}
		if len(fragment.Address) == 0 || len(fragment.Address) > protocol.MaxAddressLength || len(fragment.Payload) > MaxPayloadSize {
			t.Fatalf("parser exceeded bounds: %+v", fragment)
		}
	})
}
