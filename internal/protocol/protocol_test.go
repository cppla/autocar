package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

const validTestToken = "0123456789abcdef"

func TestRequestRoundTrip(t *testing.T) {
	want := Request{Network: NetworkTCP6, Token: []byte(validTestToken), Address: "[2001:db8::1]:443"}
	var wire bytes.Buffer
	if err := WriteRequest(&wire, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadRequest(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Network != want.Network || got.Address != want.Address || !bytes.Equal(got.Token, want.Token) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestResponseRoundTrip(t *testing.T) {
	want := Response{Status: StatusDialFailed, Message: "destination unavailable"}
	var wire bytes.Buffer
	if err := WriteResponse(&wire, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadResponse(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestReadRequestRejectsInvalidHeadersWithoutLargeAllocation(t *testing.T) {
	tests := []struct {
		name string
		edit func([]byte)
		want error
	}{
		{"magic", func(b []byte) { b[0] ^= 0xff }, ErrBadMagic},
		{"version", func(b []byte) { b[4]++ }, ErrBadVersion},
		{"kind", func(b []byte) { b[5] = kindResponse }, ErrBadKind},
		{"network", func(b []byte) { binary.BigEndian.PutUint16(b[6:8], 99) }, ErrBadNetwork},
		{"zero token", func(b []byte) { binary.BigEndian.PutUint16(b[8:10], 0) }, ErrInvalidLength},
		{"short token", func(b []byte) { binary.BigEndian.PutUint16(b[8:10], MinTokenLength-1) }, ErrInvalidLength},
		{"oversize token", func(b []byte) { binary.BigEndian.PutUint16(b[8:10], MaxTokenLength+1) }, ErrInvalidLength},
		{"oversize address", func(b []byte) { binary.BigEndian.PutUint16(b[10:12], MaxAddressLength+1) }, ErrInvalidLength},
	}
	var valid bytes.Buffer
	if err := WriteRequest(&valid, Request{Network: NetworkTCP, Token: []byte(validTestToken), Address: "example.com:443"}); err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := append([]byte(nil), valid.Bytes()...)
			tt.edit(wire)
			_, err := ReadRequest(bytes.NewReader(wire))
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}
}

func TestReadResponseRejectsReservedAndOversize(t *testing.T) {
	var valid bytes.Buffer
	if err := WriteResponse(&valid, Response{Status: StatusOK}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		off  int
		val  uint16
		want error
	}{
		{"status", 6, 99, ErrBadStatus},
		{"message", 8, MaxMessageLength + 1, ErrInvalidLength},
		{"reserved", 10, 1, ErrBadReserved},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := append([]byte(nil), valid.Bytes()...)
			binary.BigEndian.PutUint16(wire[tc.off:tc.off+2], tc.val)
			_, err := ReadResponse(bytes.NewReader(wire))
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestWritersValidateBeforeWriting(t *testing.T) {
	for _, req := range []Request{
		{Network: 99, Token: []byte(validTestToken), Address: "example.com:1"},
		{Network: NetworkTCP, Address: "example.com:1"},
		{Network: NetworkTCP, Token: []byte("too-short"), Address: "example.com:1"},
		{Network: NetworkTCP, Token: []byte(validTestToken), Address: "missing-port"},
		{Network: NetworkTCP, Token: []byte(validTestToken), Address: strings.Repeat("x", MaxAddressLength+1)},
	} {
		var dst bytes.Buffer
		if err := WriteRequest(&dst, req); err == nil || dst.Len() != 0 {
			t.Fatalf("WriteRequest(%#v) error=%v bytes=%d", req, err, dst.Len())
		}
	}
	var dst bytes.Buffer
	if err := WriteResponse(&dst, Response{Status: 99}); err == nil || dst.Len() != 0 {
		t.Fatalf("WriteResponse error=%v bytes=%d", err, dst.Len())
	}
}

func TestShortIO(t *testing.T) {
	var wire bytes.Buffer
	if err := WriteRequest(&oneByteWriter{w: &wire}, Request{Network: NetworkTCP, Token: []byte(validTestToken), Address: "localhost:80"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRequest(&wire); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRequest(bytes.NewReader([]byte("AUTO"))); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v", err)
	}
}

type oneByteWriter struct{ w io.Writer }

func (w *oneByteWriter) Write(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return w.w.Write(p)
}

func FuzzReadRequest(f *testing.F) {
	var seed bytes.Buffer
	_ = WriteRequest(&seed, Request{Network: NetworkTCP, Token: []byte(validTestToken), Address: "example.com:443"})
	f.Add(seed.Bytes())
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ReadRequest(bytes.NewReader(b))
	})
}
