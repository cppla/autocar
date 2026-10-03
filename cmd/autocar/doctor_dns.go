package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/cppla/autocar/internal/transport"
	"golang.org/x/net/dns/dnsmessage"
)

type doctorDNSResult struct {
	Questions   int    `json:"questions"`
	Answers     int    `json:"answers"`
	Authorities int    `json:"authorities"`
	Additionals int    `json:"additionals"`
	RCode       string `json:"rcode"`
}

func doctorDNSTarget(target string) (netip.AddrPort, error) {
	endpoint, err := netip.ParseAddrPort(target)
	if err != nil || endpoint.Port() == 0 || endpoint.Addr().Zone() != "" {
		return netip.AddrPort{}, errors.New("UDP DNS requires a numeric IP and nonzero port")
	}
	addr := endpoint.Addr().Unmap()
	if addr.IsUnspecified() || addr.IsMulticast() || addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return netip.AddrPort{}, errors.New("UDP DNS requires an unzoned unicast target")
	}
	return netip.AddrPortFrom(addr, endpoint.Port()), nil
}

func doctorDNSName(value string) (dnsmessage.Name, error) {
	bare := strings.TrimSuffix(value, ".")
	if bare == "" || len(bare) > 253 {
		return dnsmessage.Name{}, errors.New("an explicit ASCII DNS name is required")
	}
	for _, label := range strings.Split(bare, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return dnsmessage.Name{}, errors.New("invalid DNS label")
		}
		for i := range label {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return dnsmessage.Name{}, errors.New("DNS labels must be ASCII letters, digits or hyphens")
			}
		}
	}
	return dnsmessage.NewName(strings.ToLower(bare) + ".")
}

// The opening context detaches from successful PacketConn setup. Independently
// close that owned packet on the full exchange budget, then join the worker;
// enqueueing Send or opening a logical H3 association is not a DNS health proof.
func probeDoctorDNS(ctx context.Context, dialer transport.PacketDialer, target netip.AddrPort, name dnsmessage.Name) (*doctorDNSResult, error) {
	if err := doctorProbeContextError(ctx); err != nil {
		return nil, err
	}
	var entropy [2]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return nil, errors.New("DNS transaction entropy unavailable")
	}
	id := binary.BigEndian.Uint16(entropy[:])
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	wire, err := query.Pack()
	if err != nil {
		return nil, errors.New("DNS query encoding failed")
	}
	packet, err := dialer.DialPacket(ctx)
	if err != nil {
		if packet != nil {
			_ = packet.Close()
		}
		if cause := doctorProbeContextError(ctx); cause != nil {
			return nil, cause
		}
		return nil, err
	}
	if packet == nil {
		return nil, errors.New("tunnel returned no packet connection")
	}
	closePacket := sync.OnceFunc(func() { _ = packet.Close() })
	watcherJoined := make(chan struct{})
	stopWatcher := context.AfterFunc(ctx, func() { defer close(watcherJoined); closePacket() })
	defer func() {
		closePacket()
		if !stopWatcher() {
			<-watcherJoined
		}
	}()
	if err := doctorProbeContextError(ctx); err != nil {
		return nil, err
	}
	type exchange struct {
		result *doctorDNSResult
		err    error
	}
	outcome, joined := make(chan exchange, 1), make(chan struct{})
	go func() {
		defer close(joined)
		if err := packet.Send(wire, target.String()); err != nil {
			outcome <- exchange{err: err}
			return
		}
		// A single query, bounded discards, no retries and no TCP fallback.
		for discarded := 0; discarded < 8; discarded++ {
			payload, source, err := packet.Receive()
			if err != nil {
				outcome <- exchange{err: err}
				return
			}
			if result, err := doctorDNSResponse(payload, source, target, id, name); err == nil {
				outcome <- exchange{result: result}
				return
			}
		}
		outcome <- exchange{err: errors.New("no matching classic DNS response within discard limit")}
	}()
	var received exchange
	select {
	case received = <-outcome:
	case <-ctx.Done():
		received.err = context.Cause(ctx)
	}
	closePacket()
	<-joined
	if err := doctorProbeContextError(ctx); err != nil {
		return nil, err
	}
	return received.result, received.err
}

func doctorProbeContextError(ctx context.Context) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

var errDoctorDNSResponse = errors.New("unmatched or unsupported classic DNS response")

func doctorDNSResponse(payload []byte, source string, target netip.AddrPort, id uint16, name dnsmessage.Name) (*doctorDNSResult, error) {
	endpoint, err := doctorDNSTarget(source)
	if err != nil || endpoint != target || !doctorDNSFraming(payload) {
		return nil, errDoctorDNSResponse
	}
	var message dnsmessage.Message
	if err := message.Unpack(payload); err != nil || message.ID != id || !message.Response || message.OpCode != 0 || message.Truncated || message.RCode != dnsmessage.RCodeSuccess || len(message.Questions) != 1 {
		return nil, errDoctorDNSResponse
	}
	question := message.Questions[0]
	if !doctorDNSASCIIEqual(question.Name.String(), name.String()) || question.Type != dnsmessage.TypeA || question.Class != dnsmessage.ClassINET {
		return nil, errDoctorDNSResponse
	}
	// NOERROR with no answers is a valid exchange, not a resolution claim.
	return &doctorDNSResult{Questions: 1, Answers: len(message.Answers), Authorities: len(message.Authorities), Additionals: len(message.Additionals), RCode: "NOERROR"}, nil
}

func doctorDNSASCIIEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x > 127 || y > 127 || x != y {
			return false
		}
	}
	return true
}

// Unpack alone accepts trailing bytes and some typed bodies outside RDLENGTH.
// First bound every locally encoded field, then let Unpack expand names against
// the original packet. This is a small classic probe, not a general DNS server.
func doctorDNSFraming(wire []byte) bool {
	if len(wire) < 12 || len(wire) > 512 || binary.BigEndian.Uint16(wire[4:6]) != 1 {
		return false
	}
	off, ok := doctorDNSWireName(wire, 12, len(wire))
	if !ok || off+4 > len(wire) {
		return false
	}
	off += 4
	for section := 6; section < 12; section += 2 {
		count := int(binary.BigEndian.Uint16(wire[section : section+2]))
		for i := 0; i < count; i++ {
			off, ok = doctorDNSWireName(wire, off, len(wire))
			if !ok || off+10 > len(wire) {
				return false
			}
			typ := dnsmessage.Type(binary.BigEndian.Uint16(wire[off : off+2]))
			length := int(binary.BigEndian.Uint16(wire[off+8 : off+10]))
			off += 10
			end := off + length
			if end > len(wire) || !doctorDNSWireBody(wire, typ, off, end) {
				return false
			}
			off = end
		}
	}
	return off == len(wire)
}

func doctorDNSWireName(wire []byte, off, end int) (int, bool) {
	for off < end {
		n := int(wire[off])
		off++
		switch n & 0xc0 {
		case 0:
			if n == 0 {
				return off, true
			}
			if off+n > end {
				return off, false
			}
			off += n
		case 0xc0:
			if off >= end {
				return off, false
			}
			pointer := (n&0x3f)<<8 | int(wire[off])
			return off + 1, pointer < len(wire)
		default:
			return off, false
		}
	}
	return off, false
}

func doctorDNSWireBody(wire []byte, typ dnsmessage.Type, off, end int) bool {
	name := func() bool { var ok bool; off, ok = doctorDNSWireName(wire, off, end); return ok }
	switch typ {
	case dnsmessage.TypeOPT:
		// No EDNS was offered; do not mistake an extended error for NOERROR.
		return false
	case dnsmessage.TypeA:
		return end-off == 4
	case dnsmessage.TypeAAAA:
		return end-off == 16
	case dnsmessage.TypeNS, dnsmessage.TypeCNAME, dnsmessage.TypePTR:
		return name() && off == end
	case dnsmessage.TypeMX:
		off += 2
		return name() && off == end
	case dnsmessage.TypeSOA:
		return name() && name() && off+20 == end
	case dnsmessage.TypeSRV:
		off += 6
		return name() && off == end
	case dnsmessage.TypeTXT:
		for off < end {
			n := int(wire[off])
			off++
			off += n
			if off > end {
				return false
			}
		}
		return off == end
	case dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS:
		off += 2
		if !name() {
			return false
		}
		previous := -1
		for off < end {
			if off+4 > end {
				return false
			}
			key := int(binary.BigEndian.Uint16(wire[off : off+2]))
			length := int(binary.BigEndian.Uint16(wire[off+2 : off+4]))
			if key <= previous {
				return false
			}
			previous = key
			off += 4 + length
			if off > end {
				return false
			}
		}
		return off == end
	default:
		return true // Unknown records are opaque and already length-bounded.
	}
}
