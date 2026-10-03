package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

// These frontend contract tests use real, owned loopback UDP ingress/egress,
// but a deliberately controlled PacketConn. They do not model relay DNS,
// authenticate an H3 peer, or prove end-to-end delivery through a tunnel.
// The local structural interface also lets this source compile before the
// optional production interface exists; missing capability is a behavioral
// assertion, not a missing-type compilation oracle.
type socksUDPConcurrencyCapability interface {
	transport.PacketConn
	ConcurrentSendLimit() int
	SendTargetKey(string) (string, error)
}

type socksUDPConcurrencyCall struct {
	payload []byte
	address string
	err     error
	done    chan struct{}
}

type socksUDPConcurrencyPacket struct {
	started     chan *socksUDPConcurrencyCall
	incoming    chan packetRecord
	closed      chan struct{}
	receiveDone chan struct{}
	closeOnce   sync.Once
	receiveOnce sync.Once
	closes      atomic.Int32
	active      atomic.Int32
	maximum     atomic.Int32
	send        func([]byte, string) error
}

func newSOCKSUDPConcurrencyPacket() *socksUDPConcurrencyPacket {
	return &socksUDPConcurrencyPacket{
		started:     make(chan *socksUDPConcurrencyCall, 16),
		incoming:    make(chan packetRecord, 16),
		closed:      make(chan struct{}),
		receiveDone: make(chan struct{}),
	}
}

func (p *socksUDPConcurrencyPacket) Send(payload []byte, address string) (err error) {
	n := p.active.Add(1)
	for old := p.maximum.Load(); n > old && !p.maximum.CompareAndSwap(old, n); old = p.maximum.Load() {
	}
	call := &socksUDPConcurrencyCall{
		payload: append([]byte(nil), payload...), address: address, done: make(chan struct{}),
	}
	defer func() {
		p.active.Add(-1)
		call.err = err
		close(call.done)
	}()
	select {
	case p.started <- call:
	case <-p.closed:
		return net.ErrClosed
	}
	if p.send != nil {
		return p.send(payload, address)
	}
	return nil
}

func (p *socksUDPConcurrencyPacket) Receive() ([]byte, string, error) {
	select {
	case record := <-p.incoming:
		return record.payload, record.address, nil
	case <-p.closed:
		p.receiveOnce.Do(func() { close(p.receiveDone) })
		return nil, "", net.ErrClosed
	}
}

func (p *socksUDPConcurrencyPacket) Close() error {
	p.closes.Add(1)
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

type socksUDPConcurrencyOptional struct {
	*socksUDPConcurrencyPacket
	limit int
	keys  chan string
	key   func(string) (string, error)
}

func (p *socksUDPConcurrencyOptional) ConcurrentSendLimit() int { return p.limit }

func (p *socksUDPConcurrencyOptional) SendTargetKey(address string) (string, error) {
	p.keys <- address
	if p.key != nil {
		return p.key(address)
	}
	return socksUDPConcurrencyCanonicalKey(address)
}

// This is a fixture-provided key, not the production CONNECT-UDP normalizer.
// Its purpose is to prove that the frontend obeys its provider's identity.
func socksUDPConcurrencyCanonicalKey(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return "", errors.New("fixture invalid target port")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return "", errors.New("fixture target zone")
		}
		host = ip.Unmap().String()
	} else {
		host = strings.ToLower(host)
	}
	return net.JoinHostPort(host, strconv.FormatUint(n, 10)), nil
}

type socksUDPConcurrencyFixture struct {
	t        *testing.T
	packet   *socksUDPConcurrencyPacket
	upstream *closeOncePacketConn
	local    *net.UDPConn
	client   *net.UDPConn
	relay    *net.UDPAddr
	control  chan struct{}
	stopOnce sync.Once
	done     chan struct{}
	started  bool
	releases []func()
}

func newSOCKSUDPConcurrencyFixture(t *testing.T, packet *socksUDPConcurrencyPacket, upstream transport.PacketConn, releases ...func()) *socksUDPConcurrencyFixture {
	t.Helper()
	f := &socksUDPConcurrencyFixture{
		t: t, packet: packet, upstream: &closeOncePacketConn{PacketConn: upstream},
		control: make(chan struct{}), done: make(chan struct{}), releases: releases,
	}
	t.Cleanup(func() {
		// Release every callback/return gate before shutting down owned I/O,
		// including the path taken by Fatal at any earlier checkpoint.
		for _, release := range f.releases {
			release()
		}
		f.stop()
		if f.local != nil {
			_ = f.local.Close()
		}
		if f.client != nil {
			_ = f.client.Close()
		}
		_ = f.upstream.Close()
		if f.started {
			socksUDPConcurrencyWait(t, f.done, "association cleanup join")
			socksUDPConcurrencyWait(t, packet.receiveDone, "upstream Receive cleanup join")
		}
	})
	var err error
	f.local, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f.client, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f.relay = f.local.LocalAddr().(*net.UDPAddr)
	endpoint := &socksUDPClientEndpoint{
		peerIP:        net.IPv4(127, 0, 0, 1),
		requestedPort: f.client.LocalAddr().(*net.UDPAddr).Port,
	}
	f.started = true
	go func() {
		defer close(f.done)
		runSOCKSUDPAssociation(f.control, f.local, f.upstream, endpoint, 0)
	}()
	return f
}

func (f *socksUDPConcurrencyFixture) stop() { f.stopOnce.Do(func() { close(f.control) }) }

func (f *socksUDPConcurrencyFixture) write(target, payload string) {
	f.t.Helper()
	packet, err := buildSOCKSUDPDatagram([]byte(payload), target)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.client.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.client.WriteToUDP(packet, f.relay); err != nil {
		f.t.Fatal(err)
	}
}

func (f *socksUDPConcurrencyFixture) call(payload, address string) *socksUDPConcurrencyCall {
	f.t.Helper()
	select {
	case call := <-f.packet.started:
		if string(call.payload) != payload || call.address != address {
			f.t.Fatalf("actual Send = %q to %q, want %q to %q", call.payload, call.address, payload, address)
		}
		return call
	case <-time.After(2 * time.Second):
		f.t.Fatal("expected actual Send did not enter")
		return nil
	}
}

func (f *socksUDPConcurrencyFixture) echo(payload, address string) {
	f.t.Helper()
	f.packet.incoming <- packetRecord{payload: []byte(payload), address: address}
	if err := f.client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		f.t.Fatal(err)
	}
	buffer := make([]byte, 256)
	n, source, err := f.client.ReadFromUDP(buffer)
	if err != nil {
		f.t.Fatal(err)
	}
	got, target, err := parseSOCKSUDPDatagram(buffer[:n])
	if err != nil || !bytes.Equal(got, []byte(payload)) || target != address || !source.IP.Equal(f.relay.IP) || source.Port != f.relay.Port {
		f.t.Fatalf("actual UDP response=%q target=%q source=%v err=%v", got, target, source, err)
	}
}

func (f *socksUDPConcurrencyFixture) assertJoined() {
	f.t.Helper()
	socksUDPConcurrencyWait(f.t, f.done, "association join")
	socksUDPConcurrencyWait(f.t, f.packet.receiveDone, "Receive join")
	if got := f.packet.active.Load(); got != 0 {
		f.t.Errorf("association returned with %d active Send calls", got)
	}
	if got := f.packet.closes.Load(); got != 1 {
		f.t.Errorf("upstream actual Close calls=%d, want one", got)
	}
}

func socksUDPConcurrencyWait(t *testing.T, done <-chan struct{}, name string) bool {
	t.Helper()
	select {
	case <-done:
		return true
	case <-time.After(2 * time.Second):
		t.Errorf("%s did not finish", name)
		return false
	}
}

func (f *socksUDPConcurrencyFixture) await(done <-chan struct{}, name string) {
	f.t.Helper()
	if !socksUDPConcurrencyWait(f.t, done, name) {
		f.t.Fatal("required causal checkpoint failed")
	}
}

func socksUDPConcurrencyGate() (<-chan struct{}, func()) {
	gate := make(chan struct{})
	return gate, sync.OnceFunc(func() { close(gate) })
}

func socksUDPConcurrencyKey(t *testing.T, keys <-chan string, want string) {
	t.Helper()
	select {
	case got := <-keys:
		if got != want {
			t.Fatalf("provider key input=%q, want %q", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("frontend did not request provider's canonical target key")
	}
}

func TestSOCKS5UDPConcurrencyLegacyRemainsSerial(t *testing.T) {
	for _, mode := range []string{"legacy", "limit_zero", "limit_one"} {
		t.Run(mode, func(t *testing.T) {
			packet := newSOCKSUDPConcurrencyPacket()
			gate, release := socksUDPConcurrencyGate()
			packet.send = func(payload []byte, _ string) error {
				if string(payload) == "first" {
					select {
					case <-gate:
					case <-packet.closed:
						return net.ErrClosed
					}
				}
				return nil
			}
			optional := &socksUDPConcurrencyOptional{packet, 0, make(chan string, 16), nil}
			var upstream transport.PacketConn = packet
			if mode != "legacy" {
				upstream = optional
			}
			if mode == "limit_one" {
				optional.limit = 1
			}
			f := newSOCKSUDPConcurrencyFixture(t, packet, upstream, release)
			f.write("first.invalid:5300", "first")
			first := f.call("first", "first.invalid:5300")
			f.write("second.invalid:5301", "second")
			// This bounded absence window is a serial-mode control, not an entry
			// witness or performance measurement. Actual first Send is held.
			select {
			case call := <-packet.started:
				t.Fatalf("serial mode overlapped actual Send: %q", call.payload)
			case <-time.After(75 * time.Millisecond):
			}
			release()
			f.await(first.done, "first Send")
			second := f.call("second", "second.invalid:5301")
			f.await(second.done, "second Send")
			f.echo("second response", "second.invalid:5301")
			f.stop()
			f.assertJoined()
			if packet.maximum.Load() != 1 || len(optional.keys) != 0 {
				t.Errorf("serial control maximum=%d key calls=%d", packet.maximum.Load(), len(optional.keys))
			}
		})
	}
}

func TestSOCKS5UDPConcurrencyOptionalTargetIsolationAndCanonicalFIFO(t *testing.T) {
	packet := newSOCKSUDPConcurrencyPacket()
	gate, release := socksUDPConcurrencyGate()
	packet.send = func(payload []byte, _ string) error {
		if string(payload) == "slow first" {
			select {
			case <-gate:
				if string(payload) != "slow first" {
					return errors.New("frontend reused ingress payload buffer")
				}
			case <-packet.closed:
				return net.ErrClosed
			}
		}
		return nil
	}
	optional := &socksUDPConcurrencyOptional{packet, 2, make(chan string, 16), nil}
	f := newSOCKSUDPConcurrencyFixture(t, packet, optional, release)
	capability, ok := any(f.upstream).(socksUDPConcurrencyCapability)
	if !ok || capability.ConcurrentSendLimit() != 2 {
		t.Fatal("close-once wrapper did not preserve optional concurrent-send capacity")
	}
	for _, test := range []struct{ address, want string }{
		{"UPPER.invalid:053", "upper.invalid:53"},
		{"[2001:db8:0:0:0:0:0:1]:53", "[2001:db8::1]:53"},
		{"[::ffff:127.0.0.1]:53", "127.0.0.1:53"},
	} {
		got, err := capability.SendTargetKey(test.address)
		if err != nil || got != test.want {
			t.Fatalf("wrapper key(%q)=%q err=%v, want %q", test.address, got, err, test.want)
		}
		socksUDPConcurrencyKey(t, optional.keys, test.address)
	}
	f.write("SLOW.invalid:5300", "slow first")
	socksUDPConcurrencyKey(t, optional.keys, "SLOW.invalid:5300")
	first := f.call("slow first", "slow.invalid:5300")
	f.write("slow.invalid:5300", "slow second")
	socksUDPConcurrencyKey(t, optional.keys, "slow.invalid:5300")
	f.write("fast.invalid:5301", "fast")
	socksUDPConcurrencyKey(t, optional.keys, "fast.invalid:5301")
	fast := f.call("fast", "fast.invalid:5301")
	f.await(fast.done, "fast target Send")
	f.echo("fast response", "fast.invalid:5301")
	select {
	case <-first.done:
		t.Fatal("slow actual callback ended before its release gate")
	default:
	}
	if packet.maximum.Load() != 2 {
		t.Errorf("actual concurrent Send maximum=%d, want two", packet.maximum.Load())
	}
	release()
	f.await(first.done, "slow first Send")
	if first.err != nil {
		t.Errorf("slow first Send after release=%v", first.err)
	}
	second := f.call("slow second", "slow.invalid:5300")
	f.await(second.done, "slow second Send")
	f.echo("slow second response", "slow.invalid:5300")
	f.stop()
	f.assertJoined()
}

func TestSOCKS5UDPConcurrencyErrorsPreserveAssociationPolicy(t *testing.T) {
	for _, test := range []struct {
		name        string
		err         error
		recoverable bool
	}{
		{"queue_full", fmt.Errorf("fixture pressure: %w", transport.ErrPacketQueueFull), true},
		{"target_unavailable", fmt.Errorf("fixture target: %w", transport.ErrPacketTargetUnavailable), true},
		{"unknown", errors.New("fixture terminal failure"), false},
		{"canceled", fmt.Errorf("fixture terminal cancellation: %w", context.Canceled), false},
		{"deadline", fmt.Errorf("fixture terminal deadline: %w", context.DeadlineExceeded), false},
		{"closed", fmt.Errorf("fixture terminal close: %w", net.ErrClosed), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet := newSOCKSUDPConcurrencyPacket()
			packet.send = func(payload []byte, _ string) error {
				if string(payload) == "error" {
					return test.err
				}
				return nil
			}
			optional := &socksUDPConcurrencyOptional{packet, 2, make(chan string, 16), nil}
			f := newSOCKSUDPConcurrencyFixture(t, packet, optional)
			f.write("policy.invalid:5300", "error")
			failed := f.call("error", "policy.invalid:5300")
			f.await(failed.done, "failed Send")
			if failed.err != test.err {
				t.Errorf("controlled Send error identity changed: %v", failed.err)
			}
			if test.recoverable {
				f.write("policy.invalid:5300", "healthy")
				healthy := f.call("healthy", "policy.invalid:5300")
				f.await(healthy.done, "healthy Send")
				f.echo("healthy response", "policy.invalid:5300")
				select {
				case <-packet.closed:
					t.Fatal("recoverable Send error closed the association")
				default:
				}
				f.stop()
			}
			f.assertJoined()
			if len(packet.started) != 0 {
				t.Error("failed packet was transparently retried")
			}
		})
	}
}

func TestSOCKS5UDPConcurrencyCloseJoinsPendingSends(t *testing.T) {
	packet := newSOCKSUDPConcurrencyPacket()
	returnGate, release := socksUDPConcurrencyGate()
	observedClose := make(chan struct{})
	packet.send = func([]byte, string) error {
		<-packet.closed
		close(observedClose)
		// This explicit post-cancellation return gate tests owner join, not
		// network backpressure or a natural scheduling race.
		<-returnGate
		return net.ErrClosed
	}
	optional := &socksUDPConcurrencyOptional{packet, 2, make(chan string, 16), nil}
	f := newSOCKSUDPConcurrencyFixture(t, packet, optional, release)
	f.write("close.invalid:5300", "blocked")
	call := f.call("blocked", "close.invalid:5300")
	f.stop()
	f.await(observedClose, "actual Send observing upstream Close")
	select {
	case <-f.done:
		t.Fatal("association returned before its accepted Send completed")
	case <-time.After(75 * time.Millisecond):
	}
	if packet.active.Load() != 1 {
		t.Errorf("held actual Send count=%d, want one", packet.active.Load())
	}
	release()
	f.await(call.done, "canceled Send completion")
	f.assertJoined()
}
