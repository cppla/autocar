package tunnel

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/quicvarint"
)

type webH3WirePacketCounts struct {
	initial, handshake, zeroRTT, oneRTT int
}

// Only invariant, unencrypted packet boundaries and type bits are inspected.
// For v1, the long-header Length includes the protected packet number and
// ciphertext. A UDP datagram may contain several such packets; a short header
// has no Length and consumes the remainder, so ciphertext must never be scanned
// for apparent packet headers. Chrome's pinned profile permits QUIC v1 only.
func countWebH3WirePackets(datagram []byte) (webH3WirePacketCounts, error) {
	var counts webH3WirePacketCounts
	if len(datagram) == 0 {
		return counts, io.ErrUnexpectedEOF
	}
	for len(datagram) > 0 {
		if datagram[0]&0x40 == 0 {
			return counts, errors.New("QUIC fixed bit missing")
		}
		if datagram[0]&0x80 == 0 {
			// A protected short header needs at least a packet number and AEAD
			// tag even when the destination connection ID is empty.
			if len(datagram) < 18 {
				return counts, io.ErrUnexpectedEOF
			}
			counts.oneRTT++
			return counts, nil
		}
		if len(datagram) < 7 || binary.BigEndian.Uint32(datagram[1:5]) != 1 {
			return counts, errors.New("truncated or non-v1 QUIC long header")
		}
		kind := (datagram[0] >> 4) & 3
		if kind == 3 {
			return counts, errors.New("client emitted a Retry packet")
		}
		dcidLen := int(datagram[5])
		if dcidLen > 20 || 6+dcidLen >= len(datagram) {
			return counts, errors.New("invalid QUIC destination connection ID")
		}
		scidLen := int(datagram[6+dcidLen])
		if scidLen > 20 || 7+dcidLen+scidLen > len(datagram) {
			return counts, errors.New("invalid QUIC source connection ID")
		}
		offset := 7 + dcidLen + scidLen
		if kind == 0 {
			tokenLen, n, err := quicvarint.Parse(datagram[offset:])
			if err != nil {
				return counts, err
			}
			offset += n
			if tokenLen > uint64(len(datagram)-offset) {
				return counts, io.ErrUnexpectedEOF
			}
			offset += int(tokenLen)
		}
		length, n, err := quicvarint.Parse(datagram[offset:])
		if err != nil {
			return counts, err
		}
		offset += n
		if length < 17 || length > uint64(len(datagram)-offset) {
			return counts, io.ErrUnexpectedEOF
		}
		switch kind {
		case 0:
			counts.initial++
		case 1:
			counts.zeroRTT++
		case 2:
			counts.handshake++
		}
		datagram = datagram[offset+int(length):]
	}
	return counts, nil
}

func TestWebH3WirePacketCounterHandlesCoalescing(t *testing.T) {
	packet := func(kind byte) []byte {
		b := []byte{0xc3 | kind<<4, 0, 0, 0, 1, 2, 1, 2, 0}
		if kind == 0 {
			b = quicvarint.Append(b, 70)
			b = append(b, make([]byte, 70)...)
		}
		b = quicvarint.Append(b, 66)
		return append(b, make([]byte, 66)...)
	}
	short := append([]byte{0x43}, make([]byte, 32)...)
	coalesced := append(packet(0), packet(1)...)
	coalesced = append(coalesced, packet(2)...)
	coalesced = append(coalesced, short...)
	got, err := countWebH3WirePackets(coalesced)
	if err != nil || got != (webH3WirePacketCounts{initial: 1, zeroRTT: 1, handshake: 1, oneRTT: 1}) {
		t.Fatalf("coalesced packet counts=%+v error=%v", got, err)
	}
	// These bytes are short-header ciphertext, not a second coalesced packet.
	got, err = countWebH3WirePackets(append(short, packet(1)...))
	if err != nil || got != (webH3WirePacketCounts{oneRTT: 1}) {
		t.Fatalf("short-header ciphertext was reparsed: counts=%+v error=%v", got, err)
	}
	wrongVersion := packet(0)
	wrongVersion[4] = 2
	for name, invalid := range map[string][]byte{
		"empty": nil, "short_header": {0x43}, "missing_fixed_bit": {0},
		"bad_version": wrongVersion, "truncated_coalesced": append(packet(0), 0xd0),
		"truncated_payload": packet(1)[:20], "retry_from_client": packet(3),
	} {
		if _, err := countWebH3WirePackets(invalid); err == nil {
			t.Errorf("%s did not fail closed", name)
		}
	}
}

type webH3RecordingProxy struct {
	socket  *net.UDPConn
	done    chan struct{}
	changed chan struct{}
	mu      sync.Mutex
	counts  webH3WirePacketCounts
	err     error
}

func newWebH3RecordingProxy(t *testing.T, destination string) *webH3RecordingProxy {
	t.Helper()
	remote, err := net.ResolveUDPAddr("udp4", destination)
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	p := &webH3RecordingProxy{socket: socket, done: make(chan struct{}), changed: make(chan struct{}, 1)}
	t.Cleanup(func() {
		_ = socket.Close()
		select {
		case <-p.done:
		case <-time.After(2 * time.Second):
			t.Error("recording UDP proxy did not stop")
		}
	})
	go func() {
		defer close(p.done)
		var client *net.UDPAddr
		buffer := make([]byte, 64<<10)
		for {
			n, source, err := socket.ReadFromUDP(buffer)
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					p.fail(err)
				}
				return
			}
			forward := remote
			if source.Port == remote.Port && source.IP.Equal(remote.IP) {
				if client == nil {
					p.fail(errors.New("server replied before client was observed"))
					return
				}
				forward = client
			} else {
				if client == nil {
					client = source
				} else if source.Port != client.Port || !source.IP.Equal(client.IP) {
					p.fail(errors.New("recording proxy received an unexpected second client"))
					return
				}
				counts, parseErr := countWebH3WirePackets(buffer[:n])
				if parseErr != nil {
					p.fail(fmt.Errorf("outbound QUIC datagram: %w", parseErr))
					return
				}
				p.mu.Lock()
				p.counts.initial += counts.initial
				p.counts.handshake += counts.handshake
				p.counts.zeroRTT += counts.zeroRTT
				p.counts.oneRTT += counts.oneRTT
				p.mu.Unlock()
				select {
				case p.changed <- struct{}{}:
				default:
				}
			}
			if _, err := socket.WriteToUDP(buffer[:n], forward); err != nil {
				if !errors.Is(err, net.ErrClosed) {
					p.fail(err)
				}
				return
			}
		}
	}()
	return p
}

func (p *webH3RecordingProxy) fail(err error) {
	p.mu.Lock()
	p.err = err
	p.mu.Unlock()
}

func (p *webH3RecordingProxy) snapshot(t *testing.T) webH3WirePacketCounts {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		t.Fatal(p.err)
	}
	return p.counts
}

type webH3WireHandshakeGate struct {
	entered, release chan struct{}
	once             sync.Once
}

func (g *webH3WireHandshakeGate) block() {
	g.once.Do(func() { close(g.entered) })
	<-g.release
}

func TestWebH3ResumptionWireNeverSendsEarlyApplicationData(t *testing.T) {
	serverTLS, clientTLS := webH2ResumptionTLSConfigs(t)
	clientTLS.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	serverTLS.SetSessionTicketKeys([][32]byte{{4, 5, 6}})
	certificate := serverTLS.Certificates[0]
	serverTLS.Certificates = nil
	var activeGate atomic.Pointer[webH3WireHandshakeGate]
	serverTLS.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		activeGate.Load().block()
		return &certificate, nil
	}
	serverTLS.UnwrapSession = func(identity []byte, state tls.ConnectionState) (*tls.SessionState, error) {
		activeGate.Load().block()
		return serverTLS.DecryptTicket(identity, state)
	}
	target, closeTarget := startHalfCloseTarget(t)
	t.Cleanup(closeTarget)
	var dials, requests atomic.Int32
	var prematureRequest atomic.Bool
	server, err := ListenWebH3(WebH3ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
		Dialer: countingDialer{dials: &dials}, Cover: http.NotFoundHandler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	observations := make(chan quic.ConnectionState, 2)
	handler := server.server.Handler
	server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn := r.Context().Value(webH3ConnectionContextKey{}).(*quic.Conn)
		state := conn.ConnectionState()
		if !state.TLS.HandshakeComplete {
			prematureRequest.Store(true)
		}
		requests.Add(1)
		select {
		case observations <- state:
		default:
			// An unexpected extra request must fail the assertion, not leave a
			// server handler blocked while the failed test is cleaning up.
			prematureRequest.Store(true)
		}
		handler.ServeHTTP(w, r)
	})
	serveWebH3ForTest(t, server)
	client, err := NewWebH3Client(WebH3ClientConfig{
		ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
		FingerprintProfile: H3FingerprintChrome202610Resume, DialTimeout: 5 * time.Second, HandshakeTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	cache := watchWebH3UTLSTickets(t, client)
	entropy := &webH2AuthEntropyCounter{}
	client.signer = newWebAuthSigner(mustWebAuthKey(t, webTestToken), nil, entropy)
	for phase, name := range []string{"cold", "resumed"} {
		t.Run(name, func(t *testing.T) {
			gate := &webH3WireHandshakeGate{entered: make(chan struct{}), release: make(chan struct{})}
			var release sync.Once
			defer release.Do(func() { close(gate.release) })
			activeGate.Store(gate)
			proxy := newWebH3RecordingProxy(t, server.Addr().String())
			// The previous physical session was fully retired. Preserve the
			// verified DNS identity and client-owned cache across UDP endpoints.
			client.address = proxy.socket.LocalAddr().String()
			opened := make(chan error, 1)
			go func() { opened <- exchange(client, target, name+" wire test") }()
			select {
			case <-gate.entered:
			case err := <-opened:
				t.Fatalf("handshake skipped the server gate: %v", err)
			case <-time.After(3 * time.Second):
				t.Fatal("handshake did not reach the server gate")
			}
			before := proxy.snapshot(t)
			if before.initial == 0 {
				t.Fatal("no actual outbound Initial was observed")
			}
			// Wait for additional Initial traffic while TLS remains blocked,
			// not a sleep or a post-handshake ConnectionState-only assertion.
			// Header inspection does not distinguish ACKs from CRYPTO retries.
			deadline := time.NewTimer(3 * time.Second)
			defer deadline.Stop()
			for proxy.snapshot(t).initial <= before.initial {
				select {
				case <-proxy.changed:
				case <-proxy.done:
					t.Fatal("packet recorder stopped during the gated handshake")
				case <-deadline.C:
					t.Fatal("no additional Initial traffic observed while handshake was blocked")
				}
			}
			blocked := proxy.snapshot(t)
			if blocked.zeroRTT != 0 || blocked.oneRTT != 0 || requests.Load() != int32(phase) || dials.Load() != int32(phase) || entropy.nonceReads.Load() != int64(phase) {
				t.Fatalf("application activity before TLS completion: packets=%+v requests=%d dials=%d bootstraps=%d", blocked, requests.Load(), dials.Load(), entropy.nonceReads.Load())
			}
			release.Do(func() { close(gate.release) })
			select {
			case err := <-opened:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("authenticated request did not finish after handshake release")
			}
			select {
			case state := <-observations:
				if state.TLS.DidResume != (phase == 1) || !state.TLS.HandshakeComplete || state.Used0RTT {
					t.Fatal("server did not observe the expected complete 1-RTT handshake")
				}
			case <-time.After(time.Second):
				t.Fatal("authenticated server request observation missing")
			}
			waitWebH3Ticket(t, cache.stored)
			session := webH3SelectedSession(t, client)
			if state := session.conn.ConnectionState(); state.TLS.DidResume != (phase == 1) || !state.TLS.HandshakeComplete || state.Used0RTT {
				t.Fatal("client did not observe the expected complete 1-RTT handshake")
			}
			client.retire(session.conn)
			assertWebH3SessionRetired(t, client, session)
			final := proxy.snapshot(t)
			if final.zeroRTT != 0 || final.initial == 0 || final.handshake == 0 || final.oneRTT == 0 || prematureRequest.Load() {
				t.Fatalf("outbound packet evidence incomplete or contained early data: %+v", final)
			}
			t.Logf("observed outbound packets: Initial=%d Handshake=%d 0-RTT=%d 1-RTT=%d; resumed=%t", final.initial, final.handshake, final.zeroRTT, final.oneRTT, phase == 1)
		})
		if t.Failed() {
			return
		}
	}
	if cache.hits.Load() == 0 || requests.Load() != 2 || dials.Load() != 2 || entropy.nonceReads.Load() != 2 {
		t.Fatal("wire test lacked actual ticket reuse or fresh connection authentication")
	}
}
