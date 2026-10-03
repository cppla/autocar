package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/security"
	"github.com/cppla/autocar/internal/transport"
	"github.com/cppla/autocar/internal/tunnel"
	"golang.org/x/net/dns/dnsmessage"
)

// These public-command tests intentionally compile before udp-dns exists.
// Missing flags on that source are a missing opt-in feature, not evidence of
// an already-existing UDP defect. Parser internals are not used by this file.
func doctorUDPArgs() []string {
	return []string{"--probe", "udp-dns", "--transport", "quic", "--target", "127.0.0.1:5300", "--dns-name", "Example.test", "--open-timeout", "1s", "--json"}
}

func doctorUDPJSON(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode command JSON: %v; output=%q", err, data)
	}
	return result
}

func doctorUDPRedacted(t *testing.T, output string, err error, secrets ...string) {
	t.Helper()
	if err != nil {
		output += err.Error()
	}
	for _, secret := range secrets {
		if secret != "" && strings.Contains(output, secret) {
			t.Errorf("command disclosed private probe input %q", secret)
		}
	}
}

func doctorUDPAssertResult(t *testing.T, data []byte, selected string, answers int) {
	t.Helper()
	result := doctorUDPJSON(t, data)
	if result["status"] != "ok" || result["probe"] != "authenticated_udp_dns" || result["selected_transport"] != selected {
		t.Fatalf("UDP command metadata=%v", result)
	}
	dns, ok := result["dns"].(map[string]any)
	if !ok {
		t.Fatalf("missing redacted DNS result: %v", result)
	}
	want := map[string]any{"questions": float64(1), "answers": float64(answers), "authorities": float64(0), "additionals": float64(0), "rcode": "NOERROR"}
	if len(dns) != len(want) {
		t.Fatalf("unexpected DNS result fields: %v", dns)
	}
	for key, value := range want {
		if dns[key] != value {
			t.Errorf("DNS %s=%v, want %v", key, dns[key], value)
		}
	}
	doctorUDPRedacted(t, string(data), nil, "example.test", "Example.test", "127.0.0.1:5300")
}

func TestDoctorUDPFlagsConfigAndPrivacy(t *testing.T) {
	t.Run("invalid inputs never build", func(t *testing.T) {
		cases := []struct{ name, flag, value string }{
			{"unknown probe", "probe", "private-unknown-probe"},
			{"hostname target", "target", "private-resolver.test:53"},
			{"missing target", "target", ""},
			{"zero port", "target", "127.0.0.1:0"},
			{"named port", "target", "127.0.0.1:domain"},
			{"large port", "target", "127.0.0.1:65536"},
			{"zone", "target", "[fe80::1%private-zone]:53"},
			{"unspecified v4", "target", "0.0.0.0:53"},
			{"unspecified v6", "target", "[::]:53"},
			{"multicast v4", "target", "224.0.0.1:53"},
			{"multicast v6", "target", "[ff02::1]:53"},
			{"missing name", "dns-name", ""},
			{"root name", "dns-name", "."},
			{"empty label", "dns-name", "private..test"},
			{"leading hyphen", "dns-name", "-private.test"},
			{"trailing hyphen", "dns-name", "private-.test"},
			{"unicode", "dns-name", "privaté.test"},
			{"URL", "dns-name", "https://private.test"},
			{"control", "dns-name", "private\ttest"},
			{"long label", "dns-name", strings.Repeat("p", 64) + ".test"},
			{"long name", "dns-name", strings.Repeat(strings.Repeat("p", 63)+".", 4) + "test"},
			{"TCP rejects DNS name", "probe", "tcp-open"},
			{"H2 unsupported", "transport", "h2"},
			{"TLS unsupported", "transport", "tls"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				args := append(doctorUDPArgs(), "--"+tc.flag, tc.value)
				var stdout, stderr bytes.Buffer
				builds := 0
				err := runDoctorWith(context.Background(), args, &stdout, &stderr, func(tunnelFlags) (closeDialer, error) {
					builds++
					return nil, errors.New("private-builder-must-not-run")
				})
				if commandExitCode(err) != doctorExitUsageFailure || builds != 0 {
					t.Errorf("exit=%d builds=%d err=%v", commandExitCode(err), builds, err)
				}
				if result := doctorUDPJSON(t, stdout.Bytes()); result["status"] != "failed" {
					t.Errorf("usage result=%v", result)
				}
				if stderr.Len() != 0 {
					t.Errorf("unexpected stderr=%q", stderr.String())
				}
				if strings.Contains(tc.value, "private") {
					doctorUDPRedacted(t, stdout.String()+stderr.String(), err, tc.value)
				}
			})
		}
	})
	t.Run("numeric IPv6 canonical target", func(t *testing.T) {
		packet := newDoctorUDPPacket("valid")
		dialer := &doctorUDPFakeDialer{packet: packet}
		var stdout bytes.Buffer
		err := runDoctorWith(context.Background(), append(doctorUDPArgs(), "--target", "[0:0:0:0:0:0:0:1]:5300"), &stdout, &bytes.Buffer{}, dialer.build)
		if err != nil {
			t.Fatalf("IPv6 UDP probe: %v; output=%s", err, stdout.String())
		}
		packet.mu.Lock()
		target := packet.target
		packet.mu.Unlock()
		if target != "[::1]:5300" {
			t.Errorf("numeric IPv6 target=%q", target)
		}
		doctorUDPAssertResult(t, stdout.Bytes(), "quic", 0)
	})
	t.Run("missing packet capability never falls back", func(t *testing.T) {
		dialer := &fakeDoctorDialer{snapshot: tunnel.ClientSnapshot{SelectedTransport: "quic"}}
		var stdout bytes.Buffer
		err := runDoctorWith(context.Background(), doctorUDPArgs(), &stdout, &bytes.Buffer{}, func(tunnelFlags) (closeDialer, error) { return dialer, nil })
		if commandExitCode(err) != doctorExitUsageFailure || dialer.network != "" || !dialer.closed {
			t.Errorf("unsupported capability exit=%d network=%q closed=%v err=%v", commandExitCode(err), dialer.network, dialer.closed, err)
		}
		if doctorUDPJSON(t, stdout.Bytes())["code"] != "udp_unsupported" {
			t.Errorf("missing packet capability output=%s", stdout.String())
		}
	})
	t.Run("human error is redacted", func(t *testing.T) {
		packet := newDoctorUDPPacket("private receive error")
		dialer := &doctorUDPFakeDialer{packet: packet}
		var stdout, stderr bytes.Buffer
		err := runDoctorWith(context.Background(), append(doctorUDPArgs(), "--json=false"), &stdout, &stderr, dialer.build)
		if commandExitCode(err) != doctorExitProbeFailure || !packet.isClosed() || !dialer.closed.Load() {
			t.Errorf("human UDP failure exit=%d cleanup=%v/%v err=%v", commandExitCode(err), packet.isClosed(), dialer.closed.Load(), err)
		}
		doctorUDPRedacted(t, stdout.String()+stderr.String(), err, "private-receive-error", "Example.test", "127.0.0.1:5300")
	})
	t.Run("config and CLI precedence", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "private-doctor-config.json")
		data, err := json.Marshal(map[string]any{"probe": "udp-dns", "transport": "quic", "target": "127.0.0.1:5400", "dns-name": "private.config.test.", "open-timeout": "1s", "json": true})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, data, 0o600); err != nil {
			t.Fatal(err)
		}
		packet := newDoctorUDPPacket("valid")
		dialer := &doctorUDPFakeDialer{packet: packet}
		var stdout, stderr bytes.Buffer
		err = runDoctorWith(context.Background(), []string{"--config", file, "--target", "[::ffff:127.0.0.1]:5300", "--dns-name", "Example.test"}, &stdout, &stderr, dialer.build)
		if err != nil {
			t.Fatalf("config UDP probe: %v; output=%s", err, stdout.String())
		}
		doctorUDPAssertResult(t, stdout.Bytes(), "quic", 0)
		packet.mu.Lock()
		target := packet.target
		packet.mu.Unlock()
		if target != "127.0.0.1:5300" || packet.sends.Load() != 1 || !dialer.closed.Load() {
			t.Errorf("target=%q sends=%d closed=%v", target, packet.sends.Load(), dialer.closed.Load())
		}
		doctorUDPRedacted(t, stdout.String()+stderr.String(), err, file, "private.config.test")
	})
}

func TestDoctorUDPExchangeValidatesAndDiscards(t *testing.T) {
	for _, style := range []string{"valid", "answer", "wrong ID then valid", "wrong source then valid", "discard limit", "query not response", "opcode", "wrong question", "wrong type", "wrong class", "truncated", "rcode", "OPT", "trailing bytes", "oversized", "private send error", "private receive error", "packet open error"} {
		t.Run(style, func(t *testing.T) {
			packet := newDoctorUDPPacket(style)
			dialer := &doctorUDPFakeDialer{packet: packet}
			if style == "packet open error" {
				dialer.openErr = errors.New("private-packet-open-error")
			}
			var stdout, stderr bytes.Buffer
			err := runDoctorWith(context.Background(), doctorUDPArgs(), &stdout, &stderr, dialer.build)
			wantOK := style == "valid" || style == "answer" || style == "wrong ID then valid" || style == "wrong source then valid"
			if wantOK {
				if err != nil {
					t.Errorf("valid UDP exchange failed: %v; output=%s", err, stdout.String())
				} else {
					answers := 0
					if style == "answer" {
						answers = 1
					}
					doctorUDPAssertResult(t, stdout.Bytes(), "quic", answers)
				}
			} else if commandExitCode(err) != doctorExitProbeFailure || doctorUDPJSON(t, stdout.Bytes())["status"] != "failed" {
				t.Errorf("invalid reply exit=%d err=%v output=%s", commandExitCode(err), err, stdout.String())
			}
			wantSends := int32(1)
			if style == "packet open error" {
				wantSends = 0
			}
			if packet.sends.Load() != wantSends || dialer.tcpCalls.Load() != 0 || packet.receives.Load() > 9 {
				t.Errorf("sends=%d TCP=%d receives=%d", packet.sends.Load(), dialer.tcpCalls.Load(), packet.receives.Load())
			}
			if (style == "wrong ID then valid" || style == "wrong source then valid") && packet.receives.Load() != 2 {
				t.Errorf("discarded reply was not followed by one receive: %d", packet.receives.Load())
			}
			if !dialer.closed.Load() || !packet.isClosed() || packet.active.Load() != 0 || dialer.earlySnapshot.Load() {
				t.Errorf("lifecycle closed=%v packetclosed=%v active=%d earlymetadata=%v", dialer.closed.Load(), packet.isClosed(), packet.active.Load(), dialer.earlySnapshot.Load())
			}
			doctorUDPRedacted(t, stdout.String()+stderr.String(), err, "private-packet-open-error", "private-send-error", "private-receive-error", "Example.test", "example.test", "127.0.0.1:5300", "203.0.113.9")
		})
	}
}

func TestDoctorUDPCancellationAndTimeoutJoin(t *testing.T) {
	for _, phase := range []string{"send", "receive"} {
		for _, reason := range []string{"parent cause", "probe timeout"} {
			t.Run(phase+"/"+reason, func(t *testing.T) {
				packet := newDoctorUDPPacket("blocked " + phase)
				dialer := &doctorUDPFakeDialer{packet: packet}
				ctx, cancel := context.WithCancelCause(context.Background())
				var stdout, stderr bytes.Buffer
				result := make(chan error, 1)
				joined := make(chan struct{})
				args := append(doctorUDPArgs(), "--open-timeout", "100ms")
				if reason == "parent cause" {
					args = append(args, "--open-timeout", "1s")
				}
				go func() {
					defer close(joined)
					result <- runDoctorWith(ctx, args, &stdout, &stderr, dialer.build)
				}()
				t.Cleanup(func() {
					cancel(context.Canceled)
					_ = dialer.Close()
					doctorUDPWait(t, joined, "command fatal cleanup")
				})
				entered, returned := packet.sendEntered, packet.sendReturned
				if phase == "receive" {
					entered, returned = packet.receiveEntered, packet.receiveReturned
				}
				select {
				case <-entered:
				case <-joined:
					t.Fatalf("command exited before actual %s entry: %v; output=%s", phase, <-result, stdout.String())
				case <-time.After(2 * time.Second):
					t.Fatalf("command never entered actual %s", phase)
				}
				if reason == "parent cause" {
					cancel(errors.New("private-doctor-cancellation-cause"))
				}
				doctorUDPWait(t, joined, "bounded command return")
				err := <-result
				if commandExitCode(err) != doctorExitProbeFailure || doctorUDPJSON(t, stdout.Bytes())["status"] != "failed" {
					t.Errorf("canceled/expired exit=%d err=%v output=%s", commandExitCode(err), err, stdout.String())
				}
				select {
				case <-returned:
				default:
					t.Error("command returned before actual blocked packet call completed")
				}
				if !packet.isClosed() || !dialer.closed.Load() || packet.active.Load() != 0 || packet.sends.Load() != 1 || dialer.tcpCalls.Load() != 0 {
					t.Errorf("cleanup closed=%v/%v active=%d sends=%d TCP=%d", packet.isClosed(), dialer.closed.Load(), packet.active.Load(), packet.sends.Load(), dialer.tcpCalls.Load())
				}
				doctorUDPRedacted(t, stdout.String()+stderr.String(), err, "private-doctor-cancellation-cause", "Example.test", "127.0.0.1:5300")
			})
		}
	}
}

func TestDoctorUDPDefaultTCPContractUnchanged(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprintf("explicit=%v", explicit), func(t *testing.T) {
			dialer := &fakeDoctorDialer{snapshot: tunnel.ClientSnapshot{SelectedTransport: "tls", ClientPacing: "tls-fallback", RelayPacing: "tls-fallback"}}
			args := []string{"--target", "ordinary.test:443", "--json"}
			if explicit {
				args = append(args, "--probe", "tcp-open")
			}
			var stdout bytes.Buffer
			err := runDoctorWith(context.Background(), args, &stdout, &bytes.Buffer{}, func(tunnelFlags) (closeDialer, error) { return dialer, nil })
			if err != nil {
				t.Fatalf("existing TCP contract: %v", err)
			}
			result := doctorUDPJSON(t, stdout.Bytes())
			if result["probe"] != "authenticated_tcp_open" || result["selected_transport"] != "tls" || result["dns"] != nil || dialer.network != "tcp" || !dialer.closed {
				t.Fatalf("TCP behavior changed: %v; dial=%q closed=%v", result, dialer.network, dialer.closed)
			}
		})
	}
}

type doctorUDPReply struct {
	payload []byte
	address string
	valid   bool
}

type doctorUDPPacket struct {
	mu                sync.Mutex
	style             string
	target            string
	replies           []doctorUDPReply
	sendEntered       chan struct{}
	sendReturned      chan struct{}
	receiveEntered    chan struct{}
	receiveReturned   chan struct{}
	done              chan struct{}
	once              sync.Once
	sendEntryOnce     sync.Once
	sendReturnOnce    sync.Once
	receiveEntryOnce  sync.Once
	receiveReturnOnce sync.Once
	sends             atomic.Int32
	receives          atomic.Int32
	active            atomic.Int32
	verified          atomic.Bool
}

func newDoctorUDPPacket(style string) *doctorUDPPacket {
	return &doctorUDPPacket{style: style, sendEntered: make(chan struct{}), sendReturned: make(chan struct{}), receiveEntered: make(chan struct{}), receiveReturned: make(chan struct{}), done: make(chan struct{})}
}

func (p *doctorUDPPacket) Send(payload []byte, address string) error {
	p.sends.Add(1)
	p.active.Add(1)
	defer func() { p.active.Add(-1); p.sendReturnOnce.Do(func() { close(p.sendReturned) }) }()
	p.sendEntryOnce.Do(func() { close(p.sendEntered) })
	if p.style == "blocked send" {
		<-p.done
		return net.ErrClosed
	}
	if p.style == "private send error" {
		return errors.New("private-send-error")
	}
	query, err := doctorUDPQuery(payload)
	if err != nil {
		return err
	}
	replies, err := doctorUDPReplies(query, address, p.style)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.target, p.replies = address, replies
	p.mu.Unlock()
	return nil
}

func (p *doctorUDPPacket) Receive() ([]byte, string, error) {
	p.receives.Add(1)
	p.active.Add(1)
	defer func() { p.active.Add(-1); p.receiveReturnOnce.Do(func() { close(p.receiveReturned) }) }()
	p.receiveEntryOnce.Do(func() { close(p.receiveEntered) })
	if p.style == "private receive error" {
		return nil, "", errors.New("private-receive-error")
	}
	p.mu.Lock()
	if len(p.replies) != 0 && p.style != "blocked receive" {
		reply := p.replies[0]
		p.replies = p.replies[1:]
		p.mu.Unlock()
		if reply.valid {
			p.verified.Store(true)
		}
		return reply.payload, reply.address, nil
	}
	p.mu.Unlock()
	<-p.done
	return nil, "", net.ErrClosed
}

func (p *doctorUDPPacket) Close() error { p.once.Do(func() { close(p.done) }); return nil }
func (p *doctorUDPPacket) isClosed() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

type doctorUDPFakeDialer struct {
	packet        *doctorUDPPacket
	openErr       error
	closed        atomic.Bool
	tcpCalls      atomic.Int32
	earlySnapshot atomic.Bool
}

func (d *doctorUDPFakeDialer) build(tunnelFlags) (closeDialer, error) { return d, nil }
func (d *doctorUDPFakeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.tcpCalls.Add(1)
	return nil, errors.New("unexpected TCP fallback")
}
func (d *doctorUDPFakeDialer) DialPacket(context.Context) (transport.PacketConn, error) {
	return d.packet, d.openErr
}
func (d *doctorUDPFakeDialer) Close() error { d.closed.Store(true); return d.packet.Close() }
func (d *doctorUDPFakeDialer) Snapshot() tunnel.ClientSnapshot {
	if !d.packet.verified.Load() {
		d.earlySnapshot.Store(true)
	}
	return tunnel.ClientSnapshot{SelectedTransport: "quic", ClientPacing: "adaptive-balanced", RelayPacing: "adaptive-balanced"}
}

func doctorUDPQuery(payload []byte) (dnsmessage.Message, error) {
	var query dnsmessage.Message
	if err := query.Unpack(payload); err != nil {
		return query, err
	}
	if len(payload) > 512 || query.Response || query.OpCode != 0 || !query.RecursionDesired || len(query.Questions) != 1 || len(query.Answers)+len(query.Authorities)+len(query.Additionals) != 0 {
		return query, errors.New("not one classic recursive DNS question")
	}
	question := query.Questions[0]
	if !strings.EqualFold(question.Name.String(), "example.test.") || question.Type != dnsmessage.TypeA || question.Class != dnsmessage.ClassINET {
		return query, errors.New("DNS query name/type/class mismatch")
	}
	return query, nil
}

func doctorUDPReplies(query dnsmessage.Message, address, style string) ([]doctorUDPReply, error) {
	response := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionDesired: query.RecursionDesired}, Questions: append([]dnsmessage.Question(nil), query.Questions...)}
	valid := style == "valid" || style == "answer" || style == "wrong ID then valid" || style == "wrong source then valid"
	switch style {
	case "answer":
		response.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 9}}}}
	case "query not response":
		response.Response = false
	case "opcode":
		response.OpCode = 1
	case "wrong question":
		response.Questions[0].Name = dnsmessage.MustNewName("private.other.test.")
	case "wrong type":
		response.Questions[0].Type = dnsmessage.TypeAAAA
	case "wrong class":
		response.Questions[0].Class = dnsmessage.ClassCHAOS
	case "truncated":
		response.Truncated = true
	case "rcode":
		response.RCode = dnsmessage.RCodeNameError
	case "OPT":
		response.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 512}, Body: &dnsmessage.OPTResource{}}}
	}
	wire, err := response.Pack()
	if err != nil {
		return nil, err
	}
	if style == "trailing bytes" {
		wire = append(wire, 0x7f)
	}
	if style == "oversized" {
		wire = append(wire, make([]byte, 513-len(wire))...)
	}
	reply := doctorUDPReply{payload: wire, address: address, valid: valid}
	if style == "wrong ID then valid" {
		bad := append([]byte(nil), wire...)
		bad[1] ^= 1
		return []doctorUDPReply{{payload: bad, address: address}, reply}, nil
	}
	if style == "wrong source then valid" {
		return []doctorUDPReply{{payload: wire, address: "127.0.0.1:5301"}, reply}, nil
	}
	if !valid {
		if style == "discard limit" {
			reply.address = "127.0.0.1:5301"
		}
		// Allow either immediate protocol rejection or bounded rejection after
		// discarded replies. A ninth invalid reply must never trigger a resend.
		return []doctorUDPReply{reply, reply, reply, reply, reply, reply, reply, reply, reply}, nil
	}
	return []doctorUDPReply{reply}, nil
}

func doctorUDPWait(t *testing.T, done <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("did not join %s", description)
	}
}

type doctorUDPServer interface {
	Addr() net.Addr
	Serve(context.Context) error
	Close() error
}

func TestDoctorUDPRealAuthenticatedDNSExchange(t *testing.T) {
	for _, mode := range []string{"quic", "h3"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			certFile, keyFile := filepath.Join(directory, "server.crt"), filepath.Join(directory, "server.key")
			if err := security.WriteSelfSignedCertificate(certFile, keyFile, security.CertificateOptions{Hosts: []string{"127.0.0.1"}, ValidFor: time.Hour}); err != nil {
				t.Fatal(err)
			}
			certificate, err := security.LoadKeyPair(certFile, keyFile)
			if err != nil {
				t.Fatal(err)
			}
			const token = "doctor-owned-udp-auth-token"
			tokenFile := filepath.Join(directory, "token")
			if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			endpoint, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			dnsDone := make(chan struct{})
			dnsResult := make(chan error, 1)
			var queries atomic.Int32
			go func() {
				defer close(dnsDone)
				buffer := make([]byte, 513)
				for {
					n, peer, err := endpoint.ReadFromUDPAddrPort(buffer)
					if err != nil {
						if !errors.Is(err, net.ErrClosed) {
							select {
							case dnsResult <- err:
							default:
							}
						}
						return
					}
					queries.Add(1)
					query, err := doctorUDPQuery(buffer[:n])
					if err == nil {
						var replies []doctorUDPReply
						replies, err = doctorUDPReplies(query, endpoint.LocalAddr().String(), "valid")
						if err == nil {
							_, err = endpoint.WriteToUDPAddrPort(replies[0].payload, peer)
						}
					}
					select {
					case dnsResult <- err:
					default:
					}
				}
			}()
			t.Cleanup(func() { _ = endpoint.Close(); doctorUDPWait(t, dnsDone, "owned DNS socket worker") })
			var resolves, tcpDials, coverCalls atomic.Int32
			resolver := tunnel.UDPResolverFunc(func(_ context.Context, address string) ([]netip.AddrPort, error) {
				resolves.Add(1)
				if address != endpoint.LocalAddr().String() {
					return nil, errors.New("non-owned UDP target rejected")
				}
				return []netip.AddrPort{endpoint.LocalAddr().(*net.UDPAddr).AddrPort()}, nil
			})
			destination := transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
				tcpDials.Add(1)
				return nil, errors.New("TCP destination is outside UDP probe")
			})
			var server doctorUDPServer
			if mode == "quic" {
				server, err = tunnel.ListenQUIC(tunnel.QUICServerConfig{Address: "127.0.0.1:0", Token: token, TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}}, Dialer: destination, UDPResolver: resolver})
			} else {
				server, err = tunnel.ListenWebH3(tunnel.WebH3ServerConfig{Address: "127.0.0.1:0", Token: token, TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}}, Dialer: destination, UDPResolver: resolver, Cover: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { coverCalls.Add(1); w.WriteHeader(http.StatusNotFound) })})
			}
			if err != nil {
				t.Fatal(err)
			}
			serverCtx, cancelServer := context.WithCancel(context.Background())
			serveResult, serveJoined := make(chan error, 1), make(chan struct{})
			go func() { defer close(serveJoined); serveResult <- server.Serve(serverCtx) }()
			t.Cleanup(func() {
				if err := server.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					t.Errorf("close owned relay: %v", err)
				}
				cancelServer()
				doctorUDPWait(t, serveJoined, "owned relay Serve")
				if err := <-serveResult; err != nil {
					t.Errorf("owned relay Serve: %v", err)
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var stdout, stderr bytes.Buffer
			err = runDoctorWith(ctx, []string{"--server", server.Addr().String(), "--ca", certFile, "--token-file", tokenFile, "--transport", mode, "--h3-fingerprint", "native", "--probe", "udp-dns", "--target", endpoint.LocalAddr().String(), "--dns-name", "Example.test", "--open-timeout", "2s", "--json"}, &stdout, &stderr, buildTunnelDialer)
			if err != nil {
				t.Errorf("real owned DNS exchange: %v; output=%s stderr=%s", err, stdout.String(), stderr.String())
			} else {
				doctorUDPAssertResult(t, stdout.Bytes(), mode, 0)
			}
			if queries.Load() != 1 || resolves.Load() != 1 || tcpDials.Load() != 0 || coverCalls.Load() != 0 {
				t.Errorf("DNS queries=%d resolver=%d TCP=%d cover=%d", queries.Load(), resolves.Load(), tcpDials.Load(), coverCalls.Load())
			}
			select {
			case err := <-dnsResult:
				if err != nil {
					t.Errorf("actual DNS query/response: %v", err)
				}
			case <-time.After(time.Second):
				t.Error("owned DNS endpoint never completed a real exchange")
			}
			doctorUDPRedacted(t, stdout.String()+stderr.String(), err, token, tokenFile, certFile, endpoint.LocalAddr().String(), "Example.test")
		})
	}
}
