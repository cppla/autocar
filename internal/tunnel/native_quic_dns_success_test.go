package tunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/transport"
	"golang.org/x/net/dns/dnsmessage"
)

const nativeQUICDNSSuccessChild = "AUTOCAR_NATIVE_QUIC_DNS_SUCCESS_CHILD"
const nativeQUICDNSSuccessName = "native-dns-success.invalid."

func TestNativeQUICNamedRelayPreservesTLSIdentity(t *testing.T) {
	if os.Getenv(nativeQUICDNSSuccessChild) != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0],
			"-test.run=^TestNativeQUICNamedRelayPreservesTLSIdentity$", "-test.count=1", "-test.v", "-test.timeout=10s")
		cmd.Env = append(os.Environ(), nativeQUICDNSSuccessChild+"=1")
		out, err := cmd.CombinedOutput()
		for _, line := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
			t.Logf("isolated child | %s", line)
		}
		if ctx.Err() != nil || err != nil {
			t.Fatalf("isolated named-relay flow failed: process=%v outer=%v", err, ctx.Err())
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	serverTLS, clientTLS := nativeQUICDNSSuccessTLS(t)
	target, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = target.Close()
		t.Fatal(err)
	}
	f := &nativeQUICDNSSuccessFixture{peer: peer}
	var destinationDials atomic.Int64
	server, err := ListenQUIC(QUICServerConfig{Address: "127.0.0.1:0", Token: testToken,
		TLSConfig: serverTLS, HandshakeTimeout: 2 * time.Second,
		Dialer: transport.DialFunc(func(dialCtx context.Context, network, address string) (net.Conn, error) {
			destinationDials.Add(1)
			if network != "tcp" || address != target.Addr().String() {
				return nil, errors.New("unexpected non-owned destination")
			}
			return (&net.Dialer{}).DialContext(dialCtx, "tcp4", address)
		})})
	if err != nil {
		_ = target.Close()
		_ = peer.Close()
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(server.Addr().String())
	if err != nil {
		_ = server.Close()
		_ = target.Close()
		_ = peer.Close()
		t.Fatal(err)
	}
	client, err := NewClient(ClientConfig{ServerAddress: net.JoinHostPort(nativeQUICDNSSuccessName, port),
		Token: testToken, TLSConfig: clientTLS, QUICDialTimeout: 2 * time.Second, HandshakeTimeout: 2 * time.Second})
	if err != nil {
		_ = server.Close()
		_ = target.Close()
		_ = peer.Close()
		t.Fatal(err)
	}

	// Only this exact-test child changes the global. Keep it installed until
	// process exit, because resolver-owned background work is outside our joins.
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: f.dial}
	dnsDone, echoDone, serveDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	echoResult, serveResult := make(chan error, 1), make(chan error, 1)
	clientDone, serverDone := make(chan struct{}), make(chan struct{})
	clientResult, serverResult := make(chan error, 1), make(chan error, 1)
	var clientOnce, serverOnce sync.Once
	closeClient := func() {
		clientOnce.Do(func() {
			go func() { defer close(clientDone); clientResult <- client.Close() }()
		})
	}
	closeServer := func() {
		serverOnce.Do(func() {
			go func() { defer close(serverDone); serverResult <- server.Close() }()
		})
	}
	var stream net.Conn
	var echoMu sync.Mutex
	var echoConn *net.TCPConn
	echoStopping := false
	t.Cleanup(func() {
		// Independently dispose exact sockets before joining production owners;
		// failed handshakes or assertions must not strand the echo accept/read.
		if stream != nil {
			_ = stream.Close()
		}
		echoMu.Lock()
		echoStopping = true
		if echoConn != nil {
			_ = echoConn.Close()
		}
		echoMu.Unlock()
		_ = target.Close()
		f.stop()
		closeClient()
		closeServer()
		cancel()
		joinCtx, stopJoin := context.WithTimeout(context.Background(), 2*time.Second)
		defer stopJoin()
		joined := true
		for name, done := range map[string]<-chan struct{}{
			"client Close": clientDone, "server Close": serverDone, "server Serve": serveDone,
			"DNS peer": dnsDone, "TCP echo": echoDone,
		} {
			select {
			case <-done:
			case <-joinCtx.Done():
				joined = false
				t.Errorf("owned %s did not join", name)
			}
		}
		for name, result := range map[string]<-chan error{
			"client Close": clientResult, "server Close": serverResult, "server Serve": serveResult,
		} {
			select {
			case err := <-result:
				if err != nil {
					t.Errorf("%s: %v", name, err)
				}
			default: // A successful main-path Close check may consume its result.
			}
		}
		f.mu.Lock()
		problem, queries, answers, sockets := f.problem, f.queries, f.answers, len(f.conns)
		f.mu.Unlock()
		if problem != nil {
			t.Errorf("DNS fixture: %v", problem)
		}
		t.Logf("cleanup all_owned_workers_joined=%t DNS_queries=%d A_answers=%d DNS_sockets=%d destination_dials=%d",
			joined, queries, answers, sockets, destinationDials.Load())
	})
	go func() { defer close(dnsDone); f.serve() }()
	go func() { defer close(serveDone); serveResult <- server.Serve(ctx) }()
	const payload = "named relay verified TLS authenticated echo"
	go func() {
		defer close(echoDone)
		conn, err := target.AcceptTCP()
		if err != nil {
			echoResult <- err
			return
		}
		defer conn.Close()
		echoMu.Lock()
		if echoStopping {
			echoMu.Unlock()
			echoResult <- net.ErrClosed
			return
		}
		echoConn = conn
		echoMu.Unlock()
		err = conn.SetDeadline(time.Now().Add(4 * time.Second))
		var body []byte
		if err == nil {
			body, err = io.ReadAll(conn)
		}
		if err == nil && string(body) != payload {
			err = fmt.Errorf("actual upload mismatch: %q", body)
		}
		if err == nil {
			var n int
			n, err = io.WriteString(conn, "reply:"+payload)
			if err == nil && n != len("reply:"+payload) {
				err = io.ErrShortWrite
			}
		}
		if err == nil {
			err = conn.CloseWrite()
		}
		echoResult <- err
	}()

	if clientTLS.ServerName != "" || clientTLS.InsecureSkipVerify || client.tlsConfig.ServerName != nativeQUICDNSSuccessName {
		t.Fatal("fixture must use the configured relay name with no explicit or insecure TLS override")
	}
	stream, err = client.DialContext(ctx, "tcp", target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := io.WriteString(stream, payload); err != nil || n != len(payload) {
		t.Fatalf("upload n=%d err=%v", n, err)
	}
	closeWriter, ok := stream.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("authenticated stream lost CloseWrite")
	}
	if err := closeWriter.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(stream)
	if err != nil || string(reply) != "reply:"+payload {
		t.Fatalf("actual reply=%q err=%v", reply, err)
	}
	select {
	case <-echoDone:
		if err := <-echoResult; err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("actual echo worker did not complete")
	}
	client.mu.Lock()
	physical := client.conn
	client.mu.Unlock()
	if physical == nil {
		t.Fatal("authenticated flow did not retain the actual QUIC connection")
	}
	state := physical.ConnectionState()
	if state.TLS.Version != tls.VersionTLS13 || state.TLS.NegotiatedProtocol != protocol.ALPN ||
		state.Used0RTT || len(state.TLS.VerifiedChains) == 0 || len(state.TLS.PeerCertificates) == 0 {
		t.Fatalf("unverified physical security state: TLS=%#x ALPN=%q 0RTT=%t chains=%d",
			state.TLS.Version, state.TLS.NegotiatedProtocol, state.Used0RTT, len(state.TLS.VerifiedChains))
	}
	cert := state.TLS.PeerCertificates[0]
	if len(cert.IPAddresses) != 0 || len(cert.DNSNames) != 1 || cert.DNSNames[0] != strings.TrimSuffix(nativeQUICDNSSuccessName, ".") {
		t.Fatal("actual peer certificate must contain only the owned DNS identity and no IP SAN")
	}
	f.mu.Lock()
	queries, answers := f.queries, f.answers
	f.mu.Unlock()
	if queries == 0 || answers == 0 || destinationDials.Load() != 1 || client.SelectedTransport() != "quic" {
		t.Fatalf("incomplete DNS/authenticated path: queries=%d answers=%d destination_dials=%d path=%q",
			queries, answers, destinationDials.Load(), client.SelectedTransport())
	}
	_ = stream.Close()
	closeClient()
	select {
	case <-clientDone:
		if err := <-clientResult; err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("client Close did not join after the successful named-relay flow")
	}
	select {
	case <-physical.Context().Done():
	case <-ctx.Done():
		t.Fatal("joined Close left the actual QUIC connection live")
	}
	t.Log("owned DNS A reply -> numeric QUIC -> verified DNS-only TLS certificate -> authenticated FIN/echo -> joined Close")
}

type nativeQUICDNSSuccessFixture struct {
	peer             *net.UDPConn
	mu               sync.Mutex
	stopping         bool
	conns            []*net.UDPConn
	queries, answers int
	problem          error
}

func (f *nativeQUICDNSSuccessFixture) dial(ctx context.Context, network, _ string) (net.Conn, error) {
	if network != "udp" && network != "udp4" && network != "udp6" {
		return nil, errors.New("owned DNS fixture supports only UDP")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp4", f.peer.LocalAddr().String())
	if err != nil {
		return nil, err
	}
	raw, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("owned DNS dial did not return a UDP socket")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopping {
		_ = raw.Close()
		return nil, net.ErrClosed
	}
	f.conns = append(f.conns, raw)
	return raw, nil
}

func (f *nativeQUICDNSSuccessFixture) serve() {
	buf := make([]byte, 4096)
	for {
		n, from, err := f.peer.ReadFromUDP(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				f.note(err)
			}
			return
		}
		var query dnsmessage.Message
		if err := query.Unpack(buf[:n]); err != nil || query.Header.Response || len(query.Questions) != 1 {
			f.note(errors.New("invalid actual DNS query framing"))
			continue
		}
		question := query.Questions[0]
		if !strings.EqualFold(question.Name.String(), nativeQUICDNSSuccessName) || question.Class != dnsmessage.ClassINET ||
			(question.Type != dnsmessage.TypeA && question.Type != dnsmessage.TypeAAAA) {
			f.note(errors.New("unexpected DNS question outside the owned relay name"))
			continue
		}
		response := dnsmessage.Message{Header: dnsmessage.Header{ID: query.Header.ID, Response: true,
			Authoritative: true, RecursionAvailable: true}, Questions: query.Questions}
		if question.Type == dnsmessage.TypeA {
			response.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{
				Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60,
			}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}}}
		}
		payload, err := response.Pack()
		if err == nil {
			_, err = f.peer.WriteToUDP(payload, from)
		}
		if err != nil {
			f.note(err)
			continue
		}
		f.mu.Lock()
		f.queries++
		if question.Type == dnsmessage.TypeA {
			f.answers++
		}
		f.mu.Unlock()
	}
}

func (f *nativeQUICDNSSuccessFixture) note(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopping && errors.Is(err, net.ErrClosed) {
		return // An owned peer/socket Close may interrupt its final response.
	}
	if f.problem == nil {
		f.problem = err
	}
}

func (f *nativeQUICDNSSuccessFixture) stop() {
	f.mu.Lock()
	f.stopping = true
	conns := append([]*net.UDPConn(nil), f.conns...)
	f.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	_ = f.peer.Close()
}

func nativeQUICDNSSuccessTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()),
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true,
		DNSNames: []string{strings.TrimSuffix(nativeQUICDNSSuccessName, ".")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}},
		&tls.Config{RootCAs: pool} // ServerName intentionally unset; no IP SAN exists.
}
