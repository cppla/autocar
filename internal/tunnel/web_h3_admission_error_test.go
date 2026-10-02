package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/cppla/autocar/internal/transport"
)

type webH3AdmissionErrorPeer struct {
	packet    net.PacketConn
	transport *quic.Transport
	conn      *quic.Conn
	http      *http3.Transport
	client    *http3.ClientConn
	closeOnce sync.Once
	closeErr  error
}

func (p *webH3AdmissionErrorPeer) close() error {
	p.closeOnce.Do(func() {
		if p.conn != nil {
			p.closeErr = errors.Join(p.closeErr, p.conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), ""))
		}
		if p.http != nil {
			p.closeErr = errors.Join(p.closeErr, p.http.Close())
		}
		p.closeErr = errors.Join(p.closeErr, p.transport.Close(), p.packet.Close())
	})
	return p.closeErr
}

type webH3AdmissionErrorAccepted struct {
	conn *quic.Conn
	auth *webServerConnectionAuth
}

type webH3AdmissionErrorFixture struct {
	t         *testing.T
	ctx       context.Context
	clientTLS *tls.Config
	server    *WebH3Server
	peers     []*webH3AdmissionErrorPeer
	mu        sync.Mutex
	accepted  []webH3AdmissionErrorAccepted
	covers    atomic.Int64
	dials     atomic.Int64
	resolves  atomic.Int64
	encoding  atomic.Bool
}

func newWebH3AdmissionErrorFixture(t *testing.T, global, perSource int) *webH3AdmissionErrorFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	serverTLS, clientTLS := testTLSConfigs(t)
	clientTLS = clientTLS.Clone()
	clientTLS.NextProtos = []string{http3.NextProtoH3}
	f := &webH3AdmissionErrorFixture{t: t, ctx: ctx, clientTLS: clientTLS}
	server, err := ListenWebH3(WebH3ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
		MaxConnections: global, MaxClientConnections: perSource,
		HandshakeTimeout: time.Second, DialTimeout: time.Second,
		Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
			f.dials.Add(1)
			return nil, errors.New("admission fixture forbids destination dialing")
		}),
		UDPResolver: UDPResolverFunc(func(context.Context, string) ([]netip.AddrPort, error) {
			f.resolves.Add(1)
			return nil, errors.New("admission fixture forbids destination resolution")
		}),
		Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			f.covers.Add(1)
			if r.Header.Get("Accept-Encoding") != "" {
				f.encoding.Store(true)
			}
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("X-Owned-Cover", "admission")
			_, _ = io.WriteString(w, "ordinary:"+r.URL.Path)
		}),
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	f.server = server
	originalContext := server.server.ConnContext
	// Installed before Serve. Only a genuinely admitted physical connection
	// reaches this hook; the original transport-owned auth state is preserved.
	server.server.ConnContext = func(ctx context.Context, conn *quic.Conn) context.Context {
		ctx = originalContext(ctx, conn)
		auth, _ := ctx.Value(webServerConnectionAuthContextKey{}).(*webServerConnectionAuth)
		f.mu.Lock()
		f.accepted = append(f.accepted, webH3AdmissionErrorAccepted{conn, auth})
		f.mu.Unlock()
		return ctx
	}
	serveResult, serveJoined := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(serveJoined)
		serveResult <- server.Serve(ctx)
	}()
	t.Cleanup(func() {
		for _, peer := range f.peers {
			if err := peer.close(); err != nil {
				t.Errorf("owned peer cleanup: %v", err)
			}
		}
		if err := server.Close(); err != nil {
			t.Errorf("owned server cleanup: %v", err)
		}
		// Finish exact-owned socket/connection Close before canceling Serve;
		// otherwise its Shutdown can race our Close on the packet socket.
		cancel()
		select {
		case <-serveJoined:
			if err := <-serveResult; err != nil {
				t.Errorf("owned Serve: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("owned Serve worker did not join")
		}
		f.waitReleased()
	})
	return f
}

func (f *webH3AdmissionErrorFixture) dial() (*webH3AdmissionErrorPeer, error) {
	f.t.Helper()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		f.t.Fatal(err)
	}
	peer := &webH3AdmissionErrorPeer{packet: packet, transport: &quic.Transport{Conn: packet}}
	f.peers = append(f.peers, peer)
	ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
	defer cancel()
	peer.conn, err = peer.transport.Dial(ctx, f.server.Addr(), f.clientTLS, &quic.Config{
		Versions: []quic.Version{quic.Version1}, HandshakeIdleTimeout: time.Second, MaxIdleTimeout: 3 * time.Second,
	})
	return peer, err
}

func (f *webH3AdmissionErrorFixture) get(peer *webH3AdmissionErrorPeer, path string) {
	f.t.Helper()
	// NewClientConn does not register this connection in a Transport pool. The
	// fixture explicitly owns and closes its QUIC connection/Transport/socket.
	peer.http = &http3.Transport{DisableCompression: true, MaxResponseHeaderBytes: defaultWebClientMaxResponseHeaderBytes}
	peer.client = peer.http.NewClientConn(peer.conn)
	ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+f.server.Addr().String()+path, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	response, err := peer.client.RoundTrip(request)
	if err != nil {
		f.t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || response.ProtoMajor != 3 ||
		response.Header.Get("X-Owned-Cover") != "admission" || string(body) != "ordinary:"+path {
		f.t.Fatalf("real H3 GET status=%d protocol=%d body=%q read=%v close=%v", response.StatusCode, response.ProtoMajor, body, readErr, closeErr)
	}
	f.t.Logf("healthy real H3 GET %s: status=200 complete body=%q", path, body)
}

func (f *webH3AdmissionErrorFixture) sourceKey() string {
	return tlsSourceKey(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
}

func (f *webH3AdmissionErrorFixture) waitReleased() {
	f.t.Helper()
	// Low-frequency observation of actual release state, not a mock Close or
	// an entry witness. An independent cleanup budget also works after f.ctx
	// has been canceled. No packet retry or sleep-based scheduling assumption.
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if len(f.server.listener.admission.slots) == 0 && f.server.listener.admission.clients.count(f.sourceKey()) == 0 {
			return
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			f.t.Errorf("actual admission did not release: global=%d source=%d", len(f.server.listener.admission.slots), f.server.listener.admission.clients.count(f.sourceKey()))
			return
		}
	}
}

func (f *webH3AdmissionErrorFixture) assertState(covers, accepted, occupied int) {
	f.t.Helper()
	f.mu.Lock()
	connections := append([]webH3AdmissionErrorAccepted(nil), f.accepted...)
	f.mu.Unlock()
	for _, connection := range connections {
		if connection.auth == nil || connection.auth.phaseSnapshot() != webServerConnectionAuthFresh {
			f.t.Error("public GET changed actual physical connection authentication state")
		}
	}
	handler := f.server.server.Handler.(*webTunnelHandler)
	handler.auth.mu.Lock()
	nonces := len(handler.auth.nonces)
	handler.auth.mu.Unlock()
	if f.covers.Load() != int64(covers) || len(connections) != accepted || nonces != 0 ||
		len(handler.core.sem) != 0 || f.dials.Load() != 0 || f.resolves.Load() != 0 || f.encoding.Load() ||
		len(f.server.listener.admission.slots) != occupied || f.server.listener.admission.clients.count(f.sourceKey()) != occupied {
		f.t.Errorf("state cover=%d/%d admitted=%d/%d accepted-nonces=%d tunnel-slots=%d dials=%d resolves=%d compressed=%t physical-slots=%d/%d source-slots=%d/%d",
			f.covers.Load(), covers, len(connections), accepted, nonces, len(handler.core.sem), f.dials.Load(), f.resolves.Load(), f.encoding.Load(),
			len(f.server.listener.admission.slots), occupied, f.server.listener.admission.clients.count(f.sourceKey()), occupied)
	}
}

func TestWebH3AdmissionRejectsExcessiveLoad(t *testing.T) {
	for _, test := range []struct {
		name   string
		global int
	}{
		{name: "global_capacity", global: 1},
		{name: "per_source_capacity", global: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newWebH3AdmissionErrorFixture(t, test.global, 1)
			first, err := f.dial()
			if err != nil {
				t.Fatal(err)
			}
			f.get(first, "/first")
			f.assertState(1, 1, 1)
			f.mu.Lock()
			if len(f.accepted) != 1 {
				f.mu.Unlock()
				t.Fatal("first GET did not have exactly one actual admitted physical connection")
			}
			firstServer := f.accepted[0].conn
			f.mu.Unlock()

			second, err := f.dial()
			if err == nil {
				if second.conn == nil || second.conn == first.conn {
					t.Fatal("second dial did not create an independent physical QUIC connection")
				}
				select {
				case <-second.conn.Context().Done():
					err = context.Cause(second.conn.Context())
				case <-f.ctx.Done():
					t.Fatal("second physical connection was not rejected within independent fixture budget")
				}
			}
			var rejection *quic.ApplicationError
			if !errors.As(err, &rejection) || !rejection.Remote {
				t.Errorf("second physical connection did not receive a remote application rejection: %v", err)
			} else {
				t.Logf("actual remote rejection error-code=%#x", uint64(rejection.ErrorCode))
				if rejection.ErrorCode != quic.ApplicationErrorCode(http3.ErrCodeExcessiveLoad) {
					// Keep the real release/recovery controls running on the old
					// wrong-code baseline; do not inspect a private reason string.
					t.Errorf("actual H3 admission code=%#x want=%#x (H3_EXCESSIVE_LOAD)", uint64(rejection.ErrorCode), uint64(http3.ErrCodeExcessiveLoad))
				}
			}
			f.assertState(1, 1, 1)
			if err := second.close(); err != nil {
				t.Fatal(err)
			}
			if err := first.close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-firstServer.Context().Done():
			case <-f.ctx.Done():
				t.Fatal("actual first server connection did not close")
			}
			f.waitReleased()
			f.assertState(1, 1, 0)
			third, err := f.dial()
			if err != nil {
				t.Fatal(err)
			}
			f.get(third, "/third")
			f.assertState(2, 2, 1)
			if err := third.close(); err != nil {
				t.Fatal(err)
			}
			f.waitReleased()
			f.assertState(2, 2, 0)
			t.Logf("healthy recovery: cover calls=2, admitted connections=2, source/global slots=0, destination calls=0/0; limit=%d/1", test.global)
		})
	}
}
