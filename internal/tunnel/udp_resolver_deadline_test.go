package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

type udpResolverDeadlineReceipt struct {
	payload []byte
	source  netip.AddrPort
}

type udpResolverDeadlineRequest struct {
	auth   *webServerConnectionAuth
	full   bool
	short  bool
	proof  bool // Inspected only after joined closes.
	joined chan struct{}
}

type udpResolverDeadlineTransfer struct {
	firstErr error
	err      error
	replies  []packetReceiveResult
}

// The sole synthetic behavior is a resolver returning a real owned address
// with nil error after its actual server-side context deadline. TLS, QUIC,
// authentication, UDP writes, replies and subsequent association reuse are real.
func TestUDPResolverDeadlineRejectsLateSuccess(t *testing.T) {
	for _, mode := range []string{"native_quic", "h3"} {
		t.Run(mode, func(t *testing.T) {
			f := newWebH2DialSharingFixture(t)
			caller, stopCaller := context.WithTimeout(f.ctx, 2*time.Second)
			defer stopCaller()
			echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			target := echo.LocalAddr().(*net.UDPAddr).AddrPort()
			f.close = append(f.close, func() { _ = echo.Close() })
			receipts := make(chan udpResolverDeadlineReceipt, 3)
			echoJoined := make(chan struct{})
			f.register(echoJoined)
			var echoErr error
			var unexpected atomic.Int32
			f.checks = append(f.checks, func() {
				if echoErr != nil {
					t.Errorf("owned UDP echo: %v", echoErr)
				}
			})
			go func() {
				defer close(echoJoined)
				buffer := make([]byte, 256)
				for {
					if err := echo.SetDeadline(time.Now().Add(7 * time.Second)); err != nil {
						echoErr = err
						return
					}
					n, source, err := echo.ReadFromUDPAddrPort(buffer)
					if err != nil {
						if !errors.Is(err, net.ErrClosed) {
							echoErr = err
						}
						return
					}
					select {
					case receipts <- udpResolverDeadlineReceipt{append([]byte(nil), buffer[:n]...), source}:
					default:
						unexpected.Add(1)
					}
					if _, err := echo.WriteToUDPAddrPort(buffer[:n], source); err != nil {
						if !errors.Is(err, net.ErrClosed) {
							echoErr = err
						}
						return
					}
				}
			}()

			expired, firstResolverJoined := make(chan error, 1), make(chan struct{})
			var resolutions atomic.Int32
			resolver := UDPResolverFunc(func(ctx context.Context, address string) ([]netip.AddrPort, error) {
				joined := make(chan struct{})
				f.register(joined)
				defer close(joined)
				if address != target.String() {
					unexpected.Add(1)
					return nil, errors.New("UDP deadline fixture refuses a non-owned numeric target")
				}
				if resolutions.Add(1) == 1 {
					defer close(firstResolverJoined)
					select {
					case <-ctx.Done():
						expired <- context.Cause(ctx)
					case <-f.ctx.Done():
						return nil, context.Cause(f.ctx)
					}
				}
				return []netip.AddrPort{target}, nil
			})
			serverTLS, clientTLS := testTLSConfigs(t)
			var packet transport.PacketConn
			var h3 *WebH3Client
			var native *Client
			var h3Handler *webTunnelHandler
			var nativeServer *QUICServer
			var closeServer func() error
			var serve func(context.Context) error
			var entropy webH2AuthEntropyCounter
			requests := make(chan *udpResolverDeadlineRequest, 3)
			var requestCount atomic.Int32
			refuseTCP := transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
				unexpected.Add(1)
				return nil, errors.New("UDP deadline fixture never dials TCP")
			})
			if mode == "native_quic" {
				nativeServer, err = ListenQUIC(QUICServerConfig{
					Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
					Dialer: refuseTCP, UDPResolver: resolver, DialTimeout: 100 * time.Millisecond,
					HandshakeTimeout: time.Second, MaxUDPSessions: 1, MaxClientUDPSessions: 1,
					MaxUDPDestinations: 1,
				})
				if err != nil {
					t.Fatal(err)
				}
				closeServer, serve = nativeServer.Close, nativeServer.Serve
				native, err = NewClient(ClientConfig{
					ServerAddress: nativeServer.Addr().String(), Token: testToken, TLSConfig: clientTLS,
					QUICDialTimeout: time.Second, HandshakeTimeout: time.Second, MaxUDPSessions: 1,
				})
			} else {
				server, serverErr := ListenWebH3(WebH3ServerConfig{
					Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
					Dialer: refuseTCP, UDPResolver: resolver, DialTimeout: 100 * time.Millisecond,
					HandshakeTimeout: time.Second, MaxUDPSessions: 1, MaxClientUDPSessions: 1,
					MaxUDPDestinations: 1,
					Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						unexpected.Add(1)
						http.NotFound(w, r)
					}),
				})
				if serverErr != nil {
					t.Fatal(serverErr)
				}
				closeServer, serve = server.Close, server.Serve
				h3Handler = server.server.Handler.(*webTunnelHandler)
				original := server.server.Handler
				server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requestCount.Add(1)
					joined := make(chan struct{})
					f.register(joined)
					defer close(joined)
					auth, _ := r.Context().Value(webServerConnectionAuthContextKey{}).(*webServerConnectionAuth)
					bearer := r.Header.Get("Proxy-Authorization")
					_, short := parseWebSessionBearer(bearer)
					request := &udpResolverDeadlineRequest{auth: auth, full: len(bearer) >= 385 && len(bearer) <= 2047, short: short, joined: joined}
					select {
					case requests <- request:
					default:
						unexpected.Add(1)
					}
					original.ServeHTTP(w, r)
					request.proof = w.Header().Get(webAuthResponseHeader) != ""
				})
				h3, err = NewWebH3Client(WebH3ClientConfig{
					ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
					FingerprintProfile: H3FingerprintNative, DialTimeout: time.Second, HandshakeTimeout: time.Second,
					MaxUDPSessions: 1, MaxUDPDestinations: 1,
				})
			}
			// Publish server cleanup before any possible client constructor failure.
			f.close = append(f.close, func() {
				if err := normalizeWebServerCloseError(closeServer()); err != nil {
					t.Errorf("owned UDP server Close: %v", err)
				}
			})
			if err != nil {
				t.Fatal(err)
			}
			if h3 != nil {
				h3.signer = newWebAuthSigner(mustWebAuthKey(t, webTestToken), nil, &entropy)
				f.close = append(f.close, func() { _ = h3.Close() })
			} else {
				f.close = append(f.close, func() { _ = native.Close() })
			}
			serveJoined, serveResult := make(chan struct{}), make(chan error, 1)
			f.register(serveJoined)
			f.checks = append(f.checks, func() {
				if err := <-serveResult; err != nil {
					t.Errorf("owned UDP Serve: %v", err)
				}
			})
			go func() { defer close(serveJoined); serveResult <- serve(f.ctx) }()
			if h3 != nil {
				packet, err = h3.DialPacket(caller)
			} else {
				packet, err = native.DialPacket(caller)
			}
			if err != nil {
				t.Fatal(err)
			}
			f.close = append(f.close, func() { _ = packet.Close() })
			var initialH3Session *webH3ClientSession
			var verified tls.ConnectionState
			if h3 != nil {
				h3.mu.Lock()
				initialH3Session = h3.conns[h3.conn]
				h3.mu.Unlock()
				if initialH3Session == nil {
					t.Fatal("public H3 packet opening did not retain a physical session")
				}
				verified = initialH3Session.conn.ConnectionState().TLS
			} else {
				verified = packet.(*quicPacketConn).dispatcher.conn.ConnectionState().TLS
			}
			if verified.Version != tls.VersionTLS13 || len(verified.VerifiedChains) == 0 {
				t.Fatal("public packet opening did not actually verify TLS1.3")
			}

			releaseHealthy := make(chan struct{})
			ungate := sync.OnceFunc(func() { close(releaseHealthy) })
			f.close = append(f.close, ungate)
			firstSent, transferJoined := make(chan error, 1), make(chan struct{})
			transferResult := make(chan udpResolverDeadlineTransfer, 1)
			f.register(transferJoined)
			const late, healthyOne, healthyTwo = "late-result-must-not-deliver", "healthy-one", "healthy-two"
			go func() {
				defer close(transferJoined)
				result := udpResolverDeadlineTransfer{firstErr: packet.Send([]byte(late), target.String())}
				firstSent <- result.firstErr
				select {
				case <-releaseHealthy:
				case <-f.ctx.Done():
					result.err = context.Cause(f.ctx)
					transferResult <- result
					return
				}
				for _, payload := range []string{healthyOne, healthyTwo} {
					if err := packet.Send([]byte(payload), target.String()); err != nil {
						result.err = err
						transferResult <- result
						return
					}
				}
				// Two healthy replies, plus the old implementation's unexpected late
				// reply, fit this fixed bound. Close independently unblocks Receive.
				seen := make(map[string]bool)
				for len(result.replies) < 3 && len(seen) < 2 {
					payload, address, err := packet.Receive()
					if err != nil {
						result.err = err
						break
					}
					result.replies = append(result.replies, packetReceiveResult{payload: payload, address: address})
					if string(payload) == healthyOne || string(payload) == healthyTwo {
						seen[string(payload)] = true
					}
				}
				transferResult <- result
			}()
			select {
			case cause := <-expired:
				if cause != context.DeadlineExceeded {
					t.Errorf("resolver's actual server budget ended with %v, want DeadlineExceeded", cause)
				}
			case <-f.ctx.Done():
				t.Fatal("resolver did not reach its actual configured server deadline")
			}
			f.wait(firstResolverJoined, "late successful resolver callback")
			var firstErr error
			select {
			case firstErr = <-firstSent:
			case <-f.ctx.Done():
				t.Fatal("first public packet Send exceeded fixture budget")
			}
			var firstRequest *udpResolverDeadlineRequest
			if h3 != nil && firstErr != nil {
				// At capacity one, join the rejected handler's real admission
				// release before opening the healthy target. Old success owns a
				// live handler and must instead continue to the healthy controls.
				select {
				case firstRequest = <-requests:
				case <-f.ctx.Done():
					t.Fatal("rejected first H3 request observation missing")
				}
				f.wait(firstRequest.joined, "first rejected CONNECT-UDP handler completed")
			}
			if err := caller.Err(); err != nil {
				t.Fatalf("caller ended before the server-only deadline witness: %v", err)
			}
			ungate()
			f.wait(transferJoined, "real public packet payload transfer")
			result := <-transferResult
			if mode == "native_quic" {
				if result.firstErr != nil {
					t.Errorf("native queued first Send: %v", result.firstErr)
				}
			} else {
				var refused *WebConnectError
				if !errors.Is(result.firstErr, transport.ErrPacketTargetUnavailable) || !errors.As(result.firstErr, &refused) || refused.StatusCode != http.StatusBadGateway {
					t.Errorf("late H3 resolution Send=%v, want recoverable authenticated 502", result.firstErr)
				}
			}
			if result.err != nil {
				t.Errorf("later same-association transfer: %v", result.err)
			}
			if len(result.replies) != 2 || string(result.replies[0].payload) != healthyOne || string(result.replies[1].payload) != healthyTwo {
				t.Errorf("same-association replies=%+v, want exactly the two healthy payloads", result.replies)
			}
			for _, reply := range result.replies {
				if reply.address != target.String() {
					t.Errorf("public packet reply source=%q, want owned target %q", reply.address, target.String())
				}
			}
			var observed []udpResolverDeadlineReceipt
			for len(observed) < len(result.replies) {
				select {
				case receipt := <-receipts:
					observed = append(observed, receipt)
				case <-f.ctx.Done():
					t.Fatal("real reply lacked its owned origin receipt")
				}
			}
			if len(observed) != 2 || !bytes.Equal(observed[0].payload, []byte(healthyOne)) || !bytes.Equal(observed[1].payload, []byte(healthyTwo)) {
				t.Errorf("origin receipt order=%+v, want healthy first and no expired-resolution payload", observed)
			}
			if len(observed) >= 2 && observed[len(observed)-2].source != observed[len(observed)-1].source {
				t.Error("two healthy packets did not reuse the same relay UDP socket")
			}
			if h3 != nil {
				h3.mu.Lock()
				same := h3.conns[h3.conn] == initialH3Session
				ready := initialH3Session.authState == webH3ClientAuthReady && initialH3Session.auth != nil && !initialH3Session.retired
				h3.mu.Unlock()
				if !same || !ready || initialH3Session.conn.Context().Err() != nil || entropy.nonceReads.Load() != 1 {
					t.Errorf("H3 same/Ready/live/nonce=%t/%t/%t/%d", same, ready, initialH3Session.conn.Context().Err() == nil, entropy.nonceReads.Load())
				}
			}
			if err := packet.Close(); err != nil {
				t.Error(err)
			}
			if h3 != nil {
				var auth *webServerConnectionAuth
				count := int(requestCount.Load())
				for i := 0; i < count; i++ {
					request := firstRequest
					if i != 0 || request == nil {
						select {
						case request = <-requests:
						case <-f.ctx.Done():
							t.Fatal("actual H3 request observation missing")
						}
					}
					f.wait(request.joined, "actual CONNECT-UDP handler completed")
					if request.auth == nil || !request.proof || (i == 0 && (!request.full || request.short)) || (i > 0 && (!request.short || request.full || request.auth != auth)) {
						t.Errorf("actual H3 request %d lost full/short/proof/physical authentication continuity", i)
					}
					auth = request.auth
				}
				if count != 2 || resolutions.Load() != 2 || len(h3.udpSlots) != 0 || len(h3Handler.udp.slots) != 0 {
					t.Errorf("H3 request/resolver/client/server slots=%d/%d/%d/%d, want 2/2/0/0", count, resolutions.Load(), len(h3.udpSlots), len(h3Handler.udp.slots))
				}
			} else if resolutions.Load() != 3 {
				t.Errorf("native resolver calls=%d, want one expired and two healthy", resolutions.Load())
			}
			if unexpected.Load() != 0 {
				t.Errorf("unexpected request/target/echo overflow count=%d", unexpected.Load())
			}
			t.Log(fmt.Sprintf("%s: actual 100ms server resolver deadline; healthy same-association UDP socket, complete payload replies and independent joins evaluated", mode))
		})
	}
}
