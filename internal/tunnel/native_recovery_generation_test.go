package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/protocol"
	quic "github.com/quic-go/quic-go"
)

// The first request stays pending until a later request has proved that the
// shared QUIC path is healthy. Only then does the peer reset the older stream.
// The failed request may use TLS, but it must not send subsequent requests into
// a fresh fallback cooldown. Channel ordering avoids a timing-dependent race.
func TestNativeLateFailurePreservesNewerQUICHealth(t *testing.T) {
	for _, health := range []string{"tcp", "udp", "authenticated-error"} {
		t.Run(health, func(t *testing.T) {
			target, closeTarget := startHalfCloseTarget(t)
			defer closeTarget()
			serverTLS, clientTLS := testTLSConfigs(t)
			fallback := startTLSServer(t, serverTLS, &net.Dialer{}, testToken)
			entered, release := make(chan struct{}), make(chan struct{})
			primary := startNativeRecoveryPeer(t, serverTLS, entered, release)
			client, err := NewClient(ClientConfig{
				ServerAddress: primary, FallbackAddress: fallback.Addr().String(),
				Token: testToken, TLSConfig: clientTLS,
				PrimaryAttemptTimeout: 5 * time.Second, FallbackCooldown: time.Hour,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			olderDone := make(chan error, 1)
			go func() {
				conn, err := client.DialContext(ctx, "tcp", target)
				if conn != nil {
					_ = conn.Close()
				}
				olderDone <- err
			}()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("older QUIC request did not reach the peer")
			}
			switch health {
			case "tcp":
				conn, err := client.DialContext(ctx, "tcp", "healthy.test:443")
				if err != nil {
					t.Fatal(err)
				}
				_ = conn.Close()
			case "udp":
				packet, err := client.DialPacket(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer packet.Close()
			case "authenticated-error":
				_, err := client.DialContext(ctx, "tcp", "rejected.test:443")
				var remoteErr *RemoteError
				if !errors.As(err, &remoteErr) {
					t.Fatalf("health response = %v, want authenticated rejection", err)
				}
			}
			close(release)
			select {
			case err := <-olderDone:
				if err != nil {
					t.Fatalf("older stream did not retain its TLS fallback: %v", err)
				}
			case <-ctx.Done():
				t.Fatal("older stream did not finish")
			}
			conn, err := client.DialContext(ctx, "tcp", target)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, ok := conn.(*quicStreamConn); !ok {
				t.Fatalf("new stream used %T: older failure reopened a healthy QUIC circuit", conn)
			}
		})
	}
}

func TestNativePrimaryCompletionOwnsOnlyItsProbe(t *testing.T) {
	for _, completion := range []string{"canceled", "failed", "stale-failure"} {
		t.Run(completion, func(t *testing.T) {
			now := time.Date(2026, time.September, 14, 0, 0, 0, 0, time.UTC)
			client := &Client{fallbackCooldown: time.Second}
			_, _, older := client.shouldTryPrimary(now)
			if completion == "stale-failure" {
				client.primaryHealthy()
			}
			_, _, failed := client.shouldTryPrimary(now)
			client.primaryFailed(failed, now, ClientReasonQUICAttemptTimeout)
			try, _, probe := client.shouldTryPrimary(now.Add(time.Second))
			if !try || probe.id == 0 {
				t.Fatal("half-open probe was not admitted")
			}
			if completion == "canceled" {
				client.primaryProbeFinished(older)
			} else {
				client.primaryFailed(older, now.Add(time.Second), ClientReasonQUICHandshakeFailed)
			}
			if try, _, _ := client.shouldTryPrimary(now.Add(time.Hour)); try {
				t.Fatal("older completion released another caller's half-open probe")
			}
			client.primaryProbeFinished(probe)
			if try, _, replacement := client.shouldTryPrimary(now.Add(time.Hour)); !try || replacement.id == probe.id {
				t.Fatal("canceling the owning probe did not permit one replacement")
			}
		})
	}
}

func TestNativeCurrentFailureStillOpensCooldown(t *testing.T) {
	now := time.Date(2026, time.September, 14, 0, 0, 0, 0, time.UTC)
	client := &Client{fallbackCooldown: time.Second}
	client.primaryHealthy()
	_, _, attempt := client.shouldTryPrimary(now)
	client.primaryFailed(attempt, now, ClientReasonQUICAttemptTimeout)
	if try, reason, _ := client.shouldTryPrimary(now); try || reason != ClientReasonQUICAttemptTimeout {
		t.Fatalf("current failure did not open cooldown: try=%v reason=%q", try, reason)
	}
	if try, _, _ := client.shouldTryPrimary(now.Add(time.Second)); !try {
		t.Fatal("current failure changed the configured cooldown duration")
	}
}

func TestNativeSharedDialFailurePreservesLaterHealth(t *testing.T) {
	_, clientTLS := testTLSConfigs(t)
	client, err := NewClient(ClientConfig{
		ServerAddress: "127.0.0.1:4433", FallbackAddress: "127.0.0.1:4433",
		Token: testToken, TLSConfig: clientTLS, QUICDialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	dialFailure := errors.New("controlled older shared dial failure")
	client.dialQUIC = func(ctx context.Context, _ string, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
		close(entered)
		select {
		case <-release:
			return nil, dialFailure
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
	}
	done := make(chan error, 1)
	go func() {
		_, err := client.connection(context.Background())
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("shared dial did not start")
	}
	client.primaryHealthy()
	close(release)
	if err := <-done; !errors.Is(err, dialFailure) {
		t.Fatalf("shared dial = %v, want controlled failure", err)
	}
	if try, _, _ := client.shouldTryPrimary(time.Now()); !try {
		t.Fatal("background dial failure reopened a circuit after later health evidence")
	}
}

func startNativeRecoveryPeer(t *testing.T, config *tls.Config, entered chan<- struct{}, release <-chan struct{}) string {
	t.Helper()
	listener, err := quic.ListenAddr("127.0.0.1:0", mustServerTLSConfig(t, config), hardenedQUICServerConfig(nil, 16))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept(ctx)
		if err != nil {
			return
		}
		defer conn.CloseWithError(applicationShutdown, "test finished")
		var handlers sync.WaitGroup
		defer handlers.Wait()
		for index := 0; ; index++ {
			stream, err := conn.AcceptStream(ctx)
			if err != nil {
				return
			}
			handlers.Add(1)
			go func(first bool) {
				defer handlers.Done()
				defer stream.CancelRead(streamCanceled)
				request, err := protocol.ReadRequest(stream)
				if err != nil {
					return
				}
				if first {
					close(entered)
					select {
					case <-release:
					case <-ctx.Done():
					}
					stream.CancelWrite(streamCanceled)
					return
				}
				response := protocol.Response{
					Status: protocol.StatusOK,
					TxMode: request.TxMode, TxProfile: request.TxProfile,
					RxMode: protocol.PacingAdaptive, RxProfile: protocol.ProfileBalanced,
				}
				if request.Network == protocol.NetworkUDP {
					response.SessionID = 42
				}
				if request.Address == "rejected.test:443" {
					response.Status = protocol.StatusDialFailed
				}
				if err := protocol.WriteResponse(stream, response); err != nil {
					return
				}
				if request.Network == protocol.NetworkUDP {
					select {
					case <-ctx.Done():
					case <-stream.Context().Done():
					}
				}
				_ = stream.Close()
			}(index == 0)
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		<-done
	})
	return listener.Addr().String()
}
