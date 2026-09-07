package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/cppla/autocar/internal/transport"
)

func newWebH3RetirementClient(t *testing.T, maxStreams int64, dialer transport.Dialer, resolver UDPResolver) *WebH3Client {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	if dialer == nil {
		dialer = transport.DialFunc((&net.Dialer{}).DialContext)
	}
	server, err := ListenWebH3(WebH3ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
		Dialer: dialer, Cover: http.NotFoundHandler(), UDPResolver: resolver,
		QUICConfig: &quic.Config{MaxIncomingStreams: maxStreams, MaxIdleTimeout: 200 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	serveWebH3ForTest(t, server)
	client, err := NewWebH3Client(WebH3ClientConfig{
		ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
		FingerprintProfile: H3FingerprintNative, HandshakeTimeout: 250 * time.Millisecond,
		QUICConfig: &quic.Config{MaxIdleTimeout: 200 * time.Millisecond, KeepAlivePeriod: 20 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func webH3SelectedSession(t *testing.T, client *WebH3Client) *webH3ClientSession {
	t.Helper()
	client.mu.Lock()
	defer client.mu.Unlock()
	session := client.conns[client.conn]
	if session == nil {
		t.Fatal("missing selected H3 session")
	}
	return session
}

func assertWebH3SessionUsers(t *testing.T, client *WebH3Client, session *webH3ClientSession, want int) {
	t.Helper()
	client.mu.Lock()
	got := session.users
	client.mu.Unlock()
	if got != want {
		t.Fatalf("session owners = %d, want %d", got, want)
	}
}

func assertWebH3SessionRetired(t *testing.T, client *WebH3Client, session *webH3ClientSession) {
	t.Helper()
	select {
	case <-session.conn.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("retired H3 session was kept alive after its final owner closed")
	}
	eventuallyWebUDP(t, func() bool {
		client.mu.Lock()
		defer client.mu.Unlock()
		return client.conns[session.conn] == nil
	}, "retired H3 session was not removed from tracking")
	assertWebH3SessionUsers(t, client, session, 0)
}

func assertWebH3StreamEcho(t *testing.T, stream net.Conn) {
	t.Helper()
	if err := stream.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte("live")); err != nil {
		t.Fatal(err)
	}
	var payload [4]byte
	if _, err := io.ReadFull(stream, payload[:]); err != nil || string(payload[:]) != "live" {
		t.Fatalf("sibling echo = %q, %v", payload, err)
	}
	if err := stream.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestWebH3RetirementAfterStreamCapacityTimeout(t *testing.T) {
	client := newWebH3RetirementClient(t, 1, nil, nil)
	target := startWebTCPEcho(t)
	sibling, err := client.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sibling.Close() })
	old := webH3SelectedSession(t, client)
	blocked, err := client.DialContext(context.Background(), "tcp", target)
	if blocked != nil {
		_ = blocked.Close()
		t.Fatal("second stream unexpectedly opened with a one-stream limit")
	}
	if err == nil {
		t.Fatal("expected stream capacity timeout")
	}
	assertWebH3SessionUsers(t, client, old, 1)
	// Retirement is not a connection-wide abort. Keepalive keeps the old
	// session live beyond its idle timeout while its existing stream works.
	select {
	case <-old.conn.Context().Done():
		t.Fatal("retirement aborted a live sibling")
	case <-time.After(400 * time.Millisecond):
	}
	assertWebH3StreamEcho(t, sibling)
	replacement, err := client.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = replacement.Close() })
	if webH3SelectedSession(t, client) == old {
		t.Fatal("new request selected the retired session")
	}
	_ = sibling.Close()
	_ = sibling.Close() // Stream ownership is released exactly once.
	assertWebH3SessionRetired(t, client, old)
	assertWebH3StreamEcho(t, replacement)
}

func TestWebH3RetirementProtectsPendingOpen(t *testing.T) {
	target := startWebTCPEcho(t)
	entered, proceed := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(proceed) }) })
	dialer := transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "pending.example:443" {
			close(entered)
			select {
			case <-proceed:
			case <-ctx.Done():
				return nil, context.Cause(ctx)
			}
		}
		return (&net.Dialer{}).DialContext(ctx, network, target)
	})
	client := newWebH3RetirementClient(t, 4, dialer, nil)
	sibling, err := client.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sibling.Close() })
	old := webH3SelectedSession(t, client)
	type result struct {
		conn net.Conn
		err  error
	}
	opened := make(chan result, 1)
	go func() {
		conn, err := client.DialContext(context.Background(), "tcp", "pending.example:443")
		opened <- result{conn, err}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("pending request did not reach destination dial")
	}
	client.retire(old.conn)
	_ = sibling.Close()
	assertWebH3SessionUsers(t, client, old, 1)
	if old.conn.Context().Err() != nil {
		t.Fatal("retirement closed a session with a pending request")
	}
	unblock.Do(func() { close(proceed) })
	var pending net.Conn
	select {
	case result := <-opened:
		if result.err != nil {
			t.Fatal(result.err)
		}
		pending = result.conn
	case <-time.After(2 * time.Second):
		t.Fatal("pending request did not finish opening")
	}
	t.Cleanup(func() { _ = pending.Close() })
	assertWebH3StreamEcho(t, pending)
	_ = pending.Close()
	assertWebH3SessionRetired(t, client, old)
}

func TestWebH3RetirementReleasesCanceledOpen(t *testing.T) {
	client := newWebH3RetirementClient(t, 1, nil, nil)
	target := startWebTCPEcho(t)
	sibling, err := client.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sibling.Close() })
	old := webH3SelectedSession(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	stream, err := client.DialContext(ctx, "tcp", target)
	if stream != nil {
		_ = stream.Close()
		t.Fatal("blocked request unexpectedly succeeded")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled open error = %v", err)
	}
	assertWebH3SessionUsers(t, client, old, 1)
	if webH3SelectedSession(t, client) != old {
		t.Fatal("caller cancellation retired a usable session")
	}
	client.retire(old.conn)
	_ = sibling.Close()
	assertWebH3SessionRetired(t, client, old)
}

func TestWebH3RetirementTracksMixedTCPAndUDP(t *testing.T) {
	udpTarget := startWebUDPEcho(t)
	resolver := newWebUDPTestResolver(map[string]netip.AddrPort{udpTarget.String(): udpTarget})
	client := newWebH3RetirementClient(t, 4, nil, resolver)
	tcp, err := client.DialContext(context.Background(), "tcp", startWebTCPEcho(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcp.Close() })
	packet, err := client.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packet.Close() })
	assertWebUDPEcho(t, packet, []byte("before retirement"), udpTarget.String())
	old := webH3SelectedSession(t, client)
	assertWebH3SessionUsers(t, client, old, 2)
	client.retire(old.conn)
	_ = tcp.Close()
	assertWebH3SessionUsers(t, client, old, 1)
	assertWebUDPEcho(t, packet, []byte("after TCP closes"), udpTarget.String())
	_ = packet.Close()
	_ = packet.Close()
	assertWebH3SessionRetired(t, client, old)
	if got := len(client.udpSlots); got != 0 {
		t.Fatalf("UDP slot count after close = %d, want zero", got)
	}
}

func TestWebH3RetirementReleasesAuthenticatedUDPRejection(t *testing.T) {
	resolver := newWebUDPTestResolver(map[string]netip.AddrPort{})
	client := newWebH3RetirementClient(t, 4, nil, resolver)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	opened, err := client.openConnectUDPSession(ctx, "missing.example:443")
	if opened != nil {
		opened.close()
		t.Fatal("UDP request unexpectedly succeeded")
	}
	var rejection *WebConnectError
	if !errors.As(err, &rejection) {
		t.Fatalf("UDP request error = %v, want an authenticated rejection", err)
	}
	old := webH3SelectedSession(t, client)
	assertWebH3SessionUsers(t, client, old, 0)
	client.retire(old.conn)
	assertWebH3SessionRetired(t, client, old)
}

func TestWebH3RetirementPreservesHalfClosedResponse(t *testing.T) {
	target, closeTarget := startHalfCloseTarget(t)
	t.Cleanup(closeTarget)
	client := newWebH3RetirementClient(t, 4, nil, nil)
	conn, err := client.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	old := webH3SelectedSession(t, client)
	client.retire(old.conn)
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("half-close")); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*webH3Conn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	assertWebH3SessionUsers(t, client, old, 1)
	response, err := io.ReadAll(conn)
	if err != nil || string(response) != "reply:half-close" {
		t.Fatalf("half-closed response = %q, %v", response, err)
	}
	_ = conn.Close()
	assertWebH3SessionRetired(t, client, old)
}

func TestWebH3RetirementClientCloseTerminatesLiveOwners(t *testing.T) {
	client := newWebH3RetirementClient(t, 4, nil, nil)
	conn, err := client.DialContext(context.Background(), "tcp", startWebTCPEcho(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	old := webH3SelectedSession(t, client)
	client.retire(old.conn)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-old.conn.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("client Close left a retired session running")
	}
	// Closing a stream after client shutdown still releases its reservation,
	// without relying on the session remaining in the tracking map.
	_ = conn.Close()
	assertWebH3SessionRetired(t, client, old)
}
