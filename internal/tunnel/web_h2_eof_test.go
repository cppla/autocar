package tunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

func TestWebServerEOFFinishesResponse(t *testing.T) {
	for _, mode := range []string{"h2", "h3"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_, _ = io.WriteString(conn, "EOF-delimited response")
			}()
			serverTLS, clientTLS := testTLSConfigs(t)
			var dialer transport.Dialer
			if mode == "h2" {
				server := startWebH2TestServer(t, WebH2ServerConfig{
					Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
					Cover: http.NotFoundHandler(), Dialer: &net.Dialer{},
				})
				client, err := NewWebH2Client(WebH2ClientConfig{
					ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
				})
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				dialer = client
			} else {
				server, err := ListenWebH3(WebH3ServerConfig{
					Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
					Cover: http.NotFoundHandler(), Dialer: &net.Dialer{},
				})
				if err != nil {
					t.Fatal(err)
				}
				serveWebH3ForTest(t, server)
				client, err := NewWebH3Client(WebH3ClientConfig{
					ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
				})
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				dialer = client
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, err := dialer.DialContext(ctx, "tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			// No upload FIN: the actual destination's EOF must finish the reply.
			assertWebEOFBody(t, conn, []byte("EOF-delimited response"))
			if err := exchangeWebSessionEcho(dialer, startWebTCPEcho(t)); err != nil {
				t.Fatalf("another stream after target EOF: %v", err)
			}
		})
	}
}

func TestWebH2ClientHalfCloseDrainsLargeReply(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	payload := bytes.Repeat([]byte("reply"), 1<<18)
	targetDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			targetDone <- err
			return
		}
		defer conn.Close()
		if _, err := io.Copy(io.Discard, conn); err != nil {
			targetDone <- err
			return
		}
		_, err = io.Copy(conn, bytes.NewReader(payload))
		targetDone <- err
	}()
	serverTLS, clientTLS := testTLSConfigs(t)
	server := startWebH2TestServer(t, WebH2ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
		Cover: http.NotFoundHandler(), Dialer: &net.Dialer{},
	})
	client, err := NewWebH2Client(WebH2ClientConfig{
		ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, err := client.DialContext(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "upload"); err != nil {
		t.Fatal(err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	assertWebEOFBody(t, conn, payload)
	if err := <-targetDone; err != nil {
		t.Fatal(err)
	}
}

func TestWebH2LargeDestinationEOFLeavesSiblingUsable(t *testing.T) {
	payload := bytes.Repeat([]byte("response-"), 1<<20)
	upstream, target := net.Pipe()
	defer upstream.Close()
	defer target.Close()
	client := newWebH2DeadlineTestClient(t, transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "large.example:443" {
			return upstream, nil
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}))
	sibling := dialWebH2DeadlineTestConn(t, client, startWebTCPEcho(t))
	conn := dialWebH2DeadlineTestConn(t, client, "large.example:443")
	client.mu.Lock()
	session := client.current
	client.mu.Unlock()
	targetDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(target, bytes.NewReader(payload))
		_ = target.Close()
		targetDone <- err
	}()
	// The 9 MiB reply exceeds the client's receive window. Before reading
	// it, verify that an existing sibling still works while it is stalled.
	select {
	case err := <-targetDone:
		t.Fatalf("response did not reach stream flow control: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	assertWebSessionSiblingEcho(t, sibling)
	if err := sibling.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	// No client CloseWrite: the destination's EOF must finish a complete
	// multi-window response without truncation or closing the TLS session.
	assertWebEOFBody(t, conn, payload)
	select {
	case err := <-targetDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("destination writer did not drain")
	}
	assertWebSessionSiblingEcho(t, sibling)
	assertWebH2DeadlineSessionUnchanged(t, client, session)
}

func assertWebEOFBody(t *testing.T, conn net.Conn, expected []byte) {
	t.Helper()
	type result struct {
		body []byte
		err  error
	}
	readDone := make(chan result, 1)
	go func() {
		body, err := io.ReadAll(conn)
		readDone <- result{body: body, err: err}
	}()
	select {
	case got := <-readDone:
		if got.err != nil || !bytes.Equal(got.body, expected) {
			t.Fatalf("response bytes=%d want=%d error=%v", len(got.body), len(expected), got.err)
		}
	case <-time.After(3 * time.Second):
		_ = conn.Close()
		<-readDone
		t.Fatal("destination finished but response EOF was not delivered")
	}
}

func TestWebH2DestinationEOFInterruptsBlockedUpload(t *testing.T) {
	stream, client := net.Pipe()
	defer stream.Close()
	defer client.Close()
	upstream := &webEOFFakeConn{
		eof: make(chan struct{}), closed: make(chan struct{}), writing: make(chan struct{}),
	}
	defer upstream.Close()
	done := make(chan struct{})
	go func() { relayWebH2(stream, upstream); close(done) }()
	go func() { _, _ = client.Write([]byte("upload")) }()
	select {
	case <-upstream.writing:
	case <-time.After(time.Second):
		t.Fatal("upload did not reach the blocking destination writer")
	}
	close(upstream.eof)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("destination EOF did not interrupt the blocked upload")
	}
}

// Models a target that half-closes its sending direction while not reading
// uploads; the relay must close it to unblock an already in-progress Write.
type webEOFFakeConn struct {
	net.Conn
	eof, closed, writing chan struct{}
	once, writeOnce      sync.Once
}

func (c *webEOFFakeConn) Read([]byte) (int, error) {
	select {
	case <-c.eof:
		return 0, io.EOF
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *webEOFFakeConn) Write([]byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writing) })
	<-c.closed
	return 0, net.ErrClosed
}

func (c *webEOFFakeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
