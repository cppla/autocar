package tunnel

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

const destinationIntegrationWriteTimeout = 200 * time.Millisecond

// These are real authenticated client/server pairs. Only the destination is
// a controlled net.Pipe, whose unread peer guarantees a blocked network Write.
func TestDestinationWriteTimeoutReleasesStalledRelay(t *testing.T) {
	for _, mode := range []string{"quic", "tls", "h2", "h3"} {
		t.Run(mode, func(t *testing.T) {
			exerciseDestinationWriteTimeout(t, mode, false)
		})
	}
}

func TestH3DestinationWriteTimeoutAfterResponseFINAndReset(t *testing.T) {
	exerciseDestinationWriteTimeout(t, "h3", true)
}

func exerciseDestinationWriteTimeout(t *testing.T, mode string, resetAfterFIN bool) {
	t.Helper()
	upstream, target := net.Pipe()
	defer target.Close()
	tracked := &destinationIntegrationTarget{
		Conn: upstream, started: make(chan time.Time, 1), result: make(chan error, 1), closed: make(chan struct{}),
	}
	defer tracked.Close() // Also releases the baseline failure before server cleanup.
	admission, err := NewStreamAdmission(2)
	if err != nil {
		t.Fatal(err)
	}
	outbound := transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "stall.example:443" {
			if resetAfterFIN {
				return &destinationIntegrationResponseFIN{tracked}, nil
			}
			return tracked, nil
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	})
	client := newDestinationWriteIntegrationClient(t, mode, outbound, admission)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	sibling, err := client.DialContext(ctx, "tcp", startWebTCPEcho(t))
	if err != nil {
		t.Fatal(err)
	}
	defer sibling.Close()
	conn, err := client.DialContext(ctx, "tcp", "stall.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if resetAfterFIN {
		if response, err := io.ReadAll(conn); err != nil || len(response) != 0 {
			t.Fatalf("response FIN = %q, %v", response, err)
		}
	}
	if _, err := io.WriteString(conn, "upload"); err != nil {
		t.Fatal(err)
	}
	var started time.Time
	select {
	case started = <-tracked.started:
	case <-time.After(time.Second):
		t.Fatal("upload never entered the destination Write")
	}
	if resetAfterFIN {
		_ = conn.Close()
	}
	// No unrelated cancellation is used for the ordinary four-transport
	// cases. The post-FIN reset case must likewise be a write timeout, not
	// an assertion that the currently unavailable reset signal is immediate.
	select {
	case err := <-tracked.result:
		if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
			t.Fatalf("destination Write error = %v, want its configured timeout", err)
		}
		if elapsed := time.Since(started); elapsed < destinationIntegrationWriteTimeout/2 {
			t.Fatalf("Write ended after %s, too early to prove bounded stall reclamation", elapsed)
		}
	case <-time.After(time.Second):
		t.Fatal("stalled destination Write outlived its 200 ms timeout")
	}
	select {
	case <-tracked.closed:
	case <-time.After(time.Second):
		t.Fatal("expired destination remained open")
	}
	awaitWebServerAdmission(t, admission, 1)
	assertWebSessionSiblingEcho(t, sibling)
	_ = sibling.Close()
	awaitWebServerAdmission(t, admission, 0)
}

// A write deadline must be scoped to a pending Write, not a dormant half-open
// connection or the entire upload. This target reads normally after its FIN.
func TestH3DestinationWriteTimeoutPreservesResponseFINUpload(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	chunk := []byte("after-FIN-upload\x00\xff")
	payload := bytes.Repeat(chunk, 8)
	wantResponse := []byte("response before upload")
	result := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		result <- func() error {
			conn, err := listener.Accept()
			if err != nil {
				return err
			}
			defer conn.Close()
			stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
			defer stop()
			if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				return err
			}
			if _, err := conn.Write(wantResponse); err != nil {
				return err
			}
			if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
				return err
			}
			got, err := io.ReadAll(conn)
			if err != nil {
				return err
			}
			if !bytes.Equal(got, payload) {
				return fmt.Errorf("upload = %q, want %q", got, payload)
			}
			return nil
		}()
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("response-FIN target did not stop")
		}
	})
	admission, err := NewStreamAdmission(1)
	if err != nil {
		t.Fatal(err)
	}
	client := newDestinationWriteIntegrationClient(t, "h3", &net.Dialer{}, admission)
	dialCtx, cancelDial := context.WithTimeout(ctx, 2*time.Second)
	defer cancelDial()
	conn, err := client.DialContext(dialCtx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(response, wantResponse) {
		t.Fatalf("response FIN = %q, %v", response, err)
	}
	// With no pending Write, waiting longer than the bound is harmless.
	time.Sleep(2 * destinationIntegrationWriteTimeout)
	for range 8 {
		if _, err := conn.Write(chunk); err != nil {
			t.Fatalf("active upload after response FIN: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("normal upload did not finish after response FIN")
	}
	awaitWebServerAdmission(t, admission, 0)
}

type destinationIntegrationServer interface {
	Addr() net.Addr
	Serve(context.Context) error
	Close() error
}

func newDestinationWriteIntegrationClient(t *testing.T, mode string, outbound transport.Dialer, admission *StreamAdmission) transport.Dialer {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	var server destinationIntegrationServer
	var err error
	switch mode {
	case "quic":
		server, err = ListenQUIC(QUICServerConfig{
			Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
			Dialer: outbound, StreamAdmission: admission, DestinationWriteTimeout: destinationIntegrationWriteTimeout,
		})
	case "tls":
		server, err = ListenTLS(TLSServerConfig{
			Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
			Dialer: outbound, StreamAdmission: admission, DestinationWriteTimeout: destinationIntegrationWriteTimeout,
		})
	case "h2":
		server, err = ListenWebH2(WebH2ServerConfig{
			Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS, Cover: http.NotFoundHandler(),
			Dialer: outbound, StreamAdmission: admission, DestinationWriteTimeout: destinationIntegrationWriteTimeout,
		})
	case "h3":
		server, err = ListenWebH3(WebH3ServerConfig{
			Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS, Cover: http.NotFoundHandler(),
			Dialer: outbound, StreamAdmission: admission, DestinationWriteTimeout: destinationIntegrationWriteTimeout,
		})
	default:
		t.Fatalf("unknown transport %q", mode)
	}
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("%s server: %v", mode, err)
			}
		case <-time.After(time.Second):
			t.Errorf("%s server did not stop", mode)
		}
	})
	var client interface {
		transport.Dialer
		io.Closer
	}
	switch mode {
	case "quic":
		client, err = NewClient(ClientConfig{ServerAddress: server.Addr().String(), Token: testToken, TLSConfig: clientTLS})
	case "tls":
		client, err = NewTLSClient(TLSClientConfig{ServerAddress: server.Addr().String(), Token: testToken, TLSConfig: clientTLS})
	case "h2":
		client, err = NewWebH2Client(WebH2ClientConfig{ServerAddress: server.Addr().String(), Token: testToken, TLSConfig: clientTLS})
	case "h3":
		client, err = NewWebH3Client(WebH3ClientConfig{ServerAddress: server.Addr().String(), Token: testToken, TLSConfig: clientTLS})
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

type destinationIntegrationTarget struct {
	net.Conn
	started              chan time.Time
	result               chan error
	closed               chan struct{}
	writeOnce, closeOnce sync.Once
}

func (c *destinationIntegrationTarget) Write(p []byte) (int, error) {
	c.writeOnce.Do(func() { c.started <- time.Now() })
	n, err := c.Conn.Write(p)
	c.result <- err
	return n, err
}

func (c *destinationIntegrationTarget) Close() error {
	var err error
	c.closeOnce.Do(func() { err = c.Conn.Close(); close(c.closed) })
	return err
}

type destinationIntegrationResponseFIN struct{ *destinationIntegrationTarget }

func (*destinationIntegrationResponseFIN) Read([]byte) (int, error) { return 0, io.EOF }
