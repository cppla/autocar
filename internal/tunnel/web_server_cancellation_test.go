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

func TestWebServerCancellationReleasesStalledDestination(t *testing.T) {
	for _, mode := range []string{"h2", "h3"} {
		actions := []string{"close_stream", "close_server"}
		if mode == "h3" {
			actions = append(actions, "close_server_after_response_fin")
		}
		for _, action := range actions {
			t.Run(mode+"/"+action, func(t *testing.T) {
				upstream, target := net.Pipe()
				defer target.Close()
				tracked := &webServerStalledTarget{
					Conn: upstream, writing: make(chan struct{}), closed: make(chan struct{}),
				}
				defer tracked.Close()
				admission, err := NewStreamAdmission(2)
				if err != nil {
					t.Fatal(err)
				}
				outbound := transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
					if address == "stall.example:443" {
						if action == "close_server_after_response_fin" {
							return &webServerResponseEOF{tracked}, nil
						}
						return tracked, nil
					}
					return (&net.Dialer{}).DialContext(ctx, network, address)
				})
				client, closeServer := newWebServerCancellationClient(t, mode, outbound, admission)
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
				if action == "close_server_after_response_fin" {
					if reply, err := io.ReadAll(conn); err != nil || len(reply) != 0 {
						t.Fatalf("initial response FIN: %q, %v", reply, err)
					}
				}
				if _, err := io.WriteString(conn, "x"); err != nil {
					t.Fatal(err)
				}
				select {
				case <-tracked.writing:
				case <-time.After(time.Second):
					t.Fatal("upload never reached the blocking destination Write")
				}
				// Both relay copies now wait on the destination, not on the
				// HTTP stream. A reset must actively close that destination.
				if action == "close_stream" {
					_ = conn.Close()
				} else {
					closed := make(chan error, 1)
					go func() { closed <- closeServer() }()
					select {
					case <-closed:
					case <-time.After(time.Second):
						_ = tracked.Close()
						select {
						case <-closed:
						case <-time.After(time.Second):
							t.Fatal("server Close stayed blocked after forced target cleanup")
						}
						t.Fatal("server Close waited for a stalled destination")
					}
				}
				select {
				case <-tracked.closed:
				case <-time.After(time.Second):
					t.Fatal("cancellation left destination Read and Write blocked")
				}
				if action == "close_stream" {
					awaitWebServerAdmission(t, admission, 1)
					assertWebSessionSiblingEcho(t, sibling)
					_ = sibling.Close()
				}
				awaitWebServerAdmission(t, admission, 0)
			})
		}
	}
}

// QUIC's send-stream context is canceled by an ordinary response FIN too.
// That signal must not abort the client's still-live upload direction.
func TestWebH3ServerResponseFINPreservesUpload(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wantUpload := []byte("upload after response EOF")
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
			if !bytes.Equal(got, wantUpload) {
				return fmt.Errorf("upload = %q, want %q", got, wantUpload)
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
			t.Error("half-closed target did not stop")
		}
	})
	admission, err := NewStreamAdmission(1)
	if err != nil {
		t.Fatal(err)
	}
	client, _ := newWebServerCancellationClient(t, "h3", &net.Dialer{}, admission)
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
	got, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(got, wantResponse) {
		t.Fatalf("response before upload = %q, err = %v", got, err)
	}
	if _, err := conn.Write(wantUpload); err != nil {
		t.Fatalf("upload after response FIN: %v", err)
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
		t.Fatal("upload did not finish after server response FIN")
	}
	awaitWebServerAdmission(t, admission, 0)
}

func newWebServerCancellationClient(t *testing.T, mode string, outbound transport.Dialer, admission *StreamAdmission) (transport.Dialer, func() error) {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	if mode == "h2" {
		server := startWebH2TestServer(t, WebH2ServerConfig{
			Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
			Cover: http.NotFoundHandler(), Dialer: outbound, StreamAdmission: admission,
		})
		client, err := NewWebH2Client(WebH2ClientConfig{
			ServerAddress: server.Addr().String(), Token: webTestToken, TLSConfig: clientTLS,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		return client, server.Close
	}
	server, err := ListenWebH3(WebH3ServerConfig{
		Address: "127.0.0.1:0", Token: webTestToken, TLSConfig: serverTLS,
		Cover: http.NotFoundHandler(), Dialer: outbound, StreamAdmission: admission,
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
	t.Cleanup(func() { _ = client.Close() })
	return client, server.Close
}

func awaitWebServerAdmission(t *testing.T, admission *StreamAdmission, want int) {
	t.Helper()
	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for len(admission.sem) != want {
		select {
		case <-ticker.C:
		case <-timeout.C:
			t.Fatalf("occupied stream slots = %d, want %d", len(admission.sem), want)
		}
	}
}

type webServerStalledTarget struct {
	net.Conn
	writing, closed      chan struct{}
	writeOnce, closeOnce sync.Once
}

func (c *webServerStalledTarget) Write(p []byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writing) })
	return c.Conn.Write(p)
}

func (c *webServerStalledTarget) Close() error {
	var err error
	c.closeOnce.Do(func() { err = c.Conn.Close(); close(c.closed) })
	return err
}

// The target has finished sending but still accepts uploads, which can stall.
type webServerResponseEOF struct{ *webServerStalledTarget }

func (*webServerResponseEOF) Read([]byte) (int, error) { return 0, io.EOF }
