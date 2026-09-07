package tunnel

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

type observedWebRequestHeaders struct {
	userAgent      []string
	acceptEncoding []string
}

func TestWebConnectClientsSuppressLibraryDefaultHeaders(t *testing.T) {
	for _, protocol := range []string{webAuthTransportH2, webAuthTransportH3} {
		t.Run(protocol, func(t *testing.T) {
			serverTLS, clientTLS := testTLSConfigs(t)
			observed := make(chan observedWebRequestHeaders, 1)
			cover := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				observed <- observedWebRequestHeaders{
					userAgent:      append([]string(nil), request.Header.Values("User-Agent")...),
					acceptEncoding: append([]string(nil), request.Header.Values("Accept-Encoding")...),
				}
				w.WriteHeader(http.StatusNotFound)
			})
			unexpectedDial := transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("authenticated request unexpectedly reached destination dialer")
			})

			var dial func(context.Context) error
			switch protocol {
			case webAuthTransportH2:
				server := startWebH2TestServer(t, WebH2ServerConfig{
					Address: "127.0.0.1:0", Token: testToken + "-server", TLSConfig: serverTLS,
					Cover: cover, Dialer: unexpectedDial,
				})
				client, err := NewWebH2Client(WebH2ClientConfig{
					ServerAddress: server.Addr().String(), Token: testToken, TLSConfig: clientTLS,
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = client.Close() })
				dial = func(ctx context.Context) error {
					connection, err := client.DialContext(ctx, "tcp", "example.com:443")
					if connection != nil {
						_ = connection.Close()
					}
					return err
				}
			case webAuthTransportH3:
				server, err := ListenWebH3(WebH3ServerConfig{
					Address: "127.0.0.1:0", Token: testToken + "-server", TLSConfig: serverTLS,
					Cover: cover, Dialer: unexpectedDial,
				})
				if err != nil {
					t.Fatal(err)
				}
				serveCtx, cancelServe := context.WithCancel(context.Background())
				serveDone := make(chan error, 1)
				go func() { serveDone <- server.Serve(serveCtx) }()
				t.Cleanup(func() {
					cancelServe()
					_ = server.Close()
					select {
					case err := <-serveDone:
						if err != nil {
							t.Errorf("web-cover HTTP/3 Serve: %v", err)
						}
					case <-time.After(2 * time.Second):
						t.Error("web-cover HTTP/3 server did not stop")
					}
				})
				client, err := NewWebH3Client(WebH3ClientConfig{
					ServerAddress: server.Addr().String(), Token: testToken, TLSConfig: clientTLS,
					DialTimeout: time.Second, HandshakeTimeout: time.Second,
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = client.Close() })
				dial = func(ctx context.Context) error {
					connection, err := client.DialContext(ctx, "tcp", "example.com:443")
					if connection != nil {
						_ = connection.Close()
					}
					return err
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := dial(ctx); err == nil {
				t.Fatal("mismatched authentication unexpectedly succeeded")
			}
			select {
			case headers := <-observed:
				if len(headers.userAgent) != 0 {
					t.Fatalf("cover observed library User-Agent values %q", headers.userAgent)
				}
				if len(headers.acceptEncoding) != 0 {
					t.Fatalf("cover observed library Accept-Encoding values %q", headers.acceptEncoding)
				}
			case <-ctx.Done():
				t.Fatal("cover did not observe the unauthenticated CONNECT request")
			}
		})
	}
}

func TestWebConnectUDPClientSuppressesLibraryDefaultHeaders(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	observed := make(chan observedWebRequestHeaders, 1)
	server, err := ListenWebH3(WebH3ServerConfig{
		Address:   "127.0.0.1:0",
		Token:     testToken + "-server",
		TLSConfig: serverTLS,
		Dialer:    unusedWebUDPDialer(),
		UDPResolver: UDPResolverFunc(func(context.Context, string) ([]netip.AddrPort, error) {
			return nil, errors.New("unauthenticated CONNECT-UDP unexpectedly reached resolver")
		}),
		Cover: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			observed <- observedWebRequestHeaders{
				userAgent:      append([]string(nil), request.Header.Values("User-Agent")...),
				acceptEncoding: append([]string(nil), request.Header.Values("Accept-Encoding")...),
			}
			w.WriteHeader(http.StatusNotFound)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	serveWebH3ForTest(t, server)

	client, err := NewWebH3Client(WebH3ClientConfig{
		ServerAddress:    server.Addr().String(),
		Token:            testToken,
		TLSConfig:        clientTLS,
		DialTimeout:      time.Second,
		HandshakeTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	packet, err := client.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packet.Close() })
	if err := packet.Send([]byte("header probe"), "example.com:53"); err == nil {
		t.Fatal("mismatched CONNECT-UDP authentication unexpectedly succeeded")
	}
	select {
	case headers := <-observed:
		if len(headers.userAgent) != 0 {
			t.Fatalf("cover observed library User-Agent values %q", headers.userAgent)
		}
		if len(headers.acceptEncoding) != 0 {
			t.Fatalf("cover observed library Accept-Encoding values %q", headers.acceptEncoding)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cover did not observe the unauthenticated CONNECT-UDP request")
	}
}

func TestWebConnectRequestHeadersRetainAuthentication(t *testing.T) {
	header := webConnectRequestHeaders("Bearer ticket")
	if got := header.Get("Proxy-Authorization"); got != "Bearer ticket" {
		t.Fatalf("Proxy-Authorization = %q", got)
	}
	values, present := header["User-Agent"]
	if !present || values != nil {
		t.Fatalf("User-Agent suppression marker = %#v, present=%v", values, present)
	}
}
