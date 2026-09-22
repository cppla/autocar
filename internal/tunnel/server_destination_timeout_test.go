package tunnel

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServerDestinationWriteTimeoutConfigurationWiring(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	for _, mode := range []string{"tls", "quic", "h2", "h3", "web"} {
		for _, value := range []time.Duration{-time.Second, 0, 37 * time.Millisecond} {
			t.Run(mode+"/"+value.String(), func(t *testing.T) {
				var (
					core   *serverCore
					closer io.Closer
					err    error
				)
				switch mode {
				case "tls":
					server, createErr := ListenTLS(TLSServerConfig{
						Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
						DestinationWriteTimeout: value,
					})
					err = createErr
					if err == nil {
						core, closer = server.core, server
					}
				case "quic":
					server, createErr := ListenQUIC(QUICServerConfig{
						Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
						DestinationWriteTimeout: value,
					})
					err = createErr
					if err == nil {
						core, closer = server.core, server
					}
				case "h2":
					server, createErr := ListenWebH2(WebH2ServerConfig{
						Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
						Cover: http.NotFoundHandler(), Dialer: &net.Dialer{}, DestinationWriteTimeout: value,
					})
					err = createErr
					if err == nil {
						core, closer = server.server.Handler.(*webTunnelHandler).core, server
					}
				case "h3":
					server, createErr := ListenWebH3(WebH3ServerConfig{
						Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
						Cover: http.NotFoundHandler(), Dialer: &net.Dialer{}, DestinationWriteTimeout: value,
					})
					err = createErr
					if err == nil {
						core, closer = server.server.Handler.(*webTunnelHandler).core, server
					}
				case "web":
					server, createErr := ListenWeb(WebServerConfig{
						TCPAddress: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
						Cover: http.NotFoundHandler(), Dialer: &net.Dialer{}, DestinationWriteTimeout: value,
					})
					err = createErr
					if err == nil {
						core, closer = server.h2.server.Handler.(*webTunnelHandler).core, server
						h3Core := server.h3.server.Handler.(*webTunnelHandler).core
						if h3Core != core {
							_ = server.Close()
							t.Fatal("combined web server did not share the timeout-bearing core")
						}
					}
				}
				if closer != nil {
					t.Cleanup(func() { _ = closer.Close() })
				}
				if value < 0 {
					if err == nil {
						t.Fatal("negative destination write timeout was accepted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				want := value
				if want == 0 {
					want = 5 * time.Minute
				}
				if core.destinationWriteTimeout != want {
					t.Fatalf("destination write timeout=%s want=%s", core.destinationWriteTimeout, want)
				}
			})
		}
	}
}
