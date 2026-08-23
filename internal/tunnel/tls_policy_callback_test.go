package tunnel

import (
	"crypto/tls"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/protocol"
)

func TestServerTLSConfigRehardensDynamicConfig(t *testing.T) {
	certificateConfig, _ := testTLSConfigs(t)
	selected := certificateConfig.Clone()
	selected.MinVersion = tls.VersionTLS12
	selected.NextProtos = []string{"h2"}
	selected.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		t.Fatal("nested GetConfigForClient must not remain reachable")
		return nil, nil
	}

	config, err := serverTLSConfig(&tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return selected, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := config.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if got == selected {
		t.Fatal("GetConfigForClient result was not cloned")
	}
	if got.MinVersion != tls.VersionTLS13 {
		t.Fatalf("dynamic MinVersion = %x, want TLS 1.3", got.MinVersion)
	}
	if !slices.Equal(got.NextProtos, []string{protocol.ALPN}) {
		t.Fatalf("dynamic NextProtos = %q, want only %q", got.NextProtos, protocol.ALPN)
	}
	if got.GetConfigForClient != nil {
		t.Fatal("dynamic GetConfigForClient was not cleared")
	}
	if selected.MinVersion != tls.VersionTLS12 || !slices.Equal(selected.NextProtos, []string{"h2"}) {
		t.Fatal("caller-owned dynamic TLS config was mutated")
	}
}

func TestServerTLSConfigRejectsTLS12DynamicDowngrade(t *testing.T) {
	certificateConfig, clientConfig := testTLSConfigs(t)
	downgraded := certificateConfig.Clone()
	downgraded.MinVersion = tls.VersionTLS12
	downgraded.MaxVersion = tls.VersionTLS12
	downgraded.NextProtos = []string{protocol.ALPN}

	server := startTLSServer(t, &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return downgraded, nil
		},
	}, nil, testToken)

	raw, err := net.DialTimeout("tcp", server.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	clientConfig = clientConfig.Clone()
	clientConfig.MinVersion = tls.VersionTLS12
	clientConfig.MaxVersion = tls.VersionTLS12
	clientConfig.NextProtos = []string{protocol.ALPN}
	client := tls.Client(raw, clientConfig)
	if err := client.Handshake(); err == nil {
		t.Fatalf("TLS 1.2 downgrade succeeded with negotiated version %x", client.ConnectionState().Version)
	}
}
