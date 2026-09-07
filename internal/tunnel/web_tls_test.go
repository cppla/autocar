package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"slices"
	"strings"
	"testing"
)

func TestWebServerTLSConfigReassertsHTTPPolicyAfterCertificateSelection(t *testing.T) {
	selected := &tls.Config{
		NextProtos: []string{"autocar/2"},
	}
	config, err := webServerTLSConfig(&tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return selected, nil
		},
	}, webH2ALPN, webHTTP11ALPN)
	if err != nil {
		t.Fatal(err)
	}
	got, err := config.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if got == selected {
		t.Fatal("web TLS policy returned the caller-owned dynamic config without cloning")
	}
	if !slices.Equal(got.NextProtos, []string{webH2ALPN, webHTTP11ALPN}) {
		t.Fatalf("dynamic web ALPN = %q", got.NextProtos)
	}
	if got.ClientAuth != tls.NoClientCert || got.ClientCAs != nil {
		t.Fatalf("dynamic web mTLS policy = %v/%v", got.ClientAuth, got.ClientCAs != nil)
	}
	if got.MinVersion != tls.VersionTLS12 {
		t.Fatalf("dynamic public cover minimum TLS version = %#x, want TLS 1.2", got.MinVersion)
	}
	if !slices.Equal(selected.NextProtos, []string{"autocar/2"}) {
		t.Fatalf("caller-owned dynamic config was mutated: %q", selected.NextProtos)
	}
}

func TestWebServerTLSConfigAllowsTLS12OnlyForPublicCover(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	got, err := webServerTLSConfig(serverTLS, webH2ALPN, webHTTP11ALPN)
	if err != nil {
		t.Fatal(err)
	}
	if got.MinVersion != tls.VersionTLS12 || got.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("public cover TLS range = %#x..%#x, want TLS 1.2..1.3", got.MinVersion, got.MaxVersion)
	}
}

func TestWebServerTLSConfigRejectsMutualTLSAtEverySelectionLayer(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	clientCAs := x509.NewCertPool()
	serverTLS.ClientAuth = tls.RequireAndVerifyClientCert
	serverTLS.ClientCAs = clientCAs
	if _, err := webServerTLSConfig(serverTLS,
		webH2ALPN); err == nil || !strings.Contains(err.Error(), "client certificate") {
		t.Fatalf("base mTLS error = %v", err)
	}

	config, err := webServerTLSConfig(&tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return &tls.Config{
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs:  clientCAs,
			}, nil
		},
	}, webH2ALPN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.GetConfigForClient(&tls.ClientHelloInfo{}); err == nil || !strings.Contains(err.Error(), "client authentication") {
		t.Fatalf("dynamic mTLS error = %v", err)
	}
}

func TestWebClientTLSConfigCannotRestoreNativeALPN(t *testing.T) {
	_, client := testTLSConfigs(t)
	client.NextProtos = []string{"autocar/2"}
	got, err := webClientTLSConfig(client, "127.0.0.1:443", webH2ALPN)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.NextProtos, []string{webH2ALPN}) {
		t.Fatalf("web client ALPN = %q", got.NextProtos)
	}
	if !slices.Equal(client.NextProtos, []string{"autocar/2"}) {
		t.Fatalf("caller TLS config was mutated: %q", client.NextProtos)
	}
}
