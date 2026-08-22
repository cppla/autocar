package security

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestTLSConfigSecureDefaults(t *testing.T) {
	certPEM, pair := generatePair(t, "server.example")
	clientConfig, err := NewClientTLSConfig(ClientTLSOptions{
		ServerName: "server.example",
		CAPEM:      certPEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	if clientConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify enabled")
	}
	if clientConfig.ClientSessionCache == nil {
		t.Fatal("TLS 1.3 session cache is disabled for the per-flow fallback")
	}
	if clientConfig.MinVersion != tls.VersionTLS13 || clientConfig.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("client TLS versions = %x..%x", clientConfig.MinVersion, clientConfig.MaxVersion)
	}
	if len(clientConfig.NextProtos) != 1 || clientConfig.NextProtos[0] != ALPN {
		t.Fatalf("client ALPN = %v", clientConfig.NextProtos)
	}

	serverConfig, err := NewServerTLSConfig(ServerTLSOptions{Certificates: []tls.Certificate{pair}})
	if err != nil {
		t.Fatal(err)
	}
	if serverConfig.MinVersion != tls.VersionTLS13 || serverConfig.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("server TLS versions = %x..%x", serverConfig.MinVersion, serverConfig.MaxVersion)
	}
	if serverConfig.ClientAuth != tls.NoClientCert {
		t.Fatalf("unexpected ClientAuth = %v", serverConfig.ClientAuth)
	}
	if len(serverConfig.NextProtos) != 1 || serverConfig.NextProtos[0] != ALPN {
		t.Fatalf("server ALPN = %v", serverConfig.NextProtos)
	}

	clientState, serverState, clientErr, serverErr := tlsHandshake(clientConfig, serverConfig)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake errors: client=%v server=%v", clientErr, serverErr)
	}
	if clientState.Version != tls.VersionTLS13 || serverState.Version != tls.VersionTLS13 {
		t.Fatalf("negotiated versions: client=%x server=%x", clientState.Version, serverState.Version)
	}
	if clientState.NegotiatedProtocol != ALPN || serverState.NegotiatedProtocol != ALPN {
		t.Fatalf("negotiated ALPN: client=%q server=%q", clientState.NegotiatedProtocol, serverState.NegotiatedProtocol)
	}
}

func TestClientTLSConfigRequiresNameAndCA(t *testing.T) {
	certPEM, _ := generatePair(t, "server.example")
	tests := []ClientTLSOptions{
		{CAPEM: certPEM},
		{ServerName: "server.example"},
		{ServerName: "server.example", CAPEM: []byte("not PEM")},
		{ServerName: "bad\nname", CAPEM: certPEM},
	}
	for _, opts := range tests {
		if _, err := NewClientTLSConfig(opts); err == nil {
			t.Fatalf("expected error for %+v", opts)
		}
	}
}

func TestClientTLSRejectsWrongServerName(t *testing.T) {
	certPEM, pair := generatePair(t, "server.example")
	clientConfig, err := NewClientTLSConfig(ClientTLSOptions{ServerName: "attacker.example", CAPEM: certPEM})
	if err != nil {
		t.Fatal(err)
	}
	serverConfig, err := NewServerTLSConfig(ServerTLSOptions{Certificates: []tls.Certificate{pair}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, clientErr, _ := tlsHandshake(clientConfig, serverConfig)
	if clientErr == nil {
		t.Fatal("wrong server name unexpectedly verified")
	}
}

func TestMutualTLS(t *testing.T) {
	serverPEM, serverPair := generatePair(t, "server.example")
	clientPEM, clientPair := generatePair(t, "client.example")

	serverConfig, err := NewServerTLSConfig(ServerTLSOptions{
		Certificates: []tls.Certificate{serverPair},
		ClientCAPEM:  clientPEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	if serverConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth = %v", serverConfig.ClientAuth)
	}
	clientConfig, err := NewClientTLSConfig(ClientTLSOptions{
		ServerName:   "server.example",
		CAPEM:        serverPEM,
		Certificates: []tls.Certificate{clientPair},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, serverState, clientErr, serverErr := tlsHandshake(clientConfig, serverConfig)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("mTLS handshake errors: client=%v server=%v", clientErr, serverErr)
	}
	if len(serverState.PeerCertificates) != 1 || serverState.PeerCertificates[0].Subject.CommonName != "client.example" {
		t.Fatalf("server peer certificates = %v", serverState.PeerCertificates)
	}

	clientWithoutCert, err := NewClientTLSConfig(ClientTLSOptions{ServerName: "server.example", CAPEM: serverPEM})
	if err != nil {
		t.Fatal(err)
	}
	_, _, clientErr, serverErr = tlsHandshake(clientWithoutCert, serverConfig)
	if clientErr == nil && serverErr == nil {
		t.Fatal("mTLS server accepted a client without a certificate")
	}
}

func TestServerTLSConfigValidation(t *testing.T) {
	if _, err := NewServerTLSConfig(ServerTLSOptions{}); err == nil {
		t.Fatal("server config accepted no certificate")
	}
	_, pair := generatePair(t, "server.example")
	if _, err := NewServerTLSConfig(ServerTLSOptions{Certificates: []tls.Certificate{pair}, ClientCAPEM: []byte("bad")}); err == nil {
		t.Fatal("server config accepted invalid client CA")
	}
}

func TestCertPoolAndKeyPairFileHelpers(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedCertificate(CertificateOptions{Hosts: []string{"server.example"}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	for path, content := range map[string][]byte{caPath: certPEM, certPath: certPEM, keyPath: keyPEM} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pool, err := LoadCertPool(caPath)
	if err != nil || pool == nil {
		t.Fatalf("LoadCertPool: pool=%v err=%v", pool, err)
	}
	if _, err := LoadKeyPair(certPath, keyPath); err != nil {
		t.Fatalf("LoadKeyPair: %v", err)
	}
	if _, err := CertPoolFromPEM(nil); err == nil {
		t.Fatal("empty CA PEM accepted")
	}
}

func TestLoadKeyPairRejectsUnsafePrivateKeyFile(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedCertificate(CertificateOptions{Hosts: []string{"server.example"}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(keyPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadKeyPair(certPath, keyPath); err == nil || !strings.Contains(err.Error(), "permissions") {
			t.Fatalf("want private-key permissions error, got %v", err)
		}
		if err := os.Chmod(keyPath, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	directoryKey := filepath.Join(dir, "directory-key")
	if err := os.Mkdir(directoryKey, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyPair(certPath, directoryKey); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("want regular-file error, got %v", err)
	}
}

func generatePair(t *testing.T, host string) ([]byte, tls.Certificate) {
	t.Helper()
	certPEM, keyPEM, err := GenerateSelfSignedCertificate(CertificateOptions{Hosts: []string{host}, ValidFor: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, pair
}

func tlsHandshake(clientConfig, serverConfig *tls.Config) (tls.ConnectionState, tls.ConnectionState, error, error) {
	clientNet, serverNet := net.Pipe()
	client := tls.Client(clientNet, clientConfig)
	server := tls.Server(serverNet, serverConfig)
	deadline := time.Now().Add(5 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)

	type result struct {
		client bool
		err    error
	}
	results := make(chan result, 2)
	go func() {
		err := client.Handshake()
		if err == nil {
			// Read one application byte. Besides proving the protected channel
			// works, this lets the peer deliver a TLS 1.3 post-handshake alert
			// (for example, a missing client certificate) over net.Pipe.
			var probe [1]byte
			_, err = client.Read(probe[:])
		}
		results <- result{client: true, err: err}
	}()
	go func() {
		err := server.Handshake()
		if err == nil {
			_, err = server.Write([]byte{0xa5})
		}
		results <- result{client: false, err: err}
	}()
	var clientErr, serverErr error
	for range 2 {
		result := <-results
		if result.client {
			clientErr = result.err
		} else {
			serverErr = result.err
		}
	}
	clientState := client.ConnectionState()
	serverState := server.ConnectionState()
	// Closing a TLS endpoint over net.Pipe can block while it writes a
	// close_notify to a peer that is no longer reading. Close the underlying
	// in-memory endpoints directly after capturing connection state.
	_ = clientNet.Close()
	_ = serverNet.Close()
	return clientState, serverState, clientErr, serverErr
}
