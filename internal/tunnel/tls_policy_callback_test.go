package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/protocol"
	"github.com/cppla/autocar/internal/security"
)

func TestServerTLSConfigRehardensDynamicConfig(t *testing.T) {
	certificateConfig, _ := testTLSConfigs(t)
	selected := certificateConfig.Clone()
	selected.MinVersion = tls.VersionTLS12
	selected.MaxVersion = tls.VersionTLS12
	selected.NextProtos = []string{"h2"}
	selected.ClientAuth = tls.NoClientCert
	selected.SessionTicketsDisabled = false
	selected.CurvePreferences = []tls.CurveID{tls.X25519}
	selectedCertificate := &selected.Certificates[0]
	selected.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return selectedCertificate, nil
	}
	selected.NameToCertificate = map[string]*tls.Certificate{"dynamic.test": selectedCertificate}
	selected.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		t.Fatal("nested GetConfigForClient must not remain reachable")
		return nil, nil
	}

	clientCAs := x509.NewCertPool()
	parentTime := time.Unix(1_700_000_000, 0)
	config, err := serverTLSConfig(&tls.Config{
		MinVersion:             tls.VersionTLS12,
		MaxVersion:             tls.VersionTLS13,
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              clientCAs,
		VerifyPeerCertificate:  func([][]byte, [][]*x509.Certificate) error { return nil },
		VerifyConnection:       func(tls.ConnectionState) error { return nil },
		Time:                   func() time.Time { return parentTime },
		SessionTicketsDisabled: true,
		UnwrapSession: func([]byte, tls.ConnectionState) (*tls.SessionState, error) {
			return nil, nil
		},
		WrapSession: func(tls.ConnectionState, *tls.SessionState) ([]byte, error) {
			return nil, nil
		},
		CurvePreferences: []tls.CurveID{tls.CurveP256},
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
	if got.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("dynamic MaxVersion = %x, want parent TLS 1.3", got.MaxVersion)
	}
	if !slices.Equal(got.NextProtos, []string{protocol.ALPN}) {
		t.Fatalf("dynamic NextProtos = %q, want only %q", got.NextProtos, protocol.ALPN)
	}
	if got.GetConfigForClient != nil {
		t.Fatal("dynamic GetConfigForClient was not cleared")
	}
	if len(got.Certificates) != 1 || got.GetCertificate == nil || got.NameToCertificate["dynamic.test"] == nil {
		t.Fatal("dynamic certificate material was not selected")
	}
	if got.ClientAuth != tls.RequireAndVerifyClientCert || got.ClientCAs != clientCAs {
		t.Fatalf("dynamic client auth = %v, CAs preserved=%t", got.ClientAuth, got.ClientCAs == clientCAs)
	}
	if got.VerifyPeerCertificate == nil || got.VerifyConnection == nil {
		t.Fatal("parent certificate verification hooks were not preserved")
	}
	if !got.Time().Equal(parentTime) {
		t.Fatalf("dynamic Time = %s, want parent %s", got.Time(), parentTime)
	}
	if !got.SessionTicketsDisabled || got.UnwrapSession == nil || got.WrapSession == nil {
		t.Fatal("parent session policy was not preserved")
	}
	if !slices.Equal(got.CurvePreferences, []tls.CurveID{tls.CurveP256}) {
		t.Fatalf("dynamic CurvePreferences = %v, want parent P-256 only", got.CurvePreferences)
	}
	if selected.MinVersion != tls.VersionTLS12 || selected.MaxVersion != tls.VersionTLS12 ||
		!slices.Equal(selected.NextProtos, []string{"h2"}) || selected.GetConfigForClient == nil {
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

func TestServerTLSConfigDynamicConfigPreservesMutualTLSHandshake(t *testing.T) {
	serverCertificate, serverRoots := generateTestTLSIdentity(t, "127.0.0.1")
	clientCertificate, clientRoots := generateTestTLSIdentity(t, "client.test")

	config, err := serverTLSConfig(&tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientRoots,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			// A certificate-only dynamic config previously replaced the parent
			// mTLS policy wholesale and admitted clients without certificates.
			return &tls.Config{Certificates: []tls.Certificate{serverCertificate}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	clientConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		RootCAs:    serverRoots,
		ServerName: "127.0.0.1",
		NextProtos: []string{protocol.ALPN},
	}
	_, _, _, serverErr := handshakeTLSConfigs(clientConfig, config)
	if serverErr == nil {
		t.Fatal("dynamic server config admitted a client without an mTLS certificate")
	}

	clientConfig = clientConfig.Clone()
	clientConfig.Certificates = []tls.Certificate{clientCertificate}
	clientState, serverState, clientErr, serverErr := handshakeTLSConfigs(clientConfig, config)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("valid mTLS handshake failed: client=%v server=%v", clientErr, serverErr)
	}
	if clientState.NegotiatedProtocol != protocol.ALPN || serverState.NegotiatedProtocol != protocol.ALPN {
		t.Fatalf("negotiated ALPN: client=%q server=%q", clientState.NegotiatedProtocol, serverState.NegotiatedProtocol)
	}
	if len(serverState.PeerCertificates) != 1 || serverState.PeerCertificates[0].Subject.CommonName != "client.test" {
		t.Fatalf("server peer certificates = %v", serverState.PeerCertificates)
	}
}

func TestServerTLSConfigDynamicConfigPreservesParentVerificationHooks(t *testing.T) {
	serverCertificate, serverRoots := generateTestTLSIdentity(t, "127.0.0.1")
	clientCertificate, clientRoots := generateTestTLSIdentity(t, "client.test")
	clientConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		RootCAs:      serverRoots,
		ServerName:   "127.0.0.1",
		NextProtos:   []string{protocol.ALPN},
		Certificates: []tls.Certificate{clientCertificate},
	}

	tests := []struct {
		name      string
		configure func(*tls.Config, error)
	}{
		{
			name: "VerifyPeerCertificate",
			configure: func(config *tls.Config, rejection error) {
				config.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error { return rejection }
			},
		},
		{
			name: "VerifyConnection",
			configure: func(config *tls.Config, rejection error) {
				config.VerifyConnection = func(tls.ConnectionState) error { return rejection }
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rejection := errors.New("parent verification rejected client")
			parent := &tls.Config{
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs:  clientRoots,
				GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
					return &tls.Config{
						Certificates:          []tls.Certificate{serverCertificate},
						ClientAuth:            tls.NoClientCert,
						VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error { return nil },
						VerifyConnection:      func(tls.ConnectionState) error { return nil },
					}, nil
				},
			}
			test.configure(parent, rejection)
			config, err := serverTLSConfig(parent)
			if err != nil {
				t.Fatal(err)
			}

			_, _, _, serverErr := handshakeTLSConfigs(clientConfig, config)
			if !errors.Is(serverErr, rejection) {
				t.Fatalf("server handshake error = %v, want parent rejection", serverErr)
			}
		})
	}
}

func generateTestTLSIdentity(t *testing.T, host string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	certPEM, keyPEM, err := security.GenerateSelfSignedCertificate(security.CertificateOptions{
		Hosts: []string{host}, ValidFor: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := security.CertPoolFromPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, roots
}

func handshakeTLSConfigs(clientConfig, serverConfig *tls.Config) (tls.ConnectionState, tls.ConnectionState, error, error) {
	clientNet, serverNet := net.Pipe()
	client := tls.Client(clientNet, clientConfig)
	server := tls.Server(serverNet, serverConfig)
	deadline := time.Now().Add(5 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)

	clientResult := make(chan error, 1)
	serverResult := make(chan error, 1)
	go func() {
		err := client.Handshake()
		if err == nil {
			var probe [1]byte
			_, err = client.Read(probe[:])
		}
		clientResult <- err
	}()
	go func() {
		err := server.Handshake()
		if err == nil {
			_, err = server.Write([]byte{0xa5})
		}
		serverResult <- err
	}()
	clientErr := <-clientResult
	serverErr := <-serverResult
	clientState := client.ConnectionState()
	serverState := server.ConnectionState()
	_ = clientNet.Close()
	_ = serverNet.Close()
	return clientState, serverState, clientErr, serverErr
}
