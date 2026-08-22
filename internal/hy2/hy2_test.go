package hy2

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	hyclient "github.com/apernet/hysteria/core/v2/client"
	hyserver "github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/quic-go/http3"
	"github.com/cppla/autocar/internal/security"
	"github.com/cppla/autocar/internal/transport"
)

const (
	testToken      = "correct horse battery staple"
	wrongTestToken = "incorrect horse battery staple"
)

func TestBBRLoopbackTCPEcho(t *testing.T) {
	target := startTCPEcho(t)
	server, clientTLS, outbound := startTestServer(t, nil)
	client := newTestClient(t, server, clientTLS, nil)

	exchangeTCP(t, client, target, "BBR keeps one authenticated QUIC session hot")
	if got := client.NegotiatedTx(); got != 0 {
		t.Fatalf("NegotiatedTx = %d, want 0 while BBR is active", got)
	}
	if got := server.admission.lastTx.Load(); got != 0 {
		t.Fatalf("server negotiated Tx = %d, want 0 while BBR is active", got)
	}
	if got := client.ConnectionCount(); got != 1 {
		t.Fatalf("authenticated connection count = %d, want 1", got)
	}
	if got := client.AccelerationMode(); got != "bbr-standard" {
		t.Fatalf("acceleration mode = %q, want bbr-standard", got)
	}
	if got := outbound.tcpDials.Load(); got != 1 {
		t.Fatalf("target dial count = %d, want 1", got)
	}
}

func TestBrutalNegotiatesBothDirectionsAndAppliesServerCaps(t *testing.T) {
	const (
		serverMaxTx = 300_000
		serverMaxRx = 400_000
		clientMaxTx = 700_000
		clientMaxRx = 600_000
	)
	target := startTCPEcho(t)
	server, clientTLS, _ := startTestServer(t, func(config *ServerConfig) {
		config.MaxTx = serverMaxTx
		config.MaxRx = serverMaxRx
		config.AllowClientBandwidth = true
	})
	client := newTestClient(t, server, clientTLS, func(config *ClientConfig) {
		config.MaxTx = clientMaxTx
		config.MaxRx = clientMaxRx
	})

	exchangeTCP(t, client, target, "Brutal is negotiated independently in both directions")
	if got := client.NegotiatedTx(); got != serverMaxRx {
		t.Fatalf("client Tx = %d, want server Rx cap %d", got, serverMaxRx)
	}
	if got := server.admission.lastTx.Load(); got != serverMaxTx {
		t.Fatalf("server Tx = %d, want server Tx cap %d", got, serverMaxTx)
	}
	if got := client.AccelerationMode(); got != "brutal" {
		t.Fatalf("acceleration mode = %q, want brutal", got)
	}
}

func TestServerIgnoresClientBandwidthByDefault(t *testing.T) {
	const requested = 900_000
	target := startTCPEcho(t)
	server, clientTLS, _ := startTestServer(t, nil)
	client := newTestClient(t, server, clientTLS, func(config *ClientConfig) {
		config.MaxTx = requested
		config.MaxRx = requested
	})

	exchangeTCP(t, client, target, "secure default keeps the model controller")
	if got := client.NegotiatedTx(); got != 0 {
		t.Fatalf("client Tx = %d, want BBR negotiation value 0", got)
	}
	if got := server.admission.lastTx.Load(); got != 0 {
		t.Fatalf("server Tx = %d, want BBR negotiation value 0", got)
	}
	if got := client.AccelerationMode(); got != "bbr-standard" {
		t.Fatalf("acceleration mode = %q, want bbr-standard", got)
	}
}

func TestAccelerationModeLabelsControllerAndProfile(t *testing.T) {
	for _, test := range []struct {
		name   string
		config ClientConfig
		want   string
	}{
		{name: "default BBR", want: "bbr-standard"},
		{name: "conservative BBR", config: ClientConfig{Congestion: CongestionBBR, BBRProfile: BBRConservative}, want: "bbr-conservative"},
		{name: "aggressive BBR", config: ClientConfig{Congestion: CongestionBBR, BBRProfile: BBRAggressive}, want: "bbr-aggressive"},
		{name: "Reno", config: ClientConfig{Congestion: CongestionReno}, want: "reno"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &Client{config: test.config}
			if got := client.AccelerationMode(); got != test.want {
				t.Fatalf("AccelerationMode = %q, want %q", got, test.want)
			}
		})
	}
	client := &Client{config: ClientConfig{Congestion: CongestionBBR, BBRProfile: BBRStandard}}
	auto := &AutoClient{primary: client}
	if got := auto.AccelerationMode(); got != "bbr-standard" {
		t.Fatalf("AutoClient AccelerationMode = %q", got)
	}
	client.negotiated.Store(123_456)
	if got := auto.NegotiatedTx(); got != 123_456 {
		t.Fatalf("AutoClient NegotiatedTx = %d, want 123456", got)
	}
	auto.route.Store(autoRouteFallback)
	if got := auto.AccelerationMode(); got != "tls-fallback" {
		t.Fatalf("fallback AccelerationMode = %q", got)
	}
	if got := auto.NegotiatedTx(); got != 0 {
		t.Fatalf("fallback NegotiatedTx = %d, want 0", got)
	}
	auto.primarySucceeded()
	if got := auto.AccelerationMode(); got != "brutal" {
		t.Fatalf("restored primary AccelerationMode = %q", got)
	}
}

func TestChromeHandshakeFailureIncludesCertificateGuidance(t *testing.T) {
	client := &Client{
		config:  ClientConfig{},
		closeCh: make(chan struct{}),
		connectFunc: func() (hyclient.Client, *hyclient.HandshakeInfo, error) {
			return nil, nil, errors.New("remote error: tls: handshake failure")
		},
	}
	_, err := client.coreForContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Ed25519") || !strings.Contains(err.Error(), "--disable-chrome-parrot") {
		t.Fatalf("Chrome handshake guidance error = %v", err)
	}

	disabled := &Client{
		config:  ClientConfig{DisableChromeParrot: true},
		closeCh: make(chan struct{}),
		connectFunc: func() (hyclient.Client, *hyclient.HandshakeInfo, error) {
			return nil, nil, errors.New("remote error: tls: handshake failure")
		},
	}
	_, err = disabled.coreForContext(context.Background())
	if err == nil || strings.Contains(err.Error(), "Ed25519") {
		t.Fatalf("disabled Chrome mode added misleading guidance: %v", err)
	}
}

func TestWrongTokenNeverDialsTarget(t *testing.T) {
	server, clientTLS, outbound := startTestServer(t, nil)
	client := newTestClient(t, server, clientTLS, func(config *ClientConfig) {
		config.Token = wrongTestToken
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := client.DialContext(ctx, "tcp", "127.0.0.1:1")
	if err == nil || !IsAuthenticationError(err) {
		t.Fatalf("wrong-token error = %v, want authentication rejection", err)
	}
	if got := outbound.tcpDials.Load(); got != 0 {
		t.Fatalf("wrong token caused %d target dials", got)
	}
}

func TestWrongCAPreventsSessionAndTargetDial(t *testing.T) {
	server, _, outbound := startTestServer(t, nil)
	_, wrongClientTLS := testTLSConfigs(t)
	client := newTestClient(t, server, wrongClientTLS, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := client.DialContext(ctx, "tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatal("relay certificate signed by an untrusted CA was accepted")
	}
	if got := outbound.tcpDials.Load(); got != 0 {
		t.Fatalf("failed TLS verification caused %d target dials", got)
	}
}

func TestClientVerifyPeerCertificateCallbackIsPreserved(t *testing.T) {
	server, clientTLS, outbound := startTestServer(t, nil)
	var called atomic.Bool
	client := newTestClient(t, server, clientTLS, func(config *ClientConfig) {
		config.TLSConfig = config.TLSConfig.Clone()
		config.TLSConfig.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error {
			called.Store(true)
			return errors.New("test certificate policy rejected the relay")
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := client.DialContext(ctx, "tcp", "127.0.0.1:1"); err == nil {
		t.Fatal("custom certificate policy was silently ignored")
	}
	if !called.Load() {
		t.Fatal("VerifyPeerCertificate was not called")
	}
	if got := outbound.tcpDials.Load(); got != 0 {
		t.Fatalf("rejected TLS policy caused %d target dials", got)
	}
}

func TestHysteriaStrictMutualTLS(t *testing.T) {
	target := startTCPEcho(t)
	var clientCertificate tls.Certificate
	server, clientTLS, outbound := startTestServer(t, func(config *ServerConfig) {
		clientCertificate = config.TLSConfig.Certificates[0]
		leaf, err := x509.ParseCertificate(clientCertificate.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		clientCAs := x509.NewCertPool()
		clientCAs.AddCert(leaf)
		config.TLSConfig.ClientCAs = clientCAs
		config.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
	})

	withoutCertificate := newTestClient(t, server, clientTLS, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_, err := withoutCertificate.DialContext(ctx, "tcp", target)
	cancel()
	if err == nil {
		t.Fatal("strict mTLS accepted a client without a certificate")
	}
	if got := outbound.tcpDials.Load(); got != 0 {
		t.Fatalf("client without an mTLS certificate caused %d target dials", got)
	}

	withCertificate := newTestClient(t, server, clientTLS, func(config *ClientConfig) {
		config.TLSConfig = config.TLSConfig.Clone()
		config.TLSConfig.Certificates = []tls.Certificate{clientCertificate}
	})
	exchangeTCP(t, withCertificate, target, "strict Hysteria mutual TLS")
}

func TestClientRejectsTLSVerificationPoliciesTheAdapterCannotPreserve(t *testing.T) {
	_, base := testTLSConfigs(t)
	tests := []struct {
		name   string
		field  string
		modify func(*tls.Config)
	}{
		{
			name:  "VerifyConnection",
			field: "VerifyConnection",
			modify: func(config *tls.Config) {
				config.VerifyConnection = func(tls.ConnectionState) error { return nil }
			},
		},
		{
			name:  "ECH rejection verifier",
			field: "EncryptedClientHelloRejectionVerify",
			modify: func(config *tls.Config) {
				config.EncryptedClientHelloRejectionVerify = func(tls.ConnectionState) error { return nil }
			},
		},
		{name: "custom time", field: "Time", modify: func(config *tls.Config) { config.Time = time.Now }},
		{name: "custom randomness", field: "Rand", modify: func(config *tls.Config) { config.Rand = rand.Reader }},
		{
			name:   "curve policy",
			field:  "CurvePreferences",
			modify: func(config *tls.Config) { config.CurvePreferences = []tls.CurveID{tls.CurveP256} },
		},
		{
			name:   "TLS 1.2 maximum",
			field:  "MaxVersion",
			modify: func(config *tls.Config) { config.MaxVersion = tls.VersionTLS12 },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := base.Clone()
			test.modify(config)
			_, err := NewClient(ClientConfig{
				ServerAddress: "127.0.0.1:443",
				Token:         testToken,
				TLSConfig:     config,
			})
			if err == nil || !strings.Contains(err.Error(), test.field) {
				t.Fatalf("error = %v, want explicit %s rejection", err, test.field)
			}
		})
	}
}

func TestServerRejectsTLSPoliciesTheAdapterCannotPreserve(t *testing.T) {
	base, _ := testTLSConfigs(t)
	tests := []struct {
		name   string
		field  string
		modify func(*tls.Config)
	}{
		{
			name:  "GetConfigForClient",
			field: "GetConfigForClient",
			modify: func(config *tls.Config) {
				config.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return config, nil }
			},
		},
		{
			name:  "VerifyConnection",
			field: "VerifyConnection",
			modify: func(config *tls.Config) {
				config.VerifyConnection = func(tls.ConnectionState) error { return nil }
			},
		},
		{
			name:  "VerifyPeerCertificate",
			field: "VerifyPeerCertificate",
			modify: func(config *tls.Config) {
				config.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error { return nil }
			},
		},
		{name: "custom time", field: "Time", modify: func(config *tls.Config) { config.Time = time.Now }},
		{name: "custom randomness", field: "Rand", modify: func(config *tls.Config) { config.Rand = rand.Reader }},
		{
			name:   "curve policy",
			field:  "CurvePreferences",
			modify: func(config *tls.Config) { config.CurvePreferences = []tls.CurveID{tls.CurveP256} },
		},
		{
			name:  "certificate name map",
			field: "NameToCertificate",
			modify: func(config *tls.Config) {
				config.NameToCertificate = map[string]*tls.Certificate{"relay.example": &config.Certificates[0]}
			},
		},
		{
			name:   "session tickets disabled",
			field:  "SessionTicketsDisabled",
			modify: func(config *tls.Config) { config.SessionTicketsDisabled = true },
		},
		{
			name:   "custom session ticket key",
			field:  "SessionTicketKey",
			modify: func(config *tls.Config) { config.SessionTicketKey[0] = 1 },
		},
		{
			name:  "custom session wrapper",
			field: "WrapSession",
			modify: func(config *tls.Config) {
				config.WrapSession = func(tls.ConnectionState, *tls.SessionState) ([]byte, error) { return nil, nil }
			},
		},
		{
			name:  "custom session unwrapper",
			field: "UnwrapSession",
			modify: func(config *tls.Config) {
				config.UnwrapSession = func([]byte, tls.ConnectionState) (*tls.SessionState, error) { return nil, nil }
			},
		},
		{
			name:   "client auth without CA",
			field:  "ClientAuth",
			modify: func(config *tls.Config) { config.ClientAuth = tls.RequireAnyClientCert },
		},
		{
			name:   "client CA without strict auth",
			field:  "ClientCAs",
			modify: func(config *tls.Config) { config.ClientCAs = x509.NewCertPool() },
		},
		{
			name:   "TLS 1.2 maximum",
			field:  "MaxVersion",
			modify: func(config *tls.Config) { config.MaxVersion = tls.VersionTLS12 },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := base.Clone()
			test.modify(config)
			err := validateServerConfig(ServerConfig{
				Address:   "127.0.0.1:0",
				Token:     testToken,
				TLSConfig: config,
				Outbound:  &testOutbound{},
			})
			if err == nil || !strings.Contains(err.Error(), test.field) {
				t.Fatalf("error = %v, want explicit %s rejection", err, test.field)
			}
		})
	}
}

func TestTLSAdapterAllowsTLS13IrrelevantAndForwardedCLIFields(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	clientTLS.NextProtos = []string{security.ALPN}
	clientTLS.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
	clientTLS.DynamicRecordSizingDisabled = true
	clientTLS.Renegotiation = tls.RenegotiateFreelyAsClient
	clientTLS.ClientSessionCache = tls.NewLRUClientSessionCache(8)
	if _, err := NewClient(ClientConfig{
		ServerAddress: "127.0.0.1:443",
		Token:         testToken,
		TLSConfig:     clientTLS,
	}); err != nil {
		t.Fatalf("ordinary TLS 1.3 client config was rejected: %v", err)
	}

	serverTLS.NextProtos = []string{security.ALPN}
	serverTLS.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
	serverTLS.DynamicRecordSizingDisabled = true
	serverTLS.Renegotiation = tls.RenegotiateNever
	if err := validateServerConfig(ServerConfig{
		Address:   "127.0.0.1:0",
		Token:     testToken,
		TLSConfig: serverTLS,
		Outbound:  &testOutbound{},
	}); err != nil {
		t.Fatalf("ordinary TLS 1.3 server config was rejected: %v", err)
	}
}

func TestHTTP3CoverLooksLikeOrdinaryWebsite(t *testing.T) {
	server, clientTLS, _ := startTestServer(t, func(config *ServerConfig) {
		config.MasqueradeHandler = NewCoverHandler("AutoCAR Edge")
	})
	h3 := &http3.Transport{TLSClientConfig: clientTLS.Clone()}
	t.Cleanup(func() { _ = h3.Close() })
	httpClient := &http.Client{Transport: h3, Timeout: 3 * time.Second}

	response, err := httpClient.Get("https://" + server.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "AutoCAR Edge") {
		t.Fatalf("cover response status=%d body=%q", response.StatusCode, body)
	}
	if got := response.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q", got)
	}
}

func TestHTTP3CoverRejectsOversizedRequestHeaders(t *testing.T) {
	server, clientTLS, _ := startTestServer(t, nil)
	h3 := &http3.Transport{TLSClientConfig: clientTLS.Clone()}
	t.Cleanup(func() { _ = h3.Close() })
	httpClient := &http.Client{Transport: h3, Timeout: 3 * time.Second}
	request, err := http.NewRequest(http.MethodGet, "https://"+server.Addr().String()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Oversized", strings.Repeat("a", defaultMaxHTTPHeaderBytes*2))
	response, err := httpClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("oversized request status = %d, want %d", response.StatusCode, http.StatusRequestHeaderFieldsTooLarge)
	}
}

func TestSalamanderMatchingKeyWorksAndWrongKeyFails(t *testing.T) {
	key := []byte("salamander integration secret")
	target := startTCPEcho(t)
	server, clientTLS, _ := startTestServer(t, func(config *ServerConfig) {
		config.ObfuscationKey = key
	})
	client := newTestClient(t, server, clientTLS, func(config *ClientConfig) {
		config.ObfuscationKey = key
	})
	exchangeTCP(t, client, target, "matching Salamander PSKs")

	badClient, err := NewClient(ClientConfig{
		ServerAddress:  server.Addr().String(),
		Token:          testToken,
		TLSConfig:      clientTLS,
		ObfuscationKey: []byte("different integration secret"),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if _, err := badClient.DialContext(ctx, "tcp", target); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wrong Salamander key error = %v, want deadline exceeded", err)
	}
	// The Hysteria core does not expose a handshake context. DialContext still
	// returns promptly; close asynchronously so the core's bounded handshake
	// timeout can release its reconnect lock without slowing this test.
	go func() { _ = badClient.Close() }()
}

func TestUDPDatagramBidirectionalLoopback(t *testing.T) {
	target := startUDPEcho(t)
	server, clientTLS, outbound := startTestServer(t, nil)
	client := newTestClient(t, server, clientTLS, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	packet, err := client.DialPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	if !client.UDPEnabled() {
		t.Fatal("server handshake did not enable QUIC DATAGRAM")
	}

	payload := []byte("UDP survives without TCP head-of-line blocking")
	if err := packet.Send(payload, target); err != nil {
		t.Fatal(err)
	}
	type receiveResult struct {
		payload []byte
		address string
		err     error
	}
	result := make(chan receiveResult, 1)
	go func() {
		data, address, err := packet.Receive()
		result <- receiveResult{payload: data, address: address, err: err}
	}()
	select {
	case value := <-result:
		if value.err != nil {
			t.Fatal(value.err)
		}
		if string(value.payload) != string(payload) {
			t.Fatalf("UDP payload = %q, want %q", value.payload, payload)
		}
		if value.address != target {
			t.Fatalf("UDP source = %q, want %q", value.address, target)
		}
	case <-ctx.Done():
		t.Fatalf("UDP receive: %v", context.Cause(ctx))
	}
	if outbound.udpChecks.Load() == 0 {
		t.Fatal("UDP destination policy was not checked")
	}
}

func TestSafeUDPOutboundChecksInitialAddressAndRebinding(t *testing.T) {
	unsafeResolver := &hyRotatingResolver{answers: [][]netip.Addr{{netip.MustParseAddr("169.254.169.254")}}}
	unsafeDialer := security.NewSafeDialer(security.SafeDialerOptions{Resolver: unsafeResolver})
	unsafeOutbound := &safeOutbound{dialer: unsafeDialer, timeout: time.Second}
	if _, err := unsafeOutbound.UDP("metadata.example:53"); !errors.Is(err, security.ErrUnsafeAddress) {
		t.Fatalf("initial unsafe UDP address error = %v", err)
	}

	rebindingResolver := &hyRotatingResolver{answers: [][]netip.Addr{
		{netip.MustParseAddr("8.8.8.8")},
		{netip.MustParseAddr("127.0.0.1")},
	}}
	rebindingDialer := security.NewSafeDialer(security.SafeDialerOptions{Resolver: rebindingResolver})
	rebindingOutbound := &safeOutbound{dialer: rebindingDialer, timeout: time.Second}
	conn, err := rebindingOutbound.UDP("rebinding.example:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.WriteTo([]byte("must not escape"), "rebinding.example:53"); !errors.Is(err, security.ErrUnsafeAddress) {
		t.Fatalf("rebound UDP destination error = %v", err)
	}
	if got := rebindingResolver.calls.Load(); got != 2 {
		t.Fatalf("resolver calls = %d, want initial and send-time checks", got)
	}
}

func TestSafeOutboundGloballyLimitsTCPAndUDPSessions(t *testing.T) {
	dialer := security.NewSafeDialer(security.SafeDialerOptions{
		Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
			local, peer := net.Pipe()
			_ = peer.Close()
			return local, nil
		}),
	})
	outbound := &safeOutbound{
		dialer: dialer, timeout: time.Second,
		tcpSlots: make(chan struct{}, 1),
		udpSlots: make(chan struct{}, 1),
	}

	tcp, err := outbound.TCP("8.8.8.8:443")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := outbound.TCP("8.8.8.8:443"); !errors.Is(err, ErrOutboundCapacity) {
		t.Fatalf("second TCP error = %v, want capacity rejection", err)
	}
	if err := tcp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tcp.Close(); err != nil {
		t.Fatal(err)
	}
	tcp, err = outbound.TCP("8.8.8.8:443")
	if err != nil {
		t.Fatalf("TCP slot was not released: %v", err)
	}
	_ = tcp.Close()

	udp, err := outbound.UDP("8.8.8.8:53")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := outbound.UDP("8.8.8.8:53"); !errors.Is(err, ErrOutboundCapacity) {
		t.Fatalf("second UDP error = %v, want capacity rejection", err)
	}
	if err := udp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := udp.Close(); err != nil {
		t.Fatal(err)
	}
	udp, err = outbound.UDP("8.8.8.8:53")
	if err != nil {
		t.Fatalf("UDP slot was not released: %v", err)
	}
	_ = udp.Close()
}

func TestSafeUDPConnDropsUnsolicitedSources(t *testing.T) {
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	approved, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer approved.Close()
	unsolicited, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer unsolicited.Close()

	conn := &safeUDPConn{conn: relay}
	approvedAddress := approved.LocalAddr().(*net.UDPAddr).AddrPort()
	approvedAddress = netip.AddrPortFrom(approvedAddress.Addr().Unmap(), approvedAddress.Port())
	if _, err := conn.writeToDestination([]byte("authorize"), approvedAddress); err != nil {
		t.Fatalf("authorize destination: %v", err)
	}
	target := relay.LocalAddr().(*net.UDPAddr).AddrPort()
	if _, err := unsolicited.WriteToUDPAddrPort([]byte("injected"), target); err != nil {
		t.Fatal(err)
	}
	if _, err := approved.WriteToUDPAddrPort([]byte("approved"), target); err != nil {
		t.Fatal(err)
	}
	if err := relay.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	n, source, err := conn.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:n]); got != "approved" {
		t.Fatalf("payload = %q, want approved", got)
	}
	if source != approvedAddress.String() {
		t.Fatalf("source = %q, want %q", source, approvedAddress)
	}
}

func TestSafeUDPConnDestinationCapacity(t *testing.T) {
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	conn := &safeUDPConn{conn: relay}
	host := netip.MustParseAddr("127.0.0.1")

	for i := range maxUDPAllowedDestinations {
		destination := netip.AddrPortFrom(host, uint16(20_000+i))
		if _, err := conn.writeToDestination([]byte("fill"), destination); err != nil {
			t.Fatalf("authorize destination %d: %v", i, err)
		}
	}
	newDestination := netip.AddrPortFrom(host, 30_000)
	if _, err := conn.writeToDestination([]byte("reject"), newDestination); !errors.Is(err, ErrUDPDestinationCapacity) {
		t.Fatalf("new destination after capacity error = %v, want %v", err, ErrUDPDestinationCapacity)
	}
	if conn.destinationAllowed(newDestination) {
		t.Fatal("capacity-rejected destination was authorized")
	}

	// Filling the set must not revoke destinations that were already approved.
	existing := netip.AddrPortFrom(host, 20_000)
	if _, err := conn.writeToDestination([]byte("existing"), existing); err != nil {
		t.Fatalf("existing destination after capacity: %v", err)
	}
	conn.allowedMu.RLock()
	allowedCount := len(conn.allowed)
	conn.allowedMu.RUnlock()
	if allowedCount != maxUDPAllowedDestinations {
		t.Fatalf("allowed destination count = %d, want %d", allowedCount, maxUDPAllowedDestinations)
	}
}

func TestSafeUDPConnFailedWriteDoesNotAuthorize(t *testing.T) {
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := relay.Close(); err != nil {
		t.Fatal(err)
	}
	conn := &safeUDPConn{conn: relay}
	destination := netip.MustParseAddrPort("127.0.0.1:20000")
	if _, err := conn.writeToDestination([]byte("must fail"), destination); err == nil {
		t.Fatal("write on closed socket unexpectedly succeeded")
	}
	if conn.destinationAllowed(destination) {
		t.Fatal("failed write authorized its destination")
	}
}

func TestSafeUDPConnDestinationSetConcurrent(t *testing.T) {
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	conn := &safeUDPConn{conn: relay}
	host := netip.MustParseAddr("127.0.0.1")
	const attempts = maxUDPAllowedDestinations + 64

	var wait sync.WaitGroup
	start := make(chan struct{})
	errorsByAttempt := make(chan error, attempts)
	for i := range attempts {
		destination := netip.AddrPortFrom(host, uint16(31_000+i))
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := conn.writeToDestination([]byte("concurrent"), destination)
			_ = conn.destinationAllowed(destination)
			errorsByAttempt <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errorsByAttempt)

	var successes int
	for err := range errorsByAttempt {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrUDPDestinationCapacity):
		default:
			t.Fatalf("concurrent write error = %v", err)
		}
	}
	if successes != maxUDPAllowedDestinations {
		t.Fatalf("successful new destinations = %d, want %d", successes, maxUDPAllowedDestinations)
	}
	conn.allowedMu.RLock()
	allowedCount := len(conn.allowed)
	conn.allowedMu.RUnlock()
	if allowedCount != maxUDPAllowedDestinations {
		t.Fatalf("allowed destination count = %d, want %d", allowedCount, maxUDPAllowedDestinations)
	}
}

func TestDialContextCancellationClosesLateConnection(t *testing.T) {
	core := newDelayedCore()
	client := &Client{core: core}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := client.DialContext(ctx, "tcp", "1.1.1.1:443")
		result <- err
	}()
	<-core.started
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("DialContext error = %v, want context canceled", err)
	}
	close(core.release)
	select {
	case <-core.returned.closed:
	case <-time.After(time.Second):
		t.Fatal("connection returned after cancellation was not closed")
	}
}

func TestConcurrentCanceledDialsShareOneConnectionAttempt(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var startOnce sync.Once
	var attempts atomic.Int64
	core := &instantCore{}
	client := &Client{
		connectFunc: func() (hyclient.Client, *hyclient.HandshakeInfo, error) {
			attempts.Add(1)
			startOnce.Do(func() { close(started) })
			<-release
			return core, &hyclient.HandshakeInfo{UDPEnabled: true}, nil
		},
	}

	const callers = 128
	results := make(chan error, callers)
	var callersDone sync.WaitGroup
	for range callers {
		callersDone.Add(1)
		go func() {
			defer callersDone.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			_, err := client.DialContext(ctx, "tcp", "1.1.1.1:443")
			results <- err
		}()
	}
	<-started
	callersDone.Wait()
	close(results)
	for err := range results {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("canceled dial error = %v, want deadline exceeded", err)
		}
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("connection attempts = %d, want 1", got)
	}

	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", "1.1.1.1:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if got := attempts.Load(); got != 1 {
		t.Fatalf("successful reuse started %d connection attempts, want 1", got)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCanceledTCPDialsKeepUnderlyingWorkersBounded(t *testing.T) {
	core := newBlockingOpenCore()
	client := &Client{
		core:      core,
		closeCh:   make(chan struct{}),
		openSlots: make(chan struct{}, 2),
	}
	t.Cleanup(func() { _ = client.Close() })

	for index := 1; index <= 2; index++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, err := client.DialContext(ctx, "tcp", "1.1.1.1:443")
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("dial %d error = %v, want deadline", index, err)
		}
	}
	if got := core.calls.Load(); got != 2 {
		t.Fatalf("underlying open calls = %d, want 2", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, err := client.DialContext(ctx, "tcp", "1.1.1.1:443")
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("capacity-waiting dial error = %v, want deadline", err)
	}
	if got := core.calls.Load(); got != 2 {
		t.Fatalf("capacity gate allowed %d underlying opens, want 2", got)
	}

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for len(client.openSlots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(client.openSlots); got != 0 {
		t.Fatalf("worker slots after Close = %d, want 0", got)
	}
}

func TestAutoFallsBackAfterPrimaryUDPPathTimeout(t *testing.T) {
	core := newDelayedCore()
	primary := &Client{core: core}
	fallback := &recordingFallback{}
	var observed atomic.Int64
	auto, err := NewAutoClient(AutoConfig{
		Primary: primary, Fallback: fallback,
		AttemptTimeout: 30 * time.Millisecond,
		Cooldown:       time.Second,
		OnFallback: func(error) {
			observed.Add(1)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = auto.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := auto.DialContext(ctx, "tcp", "1.1.1.1:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if got := fallback.calls.Load(); got != 1 {
		t.Fatalf("TLS fallback calls = %d, want 1", got)
	}
	if got := observed.Load(); got != 1 {
		t.Fatalf("fallback observations = %d, want 1", got)
	}
	if got := auto.AccelerationMode(); got != "tls-fallback" {
		t.Fatalf("fallback acceleration mode = %q", got)
	}
	if got := auto.NegotiatedTx(); got != 0 {
		t.Fatalf("fallback negotiated rate = %d, want 0", got)
	}
	close(core.release)
	select {
	case <-core.returned.closed:
	case <-time.After(time.Second):
		t.Fatal("timed-out primary returned a connection that was not closed")
	}
	if _, err := auto.DialContext(ctx, "tcp", "1.1.1.1:443"); err != nil {
		t.Fatalf("circuit fallback: %v", err)
	}
	if got := fallback.calls.Load(); got != 2 {
		t.Fatalf("TLS fallback calls in cooldown = %d, want 2", got)
	}
	if got := observed.Load(); got != 1 {
		t.Fatalf("cooldown emitted %d fallback observations, want one", got)
	}
}

func TestAdmissionControllerEnforcesMaximumAndReleasesSlot(t *testing.T) {
	controller := newAdmissionController(testToken, 1)
	address := netip.MustParseAddrPort("127.0.0.1:12345")
	firstOK, firstID := controller.Authenticate(net.UDPAddrFromAddrPort(address), testToken, 0)
	if !firstOK || firstID == "" {
		t.Fatal("first authenticated connection was rejected")
	}
	if ok, _ := controller.Authenticate(net.UDPAddrFromAddrPort(address), testToken, 0); ok {
		t.Fatal("connection beyond configured maximum was admitted")
	}
	if ok, _ := controller.Authenticate(net.UDPAddrFromAddrPort(address), wrongTestToken, 0); ok {
		t.Fatal("wrong token was admitted")
	}
	controller.Disconnect(net.UDPAddrFromAddrPort(address), firstID, nil)
	if ok, id := controller.Authenticate(net.UDPAddrFromAddrPort(address), testToken, 0); !ok || id == "" {
		t.Fatal("released admission slot was not reusable")
	}
}

func TestClientCloseIsConcurrentIdempotentAndReturnsFirstError(t *testing.T) {
	want := errors.New("close failure")
	core := &closeErrorCore{err: want}
	client := &Client{core: core}
	const callers = 16
	errorsSeen := make(chan error, callers)
	var callersDone sync.WaitGroup
	for range callers {
		callersDone.Add(1)
		go func() {
			defer callersDone.Done()
			errorsSeen <- client.Close()
		}()
	}
	callersDone.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if !errors.Is(err, want) {
			t.Fatalf("Close error = %v, want %v", err, want)
		}
	}
	if got := core.calls.Load(); got != 1 {
		t.Fatalf("core Close calls = %d, want 1", got)
	}
	if _, err := client.DialContext(context.Background(), "tcp", "1.1.1.1:443"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("TCP dial after Close = %v, want net.ErrClosed", err)
	}
	if _, err := client.DialPacket(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("UDP dial after Close = %v, want net.ErrClosed", err)
	}
}

func TestServerServeAndCloseAreOneShotAndConcurrentSafe(t *testing.T) {
	core := newBlockingServerCore()
	server := &Server{core: core, address: &net.UDPAddr{}, admission: newAdmissionController(testToken, 1)}
	ctx, cancel := context.WithCancelCause(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	select {
	case <-core.started:
	case <-time.After(time.Second):
		t.Fatal("core Serve did not start")
	}
	if err := server.Serve(context.Background()); err == nil || !strings.Contains(err.Error(), "already serving") {
		t.Fatalf("second Serve error = %v", err)
	}
	cancel(context.Canceled)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop after context cancellation")
	}

	const closers = 16
	var closeDone sync.WaitGroup
	for range closers {
		closeDone.Add(1)
		go func() {
			defer closeDone.Done()
			if err := server.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		}()
	}
	closeDone.Wait()
	if got := core.closeCalls.Load(); got != 1 {
		t.Fatalf("core Close calls = %d, want 1", got)
	}
}

func TestAutoRejectsDialsAfterClose(t *testing.T) {
	core := newDelayedCore()
	close(core.release)
	primary := &Client{core: core}
	fallback := &recordingFallback{}
	auto, err := NewAutoClient(AutoConfig{
		Primary: primary, Fallback: fallback,
		AttemptTimeout: time.Second,
		Cooldown:       time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := auto.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := auto.DialContext(context.Background(), "tcp", "1.1.1.1:443"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("TCP dial after Close = %v, want net.ErrClosed", err)
	}
	if _, err := auto.DialPacket(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("UDP dial after Close = %v, want net.ErrClosed", err)
	}
	if got := fallback.calls.Load(); got != 0 {
		t.Fatalf("closed AutoClient invoked fallback %d times", got)
	}
}

func TestAutoCloseIsConcurrentIdempotentAndPreservesErrors(t *testing.T) {
	primaryErr := errors.New("primary close failure")
	fallbackErr := errors.New("fallback close failure")
	primaryCore := &closeErrorCore{err: primaryErr}
	primary := &Client{core: primaryCore}
	fallback := &recordingFallback{closeErr: fallbackErr}
	auto, err := NewAutoClient(AutoConfig{
		Primary: primary, Fallback: fallback,
		AttemptTimeout: time.Second,
		Cooldown:       time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	const callers = 16
	errorsSeen := make(chan error, callers)
	var callersDone sync.WaitGroup
	for range callers {
		callersDone.Add(1)
		go func() {
			defer callersDone.Done()
			errorsSeen <- auto.Close()
		}()
	}
	callersDone.Wait()
	close(errorsSeen)
	for closeErr := range errorsSeen {
		if !errors.Is(closeErr, primaryErr) || !errors.Is(closeErr, fallbackErr) {
			t.Fatalf("Close error = %v, want both close failures", closeErr)
		}
	}
	if got := primaryCore.calls.Load(); got != 1 {
		t.Fatalf("primary Close calls = %d, want 1", got)
	}
	if got := fallback.closeCalls.Load(); got != 1 {
		t.Fatalf("fallback Close calls = %d, want 1", got)
	}
}

func TestAutoCloseCancelsActiveFallbackBeforeClosingIt(t *testing.T) {
	primary := &Client{core: &instantCore{}}
	fallback := newContextBlockingFallback()
	auto, err := NewAutoClient(AutoConfig{
		Primary: primary, Fallback: fallback,
		AttemptTimeout: time.Second,
		Cooldown:       time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	dialDone := make(chan error, 1)
	go func() {
		_, err := auto.dialFallback(context.Background(), "tcp", "1.1.1.1:443")
		dialDone <- err
	}()
	select {
	case <-fallback.started:
	case <-time.After(time.Second):
		t.Fatal("fallback dial did not start")
	}
	if err := auto.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-dialDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("active fallback error = %v, want closed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel the active fallback")
	}
	if got := fallback.closeCalls.Load(); got != 1 {
		t.Fatalf("fallback close calls = %d, want 1", got)
	}
	if _, err := auto.dialFallback(context.Background(), "tcp", "1.1.1.1:443"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("fallback dispatch after Close = %v, want closed", err)
	}
	if got := fallback.calls.Load(); got != 1 {
		t.Fatalf("fallback was dispatched %d times, want one pre-Close call", got)
	}
}

func TestClientAndServerRejectCoreInvalidTimeoutsEagerly(t *testing.T) {
	_, clientTLS := testTLSConfigs(t)
	for name, modify := range map[string]func(*ClientConfig){
		"idle too short":      func(config *ClientConfig) { config.MaxIdleTimeout = time.Second },
		"keepalive too short": func(config *ClientConfig) { config.KeepAlivePeriod = time.Second },
		"idle too long":       func(config *ClientConfig) { config.MaxIdleTimeout = 121 * time.Second },
	} {
		t.Run("client "+name, func(t *testing.T) {
			config := ClientConfig{ServerAddress: "127.0.0.1:443", Token: testToken, TLSConfig: clientTLS}
			modify(&config)
			if _, err := NewClient(config); err == nil {
				t.Fatal("invalid core timeout passed eager validation")
			}
		})
	}
	serverTLS, _ := testTLSConfigs(t)
	for name, modify := range map[string]func(*ServerConfig){
		"idle too short":          func(config *ServerConfig) { config.MaxIdleTimeout = time.Second },
		"UDP idle too short":      func(config *ServerConfig) { config.UDPIdleTimeout = time.Second },
		"UDP idle too long":       func(config *ServerConfig) { config.UDPIdleTimeout = 601 * time.Second },
		"authentication too long": func(config *ServerConfig) { config.AuthenticationTimeout = 61 * time.Second },
		"too few unidirectional":  func(config *ServerConfig) { config.MaxIncomingUniStreams = 2 },
		"too many unidirectional": func(config *ServerConfig) { config.MaxIncomingUniStreams = 1025 },
		"source connections over global": func(config *ServerConfig) {
			config.MaxConnections, config.MaxClientConnections = 1, 2
		},
		"source TCP over global": func(config *ServerConfig) {
			config.MaxOutboundTCP, config.MaxClientTCPHandlers = 1, 2
		},
		"source UDP over global": func(config *ServerConfig) {
			config.MaxOutboundUDP, config.MaxClientUDPSessions = 1, 2
		},
		"unsafe Brutal opt-in": func(config *ServerConfig) { config.AllowClientBandwidth = true },
	} {
		t.Run("server "+name, func(t *testing.T) {
			config := ServerConfig{
				Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
				Outbound: &testOutbound{},
			}
			modify(&config)
			if _, err := Listen(config); err == nil {
				t.Fatal("invalid core timeout passed eager validation")
			}
		})
	}
}

type testOutbound struct {
	tcpDials  atomic.Int64
	udpChecks atomic.Int64
}

type hyRotatingResolver struct {
	answers [][]netip.Addr
	calls   atomic.Uint64
}

func (r *hyRotatingResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	call := r.calls.Add(1)
	index := int(call - 1)
	if index >= len(r.answers) {
		index = len(r.answers) - 1
	}
	return append([]netip.Addr(nil), r.answers[index]...), nil
}

func (o *testOutbound) TCP(address string) (net.Conn, error) {
	o.tcpDials.Add(1)
	return net.DialTimeout("tcp", address, 2*time.Second)
}

func (o *testOutbound) UDP(string) (hyserver.UDPConn, error) {
	o.udpChecks.Add(1)
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	return &testUDPConn{UDPConn: conn}, nil
}

func (o *testOutbound) CheckUDP(string) error {
	o.udpChecks.Add(1)
	return nil
}

type testUDPConn struct{ *net.UDPConn }

func (c *testUDPConn) ReadFrom(payload []byte) (int, string, error) {
	n, address, err := c.ReadFromUDPAddrPort(payload)
	if err != nil {
		return n, "", err
	}
	address = netip.AddrPortFrom(address.Addr().Unmap(), address.Port())
	return n, address.String(), nil
}

func (c *testUDPConn) WriteTo(payload []byte, address string) (int, error) {
	target, err := netip.ParseAddrPort(address)
	if err != nil {
		return 0, err
	}
	return c.WriteToUDPAddrPort(payload, target)
}

func startTestServer(t *testing.T, modify func(*ServerConfig)) (*Server, *tls.Config, *testOutbound) {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	outbound := &testOutbound{}
	config := ServerConfig{
		Address:   "127.0.0.1:0",
		Token:     testToken,
		TLSConfig: serverTLS,
		Outbound:  outbound,
	}
	if modify != nil {
		modify(&config)
	}
	server, err := Listen(config)
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
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("server did not stop")
		}
	})
	return server, clientTLS, outbound
}

func newTestClient(t *testing.T, server *Server, tlsConfig *tls.Config, modify func(*ClientConfig)) *Client {
	t.Helper()
	config := ClientConfig{
		ServerAddress: server.Addr().String(),
		Token:         testToken,
		TLSConfig:     tlsConfig,
	}
	if modify != nil {
		modify(&config)
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func exchangeTCP(t *testing.T, dialer transport.Dialer, address, message string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, message); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(message))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != message {
		t.Fatalf("response = %q, want %q", response, message)
	}
}

func startTCPEcho(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var connections sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
		connections.Wait()
	})
	return listener.Addr().String()
}

func startUDPEcho(t *testing.T) string {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 64<<10)
		for {
			n, address, err := listener.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			_, _ = listener.WriteToUDPAddrPort(buffer[:n], address)
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	return listener.LocalAddr().String()
}

func testTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	certPEM, keyPEM, err := security.GenerateSelfSignedCertificate(security.CertificateOptions{
		Hosts: []string{"127.0.0.1"}, ValidFor: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("test certificate was not accepted as a root")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
	}, &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		ServerName: "127.0.0.1",
		RootCAs:    pool,
	}
}

type delayedCore struct {
	started  chan struct{}
	release  chan struct{}
	returned *closeTrackingConn
	start    sync.Once
	close    sync.Once
}

type blockingOpenCore struct {
	release chan struct{}
	close   sync.Once
	calls   atomic.Int64
}

func newBlockingOpenCore() *blockingOpenCore {
	return &blockingOpenCore{release: make(chan struct{})}
}

func (c *blockingOpenCore) TCP(string) (net.Conn, error) {
	c.calls.Add(1)
	<-c.release
	return nil, net.ErrClosed
}

func (c *blockingOpenCore) UDP() (hyclient.HyUDPConn, error) {
	return nil, errors.New("not implemented")
}

func (c *blockingOpenCore) Close() error {
	c.close.Do(func() { close(c.release) })
	return nil
}

type closeErrorCore struct {
	err   error
	calls atomic.Int64
}

type instantCore struct {
	closed atomic.Bool
}

func (c *instantCore) TCP(string) (net.Conn, error) {
	if c.closed.Load() {
		return nil, net.ErrClosed
	}
	local, peer := net.Pipe()
	_ = peer.Close()
	return local, nil
}

func (c *instantCore) UDP() (hyclient.HyUDPConn, error) {
	return nil, errors.New("not implemented")
}

func (c *instantCore) Close() error {
	c.closed.Store(true)
	return nil
}

func (c *closeErrorCore) TCP(string) (net.Conn, error)     { return nil, net.ErrClosed }
func (c *closeErrorCore) UDP() (hyclient.HyUDPConn, error) { return nil, net.ErrClosed }
func (c *closeErrorCore) Close() error {
	c.calls.Add(1)
	return c.err
}

type blockingServerCore struct {
	started    chan struct{}
	closed     chan struct{}
	start      sync.Once
	close      sync.Once
	closeCalls atomic.Int64
}

func newBlockingServerCore() *blockingServerCore {
	return &blockingServerCore{started: make(chan struct{}), closed: make(chan struct{})}
}

func (c *blockingServerCore) Serve() error {
	c.start.Do(func() { close(c.started) })
	<-c.closed
	return net.ErrClosed
}

func (c *blockingServerCore) Close() error {
	c.closeCalls.Add(1)
	c.close.Do(func() { close(c.closed) })
	return nil
}

func newDelayedCore() *delayedCore {
	local, peer := net.Pipe()
	_ = peer.Close()
	return &delayedCore{
		started: make(chan struct{}), release: make(chan struct{}),
		returned: &closeTrackingConn{Conn: local, closed: make(chan struct{})},
	}
}

func (c *delayedCore) TCP(string) (net.Conn, error) {
	c.start.Do(func() { close(c.started) })
	<-c.release
	return c.returned, nil
}

func (c *delayedCore) UDP() (hyclient.HyUDPConn, error) {
	return nil, errors.New("not implemented")
}

func (c *delayedCore) Close() error {
	c.close.Do(func() { _ = c.returned.Close() })
	return nil
}

type closeTrackingConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *closeTrackingConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

type recordingFallback struct {
	calls      atomic.Int64
	closeCalls atomic.Int64
	closed     atomic.Bool
	closeErr   error
}

type contextBlockingFallback struct {
	started    chan struct{}
	start      sync.Once
	calls      atomic.Int64
	closeCalls atomic.Int64
}

func newContextBlockingFallback() *contextBlockingFallback {
	return &contextBlockingFallback{started: make(chan struct{})}
}

func (d *contextBlockingFallback) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	d.calls.Add(1)
	d.start.Do(func() { close(d.started) })
	<-ctx.Done()
	return nil, context.Cause(ctx)
}

func (d *contextBlockingFallback) Close() error {
	d.closeCalls.Add(1)
	return nil
}

func (d *recordingFallback) DialContext(context.Context, string, string) (net.Conn, error) {
	if d.closed.Load() {
		return nil, net.ErrClosed
	}
	d.calls.Add(1)
	local, peer := net.Pipe()
	_ = peer.Close()
	return local, nil
}

func (d *recordingFallback) Close() error {
	d.closeCalls.Add(1)
	d.closed.Store(true)
	return d.closeErr
}

var _ hyserver.Outbound = (*testOutbound)(nil)
var _ hyserver.UDPConn = (*testUDPConn)(nil)
var _ hyclient.Client = (*delayedCore)(nil)
var _ hyclient.Client = (*blockingOpenCore)(nil)
var _ hyclient.Client = (*closeErrorCore)(nil)
var _ hyclient.Client = (*instantCore)(nil)
var _ hyserver.Server = (*blockingServerCore)(nil)
