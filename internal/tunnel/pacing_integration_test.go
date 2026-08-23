package tunnel

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/cppla/autocar/internal/accel"
	"github.com/cppla/autocar/internal/protocol"
)

func TestRenoPacerDoesNotChunkBypassWrites(t *testing.T) {
	reno, err := newConnectionPacer(PacingConfig{
		Mode:       accel.ModeReno,
		BurstBytes: 10,
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := reno.maxChunkBytes(); got != 0 {
		t.Fatalf("Reno max chunk = %d, want bypass value 0", got)
	}

	adaptive, err := newConnectionPacer(PacingConfig{
		Mode:       accel.ModeAdaptive,
		BurstBytes: 10,
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := adaptive.maxChunkBytes(); got != 10 {
		t.Fatalf("adaptive max chunk = %d, want 10", got)
	}
}

func TestQUICPacingMetadataIsDirectional(t *testing.T) {
	targetAddress, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	serverTLS, clientTLS := testTLSConfigs(t)

	tests := []struct {
		name         string
		server       QUICServerConfig
		client       ClientConfig
		wantLocal    string
		wantRemote   string
		wantTx       uint64
		wantRemoteTx uint64
	}{
		{
			name:      "adaptive",
			server:    QUICServerConfig{Pacing: PacingConfig{Mode: accel.ModeAdaptive, Profile: accel.ProfileBalanced}},
			client:    ClientConfig{Pacing: PacingConfig{Mode: accel.ModeAdaptive, Profile: accel.ProfileBalanced}},
			wantLocal: "adaptive-balanced", wantRemote: "adaptive-balanced",
		},
		{
			name:      "reno bypass",
			server:    QUICServerConfig{Pacing: PacingConfig{Mode: accel.ModeReno, Profile: accel.ProfileBalanced}},
			client:    ClientConfig{Pacing: PacingConfig{Mode: accel.ModeReno, Profile: accel.ProfileBalanced}},
			wantLocal: "reno", wantRemote: "reno",
		},
		{
			name: "fixed rate is capped by the receiver",
			server: QUICServerConfig{
				Pacing: PacingConfig{Mode: accel.ModeFixedRate, Profile: accel.ProfileBalanced},
				MaxTx:  3_000_000, MaxRx: 2_000_000, AllowClientRates: true,
			},
			client: ClientConfig{
				Pacing: PacingConfig{Mode: accel.ModeFixedRate, Profile: accel.ProfileBalanced},
				MaxTx:  4_000_000, MaxRx: 1_500_000,
			},
			wantLocal: "fixed-rate", wantRemote: "fixed-rate",
			wantTx: 2_000_000, wantRemoteTx: 1_500_000,
		},
	}

	for index := range tests {
		test := &tests[index]
		t.Run(test.name, func(t *testing.T) {
			test.server.Address = "127.0.0.1:0"
			test.server.Token = testToken
			test.server.TLSConfig = serverTLS
			test.server.Dialer = &net.Dialer{}
			server := startConfiguredQUICServer(t, test.server)

			test.client.ServerAddress = server.Addr().String()
			test.client.Token = testToken
			test.client.TLSConfig = clientTLS
			client, err := NewClient(test.client)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err := exchange(client, targetAddress, "pacing metadata"); err != nil {
				t.Fatal(err)
			}
			if got := client.AccelerationMode(); got != test.wantLocal {
				t.Fatalf("local sender = %q, want %q", got, test.wantLocal)
			}
			if got := client.RemoteTxAcceleration(); got != test.wantRemote {
				t.Fatalf("relay sender = %q, want %q", got, test.wantRemote)
			}
			if got := client.NegotiatedTx(); got != test.wantTx {
				t.Fatalf("client fixed rate = %d, want %d", got, test.wantTx)
			}
			if got := client.RemoteNegotiatedTx(); got != test.wantRemoteTx {
				t.Fatalf("relay fixed rate = %d, want %d", got, test.wantRemoteTx)
			}
		})
	}
}

func TestQUICServerRejectsUnapprovedClientRates(t *testing.T) {
	targetAddress, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	serverTLS, clientTLS := testTLSConfigs(t)
	server := startConfiguredQUICServer(t, QUICServerConfig{
		Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
		Dialer: &net.Dialer{},
	})
	client, err := NewClient(ClientConfig{
		ServerAddress: server.Addr().String(), Token: testToken, TLSConfig: clientTLS,
		Pacing: PacingConfig{Mode: accel.ModeFixedRate, Profile: accel.ProfileBalanced},
		MaxTx:  1_000_000, MaxRx: 1_000_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, err := client.DialContext(context.Background(), "tcp", targetAddress)
	if conn != nil {
		_ = conn.Close()
		t.Fatal("server accepted disabled client rate hints")
	}
	var remoteErr *RemoteError
	if !errors.As(err, &remoteErr) || remoteErr.Status != protocol.StatusBadRequest {
		t.Fatalf("rate rejection = %v, want bad-request RemoteError", err)
	}
}

func TestClientValidatesPacingCapsBeforeApplyingThem(t *testing.T) {
	validFixed := protocol.Response{
		Status: protocol.StatusOK,
		MaxTx:  80, MaxRx: 90,
		TxMode: protocol.PacingFixedRate, TxProfile: protocol.ProfileBalanced,
		RxMode: protocol.PacingFixedRate, RxProfile: protocol.ProfileBalanced,
	}
	tests := []struct {
		name     string
		client   Client
		response protocol.Response
		wantErr  bool
	}{
		{
			name: "valid lower directional caps",
			client: Client{
				txMode: protocol.PacingFixedRate, txProfile: protocol.ProfileBalanced,
				maxTx: 100, maxRx: 100,
			},
			response: validFixed,
		},
		{
			name: "relay raises client rate",
			client: Client{
				txMode: protocol.PacingFixedRate, txProfile: protocol.ProfileBalanced,
				maxTx: 100, maxRx: 100,
			},
			response: func() protocol.Response {
				response := validFixed
				response.MaxTx = 101
				return response
			}(),
			wantErr: true,
		},
		{
			name: "relay raises requested receive rate",
			client: Client{
				txMode: protocol.PacingFixedRate, txProfile: protocol.ProfileBalanced,
				maxTx: 100, maxRx: 100,
			},
			response: func() protocol.Response {
				response := validFixed
				response.MaxRx = 101
				return response
			}(),
			wantErr: true,
		},
		{
			name: "relay introduces fixed client pacing",
			client: Client{
				txMode: protocol.PacingAdaptive, txProfile: protocol.ProfileBalanced,
			},
			response: validFixed,
			wantErr:  true,
		},
	}
	for index := range tests {
		test := &tests[index]
		t.Run(test.name, func(t *testing.T) {
			err := test.client.validatePacingResponse(test.response, 0, false)
			if (err != nil) != test.wantErr {
				t.Fatalf("validatePacingResponse() error = %v, wantErr=%v", err, test.wantErr)
			}
		})
	}
}

func startConfiguredQUICServer(t *testing.T, config QUICServerConfig) *QUICServer {
	t.Helper()
	server, err := ListenQUIC(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		if err := <-done; err != nil {
			t.Errorf("QUIC Serve: %v", err)
		}
	})
	return server
}
