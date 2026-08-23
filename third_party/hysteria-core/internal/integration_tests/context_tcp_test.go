package integration_tests

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/internal/integration_tests/mocks"
	"github.com/apernet/hysteria/core/v2/server"
)

type blockingTCPOutbound struct {
	blocked string
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (o *blockingTCPOutbound) TCP(address string) (net.Conn, error) {
	if address == o.blocked {
		o.once.Do(func() { close(o.started) })
		<-o.release
		return nil, errors.New("released blocked dial")
	}
	return net.Dial("tcp", address)
}

func (o *blockingTCPOutbound) UDP(string) (server.UDPConn, error) {
	return nil, errors.New("UDP disabled")
}

func (o *blockingTCPOutbound) CheckUDP(string) error { return errors.New("UDP disabled") }

func TestNewClientContextCancellationStopsHandshake(t *testing.T) {
	blackhole, address, err := serverConn()
	require.NoError(t, err)
	defer blackhole.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	started := time.Now()
	core, _, err := client.NewClientContext(ctx, &client.Config{
		ServerAddr: address,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	assert.Nil(t, core)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(started), time.Second)
}

func TestTCPContextCancellationKeepsSharedConnectionHealthy(t *testing.T) {
	udpConn, udpAddr, err := serverConn()
	require.NoError(t, err)
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
	outbound := &blockingTCPOutbound{
		blocked: "blocked.test:443",
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	relay, err := server.NewServer(&server.Config{
		TLSConfig:     serverTLSConfig(),
		Conn:          udpConn,
		DisableUDP:    true,
		Authenticator: auth,
		Outbound:      outbound,
	})
	require.NoError(t, err)
	defer relay.Close()
	defer close(outbound.release)
	go relay.Serve()

	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	echoServer := &tcpEchoServer{Listener: echoListener}
	defer echoServer.Close()
	go echoServer.Serve()

	core, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	require.NoError(t, err)
	defer core.Close()
	contextual, ok := core.(client.ContextualTCPClient)
	require.True(t, ok)

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, openErr := contextual.TCPContext(ctx, outbound.blocked)
		result <- openErr
	}()
	select {
	case <-outbound.started:
	case <-time.After(time.Second):
		t.Fatal("relay did not start blocked outbound dial")
	}
	cancel()
	select {
	case openErr := <-result:
		assert.ErrorIs(t, openErr, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("canceled TCP request remained blocked")
	}

	conn, err := core.TCP(echoListener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	payload := []byte("shared QUIC connection survives stream cancellation")
	_, err = conn.Write(payload)
	require.NoError(t, err)
	received := make([]byte, len(payload))
	_, err = io.ReadFull(conn, received)
	require.NoError(t, err)
	assert.Equal(t, payload, received)
}
