package tunnel

import (
	"testing"
	"time"

	"github.com/apernet/quic-go"
)

func TestWebH3QUICConfigHardeningCannotBeBypassed(t *testing.T) {
	input := &quic.Config{
		Versions:                       []quic.Version{quic.Version2},
		Allow0RTT:                      true,
		EnableDatagrams:                false,
		HandshakeIdleTimeout:           time.Hour,
		MaxIdleTimeout:                 time.Hour,
		KeepAlivePeriod:                time.Hour,
		MaxIncomingStreams:             1 << 20,
		MaxIncomingUniStreams:          1 << 20,
		InitialStreamReceiveWindow:     1 << 30,
		MaxStreamReceiveWindow:         1 << 30,
		InitialConnectionReceiveWindow: 1 << 30,
		MaxConnectionReceiveWindow:     1 << 30,
	}
	input.GetConfigForClient = func(*quic.ClientInfo) (*quic.Config, error) {
		return input.Clone(), nil
	}

	server := hardenedWebH3ServerConfig(input, 1024, 7*time.Second)
	assertHardenedWebH3ServerConfig(t, server, 7*time.Second)
	selected, err := server.GetConfigForClient(&quic.ClientInfo{})
	if err != nil {
		t.Fatal(err)
	}
	assertHardenedWebH3ServerConfig(t, selected, 7*time.Second)
	if selected.GetConfigForClient != nil {
		t.Fatal("dynamic QUIC config retained a recursive selector")
	}
	if !input.Allow0RTT || input.MaxIncomingStreams != 1<<20 {
		t.Fatal("hardening mutated the caller's QUIC config")
	}

	client := hardenedWebH3ClientConfig(input, 6*time.Second, H3FingerprintNative)
	if client.Allow0RTT || !client.EnableDatagrams || client.MaxIncomingStreams != -1 ||
		client.MaxIncomingUniStreams != webH3RequiredIncomingUniStreams {
		t.Fatalf("client stream/datagram hardening = %+v", client)
	}
	if client.HandshakeIdleTimeout != 6*time.Second || client.MaxIdleTimeout != webH3MaxIdleTimeout ||
		client.KeepAlivePeriod != webH3MaxKeepAlivePeriod {
		t.Fatalf("client timeout hardening = handshake %s idle %s keepalive %s", client.HandshakeIdleTimeout, client.MaxIdleTimeout, client.KeepAlivePeriod)
	}
	assertWebH3Windows(t, client)
	if len(client.Versions) != 1 || client.Versions[0] != quic.Version2 {
		t.Fatalf("native rollback versions = %v, want caller's QUIC v2", client.Versions)
	}

	defaults := hardenedWebH3ClientConfig(nil, 5*time.Second, H3FingerprintChrome202608)
	if !defaults.ChromeParrot || defaults.KeepAlivePeriod != 0 {
		t.Fatalf("default client profile = ChromeParrot %v keepalive %s", defaults.ChromeParrot, defaults.KeepAlivePeriod)
	}
	if len(defaults.Versions) != 1 || defaults.Versions[0] != quic.Version1 {
		t.Fatalf("ChromeParrot versions = %v, want QUIC v1 only", defaults.Versions)
	}
	chromeFromV2 := hardenedWebH3ClientConfig(input, 5*time.Second, H3FingerprintChrome202608)
	if len(chromeFromV2.Versions) != 1 || chromeFromV2.Versions[0] != quic.Version1 {
		t.Fatalf("ChromeParrot retained incompatible caller versions %v", chromeFromV2.Versions)
	}
	if len(input.Versions) != 1 || input.Versions[0] != quic.Version2 {
		t.Fatal("client hardening mutated the caller's QUIC versions")
	}
	if client.ChromeParrot {
		t.Fatal("native rollback profile unexpectedly enabled ChromeParrot")
	}
}

func assertHardenedWebH3ServerConfig(t *testing.T, config *quic.Config, handshake time.Duration) {
	t.Helper()
	if config.Allow0RTT || !config.EnableDatagrams || config.ChromeParrot {
		t.Fatalf("server 0-RTT/datagrams/ChromeParrot = %v/%v/%v", config.Allow0RTT, config.EnableDatagrams, config.ChromeParrot)
	}
	if config.MaxIncomingStreams != defaultWebMaxStreamsPerConnection ||
		config.MaxIncomingUniStreams != webH3RequiredIncomingUniStreams {
		t.Fatalf("server stream limits = %d/%d", config.MaxIncomingStreams, config.MaxIncomingUniStreams)
	}
	if config.HandshakeIdleTimeout != handshake || config.MaxIdleTimeout != webH3MaxIdleTimeout || config.KeepAlivePeriod != 0 {
		t.Fatalf("server timeout hardening = handshake %s idle %s keepalive %s", config.HandshakeIdleTimeout, config.MaxIdleTimeout, config.KeepAlivePeriod)
	}
	assertWebH3Windows(t, config)
}

func assertWebH3Windows(t *testing.T, config *quic.Config) {
	t.Helper()
	if config.InitialStreamReceiveWindow > webH3InitialStreamWindow || config.MaxStreamReceiveWindow > webH3MaxStreamWindow ||
		config.InitialConnectionReceiveWindow > webH3InitialConnWindow || config.MaxConnectionReceiveWindow > webH3MaxConnWindow {
		t.Fatalf("unbounded QUIC receive windows: %+v", config)
	}
}
