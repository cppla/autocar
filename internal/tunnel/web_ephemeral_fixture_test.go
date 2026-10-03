package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"syscall"
	"testing"

	"github.com/cppla/autocar/internal/transport"
)

const webEphemeralFixtureAttempts = 32

// Test setup only: TCP chooses a free ephemeral port before ListenWeb binds
// UDP to that same port. The independent UDP namespace may already own it.
// Never use this helper for fixed-address policy or rollback assertions.
func listenWebEphemeralFixture(config WebServerConfig) (*WebServer, error) {
	return listenWebEphemeralFixtureWith(config, ListenWeb)
}

func listenWebEphemeralFixtureWith(config WebServerConfig, listen func(WebServerConfig) (*WebServer, error)) (*WebServer, error) {
	if config.TCPAddress != "127.0.0.1:0" || config.UDPAddress != "127.0.0.1:0" {
		return listen(config)
	}
	for attempt := 0; ; attempt++ {
		server, err := listen(config)
		if server != nil || err == nil || attempt+1 == webEphemeralFixtureAttempts || !webEphemeralFixtureUDPCollision(err) {
			return server, err
		}
	}
}

func webEphemeralFixtureUDPCollision(err error) bool {
	// A rollback failure joined to the bind error must not be hidden by setup
	// retry. Accept a single wrapping chain only, not any matching joined leaf.
	for current := err; current != nil; current = errors.Unwrap(current) {
		if _, joined := current.(interface{ Unwrap() []error }); joined {
			return false
		}
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "listen" || opErr.Net != "udp" {
		return false
	}
	address, ok := opErr.Addr.(*net.UDPAddr)
	return ok && address != nil && address.Zone == "" && address.Port > 0 && address.Port <= 65535 &&
		address.IP.Equal(net.IPv4(127, 0, 0, 1)) && isWebTestAddressInUse(opErr.Err)
}

func TestWebEphemeralFixtureListenRetriesRealUDPPortCollision(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	config := WebServerConfig{
		TCPAddress: "127.0.0.1:0", UDPAddress: "127.0.0.1:0", Token: testToken,
		TLSConfig: serverTLS, Cover: http.NotFoundHandler(),
		Dialer: transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("ephemeral listener fixture forbids destination dialing")
		}),
	}
	reservedTCP, occupiedUDP := reserveWebTestTCPUDP(t)
	occupiedAddress := occupiedUDP.LocalAddr().String()
	if err := reservedTCP.Close(); err != nil {
		t.Fatal(err)
	}
	var firstError error
	calls := 0
	server, err := listenWebEphemeralFixtureWith(config, func(attempt WebServerConfig) (*WebServer, error) {
		calls++
		if attempt.TCPAddress != config.TCPAddress || attempt.UDPAddress != config.UDPAddress {
			t.Fatalf("helper changed caller's ephemeral addresses: %q/%q", attempt.TCPAddress, attempt.UDPAddress)
		}
		if calls > 1 {
			// All retries go through the real normal :0 constructor. A later
			// unrelated ephemeral collision is still subject to the same bound.
			return ListenWeb(attempt)
		}
		// The controlled first call uses an actually occupied owned UDP port,
		// not a fabricated bind error. TCP is available in its own namespace.
		attempt.TCPAddress, attempt.UDPAddress = occupiedAddress, occupiedAddress
		unexpected, err := ListenWeb(attempt)
		if unexpected != nil {
			_ = unexpected.Close()
			t.Fatal("actual occupied UDP constructor unexpectedly returned a server")
		}
		requireWebListenAddressInUse(t, err, "udp", occupiedAddress)
		firstError = err
		// Prove rollback before any retry: no retrying bind or helper is used
		// for this assertion, so a leaked TCP listener cannot be concealed.
		probe, probeErr := net.Listen("tcp", occupiedAddress)
		if probeErr != nil {
			t.Fatalf("original ListenWeb failed to roll back TCP: %v", probeErr)
		}
		if closeErr := probe.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		return nil, err
	})
	if server != nil {
		t.Cleanup(func() {
			if err := normalizeWebServerCloseError(server.Close()); err != nil {
				t.Errorf("owned ephemeral server cleanup: %v", err)
			}
		})
	}
	if err != nil || server == nil {
		t.Fatalf("normal ephemeral setup after actual UDP collision: server=%t calls=%d err=%v", server != nil, calls, err)
	}
	if firstError == nil || calls < 2 || calls > webEphemeralFixtureAttempts {
		t.Fatalf("real collision/retry evidence: first=%v calls=%d", firstError, calls)
	}
	if server.TCPAddr().String() != server.UDPAddr().String() {
		t.Fatalf("successful retry changed shared TCP/UDP authority: %s/%s", server.TCPAddr(), server.UDPAddr())
	}
	if config.TCPAddress != "127.0.0.1:0" || config.UDPAddress != "127.0.0.1:0" {
		t.Fatal("fixture mutated the caller's config")
	}
	t.Logf("actual owned UDP bind failure, immediate TCP rollback, and normal shared-port retry succeeded (%d attempts)", calls)
}

func TestWebEphemeralFixtureListenRetryPolicy(t *testing.T) {
	// Pure policy controls below are synthetic, not network observations. The
	// top above separately proves real ListenWeb bind failure and TCP rollback.
	nativeErrno := syscall.EADDRINUSE
	if runtime.GOOS == "windows" {
		nativeErrno = syscall.Errno(10048)
	}
	address := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 43217}
	collision := &net.OpError{Op: "listen", Net: "udp", Addr: address, Err: nativeErrno}
	ordinary := errors.New("private ordinary setup error")
	tests := []struct {
		name     string
		tcp, udp string
		err      error
		calls    int
	}{
		{"udp_collision_bound", "127.0.0.1:0", "127.0.0.1:0", collision, webEphemeralFixtureAttempts},
		{"wrapped_udp_collision_bound", "127.0.0.1:0", "127.0.0.1:0", fmt.Errorf("constructor: %w", collision), webEphemeralFixtureAttempts},
		{"ordinary_error", "127.0.0.1:0", "127.0.0.1:0", ordinary, 1},
		{"matching_text_only", "127.0.0.1:0", "127.0.0.1:0", errors.New("listen udp 127.0.0.1:43217: address already in use"), 1},
		{"bare_errno", "127.0.0.1:0", "127.0.0.1:0", nativeErrno, 1},
		{"tcp_collision", "127.0.0.1:0", "127.0.0.1:0", &net.OpError{Op: "listen", Net: "tcp", Addr: address, Err: nativeErrno}, 1},
		{"udp4_not_production_network", "127.0.0.1:0", "127.0.0.1:0", &net.OpError{Op: "listen", Net: "udp4", Addr: address, Err: nativeErrno}, 1},
		{"non_listen_operation", "127.0.0.1:0", "127.0.0.1:0", &net.OpError{Op: "dial", Net: "udp", Addr: address, Err: nativeErrno}, 1},
		{"permission_error", "127.0.0.1:0", "127.0.0.1:0", &net.OpError{Op: "listen", Net: "udp", Addr: address, Err: syscall.EACCES}, 1},
		{"non_loopback_error_address", "127.0.0.1:0", "127.0.0.1:0", &net.OpError{Op: "listen", Net: "udp", Addr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 43217}, Err: nativeErrno}, 1},
		{"missing_error_address", "127.0.0.1:0", "127.0.0.1:0", &net.OpError{Op: "listen", Net: "udp", Err: nativeErrno}, 1},
		{"joined_rollback_error", "127.0.0.1:0", "127.0.0.1:0", errors.Join(collision, ordinary), 1},
		{"joined_inner_error", "127.0.0.1:0", "127.0.0.1:0", &net.OpError{Op: "listen", Net: "udp", Addr: address, Err: errors.Join(nativeErrno, ordinary)}, 1},
		{"fixed_tcp", "127.0.0.1:43217", "127.0.0.1:0", collision, 1},
		{"fixed_udp", "127.0.0.1:0", "127.0.0.1:43217", collision, 1},
		{"both_fixed", "127.0.0.1:43217", "127.0.0.1:43217", collision, 1},
		{"inherited_udp", "127.0.0.1:0", "", collision, 1},
		{"wildcard_tcp", ":0", "127.0.0.1:0", collision, 1},
		{"dns_authority", "localhost:0", "127.0.0.1:0", collision, 1},
		{"ipv6_ephemeral", "[::1]:0", "[::1]:0", collision, 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			server, err := listenWebEphemeralFixtureWith(WebServerConfig{TCPAddress: test.tcp, UDPAddress: test.udp}, func(WebServerConfig) (*WebServer, error) {
				calls++
				return nil, test.err
			})
			if server != nil || err != test.err || calls != test.calls {
				t.Fatalf("error identity/bounded attempts: server=%t exact=%t calls=%d; want %d", server != nil, err == test.err, calls, test.calls)
			}
		})
	}
	t.Run("successful_result_not_retried", func(t *testing.T) {
		owned := &WebServer{}
		calls := 0
		server, err := listenWebEphemeralFixtureWith(WebServerConfig{TCPAddress: "127.0.0.1:0", UDPAddress: "127.0.0.1:0"}, func(WebServerConfig) (*WebServer, error) {
			calls++
			return owned, nil
		})
		if server != owned || err != nil || calls != 1 {
			t.Fatalf("successful constructor changed: exact=%t err=%v calls=%d", server == owned, err, calls)
		}
	})
}
