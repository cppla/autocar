package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"syscall"
	"testing"
)

func TestWebListenRetryRealUDPCollision(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	dialer := &webClientTestDialer{dial: func(context.Context, int64, string, string) (net.Conn, error) {
		return nil, errors.New("listen retry must not dial a destination")
	}}
	t.Cleanup(func() { assertWebListenRetryDialerUntouched(t, dialer) })
	streamAdmission, err := NewStreamAdmission(7)
	if err != nil {
		t.Fatal(err)
	}
	config := WebServerConfig{
		TCPAddress: "127.0.0.1:0", UDPAddress: "127.0.0.1:0", Token: testToken,
		TLSConfig: serverTLS, Dialer: dialer, StreamAdmission: streamAdmission,
		Cover: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Alt-Svc", `h3=":1"`)
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	reservedTCP, occupiedUDP := reserveWebTestTCPUDP(t)
	occupiedAddress := occupiedUDP.LocalAddr().String()
	if err := reservedTCP.Close(); err != nil {
		t.Fatal(err)
	}

	var sharedCore *serverCore
	var sharedVerifier *webAuthVerifier
	var sharedAdmission *webConnectionAdmission
	var sharedCover http.Handler
	checkShared := func(core *serverCore, verifier *webAuthVerifier, admission *webConnectionAdmission, cover http.Handler) {
		t.Helper()
		if core == nil || verifier == nil || admission == nil || cover == nil {
			t.Fatal("constructor received nil shared state")
		}
		if sharedCore == nil {
			sharedCore, sharedVerifier, sharedAdmission, sharedCover = core, verifier, admission, cover
		}
		if core != sharedCore || verifier != sharedVerifier || admission != sharedAdmission || cover != sharedCover {
			t.Fatal("retry recreated shared core, replay verifier, admission, or cover")
		}
		if core.sem != streamAdmission.sem || core.dialer != dialer {
			t.Fatal("retry replaced caller-owned stream admission or destination dialer")
		}
	}
	var firstBindError error
	var previousTCP string
	h2Calls, h3Calls, rollbackChecks := 0, 0, 0
	server, err := listenWebWith(config,
		func(attempt WebH2ServerConfig, core *serverCore, verifier *webAuthVerifier) (*WebH2Server, error) {
			h2Calls++
			checkShared(core, verifier, attempt.connectionAdmission, attempt.Cover)
			if attempt.Address != config.TCPAddress {
				t.Fatalf("retry changed ephemeral TCP request: %q", attempt.Address)
			}
			if h2Calls > 1 {
				// Probe once, before the next constructor: retrying this assertion
				// could conceal a real rollback leak.
				assertWebListenRetryTCPReleased(t, previousTCP)
				rollbackChecks++
			} else {
				// Keep the outer configuration ephemeral, but deterministically
				// make the first real TCP bind choose our occupied UDP port.
				attempt.Address = occupiedAddress
			}
			h2, err := listenWebH2WithCore(attempt, core, verifier)
			if err == nil {
				previousTCP = h2.Addr().String()
				t.Cleanup(func() { _ = h2.Close() })
			}
			return h2, err
		},
		func(attempt WebH3ServerConfig, core *serverCore, verifier *webAuthVerifier) (*WebH3Server, error) {
			h3Calls++
			checkShared(core, verifier, attempt.connectionAdmission, attempt.Cover)
			if attempt.Address != previousTCP {
				t.Fatalf("UDP did not follow the current bound TCP port: %q / %q", attempt.Address, previousTCP)
			}
			h3, err := listenWebH3WithCore(attempt, core, verifier)
			if h3 != nil {
				t.Cleanup(func() { _ = h3.Close() })
			}
			if h3Calls == 1 {
				if h3 != nil {
					t.Fatal("occupied UDP endpoint unexpectedly bound")
				}
				requireWebListenAddressInUse(t, err, "udp", occupiedAddress)
				firstBindError = err
			}
			return h3, err
		},
	)
	if server != nil {
		t.Cleanup(func() { _ = server.Close() })
	}
	if err != nil || server == nil {
		t.Fatalf("retry after real UDP collision: server=%t attempts=%d error=%v", server != nil, h2Calls, err)
	}
	if firstBindError == nil || h2Calls < 2 || h2Calls > webListenPortAttempts || h3Calls != h2Calls || rollbackChecks != h2Calls-1 {
		t.Fatalf("collision/retry evidence: first=%v H2=%d H3=%d rollback=%d", firstBindError, h2Calls, h3Calls, rollbackChecks)
	}
	if server.TCPAddr().String() != server.UDPAddr().String() || server.UDPAddr().String() == occupiedAddress {
		t.Fatalf("retry did not select one new TCP/UDP port: %s / %s", server.TCPAddr(), server.UDPAddr())
	}
	for name, handler := range map[string]http.Handler{"h2": server.h2.server.Handler, "h3": server.h3.server.Handler} {
		actual, ok := handler.(*webTunnelHandler)
		if !ok || actual.core != sharedCore || actual.auth != sharedVerifier || actual.cover != sharedCover {
			t.Fatalf("final %s handler lost shared state", name)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://cover.test/", nil))
		if got, want := recorder.Header().Get("Alt-Svc"), webH3AltSvcValue(server.UDPAddr()); got != want {
			t.Fatalf("%s Alt-Svc = %q, want final UDP port %q", name, got, want)
		}
	}
	if err := normalizeWebServerCloseError(server.Close()); err != nil {
		t.Fatalf("final server Close: %v", err)
	}
	assertWebListenRetryDialerUntouched(t, dialer)
}

func TestWebListenRetryPolicy(t *testing.T) {
	if webListenPortAttempts != 8 {
		t.Fatalf("bind attempt budget = %d, want 8", webListenPortAttempts)
	}
	nativeErrno, foreignErrno := syscall.EADDRINUSE, syscall.Errno(10048)
	if runtime.GOOS == "windows" {
		nativeErrno, foreignErrno = syscall.Errno(10048), syscall.EADDRINUSE
	}
	address := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 43217}
	collision := &net.OpError{Op: "listen", Net: "udp", Addr: address, Err: nativeErrno}
	ordinary := errors.New("non-collision constructor failure")
	cases := []struct {
		name, tcp, udp, normalizedTCP string
		h3Error                       error
		tcpError                      bool
		attempts                      int
	}{
		{"bounded_collision", "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0", collision, false, 8},
		{"wrapped_collision", "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0", fmt.Errorf("wrapped: %w", collision), false, 8},
		{"inherited_udp_zero", "127.0.0.1:0", "", "127.0.0.1:0", collision, false, 8},
		{"inherited_tcp_zero", "", "127.0.0.1:0", "127.0.0.1:0", collision, false, 8},
		{"numeric_zero_00", "127.0.0.1:00", "127.0.0.1:00", "127.0.0.1:00", collision, false, 8},
		{"tcp_zero_udp_fixed", "127.0.0.1:0", "127.0.0.1:43217", "127.0.0.1:43217", collision, false, 1},
		{"tcp_fixed_udp_zero", "127.0.0.1:43217", "127.0.0.1:0", "127.0.0.1:43217", collision, false, 1},
		{"both_fixed", "127.0.0.1:43217", "127.0.0.1:43217", "127.0.0.1:43217", collision, false, 1},
		{"tcp_constructor_error", "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0", collision, true, 1},
		{"ordinary_error", "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0", ordinary, false, 1},
		{"text_only", "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0", errors.New("listen udp: address already in use"), false, 1},
		{"bare_errno", "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0", nativeErrno, false, 1},
		{"tcp_op_error", "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0", &net.OpError{Op: "listen", Net: "tcp", Err: nativeErrno}, false, 1},
		{"udp_dial_error", "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0", &net.OpError{Op: "dial", Net: "udp", Err: nativeErrno}, false, 1},
		{"permission_error", "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0", &net.OpError{Op: "listen", Net: "udp", Err: syscall.EACCES}, false, 1},
		{"foreign_os_errno", "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0", &net.OpError{Op: "listen", Net: "udp", Err: foreignErrno}, false, 1},
		{"joined_error", "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0", errors.Join(collision, ordinary), false, 1},
		{"wrapped_join", "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0", fmt.Errorf("wrapped: %w", errors.Join(collision, ordinary)), false, 1},
		{"joined_op_cause", "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0", &net.OpError{Op: "listen", Net: "udp", Err: errors.Join(nativeErrno, ordinary)}, false, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dialer := &webClientTestDialer{}
			config := WebServerConfig{
				TCPAddress: tc.tcp, UDPAddress: tc.udp, Token: testToken,
				Cover: http.NotFoundHandler(), Dialer: dialer,
			}
			var listeners []*webListenRetryStubListener
			h2Calls, h3Calls := 0, 0
			server, err := listenWebWith(config,
				func(attempt WebH2ServerConfig, _ *serverCore, _ *webAuthVerifier) (*WebH2Server, error) {
					h2Calls++
					if attempt.Address != tc.normalizedTCP {
						t.Fatalf("effective TCP address = %q, want %q", attempt.Address, tc.normalizedTCP)
					}
					if tc.tcpError {
						// Even an error that looks like a UDP collision must never
						// trigger retry when returned by the TCP constructor.
						return nil, tc.h3Error
					}
					listener := &webListenRetryStubListener{address: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 43217}}
					listeners = append(listeners, listener)
					h2 := &WebH2Server{listener: listener, server: &http.Server{}, tcpOwner: newWebTCPConnectionOwner()}
					t.Cleanup(func() { _ = h2.Close() })
					return h2, nil
				},
				func(attempt WebH3ServerConfig, _ *serverCore, _ *webAuthVerifier) (*WebH3Server, error) {
					h3Calls++
					if attempt.Address != "127.0.0.1:43217" {
						t.Fatalf("UDP address did not use bound TCP port: %q", attempt.Address)
					}
					return nil, tc.h3Error
				},
			)
			if server != nil || err != tc.h3Error {
				t.Fatalf("failure identity changed: server=%t exactError=%t error=%v", server != nil, err == tc.h3Error, err)
			}
			wantH3 := tc.attempts
			if tc.tcpError {
				wantH3 = 0
			}
			if h2Calls != tc.attempts || h3Calls != wantH3 {
				t.Fatalf("constructor calls H2/H3 = %d/%d, want %d/%d", h2Calls, h3Calls, tc.attempts, wantH3)
			}
			for index, listener := range listeners {
				if listener.closes != 1 {
					t.Fatalf("attempt %d TCP close count = %d, want 1", index+1, listener.closes)
				}
			}
			assertWebListenRetryDialerUntouched(t, dialer)
		})
	}
}

func TestWebListenRetryCloseFailure(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	sentinel := errors.New("controlled TCP close failure")
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"sentinel", sentinel},
		{"joined_closed", errors.Join(net.ErrClosed, sentinel)},
		{"wrapped_joined_closed", fmt.Errorf("wrapped close: %w", errors.Join(net.ErrClosed, sentinel))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dialer := &webClientTestDialer{}
			t.Cleanup(func() { assertWebListenRetryDialerUntouched(t, dialer) })
			reservedTCP, occupiedUDP := reserveWebTestTCPUDP(t)
			occupiedAddress := occupiedUDP.LocalAddr().String()
			if err := reservedTCP.Close(); err != nil {
				t.Fatal(err)
			}
			config := WebServerConfig{
				TCPAddress: "127.0.0.1:0", UDPAddress: "127.0.0.1:0", Token: testToken,
				TLSConfig: serverTLS, Cover: http.NotFoundHandler(), Dialer: dialer,
			}
			h2Calls, h3Calls := 0, 0
			var bindError error
			server, err := listenWebWith(config,
				func(attempt WebH2ServerConfig, core *serverCore, verifier *webAuthVerifier) (*WebH2Server, error) {
					h2Calls++
					if h2Calls > 1 {
						t.Fatal("retry concealed a TCP rollback close failure")
					}
					attempt.Address = occupiedAddress
					h2, err := listenWebH2WithCore(attempt, core, verifier)
					if err == nil {
						h2.listener = &webListenRetryCloseErrorListener{Listener: h2.listener, closeError: tc.err}
						t.Cleanup(func() { _ = h2.Close() })
					}
					return h2, err
				},
				func(attempt WebH3ServerConfig, core *serverCore, verifier *webAuthVerifier) (*WebH3Server, error) {
					h3Calls++
					h3, err := listenWebH3WithCore(attempt, core, verifier)
					if h3 != nil {
						_ = h3.Close()
						t.Fatal("occupied UDP endpoint unexpectedly bound")
					}
					requireWebListenAddressInUse(t, err, "udp", occupiedAddress)
					bindError = err
					return nil, err
				},
			)
			if server != nil {
				_ = server.Close()
				t.Fatal("close failure returned a server")
			}
			if h2Calls != 1 || h3Calls != 1 || bindError == nil || !errors.Is(err, bindError) || !errors.Is(err, sentinel) {
				t.Fatalf("close failure lost causes or retried: H2=%d H3=%d bind=%v result=%v", h2Calls, h3Calls, bindError, err)
			}
			// The injected close reports failure only after closing the real
			// listener. Confirm that rollback happened, without retrying the bind.
			assertWebListenRetryTCPReleased(t, occupiedAddress)
			assertWebListenRetryDialerUntouched(t, dialer)
		})
	}
}

func assertWebListenRetryTCPReleased(t *testing.T, address string) {
	t.Helper()
	probe, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("TCP listener was not released before retry: %v", err)
	}
	if err := probe.Close(); err != nil {
		t.Fatalf("close rollback probe: %v", err)
	}
}

func assertWebListenRetryDialerUntouched(t *testing.T, dialer *webClientTestDialer) {
	t.Helper()
	if got := dialer.calls.Load(); got != 0 {
		t.Errorf("listener setup made %d destination dials", got)
	}
	if got := dialer.closeCalls.Load(); got != 0 {
		t.Errorf("listener setup closed caller-owned dialer %d times", got)
	}
}

// These policy-only listeners never bind a socket. The real collision and
// rollback behavior is exercised separately above with OS listeners.
type webListenRetryStubListener struct {
	address net.Addr
	closes  int
}

func (l *webListenRetryStubListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (l *webListenRetryStubListener) Addr() net.Addr            { return l.address }
func (l *webListenRetryStubListener) Close() error {
	l.closes++
	return nil
}

type webListenRetryCloseErrorListener struct {
	net.Listener
	closeError error
}

func (l *webListenRetryCloseErrorListener) Close() error {
	return errors.Join(l.Listener.Close(), l.closeError)
}
