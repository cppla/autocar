package tunnel

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/accel"
)

func TestQUICStreamPacingDeadlineMatchesNetConn(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	target, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	server := startDatagramQUICServer(t, QUICServerConfig{
		Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
		MaxTx: 1000, MaxRx: 1000, AllowClientRates: true,
	})
	client := newDatagramClient(t, server, clientTLS, ClientConfig{
		Pacing: PacingConfig{Mode: accel.ModeFixedRate}, MaxTx: 1000,
	})
	defer client.Close()
	for _, bothDirections := range []bool{false, true} {
		name := "SetWriteDeadline"
		if bothDirections {
			name = "SetDeadline"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx, "tcp", target)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			setDeadline := conn.SetWriteDeadline
			if bothDirections {
				setDeadline = conn.SetDeadline
			}
			if err := setDeadline(time.Now().Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
			// Compare the underlying real QUIC stream with its paced net.Conn
			// adapter. Neither timed-out write may reach the TCP destination.
			n, err := conn.Write([]byte("timed-out adapter write"))
			assertQUICPacingDeadlineError(t, n, err)
			n, err = conn.(*quicStreamConn).stream.Write([]byte("timed-out raw write"))
			assertQUICPacingDeadlineError(t, n, err)
			if err := setDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
			if err := completeExchange(conn, "same stream after timeout"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func assertQUICPacingDeadlineError(t *testing.T, n int, err error) {
	t.Helper()
	var timeout net.Error
	if n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) || !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("Write = %d, %T %v; want zero bytes and net.Conn timeout", n, err, err)
	}
}

func TestQUICStreamPacingDeadlineUpdateBeforeReturn(t *testing.T) {
	for _, action := range []string{"extend", "clear", "close"} {
		t.Run(action, func(t *testing.T) {
			stream := &recordingQUICStream{}
			expired, release := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			calls := 0
			pacer := &activityQUICWritePacer{waitFn: func(ctx context.Context) error {
				calls++
				if calls > 1 {
					return ctx.Err()
				}
				<-ctx.Done()
				close(expired)
				<-release
				return context.Cause(ctx)
			}}
			conn := newQUICStreamConnWithPacer(stream, nil, pacer)
			defer conn.Close()
			if err := conn.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { _, err := conn.Write([]byte("pending")); done <- err }()
			awaitActivitySignal(t, expired)
			// Model scheduling between the pacer's actual timeout and its
			// return. The adapter must honor the newer connection state.
			switch action {
			case "extend":
				_ = conn.SetWriteDeadline(time.Now().Add(time.Minute))
			case "clear":
				_ = conn.SetWriteDeadline(time.Time{})
			case "close":
				_ = conn.Close()
			}
			unblock()
			err := awaitActivityResult(t, done)
			if action == "close" {
				if !errors.Is(err, net.ErrClosed) || len(stream.writes) != 0 || calls != 1 {
					t.Fatalf("closed write = %v, writes=%v, waits=%d", err, stream.writes, calls)
				}
			} else if err != nil || len(stream.writes) != 1 || calls != 2 {
				t.Fatalf("updated deadline write = %v, writes=%v, waits=%d", err, stream.writes, calls)
			}
		})
	}
}

func TestQUICStreamPacingErrorWithoutExpiredWriteDeadline(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(cause.Error(), func(t *testing.T) {
			pacer := &activityQUICWritePacer{waitFn: func(context.Context) error { return cause }}
			stream := &recordingQUICStream{}
			conn := newQUICStreamConnWithPacer(stream, nil, pacer)
			defer conn.Close()
			for _, deadline := range []time.Time{{}, time.Now().Add(time.Minute)} {
				if err := conn.SetWriteDeadline(deadline); err != nil {
					t.Fatal(err)
				}
				if n, err := conn.Write([]byte("not admitted")); n != 0 || err != cause {
					t.Fatalf("pacer error changed without a write timeout: %d, %v; want %v", n, err, cause)
				}
			}
			if len(stream.writes) != 0 {
				t.Fatal("failed admission reached the transport")
			}
		})
	}
}
