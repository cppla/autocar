package tunnel

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

// Models a context deadline whose timer has not yet published Done. The
// caller's fixed deadline is authoritative even if its timer loses the race.
type webH2UnpublishedDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (c webH2UnpublishedDeadlineContext) Deadline() (time.Time, bool) {
	return c.deadline, true
}

func TestWebH2DialContextPreflightCause(t *testing.T) {
	for _, mode := range []string{"canceled_cause", "elapsed_unpublished_deadline"} {
		t.Run(mode, func(t *testing.T) {
			_, clientTLS := testTLSConfigs(t)
			client, err := NewWebH2Client(WebH2ClientConfig{
				ServerAddress: "127.0.0.1:443", Token: testToken, TLSConfig: clientTLS,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			var calls atomic.Int32
			client.dialer = transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
				calls.Add(1)
				return nil, errors.New("expired caller reached physical dial")
			})
			var ctx context.Context
			want := error(context.DeadlineExceeded)
			if mode == "canceled_cause" {
				cause := errors.New("private H2 caller cancellation")
				parent, cancel := context.WithCancelCause(context.Background())
				cancel(cause)
				ctx, want = parent, cause
			} else {
				ctx = webH2UnpublishedDeadlineContext{Context: context.Background(), deadline: time.Now().Add(-time.Second)}
			}
			conn, err := client.DialContext(ctx, "tcp", "target.invalid:443")
			if conn != nil {
				_ = conn.Close()
				t.Error("expired caller received a connection")
			}
			if !errors.Is(err, want) || calls.Load() != 0 {
				t.Errorf("error=%v physical dials=%d; want cause %v and no dial", err, calls.Load(), want)
			}
		})
	}
}

func TestWebH2DialConnectionErrorOwnership(t *testing.T) {
	_, clientTLS := testTLSConfigs(t)
	client, err := NewWebH2Client(WebH2ClientConfig{
		ServerAddress: "127.0.0.1:443", Token: testToken, TLSConfig: clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, peer := net.Pipe()
	wire := &webH2InitializationWire{Conn: raw, closed: make(chan struct{})}
	t.Cleanup(func() { _ = raw.Close(); _ = peer.Close(); _ = client.Close() })
	fault := errors.New("physical TCP dial returned connection and failure")
	client.dialer = transport.DialFunc(func(context.Context, string, string) (net.Conn, error) { return wire, fault })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", "target.invalid:443")
	if conn != nil {
		_ = conn.Close()
		t.Error("failed physical dial returned a stream")
	}
	if !errors.Is(err, fault) {
		t.Errorf("dial error=%v, want original failure", err)
	}
	select {
	case <-wire.closed:
	default:
		t.Error("failed physical dial retained its non-nil connection")
	}
}

// Old production panics for nil+nil; this guard is deliberately excluded from
// old-source negative runs, rather than treating a process crash as evidence.
func TestWebH2DialMissingConnectionFailsClosed(t *testing.T) {
	_, clientTLS := testTLSConfigs(t)
	client, err := NewWebH2Client(WebH2ClientConfig{
		ServerAddress: "127.0.0.1:443", Token: testToken, TLSConfig: clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	client.dialer = transport.DialFunc(func(context.Context, string, string) (net.Conn, error) { return nil, nil })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", "target.invalid:443")
	if conn != nil || err == nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("nil physical result: conn=%v error=%v", conn, err)
	}
}
