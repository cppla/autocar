package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

func TestConnectionAdmissionValidationAndCompatibility(t *testing.T) {
	for _, limit := range []int{-1, 0} {
		if admission, err := NewConnectionAdmission(limit); err == nil || admission != nil {
			t.Fatalf("NewConnectionAdmission(%d) = (%v, %v), want error", limit, admission, err)
		}
	}
	serverTLS, _ := testTLSConfigs(t)
	shared, err := NewConnectionAdmission(2)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		limit     int
		admission *ConnectionAdmission
		wantErr   bool
	}{
		{name: "negative", limit: -1, wantErr: true},
		{name: "negative with shared", limit: -1, admission: shared, wantErr: true},
		{name: "zero-value", admission: &ConnectionAdmission{}, wantErr: true},
		{name: "mismatch", limit: 1, admission: shared, wantErr: true},
		{name: "shared inferred", admission: shared},
		{name: "shared explicit", limit: 2, admission: shared},
		{name: "independent default"},
		{name: "independent explicit", limit: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			q, qErr := ListenQUIC(QUICServerConfig{
				Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
				MaxConcurrentStreams: 4, MaxConnections: test.limit, ConnectionAdmission: test.admission,
			})
			if q != nil {
				defer q.Close()
			}
			s, sErr := ListenTLS(TLSServerConfig{
				Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
				MaxConcurrentStreams: 4, MaxConnections: test.limit, ConnectionAdmission: test.admission,
			})
			if s != nil {
				defer s.Close()
			}
			if (qErr != nil) != test.wantErr || (sErr != nil) != test.wantErr {
				t.Fatalf("QUIC error = %v, TLS error = %v, wantErr %t", qErr, sErr, test.wantErr)
			}
			if test.wantErr {
				return
			}
			if test.admission != nil {
				if q.connSem != shared.sem || s.connSem != shared.sem {
					t.Fatal("native transports do not share the configured connection budget")
				}
			} else {
				if q.connSem == s.connSem {
					t.Fatal("independent servers unexpectedly share a connection budget")
				}
				qLimit, sLimit := test.limit, test.limit
				if test.limit == 0 {
					qLimit, sLimit = defaultMaxConnections, 4
				}
				if cap(q.connSem) != qLimit || cap(s.connSem) != sLimit {
					t.Fatalf("connection limits = (%d, %d), want (%d, %d)", cap(q.connSem), cap(s.connSem), qLimit, sLimit)
				}
			}
		})
	}
}

func TestQUICAndTLSShareGlobalConnectionAdmission(t *testing.T) {
	f := newConnectionAdmissionFixture(t, 2)
	firstTLS := f.dialTLS()
	f.awaitUsage(1)
	firstQUIC := f.dialQUIC()
	f.awaitUsage(2)
	if len(f.tlsServer.core.sem) != 0 || len(f.quicServer.core.sem) != 0 {
		t.Fatal("idle unauthenticated connections consumed active-stream slots")
	}
	f.rejectTLS()
	f.rejectQUIC()
	f.awaitUsage(2)

	_ = firstTLS.Close()
	f.awaitUsage(1)
	secondQUIC := f.dialQUIC()
	f.awaitUsage(2)
	_ = firstQUIC.CloseWithError(0, "test connection release")
	f.awaitUsage(1)
	_ = f.dialTLS()
	f.awaitUsage(2)
	_ = secondQUIC.CloseWithError(0, "test connection release")
	f.awaitUsage(1)
	_ = f.dialQUIC()
	f.awaitUsage(2)

	// Closing one transport must release only its own connections. The shared
	// budget remains usable by the other transport until it too shuts down.
	if err := f.quicServer.Close(); err != nil {
		t.Fatal(err)
	}
	f.awaitUsage(1)
	_ = f.dialTLS()
	f.awaitUsage(2)
	if err := f.tlsServer.Close(); err != nil {
		t.Fatal(err)
	}
	f.awaitUsage(0)
}

func TestConnectionAdmissionRollsBackPerSourceRejection(t *testing.T) {
	for _, mode := range []string{"quic", "tls"} {
		t.Run(mode, func(t *testing.T) {
			f := newConnectionAdmissionFixture(t, 1)
			if mode == "quic" {
				_ = f.dialQUIC()
			} else {
				_ = f.dialTLS()
			}
			f.awaitUsage(1)
			if mode == "quic" {
				f.rejectQUIC()
				f.awaitUsage(1)
				_ = f.dialTLS()
			} else {
				f.rejectTLS()
				f.awaitUsage(1)
				_ = f.dialQUIC()
			}
			f.awaitUsage(2)
		})
	}
}

func TestConnectionAdmissionReturnsFailedTLSHandshake(t *testing.T) {
	f := newConnectionAdmissionFixture(t, 2)
	conn, err := net.DialTimeout("tcp", f.tlsServer.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	f.awaitUsage(1)
	if _, err := conn.Write([]byte("invalid TLS handshake\r\n")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("invalid TLS handshake remained open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("invalid TLS handshake was not rejected promptly")
	}
	f.awaitUsage(0)
	_ = f.dialQUIC()
	f.awaitUsage(1)
}

type connectionAdmissionFixture struct {
	t          *testing.T
	admission  *ConnectionAdmission
	quicServer *QUICServer
	tlsServer  *TLSServer
	clientTLS  *tls.Config
}

func newConnectionAdmissionFixture(t *testing.T, sourceLimit int) *connectionAdmissionFixture {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	shared, err := NewConnectionAdmission(2)
	if err != nil {
		t.Fatal(err)
	}
	q, err := ListenQUIC(QUICServerConfig{
		Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
		HandshakeTimeout: 30 * time.Second, MaxConcurrentStreams: 4,
		ConnectionAdmission: shared, MaxClientConnections: sourceLimit,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = q.Close() })
	s, err := ListenTLS(TLSServerConfig{
		Address: "127.0.0.1:0", Token: testToken, TLSConfig: serverTLS,
		HandshakeTimeout: 30 * time.Second, MaxConcurrentStreams: 4,
		ConnectionAdmission: shared, MaxClientConnections: sourceLimit,
	})
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err = clientTLSConfig(clientTLS, s.Addr().String())
	if err != nil {
		_ = s.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	qDone, sDone := make(chan error, 1), make(chan error, 1)
	go func() { qDone <- q.Serve(ctx) }()
	go func() { sDone <- s.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = q.Close()
		_ = s.Close()
		for name, done := range map[string]<-chan error{"QUIC": qDone, "TLS": sDone} {
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("%s Serve: %v", name, err)
				}
			case <-time.After(3 * time.Second):
				t.Errorf("%s Serve did not stop", name)
			}
		}
		if got := len(shared.sem); got != 0 {
			t.Errorf("connection admission after shutdown = %d, want 0", got)
		}
	})
	return &connectionAdmissionFixture{t: t, admission: shared, quicServer: q, tlsServer: s, clientTLS: clientTLS}
}

func (f *connectionAdmissionFixture) awaitUsage(want int) {
	f.t.Helper()
	waitForCondition(f.t, 3*time.Second, func() bool { return len(f.admission.sem) == want }, "shared connection budget")
}

func (f *connectionAdmissionFixture) dialTLS() net.Conn {
	f.t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", f.tlsServer.Addr().String(), f.clientTLS.Clone())
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func (f *connectionAdmissionFixture) rejectTLS() {
	f.t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", f.tlsServer.Addr().String(), f.clientTLS.Clone())
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		f.t.Fatal("TLS connection was admitted while the connection budget was full")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		f.t.Fatalf("TLS rejection timed out: %v", err)
	}
}

func (f *connectionAdmissionFixture) dialQUIC() *quic.Conn {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, f.quicServer.Addr().String(), f.clientTLS.Clone(), hardenedQUICClientConfig(nil))
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = conn.CloseWithError(0, "test cleanup") })
	return conn
}

func (f *connectionAdmissionFixture) rejectQUIC() {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, f.quicServer.Addr().String(), f.clientTLS.Clone(), hardenedQUICClientConfig(nil))
	if conn != nil {
		defer conn.CloseWithError(0, "test cleanup")
		select {
		case <-conn.Context().Done():
			err = context.Cause(conn.Context())
		case <-ctx.Done():
			f.t.Fatal("QUIC connection was not rejected promptly")
		}
	}
	var appErr *quic.ApplicationError
	if !errors.As(err, &appErr) || appErr.ErrorCode != connectionRejected {
		f.t.Fatalf("QUIC connection rejection = %v, want connection limit", err)
	}
}
