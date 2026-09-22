package tunnel

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

// This exercises the production QUIC stream adapter and controller against
// real connection statistics. Authentication and serverCore are intentionally
// outside this focused regression; the peer is a controlled loopback fixture.
func TestQUICPacingReceiveOnlyIntervalDoesNotCollapseSender(t *testing.T) {
	const (
		minimumRate = 64 << 10
		initialRate = 8_000_000
		chunkSize   = 1024
		chunks      = 8
	)
	upload := bytes.Repeat([]byte("receive-only-gap"), chunkSize*chunks/16+1)[:chunkSize*chunks]
	download := bytes.Repeat([]byte("same-QUIC-connection"), 1024)
	trailer := []byte("upload still works after the receive-only interval")
	ready := []byte("ready")
	serverTLS, clientTLS := testTLSConfigs(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", mustServerTLSConfig(t, serverTLS), hardenedQUICServerConfig(nil, 1))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	deadline, _ := ctx.Deadline()
	type result struct {
		before, after int64
		sentDuringGap uint64
		err           error
	}
	serverDone := make(chan result, 1)
	go func() {
		var observation result
		defer func() { serverDone <- observation }()
		conn, err := listener.Accept(ctx)
		if err != nil {
			observation.err = err
			return
		}
		defer conn.CloseWithError(applicationShutdown, "test finished")
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			observation.err = err
			return
		}
		pacer, err := newConnectionPacer(PacingConfig{
			InitialRateBytesPerSecond: initialRate,
			MinRateBytesPerSecond:     minimumRate,
		}, 0)
		if err != nil {
			observation.err = err
			return
		}
		wrapped := newQUICStreamConn(stream, conn, pacer)
		defer wrapped.Close()
		if err := wrapped.SetDeadline(deadline); err != nil {
			observation.err = err
			return
		}
		checkRead := func(want []byte) error {
			got := make([]byte, len(want))
			if _, err := io.ReadFull(wrapped, got); err != nil {
				return err
			}
			if !bytes.Equal(got, want) {
				return fmt.Errorf("server received incorrect %d-byte payload", len(want))
			}
			return nil
		}
		if err := checkRead([]byte{1}); err != nil {
			observation.err = err
			return
		}
		if _, err := wrapped.Write(ready); err != nil {
			observation.err = err
			return
		}
		observation.before = pacer.controller.TargetBytesPerSecond()
		sentBefore := conn.ConnectionStats().BytesSent
		// Only the receive direction carries application data during this gap.
		// QUIC still emits ACK/control packets, which are not delivery-rate
		// evidence that this application's otherwise idle sender is slow.
		if err := checkRead(upload); err != nil {
			observation.err = err
			return
		}
		observation.sentDuringGap = conn.ConnectionStats().BytesSent - sentBefore
		if _, err := wrapped.Write(download); err != nil {
			observation.err = err
			return
		}
		observation.after = pacer.controller.TargetBytesPerSecond()
		observation.err = checkRead(trailer)
	}()
	var client *quic.Conn
	joined := false
	t.Cleanup(func() {
		cancel()
		if client != nil {
			_ = client.CloseWithError(applicationShutdown, "test finished")
		}
		_ = listener.Close()
		if !joined {
			select {
			case <-serverDone:
			case <-time.After(time.Second):
				t.Error("QUIC pacing fixture did not stop")
			}
		}
	})
	rawClientTLS, err := clientTLSConfig(clientTLS, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client, err = quic.DialAddr(ctx, listener.Addr().String(), rawClientTLS, hardenedQUICClientConfig(nil))
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	gotReady := make([]byte, len(ready))
	if _, err := io.ReadFull(stream, gotReady); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotReady, ready) {
		t.Fatalf("greeting = %q", gotReady)
	}
	ticker := time.NewTicker(40 * time.Millisecond)
	defer ticker.Stop()
	for offset := 0; offset < len(upload); offset += chunkSize {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		if _, err := stream.Write(upload[offset : offset+chunkSize]); err != nil {
			t.Fatal(err)
		}
	}
	gotDownload := make([]byte, len(download))
	if _, err := io.ReadFull(stream, gotDownload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotDownload, download) {
		t.Fatal("download payload mismatch")
	}
	if _, err := stream.Write(trailer); err != nil {
		t.Fatal(err)
	}
	select {
	case observation := <-serverDone:
		joined = true
		if observation.err != nil {
			t.Fatal(observation.err)
		}
		if observation.sentDuringGap == 0 {
			t.Fatal("fixture did not produce outgoing QUIC control traffic during upload")
		}
		if observation.before != initialRate {
			t.Fatalf("initial server target = %d, want %d", observation.before, initialRate)
		}
		if observation.after != observation.before {
			t.Fatalf("receive-only interval changed server target from %d to %d (floor %d, %d control bytes)",
				observation.before, observation.after, minimumRate, observation.sentDuringGap)
		}
		t.Logf("same-connection server target %d -> %d; %d outgoing QUIC control bytes during receive-only interval",
			observation.before, observation.after, observation.sentDuringGap)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
