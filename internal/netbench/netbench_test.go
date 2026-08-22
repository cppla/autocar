package netbench

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

func TestUploadAndDownload(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (&Server{MaxBytes: 1 << 20}).Serve(ctx, ln) }()

	dialer := transport.DialFunc((&net.Dialer{}).DialContext)
	for _, mode := range []byte{ModeUpload, ModeDownload} {
		result, err := Run(context.Background(), dialer, ln.Addr().String(), mode, 256<<10)
		if err != nil {
			t.Fatalf("mode %d: %v", mode, err)
		}
		if result.Bytes != 256<<10 || result.Duration <= 0 || result.Mbps() <= 0 {
			t.Fatalf("bad result: %+v", result)
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}

func TestRejectsInvalidMode(t *testing.T) {
	dialer := transport.DialFunc((&net.Dialer{}).DialContext)
	if _, err := Run(context.Background(), dialer, "unused", 99, 1); err == nil {
		t.Fatal("expected error")
	}
}
