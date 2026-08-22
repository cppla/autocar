package client

import (
	"errors"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
)

func TestFastOpenConcurrentReadsConsumeResponseOnce(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer serverSide.Close()
	conn := &tcpConn{Orig: clientSide}
	go func() {
		_ = protocol.WriteTCPResponse(serverSide, true, "connected")
		_, _ = serverSide.Write([]byte("xy"))
	}()

	start := make(chan struct{})
	results := make(chan byte, 2)
	errorsSeen := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			buffer := make([]byte, 1)
			_, err := conn.Read(buffer)
			if err != nil {
				errorsSeen <- err
				return
			}
			results <- buffer[0]
		}()
	}
	close(start)
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Fatalf("concurrent Read: %v", err)
	}
	close(results)
	var got []byte
	for result := range results {
		got = append(got, result)
	}
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	if string(got) != "xy" {
		t.Fatalf("concurrent payload = %q, want xy", got)
	}
}

func TestFastOpenFailureIsCachedAndClosesStream(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	conn := &tcpConn{Orig: clientSide}
	go func() {
		_ = protocol.WriteTCPResponse(serverSide, false, "destination denied")
		_ = serverSide.Close()
	}()

	buffer := make([]byte, 1)
	_, firstErr := conn.Read(buffer)
	var firstDialError coreErrs.DialError
	if !errors.As(firstErr, &firstDialError) {
		t.Fatalf("first Read error = %v, want DialError", firstErr)
	}
	done := make(chan error, 1)
	go func() {
		_, err := conn.Read(buffer)
		done <- err
	}()
	select {
	case secondErr := <-done:
		var secondDialError coreErrs.DialError
		if !errors.As(secondErr, &secondDialError) || secondErr.Error() != firstErr.Error() {
			t.Fatalf("cached Read error = %v, want %v", secondErr, firstErr)
		}
	case <-time.After(time.Second):
		t.Fatal("second Read retried the consumed Fast Open response")
	}
}
