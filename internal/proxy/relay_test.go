package proxy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestRelayHardErrorAbortsBothDirections(t *testing.T) {
	leftRelay, leftPeer := net.Pipe()
	rightRelay, rightPeer := net.Pipe()
	defer leftPeer.Close()
	defer rightPeer.Close()
	sentinel := errors.New("synthetic read failure")
	broken := &readErrorConn{Conn: leftRelay, err: sentinel}
	done := make(chan error, 1)
	go func() { done <- relay(broken, rightRelay, 10*time.Second) }()

	select {
	case err := <-done:
		if !errors.Is(err, sentinel) {
			t.Fatalf("relay error = %v, want sentinel", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("hard relay error did not promptly abort the opposite direction")
	}
	_ = rightPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := rightPeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("right peer remained open after hard relay failure")
	}
}

func TestRelayCleanEOFPreservesReverseDirection(t *testing.T) {
	leftRelay, leftPeer := tcpConnPair(t)
	rightRelay, rightPeer := tcpConnPair(t)
	defer leftPeer.Close()
	defer rightPeer.Close()
	done := make(chan error, 1)
	go func() { done <- relay(leftRelay, rightRelay, time.Second) }()

	request := []byte("request followed by FIN")
	mustWrite(t, leftPeer, request)
	if err := leftPeer.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	gotRequest, err := io.ReadAll(rightPeer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotRequest, request) {
		t.Fatalf("request = %q, want %q", gotRequest, request)
	}

	response := []byte("response after request half-close")
	mustWrite(t, rightPeer, response)
	if err := rightPeer.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	gotResponse, err := io.ReadAll(leftPeer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotResponse, response) {
		t.Fatalf("response = %q, want %q", gotResponse, response)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("relay: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("relay did not finish after two clean half-closes")
	}
}

type readErrorConn struct {
	net.Conn
	err error
}

func (c *readErrorConn) Read([]byte) (int, error) { return 0, c.err }

func tcpConnPair(t *testing.T) (relay net.Conn, peer net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	peer, err = net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case relay = <-accepted:
		return relay, peer
	case err := <-acceptErr:
		peer.Close()
		t.Fatal(err)
		return nil, nil
	case <-time.After(time.Second):
		peer.Close()
		t.Fatal("accept timed out")
		return nil, nil
	}
}
