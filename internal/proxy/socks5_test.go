package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

func TestSOCKS5ConnectNoAuth(t *testing.T) {
	echoAddress, stopEcho := startTCPEcho(t)
	defer stopEcho()

	server, proxyAddress, stopProxy := startSOCKS5(t, Config{Dialer: directDialer()})
	defer stopProxy(server)
	client := dialTCP(t, proxyAddress)
	defer client.Close()

	socksGreeting(t, client, nil)
	host, port := splitAddress(t, echoAddress)
	request := domainSOCKSRequest(socksCommandConnect, host, port)
	mustWrite(t, client, request)
	if reply := readSOCKSReply(t, client); reply != socksReplySucceeded {
		t.Fatalf("reply = %d, want success", reply)
	}
	payload := []byte("autocar socks relay")
	mustWrite(t, client, payload)
	got := make([]byte, len(payload))
	mustReadFull(t, client, got)
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

func TestSOCKS5SuccessReplyUsesUnknownBoundAddress(t *testing.T) {
	var wire bytes.Buffer
	if err := writeSOCKSReply(&wire, socksReplySucceeded, nil); err != nil {
		t.Fatal(err)
	}
	want := []byte{5, socksReplySucceeded, 0, socksAddressIPv4, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(wire.Bytes(), want) {
		t.Fatalf("reply = %v, want %v", wire.Bytes(), want)
	}
}

func TestSOCKS5UsernamePasswordAndIPv4(t *testing.T) {
	echoAddress, stopEcho := startTCPEcho(t)
	defer stopEcho()

	server, proxyAddress, stopProxy := startSOCKS5(t, Config{
		Dialer:        directDialer(),
		Authenticator: StaticAuthenticator("alice", "correct horse"),
	})
	defer stopProxy(server)
	client := dialTCP(t, proxyAddress)
	defer client.Close()

	socksGreeting(t, client, []byte{socksMethodNoAuth, socksMethodUserPassword})
	mustWrite(t, client, append(append([]byte{1, 5}, []byte("alice")...), append([]byte{13}, []byte("correct horse")...)...))
	authReply := make([]byte, 2)
	mustReadFull(t, client, authReply)
	if !bytes.Equal(authReply, []byte{1, 0}) {
		t.Fatalf("auth reply = %v", authReply)
	}

	host, port := splitAddress(t, echoAddress)
	ip := net.ParseIP(host).To4()
	request := []byte{5, socksCommandConnect, 0, socksAddressIPv4}
	request = append(request, ip...)
	request = binary.BigEndian.AppendUint16(request, port)
	mustWrite(t, client, request)
	if reply := readSOCKSReply(t, client); reply != socksReplySucceeded {
		t.Fatalf("reply = %d, want success", reply)
	}
	mustWrite(t, client, []byte("x"))
	response := []byte{0}
	mustReadFull(t, client, response)
	if response[0] != 'x' {
		t.Fatalf("unexpected echo byte %q", response)
	}
}

func TestSOCKS5AuthenticationFailure(t *testing.T) {
	server, proxyAddress, stopProxy := startSOCKS5(t, Config{
		Dialer:        directDialer(),
		Authenticator: StaticAuthenticator("user", "secret"),
	})
	defer stopProxy(server)
	client := dialTCP(t, proxyAddress)
	defer client.Close()

	socksGreeting(t, client, []byte{socksMethodUserPassword})
	mustWrite(t, client, []byte{1, 4, 'u', 's', 'e', 'r', 3, 'b', 'a', 'd'})
	reply := make([]byte, 2)
	mustReadFull(t, client, reply)
	if reply[0] != 1 || reply[1] == 0 {
		t.Fatalf("auth reply = %v, want failure", reply)
	}
}

func TestSOCKS5UnsupportedCommands(t *testing.T) {
	for _, command := range []byte{socksCommandBind, socksCommandUDP} {
		t.Run(string(rune('0'+command)), func(t *testing.T) {
			server, proxyAddress, stopProxy := startSOCKS5(t, Config{Dialer: directDialer()})
			defer stopProxy(server)
			client := dialTCP(t, proxyAddress)
			defer client.Close()
			socksGreeting(t, client, nil)
			mustWrite(t, client, domainSOCKSRequest(command, "example.com", 53))
			if reply := readSOCKSReply(t, client); reply != socksReplyCommandUnsupported {
				t.Fatalf("reply = %d, want %d", reply, socksReplyCommandUnsupported)
			}
		})
	}
}

func TestSOCKS5DialErrorReplies(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want byte
	}{
		{"refused", syscall.ECONNREFUSED, socksReplyConnectionRefused},
		{"network", syscall.ENETUNREACH, socksReplyNetworkUnreachable},
		{"host", syscall.EHOSTUNREACH, socksReplyHostUnreachable},
		{"timeout", context.DeadlineExceeded, socksReplyTTLExpired},
		{"dns", &net.DNSError{Err: "no such host", IsNotFound: true}, socksReplyHostUnreachable},
		{"other", errors.New("boom"), socksReplyGeneralFailure},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := socksReplyForError(test.err); got != test.want {
				t.Fatalf("reply = %d, want %d", got, test.want)
			}
		})
	}
}

func TestReadSOCKSRequestAddressTypes(t *testing.T) {
	ipv6 := net.ParseIP("2001:db8::1").To16()
	tests := []struct {
		name    string
		request []byte
		want    string
	}{
		{"domain", domainSOCKSRequest(1, "example.com", 443), "example.com:443"},
		{"ipv4", append(append([]byte{5, 1, 0, 1}, []byte{192, 0, 2, 1}...), 0x01, 0xbb), "192.0.2.1:443"},
		{"ipv6", append(append([]byte{5, 1, 0, 4}, ipv6...), 0x01, 0xbb), "[2001:db8::1]:443"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := readSOCKSRequest(bytes.NewReader(test.request))
			if err != nil {
				t.Fatal(err)
			}
			if got.address != test.want {
				t.Fatalf("address = %q, want %q", got.address, test.want)
			}
		})
	}
}

func TestSOCKS5ShutdownClosesConnectionAfterDeadline(t *testing.T) {
	upstreamClient, upstreamServer := net.Pipe()
	defer upstreamServer.Close()
	dialed := make(chan struct{})
	dialer := transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
		close(dialed)
		return upstreamClient, nil
	})
	server, proxyAddress, _ := startSOCKS5(t, Config{Dialer: dialer})
	client := dialTCP(t, proxyAddress)
	socksGreeting(t, client, nil)
	mustWrite(t, client, domainSOCKSRequest(1, "example.com", 443))
	if reply := readSOCKSReply(t, client); reply != 0 {
		t.Fatalf("reply = %d", reply)
	}
	<-dialed

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := server.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown error = %v, want deadline exceeded", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("client remained open after forced shutdown")
	}
}

func TestSOCKS5HandshakeTimeout(t *testing.T) {
	server, proxyAddress, stopProxy := startSOCKS5(t, Config{
		Dialer:           directDialer(),
		HandshakeTimeout: 20 * time.Millisecond,
	})
	defer stopProxy(server)
	client := dialTCP(t, proxyAddress)
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle handshake connection was not closed")
	}
}

func TestSOCKS5ConnectionLimit(t *testing.T) {
	server, proxyAddress, stopProxy := startSOCKS5(t, Config{
		Dialer:           directDialer(),
		HandshakeTimeout: time.Second,
		MaxConnections:   1,
	})
	defer stopProxy(server)
	first := dialTCP(t, proxyAddress)
	defer first.Close()
	deadline := time.Now().Add(time.Second)
	for {
		server.lifecycle.tracker.mu.Lock()
		count := len(server.lifecycle.tracker.conns)
		server.lifecycle.tracker.mu.Unlock()
		if count == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first connection was not accepted")
		}
		time.Sleep(time.Millisecond)
	}

	second := dialTCP(t, proxyAddress)
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	mustWrite(t, second, []byte{5, 1, 0})
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection beyond configured limit was not rejected")
	}
}

func TestSOCKS5NoAcceptableMethod(t *testing.T) {
	server, proxyAddress, stopProxy := startSOCKS5(t, Config{
		Dialer:        directDialer(),
		Authenticator: StaticAuthenticator("u", "p"),
	})
	defer stopProxy(server)
	client := dialTCP(t, proxyAddress)
	defer client.Close()
	mustWrite(t, client, []byte{5, 1, socksMethodNoAuth})
	reply := make([]byte, 2)
	mustReadFull(t, client, reply)
	if !bytes.Equal(reply, []byte{5, socksMethodNone}) {
		t.Fatalf("reply = %v, want no acceptable methods", reply)
	}
}

func FuzzReadSOCKSGreeting(f *testing.F) {
	f.Add([]byte{5, 1, 0})
	f.Add([]byte{5, 2, 0, 2})
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = readSOCKSGreeting(bytes.NewReader(payload))
	})
}

func FuzzReadSOCKSRequest(f *testing.F) {
	f.Add(domainSOCKSRequest(1, "example.com", 443))
	f.Add([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80})
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = readSOCKSRequest(bytes.NewReader(payload))
	})
}

func startSOCKS5(t *testing.T, cfg Config) (*SOCKS5Server, string, func(*SOCKS5Server)) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewSOCKS5Server(cfg)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	stop := func(server *SOCKS5Server) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("Serve did not return")
		}
	}
	return server, listener.Addr().String(), stop
}

func directDialer() transport.Dialer {
	return transport.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	})
}

func startTCPEcho(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String(), func() {
		_ = listener.Close()
		<-done
		wg.Wait()
	}
}

func dialTCP(t *testing.T, address string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	return conn
}

func socksGreeting(t *testing.T, conn net.Conn, methods []byte) {
	t.Helper()
	if methods == nil {
		methods = []byte{socksMethodNoAuth}
	}
	mustWrite(t, conn, append([]byte{5, byte(len(methods))}, methods...))
	reply := make([]byte, 2)
	mustReadFull(t, conn, reply)
	wanted := byte(socksMethodNoAuth)
	if containsByte(methods, socksMethodUserPassword) {
		wanted = socksMethodUserPassword
	}
	if reply[0] != 5 || reply[1] != wanted {
		t.Fatalf("greeting reply = %v, want method %d", reply, wanted)
	}
}

func domainSOCKSRequest(command byte, host string, port uint16) []byte {
	request := []byte{5, command, 0, socksAddressDomain, byte(len(host))}
	request = append(request, host...)
	return binary.BigEndian.AppendUint16(request, port)
}

func readSOCKSReply(t *testing.T, reader io.Reader) byte {
	t.Helper()
	buffered, ok := reader.(*bufio.Reader)
	if !ok {
		buffered = bufio.NewReader(reader)
	}
	header := make([]byte, 4)
	mustReadFull(t, buffered, header)
	length := 0
	switch header[3] {
	case socksAddressIPv4:
		length = 4
	case socksAddressIPv6:
		length = 16
	case socksAddressDomain:
		value, err := buffered.ReadByte()
		if err != nil {
			t.Fatal(err)
		}
		length = int(value)
	default:
		t.Fatalf("invalid reply address type %d", header[3])
	}
	tail := make([]byte, length+2)
	mustReadFull(t, buffered, tail)
	return header[1]
}

func splitAddress(t *testing.T, address string) (string, uint16) {
	t.Helper()
	host, portString, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return host, uint16(parsed)
}

func mustWrite(t *testing.T, writer io.Writer, payload []byte) {
	t.Helper()
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
}

func mustReadFull(t *testing.T, reader io.Reader, payload []byte) {
	t.Helper()
	if _, err := io.ReadFull(reader, payload); err != nil {
		t.Fatal(err)
	}
}
