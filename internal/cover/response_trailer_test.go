package cover

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"
)

func TestReverseProxyScrubsResponseTrailersOnWire(t *testing.T) {
	for _, announced := range []bool{true, false} {
		t.Run(fmt.Sprintf("credentials_announced_%t", announced), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				request, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					done <- err
					return
				}
				_, err = io.Copy(io.Discard, request.Body)
				_ = request.Body.Close()
				if err != nil {
					done <- err
					return
				}
				trailers := "X-End"
				if announced {
					trailers += ", Authorization, Proxy-Authorization"
				}
				// The upstream deliberately supplies prohibited credential trailer
				// fields. Only fictional values and loopback sockets are used.
				_, err = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nTrailer: %s\r\nAuthorization: fictional-initial-origin\r\nProxy-Authorization: fictional-initial-proxy\r\n\r\n1\r\nx\r\n0\r\nAuthorization: fictional-late-origin\r\nProxy-Authorization: fictional-late-proxy\r\nX-End: retained\r\n\r\n", trailers)
				done <- err
			}()
			origin, err := url.Parse("http://" + listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			transport := &http.Transport{Proxy: nil}
			t.Cleanup(transport.CloseIdleConnections)
			handler, err := NewReverseProxyHandler(origin, transport)
			if err != nil {
				t.Fatal(err)
			}
			front := httptest.NewServer(handler)
			t.Cleanup(front.Close)
			clientTransport := &http.Transport{Proxy: nil}
			t.Cleanup(clientTransport.CloseIdleConnections)
			client := &http.Client{Transport: clientTransport, Timeout: 2 * time.Second}
			response, err := client.Get(front.URL)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusOK || string(body) != "x" {
				t.Fatalf("status/body = %d/%q", response.StatusCode, body)
			}
			for _, name := range []string{"Authorization", "Proxy-Authorization"} {
				if response.Header.Get(name) != "" || response.Trailer.Get(name) != "" {
					t.Fatalf("%s escaped response filtering: headers=%v trailers=%v", name, response.Header, response.Trailer)
				}
			}
			if response.Trailer.Get("X-End") != "retained" {
				t.Fatalf("ordinary trailer was lost: %v", response.Trailer)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("origin did not finish")
			}
		})
	}
}

func TestResponseTrailerBodyPreservesStreamingAndTerminalRead(t *testing.T) {
	readFailure := errors.New("upstream read failure")
	for _, terminal := range []error{io.EOF, readFailure, context.Canceled} {
		t.Run(terminal.Error(), func(t *testing.T) {
			response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Trailer: http.Header{
				"Authorization": nil, "Proxy-Authorization": nil, "X-End": nil,
			}}
			reads := 0
			response.Body = &trailerTestBody{read: func(p []byte) (int, error) {
				reads++
				if reads == 1 {
					return copy(p, "first"), nil
				}
				// Replacement, not just mutation, catches a wrapper holding the
				// old map instead of following the response's final Trailer map.
				response.Trailer = http.Header{
					"Authorization": {"fictional"}, "Proxy-Authorization": {"fictional"},
					"Connection": {"X-Hop"}, "X-Hop": {"remove"}, "X-End": {"retained"},
				}
				return copy(p, "last"), terminal
			}}
			modifyTrailerResponse(t, response)
			if reads != 0 {
				t.Fatal("response modification read or buffered the body")
			}
			if _, present := response.Trailer["Authorization"]; present {
				t.Fatal("unsafe trailer declaration survived initial filtering")
			}
			if _, present := response.Trailer["X-End"]; !present {
				t.Fatal("ordinary trailer declaration was removed")
			}
			buffer := make([]byte, 16)
			n, err := response.Body.Read(buffer)
			if n != 5 || err != nil || string(buffer[:n]) != "first" || reads != 1 {
				t.Fatalf("first streaming Read = %d/%v/%q, calls=%d", n, err, buffer[:n], reads)
			}
			n, err = response.Body.Read(buffer)
			if n != 4 || err != terminal || string(buffer[:n]) != "last" {
				t.Fatalf("terminal Read = %d/%v/%q, want original n+error", n, err, buffer[:n])
			}
			assertFilteredTrailers(t, response.Trailer)
		})
	}
}

func TestResponseTrailerBodyPreservesCloseResultAndLateMap(t *testing.T) {
	closeFailure := errors.New("upstream close failure")
	response := &http.Response{StatusCode: http.StatusOK}
	closes := 0
	response.Body = &trailerTestBody{close: func() error {
		closes++
		response.Trailer = http.Header{"Authorization": {"fictional"}, "X-End": {"retained"}}
		return closeFailure
	}}
	modifyTrailerResponse(t, response)
	for wantCalls := 1; wantCalls <= 2; wantCalls++ {
		if err := response.Body.Close(); err != closeFailure || closes != wantCalls {
			t.Fatalf("Close result/calls = %v/%d, want original error and %d", err, closes, wantCalls)
		}
		assertFilteredTrailers(t, response.Trailer)
	}
}

func TestResponseTrailerBodyCloseDoesNotWaitForRead(t *testing.T) {
	started := make(chan struct{})
	releaseRead := make(chan struct{})
	defer close(releaseRead)
	response := &http.Response{StatusCode: http.StatusOK}
	response.Body = &trailerTestBody{read: func([]byte) (int, error) {
		close(started)
		<-releaseRead
		response.Trailer = http.Header{"Authorization": {"fictional"}, "X-End": {"retained"}}
		return 0, context.Canceled
	}}
	modifyTrailerResponse(t, response)
	done := make(chan error, 1)
	go func() { _, err := response.Body.Read(make([]byte, 1)); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("body Read did not begin")
	}
	closed := make(chan error, 1)
	go func() { closed <- response.Body.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close waited for the reader")
	}
	// Close has returned, but the response Trailer is not yet safe to inspect.
	// Release the read without closing the channel, leaving cleanup idempotent.
	releaseRead <- struct{}{}
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("Read error = %v, want original cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("body Read did not finish")
	}
	assertFilteredTrailers(t, response.Trailer)
}

func modifyTrailerResponse(t *testing.T, response *http.Response) {
	t.Helper()
	handler, err := NewReverseProxyHandler(&url.URL{Scheme: "http", Host: "origin.invalid"}, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected network call")
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.(*httputil.ReverseProxy).ModifyResponse(response); err != nil {
		t.Fatal(err)
	}
}

func assertFilteredTrailers(t *testing.T, trailers http.Header) {
	t.Helper()
	if len(trailers) != 1 || trailers.Get("X-End") != "retained" {
		t.Fatalf("filtered trailers = %v, want only X-End retained", trailers)
	}
}

type trailerTestBody struct {
	read  func([]byte) (int, error)
	close func() error
}

func (b *trailerTestBody) Read(p []byte) (int, error) {
	if b.read != nil {
		return b.read(p)
	}
	return 0, io.EOF
}

func (b *trailerTestBody) Close() error {
	if b.close != nil {
		return b.close()
	}
	return nil
}
