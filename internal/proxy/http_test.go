package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

func TestHTTPForwardProxy(t *testing.T) {
	received := make(chan *http.Request, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Clone(context.Background())
		w.Header().Set("Connection", "X-Response-Hop")
		w.Header().Set("X-Response-Hop", "secret")
		w.Header().Set("X-Origin", "yes")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("forwarded"))
	}))
	defer origin.Close()

	server, proxyURL, stopProxy := startHTTPProxy(t, Config{Dialer: directDialer()})
	defer stopProxy(server)
	client := proxyHTTPClient(t, proxyURL, nil)
	request, err := http.NewRequest(http.MethodPost, origin.URL+"/resource?q=1", strings.NewReader("body"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Connection", "X-Remove-Me")
	request.Header.Set("X-Remove-Me", "not end to end")
	request.Header.Set("X-Keep-Me", "end to end")
	request.Header.Set(proxyAuthorizationHeader, "must not leak")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusCreated || string(body) != "forwarded" {
		t.Fatalf("status/body = %d/%q", response.StatusCode, body)
	}
	if response.Header.Get("X-Response-Hop") != "" {
		t.Fatal("hop-by-hop response header leaked")
	}
	if response.Header.Get("X-Origin") != "yes" {
		t.Fatal("end-to-end response header missing")
	}

	select {
	case got := <-received:
		if got.URL.Path != "/resource" || got.URL.RawQuery != "q=1" {
			t.Fatalf("origin URL = %s", got.URL.String())
		}
		if got.Header.Get("X-Remove-Me") != "" {
			t.Fatal("connection-nominated request header leaked")
		}
		if got.Header.Get(proxyAuthorizationHeader) != "" {
			t.Fatal("proxy credentials leaked to origin")
		}
		if got.Header.Get("X-Keep-Me") != "end to end" {
			t.Fatal("end-to-end request header missing")
		}
	case <-time.After(time.Second):
		t.Fatal("origin did not receive request")
	}
}

func TestHTTPAbsoluteAuthorityOverridesHost(t *testing.T) {
	receivedHost := make(chan string, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHost <- r.Host
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()
	server, err := NewHTTPServer(Config{Dialer: directDialer()})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, origin.URL+"/resource", nil)
	request.Host = "conflicting-host.invalid"
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d", recorder.Code)
	}
	originURL, _ := url.Parse(origin.URL)
	select {
	case host := <-receivedHost:
		if host != originURL.Host {
			t.Fatalf("origin Host = %q, want URI authority %q", host, originURL.Host)
		}
	case <-time.After(time.Second):
		t.Fatal("origin did not receive request")
	}
}

func TestHTTPProxyBasicAuthentication(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer origin.Close()
	server, proxyURL, stopProxy := startHTTPProxy(t, Config{
		Dialer:        directDialer(),
		Authenticator: StaticAuthenticator("alice", "s3cret"),
	})
	defer stopProxy(server)

	unauthorized := proxyHTTPClient(t, proxyURL, nil)
	response, err := unauthorized.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", response.StatusCode)
	}
	if !strings.HasPrefix(response.Header.Get(proxyAuthenticateHeader), "Basic ") {
		t.Fatal("missing Basic proxy authentication challenge")
	}

	authenticatedProxy, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	authenticatedProxy.User = url.UserPassword("alice", "s3cret")
	authorized := proxyHTTPClient(t, authenticatedProxy.String(), nil)
	response, err = authorized.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
}

func TestHTTPConnectPreservesBufferedBytes(t *testing.T) {
	echoAddress, stopEcho := startTCPEcho(t)
	defer stopEcho()
	server, proxyURL, stopProxy := startHTTPProxy(t, Config{Dialer: directDialer()})
	defer stopProxy(server)
	parsed, _ := url.Parse(proxyURL)
	client := dialTCP(t, parsed.Host)
	defer client.Close()

	early := []byte("early tunnel payload")
	request := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echoAddress, echoAddress)
	mustWrite(t, client, append([]byte(request), early...))
	reader := bufio.NewReader(client)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, " 200 ") {
		t.Fatalf("CONNECT status = %q", status)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	got := make([]byte, len(early))
	mustReadFull(t, reader, got)
	if !bytes.Equal(got, early) {
		t.Fatalf("tunneled bytes = %q, want %q", got, early)
	}
}

func TestHTTPSOriginThroughHTTPConnect(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("encrypted end to end"))
	}))
	defer origin.Close()
	server, proxyURL, stopProxy := startHTTPProxy(t, Config{Dialer: directDialer()})
	defer stopProxy(server)
	client := proxyHTTPClient(t, proxyURL, &tls.Config{InsecureSkipVerify: true}) // test certificate
	response, err := client.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if string(body) != "encrypted end to end" {
		t.Fatalf("body = %q", body)
	}
}

func TestHTTPConnectAuthentication(t *testing.T) {
	dialCalls := 0
	dialer := transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
		dialCalls++
		return nil, errors.New("should not dial")
	})
	server, proxyURL, stopProxy := startHTTPProxy(t, Config{
		Dialer:        dialer,
		Authenticator: StaticAuthenticator("u", "p"),
	})
	defer stopProxy(server)
	parsed, _ := url.Parse(proxyURL)
	conn := dialTCP(t, parsed.Host)
	defer conn.Close()
	mustWrite(t, conn, []byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusProxyAuthRequired || dialCalls != 0 {
		t.Fatalf("status/dials = %d/%d", response.StatusCode, dialCalls)
	}
}

func TestHTTPShutdownTracksHijackedConnect(t *testing.T) {
	upstreamClient, upstreamServer := net.Pipe()
	defer upstreamServer.Close()
	dialer := transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
		return upstreamClient, nil
	})
	server, proxyURL, _ := startHTTPProxy(t, Config{Dialer: dialer})
	parsed, _ := url.Parse(proxyURL)
	client := dialTCP(t, parsed.Host)
	mustWrite(t, client, []byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
	reader := bufio.NewReader(client)
	status, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(status, " 200 ") {
		t.Fatalf("CONNECT response = %q, %v", status, err)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := server.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown error = %v, want deadline exceeded", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("hijacked connection was not closed")
	}
}

func TestHTTPRejectsOriginFormAndInvalidConnect(t *testing.T) {
	server, err := NewHTTPServer(Config{Dialer: directDialer()})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/relative", nil)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("origin-form status = %d", recorder.Code)
	}

	request = httptest.NewRequest(http.MethodConnect, "http://example.com", nil)
	request.Host = "example.com"
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid CONNECT status = %d", recorder.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "http://example.com:0/path", nil)
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid absolute target status = %d", recorder.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "https://example.com/private", nil)
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("absolute-form HTTPS status = %d; HTTPS must use CONNECT", recorder.Code)
	}
}

func TestRemoveHopByHopHeaders(t *testing.T) {
	header := http.Header{
		"Connection":       {"X-One, x-Two"},
		"X-One":            {"1"},
		"X-Two":            {"2"},
		"Keep-Alive":       {"timeout=5"},
		"Proxy-Connection": {"close"},
		"X-End-To-End":     {"yes"},
	}
	removeHopByHopHeaders(header)
	for _, key := range []string{"Connection", "X-One", "X-Two", "Keep-Alive", "Proxy-Connection"} {
		if header.Get(key) != "" {
			t.Errorf("header %s was not removed", key)
		}
	}
	if header.Get("X-End-To-End") != "yes" {
		t.Fatal("end-to-end header was removed")
	}
}

func TestHTTPActiveBodyIdleTimeouts(t *testing.T) {
	const idle = 60 * time.Millisecond

	t.Run("stalled request body", func(t *testing.T) {
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer origin.Close()
		server, proxyURL, stopProxy := startHTTPProxy(t, Config{Dialer: directDialer(), IdleTimeout: idle})
		defer stopProxy(server)

		parsedProxy, err := url.Parse(proxyURL)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := net.Dial("tcp", parsedProxy.Host)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := fmt.Fprintf(conn, "POST %s/stall HTTP/1.1\r\nHost: ignored.invalid\r\nContent-Length: 10\r\n\r\n", origin.URL); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
		if err != nil {
			t.Fatalf("read timeout response: %v", err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusGatewayTimeout && response.StatusCode != http.StatusBadGateway {
			t.Fatalf("status = %d, want a bounded gateway failure", response.StatusCode)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("stalled upload was not bounded promptly: %s", elapsed)
		}
	})

	t.Run("stalled origin body", func(t *testing.T) {
		release := make(chan struct{})
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "5")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-release
		}))
		defer func() {
			close(release)
			origin.Close()
		}()
		server, proxyURL, stopProxy := startHTTPProxy(t, Config{Dialer: directDialer(), IdleTimeout: idle})
		defer stopProxy(server)
		client := proxyHTTPClient(t, proxyURL, nil)
		response, err := client.Get(origin.URL + "/stall")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		started := time.Now()
		_, err = io.ReadAll(response.Body)
		if err == nil {
			t.Fatal("truncated stalled response unexpectedly completed successfully")
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("stalled download was not bounded promptly: %s", elapsed)
		}
	})
}

func FuzzParseProxyBasicAuth(f *testing.F) {
	f.Add("Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass")))
	f.Add("Bearer token")
	f.Add("Basic !!!")
	f.Fuzz(func(t *testing.T, value string) {
		username, password, ok := parseProxyBasicAuth(value)
		if ok && !strings.Contains(string(mustDecodeBasic(t, value)), username+":"+password) {
			t.Fatalf("successful parse did not originate in decoded value")
		}
	})
}

func mustDecodeBasic(t *testing.T, value string) []byte {
	t.Helper()
	_, encoded, found := strings.Cut(strings.TrimSpace(value), " ")
	if !found {
		t.Fatal("missing auth payload")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func startHTTPProxy(t *testing.T, cfg Config) (*HTTPServer, string, func(*HTTPServer)) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewHTTPServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	stop := func(server *HTTPServer) {
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
	return server, "http://" + listener.Addr().String(), stop
}

func proxyHTTPClient(t *testing.T, proxyAddress string, tlsConfig *tls.Config) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse(proxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			TLSClientConfig:   tlsConfig,
			DisableKeepAlives: true,
		},
	}
}
