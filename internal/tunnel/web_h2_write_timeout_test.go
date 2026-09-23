package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestWebH2WriteByteTimeoutConfiguration(t *testing.T) {
	_, clientTLS := testTLSConfigs(t)
	for _, tc := range []struct {
		name        string
		value, want time.Duration
	}{
		{"default", 0, 30 * time.Second},
		{"override", 2 * time.Second, 2 * time.Second},
		{"negative", -time.Second, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewWebH2Client(WebH2ClientConfig{
				ServerAddress: "127.0.0.1:443", Token: webTestToken, TLSConfig: clientTLS,
				WriteByteTimeout: tc.value,
			})
			if tc.value < 0 {
				if err == nil {
					_ = client.Close()
					t.Fatal("negative timeout accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if got := client.transport.WriteByteTimeout; got != tc.want {
				t.Fatalf("transport timeout = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWebClientH2WriteByteTimeoutConfiguration(t *testing.T) {
	_, clientTLS := testTLSConfigs(t)
	for _, tc := range []struct {
		name        string
		value, want time.Duration
	}{
		{"default", 0, 30 * time.Second},
		{"override", 2 * time.Second, 2 * time.Second},
		{"negative", -time.Second, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewWebClient(WebClientConfig{
				ServerAddress: "127.0.0.1:443", Token: webTestToken, TLSConfig: clientTLS,
				H2WriteByteTimeout: tc.value,
			})
			if tc.value < 0 {
				if err == nil {
					_ = client.Close()
					t.Fatal("negative timeout accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			h2 := client.fallback.dialer.(*WebH2Client)
			if got := h2.transport.WriteByteTimeout; got != tc.want {
				t.Fatalf("fallback timeout = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWebH2WriteByteTimeoutReleasesUnreadResponse(t *testing.T) {
	for _, mode := range []string{"current close", "current deadline", "retired close"} {
		t.Run(mode, func(t *testing.T) {
			// Use the production constructor's transport, not an independently
			// configured http2.Transport that could hide missing option wiring.
			_, clientTLS := testTLSConfigs(t)
			client, err := NewWebH2Client(WebH2ClientConfig{
				ServerAddress: "127.0.0.1:443", Token: webTestToken, TLSConfig: clientTLS,
				WriteByteTimeout: 250 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			stalled, conn := newWebH2UnreadResponse(t, client, mode != "retired close")
			if mode == "current deadline" {
				released := make(chan struct{})
				release := conn.onClose
				conn.onClose = func() { release(); close(released) }
				if err := conn.SetDeadline(time.Now()); err != nil {
					t.Fatal(err)
				}
				select {
				case <-released:
				case <-time.After(time.Second):
					t.Fatal("deadline did not start closing the stream")
				}
			}
			closed := make(chan error, 1)
			go func() { closed <- conn.Close() }()
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				_ = client.Close()
				select {
				case <-closed:
				case <-time.After(time.Second):
					t.Fatal("stream Close stayed blocked after physical client Close")
				}
				t.Fatal("stream Close waited indefinitely behind a stalled HTTP/2 write")
			}
			if mode == "current deadline" {
				_, err := conn.Read(make([]byte, 8))
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("expired Read = %v, want deadline exceeded", err)
				}
			}
			// Body.Close can return as soon as the write lock is released, before
			// x/net's request cleanup has closed the failed physical session. This
			// test only checks cleanup: real next-Dial recovery is covered by the
			// TLS integration tests, without manually retiring this current session.
			wire := stalled.raw.(*webH2StalledWriter)
			deadline := time.Now().Add(time.Second)
			for (stalled.h2.CanTakeNewRequest() || wire.closes.Load() == 0) && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if stalled.h2.CanTakeNewRequest() || wire.closes.Load() == 0 {
				t.Fatal("stalled physical session was not closed")
			}
			client.mu.Lock()
			_, retained := client.sessions[stalled]
			active := stalled.active
			client.mu.Unlock()
			if active != 0 || (mode == "retired close" && retained) {
				t.Fatalf("closed stream active=%d retired session retained=%v", active, retained)
			}
		})
	}
}

// The peer acknowledges startup, sends a successful response and unread DATA,
// then stops reading after another SETTINGS. Its ACK holds x/net's write mutex,
// which response Body.Close also needs to return unread flow-control credit.
func newWebH2UnreadResponse(t *testing.T, client *WebH2Client, current bool) (*webH2ClientSession, *webH2Conn) {
	t.Helper()
	raw, peer := net.Pipe()
	wire := &webH2StalledWriter{Conn: raw, started: make(chan struct{})}
	t.Cleanup(func() { _ = raw.Close(); _ = peer.Close() })
	_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
	peerDone := make(chan error, 1)
	go func() {
		peerDone <- func() error {
			prefix := make([]byte, len(http2.ClientPreface))
			if _, err := io.ReadFull(peer, prefix); err != nil {
				return err
			}
			fr := http2.NewFramer(peer, peer)
			for range 2 {
				if _, err := fr.ReadFrame(); err != nil {
					return err
				}
			}
			if err := fr.WriteSettings(); err != nil {
				return err
			}
			var streamID uint32
			acknowledged := false
			for streamID == 0 || !acknowledged {
				frame, err := fr.ReadFrame()
				if err != nil {
					return err
				}
				if headers, ok := frame.(*http2.HeadersFrame); ok {
					streamID = headers.StreamID
				}
				if settings, ok := frame.(*http2.SettingsFrame); ok && settings.IsAck() {
					acknowledged = true
				}
			}
			var headers bytes.Buffer
			if err := hpack.NewEncoder(&headers).WriteField(hpack.HeaderField{Name: ":status", Value: "200"}); err != nil {
				return err
			}
			if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: streamID, BlockFragment: headers.Bytes(), EndHeaders: true}); err != nil {
				return err
			}
			if err := fr.WriteData(streamID, false, []byte("ab")); err != nil {
				return err
			}
			wire.signal.Store(true)
			return fr.WriteSettings()
		}()
	}()
	h2, err := client.transport.NewClientConn(wire)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close(); _ = h2.Close() })
	streamCtx, streamCancel := context.WithTimeout(client.ctx, 3*time.Second)
	t.Cleanup(streamCancel)
	requestReader, requestWriter := io.Pipe()
	t.Cleanup(func() { _ = requestReader.Close(); _ = requestWriter.Close() })
	request, err := http.NewRequestWithContext(streamCtx, http.MethodConnect, "https://target.invalid:443", requestReader)
	if err != nil {
		t.Fatal(err)
	}
	response, err := h2.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-wire.started:
	case <-time.After(time.Second):
		t.Fatal("peer did not stall the HTTP/2 writer")
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
	session := &webH2ClientSession{raw: wire, h2: h2, active: 1, authState: webH2ClientAuthReady}
	client.mu.Lock()
	client.sessions[session] = struct{}{}
	if current {
		client.current = session
	}
	client.mu.Unlock()
	conn := newWebH2Conn(response.Body, requestWriter, streamCancel, raw.LocalAddr(), raw.RemoteAddr())
	conn.onClose = func() { client.releaseSessionStream(session) }
	return session, conn
}
