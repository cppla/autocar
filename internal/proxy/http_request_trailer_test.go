package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type forwardTrailerTestBody struct {
	read  func([]byte) (int, error)
	close func() error
}

func (b *forwardTrailerTestBody) Read(p []byte) (int, error) { return b.read(p) }
func (b *forwardTrailerTestBody) Close() error {
	if b.close != nil {
		return b.close()
	}
	return nil
}

func TestHTTPForwardRequestTrailerEOF(t *testing.T) {
	for _, dataWithEOF := range []bool{false, true} {
		name := "separate-EOF"
		if dataWithEOF {
			name = "data-with-EOF"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			in := &http.Request{Header: http.Header{"Content-Length": {"4"}, "Authorization": {"origin-token"}}, Trailer: http.Header{"X-End": {"stale"}, "X-Absent": {"stale"}}, ContentLength: 4}
			in = in.WithContext(ctx)
			in.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("body")), nil }
			calls := 0
			closed := false
			closeErr := errors.New("owned close error")
			in.Body = &forwardTrailerTestBody{
				read: func(p []byte) (int, error) {
					calls++
					if calls == 1 {
						if !dataWithEOF {
							return copy(p, "body"), nil
						}
					} else if calls > 2 || dataWithEOF {
						return 0, io.EOF
					}
					in.Trailer = http.Header{"X-End": {"complete"}, "X-Undeclared": {"hidden"}}
					if dataWithEOF {
						return copy(p, "body"), io.EOF
					}
					return 0, io.EOF
				},
				close: func() error { closed = true; return closeErr },
			}
			out := in.Clone(in.Context())
			prepareHTTPForwardRequestTrailers(in, out)
			captured := out.Trailer
			if out.Context() != ctx || out.Header.Get("Authorization") != "origin-token" || out.ContentLength != -1 || !reflect.DeepEqual(out.TransferEncoding, []string{"chunked"}) || out.GetBody != nil || out.Header.Get("Content-Length") != "" {
				t.Fatal("outbound context, authorization or trailer framing changed incorrectly")
			}
			if in.ContentLength != 4 || in.GetBody == nil || in.Header.Get("Content-Length") != "4" || in.TransferEncoding != nil {
				t.Fatal("modified caller's framing or replay getter")
			}
			p := make([]byte, 4)
			n, err := out.Body.Read(p)
			if n != 4 || string(p) != "body" || (dataWithEOF && err != io.EOF) || (!dataWithEOF && err != nil) {
				t.Fatalf("first Read=(%d,%v), payload=%q", n, err, p)
			}
			if !dataWithEOF {
				if captured.Get("X-End") != "stale" {
					t.Fatal("published before EOF")
				}
				if n, err := out.Body.Read(p); n != 0 || err != io.EOF {
					t.Fatalf("second Read=(%d,%v)", n, err)
				}
			}
			if captured.Get("X-End") != "complete" || len(captured) != 2 || len(captured["X-Absent"]) != 0 || captured.Get("X-Undeclared") != "" {
				t.Fatalf("EOF metadata in captured map=%v", captured)
			}
			in.Trailer["X-End"][0] = "caller-mutated"
			if _, err := out.Body.Read(p); err != io.EOF || captured.Get("X-End") != "complete" {
				t.Fatal("aliased source values or republished after EOF")
			}
			if err := out.Body.Close(); !closed || err != closeErr {
				t.Fatalf("Close error not preserved: %v closed=%v", err, closed)
			}
		})
	}
}

func TestHTTPForwardRequestTrailerPolicy(t *testing.T) {
	unsafe := []string{"Connection", "Authorization", "Proxy-Authorization", "Proxy-Authenticate", "Proxy-Authentication-Info", "Proxy-Connection", "Content-Length", "Transfer-Encoding", "Trailer", "Upgrade", "Host", "If-Match", "bad key", "X-Ünicode"}
	in := &http.Request{
		Header: http.Header{"connection": {" X-Initial , Upgrade"}, "Authorization": {"origin-token"}},
		Trailer: http.Header{
			"X-End": {"initial-a"}, "x-end": {"initial-b"}, "X-Initial": {"hidden"},
			"X-Early-Trailer": {"hidden"}, "X-Late": nil, "Connection": {"X-Early-Trailer"},
		},
	}
	for _, key := range unsafe {
		if key != "Connection" {
			in.Trailer[key] = []string{"hidden"}
		}
	}
	initial := in.Trailer.Clone()
	in.Body = &forwardTrailerTestBody{read: func([]byte) (int, error) {
		in.Trailer = http.Header{
			"X-End": {"final-a"}, "x-end": {"final-b"}, "X-Initial": {"hidden"},
			"X-Early-Trailer": {"hidden"}, "X-Late": {"hidden"}, "connection": {" x-late "},
			"X-Undeclared": {"hidden"},
		}
		for _, key := range unsafe {
			if !strings.EqualFold(key, "Connection") {
				in.Trailer[key] = []string{"hidden"}
			}
		}
		return 0, io.EOF
	}}
	out := in.Clone(in.Context())
	prepareHTTPForwardRequestTrailers(in, out)
	if !reflect.DeepEqual(in.Trailer, initial) {
		t.Fatal("preparation mutated original map")
	}
	if len(out.Trailer) != 2 || len(out.Trailer["X-End"]) != 2 {
		t.Fatalf("initial policy or alias merge=%v", out.Trailer)
	}
	out.Trailer["X-End"][0] = "out-mutated"
	if !reflect.DeepEqual(in.Trailer, initial) || in.Header.Get("Authorization") != "origin-token" {
		t.Fatal("outbound metadata aliases input")
	}
	// Header scrubbing must not erase the saved nominations.
	removeHopByHopHeaders(out.Header)
	if _, err := out.Body.Read(nil); err != io.EOF {
		t.Fatal(err)
	}
	got := slices.Clone(out.Trailer["X-End"])
	slices.Sort(got)
	if len(out.Trailer) != 1 || !reflect.DeepEqual(got, []string{"final-a", "final-b"}) || out.Header.Get("Authorization") != "origin-token" {
		t.Fatalf("EOF policy, aliases or origin authorization=%v headers=%v", out.Trailer, out.Header)
	}
	if in.Trailer.Get("Proxy-Authorization") != "hidden" || in.Trailer["connection"][0] != " x-late " {
		t.Fatal("EOF policy changed source metadata")
	}
}

func TestHTTPForwardRequestTrailerNoPublishOnErrorOrClose(t *testing.T) {
	readErr, closeErr := errors.New("body read failure"), errors.New("body close failure")
	in := &http.Request{Trailer: http.Header{"X-End": {"initial"}}}
	in.Body = &forwardTrailerTestBody{
		read: func(p []byte) (int, error) {
			in.Trailer["X-End"] = []string{"must-not-publish"}
			return copy(p, "x"), readErr
		},
		close: func() error { return closeErr },
	}
	out := in.Clone(in.Context())
	prepareHTTPForwardRequestTrailers(in, out)
	if n, err := out.Body.Read(make([]byte, 1)); n != 1 || err != readErr {
		t.Fatalf("Read error/count=(%d,%v)", n, err)
	}
	if err := out.Body.Close(); err != closeErr || out.Trailer.Get("X-End") != "initial" {
		t.Fatalf("Close error=%v trailer=%v", err, out.Trailer)
	}
}

func TestHTTPForwardRequestTrailerCloseInterruptsRead(t *testing.T) {
	entered, closed, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	closeDone := make(chan struct{})
	var readErr, closeErr error
	closerStarted := false
	var once sync.Once
	in := &http.Request{Trailer: http.Header{"X-End": nil}}
	in.Body = &forwardTrailerTestBody{
		read:  func([]byte) (int, error) { close(entered); <-closed; return 0, io.ErrClosedPipe },
		close: func() error { once.Do(func() { close(closed) }); return nil },
	}
	out := in.Clone(in.Context())
	prepareHTTPForwardRequestTrailers(in, out)
	// Cleanup independently unblocks and joins even if the success oracle fails.
	t.Cleanup(func() {
		_ = in.Body.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("owned reader did not join")
		}
		if closerStarted {
			select {
			case <-closeDone:
			case <-time.After(time.Second):
				t.Error("owned closer did not join")
			}
		}
	})
	go func() { _, readErr = out.Body.Read(nil); close(done) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("reader did not enter underlying body")
	}
	// Run Close with a separate joined worker so a regression cannot deadlock
	// the test goroutine before independent cleanup can close the source body.
	closerStarted = true
	go func() { closeErr = out.Body.Close(); close(closeDone) }()
	select {
	case <-closeDone:
		if closeErr != nil {
			t.Fatal(closeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("Close blocked behind body Read")
	}
	select {
	case <-done:
		if readErr != io.ErrClosedPipe || len(out.Trailer["X-End"]) != 0 {
			t.Fatalf("read error=%v trailer=%v", readErr, out.Trailer)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt body Read")
	}
}

func TestHTTPForwardRequestTrailerNoBridge(t *testing.T) {
	for _, mode := range []string{"nil-body", "no-body", "no-declaration", "unsafe-only"} {
		t.Run(mode, func(t *testing.T) {
			in := &http.Request{Header: http.Header{"Content-Length": {"4"}}, ContentLength: 4, TransferEncoding: []string{"identity"}, Trailer: http.Header{"X-End": nil}}
			in.Body = io.NopCloser(strings.NewReader("body"))
			in.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("body")), nil }
			switch mode {
			case "nil-body":
				in.Body = nil
			case "no-body":
				in.Body = http.NoBody
			case "no-declaration":
				in.Trailer = nil
			case "unsafe-only":
				in.Trailer = http.Header{"Authorization": {"secret"}}
			}
			out := in.Clone(in.Context())
			prepareHTTPForwardRequestTrailers(in, out)
			if out.Body != in.Body || out.ContentLength != 4 || out.Header.Get("Content-Length") != "4" || out.GetBody == nil || !reflect.DeepEqual(out.TransferEncoding, in.TransferEncoding) {
				t.Fatal("unnecessary body/framing/replay mutation")
			}
			if mode == "unsafe-only" && len(out.Trailer) != 0 {
				t.Fatal("unsafe declarations retained")
			}
		})
	}
}
