package proxy

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
)

func TestCopyHTTPResponseFlushAndErrors(t *testing.T) {
	copyErr := errors.New("response copy fixture")
	for _, test := range []struct {
		name         string
		length       int64
		contentType  string
		hideFlusher  bool
		flushErrorAt int
		writeError   bool
		readError    bool
		wantFlushes  int
		wantBody     string
		wantError    bool
	}{
		{name: "unknown length", length: -1, wantFlushes: 2, wantBody: "body"},
		{name: "event stream", length: 4, contentType: "text/event-stream; charset=utf-8", wantFlushes: 2, wantBody: "body"},
		{name: "ordinary fixed size", length: 4, contentType: "text/plain", wantBody: "body"},
		{name: "wrapper without flusher", length: -1, hideFlusher: true, wantBody: "body"},
		{name: "header flush error", length: -1, flushErrorAt: 1, wantFlushes: 1, wantError: true},
		{name: "body flush error", length: -1, flushErrorAt: 2, wantFlushes: 2, wantBody: "body", wantError: true},
		{name: "body write error", length: -1, writeError: true, wantFlushes: 1, wantError: true},
		{name: "body read error", length: -1, readError: true, wantFlushes: 1, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			writer := &httpCopyTestWriter{header: make(http.Header), err: copyErr, flushErrorAt: test.flushErrorAt, writeError: test.writeError}
			var destination http.ResponseWriter = writer
			if test.hideFlusher {
				destination = struct{ http.ResponseWriter }{writer}
			}
			var source io.Reader = strings.NewReader("body")
			if test.readError {
				source = iotest.ErrReader(copyErr)
			}
			response := &http.Response{ContentLength: test.length, Header: make(http.Header)}
			response.Header.Set("Content-Type", test.contentType)
			err := copyHTTPResponse(destination, source, response)
			if (err != nil) != test.wantError || (test.wantError && !errors.Is(err, copyErr)) {
				t.Fatalf("copy error = %v, want fixture error = %v", err, test.wantError)
			}
			if writer.flushes != test.wantFlushes || writer.body.String() != test.wantBody {
				t.Fatalf("flushes/body = %d/%q, want %d/%q", writer.flushes, writer.body.String(), test.wantFlushes, test.wantBody)
			}
		})
	}
}

type httpCopyTestWriter struct {
	header       http.Header
	body         bytes.Buffer
	err          error
	flushes      int
	flushErrorAt int
	writeError   bool
}

func (w *httpCopyTestWriter) Header() http.Header { return w.header }
func (*httpCopyTestWriter) WriteHeader(int)       {}

func (w *httpCopyTestWriter) Write(p []byte) (int, error) {
	if w.writeError {
		return 0, w.err
	}
	return w.body.Write(p)
}

func (w *httpCopyTestWriter) FlushError() error {
	w.flushes++
	if w.flushes == w.flushErrorAt {
		return w.err
	}
	return nil
}
