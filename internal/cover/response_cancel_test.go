package cover

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

func TestReverseProxyResponseBodyCancellationReachesOrigin(t *testing.T) {
	canceled := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-End")
		_, _ = io.WriteString(w, "x")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(canceled)
	}))
	t.Cleanup(origin.Close)
	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	upstream := &http.Transport{Proxy: nil}
	t.Cleanup(upstream.CloseIdleConnections)
	bodyClosed := make(chan struct{})
	var closeOnce sync.Once
	handler, err := NewReverseProxyHandler(originURL, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		response, err := upstream.RoundTrip(r)
		if err != nil {
			return nil, err
		}
		body := response.Body
		response.Body = &trailerTestBody{read: body.Read, close: func() error {
			err := body.Close()
			closeOnce.Do(func() { close(bodyClosed) })
			return err
		}}
		return response, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	frontDone := make(chan struct{})
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(frontDone)
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)
	transport := &http.Transport{Proxy: nil}
	t.Cleanup(transport.CloseIdleConnections)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, front.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	first := make([]byte, 1)
	if _, err := io.ReadFull(response.Body, first); err != nil || first[0] != 'x' {
		t.Fatalf("initial streamed byte = %q, error %v", first, err)
	}
	readDone := make(chan error, 1)
	go func() { _, err := response.Body.Read(make([]byte, 1)); readDone <- err }()
	cancel()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("body read succeeded after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("response body read did not stop after cancellation")
	}
	for name, done := range map[string]<-chan struct{}{
		"upstream request": canceled,
		"upstream body":    bodyClosed,
		"front handler":    frontDone,
	} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("client cancellation did not release %s", name)
		}
	}
}
