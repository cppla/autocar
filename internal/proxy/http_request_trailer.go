package proxy

import (
	"io"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/net/http/httpguts"
)

// Clone owns Trailer but shares Body. The server body fills the original map
// only at EOF; publish its safe declared values before the transport sees EOF.
func prepareHTTPForwardRequestTrailers(in, out *http.Request) {
	blocked := httpForwardTrailerNominations(in.Header, in.Trailer)
	destination := make(http.Header, len(out.Trailer))
	declared := make(map[string]string, len(out.Trailer))
	for field, values := range out.Trailer {
		if !httpForwardTrailerAllowed(field, blocked) {
			continue
		}
		key := http.CanonicalHeaderKey(field)
		declared[strings.ToLower(field)] = key
		destination[key] = append(destination[key], values...)
	}
	out.Trailer = destination
	if len(declared) == 0 || out.Body == nil || out.Body == http.NoBody {
		return
	}
	out.Body = &httpForwardTrailerBody{
		body: out.Body, source: in, destination: destination,
		declared: declared, blocked: blocked,
	}
	// Known-length embedder requests can have trailers too. Keep the incoming
	// body's length validation but use H1 framing which actually emits trailers.
	out.ContentLength = -1
	out.TransferEncoding = []string{"chunked"}
	for field := range out.Header {
		if strings.EqualFold(field, "Content-Length") {
			delete(out.Header, field)
		}
	}
	// A replay getter would bypass the EOF bridge. Do not modify the caller's.
	out.GetBody = nil
}

func httpForwardTrailerNominations(headers ...http.Header) map[string]bool {
	blocked := make(map[string]bool)
	for _, header := range headers {
		for field, values := range header {
			if !strings.EqualFold(field, "Connection") {
				continue
			}
			for _, value := range values {
				for _, token := range strings.Split(value, ",") {
					token = strings.TrimSpace(token)
					if httpguts.ValidHeaderFieldName(token) {
						blocked[strings.ToLower(token)] = true
					}
				}
			}
		}
	}
	return blocked
}

func httpForwardTrailerAllowed(field string, blocked map[string]bool) bool {
	return httpguts.ValidHeaderFieldName(field) && httpguts.ValidTrailerHeader(field) &&
		!isHopByHopHeader(field) && !strings.EqualFold(field, "Proxy-Authentication-Info") &&
		!blocked[strings.ToLower(field)]
}

// One body reader may run concurrently with Close, as net/http requires.
// Close delegates without taking an I/O lock so it can unblock that reader.
// Only successful EOF publishes metadata; neither errors nor Close do so.
type httpForwardTrailerBody struct {
	body        io.ReadCloser
	source      *http.Request
	destination http.Header
	declared    map[string]string
	blocked     map[string]bool
	once        sync.Once
}

func (b *httpForwardTrailerBody) Read(p []byte) (int, error) {
	n, err := b.body.Read(p)
	if err == io.EOF {
		b.once.Do(func() {
			current := b.source.Trailer // Custom bodies may replace the map at EOF.
			for field := range httpForwardTrailerNominations(current) {
				b.blocked[field] = true
			}
			// Keep the map identity already captured by the transport.
			clear(b.destination)
			for _, key := range b.declared {
				if httpForwardTrailerAllowed(key, b.blocked) {
					b.destination[key] = nil
				}
			}
			// One ASCII alias contributes values once to its logical declaration.
			// Copy slices so the outbound metadata never aliases caller storage.
			for field, values := range current {
				if !httpForwardTrailerAllowed(field, b.blocked) {
					continue
				}
				if key, ok := b.declared[strings.ToLower(field)]; ok {
					b.destination[key] = append(b.destination[key], values...)
				}
			}
		})
	}
	return n, err
}

func (b *httpForwardTrailerBody) Close() error { return b.body.Close() }
