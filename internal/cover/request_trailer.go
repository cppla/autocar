package cover

import (
	"io"
	"net/http"
	"sync"

	"golang.org/x/net/http/httpguts"
)

// CloneRequestForCover owns the request's metadata without buffering its body.
// Unlike Request.Clone alone, declared trailers are copied into the owned map
// when the shared body reaches EOF, even if the server replaces Trailer then.
// The relay credential is never delegated to the website handler. Ordinary
// Authorization retains the handler's existing policy; the reverse proxy
// applies its stricter upstream policy separately.
//
// As with an HTTP request body, one reader may run concurrently with Close.
// Trailer values must be finalized before Read returns EOF, not by Close.
func CloneRequestForCover(request *http.Request) *http.Request {
	clone := request.Clone(request.Context())
	deleteHeaderFold(clone.Header, "Proxy-Authorization")
	deleteHeaderFold(clone.Trailer, "Proxy-Authorization")
	clone.Body = bridgeRequestTrailers(clone.Body, request, clone.Trailer, nil)
	return clone
}

// ReverseProxy cloned the metadata but still shares In.Body. Preserve that
// second ownership boundary, including the original hop nominations which
// ReverseProxy removed from Out.Header before calling Rewrite.
func prepareRequestTrailers(in, out *http.Request, publicOrigin bool) {
	original := originalRequestTrailerSource(in)
	nominations := collectConnectionNominations(in.Header, in.Trailer, original.Trailer)
	filter := func(destination, current http.Header) {
		// An earlier bridge intentionally does not copy unannounced fields.
		// Still retain late Connection policy from its original source, without
		// forwarding that field or any other undeclared metadata.
		removeUnsafeHeadersWithNominations(destination, nominations, collectConnectionNominations(current, original.Trailer))
		for key := range destination {
			if !httpToken(key) || !httpguts.ValidTrailerHeader(key) {
				delete(destination, key)
			}
		}
		if publicOrigin {
			removePublicOriginForwardingHeaders(destination)
		}
	}
	filter(out.Trailer, in.Trailer)
	if len(out.Trailer) == 0 || out.Body == nil || out.Body == http.NoBody {
		return
	}
	out.Body = bridgeRequestTrailers(out.Body, in, out.Trailer, filter)
	// H2/H3 may declare trailers alongside a positive Content-Length. H1's
	// writer discards trailers unless framing is chunked; choose that framing
	// explicitly without weakening the original incoming body's length checks.
	out.ContentLength = -1
	out.TransferEncoding = []string{"chunked"}
	deleteHeaderFold(out.Header, "Content-Length")
	// Automatic body replay must not reuse a getter that bypasses this bridge.
	// Server requests normally have no GetBody; the caller's getter is untouched.
	out.GetBody = nil
}

func bridgeRequestTrailers(body io.ReadCloser, source *http.Request, destination http.Header, filter func(http.Header, http.Header)) io.ReadCloser {
	if body == nil || body == http.NoBody || len(destination) == 0 {
		return body
	}
	declared := make(map[string]string, len(destination))
	var scratch [64]byte
	folded := scratch[:0]
	for key := range destination {
		if !httpToken(key) {
			continue
		}
		folded = foldASCIIHeaderName(folded, key)
		declared[string(folded)] = http.CanonicalHeaderKey(key)
	}
	return &requestTrailerBody{body: body, source: source, original: originalRequestTrailerSource(source), destination: destination, declared: declared, filter: filter}
}

// Only our own bridge establishes this immutable ownership link. Do not infer
// an original source from arbitrary caller context or a custom transport.
func originalRequestTrailerSource(request *http.Request) *http.Request {
	if body, ok := request.Body.(*requestTrailerBody); ok {
		return body.original
	}
	return request
}

// Publication must finish before EOF is returned: the transport can write
// trailers immediately afterwards and already holds destination's map identity.
// Close does not inspect metadata or take a reader lock, so it can interrupt a
// blocked Read. The underlying HTTP body owns EOF/Close synchronization; custom
// bodies that concurrently mutate Trailer from Close violate this EOF contract.
type requestTrailerBody struct {
	body        io.ReadCloser
	source      *http.Request
	original    *http.Request
	destination http.Header
	declared    map[string]string
	filter      func(http.Header, http.Header)
	once        sync.Once
}

func (b *requestTrailerBody) Read(p []byte) (int, error) {
	n, err := b.body.Read(p)
	if err == io.EOF {
		b.once.Do(func() {
			current := b.source.Trailer // H3 can replace the entire map at EOF.
			clear(b.destination)
			for _, key := range b.declared {
				b.destination[key] = nil
			}
			// One source scan is linear in the number of fields. A logical
			// declaration owns one output key even if a custom map contains
			// multiple ASCII case aliases; values must not be multiplied.
			var scratch [64]byte
			folded := scratch[:0]
			for field, values := range current {
				if !httpToken(field) {
					continue
				}
				folded = foldASCIIHeaderName(folded, field)
				if key, declared := b.declared[string(folded)]; declared {
					b.destination[key] = append(b.destination[key], values...)
				}
			}
			if b.filter != nil {
				b.filter(b.destination, current)
			}
		})
	}
	return n, err
}

func (b *requestTrailerBody) Close() error { return b.body.Close() }
