// Package cover provides ordinary web handlers used as the public face of a
// web transport. The handlers deliberately contain no product-specific
// responses or headers.
package cover

import (
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var hopByHopHeaders = [...]string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// NewStaticHandler returns a handler rooted at directory. Only GET and HEAD
// are accepted; all other methods receive a normal HTTP 405 response.
func NewStaticHandler(directory string) (http.Handler, error) {
	if strings.TrimSpace(directory) == "" {
		return nil, errors.New("static directory is required")
	}
	root, err := filepath.Abs(directory)
	if err != nil {
		return nil, errors.New("resolve static directory")
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, errors.New("open static directory")
	}
	if !info.IsDir() {
		return nil, errors.New("static path is not a directory")
	}
	return &staticHandler{files: http.FileServer(http.Dir(root))}, nil
}

type staticHandler struct {
	files http.Handler
}

func (h *staticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	h.files.ServeHTTP(w, r)
}

// NewReverseProxyHandler returns a reverse proxy that can dial only origin.
// The requester controls the path, query, and ordinary end-to-end headers, but
// never the upstream scheme, authority, or Host header.
func NewReverseProxyHandler(origin *url.URL, transport http.RoundTripper) (http.Handler, error) {
	target, err := normalizeOrigin(origin)
	if err != nil {
		return nil, err
	}
	if transport == nil {
		defaultTransport := http.DefaultTransport.(*http.Transport).Clone()
		defaultTransport.Proxy = nil
		transport = defaultTransport
	}

	proxy := &httputil.ReverseProxy{
		Transport: &informationalHeaderTransport{base: transport},
		Rewrite: func(request *httputil.ProxyRequest) {
			upgrade := websocketRequestEligibility(request.In)
			request.SetURL(target)
			request.Out.Host = target.Host
			// ReverseProxy already removes nominated fields before Rewrite,
			// then restores its generic Upgrade pair. Retain the original
			// nomination boundary, and restore only our validated H1 WebSocket.
			removeConnectionNominatedHeaders(request.Out.Header, request.In.Header)
			removeUnsafeHeaders(request.Out.Header)
			if upgrade.eligible {
				request.Out.Header.Set("Connection", "Upgrade")
				request.Out.Header.Set("Upgrade", "websocket")
			}
			request.Out = withWebsocketRequestEligibility(request.Out, upgrade)
		},
		ModifyResponse: func(response *http.Response) error {
			if response.StatusCode == http.StatusSwitchingProtocols {
				if response.Body == nil {
					// ReverseProxy closes Body unconditionally on hook failure.
					response.Body = http.NoBody
				}
				if err := validateWebsocketResponse(response); err != nil {
					return err
				}
				if err := ownWebsocketResponse(response); err != nil {
					return err
				}
				removeUnsafeHeaders(response.Header)
				removeUnsafeHeaders(response.Trailer)
				response.Header.Set("Connection", "Upgrade")
				response.Header.Set("Upgrade", "websocket")
				return nil // Preserve duplex I/O and optional CloseWrite.
			}
			removeUnsafeHeaders(response.Header)
			removeUnsafeHeaders(response.Trailer)
			// An upgraded body is duplex, not an HTTP message with trailers.
			if response.Body != nil && response.StatusCode != http.StatusSwitchingProtocols {
				response.Body = &responseTrailerBody{body: response.Body, response: response}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, request *http.Request, _ error) {
			closeWebsocketResponse(request)
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		},
		ErrorLog: log.New(io.Discard, "", 0),
	}
	return proxy, nil
}

// informationalHeaderTransport filters upstream headers before ReverseProxy's
// trace copies an informational response to the downstream writer. Its
// ModifyResponse hook only sees the final response. Install a fresh trace here,
// after ReverseProxy installs its own, so filtering runs before older hooks
// without changing their order or return values or wrapping the response writer.
type informationalHeaderTransport struct {
	base http.RoundTripper
}

func (t *informationalHeaderTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	// Capture the immutable Rewrite result before an optional custom transport
	// sees the request. Its response.Request is not evidence of eligibility.
	trusted := websocketResponseRequest(request)
	trace := &httptrace.ClientTrace{
		Got1xxResponse: func(_ int, header textproto.MIMEHeader) error {
			removeUnsafeHeaders(http.Header(header))
			return nil
		},
	}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))
	response, err := t.base.RoundTrip(request)
	if response != nil && response.StatusCode == http.StatusSwitchingProtocols {
		response.Request = trusted
	}
	return response, err
}

// responseTrailerBody filters fields that a transport discovers only at EOF
// or Close, including replacement Trailer maps. It does not buffer the body.
// Trailer must not be inspected while Read is in progress. Close may interrupt
// that Read, so neither I/O operation holds mu: defer cleanup until concurrent
// operations have returned rather than blocking Close on the reader.
type responseTrailerBody struct {
	body     io.ReadCloser
	response *http.Response
	mu       sync.Mutex
	active   int
	pending  bool
}

func (b *responseTrailerBody) Read(p []byte) (int, error) {
	b.beginOperation()
	n, err := b.body.Read(p)
	b.finishOperation(err != nil)
	return n, err
}

func (b *responseTrailerBody) Close() error {
	b.beginOperation()
	err := b.body.Close()
	b.finishOperation(true)
	return err
}

func (b *responseTrailerBody) beginOperation() {
	b.mu.Lock()
	b.active++
	b.mu.Unlock()
}

func (b *responseTrailerBody) finishOperation(terminal bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.active--
	b.pending = b.pending || terminal
	if b.active == 0 && b.pending {
		removeUnsafeHeaders(b.response.Trailer)
		b.pending = false
	}
}

func normalizeOrigin(origin *url.URL) (*url.URL, error) {
	if origin == nil {
		return nil, errors.New("reverse proxy origin is required")
	}
	target := *origin
	target.Scheme = strings.ToLower(target.Scheme)
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, errors.New("reverse proxy origin must use http or https")
	}
	if target.Host == "" || target.Hostname() == "" || strings.ContainsAny(target.Host, "\x00\r\n\t /\\") {
		return nil, errors.New("reverse proxy origin has an invalid host")
	}
	if target.User != nil {
		return nil, errors.New("reverse proxy origin must not contain user information")
	}
	if target.Opaque != "" || target.Fragment != "" {
		return nil, errors.New("reverse proxy origin must be hierarchical and must not contain a fragment")
	}
	return &target, nil
}

func removeUnsafeHeaders(header http.Header) {
	removeConnectionNominatedHeaders(header, header)
	for _, name := range hopByHopHeaders {
		deleteHeaderFold(header, name)
	}
	deleteHeaderFold(header, "Authorization")
}

func removeConnectionNominatedHeaders(header, connectionSource http.Header) {
	for _, value := range headerValuesFold(connectionSource, "Connection") {
		for token := range strings.SplitSeq(value, ",") {
			if name := strings.TrimSpace(token); name != "" {
				deleteHeaderFold(header, name)
			}
		}
	}
}
