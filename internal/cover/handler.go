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
			if isOptionsAsterisk(request.In) {
				// A server-wide OPTIONS target is not a resource below the
				// origin's configured base path or query. Keep only its fixed
				// upstream scheme and authority from SetURL.
				request.Out.URL.Path = "*"
				request.Out.URL.RawPath = ""
				request.Out.URL.RawQuery = ""
				request.Out.URL.ForceQuery = false
			}
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
			// Production responses were prepared by the transport before
			// ReverseProxy removed their original Connection fields. Keep the
			// direct hook useful too, without replacing an already saved policy.
			prepareResponseTrailers(response)
			removeUnsafeHeaders(response.Header)
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
	} else if response != nil && err == nil {
		// ReverseProxy removes response hop fields before ModifyResponse.
		// Capture their nominations here so late trailers cannot revive them.
		prepareResponseTrailers(response)
	}
	return response, err
}

func isOptionsAsterisk(request *http.Request) bool {
	return request != nil && request.URL != nil && request.Method == http.MethodOptions &&
		request.RequestURI == "*" && request.URL.Path == "*" && request.URL.RawPath == "" &&
		request.URL.Opaque == "" && request.URL.RawQuery == "" && !request.URL.ForceQuery &&
		request.URL.Fragment == "" && request.URL.RawFragment == "" && request.URL.User == nil
}

// Save a request-local, immutable union of initial response Header and Trailer
// nominations before either map is scrubbed. A current Trailer map may add new
// nominations later; it must never change this original policy. A 101 body is
// duplex and is deliberately prepared only by the separate WebSocket owner.
func prepareResponseTrailers(response *http.Response) {
	if body, ok := response.Body.(*responseTrailerBody); ok && body.response == response {
		return
	}
	nominations := collectConnectionNominations(response.Header, response.Trailer)
	removeUnsafeHeadersWithNominations(response.Trailer, nominations)
	if response.Body != nil {
		response.Body = &responseTrailerBody{body: response.Body, response: response, nominations: nominations}
	}
}

// responseTrailerBody filters fields that a transport discovers only at EOF
// or Close, including replacement Trailer maps. It does not buffer the body.
// Trailer must not be inspected while Read is in progress. Close may interrupt
// that Read, so neither I/O operation holds mu: defer cleanup until concurrent
// operations have returned rather than blocking Close on the reader.
type responseTrailerBody struct {
	body        io.ReadCloser
	response    *http.Response
	nominations connectionNominations
	mu          sync.Mutex
	active      int
	pending     bool
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
		current := collectConnectionNominations(b.response.Trailer)
		removeUnsafeHeadersWithNominations(b.response.Trailer, b.nominations, current)
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
	removeUnsafeHeadersWithNominations(header, collectConnectionNominations(header))
}

func removeUnsafeHeadersWithNominations(header http.Header, nominations ...connectionNominations) {
	applyConnectionNominations(header, nominations...)
	for _, name := range hopByHopHeaders {
		deleteHeaderFold(header, name)
	}
	deleteHeaderFold(header, "Authorization")
	// This namespace belongs to relay-authenticated responses, not the public
	// cover origin. Authentication-Info and WWW-Authenticate remain end-to-end.
	deleteHeaderFold(header, "Proxy-Authentication-Info")
}

func removeConnectionNominatedHeaders(header, connectionSource http.Header) {
	applyConnectionNominations(header, collectConnectionNominations(connectionSource))
}

// Construct once, then only read this set while applying it to Header or any
// subsequent Trailer map. Keys own their bytes independently of source maps.
type connectionNominations map[string]struct{}

func collectConnectionNominations(sources ...http.Header) connectionNominations {
	var nominations connectionNominations
	var scratch [64]byte
	folded := scratch[:0]
	for _, source := range sources {
		for _, value := range headerValuesFold(source, "Connection") {
			for token := range strings.SplitSeq(value, ",") {
				name := strings.TrimSpace(token)
				if !httpToken(name) {
					continue
				}
				folded = foldASCIIHeaderName(folded, name)
				if _, exists := nominations[string(folded)]; !exists {
					if nominations == nil {
						nominations = make(connectionNominations)
					}
					// Only a new nomination owns a copied key. Repeated tokens
					// reuse scratch; they never rescan the destination header.
					nominations[string(folded)] = struct{}{}
				}
			}
		}
	}
	return nominations
}

func applyConnectionNominations(header http.Header, nominations ...connectionNominations) {
	active := false
	for _, set := range nominations {
		active = active || len(set) != 0
	}
	if !active {
		return
	}
	// Collect first: header and connectionSource may be the same map, and
	// Connection itself may be nominated without hiding later nominations.
	var scratch [64]byte
	folded := scratch[:0]
	for field := range header {
		if !httpToken(field) {
			continue
		}
		folded = foldASCIIHeaderName(folded, field)
		for _, set := range nominations {
			if _, nominated := set[string(folded)]; nominated {
				delete(header, field)
				break
			}
		}
	}
}

// Call only for validated ASCII HTTP tokens. The scratch buffer is local to
// one filtering call; map lookups need no separately retained folded string.
func foldASCIIHeaderName(buffer []byte, name string) []byte {
	if cap(buffer) < len(name) {
		buffer = make([]byte, len(name))
	}
	buffer = buffer[:len(name)]
	for index := range name {
		char := name[index]
		if char >= 'A' && char <= 'Z' {
			char += 'a' - 'A'
		}
		buffer[index] = char
	}
	return buffer
}
