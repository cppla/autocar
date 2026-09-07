// Package cover provides ordinary web handlers used as the public face of a
// web transport. The handlers deliberately contain no product-specific
// responses or headers.
package cover

import (
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
		Transport: transport,
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(target)
			request.Out.Host = target.Host
			removeUnsafeHeaders(request.Out.Header)
		},
		ModifyResponse: func(response *http.Response) error {
			removeUnsafeHeaders(response.Header)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		},
		ErrorLog: log.New(io.Discard, "", 0),
	}
	return proxy, nil
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
	for _, value := range header.Values("Connection") {
		for token := range strings.SplitSeq(value, ",") {
			if name := strings.TrimSpace(token); name != "" {
				header.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		header.Del(name)
	}
	header.Del("Authorization")
}
