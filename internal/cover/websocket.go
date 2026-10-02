package cover

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
)

const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type websocketRequestContextKey struct{}
type websocketResponseContextKey struct{}
type websocketCleanupContextKey struct{}

// A value, not a shared pointer: each request keeps its own original key and
// eligibility even when concurrent custom RoundTrippers replace response.Request.
type websocketRequestInfo struct {
	eligible bool
	key      string
}

func websocketRequestEligibility(request *http.Request) websocketRequestInfo {
	if request == nil || request.Method != http.MethodGet || request.ProtoMajor != 1 || request.ProtoMinor != 1 ||
		request.ContentLength != 0 || request.Body != nil && request.Body != http.NoBody ||
		len(request.TransferEncoding) != 0 || len(request.Trailer) != 0 || len(headerValuesFold(request.Header, "Transfer-Encoding")) != 0 ||
		!websocketUpgradeHeaders(request.Header) {
		return websocketRequestInfo{}
	}
	version, ok := singleHeaderValue(request.Header, "Sec-WebSocket-Version")
	if !ok || version != "13" {
		return websocketRequestInfo{}
	}
	key, ok := singleHeaderValue(request.Header, "Sec-WebSocket-Key")
	if !ok {
		return websocketRequestInfo{}
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(key)
	if err != nil || len(decoded) != 16 || base64.StdEncoding.EncodeToString(decoded) != key {
		return websocketRequestInfo{}
	}
	return websocketRequestInfo{eligible: true, key: key}
}

func withWebsocketRequestEligibility(request *http.Request, info websocketRequestInfo) *http.Request {
	ctx := context.WithValue(request.Context(), websocketRequestContextKey{}, info)
	ctx = context.WithValue(ctx, websocketCleanupContextKey{}, &websocketCleanupState{})
	return request.WithContext(ctx)
}

func websocketResponseRequest(request *http.Request) *http.Request {
	info, _ := request.Context().Value(websocketRequestContextKey{}).(websocketRequestInfo)
	return request.WithContext(context.WithValue(request.Context(), websocketResponseContextKey{}, info))
}

func validateWebsocketResponse(response *http.Response) error {
	invalid := errors.New("invalid WebSocket upgrade response")
	if response.Request == nil || response.ProtoMajor != 1 || response.ProtoMinor != 1 ||
		!websocketUpgradeHeaders(response.Header) {
		return invalid
	}
	info, ok := response.Request.Context().Value(websocketResponseContextKey{}).(websocketRequestInfo)
	if !ok || !info.eligible {
		return invalid
	}
	accept, ok := singleHeaderValue(response.Header, "Sec-WebSocket-Accept")
	// SHA-1 is the RFC 6455 handshake transform, not authentication or a MAC.
	want := sha1.Sum([]byte(info.key + websocketGUID))
	if !ok || accept != base64.StdEncoding.EncodeToString(want[:]) {
		return invalid
	}
	if _, ok := response.Body.(io.ReadWriteCloser); !ok {
		return invalid
	}
	return nil
}

// ReverseProxy closes invalid 101 bodies itself, but its early unsupported-
// Hijacker branch does not close an already validated body. Track only those
// accepted bodies, without changing the shared upstream transport's lifetime.
type websocketCleanupState struct {
	mu   sync.Mutex
	body io.ReadWriteCloser
}

func ownWebsocketResponse(response *http.Response) error {
	state, _ := response.Request.Context().Value(websocketCleanupContextKey{}).(*websocketCleanupState)
	if state == nil {
		return errors.New("missing WebSocket response owner")
	}
	body := response.Body.(io.ReadWriteCloser) // validated before ownership
	guard := &websocketDuplexBody{ReadWriteCloser: body}
	var protected io.ReadWriteCloser = guard
	if halfClose, ok := body.(interface{ CloseWrite() error }); ok {
		protected = &websocketHalfCloseBody{websocketDuplexBody: guard, halfClose: halfClose}
	}
	response.Body = protected
	state.mu.Lock()
	state.body = protected
	state.mu.Unlock()
	return nil
}

func closeWebsocketResponse(request *http.Request) {
	if request == nil {
		return
	}
	state, _ := request.Context().Value(websocketCleanupContextKey{}).(*websocketCleanupState)
	if state == nil {
		return
	}
	state.mu.Lock()
	body := state.body
	state.mu.Unlock()
	if body != nil {
		_ = body.Close()
	}
}

type websocketDuplexBody struct {
	io.ReadWriteCloser
	once     sync.Once
	closeErr error
}

func (b *websocketDuplexBody) Close() error {
	b.once.Do(func() { b.closeErr = b.ReadWriteCloser.Close() })
	return b.closeErr
}

// Do not advertise CloseWrite when the original duplex body lacks it.
type websocketHalfCloseBody struct {
	*websocketDuplexBody
	halfClose interface{ CloseWrite() error }
}

func (b *websocketHalfCloseBody) CloseWrite() error { return b.halfClose.CloseWrite() }

// Only the WebSocket Upgrade pair may survive hop removal. Other valid tokens
// remain nominations to scrub; mandatory/negotiation fields may not be revived.
func websocketUpgradeHeaders(header http.Header) bool {
	upgrade, ok := singleHeaderValue(header, "Upgrade")
	if !ok || !httpToken(upgrade) || !strings.EqualFold(upgrade, "websocket") {
		return false
	}
	connection, ok := singleHeaderValue(header, "Connection")
	if !ok {
		return false
	}
	seen := make(map[string]bool)
	for part := range strings.SplitSeq(connection, ",") {
		part = strings.Trim(part, " \t")
		token := strings.ToLower(part)
		if !httpToken(part) || seen[token] || token == "close" || websocketHandshakeHeader(token) {
			return false
		}
		seen[token] = true
	}
	return seen["upgrade"]
}

func websocketHandshakeHeader(name string) bool {
	switch name {
	case "sec-websocket-key", "sec-websocket-version", "sec-websocket-accept", "sec-websocket-protocol", "sec-websocket-extensions":
		return true
	default:
		return false
	}
}

func httpToken(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' ||
			strings.ContainsRune("!#$%&'*+-.^_`|~", rune(char)) {
			continue
		}
		return false
	}
	return true
}

func singleHeaderValue(header http.Header, name string) (string, bool) {
	values := headerValuesFold(header, name)
	if len(values) != 1 {
		return "", false
	}
	value := strings.Trim(values[0], " \t")
	return value, value != ""
}

// Native net/http fields are canonical, but an optional custom RoundTripper
// need not canonicalize its map. HTTP field names are ASCII tokens: Unicode
// case-fold aliases must not qualify when Header.Write would drop the field.
func headerValuesFold(header http.Header, name string) []string {
	var values []string
	for field, entries := range header {
		if httpToken(field) && httpToken(name) && strings.EqualFold(field, name) {
			values = append(values, entries...)
		}
	}
	return values
}

func deleteHeaderFold(header http.Header, name string) {
	for field := range header {
		if httpToken(field) && httpToken(name) && strings.EqualFold(field, name) {
			delete(header, field)
		}
	}
}
