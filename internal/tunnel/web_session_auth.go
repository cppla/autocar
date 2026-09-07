package tunnel

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

const (
	webSessionAuthVersion byte = 1

	webSessionKeyInfo        = "autocar web-cover connection auth v1"
	webSessionBootstrapLabel = "autocar web-cover connection bootstrap v1"
	webSessionRequestLabel   = "autocar web-cover connection request v1"
	webSessionResponseLabel  = "autocar web-cover connection response v1"

	// A 128-bit truncated HMAC-SHA-256 tag keeps continuation credentials
	// compact while retaining a security margin far beyond the number of
	// requests one physical HTTP connection can carry.
	webSessionTagBytes         = 16
	webSessionBootstrapBytes   = 1 + webAuthNonceBytes + webSessionTagBytes
	webSessionTicketBytes      = 1 + 8 + webSessionTagBytes
	webSessionResponseBytes    = 1 + 8 + webSessionTagBytes
	webSessionReplayWindowBits = 128
)

var errWebSessionSequenceExhausted = errors.New("tunnel: web-cover connection authentication sequence exhausted")

type webSessionKey [sha256.Size]byte

// webSessionExchange identifies one continuation request and is passed back
// to response verification. Its fields stay private so callers cannot create a
// response transcript that was not returned by authorization or verification.
type webSessionExchange struct {
	sequence uint64
}

// webSessionClientAuth is scoped to exactly one physical HTTP connection.
// The integration layer must never copy it to a replacement connection.
type webSessionClientAuth struct {
	key webSessionKey

	mu            sync.Mutex
	nextSequence  uint64
	sequenceEnded bool
	closed        bool
	pending       map[uint64]struct{}
	oldestPending uint64
	changed       chan struct{}
}

// webSessionServerAuth is scoped to exactly one physical HTTP connection. It
// retains the claims established by that connection's full bootstrap request
// and a bounded replay window for continuation requests.
type webSessionServerAuth struct {
	key           webSessionKey
	sessionClaims webAuthClaims
	replay        webSessionReplayWindow
}

// webSessionReplayWindow accepts out-of-order concurrent requests within a
// fixed 128-sequence window. Bit zero represents highest, bit 127 the oldest
// still-acceptable sequence.
type webSessionReplayWindow struct {
	mu      sync.Mutex
	highest uint64
	seen    [2]uint64
}

type webServerConnectionAuthContextKey struct{}

type webServerConnectionAuthPhase uint8

const (
	webServerConnectionAuthFresh webServerConnectionAuthPhase = iota
	webServerConnectionAuthBootstrapping
	webServerConnectionAuthEstablished
	webServerConnectionAuthClosed
)

// webServerConnectionAuth is the small lifecycle gate attached to the actual
// TLS or QUIC connection by its ConnContext hook. Keeping this state on the
// transport connection, rather than an address or HTTP client identifier,
// prevents continuation credentials from crossing connection boundaries.
type webServerConnectionAuth struct {
	mu      sync.Mutex
	phase   webServerConnectionAuthPhase
	session *webSessionServerAuth
	close   func() error
	ready   chan struct{}
	// readyClosed is protected by mu.
	readyClosed bool
	generation  uint64

	closeOnce sync.Once
}

func newWebServerConnectionAuth(closeConnection func() error) *webServerConnectionAuth {
	return &webServerConnectionAuth{close: closeConnection, ready: make(chan struct{})}
}

func (s *webServerConnectionAuth) beginBootstrap() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != webServerConnectionAuthFresh {
		return false
	}
	s.phase = webServerConnectionAuthBootstrapping
	return true
}

// abortBootstrap releases requests waiting behind an invalid full credential
// and restores ordinary cover traffic on this still-unauthenticated physical
// connection. It is not used once any valid full credential has authenticated.
func (s *webServerConnectionAuth) abortBootstrap() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.phase == webServerConnectionAuthBootstrapping {
		if !s.readyClosed {
			close(s.ready)
		}
		s.ready = make(chan struct{})
		s.readyClosed = false
		s.generation++
		s.phase = webServerConnectionAuthFresh
	}
	s.mu.Unlock()
}

func (s *webServerConnectionAuth) establish(session *webSessionServerAuth) bool {
	if s == nil || session == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != webServerConnectionAuthBootstrapping {
		return false
	}
	s.session = session
	s.phase = webServerConnectionAuthEstablished
	if !s.readyClosed {
		close(s.ready)
		s.readyClosed = true
	}
	return true
}

func (s *webServerConnectionAuth) establishedSession() (*webSessionServerAuth, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != webServerConnectionAuthEstablished || s.session == nil {
		return nil, false
	}
	return s.session, true
}

func (s *webServerConnectionAuth) phaseSnapshot() webServerConnectionAuthPhase {
	if s == nil {
		return webServerConnectionAuthFresh
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.phase
}

// waitEstablished lets concurrently dispatched streams wait without holding a
// mutex while the one full bootstrap request commits its authenticated
// response. It never treats an aborted or closed bootstrap as established.
func (s *webServerConnectionAuth) waitEstablished(ctx context.Context) (*webSessionServerAuth, bool) {
	if s == nil || ctx == nil {
		return nil, false
	}
	s.mu.Lock()
	switch s.phase {
	case webServerConnectionAuthEstablished:
		session := s.session
		s.mu.Unlock()
		return session, session != nil
	case webServerConnectionAuthBootstrapping:
		ready := s.ready
		generation := s.generation
		s.mu.Unlock()
		select {
		case <-ready:
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.generation != generation || s.phase != webServerConnectionAuthEstablished || s.session == nil {
				return nil, false
			}
			return s.session, true
		case <-ctx.Done():
			return nil, false
		}
	default:
		s.mu.Unlock()
		return nil, false
	}
}

func (s *webServerConnectionAuth) closePhysicalConnection() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.phase = webServerConnectionAuthClosed
	s.session = nil
	if !s.readyClosed {
		close(s.ready)
		s.readyClosed = true
	}
	s.mu.Unlock()
	s.closeOnce.Do(func() {
		if s.close != nil {
			_ = s.close()
		}
	})
}

// issueWebSessionBootstrap creates the short authenticated response value for
// a valid full request and the server half of the resulting connection
// session. This applies to both successful CONNECT and authenticated HTTP
// errors. The caller installs the returned state on the same physical
// connection immediately before committing that response's headers.
func issueWebSessionBootstrap(
	key webAuthKey,
	binding webAuthBinding,
	claims webAuthClaims,
	status int,
	random io.Reader,
) (string, *webSessionServerAuth, error) {
	if err := validateWebSessionBootstrapInput(binding, claims, status); err != nil {
		return "", nil, err
	}
	if random == nil {
		random = rand.Reader
	}
	var serverNonce [webAuthNonceBytes]byte
	if _, err := io.ReadFull(random, serverNonce[:]); err != nil {
		return "", nil, fmt.Errorf("tunnel: generate web-cover connection nonce: %w", err)
	}

	sessionKey, err := deriveWebSessionKey(key, claims.nonce, serverNonce)
	if err != nil {
		return "", nil, err
	}
	tag := calculateWebSessionBootstrapTag(key, binding, claims, status, webSessionAuthVersion, serverNonce)
	var raw [webSessionBootstrapBytes]byte
	raw[0] = webSessionAuthVersion
	copy(raw[1:1+webAuthNonceBytes], serverNonce[:])
	copy(raw[1+webAuthNonceBytes:], tag[:])

	proof := webAuthResponseParameter + base64.RawURLEncoding.EncodeToString(raw[:])
	server := &webSessionServerAuth{key: sessionKey, sessionClaims: claims}
	return proof, server, nil
}

// acceptWebSessionBootstrap authenticates a bootstrap response and returns the
// client half of the connection session. Every input must be the same value
// used for the full request and its HTTP response.
func acceptWebSessionBootstrap(
	key webAuthKey,
	values []string,
	binding webAuthBinding,
	claims webAuthClaims,
	status int,
) (*webSessionClientAuth, bool) {
	if err := validateWebSessionBootstrapInput(binding, claims, status); err != nil {
		dummyWebSessionBootstrapTag(key, binding, claims, status)
		return nil, false
	}
	raw, ok := parseWebSessionResponseValue(values, webSessionBootstrapBytes)
	if !ok {
		dummyWebSessionBootstrapTag(key, binding, claims, status)
		return nil, false
	}
	var serverNonce [webAuthNonceBytes]byte
	copy(serverNonce[:], raw[1:1+webAuthNonceBytes])
	expected := calculateWebSessionBootstrapTag(key, binding, claims, status, raw[0], serverNonce)
	tagOK := subtle.ConstantTimeCompare(expected[:], raw[1+webAuthNonceBytes:]) == 1
	if raw[0] != webSessionAuthVersion || !tagOK {
		return nil, false
	}
	sessionKey, err := deriveWebSessionKey(key, claims.nonce, serverNonce)
	if err != nil {
		return nil, false
	}
	return &webSessionClientAuth{key: sessionKey, nextSequence: 1}, true
}

// authorization returns a compact Bearer credential for one continuation
// request. Allocation waits until the next sequence is within the server's
// replay window of the oldest unresolved request, not merely until there are
// fewer than 128 in-flight requests. Otherwise fast requests can continuously
// overtake a single delayed request and make its valid credential too old.
// The caller must complete the exchange after response verification or after
// canceling/abandoning the request; never release a still-live request early.
func (c *webSessionClientAuth) authorization(ctx context.Context, binding webAuthBinding) (string, webSessionExchange, error) {
	if c == nil {
		return "", webSessionExchange{}, errors.New("tunnel: nil web-cover client connection authentication")
	}
	if ctx == nil {
		return "", webSessionExchange{}, errors.New("tunnel: nil web-cover authentication context")
	}
	if err := validateWebAuthBinding(binding); err != nil {
		return "", webSessionExchange{}, err
	}

	var sequence uint64
	for {
		c.mu.Lock()
		if err := ctx.Err(); err != nil {
			c.mu.Unlock()
			return "", webSessionExchange{}, context.Cause(ctx)
		}
		if c.closed {
			c.mu.Unlock()
			return "", webSessionExchange{}, net.ErrClosed
		}
		if c.sequenceEnded || c.nextSequence == 0 {
			c.sequenceEnded = true
			c.mu.Unlock()
			return "", webSessionExchange{}, errWebSessionSequenceExhausted
		}
		if len(c.pending) == 0 || c.nextSequence-c.oldestPending < webSessionReplayWindowBits {
			sequence = c.nextSequence
			if c.pending == nil {
				c.pending = make(map[uint64]struct{})
			}
			if len(c.pending) == 0 {
				c.oldestPending = sequence
			}
			c.pending[sequence] = struct{}{}
			if sequence == ^uint64(0) {
				c.sequenceEnded = true
			} else {
				c.nextSequence++
			}
			c.mu.Unlock()
			break
		}
		if c.changed == nil {
			c.changed = make(chan struct{})
		}
		changed := c.changed
		c.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return "", webSessionExchange{}, context.Cause(ctx)
		}
	}

	exchange := webSessionExchange{sequence: sequence}
	tag := calculateWebSessionRequestTag(c.key, binding, webSessionAuthVersion, sequence)
	var raw [webSessionTicketBytes]byte
	raw[0] = webSessionAuthVersion
	binary.BigEndian.PutUint64(raw[1:9], sequence)
	copy(raw[9:], tag[:])
	return webAuthBearerPrefix + base64.RawURLEncoding.EncodeToString(raw[:]), exchange, nil
}

// complete releases only this exchange. Out-of-order completions cannot move
// the oldest unresolved sequence past a request that still needs verification.
func (c *webSessionClientAuth) complete(exchange webSessionExchange) {
	if c == nil || exchange.sequence == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.pending[exchange.sequence]; !exists {
		return
	}
	delete(c.pending, exchange.sequence)
	if exchange.sequence != c.oldestPending {
		return
	}
	c.oldestPending = 0
	for sequence := range c.pending {
		if c.oldestPending == 0 || sequence < c.oldestPending {
			c.oldestPending = sequence
		}
	}
	c.notifyLocked()
}

func (c *webSessionClientAuth) close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.closed = true
	clear(c.pending)
	c.notifyLocked()
	c.mu.Unlock()
}

func (c *webSessionClientAuth) notifyLocked() {
	if c.changed != nil {
		close(c.changed)
		c.changed = nil
	}
}

// verifyAuthorization authenticates and consumes a compact continuation
// credential. Authentication failures do not advance replay state.
func (s *webSessionServerAuth) verifyAuthorization(header string, binding webAuthBinding) (webSessionExchange, bool) {
	if s == nil {
		return webSessionExchange{}, false
	}
	if err := validateWebAuthBinding(binding); err != nil {
		dummyWebSessionRequestTag(s.key, binding)
		return webSessionExchange{}, false
	}
	raw, ok := parseWebSessionBearer(header)
	if !ok {
		dummyWebSessionRequestTag(s.key, binding)
		return webSessionExchange{}, false
	}
	sequence := binary.BigEndian.Uint64(raw[1:9])
	expected := calculateWebSessionRequestTag(s.key, binding, raw[0], sequence)
	tagOK := subtle.ConstantTimeCompare(expected[:], raw[9:]) == 1
	if raw[0] != webSessionAuthVersion || sequence == 0 || !tagOK {
		return webSessionExchange{}, false
	}
	if !s.replay.accept(sequence) {
		return webSessionExchange{}, false
	}
	return webSessionExchange{sequence: sequence}, true
}

// bootstrapClaims returns the pacing metadata authenticated by the full
// request that established this physical connection's session.
func (s *webSessionServerAuth) bootstrapClaims() webAuthClaims {
	if s == nil {
		return webAuthClaims{}
	}
	return s.sessionClaims
}

// responseProof returns the compact proof for one continuation response.
func (s *webSessionServerAuth) responseProof(binding webAuthBinding, exchange webSessionExchange, status int) string {
	if s == nil || validateWebAuthBinding(binding) != nil || !validWebSessionStatus(status) || exchange.sequence == 0 {
		return ""
	}
	tag := calculateWebSessionResponseTag(s.key, binding, webSessionAuthVersion, exchange.sequence, status)
	var raw [webSessionResponseBytes]byte
	raw[0] = webSessionAuthVersion
	binary.BigEndian.PutUint64(raw[1:9], exchange.sequence)
	copy(raw[9:], tag[:])
	return webAuthResponseParameter + base64.RawURLEncoding.EncodeToString(raw[:])
}

// verifyResponseProof authenticates the HTTP response corresponding to one
// continuation request.
func (c *webSessionClientAuth) verifyResponseProof(
	values []string,
	binding webAuthBinding,
	exchange webSessionExchange,
	status int,
) bool {
	if c == nil {
		return false
	}
	validInput := validateWebAuthBinding(binding) == nil && validWebSessionStatus(status) && exchange.sequence != 0
	raw, parsed := parseWebSessionResponseValue(values, webSessionResponseBytes)
	if !parsed {
		dummyWebSessionResponseTag(c.key, binding, exchange.sequence, status)
		return false
	}
	sequence := binary.BigEndian.Uint64(raw[1:9])
	expected := calculateWebSessionResponseTag(c.key, binding, raw[0], sequence, status)
	tagOK := subtle.ConstantTimeCompare(expected[:], raw[9:]) == 1
	return validInput && raw[0] == webSessionAuthVersion && sequence == exchange.sequence && tagOK
}

func deriveWebSessionKey(
	key webAuthKey,
	clientNonce [webAuthNonceBytes]byte,
	serverNonce [webAuthNonceBytes]byte,
) (webSessionKey, error) {
	var result webSessionKey
	var salt [webAuthNonceBytes * 2]byte
	copy(salt[:webAuthNonceBytes], clientNonce[:])
	copy(salt[webAuthNonceBytes:], serverNonce[:])
	derived, err := hkdf.Key(sha256.New, key[:], salt[:], webSessionKeyInfo, len(result))
	if err != nil {
		return result, fmt.Errorf("tunnel: derive web-cover connection authentication key: %w", err)
	}
	copy(result[:], derived)
	clear(derived)
	return result, nil
}

func calculateWebSessionBootstrapTag(
	key webAuthKey,
	binding webAuthBinding,
	claims webAuthClaims,
	status int,
	version byte,
	serverNonce [webAuthNonceBytes]byte,
) [webSessionTagBytes]byte {
	mac := hmac.New(sha256.New, key[:])
	writeWebAuthField(mac, webSessionBootstrapLabel)
	writeWebAuthClaimsTranscript(mac, binding, claims)
	writeWebSessionStatus(mac, status)
	_, _ = mac.Write([]byte{version})
	_, _ = mac.Write(serverNonce[:])
	return truncateWebSessionTag(mac)
}

func calculateWebSessionRequestTag(
	key webSessionKey,
	binding webAuthBinding,
	version byte,
	sequence uint64,
) [webSessionTagBytes]byte {
	mac := hmac.New(sha256.New, key[:])
	writeWebAuthField(mac, webSessionRequestLabel)
	writeWebSessionBinding(mac, binding)
	_, _ = mac.Write([]byte{version})
	writeWebSessionSequence(mac, sequence)
	return truncateWebSessionTag(mac)
}

func calculateWebSessionResponseTag(
	key webSessionKey,
	binding webAuthBinding,
	version byte,
	sequence uint64,
	status int,
) [webSessionTagBytes]byte {
	mac := hmac.New(sha256.New, key[:])
	writeWebAuthField(mac, webSessionResponseLabel)
	writeWebSessionBinding(mac, binding)
	_, _ = mac.Write([]byte{version})
	writeWebSessionSequence(mac, sequence)
	writeWebSessionStatus(mac, status)
	return truncateWebSessionTag(mac)
}

func writeWebSessionBinding(dst io.Writer, binding webAuthBinding) {
	writeWebAuthField(dst, binding.transport)
	writeWebAuthField(dst, binding.method)
	writeWebAuthField(dst, binding.protocol)
	writeWebAuthField(dst, binding.authority)
	writeWebAuthField(dst, binding.path)
}

func writeWebSessionSequence(dst io.Writer, sequence uint64) {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], sequence)
	_, _ = dst.Write(raw[:])
}

func writeWebSessionStatus(dst io.Writer, status int) {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], uint32(status))
	_, _ = dst.Write(raw[:])
}

func truncateWebSessionTag(mac hashSum) [webSessionTagBytes]byte {
	full := mac.Sum(nil)
	var result [webSessionTagBytes]byte
	copy(result[:], full[:webSessionTagBytes])
	clear(full)
	return result
}

// hashSum is the portion of hash.Hash needed after a transcript is written.
// The small interface keeps the truncation helper testable without exporting
// any session-auth implementation type.
type hashSum interface {
	Sum([]byte) []byte
}

func parseWebSessionBearer(header string) ([]byte, bool) {
	encodedBytes := base64.RawURLEncoding.EncodedLen(webSessionTicketBytes)
	if len(header) != len(webAuthBearerPrefix)+encodedBytes ||
		!strings.EqualFold(header[:len("Bearer")], "Bearer") ||
		header[len("Bearer")] != ' ' {
		return nil, false
	}
	var raw [webSessionTicketBytes]byte
	encoded := header[len(webAuthBearerPrefix):]
	n, err := base64.RawURLEncoding.Strict().Decode(raw[:], []byte(encoded))
	if err != nil || n != len(raw) || base64.RawURLEncoding.EncodedLen(n) != len(encoded) {
		return nil, false
	}
	return raw[:], true
}

func parseWebSessionResponseValue(values []string, rawBytes int) ([]byte, bool) {
	if len(values) != 1 {
		return nil, false
	}
	encodedBytes := base64.RawURLEncoding.EncodedLen(rawBytes)
	value := values[0]
	if len(value) != len(webAuthResponseParameter)+encodedBytes ||
		!strings.HasPrefix(value, webAuthResponseParameter) {
		return nil, false
	}
	raw := make([]byte, rawBytes)
	encoded := value[len(webAuthResponseParameter):]
	n, err := base64.RawURLEncoding.Strict().Decode(raw, []byte(encoded))
	if err != nil || n != len(raw) || base64.RawURLEncoding.EncodedLen(n) != len(encoded) {
		return nil, false
	}
	return raw, true
}

func validateWebSessionBootstrapInput(binding webAuthBinding, claims webAuthClaims, status int) error {
	if err := validateWebAuthBinding(binding); err != nil {
		return err
	}
	if err := validateWebAuthClaims(claims); err != nil {
		return err
	}
	if claims.timestamp < 0 {
		return fmt.Errorf("%w: invalid bootstrap timestamp", errInvalidWebAuthConfig)
	}
	if !validWebSessionStatus(status) {
		return fmt.Errorf("%w: invalid HTTP status", errInvalidWebAuthConfig)
	}
	return nil
}

func validWebSessionStatus(status int) bool {
	return status >= http.StatusContinue && status <= 999
}

func dummyWebSessionBootstrapTag(key webAuthKey, binding webAuthBinding, claims webAuthClaims, status int) {
	tag := calculateWebSessionBootstrapTag(key, binding, claims, status, webSessionAuthVersion, [webAuthNonceBytes]byte{})
	var zero [webSessionTagBytes]byte
	_ = subtle.ConstantTimeCompare(tag[:], zero[:])
}

func dummyWebSessionRequestTag(key webSessionKey, binding webAuthBinding) {
	tag := calculateWebSessionRequestTag(key, binding, webSessionAuthVersion, 0)
	var zero [webSessionTagBytes]byte
	_ = subtle.ConstantTimeCompare(tag[:], zero[:])
}

func dummyWebSessionResponseTag(key webSessionKey, binding webAuthBinding, sequence uint64, status int) {
	tag := calculateWebSessionResponseTag(key, binding, webSessionAuthVersion, sequence, status)
	var zero [webSessionTagBytes]byte
	_ = subtle.ConstantTimeCompare(tag[:], zero[:])
}

func (w *webSessionReplayWindow) accept(sequence uint64) bool {
	if sequence == 0 {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.highest == 0 {
		w.highest = sequence
		w.seen[0] = 1
		return true
	}
	if sequence > w.highest {
		w.shift(sequence - w.highest)
		w.highest = sequence
		w.seen[0] |= 1
		return true
	}

	distance := w.highest - sequence
	if distance >= webSessionReplayWindowBits {
		return false
	}
	word := distance / 64
	bit := uint(distance % 64)
	mask := uint64(1) << bit
	if w.seen[word]&mask != 0 {
		return false
	}
	w.seen[word] |= mask
	return true
}

func (w *webSessionReplayWindow) shift(distance uint64) {
	switch {
	case distance >= webSessionReplayWindowBits:
		w.seen = [2]uint64{}
	case distance >= 64:
		w.seen[1] = w.seen[0] << (distance - 64)
		w.seen[0] = 0
	case distance > 0:
		w.seen[1] = w.seen[1]<<distance | w.seen[0]>>(64-distance)
		w.seen[0] <<= distance
	}
}
