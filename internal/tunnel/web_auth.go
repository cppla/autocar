package tunnel

import (
	"container/heap"
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
	"strings"
	"sync"
	"time"

	"github.com/cppla/autocar/internal/protocol"
)

const (
	webAuthVersion                     byte = 1
	webAuthTransportH2                      = "h2"
	webAuthTransportH3                      = "h3"
	webAuthBearerPrefix                     = "Bearer "
	webAuthKeyInfo                          = "autocar web-cover auth v1"
	webAuthTranscriptLabel                  = "autocar web-cover request v1"
	webAuthResponseLabel                    = "autocar web-cover response v1"
	webAuthResponsePaddingLengthLabel       = "autocar web-cover response padding length v1"
	webAuthResponsePaddingContentLabel      = "autocar web-cover response padding content v1"
	webAuthResponseHeader                   = "Proxy-Authentication-Info"
	webAuthResponseParameter                = "nextnonce="
	webAuthResponsePaddingParameter         = ", padding="

	webAuthTimestampBytes = 8
	webAuthNonceBytes     = 16
	webAuthMACBytes       = sha256.Size

	webAuthTimestampOffset  = 1
	webAuthNonceOffset      = webAuthTimestampOffset + webAuthTimestampBytes
	webAuthModeOffset       = webAuthNonceOffset + webAuthNonceBytes
	webAuthProfileOffset    = webAuthModeOffset + 1
	webAuthMaxTxOffset      = webAuthProfileOffset + 1
	webAuthMaxRxOffset      = webAuthMaxTxOffset + 8
	webAuthPaddingLenOffset = webAuthMaxRxOffset + 8
	webAuthPaddingOffset    = webAuthPaddingLenOffset + 2

	// The resulting Proxy-Authorization value ranges from 385 through 2047
	// bytes. Together with the pseudo-headers and ordinary request fields this
	// covers realistic requests from several hundred bytes to roughly 2 KiB,
	// while retaining a small, explicit parser allocation bound.
	webAuthMinPaddingBytes = 206
	webAuthMaxPaddingBytes = 1453
	webAuthMinTicketBytes  = webAuthPaddingOffset + webAuthMinPaddingBytes + webAuthMACBytes
	webAuthMaxTicketBytes  = webAuthPaddingOffset + webAuthMaxPaddingBytes + webAuthMACBytes

	// A response proof has two standard auth-params: nextnonce carries the MAC
	// and padding carries a deterministic, pseudorandom token. These raw padding
	// limits produce response values from 385 through 2047 bytes.
	webAuthMinResponsePaddingBytes   = 241
	webAuthMaxResponsePaddingBytes   = 1488
	webAuthDummyRequestPaddingBytes  = (webAuthMinPaddingBytes + webAuthMaxPaddingBytes) / 2
	webAuthDummyResponsePaddingBytes = (webAuthMinResponsePaddingBytes + webAuthMaxResponsePaddingBytes) / 2

	webAuthClockSkewSeconds     int64 = 60
	defaultWebAuthReplayEntries       = 64 * 1024
	maxWebAuthReplayEntries           = 1024 * 1024

	webAuthMaxMethodBytes    = 64
	webAuthMaxProtocolBytes  = 64
	webAuthMaxAuthorityBytes = protocol.MaxAddressLength
	webAuthMaxPathBytes      = 8 * 1024
)

var errInvalidWebAuthConfig = errors.New("tunnel: invalid web-cover authentication configuration")

var (
	webAuthDummyRequestPadding  [webAuthDummyRequestPaddingBytes]byte
	webAuthDummyResponsePadding [webAuthDummyResponsePaddingBytes]byte
)

// webAuthKey is derived from the configured shared token and is used only for
// web-cover request credentials. Native protocol authentication never reuses
// this key.
type webAuthKey [sha256.Size]byte

// webAuthBinding contains every HTTP property covered by a request ticket.
// Callers must pass the exact normalized values that are sent on the wire and
// later used by the authenticated handler.
type webAuthBinding struct {
	transport string
	method    string
	protocol  string
	authority string
	path      string
}

// webAuthClaims is the fixed-size metadata carried by a request ticket.
// bearer overwrites timestamp and nonce; callers supply only pacing metadata.
type webAuthClaims struct {
	timestamp int64
	nonce     [webAuthNonceBytes]byte
	mode      protocol.PacingMode
	profile   protocol.PacingProfile
	maxTx     uint64
	maxRx     uint64
}

type webAuthSigner struct {
	key    webAuthKey
	now    func() time.Time
	random io.Reader

	// Protect arbitrary injected nonce readers as well as the timestamp/nonce
	// pair so one signer remains safe when concurrent streams are opened.
	mu sync.Mutex
}

// webAuthVerifier owns a bounded, server-wide nonce cache. A valid nonce stays
// present until its complete acceptance window has elapsed. At capacity the
// verifier fails closed instead of evicting a still-valid nonce.
type webAuthVerifier struct {
	key        webAuthKey
	now        func() time.Time
	maxEntries int

	mu     sync.Mutex
	nonces map[[webAuthNonceBytes]byte]int64
	expiry webAuthReplayHeap
}

type webAuthReplayEntry struct {
	nonce   [webAuthNonceBytes]byte
	expires int64
}

type webAuthReplayHeap []webAuthReplayEntry

func (h webAuthReplayHeap) Len() int           { return len(h) }
func (h webAuthReplayHeap) Less(i, j int) bool { return h[i].expires < h[j].expires }
func (h webAuthReplayHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *webAuthReplayHeap) Push(value any)    { *h = append(*h, value.(webAuthReplayEntry)) }
func (h *webAuthReplayHeap) Pop() any {
	old := *h
	last := len(old) - 1
	value := old[last]
	old[last] = webAuthReplayEntry{}
	*h = old[:last]
	return value
}

func deriveWebAuthKey(token string) (webAuthKey, error) {
	var key webAuthKey
	if len(token) < protocol.MinTokenLength || len(token) > protocol.MaxTokenLength {
		return key, fmt.Errorf(
			"%w: token length must be between %d and %d bytes",
			errInvalidWebAuthConfig,
			protocol.MinTokenLength,
			protocol.MaxTokenLength,
		)
	}
	derived, err := hkdf.Key(sha256.New, []byte(token), nil, webAuthKeyInfo, len(key))
	if err != nil {
		return key, fmt.Errorf("%w: derive key: %v", errInvalidWebAuthConfig, err)
	}
	copy(key[:], derived)
	clear(derived)
	return key, nil
}

func newWebAuthSigner(key webAuthKey, now func() time.Time, random io.Reader) *webAuthSigner {
	if now == nil {
		now = time.Now
	}
	if random == nil {
		random = rand.Reader
	}
	return &webAuthSigner{key: key, now: now, random: random}
}

func newWebAuthVerifier(key webAuthKey, now func() time.Time, replayLimit int) (*webAuthVerifier, error) {
	if replayLimit < 0 || replayLimit > maxWebAuthReplayEntries {
		return nil, fmt.Errorf(
			"%w: replay limit must be between 0 and %d",
			errInvalidWebAuthConfig,
			maxWebAuthReplayEntries,
		)
	}
	if replayLimit == 0 {
		replayLimit = defaultWebAuthReplayEntries
	}
	if now == nil {
		now = time.Now
	}
	return &webAuthVerifier{
		key:        key,
		now:        now,
		maxEntries: replayLimit,
		nonces:     make(map[[webAuthNonceBytes]byte]int64),
	}, nil
}

// bearer returns the complete Proxy-Authorization value. RawURLEncoding keeps
// the credential inside token68 while the authenticated random padding gives
// independently opened streams a bounded, variable request-header length.
func (s *webAuthSigner) bearer(binding webAuthBinding, claims webAuthClaims) (string, error) {
	header, _, err := s.authorization(binding, claims)
	return header, err
}

// authorization returns both the wire credential and the generated claims.
// The claims are retained by clients to authenticate the corresponding HTTP
// response before exposing the stream to an application.
func (s *webAuthSigner) authorization(binding webAuthBinding, claims webAuthClaims) (string, webAuthClaims, error) {
	if err := validateWebAuthBinding(binding); err != nil {
		return "", webAuthClaims{}, err
	}
	if err := validateWebAuthClaims(claims); err != nil {
		return "", webAuthClaims{}, err
	}

	s.mu.Lock()
	now := s.now().Unix()
	if now < 0 {
		s.mu.Unlock()
		return "", webAuthClaims{}, fmt.Errorf("%w: clock is before the Unix epoch", errInvalidWebAuthConfig)
	}
	claims.timestamp = now
	_, err := io.ReadFull(s.random, claims.nonce[:])
	if err != nil {
		s.mu.Unlock()
		return "", webAuthClaims{}, fmt.Errorf("tunnel: generate web-cover authentication nonce: %w", err)
	}
	paddingLength, err := sampleWebAuthPaddingLength(s.random)
	if err != nil {
		s.mu.Unlock()
		return "", webAuthClaims{}, fmt.Errorf("tunnel: choose web-cover authentication padding length: %w", err)
	}
	padding := make([]byte, paddingLength)
	_, err = io.ReadFull(s.random, padding)
	s.mu.Unlock()
	if err != nil {
		return "", webAuthClaims{}, fmt.Errorf("tunnel: generate web-cover authentication padding: %w", err)
	}

	mac := calculateWebAuthMAC(s.key, binding, claims, webAuthVersion, padding)
	macOffset := webAuthPaddingOffset + len(padding)
	ticket := make([]byte, macOffset+webAuthMACBytes)
	ticket[0] = webAuthVersion
	binary.BigEndian.PutUint64(ticket[webAuthTimestampOffset:webAuthNonceOffset], uint64(claims.timestamp))
	copy(ticket[webAuthNonceOffset:webAuthModeOffset], claims.nonce[:])
	ticket[webAuthModeOffset] = byte(claims.mode)
	ticket[webAuthProfileOffset] = byte(claims.profile)
	binary.BigEndian.PutUint64(ticket[webAuthMaxTxOffset:webAuthMaxRxOffset], claims.maxTx)
	binary.BigEndian.PutUint64(ticket[webAuthMaxRxOffset:webAuthPaddingLenOffset], claims.maxRx)
	binary.BigEndian.PutUint16(ticket[webAuthPaddingLenOffset:webAuthPaddingOffset], uint16(len(padding)))
	copy(ticket[webAuthPaddingOffset:macOffset], padding)
	copy(ticket[macOffset:], mac[:])

	return webAuthBearerPrefix + base64.RawURLEncoding.EncodeToString(ticket), claims, nil
}

func webAuthResponseProof(key webAuthKey, binding webAuthBinding, claims webAuthClaims, status int) string {
	padding := deriveWebAuthResponsePadding(key, binding, claims, status)
	proof := calculateWebAuthResponseMAC(key, binding, claims, status, padding)
	// Proxy-Authentication-Info uses the RFC 9110 auth-param grammar, not a
	// bare token68. Both values use the token-safe base64url alphabet.
	return webAuthResponseParameter + base64.RawURLEncoding.EncodeToString(proof[:]) +
		webAuthResponsePaddingParameter + base64.RawURLEncoding.EncodeToString(padding)
}

func verifyWebAuthResponseProof(key webAuthKey, values []string, binding webAuthBinding, claims webAuthClaims, status int) bool {
	presented, padding, ok := parseWebAuthResponseProof(values)
	if !ok {
		dummy := calculateWebAuthResponseMAC(key, binding, claims, status, webAuthDummyResponsePadding[:])
		var zero [webAuthMACBytes]byte
		_ = subtle.ConstantTimeCompare(dummy[:], zero[:])
		return false
	}
	expected := calculateWebAuthResponseMAC(key, binding, claims, status, padding)
	return subtle.ConstantTimeCompare(expected[:], presented[:]) == 1
}

func parseWebAuthResponseProof(values []string) ([webAuthMACBytes]byte, []byte, bool) {
	var presented [webAuthMACBytes]byte
	if len(values) != 1 {
		return presented, nil, false
	}
	macEncodedBytes := base64.RawURLEncoding.EncodedLen(webAuthMACBytes)
	minBytes := len(webAuthResponseParameter) + macEncodedBytes + len(webAuthResponsePaddingParameter) +
		base64.RawURLEncoding.EncodedLen(webAuthMinResponsePaddingBytes)
	maxBytes := len(webAuthResponseParameter) + macEncodedBytes + len(webAuthResponsePaddingParameter) +
		base64.RawURLEncoding.EncodedLen(webAuthMaxResponsePaddingBytes)
	value := values[0]
	if len(value) < minBytes || len(value) > maxBytes || !strings.HasPrefix(value, webAuthResponseParameter) {
		return presented, nil, false
	}
	macStart := len(webAuthResponseParameter)
	macEnd := macStart + macEncodedBytes
	paddingStart := macEnd + len(webAuthResponsePaddingParameter)
	if value[macEnd:paddingStart] != webAuthResponsePaddingParameter {
		return presented, nil, false
	}
	if n, err := base64.RawURLEncoding.Strict().Decode(presented[:], []byte(value[macStart:macEnd])); err != nil || n != len(presented) {
		return [webAuthMACBytes]byte{}, nil, false
	}
	paddingEncoded := value[paddingStart:]
	decodedLength := base64.RawURLEncoding.DecodedLen(len(paddingEncoded))
	if decodedLength > webAuthMaxResponsePaddingBytes {
		return [webAuthMACBytes]byte{}, nil, false
	}
	padding := make([]byte, decodedLength)
	n, err := base64.RawURLEncoding.Strict().Decode(padding, []byte(paddingEncoded))
	if err != nil || n < webAuthMinResponsePaddingBytes || n > webAuthMaxResponsePaddingBytes ||
		base64.RawURLEncoding.EncodedLen(n) != len(paddingEncoded) {
		return [webAuthMACBytes]byte{}, nil, false
	}
	return presented, padding[:n], true
}

// verifyBearer verifies a complete Proxy-Authorization value and records its
// nonce. Every failure has the same public result; handlers must delegate that
// request to the configured cover instead of returning an authentication error.
func (v *webAuthVerifier) verifyBearer(header string, binding webAuthBinding) (webAuthClaims, bool) {
	var zero webAuthClaims
	if err := validateWebAuthBinding(binding); err != nil {
		v.dummyHMAC()
		return zero, false
	}

	minEncodedBytes := base64.RawURLEncoding.EncodedLen(webAuthMinTicketBytes)
	maxEncodedBytes := base64.RawURLEncoding.EncodedLen(webAuthMaxTicketBytes)
	if len(header) < len(webAuthBearerPrefix)+minEncodedBytes ||
		len(header) > len(webAuthBearerPrefix)+maxEncodedBytes {
		v.dummyHMACFor(binding)
		return zero, false
	}
	if !strings.EqualFold(header[:len("Bearer")], "Bearer") || header[len("Bearer")] != ' ' {
		v.dummyHMACFor(binding)
		return zero, false
	}
	encoded := header[len(webAuthBearerPrefix):]
	if base64.RawURLEncoding.DecodedLen(len(encoded)) > webAuthMaxTicketBytes {
		v.dummyHMACFor(binding)
		return zero, false
	}
	var ticketStorage [webAuthMaxTicketBytes]byte
	ticket := ticketStorage[:]
	n, err := base64.RawURLEncoding.Strict().Decode(ticket[:], []byte(encoded))
	if err != nil || n < webAuthMinTicketBytes || n > webAuthMaxTicketBytes ||
		base64.RawURLEncoding.EncodedLen(n) != len(encoded) {
		v.dummyHMACFor(binding)
		return zero, false
	}
	ticket = ticket[:n]
	paddingLength := int(binary.BigEndian.Uint16(ticket[webAuthPaddingLenOffset:webAuthPaddingOffset]))
	macOffset := webAuthPaddingOffset + paddingLength
	if paddingLength < webAuthMinPaddingBytes || paddingLength > webAuthMaxPaddingBytes ||
		macOffset+webAuthMACBytes != len(ticket) {
		v.dummyHMACFor(binding)
		return zero, false
	}

	claims := webAuthClaims{
		timestamp: int64(binary.BigEndian.Uint64(ticket[webAuthTimestampOffset:webAuthNonceOffset])),
		mode:      protocol.PacingMode(ticket[webAuthModeOffset]),
		profile:   protocol.PacingProfile(ticket[webAuthProfileOffset]),
		maxTx:     binary.BigEndian.Uint64(ticket[webAuthMaxTxOffset:webAuthMaxRxOffset]),
		maxRx:     binary.BigEndian.Uint64(ticket[webAuthMaxRxOffset:webAuthPaddingLenOffset]),
	}
	copy(claims.nonce[:], ticket[webAuthNonceOffset:webAuthModeOffset])

	expectedMAC := calculateWebAuthMAC(v.key, binding, claims, ticket[0], ticket[webAuthPaddingOffset:macOffset])
	macOK := subtle.ConstantTimeCompare(expectedMAC[:], ticket[macOffset:]) == 1
	now := v.now().Unix()
	valid := ticket[0] == webAuthVersion &&
		validateWebAuthClaims(claims) == nil &&
		webAuthTimestampAccepted(now, claims.timestamp) &&
		macOK
	if !valid {
		return zero, false
	}
	if !v.acceptNonce(claims.nonce, claims.timestamp, now) {
		return zero, false
	}
	return claims, true
}

func validateWebAuthBinding(binding webAuthBinding) error {
	if binding.transport != webAuthTransportH2 && binding.transport != webAuthTransportH3 {
		return fmt.Errorf("%w: transport must be h2 or h3", errInvalidWebAuthConfig)
	}
	if len(binding.method) == 0 || len(binding.method) > webAuthMaxMethodBytes || hasInvalidWebAuthText(binding.method) {
		return fmt.Errorf("%w: invalid method", errInvalidWebAuthConfig)
	}
	if len(binding.protocol) > webAuthMaxProtocolBytes || hasInvalidWebAuthText(binding.protocol) {
		return fmt.Errorf("%w: invalid protocol", errInvalidWebAuthConfig)
	}
	if len(binding.authority) == 0 || len(binding.authority) > webAuthMaxAuthorityBytes || hasInvalidWebAuthText(binding.authority) {
		return fmt.Errorf("%w: invalid authority", errInvalidWebAuthConfig)
	}
	if len(binding.path) > webAuthMaxPathBytes || hasInvalidWebAuthText(binding.path) {
		return fmt.Errorf("%w: invalid path", errInvalidWebAuthConfig)
	}
	return nil
}

func hasInvalidWebAuthText(value string) bool {
	return strings.ContainsAny(value, "\x00\r\n")
}

func validateWebAuthClaims(claims webAuthClaims) error {
	if claims.mode > protocol.PacingFixedRate || claims.profile > protocol.ProfileAggressive {
		return fmt.Errorf("%w: invalid pacing metadata", errInvalidWebAuthConfig)
	}
	if claims.maxTx > protocol.MaxRate || claims.maxRx > protocol.MaxRate {
		return fmt.Errorf("%w: pacing rate exceeds protocol maximum", errInvalidWebAuthConfig)
	}
	return nil
}

func calculateWebAuthMAC(
	key webAuthKey,
	binding webAuthBinding,
	claims webAuthClaims,
	version byte,
	padding []byte,
) [webAuthMACBytes]byte {
	mac := hmac.New(sha256.New, key[:])
	writeWebAuthClaimsTranscript(mac, binding, claims)
	_, _ = mac.Write([]byte{version})
	var paddingLength [2]byte
	binary.BigEndian.PutUint16(paddingLength[:], uint16(len(padding)))
	_, _ = mac.Write(paddingLength[:])
	_, _ = mac.Write(padding)

	var result [webAuthMACBytes]byte
	mac.Sum(result[:0])
	return result
}

// calculateWebAuthClaimsMAC retains the response-proof transcript semantics:
// it binds every authenticated request property and claim, while request
// ticket verification separately authenticates the variable padding above.
func calculateWebAuthClaimsMAC(key webAuthKey, binding webAuthBinding, claims webAuthClaims) [webAuthMACBytes]byte {
	mac := hmac.New(sha256.New, key[:])
	writeWebAuthClaimsTranscript(mac, binding, claims)
	var result [webAuthMACBytes]byte
	mac.Sum(result[:0])
	return result
}

func writeWebAuthClaimsTranscript(mac io.Writer, binding webAuthBinding, claims webAuthClaims) {
	writeWebAuthField(mac, webAuthTranscriptLabel)
	writeWebAuthField(mac, binding.transport)
	writeWebAuthField(mac, binding.method)
	writeWebAuthField(mac, binding.protocol)
	writeWebAuthField(mac, binding.authority)
	writeWebAuthField(mac, binding.path)

	var fixed [webAuthTimestampBytes + webAuthNonceBytes + 1 + 1 + 8 + 8]byte
	binary.BigEndian.PutUint64(fixed[0:8], uint64(claims.timestamp))
	copy(fixed[8:8+webAuthNonceBytes], claims.nonce[:])
	fixed[8+webAuthNonceBytes] = byte(claims.mode)
	fixed[8+webAuthNonceBytes+1] = byte(claims.profile)
	binary.BigEndian.PutUint64(fixed[8+webAuthNonceBytes+2:8+webAuthNonceBytes+10], claims.maxTx)
	binary.BigEndian.PutUint64(fixed[8+webAuthNonceBytes+10:], claims.maxRx)
	_, _ = mac.Write(fixed[:])
}

func calculateWebAuthResponseMAC(
	key webAuthKey,
	binding webAuthBinding,
	claims webAuthClaims,
	status int,
	padding []byte,
) [webAuthMACBytes]byte {
	mac := hmac.New(sha256.New, key[:])
	writeWebAuthField(mac, webAuthResponseLabel)
	requestMAC := calculateWebAuthClaimsMAC(key, binding, claims)
	_, _ = mac.Write(requestMAC[:])
	var statusBytes [4]byte
	binary.BigEndian.PutUint32(statusBytes[:], uint32(status))
	_, _ = mac.Write(statusBytes[:])
	var paddingLength [2]byte
	binary.BigEndian.PutUint16(paddingLength[:], uint16(len(padding)))
	_, _ = mac.Write(paddingLength[:])
	_, _ = mac.Write(padding)
	var result [webAuthMACBytes]byte
	mac.Sum(result[:0])
	return result
}

func writeWebAuthField(dst io.Writer, value string) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	_, _ = dst.Write(size[:])
	_, _ = io.WriteString(dst, value)
}

func deriveWebAuthResponsePadding(key webAuthKey, binding webAuthBinding, claims webAuthClaims, status int) []byte {
	requestMAC := calculateWebAuthClaimsMAC(key, binding, claims)
	lengthSeed := calculateWebAuthResponsePaddingBlock(
		key,
		webAuthResponsePaddingLengthLabel,
		requestMAC,
		status,
		0,
	)
	const sampleCount = webAuthMaxResponsePaddingBytes - webAuthMinResponsePaddingBytes + 1
	first := scaleWebAuthUint32(binary.BigEndian.Uint32(lengthSeed[0:4]), sampleCount)
	second := scaleWebAuthUint32(binary.BigEndian.Uint32(lengthSeed[4:8]), sampleCount)
	paddingLength := webAuthMinResponsePaddingBytes + (first+second)/2

	padding := make([]byte, paddingLength)
	for offset, counter := 0, uint32(0); offset < len(padding); counter++ {
		block := calculateWebAuthResponsePaddingBlock(
			key,
			webAuthResponsePaddingContentLabel,
			requestMAC,
			status,
			counter,
		)
		offset += copy(padding[offset:], block[:])
	}
	return padding
}

func calculateWebAuthResponsePaddingBlock(
	key webAuthKey,
	label string,
	requestMAC [webAuthMACBytes]byte,
	status int,
	counter uint32,
) [webAuthMACBytes]byte {
	mac := hmac.New(sha256.New, key[:])
	writeWebAuthField(mac, label)
	_, _ = mac.Write(requestMAC[:])
	var fixed [8]byte
	binary.BigEndian.PutUint32(fixed[0:4], uint32(status))
	binary.BigEndian.PutUint32(fixed[4:8], counter)
	_, _ = mac.Write(fixed[:])
	var result [webAuthMACBytes]byte
	mac.Sum(result[:0])
	return result
}

func scaleWebAuthUint32(value uint32, size int) int {
	return int(uint64(value) * uint64(size) >> 32)
}

func webAuthTimestampAccepted(now, timestamp int64) bool {
	if now < 0 || timestamp < 0 {
		return false
	}
	if timestamp >= now {
		return timestamp-now <= webAuthClockSkewSeconds
	}
	return now-timestamp <= webAuthClockSkewSeconds
}

// sampleWebAuthPaddingLength averages two independent uniform samples. The
// resulting near-triangular distribution favors ordinary middle-sized
// requests without losing the explicitly reachable minimum and maximum.
func sampleWebAuthPaddingLength(random io.Reader) (int, error) {
	const sampleCount = webAuthMaxPaddingBytes - webAuthMinPaddingBytes + 1
	first, err := sampleWebAuthUniform16(random, sampleCount)
	if err != nil {
		return 0, err
	}
	second, err := sampleWebAuthUniform16(random, sampleCount)
	if err != nil {
		return 0, err
	}
	return webAuthMinPaddingBytes + (first+second)/2, nil
}

// sampleWebAuthUniform16 uses rejection sampling to avoid modulo bias. size is
// deliberately bounded by the uint16 source domain and is a compile-time
// property of the ticket limits above.
func sampleWebAuthUniform16(random io.Reader, size int) (int, error) {
	const sourceValues = 1 << 16
	limit := sourceValues - sourceValues%size
	var sample [2]byte
	for {
		if _, err := io.ReadFull(random, sample[:]); err != nil {
			return 0, err
		}
		value := int(binary.BigEndian.Uint16(sample[:]))
		if value < limit {
			return value % size, nil
		}
	}
}

func (v *webAuthVerifier) acceptNonce(nonce [webAuthNonceBytes]byte, timestamp, now int64) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	for len(v.expiry) != 0 && now > v.expiry[0].expires {
		expired := heap.Pop(&v.expiry).(webAuthReplayEntry)
		delete(v.nonces, expired.nonce)
	}
	if _, replayed := v.nonces[nonce]; replayed {
		return false
	}
	if len(v.nonces) >= v.maxEntries {
		return false
	}
	maxInt64 := int64(^uint64(0) >> 1)
	expires := maxInt64
	if timestamp <= maxInt64-webAuthClockSkewSeconds {
		expires = timestamp + webAuthClockSkewSeconds
	}
	v.nonces[nonce] = expires
	heap.Push(&v.expiry, webAuthReplayEntry{nonce: nonce, expires: expires})
	return true
}

func (v *webAuthVerifier) dummyHMACFor(binding webAuthBinding) {
	dummy := calculateWebAuthMAC(
		v.key,
		binding,
		webAuthClaims{},
		webAuthVersion,
		webAuthDummyRequestPadding[:],
	)
	var presented [webAuthMACBytes]byte
	_ = subtle.ConstantTimeCompare(dummy[:], presented[:])
}

func (v *webAuthVerifier) dummyHMAC() {
	v.dummyHMACFor(webAuthBinding{
		transport: webAuthTransportH2,
		method:    "CONNECT",
		authority: "invalid.invalid:443",
	})
}
