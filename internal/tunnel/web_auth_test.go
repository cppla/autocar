package tunnel

import (
	"bytes"
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"
	mathrand "math/rand"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/protocol"
)

const webAuthTestToken = "0123456789abcdef0123456789abcdef"

var webAuthTestBinding = webAuthBinding{
	transport: webAuthTransportH3,
	method:    "CONNECT",
	authority: "example.com:443",
}

func TestWebAuthDerivedKeyAndRoundTrip(t *testing.T) {
	key := mustWebAuthKey(t, webAuthTestToken)
	wantKey, err := hex.DecodeString("0c1cb31c87c4b1d2ea5044ba6d7a6a19904b6cca8d561d186a9d2e7b3365245c")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key[:], wantKey) {
		t.Fatalf("derived key = %x, want %x", key, wantKey)
	}

	now := time.Unix(1_700_000_000, 987_654_321)
	nonce := make([]byte, webAuthNonceBytes)
	for index := range nonce {
		nonce[index] = byte(index)
	}
	padding := bytes.Repeat([]byte{0xa5}, webAuthMinPaddingBytes)
	signer := newWebAuthSigner(
		key,
		func() time.Time { return now },
		bytes.NewReader(webAuthTestEntropy(nonce, 0, 0, padding)),
	)
	wantClaims := webAuthClaims{
		mode:    protocol.PacingAdaptive,
		profile: protocol.ProfileBalanced,
		maxTx:   125_000,
		maxRx:   250_000,
	}
	header, err := signer.bearer(webAuthTestBinding, wantClaims)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(header, "=") || len(header) != len(webAuthBearerPrefix)+base64.RawURLEncoding.EncodedLen(webAuthMinTicketBytes) {
		t.Fatalf("minimum credential has unexpected base64url shape: length=%d", len(header))
	}
	ticket := decodeWebAuthTestTicket(t, header)
	if got := int(binary.BigEndian.Uint16(ticket[webAuthPaddingLenOffset:webAuthPaddingOffset])); got != len(padding) {
		t.Fatalf("padding length = %d, want %d", got, len(padding))
	}
	if got := ticket[webAuthPaddingOffset : webAuthPaddingOffset+len(padding)]; !bytes.Equal(got, padding) {
		t.Fatal("ticket did not carry the cryptographically random padding bytes")
	}

	verifier := mustWebAuthVerifier(t, key, func() time.Time { return now }, 8)
	got, ok := verifier.verifyBearer(header, webAuthTestBinding)
	if !ok {
		t.Fatal("valid credential was rejected")
	}
	var wantNonce [webAuthNonceBytes]byte
	copy(wantNonce[:], nonce)
	if got.timestamp != now.Unix() || got.nonce != wantNonce ||
		got.mode != wantClaims.mode || got.profile != wantClaims.profile ||
		got.maxTx != wantClaims.maxTx || got.maxRx != wantClaims.maxRx {
		t.Fatalf("verified claims = %#v, want timestamp=%d nonce=%x metadata=%#v", got, now.Unix(), wantNonce, wantClaims)
	}
	if _, ok := verifier.verifyBearer(header, webAuthTestBinding); ok {
		t.Fatal("replayed credential was accepted")
	}
}

func TestWebAuthResponseProofBindsRequestClaimsAndStatus(t *testing.T) {
	key := mustWebAuthKey(t, webAuthTestToken)
	signer := newWebAuthSigner(
		key,
		func() time.Time { return time.Unix(1_800_000_000, 0) },
		bytes.NewReader(webAuthTestEntropy(
			bytes.Repeat([]byte{'n'}, webAuthNonceBytes),
			0,
			0,
			bytes.Repeat([]byte{'p'}, webAuthMinPaddingBytes),
		)),
	)
	_, claims, err := signer.authorization(webAuthTestBinding, webAuthClaims{})
	if err != nil {
		t.Fatal(err)
	}
	proof := webAuthResponseProof(key, webAuthTestBinding, claims, http.StatusOK)
	if !verifyWebAuthResponseProof(key, []string{proof}, webAuthTestBinding, claims, http.StatusOK) {
		t.Fatal("valid response proof was rejected")
	}
	separator := strings.Index(proof, webAuthResponsePaddingParameter)
	if separator < 0 {
		t.Fatalf("response proof has no padding auth-param: %q", proof)
	}
	changedBinding := webAuthTestBinding
	changedBinding.authority = "other.example:443"
	for name, valid := range map[string]bool{
		"missing":               verifyWebAuthResponseProof(key, nil, webAuthTestBinding, claims, http.StatusOK),
		"duplicate field":       verifyWebAuthResponseProof(key, []string{proof, proof}, webAuthTestBinding, claims, http.StatusOK),
		"missing padding param": verifyWebAuthResponseProof(key, []string{proof[:separator]}, webAuthTestBinding, claims, http.StatusOK),
		"duplicate padding param": verifyWebAuthResponseProof(
			key,
			[]string{proof + proof[separator:]},
			webAuthTestBinding,
			claims,
			http.StatusOK,
		),
		"different status": verifyWebAuthResponseProof(key, []string{proof}, webAuthTestBinding, claims, http.StatusBadGateway),
		"different target": verifyWebAuthResponseProof(key, []string{proof}, changedBinding, claims, http.StatusOK),
	} {
		if valid {
			t.Errorf("%s response proof was accepted", name)
		}
	}
	wrongKey := mustWebAuthKey(t, "fedcba9876543210fedcba9876543210")
	if verifyWebAuthResponseProof(wrongKey, []string{proof}, webAuthTestBinding, claims, http.StatusOK) {
		t.Fatal("response proof authenticated with the wrong derived key")
	}
}

func TestWebAuthResponsePaddingVariesPerRequestAndIsDeterministic(t *testing.T) {
	key := mustWebAuthKey(t, webAuthTestToken)
	claims := webAuthClaims{timestamp: 1_700_000_000}
	lengths := make(map[int]struct{})
	proofs := make(map[string]struct{})
	minHeaderLength := len(webAuthResponseParameter) + base64.RawURLEncoding.EncodedLen(webAuthMACBytes) +
		len(webAuthResponsePaddingParameter) + base64.RawURLEncoding.EncodedLen(webAuthMinResponsePaddingBytes)
	maxHeaderLength := len(webAuthResponseParameter) + base64.RawURLEncoding.EncodedLen(webAuthMACBytes) +
		len(webAuthResponsePaddingParameter) + base64.RawURLEncoding.EncodedLen(webAuthMaxResponsePaddingBytes)

	for index := range 128 {
		binary.BigEndian.PutUint64(claims.nonce[:8], uint64(index))
		binary.BigEndian.PutUint64(claims.nonce[8:], uint64(index*index+1))
		proof := webAuthResponseProof(key, webAuthTestBinding, claims, http.StatusOK)
		if again := webAuthResponseProof(key, webAuthTestBinding, claims, http.StatusOK); again != proof {
			t.Fatal("same authenticated request produced non-deterministic response padding")
		}
		if len(proof) < minHeaderLength || len(proof) > maxHeaderLength {
			t.Fatalf("response proof length = %d, want %d..%d", len(proof), minHeaderLength, maxHeaderLength)
		}
		_, padding, ok := parseWebAuthResponseProof([]string{proof})
		if !ok {
			t.Fatal("generated response proof did not parse")
		}
		lengths[len(padding)] = struct{}{}
		proofs[proof] = struct{}{}
	}
	if len(lengths) < 32 {
		t.Fatalf("only %d response padding lengths across 128 requests", len(lengths))
	}
	if len(proofs) != 128 {
		t.Fatalf("only %d distinct response proofs across 128 request nonces", len(proofs))
	}

	if minHeaderLength < 384 || maxHeaderLength < 1900 || maxHeaderLength > 2048 {
		t.Fatalf("response proof envelope = %d..%d bytes, want several hundred through roughly 2 KiB", minHeaderLength, maxHeaderLength)
	}
}

func TestWebAuthResponsePaddingBoundsAndTampering(t *testing.T) {
	key := mustWebAuthKey(t, webAuthTestToken)
	claims := webAuthClaims{timestamp: 1_700_000_000, nonce: [webAuthNonceBytes]byte{0x91}}
	for _, paddingLength := range []int{webAuthMinResponsePaddingBytes, webAuthMaxResponsePaddingBytes} {
		padding := bytes.Repeat([]byte{byte(paddingLength)}, paddingLength)
		proof := rawWebAuthTestResponseProof(key, webAuthTestBinding, claims, http.StatusOK, padding)
		if !verifyWebAuthResponseProof(key, []string{proof}, webAuthTestBinding, claims, http.StatusOK) {
			t.Fatalf("valid response proof with %d bytes of padding was rejected", paddingLength)
		}
		_, gotPadding, ok := parseWebAuthResponseProof([]string{proof})
		if !ok || !bytes.Equal(gotPadding, padding) {
			t.Fatalf("parsed boundary padding length=%d ok=%v", len(gotPadding), ok)
		}
	}

	for _, paddingLength := range []int{webAuthMinResponsePaddingBytes - 1, webAuthMaxResponsePaddingBytes + 1} {
		proof := rawWebAuthTestResponseProof(
			key,
			webAuthTestBinding,
			claims,
			http.StatusOK,
			make([]byte, paddingLength),
		)
		if verifyWebAuthResponseProof(key, []string{proof}, webAuthTestBinding, claims, http.StatusOK) {
			t.Fatalf("out-of-range response padding length %d authenticated", paddingLength)
		}
	}

	proof := webAuthResponseProof(key, webAuthTestBinding, claims, http.StatusOK)
	macStart := len(webAuthResponseParameter)
	paddingStart := strings.Index(proof, webAuthResponsePaddingParameter) + len(webAuthResponsePaddingParameter)
	for name, offset := range map[string]int{
		"mac":     macStart,
		"padding": paddingStart,
	} {
		t.Run(name, func(t *testing.T) {
			tampered := []byte(proof)
			if tampered[offset] == 'A' {
				tampered[offset] = 'B'
			} else {
				tampered[offset] = 'A'
			}
			if verifyWebAuthResponseProof(key, []string{string(tampered)}, webAuthTestBinding, claims, http.StatusOK) {
				t.Fatalf("response proof authenticated after %s tampering", name)
			}
		})
	}

	invalidAlphabet := []byte(proof)
	invalidAlphabet[paddingStart] = '+'
	if verifyWebAuthResponseProof(key, []string{string(invalidAlphabet)}, webAuthTestBinding, claims, http.StatusOK) {
		t.Fatal("standard-base64 response padding authenticated as base64url")
	}

	zeroPaddingProof := rawWebAuthTestResponseProof(
		key,
		webAuthTestBinding,
		claims,
		http.StatusOK,
		make([]byte, webAuthMinResponsePaddingBytes),
	)
	nonCanonicalTail := []byte(zeroPaddingProof)
	if nonCanonicalTail[len(nonCanonicalTail)-1] != 'A' {
		t.Fatalf("test invariant: zero-padding base64url ended in %q", nonCanonicalTail[len(nonCanonicalTail)-1])
	}
	nonCanonicalTail[len(nonCanonicalTail)-1] = 'B'
	for name, candidate := range map[string]string{
		"non-canonical trailing bits": string(nonCanonicalTail),
		"base64 padding":              zeroPaddingProof + "=",
		"line break":                  zeroPaddingProof[:paddingStart] + "\r\n" + zeroPaddingProof[paddingStart:],
	} {
		t.Run(name, func(t *testing.T) {
			if verifyWebAuthResponseProof(key, []string{candidate}, webAuthTestBinding, claims, http.StatusOK) {
				t.Fatal("malformed response auth-param authenticated")
			}
		})
	}
}

func TestWebAuthAllowsZeroMVPMetadataOnH2AndH3(t *testing.T) {
	key := mustWebAuthKey(t, webAuthTestToken)
	now := time.Unix(1_700_000_000, 0)
	for _, transport := range []string{webAuthTransportH2, webAuthTransportH3} {
		t.Run(transport, func(t *testing.T) {
			binding := webAuthTestBinding
			binding.transport = transport
			header := mustWebAuthBearer(t, key, now, bytes.Repeat([]byte{byte(len(transport))}, webAuthNonceBytes), binding, webAuthClaims{})
			verifier := mustWebAuthVerifier(t, key, func() time.Time { return now }, 1)
			claims, ok := verifier.verifyBearer(header, binding)
			if !ok || claims.mode != protocol.PacingUnspecified ||
				claims.profile != protocol.ProfileUnspecified || claims.maxTx != 0 || claims.maxRx != 0 {
				t.Fatalf("zero-valued MVP claims rejected or changed: claims=%#v ok=%v", claims, ok)
			}
		})
	}
}

func TestWebAuthBindsEveryHTTPField(t *testing.T) {
	key := mustWebAuthKey(t, webAuthTestToken)
	now := time.Unix(1_700_000_000, 0)
	binding := webAuthBinding{
		transport: webAuthTransportH3,
		method:    "CONNECT",
		protocol:  "connect-udp",
		authority: "cover.example:443",
		path:      "/.well-known/masque/udp/target.example/53/",
	}
	header := mustWebAuthBearer(t, key, now, bytes.Repeat([]byte{0x41}, webAuthNonceBytes), binding, webAuthClaims{})

	mutations := map[string]func(*webAuthBinding){
		"transport": func(b *webAuthBinding) { b.transport = webAuthTransportH2 },
		"method":    func(b *webAuthBinding) { b.method = "POST" },
		"protocol":  func(b *webAuthBinding) { b.protocol = "" },
		"authority": func(b *webAuthBinding) { b.authority = "other.example:443" },
		"path":      func(b *webAuthBinding) { b.path += "changed" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := binding
			mutate(&changed)
			verifier := mustWebAuthVerifier(t, key, func() time.Time { return now }, 1)
			if _, ok := verifier.verifyBearer(header, changed); ok {
				t.Fatalf("credential accepted after %s mutation", name)
			}
		})
	}

	// Length prefixes prevent adjacent text fields from being repartitioned
	// into a different request with the same concatenated bytes.
	first := binding
	first.method, first.protocol = "AB", "C"
	second := binding
	second.method, second.protocol = "A", "BC"
	header = mustWebAuthBearer(t, key, now, bytes.Repeat([]byte{0x42}, webAuthNonceBytes), first, webAuthClaims{})
	verifier := mustWebAuthVerifier(t, key, func() time.Time { return now }, 1)
	if _, ok := verifier.verifyBearer(header, second); ok {
		t.Fatal("length-prefix collision authenticated")
	}
}

func TestWebAuthRejectsMalformedAndTamperedTickets(t *testing.T) {
	key := mustWebAuthKey(t, webAuthTestToken)
	now := time.Unix(1_700_000_000, 0)
	header := mustWebAuthBearer(t, key, now, bytes.Repeat([]byte{0x52}, webAuthNonceBytes), webAuthTestBinding, webAuthClaims{})

	malformed := []string{
		"",
		"Bearer",
		"Bearer ",
		"Basic " + strings.Repeat("A", base64.RawURLEncoding.EncodedLen(webAuthMinTicketBytes)),
		strings.Repeat("A", len(header)),
		header + "A",
		header[:len(header)-1],
		header[:len(header)-1] + "=",
		"bearer  " + header[len(webAuthBearerPrefix):],
	}
	for index, candidate := range malformed {
		verifier := mustWebAuthVerifier(t, key, func() time.Time { return now }, 4)
		if _, ok := verifier.verifyBearer(candidate, webAuthTestBinding); ok {
			t.Fatalf("malformed credential %d authenticated: %q", index, candidate)
		}
	}

	raw := decodeWebAuthTestTicket(t, header)
	mutations := map[string]func([]byte){
		"version":        func(ticket []byte) { ticket[0]++ },
		"timestamp":      func(ticket []byte) { ticket[webAuthTimestampOffset+7]++ },
		"nonce":          func(ticket []byte) { ticket[webAuthNonceOffset]++ },
		"mode":           func(ticket []byte) { ticket[webAuthModeOffset]++ },
		"profile":        func(ticket []byte) { ticket[webAuthProfileOffset]++ },
		"max tx":         func(ticket []byte) { ticket[webAuthMaxTxOffset+7]++ },
		"max rx":         func(ticket []byte) { ticket[webAuthMaxRxOffset+7]++ },
		"padding length": func(ticket []byte) { ticket[webAuthPaddingLenOffset+1]++ },
		"padding":        func(ticket []byte) { ticket[webAuthPaddingOffset]++ },
		"mac":            func(ticket []byte) { ticket[len(ticket)-1]++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			ticket := append([]byte(nil), raw...)
			mutate(ticket)
			candidate := webAuthBearerPrefix + base64.RawURLEncoding.EncodeToString(ticket)
			verifier := mustWebAuthVerifier(t, key, func() time.Time { return now }, 1)
			if _, ok := verifier.verifyBearer(candidate, webAuthTestBinding); ok {
				t.Fatalf("ticket authenticated after %s mutation", name)
			}
		})
	}

	wrongKey := mustWebAuthKey(t, "fedcba9876543210fedcba9876543210")
	wrongVerifier := mustWebAuthVerifier(t, wrongKey, func() time.Time { return now }, 1)
	if _, ok := wrongVerifier.verifyBearer(header, webAuthTestBinding); ok {
		t.Fatal("ticket authenticated with the wrong derived key")
	}

	claims := webAuthClaims{timestamp: now.Unix(), nonce: [webAuthNonceBytes]byte{0x73}}
	padding := bytes.Repeat([]byte{0x74}, webAuthMinPaddingBytes)
	versionOneMAC := calculateWebAuthMAC(key, webAuthTestBinding, claims, webAuthVersion, padding)
	otherVersionMAC := calculateWebAuthMAC(key, webAuthTestBinding, claims, webAuthVersion+1, padding)
	if hmac.Equal(versionOneMAC[:], otherVersionMAC[:]) {
		t.Fatal("request MAC transcript did not bind the ticket version")
	}
}

func TestWebAuthPaddingBoundsAndStrictTicketLength(t *testing.T) {
	key := mustWebAuthKey(t, webAuthTestToken)
	now := time.Unix(1_700_000_000, 0)
	const sampleCount = webAuthMaxPaddingBytes - webAuthMinPaddingBytes + 1

	for _, test := range []struct {
		name          string
		sample        uint16
		paddingLength int
		wantTicket    int
	}{
		{
			name:          "minimum",
			sample:        0,
			paddingLength: webAuthMinPaddingBytes,
			wantTicket:    webAuthMinTicketBytes,
		},
		{
			name:          "maximum",
			sample:        sampleCount - 1,
			paddingLength: webAuthMaxPaddingBytes,
			wantTicket:    webAuthMaxTicketBytes,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			nonce := bytes.Repeat([]byte{byte(test.paddingLength)}, webAuthNonceBytes)
			padding := bytes.Repeat([]byte{0xc3}, test.paddingLength)
			random := webAuthTestEntropy(nonce, test.sample, test.sample, padding)
			header, err := newWebAuthSigner(key, func() time.Time { return now }, bytes.NewReader(random)).bearer(
				webAuthTestBinding,
				webAuthClaims{},
			)
			if err != nil {
				t.Fatal(err)
			}
			ticket := decodeWebAuthTestTicket(t, header)
			if len(ticket) != test.wantTicket {
				t.Fatalf("ticket length = %d, want %d", len(ticket), test.wantTicket)
			}
			if got := int(binary.BigEndian.Uint16(ticket[webAuthPaddingLenOffset:webAuthPaddingOffset])); got != test.paddingLength {
				t.Fatalf("declared padding = %d, want %d", got, test.paddingLength)
			}
			wantHeaderLength := len(webAuthBearerPrefix) + base64.RawURLEncoding.EncodedLen(test.wantTicket)
			if len(header) != wantHeaderLength {
				t.Fatalf("header length = %d, want %d", len(header), wantHeaderLength)
			}
			verifier := mustWebAuthVerifier(t, key, func() time.Time { return now }, 1)
			if _, ok := verifier.verifyBearer(header, webAuthTestBinding); !ok {
				t.Fatal("boundary ticket was rejected")
			}
		})
	}

	minHeaderLength := len(webAuthBearerPrefix) + base64.RawURLEncoding.EncodedLen(webAuthMinTicketBytes)
	maxHeaderLength := len(webAuthBearerPrefix) + base64.RawURLEncoding.EncodedLen(webAuthMaxTicketBytes)
	if minHeaderLength < 384 || maxHeaderLength < 1900 || maxHeaderLength > 2048 {
		t.Fatalf("credential envelope = %d..%d bytes, want several hundred through roughly 2 KiB", minHeaderLength, maxHeaderLength)
	}

	claims := webAuthClaims{timestamp: now.Unix(), nonce: [webAuthNonceBytes]byte{0x81}}
	for _, paddingLength := range []int{webAuthMinPaddingBytes - 1, webAuthMaxPaddingBytes + 1} {
		candidate := rawWebAuthTestBearerWithPadding(
			key,
			webAuthTestBinding,
			claims,
			webAuthVersion,
			make([]byte, paddingLength),
		)
		verifier := mustWebAuthVerifier(t, key, func() time.Time { return now }, 1)
		if _, ok := verifier.verifyBearer(candidate, webAuthTestBinding); ok {
			t.Fatalf("out-of-range padding length %d authenticated", paddingLength)
		}
	}

	valid := rawWebAuthTestBearerWithPadding(
		key,
		webAuthTestBinding,
		claims,
		webAuthVersion,
		make([]byte, webAuthMinPaddingBytes),
	)
	raw := decodeWebAuthTestTicket(t, valid)
	declaredMismatch := append([]byte(nil), raw...)
	binary.BigEndian.PutUint16(
		declaredMismatch[webAuthPaddingLenOffset:webAuthPaddingOffset],
		uint16(webAuthMinPaddingBytes+1),
	)
	trailingByte := append(append([]byte(nil), raw...), 0)
	truncated := append([]byte(nil), raw[:len(raw)-1]...)
	oversized := make([]byte, webAuthMaxTicketBytes+1)
	for name, ticket := range map[string][]byte{
		"declared length mismatch": declaredMismatch,
		"trailing byte":            trailingByte,
		"truncated MAC":            truncated,
		"over parser cap":          oversized,
	} {
		t.Run(name, func(t *testing.T) {
			candidate := webAuthBearerPrefix + base64.RawURLEncoding.EncodeToString(ticket)
			verifier := mustWebAuthVerifier(t, key, func() time.Time { return now }, 1)
			if _, ok := verifier.verifyBearer(candidate, webAuthTestBinding); ok {
				t.Fatal("structurally invalid ticket authenticated")
			}
		})
	}
}

func TestWebAuthPaddingLengthUsesTriangularDistribution(t *testing.T) {
	random := mathrand.New(mathrand.NewSource(0x5eed))
	const samples = 50_000
	span := webAuthMaxPaddingBytes - webAuthMinPaddingBytes
	middleLow := webAuthMinPaddingBytes + span/4
	middleHigh := webAuthMaxPaddingBytes - span/4
	middle := 0
	seen := make(map[int]struct{}, span+1)
	var sum int64

	for range samples {
		length, err := sampleWebAuthPaddingLength(random)
		if err != nil {
			t.Fatal(err)
		}
		if length < webAuthMinPaddingBytes || length > webAuthMaxPaddingBytes {
			t.Fatalf("padding length %d escaped %d..%d", length, webAuthMinPaddingBytes, webAuthMaxPaddingBytes)
		}
		if length >= middleLow && length <= middleHigh {
			middle++
		}
		seen[length] = struct{}{}
		sum += int64(length)
	}

	outer := samples - middle
	if middle <= 2*outer {
		t.Fatalf("middle-half samples = %d, outer-half samples = %d; distribution is not triangular", middle, outer)
	}
	wantMean := float64(webAuthMinPaddingBytes+webAuthMaxPaddingBytes) / 2
	gotMean := float64(sum) / samples
	if math.Abs(gotMean-wantMean) > 5 {
		t.Fatalf("padding mean = %.2f, want near %.2f", gotMean, wantMean)
	}
	if len(seen) < 1000 {
		t.Fatalf("observed only %d distinct lengths across %d samples", len(seen), samples)
	}
}

func TestWebAuthDummyHMACUsesMiddleSizedPadding(t *testing.T) {
	if got, want := len(webAuthDummyRequestPadding), (webAuthMinPaddingBytes+webAuthMaxPaddingBytes)/2; got < want {
		t.Fatalf("request dummy padding = %d bytes, want at least midpoint %d", got, want)
	}
	if got, want := len(webAuthDummyResponsePadding), (webAuthMinResponsePaddingBytes+webAuthMaxResponsePaddingBytes)/2; got < want {
		t.Fatalf("response dummy padding = %d bytes, want at least midpoint %d", got, want)
	}
}

func TestWebAuthRejectsAuthenticatedInvalidMetadata(t *testing.T) {
	key := mustWebAuthKey(t, webAuthTestToken)
	now := time.Unix(1_700_000_000, 0)
	base := webAuthClaims{timestamp: now.Unix(), nonce: [webAuthNonceBytes]byte{1}}

	invalid := []webAuthClaims{
		func() webAuthClaims { claims := base; claims.mode = protocol.PacingFixedRate + 1; return claims }(),
		func() webAuthClaims { claims := base; claims.profile = protocol.ProfileAggressive + 1; return claims }(),
		func() webAuthClaims { claims := base; claims.maxTx = protocol.MaxRate + 1; return claims }(),
		func() webAuthClaims { claims := base; claims.maxRx = protocol.MaxRate + 1; return claims }(),
	}
	for index, claims := range invalid {
		header := rawWebAuthTestBearer(key, webAuthTestBinding, claims, webAuthVersion)
		verifier := mustWebAuthVerifier(t, key, func() time.Time { return now }, 2)
		if _, ok := verifier.verifyBearer(header, webAuthTestBinding); ok {
			t.Fatalf("authenticated invalid metadata case %d was accepted: %#v", index, claims)
		}
	}
}

func TestWebAuthClockWindowBoundaries(t *testing.T) {
	key := mustWebAuthKey(t, webAuthTestToken)
	issuedAt := time.Unix(1_700_000_000, 0)
	header := mustWebAuthBearer(t, key, issuedAt, bytes.Repeat([]byte{0x61}, webAuthNonceBytes), webAuthTestBinding, webAuthClaims{})

	for _, test := range []struct {
		name string
		now  time.Time
		want bool
	}{
		{name: "past boundary", now: issuedAt.Add(-60 * time.Second), want: true},
		{name: "future boundary", now: issuedAt.Add(60 * time.Second), want: true},
		{name: "too far in past", now: issuedAt.Add(-61 * time.Second), want: false},
		{name: "stale", now: issuedAt.Add(61 * time.Second), want: false},
		{name: "server clock before epoch", now: time.Unix(-1, 0), want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier := mustWebAuthVerifier(t, key, func() time.Time { return test.now }, 1)
			_, got := verifier.verifyBearer(header, webAuthTestBinding)
			if got != test.want {
				t.Fatalf("accepted = %v, want %v", got, test.want)
			}
		})
	}
}

func TestWebAuthReplayCacheFailsClosedAndExpires(t *testing.T) {
	key := mustWebAuthKey(t, webAuthTestToken)
	clock := &webAuthTestClock{value: time.Unix(1_700_000_000, 0)}
	random := make([]byte, 0, 4*(webAuthNonceBytes+4+webAuthMinPaddingBytes))
	for nonce := 0; nonce < 4; nonce++ {
		nonceBytes := bytes.Repeat([]byte{byte(nonce + 1)}, webAuthNonceBytes)
		padding := bytes.Repeat([]byte{byte(0xa0 + nonce)}, webAuthMinPaddingBytes)
		random = append(random, webAuthTestEntropy(nonceBytes, 0, 0, padding)...)
	}
	signer := newWebAuthSigner(key, clock.Now, bytes.NewReader(random))
	verifier := mustWebAuthVerifier(t, key, clock.Now, 2)

	headers := make([]string, 3)
	for index := range headers {
		var err error
		headers[index], err = signer.bearer(webAuthTestBinding, webAuthClaims{})
		if err != nil {
			t.Fatal(err)
		}
	}
	for index := 0; index < 2; index++ {
		if _, ok := verifier.verifyBearer(headers[index], webAuthTestBinding); !ok {
			t.Fatalf("credential %d was rejected before capacity", index)
		}
	}
	if _, ok := verifier.verifyBearer(headers[2], webAuthTestBinding); ok {
		t.Fatal("cache evicted a live nonce instead of failing closed")
	}
	if _, ok := verifier.verifyBearer(headers[0], webAuthTestBinding); ok {
		t.Fatal("replay was accepted while cache was full")
	}

	clock.Advance(61 * time.Second)
	fresh, err := signer.bearer(webAuthTestBinding, webAuthClaims{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := verifier.verifyBearer(fresh, webAuthTestBinding); !ok {
		t.Fatal("expired cache entries did not release bounded capacity")
	}
}

func TestWebAuthConcurrentReplayAllowsExactlyOne(t *testing.T) {
	key := mustWebAuthKey(t, webAuthTestToken)
	now := time.Unix(1_700_000_000, 0)
	header := mustWebAuthBearer(t, key, now, bytes.Repeat([]byte{0x71}, webAuthNonceBytes), webAuthTestBinding, webAuthClaims{})
	verifier := mustWebAuthVerifier(t, key, func() time.Time { return now }, 64)

	var successes atomic.Int64
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := verifier.verifyBearer(header, webAuthTestBinding); ok {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("concurrent replay successes = %d, want 1", got)
	}
}

func TestWebAuthConfigurationAndInputBounds(t *testing.T) {
	for _, token := range []string{
		"",
		strings.Repeat("x", protocol.MinTokenLength-1),
		strings.Repeat("x", protocol.MaxTokenLength+1),
	} {
		if _, err := deriveWebAuthKey(token); !errors.Is(err, errInvalidWebAuthConfig) {
			t.Fatalf("deriveWebAuthKey(%d bytes) error = %v", len(token), err)
		}
	}
	key := mustWebAuthKey(t, webAuthTestToken)
	for _, limit := range []int{-1, maxWebAuthReplayEntries + 1} {
		if _, err := newWebAuthVerifier(key, nil, limit); !errors.Is(err, errInvalidWebAuthConfig) {
			t.Fatalf("newWebAuthVerifier(limit=%d) error = %v", limit, err)
		}
	}
	defaultVerifier := mustWebAuthVerifier(t, key, nil, 0)
	if defaultVerifier.maxEntries != defaultWebAuthReplayEntries {
		t.Fatalf("default replay limit = %d, want %d", defaultVerifier.maxEntries, defaultWebAuthReplayEntries)
	}

	bindings := []webAuthBinding{
		{},
		{transport: "quic", method: "CONNECT", authority: "example.com:443"},
		{transport: webAuthTransportH2, authority: "example.com:443"},
		{transport: webAuthTransportH2, method: strings.Repeat("M", webAuthMaxMethodBytes+1), authority: "example.com:443"},
		{transport: webAuthTransportH2, method: "CON\rNECT", authority: "example.com:443"},
		{transport: webAuthTransportH2, method: "CONNECT", protocol: strings.Repeat("p", webAuthMaxProtocolBytes+1), authority: "example.com:443"},
		{transport: webAuthTransportH2, method: "CONNECT", protocol: "bad\nprotocol", authority: "example.com:443"},
		{transport: webAuthTransportH2, method: "CONNECT"},
		{transport: webAuthTransportH2, method: "CONNECT", authority: strings.Repeat("a", webAuthMaxAuthorityBytes+1)},
		{transport: webAuthTransportH2, method: "CONNECT", authority: "bad\x00authority"},
		{transport: webAuthTransportH2, method: "CONNECT", authority: "example.com:443", path: strings.Repeat("p", webAuthMaxPathBytes+1)},
		{transport: webAuthTransportH2, method: "CONNECT", authority: "example.com:443", path: "/bad\npath"},
	}
	for index, binding := range bindings {
		signer := newWebAuthSigner(key, nil, nil)
		if _, err := signer.bearer(binding, webAuthClaims{}); !errors.Is(err, errInvalidWebAuthConfig) {
			t.Fatalf("invalid binding %d error = %v", index, err)
		}
		if _, ok := defaultVerifier.verifyBearer("", binding); ok {
			t.Fatalf("invalid binding %d authenticated", index)
		}
	}

	invalidClaims := []webAuthClaims{
		{mode: protocol.PacingFixedRate + 1},
		{profile: protocol.ProfileAggressive + 1},
		{maxTx: protocol.MaxRate + 1},
		{maxRx: protocol.MaxRate + 1},
	}
	for index, claims := range invalidClaims {
		signer := newWebAuthSigner(key, nil, nil)
		if _, err := signer.bearer(webAuthTestBinding, claims); !errors.Is(err, errInvalidWebAuthConfig) {
			t.Fatalf("invalid claims %d error = %v", index, err)
		}
	}
}

func TestWebAuthNonceFailureIsReturned(t *testing.T) {
	key := mustWebAuthKey(t, webAuthTestToken)
	wantErr := errors.New("entropy unavailable")
	signer := newWebAuthSigner(key, nil, webAuthErrorReader{err: wantErr})
	if _, err := signer.bearer(webAuthTestBinding, webAuthClaims{}); !errors.Is(err, wantErr) {
		t.Fatalf("nonce error = %v, want %v", err, wantErr)
	}
	signer = newWebAuthSigner(key, nil, bytes.NewReader(make([]byte, webAuthNonceBytes-1)))
	if _, err := signer.bearer(webAuthTestBinding, webAuthClaims{}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short nonce error = %v, want %v", err, io.ErrUnexpectedEOF)
	}

	for _, test := range []struct {
		name   string
		random []byte
	}{
		{
			name:   "first length sample",
			random: make([]byte, webAuthNonceBytes+1),
		},
		{
			name:   "second length sample",
			random: make([]byte, webAuthNonceBytes+2+1),
		},
		{
			name:   "padding",
			random: make([]byte, webAuthNonceBytes+4+webAuthMinPaddingBytes-1),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			signer := newWebAuthSigner(key, nil, bytes.NewReader(test.random))
			if _, err := signer.bearer(webAuthTestBinding, webAuthClaims{}); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("short random source error = %v, want %v", err, io.ErrUnexpectedEOF)
			}
		})
	}
}

func FuzzWebAuthVerifyBearer(f *testing.F) {
	key, err := deriveWebAuthKey(webAuthTestToken)
	if err != nil {
		f.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	header, err := newWebAuthSigner(
		key,
		func() time.Time { return now },
		bytes.NewReader(webAuthTestEntropy(
			bytes.Repeat([]byte{0x31}, webAuthNonceBytes),
			0,
			0,
			bytes.Repeat([]byte{0x32}, webAuthMinPaddingBytes),
		)),
	).bearer(webAuthTestBinding, webAuthClaims{})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(header, webAuthTransportH3, "CONNECT", "", "example.com:443", "")
	f.Add("Bearer invalid", "invalid", "", "", "", "")
	f.Fuzz(func(t *testing.T, candidate, transport, method, requestProtocol, authority, path string) {
		verifier, err := newWebAuthVerifier(key, func() time.Time { return now }, 4)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = verifier.verifyBearer(candidate, webAuthBinding{
			transport: transport,
			method:    method,
			protocol:  requestProtocol,
			authority: authority,
			path:      path,
		})
	})
}

func FuzzWebAuthVerifyResponseProof(f *testing.F) {
	key, err := deriveWebAuthKey(webAuthTestToken)
	if err != nil {
		f.Fatal(err)
	}
	claims := webAuthClaims{timestamp: 1_700_000_000, nonce: [webAuthNonceBytes]byte{0xa1}}
	proof := webAuthResponseProof(key, webAuthTestBinding, claims, http.StatusOK)
	f.Add(proof, http.StatusOK)
	f.Add("nextnonce=invalid", http.StatusBadGateway)
	f.Fuzz(func(t *testing.T, candidate string, status int) {
		_ = verifyWebAuthResponseProof(key, []string{candidate}, webAuthTestBinding, claims, status)
	})
}

func mustWebAuthKey(t testing.TB, token string) webAuthKey {
	t.Helper()
	key, err := deriveWebAuthKey(token)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustWebAuthVerifier(t testing.TB, key webAuthKey, now func() time.Time, limit int) *webAuthVerifier {
	t.Helper()
	verifier, err := newWebAuthVerifier(key, now, limit)
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func mustWebAuthBearer(
	t testing.TB,
	key webAuthKey,
	now time.Time,
	random []byte,
	binding webAuthBinding,
	claims webAuthClaims,
) string {
	t.Helper()
	padding := bytes.Repeat([]byte{0xa5}, webAuthMinPaddingBytes)
	header, err := newWebAuthSigner(
		key,
		func() time.Time { return now },
		bytes.NewReader(webAuthTestEntropy(random, 0, 0, padding)),
	).bearer(binding, claims)
	if err != nil {
		t.Fatal(err)
	}
	return header
}

func decodeWebAuthTestTicket(t testing.TB, header string) []byte {
	t.Helper()
	if !strings.HasPrefix(header, webAuthBearerPrefix) {
		t.Fatalf("missing bearer prefix: %q", header)
	}
	ticket, err := base64.RawURLEncoding.Strict().DecodeString(header[len(webAuthBearerPrefix):])
	if err != nil {
		t.Fatal(err)
	}
	if len(ticket) < webAuthMinTicketBytes || len(ticket) > webAuthMaxTicketBytes {
		t.Fatalf("ticket length = %d, want range %d..%d", len(ticket), webAuthMinTicketBytes, webAuthMaxTicketBytes)
	}
	return ticket
}

func rawWebAuthTestBearer(key webAuthKey, binding webAuthBinding, claims webAuthClaims, version byte) string {
	return rawWebAuthTestBearerWithPadding(
		key,
		binding,
		claims,
		version,
		bytes.Repeat([]byte{0x5a}, webAuthMinPaddingBytes),
	)
}

func rawWebAuthTestBearerWithPadding(
	key webAuthKey,
	binding webAuthBinding,
	claims webAuthClaims,
	version byte,
	padding []byte,
) string {
	mac := calculateWebAuthMAC(key, binding, claims, version, padding)
	macOffset := webAuthPaddingOffset + len(padding)
	ticket := make([]byte, macOffset+webAuthMACBytes)
	ticket[0] = version
	binary.BigEndian.PutUint64(ticket[webAuthTimestampOffset:webAuthNonceOffset], uint64(claims.timestamp))
	copy(ticket[webAuthNonceOffset:webAuthModeOffset], claims.nonce[:])
	ticket[webAuthModeOffset] = byte(claims.mode)
	ticket[webAuthProfileOffset] = byte(claims.profile)
	binary.BigEndian.PutUint64(ticket[webAuthMaxTxOffset:webAuthMaxRxOffset], claims.maxTx)
	binary.BigEndian.PutUint64(ticket[webAuthMaxRxOffset:webAuthPaddingLenOffset], claims.maxRx)
	binary.BigEndian.PutUint16(ticket[webAuthPaddingLenOffset:webAuthPaddingOffset], uint16(len(padding)))
	copy(ticket[webAuthPaddingOffset:macOffset], padding)
	copy(ticket[macOffset:], mac[:])
	return webAuthBearerPrefix + base64.RawURLEncoding.EncodeToString(ticket)
}

func rawWebAuthTestResponseProof(
	key webAuthKey,
	binding webAuthBinding,
	claims webAuthClaims,
	status int,
	padding []byte,
) string {
	mac := calculateWebAuthResponseMAC(key, binding, claims, status, padding)
	return webAuthResponseParameter + base64.RawURLEncoding.EncodeToString(mac[:]) +
		webAuthResponsePaddingParameter + base64.RawURLEncoding.EncodeToString(padding)
}

func webAuthTestEntropy(nonce []byte, firstSample, secondSample uint16, padding []byte) []byte {
	random := make([]byte, 0, len(nonce)+4+len(padding))
	random = append(random, nonce...)
	var samples [4]byte
	binary.BigEndian.PutUint16(samples[0:2], firstSample)
	binary.BigEndian.PutUint16(samples[2:4], secondSample)
	random = append(random, samples[:]...)
	random = append(random, padding...)
	return random
}

type webAuthTestClock struct {
	mu    sync.Mutex
	value time.Time
}

func (c *webAuthTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.value
}

func (c *webAuthTestClock) Advance(delta time.Duration) {
	c.mu.Lock()
	c.value = c.value.Add(delta)
	c.mu.Unlock()
}

type webAuthErrorReader struct{ err error }

func (r webAuthErrorReader) Read([]byte) (int, error) { return 0, r.err }
