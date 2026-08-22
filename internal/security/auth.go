package security

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strings"
)

// ConstantTimeEqual compares secret-bearing strings through fixed-size
// SHA-256 digests. This avoids leaking the expected credential's length via
// subtle.ConstantTimeCompare's unequal-length fast path.
func ConstantTimeEqual(provided, expected string) bool {
	providedDigest := sha256.Sum256([]byte(provided))
	expectedDigest := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(providedDigest[:], expectedDigest[:]) == 1
}

// VerifyToken validates a bearer/shared token. An empty configured token never
// authenticates, preventing an omitted configuration value from disabling
// authentication by accident.
func VerifyToken(provided, expected string) bool {
	nonEmpty := subtle.ConstantTimeByteEq(byte(boolToInt(expected != "")), 1)
	equal := subtle.ConstantTimeCompare(digest(provided), digest(expected))
	return nonEmpty&equal == 1
}

// VerifyBasicCredentials validates a username/password pair without
// short-circuiting either comparison. Empty configured credentials are
// rejected as unsafe.
func VerifyBasicCredentials(providedUser, providedPassword, expectedUser, expectedPassword string) bool {
	userOK := subtle.ConstantTimeCompare(digest(providedUser), digest(expectedUser))
	passwordOK := subtle.ConstantTimeCompare(digest(providedPassword), digest(expectedPassword))
	userConfigured := subtle.ConstantTimeByteEq(byte(boolToInt(expectedUser != "")), 1)
	passwordConfigured := subtle.ConstantTimeByteEq(byte(boolToInt(expectedPassword != "")), 1)
	return userOK&passwordOK&userConfigured&passwordConfigured == 1
}

// VerifyBasicAuthorization parses and verifies an HTTP Proxy-Authorization or
// Authorization header using the Basic scheme.
func VerifyBasicAuthorization(header, expectedUser, expectedPassword string) bool {
	scheme, encoded, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		// Still execute fixed-size comparisons so malformed inputs do not make
		// valid-credential attempts observably special at the comparison step.
		return VerifyBasicCredentials("", "", expectedUser, expectedPassword) && false
	}
	encoded = strings.TrimSpace(encoded)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return VerifyBasicCredentials("", "", expectedUser, expectedPassword) && false
	}
	user, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return VerifyBasicCredentials(user, "", expectedUser, expectedPassword) && false
	}
	return VerifyBasicCredentials(user, password, expectedUser, expectedPassword)
}

func digest(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
