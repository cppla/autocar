package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
)

// Authenticator verifies proxy credentials. Implementations must be safe for
// concurrent use and should avoid logging either argument.
type Authenticator interface {
	Authenticate(ctx context.Context, username, password string) bool
}

// AuthFunc adapts a function to Authenticator.
type AuthFunc func(context.Context, string, string) bool

// Authenticate implements Authenticator.
func (f AuthFunc) Authenticate(ctx context.Context, username, password string) bool {
	return f(ctx, username, password)
}

type staticAuthenticator struct {
	username [sha256.Size]byte
	password [sha256.Size]byte
}

// StaticAuthenticator returns an authenticator for one username/password
// pair. Hashes are compared in constant time, including when the supplied
// strings have different lengths.
func StaticAuthenticator(username, password string) Authenticator {
	return &staticAuthenticator{
		username: sha256.Sum256([]byte(username)),
		password: sha256.Sum256([]byte(password)),
	}
}

func (a *staticAuthenticator) Authenticate(_ context.Context, username, password string) bool {
	u := sha256.Sum256([]byte(username))
	p := sha256.Sum256([]byte(password))
	return subtle.ConstantTimeCompare(a.username[:], u[:])&
		subtle.ConstantTimeCompare(a.password[:], p[:]) == 1
}
