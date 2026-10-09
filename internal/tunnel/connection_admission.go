package tunnel

import (
	"errors"
	"fmt"
)

// ConnectionAdmission bounds accepted native relay connections, including
// unauthenticated connections and idle QUIC sessions. Pass the same instance
// to QUIC and TLS servers to share one global limit. Closing a server returns
// its slots without closing the budget or affecting other servers using it.
//
// The zero value is invalid; construct values with NewConnectionAdmission.
type ConnectionAdmission struct {
	sem chan struct{}
}

// NewConnectionAdmission creates a connection budget with a positive limit.
func NewConnectionAdmission(limit int) (*ConnectionAdmission, error) {
	if limit <= 0 {
		return nil, errors.New("tunnel: connection admission limit must be positive")
	}
	return &ConnectionAdmission{sem: make(chan struct{}, limit)}, nil
}

func resolveConnectionAdmission(limit, fallback int, admission *ConnectionAdmission) (*ConnectionAdmission, error) {
	if limit < 0 {
		return nil, errors.New("tunnel: maximum connections cannot be negative")
	}
	if admission == nil {
		if limit == 0 {
			limit = fallback
		}
		return NewConnectionAdmission(limit)
	}
	if cap(admission.sem) == 0 {
		return nil, errors.New("tunnel: invalid zero-value connection admission")
	}
	if limit != 0 && limit != cap(admission.sem) {
		return nil, fmt.Errorf("tunnel: maximum connections (%d) does not match shared connection admission limit (%d)", limit, cap(admission.sem))
	}
	return admission, nil
}
