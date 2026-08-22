package hy2

import (
	"crypto/tls"
	"errors"
	"fmt"
)

// The Hysteria core intentionally exposes a smaller TLS surface than
// crypto/tls.Config. Validate every security policy that cannot be faithfully
// copied before opening a socket. Silently dropping one of these callbacks can
// turn an application-specific certificate or resumption policy into the
// default policy.
func validateClientTLSPolicy(config *tls.Config) error {
	if err := validateTLS13Versions(config, "client"); err != nil {
		return err
	}
	switch {
	case config.VerifyConnection != nil:
		return errors.New("hy2: client TLS VerifyConnection is unsupported")
	case config.EncryptedClientHelloRejectionVerify != nil:
		return errors.New("hy2: client TLS EncryptedClientHelloRejectionVerify is unsupported")
	case config.Time != nil:
		return errors.New("hy2: client TLS custom Time is unsupported")
	case config.Rand != nil:
		return errors.New("hy2: client TLS custom Rand is unsupported")
	case len(config.CurvePreferences) != 0:
		return errors.New("hy2: client TLS custom CurvePreferences are unsupported")
	}
	return nil
}

func validateServerTLSPolicy(config *tls.Config) error {
	if err := validateTLS13Versions(config, "server"); err != nil {
		return err
	}
	switch {
	case config.GetConfigForClient != nil:
		return errors.New("hy2: server TLS GetConfigForClient is unsupported")
	case config.VerifyConnection != nil:
		return errors.New("hy2: server TLS VerifyConnection is unsupported")
	case config.VerifyPeerCertificate != nil:
		return errors.New("hy2: server TLS VerifyPeerCertificate is unsupported")
	case config.Time != nil:
		return errors.New("hy2: server TLS custom Time is unsupported")
	case config.Rand != nil:
		return errors.New("hy2: server TLS custom Rand is unsupported")
	case len(config.CurvePreferences) != 0:
		return errors.New("hy2: server TLS custom CurvePreferences are unsupported")
	case config.NameToCertificate != nil:
		return errors.New("hy2: server TLS NameToCertificate is unsupported; use Certificates or GetCertificate")
	case config.SessionTicketsDisabled:
		return errors.New("hy2: server TLS SessionTicketsDisabled is unsupported")
	case config.SessionTicketKey != ([32]byte{}):
		return errors.New("hy2: server TLS custom SessionTicketKey is unsupported")
	case config.WrapSession != nil:
		return errors.New("hy2: server TLS WrapSession is unsupported")
	case config.UnwrapSession != nil:
		return errors.New("hy2: server TLS UnwrapSession is unsupported")
	}

	// Hysteria exposes client CAs rather than the full ClientAuth enum. Its
	// exact mapping is either no client certificate, or strict verified mTLS.
	// Reject every intermediate/custom policy instead of silently strengthening
	// or weakening it.
	if config.ClientCAs == nil {
		if config.ClientAuth != tls.NoClientCert {
			return errors.New("hy2: server TLS ClientAuth requires ClientCAs and must be RequireAndVerifyClientCert")
		}
	} else if config.ClientAuth != tls.RequireAndVerifyClientCert {
		return errors.New("hy2: server TLS ClientCAs require ClientAuth RequireAndVerifyClientCert")
	}
	return nil
}

func validateTLS13Versions(config *tls.Config, role string) error {
	if config.MaxVersion != 0 && config.MaxVersion < tls.VersionTLS13 {
		return fmt.Errorf("hy2: %s TLS MaxVersion excludes TLS 1.3", role)
	}
	if config.MinVersion > tls.VersionTLS13 {
		return fmt.Errorf("hy2: %s TLS MinVersion excludes TLS 1.3", role)
	}
	return nil
}
