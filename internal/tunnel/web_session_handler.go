package tunnel

import (
	"net/http"
	"strings"
)

// webRequestAuthentication is the server-side authentication result for one
// request. A bootstrap result owns the fresh -> established transition on the
// request's physical connection; a continuation result carries its sequence
// into the response proof.
type webRequestAuthentication struct {
	binding    webAuthBinding
	claims     webAuthClaims
	exchange   webSessionExchange
	connection *webServerConnectionAuth
	session    *webSessionServerAuth
	bootstrap  bool
	legacy     bool
}

// authenticateWebRequest selects full or continuation authentication solely
// from state attached by the transport's ConnContext hook.
func (h *webTunnelHandler) authenticateWebRequest(
	request *http.Request,
	binding webAuthBinding,
) (webRequestAuthentication, bool) {
	result := webRequestAuthentication{binding: binding}
	values := request.Header.Values("Proxy-Authorization")
	connection, _ := request.Context().Value(webServerConnectionAuthContextKey{}).(*webServerConnectionAuth)
	result.connection = connection

	header := ""
	if len(values) == 1 {
		header = values[0]
	}
	if connection != nil {
		var session *webSessionServerAuth
		switch connection.phaseSnapshot() {
		case webServerConnectionAuthFresh:
			// Claim the one full-auth slot before verification. Otherwise two
			// concurrently valid full credentials can both pass the global nonce
			// verifier and the loser can retire the leader's connection.
			if connection.beginBootstrap() {
				claims, ok := h.auth.verifyBearer(header, binding)
				if !ok || len(values) != 1 {
					connection.abortBootstrap()
					return result, false
				}
				result.claims = claims
				result.bootstrap = true
				return result, true
			}
			// The state changed after the snapshot. Join the winner exactly as a
			// request that observed bootstrapping would.
			var ok bool
			session, ok = connection.waitEstablished(request.Context())
			if !ok {
				return result, false
			}
		case webServerConnectionAuthBootstrapping:
			var ok bool
			session, ok = connection.waitEstablished(request.Context())
			if !ok {
				return result, false
			}
		case webServerConnectionAuthEstablished:
			var ok bool
			session, ok = connection.establishedSession()
			if !ok {
				return result, false
			}
		case webServerConnectionAuthClosed:
			_, _ = h.auth.verifyBearer("", binding)
			return result, false
		}

		result.session = session
		result.claims = session.bootstrapClaims()
		exchange, ok := session.verifyAuthorization(header, binding)
		if !ok || len(values) != 1 {
			return result, false
		}
		result.exchange = exchange
		return result, true
	}

	claims, ok := h.auth.verifyBearer(header, binding)
	if !ok || len(values) != 1 {
		return result, false
	}
	result.claims = claims
	// Direct handler tests and embedders without a connection hook retain the
	// old proof behavior. Production H2/H3 listeners always attach a physical-
	// connection state before enabling short tickets.
	result.legacy = true
	return result, true
}

func (authentication *webRequestAuthentication) closeIncompleteBootstrap() {
	if authentication != nil && authentication.bootstrap && authentication.connection != nil {
		authentication.connection.closePhysicalConnection()
		authentication.bootstrap = false
	}
}

func (h *webTunnelHandler) authenticatedResponseProof(authentication *webRequestAuthentication, status int) (string, bool) {
	if authentication == nil {
		return "", false
	}
	if authentication.legacy {
		return webAuthResponseProof(
			h.auth.key,
			authentication.binding,
			authentication.claims,
			status,
		), true
	}
	if authentication.bootstrap {
		proof, session, err := issueWebSessionBootstrap(
			h.auth.key,
			authentication.binding,
			authentication.claims,
			status,
			nil,
		)
		if err != nil || !authentication.connection.establish(session) {
			authentication.connection.closePhysicalConnection()
			return "", false
		}
		authentication.session = session
		authentication.bootstrap = false
		return proof, true
	}
	if authentication.session == nil {
		return "", false
	}
	proof := authentication.session.responseProof(
		authentication.binding,
		authentication.exchange,
		status,
	)
	return proof, proof != ""
}

func (h *webTunnelHandler) writeAuthenticatedError(
	writer http.ResponseWriter,
	authentication *webRequestAuthentication,
	status int,
) {
	proof, ok := h.authenticatedResponseProof(authentication, status)
	if !ok {
		abortWebAuthenticatedResponse(authentication)
		return
	}
	writer.Header().Set(webAuthResponseHeader, proof)
	http.Error(writer, strings.ToLower(http.StatusText(status)), status)
}

func abortWebAuthenticatedResponse(authentication *webRequestAuthentication) {
	if authentication != nil && authentication.connection != nil {
		authentication.connection.closePhysicalConnection()
	}
	panic(http.ErrAbortHandler)
}

func (h *webTunnelHandler) serveAuthenticationMiss(writer http.ResponseWriter, request *http.Request) {
	h.serveCover(writer, request)
}
