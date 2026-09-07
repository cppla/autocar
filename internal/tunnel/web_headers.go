package tunnel

import "net/http"

// webConnectRequestHeaders returns the common request fields for authenticated
// HTTP/2 and HTTP/3 CONNECT streams. Keeping an explicit nil User-Agent is
// intentional: both x/net/http2 and quic-go otherwise inject Go-specific
// defaults ("Go-http-client/2.0" and "quic-go HTTP/3") when the field is
// absent. An empty field suppresses those library markers without sending an
// invented browser identity that the rest of the request cannot yet match.
func webConnectRequestHeaders(bearer string) http.Header {
	return http.Header{
		"Proxy-Authorization": []string{bearer},
		"User-Agent":          nil,
	}
}
