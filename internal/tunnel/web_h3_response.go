package tunnel

import (
	"errors"
	"net/http"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

// Match the pinned HTTP/3 library's complete ClientConn response loop. The
// low-level request stream used by CONNECT returns one HEADERS block at a time.
const webH3MaxInformationalResponses = 5

type webH3ResponseStream interface {
	ReadResponse() (*http.Response, error)
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
}

func readWebH3FinalResponse(stream webH3ResponseStream) (*http.Response, error) {
	for informational := 0; ; {
		response, err := stream.ReadResponse()
		if err != nil {
			return nil, err
		}
		if response == nil {
			return nil, errors.New("tunnel: empty web-cover H3 response")
		}
		if response.StatusCode < 100 || response.StatusCode >= 200 || response.StatusCode == http.StatusSwitchingProtocols {
			return response, nil
		}
		informational++
		if informational > webH3MaxInformationalResponses {
			stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeExcessiveLoad))
			stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeExcessiveLoad))
			return nil, errors.New("tunnel: too many web-cover H3 informational responses")
		}
		// Do not close or drain this body: it is backed by the same request
		// stream as the final response. Keep the original establishment
		// deadline and cancellation active while reading the next HEADERS.
	}
}
