//go:build go1.27 && !http2legacy

package tunnel

import "golang.org/x/net/http2"

// x/net v0.58's Go1.27 wrapper reports immediately available slots, not whether
// its strict-concurrency RoundTrip can queue. State uses memory locks in this
// implementation. Call outside the owner mutex (as on the legacy path).
func webH2CanTakeRequest(conn *http2.ClientConn) bool {
	if conn.CanTakeNewRequest() {
		return true
	}
	state := conn.State()
	// This is a conservative queue attempt, not an exact native usability
	// test: active GOAWAY/PROTOCOL_ERROR retirement is not fully exposed by
	// the wrapper. RoundTrip remains authoritative; only an entirely unencoded
	// rejection with a live context may reselect once. Do not compare capacity
	// counts: the wrapper synthesizes them from separate native snapshots and
	// can report mismatched values while a stream finishes or starts.
	return !state.Closed && !state.Closing
}
