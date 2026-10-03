//go:build !(go1.27 && !http2legacy)

package tunnel

import "golang.org/x/net/http2"

// The legacy transport's strict-concurrency check already allows queuing and
// excludes draining connections without taking its wire-write mutex.
func webH2CanTakeRequest(conn *http2.ClientConn) bool {
	return conn.CanTakeNewRequest()
}
