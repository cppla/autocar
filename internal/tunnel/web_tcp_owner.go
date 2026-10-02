package tunnel

import (
	"context"
	"errors"
	"sync"
)

// webTCPConnectionOwner keeps accepted physical sockets owned after net/http
// relinquishes a hijacked connection. It never reads application bytes and is
// independent of the shared destination dialer and cover transport.
type webTCPConnectionOwner struct {
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
	conns  map[*webAdmissionConn]struct{}
}

func newWebTCPConnectionOwner() *webTCPConnectionOwner {
	ctx, cancel := context.WithCancel(context.Background())
	return &webTCPConnectionOwner{ctx: ctx, cancel: cancel, conns: make(map[*webAdmissionConn]struct{})}
}

func (o *webTCPConnectionOwner) register(conn *webAdmissionConn) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return false
	}
	o.conns[conn] = struct{}{}
	return true
}

func (o *webTCPConnectionOwner) remove(conn *webAdmissionConn) {
	o.mu.Lock()
	delete(o.conns, conn)
	o.mu.Unlock()
}

func (o *webTCPConnectionOwner) close() error {
	o.mu.Lock()
	o.closed = true
	conns := make([]*webAdmissionConn, 0, len(o.conns))
	for conn := range o.conns {
		conns = append(conns, conn)
	}
	o.mu.Unlock()
	// Cancellation can invoke transport callbacks; Close can unblock handlers
	// which unregister. Neither operation may execute under the registry lock.
	o.cancel()
	var closeErrors []error
	for _, conn := range conns {
		if err := conn.Close(); err != nil {
			closeErrors = append(closeErrors, err)
		}
	}
	return errors.Join(closeErrors...)
}
