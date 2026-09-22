package tunnel

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const destinationWriteChunkSize = 32 * 1024

func (s *serverCore) boundDestinationWrites(conn net.Conn) net.Conn {
	return &destinationWriteConn{Conn: conn, timeout: s.destinationWriteTimeout}
}

// destinationWriteConn owns the write deadline of a newly dialed TCP target.
// A pending write has a completion budget, not a kernel-level inactivity timer:
// partial progress inside net.Conn.Write cannot be observed until it returns.
// No deadline remains armed while there is no pending write, and read deadlines
// are untouched. Embed net.Conn rather than its concrete implementation so
// io.Copy cannot bypass Write via a promoted ReaderFrom or WriterTo method.
type destinationWriteConn struct {
	net.Conn
	timeout time.Duration
	writeMu sync.Mutex
}

func (c *destinationWriteConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	written := 0
	for len(p) > 0 {
		chunk := p[:min(len(p), destinationWriteChunkSize)]
		if err := c.Conn.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
			return written, err
		}
		n, err := c.Conn.Write(chunk)
		clearErr := c.Conn.SetWriteDeadline(time.Time{})
		if n < 0 || n > len(chunk) {
			return written, errors.New("tunnel: invalid destination write count")
		}
		written += n
		if err != nil {
			// Preserve partial progress and its error; retrying a timed-out
			// write here could hide a failed destination from the relay.
			return written, err
		}
		if clearErr != nil {
			return written, clearErr
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
		p = p[n:]
	}
	return written, nil
}

func (c *destinationWriteConn) CloseWrite() error {
	if conn, ok := c.Conn.(closeWriter); ok {
		return conn.CloseWrite()
	}
	return nil
}

func (c *destinationWriteConn) CloseRead() error {
	if conn, ok := c.Conn.(closeReader); ok {
		return conn.CloseRead()
	}
	return nil
}
