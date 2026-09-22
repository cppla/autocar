package proxy

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

var relayBufferPool = sync.Pool{New: func() any {
	buffer := make([]byte, 32*1024)
	return &buffer
}}

// activityConn applies an inactivity timeout to every blocking read and
// write. It is used for HTTP origin connections, whose request/response body
// phase is otherwise not covered by net/http's header and keepalive timeouts.
type activityConn struct {
	net.Conn
	timeout time.Duration
}

func (c *activityConn) Read(p []byte) (int, error) {
	if c.timeout > 0 {
		if err := c.Conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(p)
}

func (c *activityConn) Write(p []byte) (int, error) {
	return writeWithStallDeadline(c.Conn, p, c.timeout)
}

// Bound only the pending write. In particular, H2 streams implement deadlines
// by aborting the stream: leaving a completed write's timer armed would later
// terminate an otherwise active download with no more uploads.
func writeWithStallDeadline(conn net.Conn, p []byte, timeout time.Duration) (int, error) {
	if timeout <= 0 {
		return conn.Write(p)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}
	n, err := conn.Write(p)
	clearErr := conn.SetWriteDeadline(time.Time{})
	if err == nil {
		err = clearErr
	}
	return n, err
}

func (c *activityConn) CloseWrite() error {
	type closeWriter interface{ CloseWrite() error }
	if conn, ok := c.Conn.(closeWriter); ok {
		return conn.CloseWrite()
	}
	return nil
}

func (c *activityConn) CloseRead() error {
	type closeReader interface{ CloseRead() error }
	if conn, ok := c.Conn.(closeReader); ok {
		return conn.CloseRead()
	}
	return nil
}

func relay(left, right net.Conn, idleTimeout time.Duration) error {
	type result struct {
		destination net.Conn
		err         error
	}
	results := make(chan result, 2)
	activity := &relayActivity{left: left, right: right, timeout: idleTimeout}
	if err := activity.refresh(); err != nil {
		_ = left.Close()
		_ = right.Close()
		return err
	}
	go func() {
		results <- result{destination: right, err: copyHalf(right, left, activity)}
	}()
	go func() {
		results <- result{destination: left, err: copyHalf(left, right, activity)}
	}()

	var relayErrors []error
	aborted := false
	for range 2 {
		result := <-results
		if result.err == nil || errors.Is(result.err, io.EOF) {
			// A clean EOF is a TCP half-close: signal it to the destination but
			// keep the reverse direction alive so a final response can arrive.
			if err := closeWrite(result.destination); err != nil && !errors.Is(err, net.ErrClosed) {
				relayErrors = append(relayErrors, err)
				if !aborted {
					aborted = true
					_ = left.Close()
					_ = right.Close()
				}
			}
			continue
		}

		// Timeouts, reset connections, and write failures are not half-closes.
		// Close both sides immediately so the other copy goroutine cannot stay
		// blocked until the idle deadline.
		if !aborted {
			aborted = true
			_ = left.Close()
			_ = right.Close()
		}
		if !errors.Is(result.err, net.ErrClosed) {
			relayErrors = append(relayErrors, result.err)
		}
	}
	return errors.Join(relayErrors...)
}

// relayActivity makes read inactivity a property of the whole tunnel, not
// either direction independently. Downloads, uploads and server-push streams
// may legitimately have no reverse-direction application data for minutes.
// Serializing the update prevents an older activity event from overwriting a
// newer deadline. Writes retain their own stall deadline for backpressure.
type relayActivity struct {
	mu          sync.Mutex
	left, right net.Conn
	timeout     time.Duration
}

func (a *relayActivity) refresh() error {
	if a.timeout <= 0 {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	deadline := time.Now().Add(a.timeout)
	return errors.Join(a.left.SetReadDeadline(deadline), a.right.SetReadDeadline(deadline))
}

func copyHalf(dst, src net.Conn, activity *relayActivity) error {
	bufferPtr := relayBufferPool.Get().(*[]byte)
	defer relayBufferPool.Put(bufferPtr)
	buffer := *bufferPtr
	for {
		n, readErr := src.Read(buffer)
		if n < 0 || n > len(buffer) {
			return errors.New("proxy: invalid read count")
		}
		if n > 0 {
			if err := activity.refresh(); err != nil {
				return err
			}
			written := 0
			for written < n {
				m, writeErr := writeWithStallDeadline(dst, buffer[written:n], activity.timeout)
				if m < 0 || m > n-written {
					return errors.New("proxy: invalid write count")
				}
				written += m
				if writeErr != nil {
					return writeErr
				}
				if m > 0 {
					if err := activity.refresh(); err != nil {
						return err
					}
				}
				if m == 0 {
					return io.ErrShortWrite
				}
			}
		}
		if readErr != nil {
			return readErr
		}
	}
}

func closeWrite(conn net.Conn) error {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}
