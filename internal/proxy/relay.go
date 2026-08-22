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
	if c.timeout > 0 {
		if err := c.Conn.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
			return 0, err
		}
	}
	return c.Conn.Write(p)
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
	go func() {
		results <- result{destination: right, err: copyHalf(right, left, idleTimeout)}
	}()
	go func() {
		results <- result{destination: left, err: copyHalf(left, right, idleTimeout)}
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

func copyHalf(dst, src net.Conn, idleTimeout time.Duration) error {
	bufferPtr := relayBufferPool.Get().(*[]byte)
	defer relayBufferPool.Put(bufferPtr)
	buffer := *bufferPtr
	for {
		if idleTimeout > 0 {
			_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
		}
		n, readErr := src.Read(buffer)
		if n < 0 || n > len(buffer) {
			return errors.New("proxy: invalid read count")
		}
		if n > 0 {
			written := 0
			for written < n {
				if idleTimeout > 0 {
					_ = dst.SetWriteDeadline(time.Now().Add(idleTimeout))
				}
				m, writeErr := dst.Write(buffer[written:n])
				if m < 0 || m > n-written {
					return errors.New("proxy: invalid write count")
				}
				written += m
				if writeErr != nil {
					return writeErr
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
