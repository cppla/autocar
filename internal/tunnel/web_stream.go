package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

// webAddr supplies the address metadata required by net.Conn without exposing
// any tunnel protocol marker on the wire.
type webAddr struct {
	network string
	value   string
}

func (a webAddr) Network() string { return a.network }
func (a webAddr) String() string  { return a.value }

type h3DataStream interface {
	io.ReadWriteCloser
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// webH3Conn adapts an HTTP/3 request DATA stream to net.Conn. CloseWrite emits
// the request/response FIN while Close aborts both directions so a blocked
// relay goroutine is always released.
type webH3Conn struct {
	stream h3DataStream
	local  net.Addr
	remote net.Addr
	once   sync.Once
}

func newWebH3Conn(stream h3DataStream, local, remote net.Addr) *webH3Conn {
	return &webH3Conn{stream: stream, local: local, remote: remote}
}

func (c *webH3Conn) Read(p []byte) (int, error)  { return c.stream.Read(p) }
func (c *webH3Conn) Write(p []byte) (int, error) { return c.stream.Write(p) }

func (c *webH3Conn) Close() error {
	c.once.Do(func() {
		code := quic.StreamErrorCode(http3.ErrCodeRequestCanceled)
		c.stream.CancelRead(code)
		c.stream.CancelWrite(code)
	})
	return nil
}

func (c *webH3Conn) CloseWrite() error { return c.stream.Close() }

func (c *webH3Conn) CloseRead() error {
	c.stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	return nil
}

func (c *webH3Conn) LocalAddr() net.Addr                { return c.local }
func (c *webH3Conn) RemoteAddr() net.Addr               { return c.remote }
func (c *webH3Conn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *webH3Conn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *webH3Conn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

// webResponseStream is the server-side adapter for HTTP/2 CONNECT. HTTP/2 is
// full duplex, but net/http does not expose its stream as a net.Conn. Returning
// from the handler ends the response direction; Close therefore only needs to
// unblock a request-body read.
type webResponseStream struct {
	body    io.ReadCloser
	writer  io.Writer
	flusher http.Flusher
	once    sync.Once
}

func (s *webResponseStream) Read(p []byte) (int, error) { return s.body.Read(p) }

func (s *webResponseStream) Write(p []byte) (int, error) {
	n, err := s.writer.Write(p)
	if n > 0 {
		s.flusher.Flush()
	}
	return n, err
}

func (s *webResponseStream) Close() error {
	var err error
	s.once.Do(func() { err = s.body.Close() })
	return err
}

// webH2Conn adapts one streaming HTTP/2 CONNECT request and response to a
// net.Conn. HTTP/2 exposes no per-stream deadline API, so deadlines cancel this
// stream only. Once a deadline fires the stream is terminal, matching the
// proxy's idle-timeout behavior.
type webH2Conn struct {
	reader io.ReadCloser
	writer *io.PipeWriter
	cancel context.CancelFunc
	local  net.Addr
	remote net.Addr

	mu           sync.Mutex
	closed       bool
	readExpired  bool
	writeExpired bool
	readSeq      uint64
	writeSeq     uint64
	readTimer    *time.Timer
	writeTimer   *time.Timer
	closeOnce    sync.Once
}

func newWebH2Conn(reader io.ReadCloser, writer *io.PipeWriter, cancel context.CancelFunc, local, remote net.Addr) *webH2Conn {
	return &webH2Conn{reader: reader, writer: writer, cancel: cancel, local: local, remote: remote}
}

func (c *webH2Conn) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	c.mu.Lock()
	expired := c.readExpired
	c.mu.Unlock()
	if expired && err != nil {
		return n, os.ErrDeadlineExceeded
	}
	return n, err
}

func (c *webH2Conn) Write(p []byte) (int, error) {
	n, err := c.writer.Write(p)
	c.mu.Lock()
	expired := c.writeExpired
	c.mu.Unlock()
	if expired && err != nil {
		return n, os.ErrDeadlineExceeded
	}
	return n, err
}

func (c *webH2Conn) Close() error {
	var result error
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.stopTimersLocked()
		c.mu.Unlock()
		c.cancel()
		result = errors.Join(c.writer.Close(), c.reader.Close())
	})
	return result
}

func (c *webH2Conn) CloseWrite() error { return c.writer.Close() }

func (c *webH2Conn) LocalAddr() net.Addr  { return c.local }
func (c *webH2Conn) RemoteAddr() net.Addr { return c.remote }

func (c *webH2Conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *webH2Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.readSeq++
	if c.readTimer != nil {
		c.readTimer.Stop()
		c.readTimer = nil
	}
	if t.IsZero() {
		return nil
	}
	seq := c.readSeq
	c.readTimer = time.AfterFunc(time.Until(t), func() { c.expireRead(seq) })
	return nil
}

func (c *webH2Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.writeSeq++
	if c.writeTimer != nil {
		c.writeTimer.Stop()
		c.writeTimer = nil
	}
	if t.IsZero() {
		return nil
	}
	seq := c.writeSeq
	c.writeTimer = time.AfterFunc(time.Until(t), func() { c.expireWrite(seq) })
	return nil
}

func (c *webH2Conn) expireRead(seq uint64) {
	c.mu.Lock()
	if c.closed || seq != c.readSeq {
		c.mu.Unlock()
		return
	}
	c.readExpired = true
	c.mu.Unlock()
	c.cancel()
}

func (c *webH2Conn) expireWrite(seq uint64) {
	c.mu.Lock()
	if c.closed || seq != c.writeSeq {
		c.mu.Unlock()
		return
	}
	c.writeExpired = true
	c.mu.Unlock()
	c.cancel()
}

func (c *webH2Conn) stopTimersLocked() {
	c.readSeq++
	c.writeSeq++
	if c.readTimer != nil {
		c.readTimer.Stop()
	}
	if c.writeTimer != nil {
		c.writeTimer.Stop()
	}
}

var _ net.Conn = (*webH3Conn)(nil)
var _ net.Conn = (*webH2Conn)(nil)
