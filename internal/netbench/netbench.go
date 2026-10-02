// Package netbench provides a small dependency-free throughput target and
// client. It is intended for repeatable direct-versus-tunnel comparisons, not
// as a substitute for production measurements across real routes.
package netbench

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

const (
	headerSize      = 16
	protocolVersion = 1
	ModeDownload    = byte(1)
	ModeUpload      = byte(2)
	defaultMaxBytes = int64(1 << 30)
)

var magic = [4]byte{'A', 'C', 'N', 'B'}

// Server is a deterministic TCP source/sink used by the benchmark command.
type Server struct {
	MaxBytes       int64
	MaxConnections int
	Timeout        time.Duration
}

// Serve owns the listener and accepted connections until ctx is canceled or
// the listener fails. It closes and joins active transfers before returning.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	maxConnections := s.MaxConnections
	if maxConnections <= 0 {
		maxConnections = 128
	}
	sem := make(chan struct{}, maxConnections)
	var wg sync.WaitGroup
	serveCtx, cancel := context.WithCancel(ctx)
	listenerClosed := make(chan struct{})
	stopListener := context.AfterFunc(serveCtx, func() {
		_ = ln.Close()
		close(listenerClosed)
	})

	defer func() {
		// Accept errors also end this ownership scope, even with a live
		// parent. Cancel workers before joining them, not after their I/O
		// eventually reaches the independent transfer deadline.
		cancel()
		if stopListener() {
			_ = ln.Close()
		} else {
			<-listenerClosed
		}
		wg.Wait()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case sem <- struct{}{}:
		case <-serveCtx.Done():
			_ = conn.Close()
			return nil
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			finish := ownBenchmarkConnection(serveCtx, conn)
			defer finish()
			_ = s.handle(conn)
		}()
	}
}

func (s *Server) handle(conn net.Conn) error {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	header := make([]byte, headerSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if string(header[:4]) != string(magic[:]) || header[4] != protocolVersion {
		return errors.New("invalid benchmark protocol header")
	}
	mode := header[5]
	size := int64(binary.BigEndian.Uint64(header[8:]))
	maxBytes := s.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	if size < 0 || size > maxBytes {
		return fmt.Errorf("requested payload %d exceeds limit %d", size, maxBytes)
	}

	switch mode {
	case ModeDownload:
		if err := writeZeros(conn, size); err != nil {
			return err
		}
	case ModeUpload:
		if _, err := io.CopyN(io.Discard, conn, size); err != nil {
			return err
		}
	default:
		return errors.New("unsupported benchmark mode")
	}
	_, err := conn.Write([]byte{0})
	return err
}

// Result is one completed transfer measurement.
type Result struct {
	Mode     byte
	Bytes    int64
	Duration time.Duration
}

// Mbps returns payload goodput in decimal megabits per second.
func (r Result) Mbps() float64 {
	if r.Duration <= 0 {
		return 0
	}
	return float64(r.Bytes*8) / r.Duration.Seconds() / 1_000_000
}

// Run performs one upload or download through dialer. Cancellation interrupts
// the owned transfer, including its header and completion acknowledgement;
// it does not close the dialer or its shared physical tunnel connection.
func Run(ctx context.Context, dialer transport.Dialer, target string, mode byte, size int64) (Result, error) {
	if mode != ModeDownload && mode != ModeUpload {
		return Result{}, errors.New("invalid benchmark mode")
	}
	if size < 0 {
		return Result{}, errors.New("size must not be negative")
	}
	if err := benchmarkContextError(ctx); err != nil {
		return Result{}, err
	}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil || conn == nil {
		if conn != nil {
			_ = conn.Close()
		}
		if err == nil {
			err = errors.New("benchmark dialer returned a nil connection")
		}
		return Result{}, err
	}
	finish := ownBenchmarkConnection(ctx, conn)
	defer finish()
	if err := benchmarkContextError(ctx); err != nil {
		return Result{}, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	ioError := func(err error) (Result, error) {
		if canceled := benchmarkContextError(ctx); canceled != nil {
			err = canceled
		}
		return Result{}, err
	}

	header := make([]byte, headerSize)
	copy(header[:4], magic[:])
	header[4] = protocolVersion
	header[5] = mode
	binary.BigEndian.PutUint64(header[8:], uint64(size))
	if _, err := conn.Write(header); err != nil {
		return ioError(err)
	}

	start := time.Now()
	switch mode {
	case ModeDownload:
		if _, err := io.CopyN(io.Discard, conn, size); err != nil {
			return ioError(err)
		}
	case ModeUpload:
		if err := writeZeros(conn, size); err != nil {
			return ioError(err)
		}
	}
	var ack [1]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil {
		return ioError(err)
	}
	if err := benchmarkContextError(ctx); err != nil {
		return Result{}, err
	}
	if ack[0] != 0 {
		return Result{}, errors.New("benchmark server returned an error")
	}
	return Result{Mode: mode, Bytes: size, Duration: time.Since(start)}, nil
}

// Close exactly this owned connection once. A cancellation callback can still
// be executing when stop returns false; join it before releasing the worker or
// returning a result. Normal completion stops the callback and closes directly.
func ownBenchmarkConnection(ctx context.Context, conn net.Conn) func() {
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
		close(closed)
	})
	return func() {
		if stop() {
			_ = conn.Close()
		} else {
			<-closed
		}
	}
}

func benchmarkContextError(ctx context.Context) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	// The socket deadline may fire just before the context timer publishes
	// Done. Preserve the declared context deadline in that narrow race too.
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func writeZeros(w io.Writer, size int64) error {
	buf := make([]byte, 64<<10)
	for size > 0 {
		n := int64(len(buf))
		if size < n {
			n = size
		}
		if _, err := w.Write(buf[:n]); err != nil {
			return err
		}
		size -= n
	}
	return nil
}
