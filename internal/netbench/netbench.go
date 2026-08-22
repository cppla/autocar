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

// Serve accepts connections until ctx is canceled or the listener fails.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	maxConnections := s.MaxConnections
	if maxConnections <= 0 {
		maxConnections = 128
	}
	sem := make(chan struct{}, maxConnections)
	var wg sync.WaitGroup

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	defer wg.Wait()
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
		case <-ctx.Done():
			_ = conn.Close()
			return nil
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer conn.Close()
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

// Run performs one upload or download through dialer.
func Run(ctx context.Context, dialer transport.Dialer, target string, mode byte, size int64) (Result, error) {
	if mode != ModeDownload && mode != ModeUpload {
		return Result{}, errors.New("invalid benchmark mode")
	}
	if size < 0 {
		return Result{}, errors.New("size must not be negative")
	}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return Result{}, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	header := make([]byte, headerSize)
	copy(header[:4], magic[:])
	header[4] = protocolVersion
	header[5] = mode
	binary.BigEndian.PutUint64(header[8:], uint64(size))
	if _, err := conn.Write(header); err != nil {
		return Result{}, err
	}

	start := time.Now()
	switch mode {
	case ModeDownload:
		if _, err := io.CopyN(io.Discard, conn, size); err != nil {
			return Result{}, err
		}
	case ModeUpload:
		if err := writeZeros(conn, size); err != nil {
			return Result{}, err
		}
	}
	var ack [1]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil {
		return Result{}, err
	}
	if ack[0] != 0 {
		return Result{}, errors.New("benchmark server returned an error")
	}
	return Result{Mode: mode, Bytes: size, Duration: time.Since(start)}, nil
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
