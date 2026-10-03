//go:build linux || darwin

package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	nativeQUICAddrResourceChild     = "AUTOCAR_NATIVE_QUIC_ADDR_RESOURCE_CHILD"
	nativeQUICAddrResourceScanLimit = 4096
)

// The child temporarily disables automatic GC, not the parent test process.
// This distinguishes synchronous ownership from eventual netFD finalization;
// it does not claim that the old error path permanently leaks descriptors.
func TestNativeQUICAddressErrorDoesNotRetainUDPDescriptors(t *testing.T) {
	if os.Getenv(nativeQUICAddrResourceChild) == "1" {
		nativeQUICAddrResourceChildTest(t)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0],
		"-test.run=^TestNativeQUICAddressErrorDoesNotRetainUDPDescriptors$",
		"-test.count=1", "-test.v", "-test.timeout=6s")
	cmd.Env = append(os.Environ(), nativeQUICAddrResourceChild+"=1")
	out, err := cmd.CombinedOutput()
	for _, line := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
		t.Logf("isolated child | %s", line)
	}
	if ctx.Err() != nil {
		t.Fatalf("isolated resource probe exceeded its budget: %v", ctx.Err())
	}
	if err != nil {
		t.Fatalf("isolated resource probe failed: %v", err)
	}
}

func nativeQUICAddrResourceChildTest(t *testing.T) {
	const attempts = 32
	// Listen/Close is local socket allocation only; it warms runtime netpoll
	// before counting descriptors and sends no packet to any destination.
	warm, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	raw, rawErr := warm.SyscallConn()
	var warmFD uintptr
	var warmAddress syscall.Sockaddr
	if rawErr == nil {
		var addressErr error
		rawErr = raw.Control(func(fd uintptr) {
			warmFD = fd
			warmAddress, addressErr = syscall.Getsockname(int(fd))
		})
		if rawErr == nil {
			rawErr = addressErr
		}
	}
	if err := warm.Close(); err != nil {
		t.Fatal(err)
	}
	if rawErr != nil || warmFD >= nativeQUICAddrResourceScanLimit {
		t.Fatalf("warm socket outside the bounded descriptor scan: fd=%d err=%v", warmFD, rawErr)
	}
	switch warmAddress.(type) {
	case *syscall.SockaddrInet4, *syscall.SockaddrInet6:
	default:
		t.Fatalf("warm UDP socket is not an INET address: %T", warmAddress)
	}
	runtime.GC()
	previousGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(previousGC)
	before := nativeQUICAddrResourceSnapshot(t)
	t.Logf("automatic_gc=disabled attempts=%d before_open=%d before_udp=%d", attempts, before.open, before.udp)

	for i := 0; i < attempts; i++ {
		// The numeric out-of-range port is rejected before IP lookup. No DNS
		// query, QUIC handshake, or connection to the valid TCP target occurs.
		client, err := NewClient(ClientConfig{
			ServerAddress: "127.0.0.1:65536", Token: testToken,
			TLSConfig:       &tls.Config{ServerName: "127.0.0.1"},
			QUICDialTimeout: time.Second,
		})
		if err != nil {
			t.Fatalf("attempt %d constructor rejected the deferred address case: %v", i, err)
		}
		dialCtx, cancelDial := context.WithTimeout(context.Background(), time.Second)
		conn, dialErr := client.DialContext(dialCtx, "tcp", "127.0.0.1:1")
		cancelDial()
		if conn != nil {
			_ = conn.Close()
			t.Errorf("attempt %d returned a connection for an invalid server port", i)
		}
		if err := client.Close(); err != nil {
			t.Errorf("attempt %d client Close: %v", i, err)
		}
		var addressErr *net.AddrError
		if !errors.As(dialErr, &addressErr) || addressErr.Err != "invalid port" || addressErr.Addr != "65536" {
			t.Errorf("attempt %d did not preserve the numeric address error: %T %v", i, dialErr, dialErr)
		}
	}
	// Close has joined every default physical attempt. Any UDP descriptor
	// still retained here cannot be attributed to an unfinished dial worker.
	afterClose := nativeQUICAddrResourceSnapshot(t)
	retained := afterClose.udp - before.udp
	t.Logf("after_client_close_open=%d after_client_close_udp=%d retained_udp=%d", afterClose.open, afterClose.udp, retained)
	if retained != 0 {
		t.Errorf("client Close left %d UDP descriptors retained after %d completed address failures; cleanup must not depend on GC", retained, attempts)
	}

	// Preserve this diagnostic even when the primary no-retention assertion
	// fails: a subsequent GC may reclaim the old path's unreachable netFDs.
	runtime.GC()
	gcDeadline := time.Now().Add(2 * time.Second)
	afterGC := nativeQUICAddrResourceSnapshot(t)
	for afterGC.udp != before.udp && time.Now().Before(gcDeadline) {
		runtime.Gosched()
		time.Sleep(5 * time.Millisecond)
		afterGC = nativeQUICAddrResourceSnapshot(t)
	}
	t.Logf("after_explicit_gc_open=%d after_explicit_gc_udp=%d post_gc_udp_delta=%d", afterGC.open, afterGC.udp, afterGC.udp-before.udp)
	if afterGC.udp != before.udp {
		t.Errorf("explicit GC did not restore UDP descriptor count within the diagnostic budget: before=%d after=%d", before.udp, afterGC.udp)
	}
}

type nativeQUICAddrResources struct {
	open int
	udp  int
}

func nativeQUICAddrResourceSnapshot(t *testing.T) nativeQUICAddrResources {
	t.Helper()
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	// The isolated child has only runtime/stdio descriptors plus at most 32
	// sockets. Scan a fixed bounded range; do not raise or lower host limits.
	bound := nativeQUICAddrResourceScanLimit
	if limit.Cur < nativeQUICAddrResourceScanLimit {
		bound = int(limit.Cur)
	}
	if bound < 128 {
		t.Fatalf("descriptor limit too small for the bounded child probe: %d", bound)
	}
	var resources nativeQUICAddrResources
	for fd := 0; fd < bound; fd++ {
		_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(syscall.F_GETFD), 0)
		if errno == syscall.EBADF {
			continue
		}
		if errno != 0 {
			t.Fatalf("F_GETFD(%d): %v", fd, errno)
		}
		resources.open++
		kind, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
		if err == nil && kind == syscall.SOCK_DGRAM {
			address, err := syscall.Getsockname(fd)
			// Explicit GC can run netFD finalizers between these read-only
			// descriptor syscalls; a just-closed descriptor is not a failure.
			if errors.Is(err, syscall.EBADF) {
				continue
			}
			// SOCK_DGRAM does not imply INET UDP. Non-INET control or
			// runtime descriptors may not support this address query; do
			// not count them as UDP. The owned warm INET socket above
			// verifies that its address query works without this filter.
			if errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.ENOTSOCK) {
				continue
			}
			if err != nil {
				t.Fatalf("getsockname(%d): %v", fd, err)
			}
			switch address.(type) {
			case *syscall.SockaddrInet4, *syscall.SockaddrInet6:
				resources.udp++
			}
		}
	}
	return resources
}
