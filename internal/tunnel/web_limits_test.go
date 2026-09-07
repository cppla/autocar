package tunnel

import (
	"net"
	"strings"
	"testing"
)

func TestWebConnectionAdmissionValidation(t *testing.T) {
	for _, test := range []struct {
		name        string
		global      int
		perSource   int
		wantErrText string
	}{
		{name: "defaults"},
		{name: "explicit", global: 2, perSource: 1},
		{name: "negative global", global: -1, wantErrText: "cannot be negative"},
		{name: "negative per source", global: 2, perSource: -1, wantErrText: "cannot be negative"},
		{name: "per source above global", global: 1, perSource: 2, wantErrText: "exceeds"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := newWebConnectionAdmission(test.global, test.perSource)
			if test.wantErrText == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErrText) {
				t.Fatalf("error = %v, want %q", err, test.wantErrText)
			}
		})
	}
}

func TestWebConnectionAdmissionIsSharedAcrossTransportsAndReleasesOnce(t *testing.T) {
	admission, err := newWebConnectionAdmission(2, 1)
	if err != nil {
		t.Fatal(err)
	}
	address := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1000}
	releaseFirst, ok := admission.acquire(address)
	if !ok {
		t.Fatal("first H2-shaped connection was rejected")
	}
	// A UDP address for the same IP must share the source bucket with TCP.
	if release, accepted := admission.acquire(&net.UDPAddr{IP: address.IP, Port: 2000}); accepted {
		release()
		t.Fatal("same source obtained another slot by switching to H3")
	}
	releaseFirst()
	releaseFirst() // idempotent close paths must not over-release.
	releaseSecond, ok := admission.acquire(&net.UDPAddr{IP: address.IP, Port: 2000})
	if !ok {
		t.Fatal("capacity was not released after connection close")
	}
	releaseSecond()
}
