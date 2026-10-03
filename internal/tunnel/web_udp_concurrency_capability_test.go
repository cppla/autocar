package tunnel

import (
	"testing"

	"github.com/cppla/autocar/internal/transport"
)

// These pure capability checks use the production CONNECT-UDP canonicalizer,
// not a fixture-provided key. Real Send/Close and wrapper-chain behavior are
// covered by the separate authenticated slow-target wire tests.
func TestWebUDPConcurrentSendCapabilityPreservesTargetIdentity(t *testing.T) {
	for _, maxTargets := range []int{0, 1, 7, 32} {
		inner := &webUDPPacketConn{maxTargets: maxTargets}
		wrapped := &webClientPacketConn{inner: inner}
		for _, sender := range []transport.PacketConcurrentSender{inner, wrapped} {
			if got, want := sender.ConcurrentSendLimit(), min(8, maxTargets); got != want {
				t.Errorf("%T concurrent limit=%d, want %d", sender, got, want)
			}
			for _, test := range []struct{ address, want string }{
				{"UPPER.invalid:0053", "upper.invalid:53"},
				{"UPPER.invalid.:53", "upper.invalid.:53"},
				{"bücher.invalid:53", "xn--bcher-kva.invalid:53"},
				{"[2001:0db8:0:0:0:0:0:1]:0053", "[2001:db8::1]:53"},
				{"[::ffff:127.0.0.1]:53", "127.0.0.1:53"},
			} {
				got, err := sender.SendTargetKey(test.address)
				if err != nil || got != test.want {
					t.Errorf("%T key(%q)=%q, %v; want %q", sender, test.address, got, err, test.want)
				}
			}
			for _, address := range []string{"missing-port", "example.invalid:0", "[fe80::1%zone]:53"} {
				if _, err := sender.SendTargetKey(address); err == nil {
					t.Errorf("%T accepted invalid target key %q", sender, address)
				}
			}
		}
	}
	if got := (&webClientPacketConn{}).ConcurrentSendLimit(); got != 0 {
		t.Errorf("empty wrapper advertised concurrency %d", got)
	}
}
