package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestDoctorUDPHumanOutput(t *testing.T) {
	for _, style := range []string{"valid", "private receive error"} {
		t.Run(style, func(t *testing.T) {
			packet := newDoctorUDPPacket(style)
			dialer := &doctorUDPFakeDialer{packet: packet}
			// No affirmative JSON flag: a later false flag alone would not
			// exercise human failure output's privacy contract.
			args := doctorUDPArgs()
			args = args[:len(args)-1]
			var stdout, stderr bytes.Buffer
			err := runDoctorWith(context.Background(), args, &stdout, &stderr, dialer.build)
			if style == "valid" {
				if err != nil || !strings.Contains(stdout.String(), "Authenticated relay UDP DNS exchange: OK") || !strings.Contains(stdout.String(), "NOERROR (questions=1 answers=0 authorities=0 additionals=0)") {
					t.Errorf("human UDP success: %v; output=%s", err, stdout.String())
				}
			} else if commandExitCode(err) != doctorExitProbeFailure || stdout.Len() != 0 || !strings.Contains(err.Error(), "authenticated tunnel UDP DNS exchange failed") {
				t.Errorf("human UDP failure: %v; output=%s", err, stdout.String())
			}
			if stderr.Len() != 0 || !packet.isClosed() || !dialer.closed.Load() || packet.active.Load() != 0 {
				t.Error("human probe did not reclaim its owned packet and dialer cleanly")
			}
			doctorUDPRedacted(t, stdout.String()+stderr.String(), err, "private-receive-error", "Example.test", "example.test", "127.0.0.1:5300")
		})
	}
}
