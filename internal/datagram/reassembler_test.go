package datagram

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestReassemblerOutOfOrderAndDuplicate(t *testing.T) {
	clock := newFakeClock()
	reassembler := mustReassembler(t, ReassemblerConfig{
		MaxMessages:      4,
		MaxBufferedBytes: MaxPayloadSize,
		TTL:              time.Minute,
		Now:              clock.Now,
	})
	payload := bytes.Repeat([]byte("0123456789"), 30)
	address := "example.com:443"
	frames, err := Encode(Message{SessionID: 11, MessageID: 12, Address: address, Payload: payload}, HeaderSize+len(address)+31)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) < 3 {
		t.Fatalf("expected at least 3 fragments, got %d", len(frames))
	}

	var completed Message
	for position := len(frames) - 1; position >= 0; position-- {
		message, complete, err := reassembler.AddFrame(frames[position])
		if err != nil {
			t.Fatalf("add frame %d: %v", position, err)
		}
		if position != 0 {
			if complete || !isZeroMessage(message) {
				t.Fatalf("partial frame returned data: complete=%v message=%+v", complete, message)
			}
			if position == len(frames)-1 {
				before := reassembler.Stats()
				duplicateMessage, duplicateComplete, err := reassembler.AddFrame(frames[position])
				if err != nil || duplicateComplete || !isZeroMessage(duplicateMessage) {
					t.Fatalf("duplicate result: message=%+v complete=%v err=%v", duplicateMessage, duplicateComplete, err)
				}
				if after := reassembler.Stats(); after != before {
					t.Fatalf("duplicate changed resource use: before=%+v after=%+v", before, after)
				}
			}
			continue
		}
		if !complete {
			t.Fatal("final fragment did not complete message")
		}
		completed = message
	}
	if completed.SessionID != 11 || completed.MessageID != 12 || completed.Address != address || !bytes.Equal(completed.Payload, payload) {
		t.Fatalf("completed message mismatch: %+v", completed)
	}
	if stats := reassembler.Stats(); stats != (ReassemblerStats{}) {
		t.Fatalf("completed message retained resources: %+v", stats)
	}
}

func TestReassemblerCopiesFragments(t *testing.T) {
	reassembler := mustReassembler(t, defaultTestConfig(newFakeClock()))
	firstPayload := []byte("first")
	first := testFragment(1, 2, 0, 2, 0, "a:1", firstPayload)
	if message, complete, err := reassembler.Add(first); err != nil || complete || !isZeroMessage(message) {
		t.Fatalf("first fragment: message=%+v complete=%v err=%v", message, complete, err)
	}
	firstPayload[0] = 'X'
	message, complete, err := reassembler.Add(testFragment(1, 2, 1, 2, 0, "a:1", []byte("second")))
	if err != nil || !complete {
		t.Fatalf("second fragment: complete=%v err=%v", complete, err)
	}
	if string(message.Payload) != "firstsecond" {
		t.Fatalf("stored fragment aliases caller: %q", message.Payload)
	}
}

func TestReassemblerRejectsConflicts(t *testing.T) {
	tests := []struct {
		name     string
		first    Fragment
		conflict Fragment
	}{
		{
			name:     "address",
			first:    testFragment(1, 1, 0, 2, 0, "a:1", []byte("a")),
			conflict: testFragment(1, 1, 1, 2, 0, "b:1", []byte("b")),
		},
		{
			name:     "fragment count",
			first:    testFragment(1, 1, 0, 2, 0, "a:1", []byte("a")),
			conflict: testFragment(1, 1, 1, 3, 0, "a:1", []byte("b")),
		},
		{
			name:     "duplicate payload",
			first:    testFragment(1, 1, 0, 2, 0, "a:1", []byte("a")),
			conflict: testFragment(1, 1, 0, 2, 0, "a:1", []byte("b")),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reassembler := mustReassembler(t, defaultTestConfig(newFakeClock()))
			if _, complete, err := reassembler.Add(test.first); err != nil || complete {
				t.Fatalf("add first: complete=%v err=%v", complete, err)
			}
			message, complete, err := reassembler.Add(test.conflict)
			if !errors.Is(err, ErrConflict) || complete || !isZeroMessage(message) {
				t.Fatalf("conflict result: message=%+v complete=%v err=%v", message, complete, err)
			}
			if stats := reassembler.Stats(); stats != (ReassemblerStats{}) {
				t.Fatalf("conflicted assembly not purged: %+v", stats)
			}
		})
	}
}

func TestReassemblerSeparatesDirections(t *testing.T) {
	reassembler := mustReassembler(t, defaultTestConfig(newFakeClock()))
	request := []Fragment{
		testFragment(5, 9, 0, 2, 0, "target.example:53", []byte("re")),
		testFragment(5, 9, 1, 2, 0, "target.example:53", []byte("quest")),
	}
	response := []Fragment{
		testFragment(5, 9, 0, 2, FlagResponse, "192.0.2.1:53", []byte("res")),
		testFragment(5, 9, 1, 2, FlagResponse, "192.0.2.1:53", []byte("ponse")),
	}

	for _, fragment := range []Fragment{request[0], response[0]} {
		if _, complete, err := reassembler.Add(fragment); err != nil || complete {
			t.Fatalf("partial add: complete=%v err=%v", complete, err)
		}
	}
	if stats := reassembler.Stats(); stats.Messages != 2 {
		t.Fatalf("directions collided: %+v", stats)
	}

	requestMessage, complete, err := reassembler.Add(request[1])
	if err != nil || !complete || string(requestMessage.Payload) != "request" || requestMessage.Flags != 0 {
		t.Fatalf("request result: message=%+v complete=%v err=%v", requestMessage, complete, err)
	}
	responseMessage, complete, err := reassembler.Add(response[1])
	if err != nil || !complete || string(responseMessage.Payload) != "response" || responseMessage.Flags != FlagResponse {
		t.Fatalf("response result: message=%+v complete=%v err=%v", responseMessage, complete, err)
	}
}

func TestReassemblerCapacityBounds(t *testing.T) {
	clock := newFakeClock()
	reassembler := mustReassembler(t, ReassemblerConfig{
		MaxMessages:      1,
		MaxBufferedBytes: 4,
		TTL:              time.Minute,
		Now:              clock.Now,
	})
	first := testFragment(1, 1, 0, 2, 0, "a:1", []byte("ab"))
	if _, complete, err := reassembler.Add(first); err != nil || complete {
		t.Fatalf("add first: complete=%v err=%v", complete, err)
	}
	if _, _, err := reassembler.Add(testFragment(1, 2, 0, 2, 0, "a:1", []byte("c"))); !errors.Is(err, ErrCapacity) {
		t.Fatalf("message capacity: got %v", err)
	}
	if _, _, err := reassembler.Add(testFragment(1, 1, 1, 2, 0, "a:1", []byte("cde"))); !errors.Is(err, ErrCapacity) {
		t.Fatalf("byte capacity: got %v", err)
	}
	if stats := reassembler.Stats(); stats != (ReassemblerStats{Messages: 1, BufferedBytes: 2}) {
		t.Fatalf("capacity rejection changed state: %+v", stats)
	}
	message, complete, err := reassembler.Add(testFragment(1, 1, 1, 2, 0, "a:1", []byte("cd")))
	if err != nil || !complete || string(message.Payload) != "abcd" {
		t.Fatalf("completion after rejection: message=%+v complete=%v err=%v", message, complete, err)
	}
	if stats := reassembler.Stats(); stats != (ReassemblerStats{}) {
		t.Fatalf("resources not released: %+v", stats)
	}
}

func TestReassemblerRejectsOversizeLogicalPayload(t *testing.T) {
	reassembler := mustReassembler(t, ReassemblerConfig{
		MaxMessages:      2,
		MaxBufferedBytes: MaxPayloadSize + 1,
		TTL:              time.Minute,
		Now:              newFakeClock().Now,
	})
	if _, complete, err := reassembler.Add(testFragment(1, 1, 0, 2, 0, "a:1", make([]byte, MaxPayloadSize))); err != nil || complete {
		t.Fatalf("first fragment: complete=%v err=%v", complete, err)
	}
	message, complete, err := reassembler.Add(testFragment(1, 1, 1, 2, 0, "a:1", []byte("x")))
	if !errors.Is(err, ErrPayloadTooLarge) || complete || !isZeroMessage(message) {
		t.Fatalf("oversize result: message=%+v complete=%v err=%v", message, complete, err)
	}
	if stats := reassembler.Stats(); stats != (ReassemblerStats{}) {
		t.Fatalf("oversize assembly not purged: %+v", stats)
	}
}

func TestReassemblerExpiryUsesInjectedClock(t *testing.T) {
	clock := newFakeClock()
	reassembler := mustReassembler(t, ReassemblerConfig{
		MaxMessages:      1,
		MaxBufferedBytes: 8,
		TTL:              10 * time.Second,
		Now:              clock.Now,
	})
	fragment := testFragment(1, 1, 0, 2, 0, "a:1", []byte("a"))
	if _, _, err := reassembler.Add(fragment); err != nil {
		t.Fatal(err)
	}
	clock.Advance(9 * time.Second)
	if _, _, err := reassembler.Add(fragment); err != nil {
		t.Fatalf("duplicate before expiry: %v", err)
	}
	if expired := reassembler.Expire(); expired != 0 {
		t.Fatalf("expired early: %d", expired)
	}
	clock.Advance(time.Second)
	if expired := reassembler.Expire(); expired != 1 {
		t.Fatalf("expired at TTL: got %d", expired)
	}
	if stats := reassembler.Stats(); stats != (ReassemblerStats{}) {
		t.Fatalf("expired resources retained: %+v", stats)
	}

	if _, _, err := reassembler.Add(testFragment(1, 2, 0, 2, 0, "a:1", []byte("b"))); err != nil {
		t.Fatalf("reuse after expiry: %v", err)
	}
	clock.Advance(10 * time.Second)
	if _, _, err := reassembler.Add(testFragment(1, 3, 0, 2, 0, "a:1", []byte("c"))); err != nil {
		t.Fatalf("Add did not expire stale capacity: %v", err)
	}
	if stats := reassembler.Stats(); stats != (ReassemblerStats{Messages: 1, BufferedBytes: 1}) {
		t.Fatalf("unexpected post-expiry state: %+v", stats)
	}
}

func TestNewReassemblerValidation(t *testing.T) {
	valid := ReassemblerConfig{MaxMessages: 1, MaxBufferedBytes: 1, TTL: time.Second}
	tests := []ReassemblerConfig{
		{MaxMessages: 0, MaxBufferedBytes: 1, TTL: time.Second},
		{MaxMessages: 1, MaxBufferedBytes: 0, TTL: time.Second},
		{MaxMessages: 1, MaxBufferedBytes: 1, TTL: 0},
	}
	for _, config := range tests {
		if _, err := NewReassembler(config); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("config %+v: got %v", config, err)
		}
	}
	if _, err := NewReassembler(valid); err != nil {
		t.Fatalf("default clock rejected: %v", err)
	}
}

func TestAddRejectsInvalidFragmentWithoutState(t *testing.T) {
	reassembler := mustReassembler(t, defaultTestConfig(newFakeClock()))
	invalid := testFragment(0, 1, 0, 2, 0, "a:1", []byte("x"))
	if message, complete, err := reassembler.Add(invalid); !errors.Is(err, ErrInvalidSession) || complete || !isZeroMessage(message) {
		t.Fatalf("invalid result: message=%+v complete=%v err=%v", message, complete, err)
	}
	if stats := reassembler.Stats(); stats != (ReassemblerStats{}) {
		t.Fatalf("invalid fragment changed state: %+v", stats)
	}
}

func TestReassemblerDiscardSessionPurgesBothDirections(t *testing.T) {
	reassembler := mustReassembler(t, ReassemblerConfig{
		MaxMessages: 4, MaxBufferedBytes: 4096, TTL: time.Minute,
	})
	for _, flags := range []Flags{0, FlagResponse} {
		_, complete, err := reassembler.Add(testFragment(7, 1, 0, 2, flags, "127.0.0.1:53", []byte("old")))
		if err != nil || complete {
			t.Fatalf("Add(flags=%d) = complete %v, error %v", flags, complete, err)
		}
	}
	if _, _, err := reassembler.Add(testFragment(8, 1, 0, 2, 0, "127.0.0.1:53", []byte("keep"))); err != nil {
		t.Fatal(err)
	}
	if discarded := reassembler.DiscardSession(7); discarded != 2 {
		t.Fatalf("DiscardSession discarded %d messages, want 2", discarded)
	}
	stats := reassembler.Stats()
	if stats.Messages != 1 || stats.BufferedBytes != len("keep") {
		t.Fatalf("stats after discard = %+v", stats)
	}
}

func FuzzEncodeParseReassemble(f *testing.F) {
	f.Add([]byte("hello"), uint16(17), false)
	f.Add([]byte{}, uint16(0), true)
	f.Fuzz(func(t *testing.T, payload []byte, extra uint16, reverse bool) {
		if len(payload) > MaxPayloadSize {
			return
		}
		address := "example.com:443"
		minimumPayloadPerFrame := (len(payload) + MaxFragments - 1) / MaxFragments
		if minimumPayloadPerFrame < 1 {
			minimumPayloadPerFrame = 1
		}
		minimum := HeaderSize + len(address) + minimumPayloadPerFrame
		span := MaxFrameSize - minimum + 1
		maxFrameSize := minimum + int(extra)%span
		flags := Flags(0)
		if reverse {
			flags = FlagResponse
		}
		frames, err := Encode(Message{
			Flags:     flags,
			SessionID: 1,
			MessageID: 0,
			Address:   address,
			Payload:   payload,
		}, maxFrameSize)
		if err != nil {
			t.Fatal(err)
		}
		reassembler := mustReassembler(t, ReassemblerConfig{
			MaxMessages:      2,
			MaxBufferedBytes: MaxPayloadSize,
			TTL:              time.Minute,
			Now:              newFakeClock().Now,
		})

		completeCount := 0
		for step := 0; step < len(frames); step++ {
			index := step
			if reverse {
				index = len(frames) - 1 - step
			}
			parsed, err := Parse(frames[index])
			if err != nil {
				t.Fatal(err)
			}
			message, complete, err := reassembler.Add(parsed)
			if err != nil {
				t.Fatal(err)
			}
			if len(frames) > 1 && step == 0 {
				if duplicate, duplicateComplete, err := reassembler.Add(parsed); err != nil || duplicateComplete || !isZeroMessage(duplicate) {
					t.Fatalf("duplicate: message=%+v complete=%v err=%v", duplicate, duplicateComplete, err)
				}
			}
			if complete {
				completeCount++
				if !bytes.Equal(message.Payload, payload) || message.Address != address || message.Flags != flags {
					t.Fatalf("round-trip mismatch: %+v", message)
				}
			} else if !isZeroMessage(message) {
				t.Fatalf("partial result exposed: %+v", message)
			}
		}
		if completeCount != 1 {
			t.Fatalf("completed %d times", completeCount)
		}
		if stats := reassembler.Stats(); stats != (ReassemblerStats{}) {
			t.Fatalf("resources retained: %+v", stats)
		}
	})
}

func testFragment(sessionID, messageID uint32, index, count uint16, flags Flags, address string, payload []byte) Fragment {
	return Fragment{
		Flags:         flags,
		SessionID:     sessionID,
		MessageID:     messageID,
		FragmentIndex: index,
		FragmentCount: count,
		Address:       address,
		Payload:       payload,
	}
}

func defaultTestConfig(clock *fakeClock) ReassemblerConfig {
	return ReassemblerConfig{
		MaxMessages:      8,
		MaxBufferedBytes: MaxPayloadSize * 2,
		TTL:              time.Minute,
		Now:              clock.Now,
	}
}

func mustReassembler(t *testing.T, config ReassemblerConfig) *Reassembler {
	t.Helper()
	reassembler, err := NewReassembler(config)
	if err != nil {
		t.Fatal(err)
	}
	return reassembler
}

func isZeroMessage(message Message) bool {
	return message.Flags == 0 && message.SessionID == 0 && message.MessageID == 0 && message.Address == "" && message.Payload == nil
}

type fakeClock struct {
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Unix(1_700_000_000, 0)}
}

func (c *fakeClock) Now() time.Time {
	return c.now
}

func (c *fakeClock) Advance(duration time.Duration) {
	c.now = c.now.Add(duration)
}
