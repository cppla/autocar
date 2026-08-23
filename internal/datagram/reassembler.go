package datagram

import (
	"bytes"
	"errors"
	"sync"
	"time"
)

// ReassemblerConfig defines hard resource bounds for incomplete messages.
type ReassemblerConfig struct {
	MaxMessages      int
	MaxBufferedBytes int
	TTL              time.Duration

	// Now supplies time for deterministic expiry. A nil function uses
	// time.Now.
	Now func() time.Time
}

// ReassemblerStats describes resources currently held by incomplete messages.
type ReassemblerStats struct {
	Messages      int
	BufferedBytes int
}

var (
	ErrInvalidConfig = errors.New("datagram: invalid reassembler configuration")
	ErrCapacity      = errors.New("datagram: reassembly capacity exceeded")
	ErrConflict      = errors.New("datagram: conflicting fragment metadata")
)

// Reassembler combines parsed fragments under strict message, byte and time
// bounds. Its methods are safe for concurrent use.
type Reassembler struct {
	mu sync.Mutex

	maxMessages      int
	maxBufferedBytes int
	ttl              time.Duration
	now              func() time.Time

	messages      map[messageKey]*assembly
	bufferedBytes int
}

type messageKey struct {
	sessionID uint32
	messageID uint32
	response  bool
}

type assembly struct {
	flags     Flags
	address   string
	count     uint16
	createdAt time.Time
	parts     map[uint16][]byte
	bytes     int
}

// NewReassembler creates a bounded reassembler. All resource limits and TTL
// must be positive.
func NewReassembler(config ReassemblerConfig) (*Reassembler, error) {
	if config.MaxMessages <= 0 || config.MaxBufferedBytes <= 0 || config.TTL <= 0 {
		return nil, ErrInvalidConfig
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &Reassembler{
		maxMessages:      config.MaxMessages,
		maxBufferedBytes: config.MaxBufferedBytes,
		ttl:              config.TTL,
		now:              now,
		messages:         make(map[messageKey]*assembly),
	}, nil
}

// AddFrame parses and adds one wire frame. It returns a Message only when all
// fragments are present; incomplete input always returns the zero Message and
// complete=false.
func (r *Reassembler) AddFrame(frame []byte) (Message, bool, error) {
	fragment, err := Parse(frame)
	if err != nil {
		return Message{}, false, err
	}
	return r.Add(fragment)
}

// Add adds one validated fragment. Exact duplicates of an incomplete message
// are idempotent. Conflicting metadata or payload purges that message identity
// so fragments from different datagrams are never combined.
func (r *Reassembler) Add(fragment Fragment) (Message, bool, error) {
	if err := validateFragment(fragment); err != nil {
		return Message{}, false, err
	}
	now := r.now()
	key := messageKey{
		sessionID: fragment.SessionID,
		messageID: fragment.MessageID,
		response:  fragment.Flags&FlagResponse != 0,
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireLocked(now)

	current := r.messages[key]
	if current != nil && (current.flags != fragment.Flags || current.address != fragment.Address || current.count != fragment.FragmentCount) {
		r.removeLocked(key)
		return Message{}, false, ErrConflict
	}
	if current == nil && fragment.FragmentCount == 1 {
		payload := append([]byte(nil), fragment.Payload...)
		return Message{
			Flags:     fragment.Flags,
			SessionID: fragment.SessionID,
			MessageID: fragment.MessageID,
			Address:   fragment.Address,
			Payload:   payload,
		}, true, nil
	}

	if current == nil {
		if len(r.messages) >= r.maxMessages || len(fragment.Payload) > r.maxBufferedBytes-r.bufferedBytes {
			return Message{}, false, ErrCapacity
		}
		current = &assembly{
			flags:     fragment.Flags,
			address:   fragment.Address,
			count:     fragment.FragmentCount,
			createdAt: now,
			parts:     make(map[uint16][]byte),
		}
		r.messages[key] = current
	}

	if existing, ok := current.parts[fragment.FragmentIndex]; ok {
		if bytes.Equal(existing, fragment.Payload) {
			return Message{}, false, nil
		}
		r.removeLocked(key)
		return Message{}, false, ErrConflict
	}
	if len(fragment.Payload) > MaxPayloadSize-current.bytes {
		r.removeLocked(key)
		return Message{}, false, ErrPayloadTooLarge
	}
	if len(fragment.Payload) > r.maxBufferedBytes-r.bufferedBytes {
		return Message{}, false, ErrCapacity
	}

	payload := append([]byte(nil), fragment.Payload...)
	current.parts[fragment.FragmentIndex] = payload
	current.bytes += len(payload)
	r.bufferedBytes += len(payload)
	if len(current.parts) != int(current.count) {
		return Message{}, false, nil
	}

	completePayload := make([]byte, 0, current.bytes)
	for index := uint16(0); index < current.count; index++ {
		part, ok := current.parts[index]
		if !ok {
			return Message{}, false, nil
		}
		completePayload = append(completePayload, part...)
	}
	message := Message{
		Flags:     current.flags,
		SessionID: fragment.SessionID,
		MessageID: fragment.MessageID,
		Address:   current.address,
		Payload:   completePayload,
	}
	r.removeLocked(key)
	return message, true, nil
}

// Expire removes messages whose fixed lifetime has elapsed. Duplicate
// fragments do not extend a message's lifetime.
func (r *Reassembler) Expire() int {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.expireLocked(now)
}

// DiscardSession removes every incomplete message for sessionID. A tunnel must
// call this while retiring an association so a later association can never
// inherit fragments from the previous session epoch.
func (r *Reassembler) DiscardSession(sessionID uint32) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	discarded := 0
	for key := range r.messages {
		if key.sessionID == sessionID {
			r.removeLocked(key)
			discarded++
		}
	}
	return discarded
}

// Stats returns current resource usage after applying TTL expiry.
func (r *Reassembler) Stats() ReassemblerStats {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireLocked(now)
	return ReassemblerStats{
		Messages:      len(r.messages),
		BufferedBytes: r.bufferedBytes,
	}
}

func (r *Reassembler) expireLocked(now time.Time) int {
	expired := 0
	for key, message := range r.messages {
		if !now.Before(message.createdAt.Add(r.ttl)) {
			r.removeLocked(key)
			expired++
		}
	}
	return expired
}

func (r *Reassembler) removeLocked(key messageKey) {
	message, ok := r.messages[key]
	if !ok {
		return
	}
	delete(r.messages, key)
	r.bufferedBytes -= message.bytes
}
