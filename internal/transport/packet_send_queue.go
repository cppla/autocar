package transport

import (
	"context"
	"errors"
	"net"
	"sync"
)

const (
	packetSendQueueMaxTargets = 8
	packetSendQueueMaxBytes   = 256 << 10
	packetSendTargetMaxBytes  = packetSendQueueMaxBytes / 2
)

type packetSendItem struct {
	payload []byte
	address string
	charge  int
}

type packetSendLane struct {
	queue   []packetSendItem
	packets int
	bytes   int
	active  bool
}

// PacketSendQueue isolates slow targets with bounded, best-effort FIFO lanes.
// All limits include active callbacks, not just packets waiting to run. One
// target can use at most half the packet and byte budgets (rounded up for
// packets); multiple busy targets may still exhaust the shared budget.
// There is no delivery guarantee, retry, or ordering across different targets.
type PacketSendQueue struct {
	ctx    context.Context
	cancel context.CancelFunc
	send   func(context.Context, []byte, string) error

	mu               sync.Mutex
	stopped          bool
	lanes            map[string]*packetSendLane
	packets          int
	bytes            int
	maxPackets       int
	maxTargetPackets int
	maxTargets       int
	workers          int
	ready            chan *packetSendLane
	wg               sync.WaitGroup
	fatalOnce        sync.Once
	errors           chan error
}

// NewPacketSendQueue does not start workers until Enqueue accepts a packet.
// Nonpositive maxPackets selects one packet; nonpositive maxTargets selects
// the eight-target ceiling. The target count also cannot exceed maxPackets.
// parent and send must be non-nil. A callback must return when ctx is canceled
// or its owner closes the underlying I/O endpoint. The queue cannot forcibly
// interrupt custom code. The byte limit covers payload plus address charges,
// not total resident memory; the separate packet/target limits bound metadata.
func NewPacketSendQueue(parent context.Context, maxPackets, maxTargets int, send func(context.Context, []byte, string) error) *PacketSendQueue {
	if maxPackets <= 0 {
		maxPackets = 1
	}
	if maxTargets <= 0 {
		maxTargets = packetSendQueueMaxTargets
	}
	ctx, cancel := context.WithCancel(parent)
	return &PacketSendQueue{
		ctx: ctx, cancel: cancel, send: send,
		lanes:      make(map[string]*packetSendLane),
		maxPackets: maxPackets, maxTargetPackets: maxPackets/2 + maxPackets%2,
		maxTargets: min(maxTargets, maxPackets, packetSendQueueMaxTargets),
		ready:      make(chan *packetSendLane, min(maxTargets, maxPackets, packetSendQueueMaxTargets)),
		errors:     make(chan error, 1),
	}
}

// Enqueue consumes payload before returning and never waits for a callback.
// address is both the destination and the FIFO key. Callers with aliases must
// canonicalize it first, without resolving or bypassing destination policy.
// Payload plus address bytes are charged before copying; even empty inputs
// cost one byte, so arbitrarily large count settings cannot admit free work.
func (q *PacketSendQueue) Enqueue(payload []byte, address string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.stopped || q.ctx.Err() != nil {
		return net.ErrClosed
	}
	if len(payload) > packetSendQueueMaxBytes || len(address) > packetSendQueueMaxBytes-len(payload) {
		return ErrPacketQueueFull
	}
	charge := max(1, len(payload)+len(address))
	lane := q.lanes[address]
	if q.packets >= q.maxPackets || charge > packetSendQueueMaxBytes-q.bytes || charge > packetSendTargetMaxBytes {
		return ErrPacketQueueFull
	}
	if lane == nil {
		if len(q.lanes) >= q.maxTargets {
			return ErrPacketQueueFull
		}
		lane = &packetSendLane{}
	} else if lane.packets >= q.maxTargetPackets || charge > packetSendTargetMaxBytes-lane.bytes {
		return ErrPacketQueueFull
	}
	item := packetSendItem{payload: append([]byte(nil), payload...), address: address, charge: charge}
	lane.queue = append(lane.queue, item)
	lane.packets++
	lane.bytes += charge
	q.packets++
	q.bytes += charge
	if q.lanes[address] == nil {
		q.lanes[address] = lane
		q.ready <- lane // One ready entry per non-active lane; capacity is maxTargets.
	}
	if q.workers < len(q.lanes) {
		// Add and admission share mu with Stop. Wait after Stop can never race
		// with a new positive Add. Workers are a lazy bounded pool: idle lanes
		// retire, but no per-packet goroutine or unbounded exiting tail is created.
		q.workers++
		q.wg.Add(1)
		go q.run()
	}
	return nil
}

func (q *PacketSendQueue) run() {
	defer q.wg.Done()
	for {
		var lane *packetSendLane
		select {
		case <-q.ctx.Done():
			q.Stop()
			return
		case lane = <-q.ready:
		}
		q.mu.Lock()
		if q.stopped || q.ctx.Err() != nil {
			q.mu.Unlock()
			q.Stop()
			return
		}
		lane.active = true
		item := lane.queue[0]
		lane.queue[0] = packetSendItem{}
		lane.queue = lane.queue[1:]
		if len(lane.queue) == 0 {
			lane.queue = nil
		}
		q.mu.Unlock()

		err := q.send(q.ctx, item.payload, item.address)
		if err != nil && q.ctx.Err() == nil && !errors.Is(err, ErrPacketQueueFull) && !errors.Is(err, ErrPacketTargetUnavailable) {
			q.fatalOnce.Do(func() {
				q.Stop()
				q.errors <- err // Exactly once into a one-entry buffer; no blocking reader needed.
			})
		}
		q.mu.Lock()
		lane.packets--
		lane.bytes -= item.charge
		q.packets--
		q.bytes -= item.charge
		lane.active = false
		if q.stopped || q.ctx.Err() != nil || len(lane.queue) == 0 {
			q.discardQueued(lane)
			delete(q.lanes, item.address)
		} else {
			// Yield after each datagram instead of draining a hot target. No
			// other worker can select this lane until its callback has returned.
			q.ready <- lane
		}
		q.mu.Unlock()
	}
}

// discardQueued is called only under mu. An active item remains charged until
// its callback actually returns; Stop must not make live work disappear from
// the resource budget or free a lane that can still use the owner's endpoint.
func (q *PacketSendQueue) discardQueued(lane *packetSendLane) {
	for _, item := range lane.queue {
		lane.packets--
		lane.bytes -= item.charge
		q.packets--
		q.bytes -= item.charge
	}
	lane.queue = nil
}

// Stop forbids admission, cancels callbacks and discards waiting packets. It
// does not wait: an owner may need to close its socket to unblock active I/O.
func (q *PacketSendQueue) Stop() {
	q.mu.Lock()
	q.stopped = true
	q.cancel()
	for address, lane := range q.lanes {
		q.discardQueued(lane)
		if !lane.active {
			delete(q.lanes, address)
		}
	}
	q.mu.Unlock()
}

// Wait joins every target worker. Call Stop and interrupt underlying I/O first.
// In particular, do not call Wait from inside the queue's own callback.
func (q *PacketSendQueue) Wait() { q.wg.Wait() }

// Errors reports the first terminal callback error, preserving its identity.
// Queue-full and target-unavailable errors drop one packet, never retry it,
// and do not appear here. The channel is intentionally never closed.
func (q *PacketSendQueue) Errors() <-chan error { return q.errors }
