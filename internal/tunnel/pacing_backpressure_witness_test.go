package tunnel

import (
	"sync"
	"testing"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// feedbackBlockedTrace observes peer-received STREAM_DATA_BLOCKED frames for
// one selected stream. It keeps only a copied flow-control high-water mark;
// the library can reuse packet/frame pointers as soon as RecordEvent returns.
// Notifications are coalesced hints: waiters must inspect highest themselves.
type feedbackBlockedTrace struct {
	mu       sync.Mutex
	selected bool
	streamID quic.StreamID
	maximum  int64
	changed  <-chan struct{}
	notify   chan<- struct{}
}

var _ qlogwriter.Trace = (*feedbackBlockedTrace)(nil)
var _ qlogwriter.Recorder = (*feedbackBlockedTrace)(nil)

func newFeedbackBlockedTrace() *feedbackBlockedTrace {
	changed := make(chan struct{}, 1)
	return &feedbackBlockedTrace{changed: changed, notify: changed}
}

// selectStream is called before warmup so warmup frames contribute to the
// baseline later sampled by the recovery test. Changing streams starts a new
// high-water mark; choosing the same stream does not discard its history.
func (t *feedbackBlockedTrace) selectStream(streamID quic.StreamID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.selected || t.streamID != streamID {
		t.maximum = 0
	}
	t.streamID = streamID
	t.selected = true
}

func (t *feedbackBlockedTrace) highest() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.maximum
}

func (t *feedbackBlockedTrace) SupportsSchemas(schema string) bool {
	return schema == qlog.EventSchema
}

// Producers share the same in-memory observation. There is no output resource
// to close, and one producer finishing must not stop another's notifications.
func (t *feedbackBlockedTrace) AddProducer() qlogwriter.Recorder {
	return &feedbackBlockedRecorder{trace: t}
}

type feedbackBlockedRecorder struct{ trace *feedbackBlockedTrace }

func (r *feedbackBlockedRecorder) RecordEvent(event qlogwriter.Event) {
	r.trace.RecordEvent(event)
}

func (r *feedbackBlockedRecorder) Close() error { return nil }

func (t *feedbackBlockedTrace) Close() error { return nil }

func (t *feedbackBlockedTrace) RecordEvent(event qlogwriter.Event) {
	var packet qlog.PacketReceived
	switch event := event.(type) {
	case qlog.PacketReceived:
		packet = event
	case *qlog.PacketReceived:
		if event == nil {
			return
		}
		packet = *event
	default:
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.selected {
		return
	}
	advanced := false
	for _, frame := range packet.Frames {
		blocked, ok := frame.Frame.(*qlog.StreamDataBlockedFrame)
		if !ok || blocked == nil {
			continue
		}
		streamID, maximum := quic.StreamID(blocked.StreamID), int64(blocked.MaximumStreamData)
		if streamID != t.streamID || maximum <= t.maximum {
			continue
		}
		t.maximum = maximum
		advanced = true
	}
	if advanced {
		select {
		case t.notify <- struct{}{}:
		default:
		}
	}
}

func feedbackBlockedPacket(streamID quic.StreamID, maximum int64) qlog.PacketReceived {
	frame := &qlog.StreamDataBlockedFrame{StreamID: streamID}
	setFeedbackBlockedMaximum(&frame.MaximumStreamData, maximum)
	return qlog.PacketReceived{Frames: []qlog.Frame{{Frame: frame}}}
}

// qlog publicly aliases a frame whose ByteCount type lives in a library
// internal package. Infer that int64-derived type instead of importing it.
func setFeedbackBlockedMaximum[T ~int64](field *T, maximum int64) {
	*field = T(maximum)
}

func feedbackBlockedNotice(t *testing.T, trace *feedbackBlockedTrace, want bool) {
	t.Helper()
	got := false
	select {
	case _, open := <-trace.changed:
		if !open {
			t.Fatal("observer closed its shared notification channel")
		}
		got = true
	default:
	}
	if got != want {
		t.Fatalf("high-water notification = %t, want %t", got, want)
	}
}

func TestFeedbackBlockedTraceValueAndHighWatermark(t *testing.T) {
	trace := newFeedbackBlockedTrace()
	trace.RecordEvent(feedbackBlockedPacket(0, 4096))
	if got := trace.highest(); got != 0 {
		t.Fatalf("unselected stream high-water mark = %d", got)
	}
	feedbackBlockedNotice(t, trace, false)
	trace.selectStream(0)
	for _, packet := range []qlog.PacketReceived{
		feedbackBlockedPacket(4, 1<<20),
		feedbackBlockedPacket(0, 0),
		feedbackBlockedPacket(0, -1),
	} {
		trace.RecordEvent(packet)
	}
	if got := trace.highest(); got != 0 {
		t.Fatalf("irrelevant frames set high-water mark = %d", got)
	}
	feedbackBlockedNotice(t, trace, false)

	// The pinned library calls RecordEvent with a PacketReceived value, not
	// a pointer. Warmup establishes a baseline that stale frames cannot beat.
	trace.RecordEvent(feedbackBlockedPacket(0, 4096))
	if got := trace.highest(); got != 4096 {
		t.Fatalf("warmup high-water mark = %d", got)
	}
	feedbackBlockedNotice(t, trace, true)
	for _, maximum := range []int64{2048, 4096, 4096, 0, -1} {
		trace.RecordEvent(feedbackBlockedPacket(0, maximum))
	}
	if got := trace.highest(); got != 4096 {
		t.Fatalf("old or duplicate frame changed baseline to %d", got)
	}
	feedbackBlockedNotice(t, trace, false)
	trace.RecordEvent(feedbackBlockedPacket(0, 8192))
	trace.RecordEvent(feedbackBlockedPacket(0, 12288))
	if got := trace.highest(); got != 12288 {
		t.Fatalf("new blocked evidence high-water mark = %d", got)
	}
	feedbackBlockedNotice(t, trace, true)
	feedbackBlockedNotice(t, trace, false)
}

func TestFeedbackBlockedTraceCopiesScalarsAndHandlesPointers(t *testing.T) {
	trace := newFeedbackBlockedTrace()
	trace.selectStream(4)
	packet := feedbackBlockedPacket(4, 16384)
	frame := packet.Frames[0].Frame.(*qlog.StreamDataBlockedFrame)
	trace.RecordEvent(&packet)
	feedbackBlockedNotice(t, trace, true)
	frame.StreamID = 8
	frame.MaximumStreamData = 1 << 30
	packet.Frames[0].Frame = &qlog.StreamDataBlockedFrame{StreamID: 4, MaximumStreamData: 1 << 31}
	packet.Frames = nil
	if got := trace.highest(); got != 16384 {
		t.Fatalf("reusing recorded packet/frame changed copied high-water mark to %d", got)
	}
	feedbackBlockedNotice(t, trace, false)
	trace.RecordEvent((*qlog.PacketReceived)(nil))
	trace.RecordEvent(qlog.PacketReceived{Frames: []qlog.Frame{
		{},
		{Frame: (*qlog.StreamDataBlockedFrame)(nil)},
		{Frame: &qlog.PingFrame{}},
	}})
	trace.RecordEvent(qlog.PacketSent{Frames: []qlog.Frame{
		{Frame: &qlog.StreamDataBlockedFrame{StreamID: 4, MaximumStreamData: 1 << 32}},
	}})
	trace.RecordEvent(nil)
	if got := trace.highest(); got != 16384 {
		t.Fatalf("ignored event changed high-water mark to %d", got)
	}
	feedbackBlockedNotice(t, trace, false)
}

func TestFeedbackBlockedTraceSelectionAndSchemas(t *testing.T) {
	trace := newFeedbackBlockedTrace()
	for _, schema := range []string{"", "urn:ietf:params:qlog:events:quic-11", "urn:ietf:params:qlog:events:http3-12"} {
		if trace.SupportsSchemas(schema) {
			t.Fatalf("observer advertised unsupported schema %q", schema)
		}
	}
	if !trace.SupportsSchemas(qlog.EventSchema) {
		t.Fatal("observer does not support the pinned QUIC event schema")
	}
	trace.selectStream(0)
	trace.RecordEvent(feedbackBlockedPacket(0, 1024))
	feedbackBlockedNotice(t, trace, true)
	trace.selectStream(0)
	if got := trace.highest(); got != 1024 {
		t.Fatalf("reselecting the same stream discarded warmup: %d", got)
	}
	trace.selectStream(4)
	if got := trace.highest(); got != 0 {
		t.Fatalf("another stream inherited previous high-water mark: %d", got)
	}
	trace.RecordEvent(feedbackBlockedPacket(0, 1<<20))
	feedbackBlockedNotice(t, trace, false)
	trace.RecordEvent(feedbackBlockedPacket(4, 2048))
	if got := trace.highest(); got != 2048 {
		t.Fatalf("newly selected stream high-water mark = %d", got)
	}
	feedbackBlockedNotice(t, trace, true)
}

func TestFeedbackBlockedTraceConcurrentProducersAndClose(t *testing.T) {
	trace := newFeedbackBlockedTrace()
	trace.selectStream(0)
	const producers, eventsPerProducer = 8, 64
	var workers sync.WaitGroup
	start := make(chan struct{})
	workers.Add(producers)
	for index := range producers {
		go func() {
			defer workers.Done()
			<-start
			recorder := trace.AddProducer()
			for sequence := range eventsPerProducer {
				recorder.RecordEvent(feedbackBlockedPacket(0, int64(index*eventsPerProducer+sequence+1)))
				_ = trace.highest()
			}
			// Each recorder closes after its own calls finish; other producers
			// may still record events, as the Trace contract explicitly allows.
			_ = recorder.Close()
		}()
	}
	close(start)
	workers.Wait()
	if got := trace.highest(); got != producers*eventsPerProducer {
		t.Fatalf("concurrent high-water mark = %d", got)
	}
	feedbackBlockedNotice(t, trace, true)
	feedbackBlockedNotice(t, trace, false)
	if err := trace.Close(); err != nil {
		t.Fatal(err)
	}
	feedbackBlockedNotice(t, trace, false)
}

func TestFeedbackBlockedTraceProducerCloseKeepsSiblingActive(t *testing.T) {
	trace := newFeedbackBlockedTrace()
	trace.selectStream(0)
	first, sibling := trace.AddProducer(), trace.AddProducer()
	first.RecordEvent(feedbackBlockedPacket(0, 1024))
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	feedbackBlockedNotice(t, trace, true)
	feedbackBlockedNotice(t, trace, false)
	// The sibling is a distinct recorder and remains active after another
	// producer's Close. Do not call RecordEvent on the closed first recorder.
	sibling.RecordEvent(feedbackBlockedPacket(0, 2048))
	if got := trace.highest(); got != 2048 {
		t.Fatalf("closing another producer stopped the sibling: high-water mark = %d", got)
	}
	feedbackBlockedNotice(t, trace, true)
	if err := sibling.Close(); err != nil {
		t.Fatal(err)
	}
	feedbackBlockedNotice(t, trace, false)
}
