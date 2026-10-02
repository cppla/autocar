package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// These deliberately expose malformed or opaque error trees. A custom Is
// match on a wrapper must not hide an unknown, empty, or nil child.
type listenerCloseSingleError struct {
	child        error
	claimsClose  bool
	contextMatch error
}

func (*listenerCloseSingleError) Error() string   { return "custom single listener close error" }
func (e *listenerCloseSingleError) Unwrap() error { return e.child }
func (e *listenerCloseSingleError) Is(target error) bool {
	return e.claimsClose && target == net.ErrClosed || e.contextMatch != nil && target == e.contextMatch
}

type listenerCloseClaimsError struct{ contextMatch error }

func (*listenerCloseClaimsError) Error() string { return "custom classified listener close error" }
func (e *listenerCloseClaimsError) Is(target error) bool {
	return target == net.ErrClosed || e.contextMatch != nil && target == e.contextMatch
}

type listenerCloseManyError struct {
	children    []error
	claimsClose bool
}

func (*listenerCloseManyError) Error() string     { return "custom multi listener close error" }
func (e *listenerCloseManyError) Unwrap() []error { return e.children }
func (e *listenerCloseManyError) Is(target error) bool {
	return e.claimsClose && target == net.ErrClosed
}

func TestIsListenerClosedErrorRequiresEveryLeaf(t *testing.T) {
	other := errors.New("listener close failed for a real unrelated reason")
	wrappedClosed := fmt.Errorf("close listener: %w", net.ErrClosed)
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil"},
		{name: "closed sentinel", err: net.ErrClosed, want: true},
		{name: "wrapped closed", err: wrappedClosed, want: true},
		{name: "nested wrapped closed", err: fmt.Errorf("outer: %w", wrappedClosed), want: true},
		{name: "network operation closed", err: &net.OpError{Op: "close", Net: "tcp", Err: net.ErrClosed}, want: true},
		{name: "all closed join", err: errors.Join(net.ErrClosed, wrappedClosed), want: true},
		{name: "nested all closed joins", err: errors.Join(wrappedClosed, errors.Join(net.ErrClosed, &net.OpError{Op: "close", Err: wrappedClosed})), want: true},
		{name: "wrapped all closed join", err: fmt.Errorf("outer: %w", errors.Join(net.ErrClosed, wrappedClosed)), want: true},
		{name: "custom closed single", err: &listenerCloseSingleError{child: wrappedClosed}, want: true},
		{name: "custom all closed multi", err: &listenerCloseManyError{children: []error{net.ErrClosed, wrappedClosed}}, want: true},
		{name: "custom closed-only leaf", err: &listenerCloseClaimsError{}, want: true},
		{name: "leaf closed and canceled", err: &listenerCloseClaimsError{contextMatch: context.Canceled}},
		{name: "leaf closed and deadline", err: &listenerCloseClaimsError{contextMatch: context.DeadlineExceeded}},
		{name: "closed child with canceled wrapper", err: &listenerCloseSingleError{child: net.ErrClosed, contextMatch: context.Canceled}},
		{name: "closed child with deadline wrapper", err: &listenerCloseSingleError{child: net.ErrClosed, contextMatch: context.DeadlineExceeded}},
		{name: "closed join with dual-classified leaf", err: errors.Join(net.ErrClosed, &listenerCloseClaimsError{contextMatch: context.Canceled})},
		{name: "opaque unknown", err: other},
		{name: "opaque closed text", err: errors.New(net.ErrClosed.Error())},
		{name: "wrapped unknown", err: fmt.Errorf("close listener: %w", other)},
		{name: "operation unknown", err: &net.OpError{Op: "close", Net: "tcp", Err: other}},
		{name: "operation nil child", err: &net.OpError{Op: "close", Net: "tcp"}},
		{name: "nil single unwrap", err: &listenerCloseSingleError{}},
		{name: "nil single claiming closed", err: &listenerCloseSingleError{claimsClose: true}},
		{name: "nil multi unwrap", err: &listenerCloseManyError{}},
		{name: "empty multi unwrap", err: &listenerCloseManyError{children: []error{}}},
		{name: "empty multi claiming closed", err: &listenerCloseManyError{children: []error{}, claimsClose: true}},
		{name: "multi nil child only", err: &listenerCloseManyError{children: []error{nil}}},
		{name: "multi closed then nil", err: &listenerCloseManyError{children: []error{net.ErrClosed, nil}}},
		{name: "multi nil then closed", err: &listenerCloseManyError{children: []error{nil, net.ErrClosed}}},
		{name: "unknown child claiming closed", err: &listenerCloseSingleError{child: other, claimsClose: true}},
		{name: "mixed children claiming closed", err: &listenerCloseManyError{children: []error{net.ErrClosed, other}, claimsClose: true}},
		{name: "nested empty beside closed", err: errors.Join(net.ErrClosed, &listenerCloseManyError{})},
	}
	for _, failure := range []struct {
		name string
		err  error
	}{
		{name: "generic", err: other},
		{name: "context cancellation", err: context.Canceled},
		{name: "context deadline", err: context.DeadlineExceeded},
	} {
		cases = append(cases,
			struct {
				name string
				err  error
				want bool
			}{name: "closed then " + failure.name, err: errors.Join(net.ErrClosed, failure.err)},
			struct {
				name string
				err  error
				want bool
			}{name: failure.name + " then closed", err: errors.Join(failure.err, net.ErrClosed)},
			struct {
				name string
				err  error
				want bool
			}{name: "wrapped mixed " + failure.name, err: fmt.Errorf("outer: %w", errors.Join(wrappedClosed, failure.err))},
		)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A bool classification must not prune a mixed error or rewrite
			// its caller-owned multi-error slice while deciding to preserve it.
			var originalChildren []error
			joined, isMulti := tc.err.(interface{ Unwrap() []error })
			if isMulti {
				originalChildren = append([]error(nil), joined.Unwrap()...)
			}
			if got := isListenerClosedError(tc.err); got != tc.want {
				t.Fatalf("isListenerClosedError(%T) = %t, want %t", tc.err, got, tc.want)
			}
			if isMulti {
				children := joined.Unwrap()
				if len(children) != len(originalChildren) {
					t.Fatal("classification changed the original error tree")
				}
				for i := range children {
					if children[i] != originalChildren[i] {
						t.Fatal("classification replaced an original error child")
					}
				}
			}
		})
	}
}

func TestLifecycleForcedShutdownPreservesContextErrorIdentity(t *testing.T) {
	for _, mode := range []string{"canceled", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			lifecycle := newServerLifecycle(1)
			upstream, peer := net.Pipe()
			defer upstream.Close()
			defer peer.Close()
			tracked := &trackedConn{Conn: upstream, tracker: lifecycle.tracker}
			if !lifecycle.tracker.add(tracked) {
				t.Fatal("test connection was not admitted")
			}
			connectionCtx := tracked.connectionContext(context.Background())
			if connectionCtx.Err() != nil {
				t.Fatal("admitted connection context was already canceled")
			}
			var ctx context.Context
			var cancel context.CancelFunc
			if mode == "deadline" {
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			} else {
				ctx, cancel = context.WithCancel(context.Background())
				cancel()
			}
			defer cancel()
			// With no listener error to join, preserve the original context
			// sentinel while still closing the active tracked connection.
			if err := lifecycle.shutdown(ctx); err != ctx.Err() {
				t.Fatalf("forced Shutdown error = %T %v, want original %T %v", err, err, ctx.Err(), ctx.Err())
			}
			if connectionCtx.Err() != context.Canceled {
				t.Fatalf("forced socket close did not cancel its connection context: %v", connectionCtx.Err())
			}
			lifecycle.tracker.mu.Lock()
			count, zero := len(lifecycle.tracker.conns), lifecycle.tracker.zero
			lifecycle.tracker.mu.Unlock()
			if count != 0 {
				t.Fatalf("forced Shutdown retained %d tracked connections", count)
			}
			select {
			case <-zero:
			default:
				t.Fatal("forced Shutdown did not release the tracker zero signal")
			}
		})
	}
}
