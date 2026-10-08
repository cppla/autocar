package tunnel

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
)

type webCloseErrorWithCustomIs struct{ inner error }

func (e *webCloseErrorWithCustomIs) Error() string { return "custom cleanup failure" }
func (e *webCloseErrorWithCustomIs) Unwrap() error { return e.inner }
func (e *webCloseErrorWithCustomIs) Is(target error) bool {
	return target == net.ErrClosed
}

type webCloseUnknownMultiError struct{ parts []error }

func (e *webCloseUnknownMultiError) Error() string   { return "unknown cleanup aggregate" }
func (e *webCloseUnknownMultiError) Unwrap() []error { return e.parts }

// A valid error need not be comparable; normalization must not compare two
// arbitrary error interface values to detect that a child changed.
type webCloseSliceError []string

func (e webCloseSliceError) Error() string { return "non-comparable cleanup failure" }

func TestNormalizeWebServerCloseErrorTrees(t *testing.T) {
	failure := errors.New("meaningful listener cleanup failure")
	wrappedFailure := fmt.Errorf("listener close: %w", failure)
	mixed := errors.Join(net.ErrClosed, failure, http.ErrServerClosed)
	wrappedMixed := fmt.Errorf("listener close: %w", mixed)
	customIs := &webCloseErrorWithCustomIs{inner: failure}
	customIsLeaf := &webCloseErrorWithCustomIs{}
	emptyAggregate := &webCloseUnknownMultiError{}
	nilAggregate := &webCloseUnknownMultiError{parts: []error{nil}}
	unknownAggregate := &webCloseUnknownMultiError{parts: []error{wrappedFailure}}
	unmodifiedJoin := errors.Join(wrappedFailure, errors.New("another failure"))
	for _, test := range []struct {
		name         string
		input        error
		wantNil      bool
		wantIdentity bool
		wantFailure  bool
		wantStripped bool
	}{
		{name: "nil", wantNil: true},
		{name: "closed", input: net.ErrClosed, wantNil: true},
		{name: "server_closed", input: http.ErrServerClosed, wantNil: true},
		{name: "wrapped_closed", input: fmt.Errorf("listen: %w", net.ErrClosed), wantNil: true},
		{name: "all_benign", input: errors.Join(net.ErrClosed, fmt.Errorf("server: %w", http.ErrServerClosed)), wantNil: true},
		{name: "wrapped_all_benign", input: fmt.Errorf("close: %w", errors.Join(net.ErrClosed, http.ErrServerClosed)), wantNil: true},
		{name: "nested_all_benign", input: errors.Join(fmt.Errorf("listener: %w", errors.Join(net.ErrClosed, http.ErrServerClosed)), net.ErrClosed), wantNil: true},
		{name: "failure", input: failure, wantIdentity: true, wantFailure: true},
		{name: "wrapped_failure", input: wrappedFailure, wantIdentity: true, wantFailure: true},
		{name: "unmodified_join", input: unmodifiedJoin, wantIdentity: true, wantFailure: true},
		{name: "mixed", input: mixed, wantFailure: true, wantStripped: true},
		{name: "nested_mixed", input: errors.Join(net.ErrClosed, mixed), wantFailure: true, wantStripped: true},
		{name: "wrapped_mixed", input: wrappedMixed, wantIdentity: true, wantFailure: true},
		{name: "nested_wrapped_mixed", input: errors.Join(net.ErrClosed, wrappedMixed), wantFailure: true},
		{name: "custom_is", input: customIs, wantIdentity: true, wantFailure: true},
		{name: "custom_is_leaf", input: customIsLeaf, wantIdentity: true},
		{name: "empty_unknown_aggregate", input: emptyAggregate, wantIdentity: true},
		{name: "nil_unknown_aggregate", input: nilAggregate, wantIdentity: true},
		{name: "unknown_aggregate", input: unknownAggregate, wantIdentity: true, wantFailure: true},
		{name: "uncomparable_leaf", input: webCloseSliceError{"failure"}},
		{name: "uncomparable_in_join", input: errors.Join(net.ErrClosed, webCloseSliceError{"failure"}), wantStripped: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := normalizeWebServerCloseError(test.input)
			if test.wantNil {
				if got != nil {
					t.Fatalf("normalization = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("normalization discarded a meaningful or unknown error")
			}
			// Only known-comparable values request this identity assertion.
			if test.wantIdentity && got != test.input {
				t.Fatal("normalization replaced an unmodified error or diagnostic wrapper")
			}
			if test.wantFailure && !errors.Is(got, failure) {
				t.Fatalf("normalization lost meaningful cleanup failure: %v", got)
			}
			if test.wantStripped && (errors.Is(got, net.ErrClosed) || errors.Is(got, http.ErrServerClosed)) {
				t.Fatalf("direct joined error retained benign leaves: %v", got)
			}
		})
	}
}
