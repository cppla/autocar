package tunnel

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

func TestWebH3FinalResponsePreservesFinalMessage(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusBadGateway} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			body := &webH3ResponseTestBody{reader: strings.NewReader("final body")}
			final := &http.Response{
				StatusCode: status,
				Header: http.Header{
					webAuthResponseHeader: {"final-authenticated-proof"},
					"X-Final":             {"retained"},
				},
				Trailer:       http.Header{"X-End-Trailer": {"retained-trailer"}},
				Body:          body,
				ContentLength: 10,
			}
			stream := newWebH3ResponseTestStream(t)
			for _, status := range []int{http.StatusContinue, http.StatusProcessing, http.StatusEarlyHints} {
				stream.steps = append(stream.steps, webH3ResponseTestStep{response: stream.informational(status)})
			}
			stream.steps = append(stream.steps,
				webH3ResponseTestStep{response: final},
				webH3ResponseTestStep{err: errors.New("must not read past final")},
			)
			response, err := readWebH3FinalResponse(stream)
			if err != nil || response != final {
				t.Fatalf("final response = %p/%v, want original %p", response, err, final)
			}
			if len(response.Header) != 2 || response.Header.Get(webAuthResponseHeader) != "final-authenticated-proof" || response.Header.Get("X-Final") != "retained" {
				t.Fatalf("final headers were replaced or mixed with informational headers: %v", response.Header)
			}
			if response.Body != body || response.ContentLength != 10 || response.Trailer.Get("X-End-Trailer") != "retained-trailer" {
				t.Fatalf("final body, length, or trailer changed: %+v", response)
			}
			if body.reads != 0 || body.closes != 0 {
				t.Fatal("helper read or closed the final response body")
			}
			stream.assertUnchanged(t, 4, false)
			payload, err := io.ReadAll(response.Body)
			if err != nil || string(payload) != "final body" {
				t.Fatalf("returned final body = %q/%v", payload, err)
			}
		})
	}
}

func TestWebH3FinalResponseDiscardsInformationalProof(t *testing.T) {
	stream := newWebH3ResponseTestStream(t)
	final := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"X-Final": {"retained"}}, Body: http.NoBody}
	stream.steps = []webH3ResponseTestStep{
		{response: stream.informational(http.StatusEarlyHints)},
		{response: final},
	}
	response, err := readWebH3FinalResponse(stream)
	if err != nil || response != final || len(response.Header.Values(webAuthResponseHeader)) != 0 || response.Header.Get("X-Informational") != "" {
		t.Fatalf("informational fields reached final response: response=%+v err=%v", response, err)
	}
	stream.assertUnchanged(t, 2, false)
}

func TestWebH3FinalResponseInformationalLimit(t *testing.T) {
	for _, count := range []int{0, 1, webH3MaxInformationalResponses, webH3MaxInformationalResponses + 1} {
		t.Run(strconv.Itoa(count)+"-hints", func(t *testing.T) {
			stream := newWebH3ResponseTestStream(t)
			for range count {
				stream.steps = append(stream.steps, webH3ResponseTestStep{response: stream.informational(http.StatusEarlyHints)})
			}
			final := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody}
			stream.steps = append(stream.steps, webH3ResponseTestStep{response: final})
			response, err := readWebH3FinalResponse(stream)
			if count > webH3MaxInformationalResponses {
				if response != nil || err == nil {
					t.Fatalf("excessive hints accepted: response=%+v err=%v", response, err)
				}
				stream.assertUnchanged(t, count, true)
				return
			}
			if err != nil || response != final {
				t.Fatalf("allowed hints rejected: response=%p err=%v, want %p", response, err, final)
			}
			stream.assertUnchanged(t, count+1, false)
		})
	}
}

func TestWebH3FinalResponseSwitchingProtocolsIsTerminal(t *testing.T) {
	for _, precedingHint := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "after-hint"}[precedingHint], func(t *testing.T) {
			stream := newWebH3ResponseTestStream(t)
			if precedingHint {
				stream.steps = append(stream.steps, webH3ResponseTestStep{response: stream.informational(http.StatusEarlyHints)})
			}
			terminalBody := &webH3ResponseTestBody{reader: strings.NewReader("terminal body")}
			terminal := &http.Response{StatusCode: http.StatusSwitchingProtocols, Header: http.Header{"X-Terminal": {"retained"}}, Body: terminalBody}
			stream.steps = append(stream.steps,
				webH3ResponseTestStep{response: terminal},
				webH3ResponseTestStep{err: errors.New("must not read past 101")},
			)
			response, err := readWebH3FinalResponse(stream)
			if err != nil || response != terminal || response.Body != terminalBody || response.Header.Get("X-Terminal") != "retained" {
				t.Fatalf("101 terminal response changed: response=%+v err=%v", response, err)
			}
			reads := 1
			if precedingHint {
				reads++
			}
			stream.assertUnchanged(t, reads, false)
			if terminalBody.reads != 0 || terminalBody.closes != 0 {
				t.Fatal("helper read or closed the terminal response body")
			}
		})
	}
}

func TestWebH3FinalResponseReadFailures(t *testing.T) {
	readError := errors.New("response read failed")
	for _, test := range []struct {
		name          string
		precedingHint bool
		response      *http.Response
		err           error
	}{
		{name: "early-error", err: readError},
		{name: "response-and-error", response: &http.Response{StatusCode: http.StatusOK}, err: readError},
		{name: "error-after-hint", precedingHint: true, err: readError},
		{name: "canceled-after-hint", precedingHint: true, err: context.Canceled},
		{name: "deadline-after-hint", precedingHint: true, err: context.DeadlineExceeded},
		{name: "nil-response"},
		{name: "nil-response-after-hint", precedingHint: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			stream := newWebH3ResponseTestStream(t)
			if test.precedingHint {
				stream.steps = append(stream.steps, webH3ResponseTestStep{response: stream.informational(http.StatusEarlyHints)})
			}
			stream.steps = append(stream.steps,
				webH3ResponseTestStep{response: test.response, err: test.err},
				webH3ResponseTestStep{err: errors.New("must not read past failure")},
			)
			response, err := readWebH3FinalResponse(stream)
			if response != nil || err == nil {
				t.Fatalf("failed read accepted: response=%+v err=%v", response, err)
			}
			if test.err != nil && err != test.err {
				t.Fatalf("read error identity changed: %v, want original %v", err, test.err)
			}
			reads := 1
			if test.precedingHint {
				reads++
			}
			stream.assertUnchanged(t, reads, false)
		})
	}
}

type webH3ResponseTestStep struct {
	response *http.Response
	err      error
}

type webH3ResponseTestStream struct {
	t               *testing.T
	steps           []webH3ResponseTestStep
	reads           int
	readCancel      []quic.StreamErrorCode
	writeCancel     []quic.StreamErrorCode
	infoBodies      []*webH3ResponseTestBody
	deadline        time.Time
	initialDeadline time.Time
	deadlineCalls   int
}

func newWebH3ResponseTestStream(t *testing.T) *webH3ResponseTestStream {
	deadline := time.Now().Add(time.Second)
	return &webH3ResponseTestStream{t: t, deadline: deadline, initialDeadline: deadline}
}

func (s *webH3ResponseTestStream) ReadResponse() (*http.Response, error) {
	s.t.Helper()
	if s.reads >= len(s.steps) {
		s.t.Fatal("read past configured response sequence")
	}
	step := s.steps[s.reads]
	s.reads++
	return step.response, step.err
}

func (s *webH3ResponseTestStream) CancelRead(code quic.StreamErrorCode) {
	s.readCancel = append(s.readCancel, code)
}

func (s *webH3ResponseTestStream) CancelWrite(code quic.StreamErrorCode) {
	s.writeCancel = append(s.writeCancel, code)
}

func (s *webH3ResponseTestStream) SetDeadline(deadline time.Time) error {
	s.deadlineCalls++
	s.deadline = deadline
	return nil
}

func (s *webH3ResponseTestStream) informational(status int) *http.Response {
	body := &webH3ResponseTestBody{reader: strings.NewReader("must not drain informational body")}
	s.infoBodies = append(s.infoBodies, body)
	return &http.Response{StatusCode: status, Header: http.Header{
		webAuthResponseHeader: {"fictional-informational-proof"},
		"X-Informational":     {"not-final"},
	}, Body: body}
}

func (s *webH3ResponseTestStream) assertUnchanged(t *testing.T, reads int, excessive bool) {
	t.Helper()
	if s.reads != reads {
		t.Errorf("ReadResponse calls = %d, want %d", s.reads, reads)
	}
	if s.deadlineCalls != 0 || s.deadline != s.initialDeadline {
		t.Error("helper reset the existing request deadline")
	}
	for index, body := range s.infoBodies {
		if body.reads != 0 || body.closes != 0 {
			t.Errorf("informational body %d read=%d close=%d, want neither", index, body.reads, body.closes)
		}
	}
	if excessive {
		wantCode := quic.StreamErrorCode(http3.ErrCodeExcessiveLoad)
		if len(s.readCancel) != 1 || s.readCancel[0] != wantCode || len(s.writeCancel) != 1 || s.writeCancel[0] != wantCode {
			t.Errorf("excess cancellation read=%v write=%v, want one %d each", s.readCancel, s.writeCancel, wantCode)
		}
	} else if len(s.readCancel) != 0 || len(s.writeCancel) != 0 {
		t.Errorf("unexpected cancellation read=%v write=%v", s.readCancel, s.writeCancel)
	}
}

type webH3ResponseTestBody struct {
	reader io.Reader
	reads  int
	closes int
}

func (b *webH3ResponseTestBody) Read(p []byte) (int, error) {
	b.reads++
	return b.reader.Read(p)
}

func (b *webH3ResponseTestBody) Close() error {
	b.closes++
	return nil
}
