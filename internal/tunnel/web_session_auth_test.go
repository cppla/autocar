package tunnel

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/protocol"
)

func TestWebSessionBootstrapRoundTrip(t *testing.T) {
	key := mustWebAuthKey(t, webAuthTestToken)
	claims := webSessionTestClaims()
	serverNonce := bytes.Repeat([]byte{0xa5}, webAuthNonceBytes)
	proof, server, err := issueWebSessionBootstrap(
		key,
		webAuthTestBinding,
		claims,
		http.StatusOK,
		bytes.NewReader(serverNonce),
	)
	if err != nil {
		t.Fatal(err)
	}
	wantLength := len(webAuthResponseParameter) + base64.RawURLEncoding.EncodedLen(webSessionBootstrapBytes)
	if len(proof) != wantLength {
		t.Fatalf("bootstrap proof length = %d, want %d", len(proof), wantLength)
	}
	client, ok := acceptWebSessionBootstrap(
		key,
		[]string{proof},
		webAuthTestBinding,
		claims,
		http.StatusOK,
	)
	if !ok {
		t.Fatal("valid bootstrap proof was rejected")
	}
	if client.key != server.key {
		t.Fatal("client and server derived different connection keys")
	}
	if got := server.bootstrapClaims(); got != claims {
		t.Fatalf("bootstrap claims = %#v, want %#v", got, claims)
	}
	if len(proof) >= len(webAuthResponseProof(key, webAuthTestBinding, claims, http.StatusOK)) {
		t.Fatal("connection bootstrap proof is not shorter than the per-flow response proof")
	}
}

func TestWebSessionDeterministicProtocolVector(t *testing.T) {
	key := mustWebAuthKey(t, webAuthTestToken)
	claims := webSessionTestClaims()
	proof, server, err := issueWebSessionBootstrap(
		key,
		webAuthTestBinding,
		claims,
		http.StatusOK,
		bytes.NewReader(bytes.Repeat([]byte{0xa5}, webAuthNonceBytes)),
	)
	if err != nil {
		t.Fatal(err)
	}
	const wantBootstrap = "nextnonce=AaWlpaWlpaWlpaWlpaWlpaV7NsrU5PPsNqucrb9KboJD"
	if proof != wantBootstrap {
		t.Fatalf("bootstrap proof = %q, want %q", proof, wantBootstrap)
	}
	const wantSessionKey = "c9057c70413126b3827411997582b02d22c45789c22577af27dc8061410c05a6"
	if got := fmt.Sprintf("%x", server.key); got != wantSessionKey {
		t.Fatalf("session key = %s, want %s", got, wantSessionKey)
	}
	client, ok := acceptWebSessionBootstrap(
		key,
		[]string{proof},
		webAuthTestBinding,
		claims,
		http.StatusOK,
	)
	if !ok {
		t.Fatal("protocol-vector bootstrap was rejected")
	}
	header, exchange, err := client.authorization(context.Background(), webAuthTestBinding)
	if err != nil {
		t.Fatal(err)
	}
	const wantBearer = "Bearer AQAAAAAAAAAB-2OY5Y9iv0jCZnLhhsursQ"
	if header != wantBearer {
		t.Fatalf("continuation bearer = %q, want %q", header, wantBearer)
	}
	verified, ok := server.verifyAuthorization(header, webAuthTestBinding)
	if !ok || verified != exchange {
		t.Fatal("protocol-vector continuation was rejected")
	}
	const wantResponse = "nextnonce=AQAAAAAAAAABpreZ59WXi8-BTgknToBo7Q"
	if got := server.responseProof(webAuthTestBinding, verified, http.StatusBadGateway); got != wantResponse {
		t.Fatalf("continuation proof = %q, want %q", got, wantResponse)
	}
}

func TestWebSessionBootstrapAuthenticatesTranscript(t *testing.T) {
	key := mustWebAuthKey(t, webAuthTestToken)
	claims := webSessionTestClaims()
	proof, _, err := issueWebSessionBootstrap(
		key,
		webAuthTestBinding,
		claims,
		http.StatusOK,
		bytes.NewReader(bytes.Repeat([]byte{0xb1}, webAuthNonceBytes)),
	)
	if err != nil {
		t.Fatal(err)
	}

	bindings := map[string]webAuthBinding{}
	for name, mutate := range map[string]func(*webAuthBinding){
		"transport": func(binding *webAuthBinding) { binding.transport = webAuthTransportH2 },
		"method":    func(binding *webAuthBinding) { binding.method = http.MethodPost },
		"protocol":  func(binding *webAuthBinding) { binding.protocol = "connect-udp" },
		"authority": func(binding *webAuthBinding) { binding.authority = "other.example:443" },
		"path":      func(binding *webAuthBinding) { binding.path = "/other" },
	} {
		changed := webAuthTestBinding
		mutate(&changed)
		bindings[name] = changed
	}
	for name, binding := range bindings {
		t.Run(name, func(t *testing.T) {
			if _, ok := acceptWebSessionBootstrap(key, []string{proof}, binding, claims, http.StatusOK); ok {
				t.Fatal("bootstrap authenticated after binding mutation")
			}
		})
	}

	claimMutations := map[string]func(*webAuthClaims){
		"timestamp": func(value *webAuthClaims) { value.timestamp++ },
		"nonce":     func(value *webAuthClaims) { value.nonce[0]++ },
		"mode":      func(value *webAuthClaims) { value.mode = protocol.PacingFixedRate },
		"profile":   func(value *webAuthClaims) { value.profile = protocol.ProfileAggressive },
		"max tx":    func(value *webAuthClaims) { value.maxTx++ },
		"max rx":    func(value *webAuthClaims) { value.maxRx++ },
	}
	for name, mutate := range claimMutations {
		t.Run(name, func(t *testing.T) {
			changed := claims
			mutate(&changed)
			if _, ok := acceptWebSessionBootstrap(key, []string{proof}, webAuthTestBinding, changed, http.StatusOK); ok {
				t.Fatal("bootstrap authenticated after claim mutation")
			}
		})
	}

	if _, ok := acceptWebSessionBootstrap(key, []string{proof}, webAuthTestBinding, claims, http.StatusCreated); ok {
		t.Fatal("bootstrap authenticated for a different response status")
	}
	wrongKey := mustWebAuthKey(t, "fedcba9876543210fedcba9876543210")
	if _, ok := acceptWebSessionBootstrap(wrongKey, []string{proof}, webAuthTestBinding, claims, http.StatusOK); ok {
		t.Fatal("bootstrap authenticated with a different shared key")
	}
}

func TestWebSessionBootstrapRejectsMalformedProofs(t *testing.T) {
	key := mustWebAuthKey(t, webAuthTestToken)
	claims := webSessionTestClaims()
	proof, _, err := issueWebSessionBootstrap(
		key,
		webAuthTestBinding,
		claims,
		http.StatusOK,
		bytes.NewReader(bytes.Repeat([]byte{0xc1}, webAuthNonceBytes)),
	)
	if err != nil {
		t.Fatal(err)
	}
	raw := decodeWebSessionTestResponse(t, proof, webSessionBootstrapBytes)
	mutatedVersion := append([]byte(nil), raw...)
	mutatedVersion[0]++
	mutatedNonce := append([]byte(nil), raw...)
	mutatedNonce[1]++
	mutatedTag := append([]byte(nil), raw...)
	mutatedTag[len(mutatedTag)-1]++

	proofs := map[string][]string{
		"missing":          nil,
		"duplicate":        {proof, proof},
		"wrong parameter":  {"nonce=" + proof[len(webAuthResponseParameter):]},
		"base64 padding":   {proof + "="},
		"truncated":        {proof[:len(proof)-1]},
		"extra byte":       {webSessionTestResponse(append(raw, 0))},
		"version mutation": {webSessionTestResponse(mutatedVersion)},
		"nonce mutation":   {webSessionTestResponse(mutatedNonce)},
		"tag mutation":     {webSessionTestResponse(mutatedTag)},
	}
	for name, values := range proofs {
		t.Run(name, func(t *testing.T) {
			if _, ok := acceptWebSessionBootstrap(key, values, webAuthTestBinding, claims, http.StatusOK); ok {
				t.Fatal("malformed bootstrap proof authenticated")
			}
		})
	}
}

func TestWebSessionBootstrapValidationAndEntropyErrors(t *testing.T) {
	key := mustWebAuthKey(t, webAuthTestToken)
	claims := webSessionTestClaims()
	wantErr := errors.New("entropy unavailable")
	if _, _, err := issueWebSessionBootstrap(
		key,
		webAuthTestBinding,
		claims,
		http.StatusOK,
		webAuthErrorReader{err: wantErr},
	); !errors.Is(err, wantErr) {
		t.Fatalf("entropy error = %v, want %v", err, wantErr)
	}
	if _, _, err := issueWebSessionBootstrap(
		key,
		webAuthTestBinding,
		claims,
		http.StatusOK,
		bytes.NewReader(make([]byte, webAuthNonceBytes-1)),
	); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short entropy error = %v, want %v", err, io.ErrUnexpectedEOF)
	}

	invalidBinding := webAuthTestBinding
	invalidBinding.method = ""
	invalidClaims := claims
	invalidClaims.maxTx = protocol.MaxRate + 1
	negativeTimestamp := claims
	negativeTimestamp.timestamp = -1
	for name, test := range map[string]struct {
		binding webAuthBinding
		claims  webAuthClaims
		status  int
	}{
		"binding":            {binding: invalidBinding, claims: claims, status: http.StatusOK},
		"claims":             {binding: webAuthTestBinding, claims: invalidClaims, status: http.StatusOK},
		"negative timestamp": {binding: webAuthTestBinding, claims: negativeTimestamp, status: http.StatusOK},
		"status":             {binding: webAuthTestBinding, claims: claims, status: 99},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := issueWebSessionBootstrap(
				key,
				test.binding,
				test.claims,
				test.status,
				bytes.NewReader(make([]byte, webAuthNonceBytes)),
			); !errors.Is(err, errInvalidWebAuthConfig) {
				t.Fatalf("error = %v, want invalid authentication config", err)
			}
		})
	}
}

func TestWebSessionContinuationRoundTrip(t *testing.T) {
	client, server := newWebSessionTestPair(t, 0xd1)
	header, exchange, err := client.authorization(context.Background(), webAuthTestBinding)
	if err != nil {
		t.Fatal(err)
	}
	wantHeaderLength := len(webAuthBearerPrefix) + base64.RawURLEncoding.EncodedLen(webSessionTicketBytes)
	if len(header) != wantHeaderLength {
		t.Fatalf("continuation header length = %d, want %d", len(header), wantHeaderLength)
	}
	if len(header) >= len(mustWebAuthBearer(
		t,
		mustWebAuthKey(t, webAuthTestToken),
		webSessionTestTime,
		webAuthTestEntropy(
			bytes.Repeat([]byte{1}, webAuthNonceBytes),
			0,
			0,
			bytes.Repeat([]byte{2}, webAuthMinPaddingBytes),
		),
		webAuthTestBinding,
		webAuthClaims{},
	)) {
		t.Fatal("continuation credential is not shorter than a full credential")
	}
	verified, ok := server.verifyAuthorization(header, webAuthTestBinding)
	if !ok || verified != exchange || exchange.sequence != 1 {
		t.Fatalf("verified exchange = %#v, issued %#v, ok=%v", verified, exchange, ok)
	}
	if _, ok := server.verifyAuthorization(header, webAuthTestBinding); ok {
		t.Fatal("replayed continuation credential was accepted")
	}

	response := server.responseProof(webAuthTestBinding, verified, http.StatusOK)
	wantResponseLength := len(webAuthResponseParameter) + base64.RawURLEncoding.EncodedLen(webSessionResponseBytes)
	if len(response) != wantResponseLength {
		t.Fatalf("continuation response length = %d, want %d", len(response), wantResponseLength)
	}
	if !client.verifyResponseProof([]string{response}, webAuthTestBinding, exchange, http.StatusOK) {
		t.Fatal("valid continuation response proof was rejected")
	}

	_, second, err := client.authorization(context.Background(), webAuthTestBinding)
	if err != nil {
		t.Fatal(err)
	}
	if second.sequence != 2 {
		t.Fatalf("second sequence = %d, want 2", second.sequence)
	}
}

func TestWebSessionContinuationBindsEveryHTTPField(t *testing.T) {
	client, server := newWebSessionTestPair(t, 0xe1)
	header, _, err := client.authorization(context.Background(), webAuthTestBinding)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*webAuthBinding){
		"transport": func(binding *webAuthBinding) { binding.transport = webAuthTransportH2 },
		"method":    func(binding *webAuthBinding) { binding.method = http.MethodPost },
		"protocol":  func(binding *webAuthBinding) { binding.protocol = "connect-udp" },
		"authority": func(binding *webAuthBinding) { binding.authority = "other.example:443" },
		"path":      func(binding *webAuthBinding) { binding.path = "/other" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := webAuthTestBinding
			mutate(&changed)
			if _, ok := server.verifyAuthorization(header, changed); ok {
				t.Fatal("continuation authenticated after binding mutation")
			}
		})
	}
	if _, ok := server.verifyAuthorization(header, webAuthTestBinding); !ok {
		t.Fatal("failed binding attempts consumed the valid sequence")
	}
}

func TestWebSessionContinuationRejectsMalformedAndWrongSession(t *testing.T) {
	client, server := newWebSessionTestPair(t, 0xf1)
	header, _, err := client.authorization(context.Background(), webAuthTestBinding)
	if err != nil {
		t.Fatal(err)
	}
	raw := decodeWebSessionTestBearer(t, header)
	mutatedVersion := append([]byte(nil), raw...)
	mutatedVersion[0]++
	mutatedSequence := append([]byte(nil), raw...)
	mutatedSequence[8]++
	mutatedTag := append([]byte(nil), raw...)
	mutatedTag[len(mutatedTag)-1]++
	for name, candidate := range map[string]string{
		"missing":           "",
		"wrong scheme":      "Basic " + header[len(webAuthBearerPrefix):],
		"double space":      "Bearer  " + header[len(webAuthBearerPrefix):],
		"base64 padding":    header + "=",
		"truncated":         header[:len(header)-1],
		"extra byte":        webSessionTestBearer(append(raw, 0)),
		"version mutation":  webSessionTestBearer(mutatedVersion),
		"sequence mutation": webSessionTestBearer(mutatedSequence),
		"tag mutation":      webSessionTestBearer(mutatedTag),
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := server.verifyAuthorization(candidate, webAuthTestBinding); ok {
				t.Fatal("malformed continuation credential authenticated")
			}
		})
	}

	_, otherServer := newWebSessionTestPair(t, 0xf2)
	if _, ok := otherServer.verifyAuthorization(header, webAuthTestBinding); ok {
		t.Fatal("credential authenticated on a different connection session")
	}
	if _, ok := server.verifyAuthorization(header, webAuthTestBinding); !ok {
		t.Fatal("malformed attempts consumed the valid sequence")
	}
}

func TestWebSessionResponseProofBindsExchangeBindingAndStatus(t *testing.T) {
	client, server := newWebSessionTestPair(t, 0x31)
	_, exchange, err := client.authorization(context.Background(), webAuthTestBinding)
	if err != nil {
		t.Fatal(err)
	}
	proof := server.responseProof(webAuthTestBinding, exchange, http.StatusOK)
	changedBinding := webAuthTestBinding
	changedBinding.authority = "other.example:443"
	for name, valid := range map[string]bool{
		"missing":            client.verifyResponseProof(nil, webAuthTestBinding, exchange, http.StatusOK),
		"duplicate":          client.verifyResponseProof([]string{proof, proof}, webAuthTestBinding, exchange, http.StatusOK),
		"binding":            client.verifyResponseProof([]string{proof}, changedBinding, exchange, http.StatusOK),
		"sequence":           client.verifyResponseProof([]string{proof}, webAuthTestBinding, webSessionExchange{sequence: exchange.sequence + 1}, http.StatusOK),
		"status":             client.verifyResponseProof([]string{proof}, webAuthTestBinding, exchange, http.StatusBadGateway),
		"invalid exchange":   client.verifyResponseProof([]string{proof}, webAuthTestBinding, webSessionExchange{}, http.StatusOK),
		"invalid status":     client.verifyResponseProof([]string{proof}, webAuthTestBinding, exchange, 99),
		"malformed encoding": client.verifyResponseProof([]string{proof + "="}, webAuthTestBinding, exchange, http.StatusOK),
	} {
		if valid {
			t.Errorf("%s response proof authenticated", name)
		}
	}

	raw := decodeWebSessionTestResponse(t, proof, webSessionResponseBytes)
	for name, offset := range map[string]int{"version": 0, "sequence": 8, "tag": len(raw) - 1} {
		t.Run(name, func(t *testing.T) {
			changed := append([]byte(nil), raw...)
			changed[offset]++
			if client.verifyResponseProof(
				[]string{webSessionTestResponse(changed)},
				webAuthTestBinding,
				exchange,
				http.StatusOK,
			) {
				t.Fatal("tampered response proof authenticated")
			}
		})
	}
}

func TestWebSessionReplayWindowBoundaries(t *testing.T) {
	var window webSessionReplayWindow
	for _, sequence := range []uint64{1, 3, 2} {
		if !window.accept(sequence) {
			t.Fatalf("fresh sequence %d was rejected", sequence)
		}
	}
	if window.accept(2) {
		t.Fatal("duplicate out-of-order sequence was accepted")
	}
	if window.accept(0) {
		t.Fatal("zero sequence was accepted")
	}
	if !window.accept(130) {
		t.Fatal("forward window shift was rejected")
	}
	if window.accept(3) {
		t.Fatal("remembered sequence at oldest window edge was replayed")
	}
	if !window.accept(4) {
		t.Fatal("unseen sequence within the window was rejected")
	}
	if window.accept(2) {
		t.Fatal("sequence older than the replay window was accepted")
	}
	if !window.accept(10_000) {
		t.Fatal("large forward jump was rejected")
	}
	if window.accept(130) {
		t.Fatal("sequence behind a cleared large-jump window was accepted")
	}
}

func TestWebSessionConcurrentSequencesAndReplay(t *testing.T) {
	client, server := newWebSessionTestPair(t, 0x41)
	const count = 512
	type credential struct {
		header   string
		exchange webSessionExchange
	}
	credentials := make(chan credential, count)
	var issueFailures atomic.Int64
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var issueWG sync.WaitGroup
	for range count {
		issueWG.Add(1)
		go func() {
			defer issueWG.Done()
			header, exchange, err := client.authorization(ctx, webAuthTestBinding)
			if err != nil {
				issueFailures.Add(1)
				return
			}
			defer client.complete(exchange)
			verified, ok := server.verifyAuthorization(header, webAuthTestBinding)
			if !ok || verified != exchange || !client.verifyResponseProof(
				[]string{server.responseProof(webAuthTestBinding, verified, http.StatusOK)},
				webAuthTestBinding, exchange, http.StatusOK,
			) {
				issueFailures.Add(1)
				return
			}
			credentials <- credential{header: header, exchange: exchange}
		}()
	}
	issueWG.Wait()
	close(credentials)
	if failures := issueFailures.Load(); failures != 0 {
		t.Fatalf("concurrent authorization failures = %d", failures)
	}

	seen := make(map[uint64]credential, count)
	for value := range credentials {
		if _, duplicate := seen[value.exchange.sequence]; duplicate {
			t.Fatalf("duplicate allocated sequence %d", value.exchange.sequence)
		}
		seen[value.exchange.sequence] = value
	}
	if len(seen) != count {
		t.Fatalf("allocated sequences = %d, want %d", len(seen), count)
	}

	// Every legitimate request has now succeeded, but old credentials and
	// concurrent attempts to replay a consumed recent credential still fail.
	oldest := seen[1]
	if _, ok := server.verifyAuthorization(oldest.header, webAuthTestBinding); ok {
		t.Fatal("credential older than concurrent replay window was accepted")
	}

	latest := seen[count]
	var replaySuccesses atomic.Int64
	var replayWG sync.WaitGroup
	for range 64 {
		replayWG.Add(1)
		go func() {
			defer replayWG.Done()
			if _, ok := server.verifyAuthorization(latest.header, webAuthTestBinding); ok {
				replaySuccesses.Add(1)
			}
		}()
	}
	replayWG.Wait()
	if got := replaySuccesses.Load(); got != 0 {
		t.Fatalf("concurrent replay successes = %d, want 0", got)
	}
}

func TestWebSessionSequenceSpanRetainsDelayedRequest(t *testing.T) {
	client, server := newWebSessionTestPair(t, 0x42)
	oldHeader, oldest, err := client.authorization(context.Background(), webAuthTestBinding)
	if err != nil {
		t.Fatal(err)
	}
	// Keep only sequence 1 pending while all newer requests finish. A simple
	// in-flight-count semaphore would incorrectly keep allocating forever.
	for sequence := uint64(2); sequence <= webSessionReplayWindowBits; sequence++ {
		header, exchange, err := client.authorization(context.Background(), webAuthTestBinding)
		if err != nil || exchange.sequence != sequence {
			t.Fatalf("sequence %d: exchange=%v err=%v", sequence, exchange, err)
		}
		if _, ok := server.verifyAuthorization(header, webAuthTestBinding); !ok {
			t.Fatalf("sequence %d rejected", sequence)
		}
		client.complete(exchange)
	}
	blocked, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, _, err := client.authorization(blocked, webAuthTestBinding); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("request outside oldest pending window: %v", err)
	}
	client.mu.Lock()
	if client.nextSequence != webSessionReplayWindowBits+1 || len(client.pending) != 1 {
		t.Errorf("canceled waiter consumed a sequence or reservation: next=%d pending=%d", client.nextSequence, len(client.pending))
	}
	client.mu.Unlock()
	if _, ok := server.verifyAuthorization(oldHeader, webAuthTestBinding); !ok {
		t.Fatal("delayed oldest legitimate credential was rejected")
	}
	client.complete(oldest)
	header, exchange, err := client.authorization(context.Background(), webAuthTestBinding)
	if err != nil || exchange.sequence != webSessionReplayWindowBits+1 {
		t.Fatalf("resume after oldest completion: exchange=%v err=%v", exchange, err)
	}
	defer client.complete(exchange)
	if _, ok := server.verifyAuthorization(header, webAuthTestBinding); !ok {
		t.Fatal("resumed credential was rejected")
	}
}

func TestWebSessionSequenceWaiterWakeup(t *testing.T) {
	for _, closeSession := range []bool{false, true} {
		t.Run(fmt.Sprintf("close=%v", closeSession), func(t *testing.T) {
			client, _ := newWebSessionTestPair(t, 0x43)
			var oldest webSessionExchange
			for range webSessionReplayWindowBits {
				_, exchange, err := client.authorization(context.Background(), webAuthTestBinding)
				if err != nil {
					t.Fatal(err)
				}
				if oldest.sequence == 0 {
					oldest = exchange
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, exchange, err := client.authorization(ctx, webAuthTestBinding)
				client.complete(exchange)
				done <- err
			}()
			// Observe that the waiter actually reached the capacity gate before
			// releasing it; this covers the notify channel's lost-wakeup edge.
			for {
				client.mu.Lock()
				waiting := client.changed != nil
				client.mu.Unlock()
				if waiting {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("waiter did not reach sequence gate")
				case <-time.After(time.Millisecond):
				}
			}
			if closeSession {
				client.close()
			} else {
				client.complete(oldest)
				client.complete(oldest) // Duplicate release must be harmless.
			}
			select {
			case err := <-done:
				if closeSession && !errors.Is(err, net.ErrClosed) || !closeSession && err != nil {
					t.Fatalf("waiter result = %v", err)
				}
			case <-ctx.Done():
				t.Fatal("waiter did not wake")
			}
		})
	}
}

func TestWebSessionConcurrentReplayAllowsExactlyOne(t *testing.T) {
	client, server := newWebSessionTestPair(t, 0x51)
	header, _, err := client.authorization(context.Background(), webAuthTestBinding)
	if err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int64
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := server.verifyAuthorization(header, webAuthTestBinding); ok {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("concurrent replay successes = %d, want 1", got)
	}
}

func TestWebSessionSequenceExhaustionFailsClosed(t *testing.T) {
	client, _ := newWebSessionTestPair(t, 0x61)
	client.nextSequence = ^uint64(0)
	_, exchange, err := client.authorization(context.Background(), webAuthTestBinding)
	if err != nil || exchange.sequence != ^uint64(0) {
		t.Fatalf("last sequence exchange=%#v error=%v", exchange, err)
	}
	if _, _, err := client.authorization(context.Background(), webAuthTestBinding); !errors.Is(err, errWebSessionSequenceExhausted) {
		t.Fatalf("post-exhaustion error = %v", err)
	}
	if _, _, err := client.authorization(context.Background(), webAuthTestBinding); !errors.Is(err, errWebSessionSequenceExhausted) {
		t.Fatalf("repeated post-exhaustion error = %v", err)
	}
}

func TestWebServerConnectionAuthLifecycle(t *testing.T) {
	var closes atomic.Int64
	state := newWebServerConnectionAuth(func() error {
		closes.Add(1)
		return nil
	})
	if state.phaseSnapshot() != webServerConnectionAuthFresh {
		t.Fatal("new connection auth state is not fresh")
	}
	if !state.beginBootstrap() || state.beginBootstrap() {
		t.Fatal("bootstrap ownership was not exclusive")
	}
	abortedWait := make(chan *webSessionServerAuth, 1)
	go func() {
		session, ok := state.waitEstablished(context.Background())
		if !ok {
			abortedWait <- nil
			return
		}
		abortedWait <- session
	}()
	state.abortBootstrap()
	if got := <-abortedWait; got != nil || state.phaseSnapshot() != webServerConnectionAuthFresh {
		t.Fatal("aborted bootstrap did not wake waiters and restore fresh state")
	}
	if !state.beginBootstrap() {
		t.Fatal("connection could not retry after invalid full authentication")
	}
	waited := make(chan *webSessionServerAuth, 1)
	go func() {
		session, ok := state.waitEstablished(context.Background())
		if !ok {
			waited <- nil
			return
		}
		waited <- session
	}()
	_, server := newWebSessionTestPair(t, 0x71)
	if !state.establish(server) || state.establish(server) {
		t.Fatal("connection session establishment was not one-shot")
	}
	if got := <-waited; got != server {
		t.Fatal("bootstrap waiter did not receive established session")
	}
	if got, ok := state.establishedSession(); !ok || got != server {
		t.Fatal("established connection session was not returned")
	}
	state.closePhysicalConnection()
	state.closePhysicalConnection()
	if closes.Load() != 1 || state.phaseSnapshot() != webServerConnectionAuthClosed {
		t.Fatalf("close calls=%d phase=%d", closes.Load(), state.phaseSnapshot())
	}
	if _, ok := state.establishedSession(); ok {
		t.Fatal("closed connection retained an established session")
	}
}

func FuzzWebSessionVerifyAuthorization(f *testing.F) {
	client, _ := newWebSessionFuzzPair(f)
	header, _, err := client.authorization(context.Background(), webAuthTestBinding)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(header, webAuthTransportH3, http.MethodConnect, "", "example.com:443", "")
	f.Add("Bearer invalid", "invalid", "", "", "", "")
	f.Fuzz(func(t *testing.T, candidate, transport, method, requestProtocol, authority, path string) {
		_, server := newWebSessionFuzzPair(t)
		_, _ = server.verifyAuthorization(candidate, webAuthBinding{
			transport: transport,
			method:    method,
			protocol:  requestProtocol,
			authority: authority,
			path:      path,
		})
	})
}

func FuzzWebSessionAcceptBootstrap(f *testing.F) {
	key := mustWebAuthKey(f, webAuthTestToken)
	claims := webSessionTestClaims()
	proof, _, err := issueWebSessionBootstrap(
		key,
		webAuthTestBinding,
		claims,
		http.StatusOK,
		bytes.NewReader(bytes.Repeat([]byte{0x91}, webAuthNonceBytes)),
	)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(proof, http.StatusOK)
	f.Add("nextnonce=invalid", http.StatusBadGateway)
	f.Fuzz(func(t *testing.T, candidate string, status int) {
		_, _ = acceptWebSessionBootstrap(
			key,
			[]string{candidate},
			webAuthTestBinding,
			claims,
			status,
		)
	})
}

func FuzzWebSessionVerifyResponseProof(f *testing.F) {
	client, server := newWebSessionFuzzPair(f)
	_, exchange, err := client.authorization(context.Background(), webAuthTestBinding)
	if err != nil {
		f.Fatal(err)
	}
	proof := server.responseProof(webAuthTestBinding, exchange, http.StatusOK)
	f.Add(proof, http.StatusOK)
	f.Add("nextnonce=invalid", http.StatusBadGateway)
	f.Fuzz(func(t *testing.T, candidate string, status int) {
		client, _ := newWebSessionFuzzPair(t)
		_, localExchange, err := client.authorization(context.Background(), webAuthTestBinding)
		if err != nil {
			t.Fatal(err)
		}
		_ = client.verifyResponseProof(
			[]string{candidate},
			webAuthTestBinding,
			localExchange,
			status,
		)
	})
}

func webSessionTestClaims() webAuthClaims {
	return webAuthClaims{
		timestamp: webSessionTestTime.Unix(),
		nonce:     [webAuthNonceBytes]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		mode:      protocol.PacingAdaptive,
		profile:   protocol.ProfileBalanced,
		maxTx:     125_000,
		maxRx:     250_000,
	}
}

var webSessionTestTime = webAuthTestTimeValue()

func webAuthTestTimeValue() (result time.Time) {
	return time.Unix(1_700_000_000, 0)
}

func newWebSessionTestPair(t testing.TB, serverNonceByte byte) (*webSessionClientAuth, *webSessionServerAuth) {
	t.Helper()
	key := mustWebAuthKey(t, webAuthTestToken)
	claims := webSessionTestClaims()
	proof, server, err := issueWebSessionBootstrap(
		key,
		webAuthTestBinding,
		claims,
		http.StatusOK,
		bytes.NewReader(bytes.Repeat([]byte{serverNonceByte}, webAuthNonceBytes)),
	)
	if err != nil {
		t.Fatal(err)
	}
	client, ok := acceptWebSessionBootstrap(key, []string{proof}, webAuthTestBinding, claims, http.StatusOK)
	if !ok {
		t.Fatal("test bootstrap proof was rejected")
	}
	return client, server
}

func newWebSessionFuzzPair(t testing.TB) (*webSessionClientAuth, *webSessionServerAuth) {
	t.Helper()
	return newWebSessionTestPair(t, 0x81)
}

func decodeWebSessionTestBearer(t testing.TB, header string) []byte {
	t.Helper()
	if !strings.HasPrefix(header, webAuthBearerPrefix) {
		t.Fatalf("missing bearer prefix: %q", header)
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(header[len(webAuthBearerPrefix):])
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func decodeWebSessionTestResponse(t testing.TB, proof string, size int) []byte {
	t.Helper()
	if !strings.HasPrefix(proof, webAuthResponseParameter) {
		t.Fatalf("missing response parameter: %q", proof)
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(proof[len(webAuthResponseParameter):])
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != size {
		t.Fatalf("decoded response bytes = %d, want %d", len(raw), size)
	}
	return raw
}

func webSessionTestBearer(raw []byte) string {
	return webAuthBearerPrefix + base64.RawURLEncoding.EncodeToString(raw)
}

func webSessionTestResponse(raw []byte) string {
	return webAuthResponseParameter + base64.RawURLEncoding.EncodeToString(raw)
}
