package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/transport"
)

func TestWebSessionHandlerKeepsCoverConnectionFreshUntilValidFullAuth(t *testing.T) {
	var destinationDials atomic.Int64
	core, err := newServerCore(
		testToken,
		transport.DialFunc(func(context.Context, string, string) (net.Conn, error) {
			destinationDials.Add(1)
			return nil, errors.New("test destination unavailable")
		}),
		time.Second,
		time.Second,
		4,
	)
	if err != nil {
		t.Fatal(err)
	}
	key := mustWebAuthKey(t, testToken)
	verifier := mustWebAuthVerifier(t, key, time.Now, 8)
	var covers atomic.Int64
	handler := &webTunnelHandler{
		auth: verifier,
		core: core,
		cover: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			covers.Add(1)
			if request.Header.Get("Proxy-Authorization") != "" {
				t.Error("cover handler observed authentication credential")
			}
			writer.WriteHeader(http.StatusTeapot)
		}),
	}
	var closes atomic.Int64
	connection := newWebServerConnectionAuth(func() error {
		closes.Add(1)
		return nil
	})
	withConnection := func(request *http.Request) *http.Request {
		ctx := context.WithValue(request.Context(), webServerConnectionAuthContextKey{}, connection)
		return request.WithContext(ctx)
	}
	target := "example.com:443"

	for _, bearer := range []string{"", "Bearer invalid"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, withConnection(newWebH2ConnectRequest(target, bearer)))
		if response.Code != http.StatusTeapot {
			t.Fatalf("cover status = %d, want %d", response.Code, http.StatusTeapot)
		}
		if connection.phaseSnapshot() != webServerConnectionAuthFresh || closes.Load() != 0 {
			t.Fatalf("invalid full auth changed connection phase=%d closes=%d", connection.phaseSnapshot(), closes.Load())
		}
	}

	get := httptest.NewRequest(http.MethodGet, "https://cover.invalid/ordinary", nil)
	get.ProtoMajor = 2
	get.TLS = new(tls.ConnectionState)
	get.TLS.Version = tls.VersionTLS13
	getResponse := httptest.NewRecorder()
	handler.ServeHTTP(getResponse, withConnection(get))
	if getResponse.Code != http.StatusTeapot || connection.phaseSnapshot() != webServerConnectionAuthFresh {
		t.Fatalf("ordinary cover request status=%d phase=%d", getResponse.Code, connection.phaseSnapshot())
	}

	binding := webAuthBinding{transport: webAuthTransportH2, method: http.MethodConnect, authority: target}
	fullBearer, fullClaims, err := newWebAuthSigner(key, nil, nil).authorization(binding, webAuthClaims{})
	if err != nil {
		t.Fatal(err)
	}
	bootstrapResponse := httptest.NewRecorder()
	handler.ServeHTTP(bootstrapResponse, withConnection(newWebH2ConnectRequest(target, fullBearer)))
	if bootstrapResponse.Code != http.StatusBadGateway {
		t.Fatalf("bootstrap response status = %d, want %d", bootstrapResponse.Code, http.StatusBadGateway)
	}
	clientSession, ok := acceptWebSessionBootstrap(
		key,
		bootstrapResponse.Header().Values(webAuthResponseHeader),
		binding,
		fullClaims,
		http.StatusBadGateway,
	)
	if !ok || connection.phaseSnapshot() != webServerConnectionAuthEstablished {
		t.Fatalf("authenticated error did not establish session: ok=%v phase=%d", ok, connection.phaseSnapshot())
	}

	shortBearer, exchange, err := clientSession.authorization(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	continuationResponse := httptest.NewRecorder()
	handler.ServeHTTP(continuationResponse, withConnection(newWebH2ConnectRequest(target, shortBearer)))
	if continuationResponse.Code != http.StatusBadGateway || !clientSession.verifyResponseProof(
		continuationResponse.Header().Values(webAuthResponseHeader),
		binding,
		exchange,
		http.StatusBadGateway,
	) {
		t.Fatal("continuation authenticated error did not carry a valid short proof")
	}
	if destinationDials.Load() != 2 || covers.Load() != 3 || closes.Load() != 0 {
		t.Fatalf("dials=%d covers=%d closes=%d", destinationDials.Load(), covers.Load(), closes.Load())
	}

	invalidShortResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidShortResponse, withConnection(newWebH2ConnectRequest(target, "Bearer invalid")))
	if invalidShortResponse.Code != http.StatusTeapot || closes.Load() != 0 ||
		connection.phaseSnapshot() != webServerConnectionAuthEstablished {
		t.Fatalf(
			"invalid short result status=%d closes=%d phase=%d",
			invalidShortResponse.Code,
			closes.Load(),
			connection.phaseSnapshot(),
		)
	}
}
