package tunnel

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/cover"
)

func TestWebAltSvcReverseProxyInformationalResponses(t *testing.T) {
	for _, test := range []struct {
		name     string
		hints    []int
		implicit bool
	}{
		{name: "early-hints", hints: []int{http.StatusEarlyHints}},
		{name: "repeated-informational", hints: []int{http.StatusEarlyHints, http.StatusProcessing, http.StatusEarlyHints}},
		{name: "implicit-final", hints: []int{http.StatusEarlyHints, http.StatusEarlyHints}, implicit: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for _, status := range test.hints {
					w.Header().Set("Link", "</style.css>; rel=preload")
					w.Header().Set("Alt-Svc", `h3=":4444"; ma=86400`)
					w.WriteHeader(status)
					clear(w.Header())
				}
				w.Header().Set("Alt-Svc", `h3=":4444"; ma=86400`)
				if !test.implicit {
					w.WriteHeader(http.StatusOK)
				}
				_, _ = io.WriteString(w, "ordinary origin")
			}))
			defer origin.Close()
			originURL, err := url.Parse(origin.URL)
			if err != nil {
				t.Fatal(err)
			}
			proxy, err := cover.NewReverseProxyHandler(originURL, nil)
			if err != nil {
				t.Fatal(err)
			}
			assertWebAltSvcInformationalResponse(t, proxy, test.hints, "ordinary origin")
		})
	}
}

func TestWebAltSvcInformationalThenImplicitFinal(t *testing.T) {
	for _, mode := range []string{"write-header", "write", "flush", "read-from", "return"} {
		t.Run(mode, func(t *testing.T) {
			hints := []int{http.StatusEarlyHints, http.StatusProcessing, http.StatusEarlyHints}
			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for _, status := range hints {
					w.Header().Set("Alt-Svc", `h3=":4444"`)
					w.WriteHeader(status)
					clear(w.Header())
				}
				w.Header().Set("Alt-Svc", `h3=":4444"`)
				switch mode {
				case "write-header":
					w.WriteHeader(http.StatusOK)
				case "write":
					_, _ = w.Write([]byte("cover body"))
				case "flush":
					w.(http.Flusher).Flush()
				case "read-from":
					_, _ = w.(io.ReaderFrom).ReadFrom(strings.NewReader("cover body"))
				case "return":
					// net/http will send the empty final 200 after we return.
				}
			})
			wantBody := ""
			if mode == "write" || mode == "read-from" {
				wantBody = "cover body"
			}
			assertWebAltSvcInformationalResponse(t, handler, hints, wantBody)
		})
	}
}

func TestWebAltSvcSwitchingProtocolsCommits(t *testing.T) {
	response := httptest.NewRecorder()
	writer := &webAltSvcResponseWriter{ResponseWriter: response, value: `h3=":8443"`}
	writer.WriteHeader(http.StatusSwitchingProtocols)
	if !writer.committed {
		t.Fatal("101 must commit headers because it switches away from HTTP")
	}
	if got := response.Header().Get("Alt-Svc"); got != writer.value {
		t.Fatalf("Alt-Svc = %q, want %q", got, writer.value)
	}
}

func assertWebAltSvcInformationalResponse(t *testing.T, next http.Handler, wantHints []int, wantBody string) {
	t.Helper()
	for _, protocol := range []struct {
		name string
		h2   bool
	}{
		{name: "h1"},
		{name: "h2", h2: true},
	} {
		t.Run(protocol.name, func(t *testing.T) {
			const wantAltSvc = `h3=":8443"`
			frontend := httptest.NewUnstartedServer(&webAltSvcCover{next: next, value: wantAltSvc})
			frontend.EnableHTTP2 = protocol.h2
			frontend.StartTLS()
			defer frontend.Close()
			client := frontend.Client()
			client.Timeout = 3 * time.Second
			var gotHints []int
			var gotAltSvc []string
			trace := &httptrace.ClientTrace{
				Got1xxResponse: func(status int, header textproto.MIMEHeader) error {
					gotHints = append(gotHints, status)
					gotAltSvc = append(gotAltSvc, header.Get("Alt-Svc"))
					return nil
				},
			}
			request, err := http.NewRequest(http.MethodGet, frontend.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			wantMajor := 1
			if protocol.h2 {
				wantMajor = 2
			}
			if response.ProtoMajor != wantMajor || response.StatusCode != http.StatusOK || string(body) != wantBody {
				t.Fatalf("response = %s %d %q, want HTTP/%d 200 %q", response.Proto, response.StatusCode, body, wantMajor, wantBody)
			}
			if !reflect.DeepEqual(gotHints, wantHints) {
				t.Fatalf("informational statuses = %v, want %v", gotHints, wantHints)
			}
			for index, value := range gotAltSvc {
				if value != wantAltSvc {
					t.Errorf("informational response %d Alt-Svc = %q, want %q", index, value, wantAltSvc)
				}
			}
			if got := response.Header.Get("Alt-Svc"); got != wantAltSvc {
				t.Fatalf("final Alt-Svc = %q, want %q", got, wantAltSvc)
			}
		})
	}
}
