package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/cppla/autocar/internal/cover"
	"github.com/cppla/autocar/internal/security"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

func TestCoverServerAltSvcProtocolPolicy(t *testing.T) {
	certPEM, keyPEM, err := security.GenerateSelfSignedCertificate(security.CertificateOptions{Hosts: []string{"cover.test"}})
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("append test root certificate")
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Site", "ordinary-cover")
		_, _ = io.WriteString(w, "ordinary cover\n")
	}))
	t.Cleanup(origin.Close)
	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := cover.NewReverseProxyHandler(originURL, nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, onH3 := range []bool{false, true} {
		for _, maxAge := range []int{0, 2592000} {
			t.Run(fmt.Sprintf("h3_%t/max_age_%d", onH3, maxAge), func(t *testing.T) {
				tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = tcpListener.Close() })
				_, port, err := net.SplitHostPort(tcpListener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				packet, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", port))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = packet.Close() })
				tcpHandler, h3Handler := coverServerHandlers(handler, port, maxAge, onH3)
				tcpTLS := &tls.Config{
					MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
					Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h2", "http/1.1"},
				}
				tcpServer := &http.Server{Handler: tcpHandler, TLSConfig: tcpTLS, ReadHeaderTimeout: 5 * time.Second}
				if err := http2.ConfigureServer(tcpServer, &http2.Server{}); err != nil {
					t.Fatal(err)
				}
				h3TLS := tcpTLS.Clone()
				h3TLS.NextProtos = []string{http3.NextProtoH3}
				h3Server := &http3.Server{Handler: h3Handler, TLSConfig: h3TLS}
				serverErrors := make(chan error, 2)
				t.Cleanup(func() {
					_ = h3Server.Close()
					_ = packet.Close()
					_ = tcpServer.Close()
					for range 2 {
						select {
						case err := <-serverErrors:
							if !benignServerError(err) {
								t.Errorf("cover server stopped: %v", err)
							}
						case <-time.After(5 * time.Second):
							t.Error("cover server did not stop")
						}
					}
				})
				go func() { serverErrors <- tcpServer.Serve(tls.NewListener(tcpListener, tcpTLS)) }()
				go func() { serverErrors <- h3Server.Serve(packet) }()

				altSvc := `h3=":` + port + `"`
				if maxAge > 0 {
					altSvc += fmt.Sprintf("; ma=%d", maxAge)
				}
				for index, request := range []func(context.Context, string, string, *tls.Config, probeSpec) (*http.Response, error){requestH1, requestH2, requestH3} {
					t.Run(fmt.Sprintf("h%d", index+1), func(t *testing.T) {
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						response, err := request(ctx, tcpListener.Addr().String(), "cover.test", &tls.Config{
							MinVersion: tls.VersionTLS13, RootCAs: roots,
						}, probeSpec{method: http.MethodGet, path: "/"})
						if err != nil {
							t.Fatal(err)
						}
						defer response.Body.Close()
						body, err := io.ReadAll(response.Body)
						if err != nil {
							t.Fatal(err)
						}
						if response.ProtoMajor != index+1 || response.StatusCode != http.StatusOK || string(body) != "ordinary cover\n" || response.Header.Get("X-Site") != "ordinary-cover" {
							t.Fatalf("unexpected cover response: protocol=%s status=%d body=%q headers=%v", response.Proto, response.StatusCode, body, response.Header)
						}
						want := []string{altSvc}
						if index == 2 && !onH3 {
							want = nil
						}
						if got := response.Header.Values("Alt-Svc"); !reflect.DeepEqual(got, want) {
							t.Fatalf("Alt-Svc = %q, want %q", got, want)
						}
					})
				}
			})
		}
	}
}

func TestCanonicalEvidenceRequiresMatchingAltSvc(t *testing.T) {
	left := responseEvidence{
		OK: true, Protocol: "H3", TLSVersion: "TLS1.3", ALPN: "h3", Status: 200,
		Headers: canonicalHeaders(http.Header{"Alt-Svc": {`h3=":8443"`}}), BodySHA256: "abc", BodyBytes: 3,
	}
	for _, value := range []string{"", `h3=":8444"`, `h3=":8443"; ma=2592000`, `h3=":8443"`} {
		right := left
		right.Headers = nil
		if value != "" {
			right.Headers = canonicalHeaders(http.Header{"Alt-Svc": {value}})
		}
		if got, want := evidenceEquivalent(left, right), value == `h3=":8443"`; got != want {
			t.Errorf("Alt-Svc %q equivalent = %t, want %t", value, got, want)
		}
	}
}
