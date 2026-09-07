package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestFingerprintProfileValidation(t *testing.T) {
	for _, input := range []FingerprintProfile{"", FingerprintChrome133} {
		got, err := normalizeFingerprintProfile(input)
		if err != nil {
			t.Fatal(err)
		}
		if got != FingerprintChrome133 {
			t.Fatalf("normalizeFingerprintProfile(%q) = %q, want %q", input, got, FingerprintChrome133)
		}
	}
	if got, err := normalizeFingerprintProfile(FingerprintNative); err != nil || got != FingerprintNative {
		t.Fatalf("native profile = %q, %v", got, err)
	}
	if _, err := normalizeFingerprintProfile("chrome-current"); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unversioned profile error = %v", err)
	}
}

func TestH3FingerprintProfileValidation(t *testing.T) {
	for _, input := range []H3FingerprintProfile{"", H3FingerprintChrome202608} {
		got, err := normalizeH3FingerprintProfile(input)
		if err != nil {
			t.Fatal(err)
		}
		if got != H3FingerprintChrome202608 {
			t.Fatalf("normalizeH3FingerprintProfile(%q) = %q, want %q", input, got, H3FingerprintChrome202608)
		}
	}
	if got, err := normalizeH3FingerprintProfile(H3FingerprintNative); err != nil || got != H3FingerprintNative {
		t.Fatalf("native H3 profile = %q, %v", got, err)
	}
	if _, err := normalizeH3FingerprintProfile("chrome-current"); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unversioned H3 profile error = %v", err)
	}
}

func TestChrome133ClientHelloHasVersionedBrowserShape(t *testing.T) {
	record := captureWebH2ClientHello(t, FingerprintChrome133)
	hello, err := parseTLSClientHello(record)
	if err != nil {
		t.Fatal(err)
	}

	wantCiphers := []uint16{
		0x1301, // TLS_AES_128_GCM_SHA256
		0x1302, // TLS_AES_256_GCM_SHA384
		0x1303, // TLS_CHACHA20_POLY1305_SHA256
		0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
		0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
	}
	if got := withoutGREASE(hello.cipherSuites); !reflect.DeepEqual(got, wantCiphers) {
		t.Fatalf("non-GREASE cipher suites = %#v, want %#v", got, wantCiphers)
	}

	// These are the stable, non-GREASE extensions in uTLS v1.8.2's fixed
	// Chrome 133 reference. Chrome shuffles extension order, so the test checks
	// membership rather than freezing one random permutation.
	for _, extension := range []uint16{
		0,     // server_name
		5,     // status_request
		10,    // supported_groups
		11,    // ec_point_formats
		13,    // signature_algorithms
		16,    // ALPN
		18,    // signed_certificate_timestamp
		23,    // extended_master_secret
		27,    // compress_certificate
		35,    // session_ticket
		43,    // supported_versions
		45,    // psk_key_exchange_modes
		51,    // key_share
		17613, // application_settings (new Chrome codepoint)
		0xfe0d,
		0xff01,
	} {
		if !containsUint16(hello.extensions, extension) {
			t.Errorf("Chrome 133 ClientHello omitted extension %#x", extension)
		}
	}
	if !containsGREASE(hello.cipherSuites) || !containsGREASE(hello.extensions) {
		t.Fatalf("Chrome 133 ClientHello omitted GREASE: ciphers=%#v extensions=%#v", hello.cipherSuites, hello.extensions)
	}
	if got := hello.alpn; !reflect.DeepEqual(got, []string{webH2ALPN, webHTTP11ALPN}) {
		t.Fatalf("ALPN = %q, want [h2 http/1.1]", got)
	}
}

func TestChrome133TLSConfigRemainsVerified(t *testing.T) {
	roots := x509.NewCertPool()
	input := &tls.Config{
		ServerName:         "cover.example",
		RootCAs:            roots,
		NextProtos:         []string{"autocar/2"},
		ClientSessionCache: tls.NewLRUClientSessionCache(64),
	}
	cache := newWebH2UTLSSessionCache(input)
	got, err := chrome133UTLSConfig(input, cache)
	if err != nil {
		t.Fatal(err)
	}
	if got.InsecureSkipVerify {
		t.Fatal("Chrome profile disabled certificate verification")
	}
	if got.ServerName != input.ServerName || got.RootCAs == nil {
		t.Fatalf("verification inputs not preserved: server=%q roots=%v", got.ServerName, got.RootCAs != nil)
	}
	if got.RootCAs == input.RootCAs {
		t.Fatal("Chrome profile retained a caller-mutable root pool")
	}
	if !reflect.DeepEqual(got.NextProtos, []string{webH2ALPN, webHTTP11ALPN}) {
		t.Fatalf("uTLS NextProtos = %q", got.NextProtos)
	}
	if got.ClientSessionCache == nil || got.SessionTicketsDisabled {
		t.Fatal("Chrome profile unexpectedly disabled ordinary TLS session tickets")
	}

	insecure := input.Clone()
	insecure.InsecureSkipVerify = true
	if _, err := chrome133UTLSConfig(insecure, cache); err == nil {
		t.Fatal("Chrome profile accepted InsecureSkipVerify")
	}
	callback := input.Clone()
	callback.VerifyConnection = func(tls.ConnectionState) error { return nil }
	if _, err := chrome133UTLSConfig(callback, cache); err == nil {
		t.Fatal("Chrome profile silently dropped VerifyConnection")
	}
}

func TestChrome133SessionCacheFollowsCallerPolicyAndIsReusable(t *testing.T) {
	enabled := &tls.Config{ClientSessionCache: tls.NewLRUClientSessionCache(2)}
	cache := newWebH2UTLSSessionCache(enabled)
	if cache == nil {
		t.Fatal("enabled standard TLS resumption did not create a uTLS cache")
	}
	first, err := chrome133UTLSConfig(enabled, cache)
	if err != nil {
		t.Fatal(err)
	}
	second, err := chrome133UTLSConfig(enabled, cache)
	if err != nil {
		t.Fatal(err)
	}
	if first.ClientSessionCache != second.ClientSessionCache || first.ClientSessionCache != cache {
		t.Fatal("uTLS cache was not reused across connections")
	}

	disabled := enabled.Clone()
	disabled.SessionTicketsDisabled = true
	disabledCache := newWebH2UTLSSessionCache(disabled)
	if disabledCache != nil {
		t.Fatal("disabled session tickets created a cache")
	}
	got, err := chrome133UTLSConfig(disabled, disabledCache)
	if err != nil {
		t.Fatal(err)
	}
	if !got.SessionTicketsDisabled || got.ClientSessionCache != nil {
		t.Fatalf("disabled session policy = disabled %v cache %v", got.SessionTicketsDisabled, got.ClientSessionCache)
	}
}

func TestChrome133ProfileRejectsTLS12Negotiation(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	serverTLS.MinVersion = tls.VersionTLS12
	serverTLS.MaxVersion = tls.VersionTLS12
	serverTLS.NextProtos = []string{webH2ALPN, webHTTP11ALPN}
	clientTLS, err := webClientTLSConfig(clientTLS, "127.0.0.1:443", webH2ALPN)
	if err != nil {
		t.Fatal(err)
	}
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	server := tls.Server(serverSide, serverTLS)
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Handshake() }()

	client, err := newWebH2TLSClientConn(clientSide, clientTLS, FingerprintChrome133, newWebH2UTLSSessionCache(clientTLS))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.HandshakeContext(ctx); err == nil {
		t.Fatal("Chrome profile accepted a TLS 1.2-only server")
	}
	_ = clientSide.Close()
	select {
	case <-serverDone:
	case <-ctx.Done():
		t.Fatal("TLS 1.2 rejection did not unblock the server")
	}
}

type parsedClientHello struct {
	cipherSuites []uint16
	extensions   []uint16
	alpn         []string
}

func captureWebH2ClientHello(t *testing.T, profile FingerprintProfile) []byte {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	recordCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		var header [5]byte
		if _, err := io.ReadFull(server, header[:]); err != nil {
			errCh <- err
			return
		}
		length := int(binary.BigEndian.Uint16(header[3:]))
		payload := make([]byte, length)
		if _, err := io.ReadFull(server, payload); err != nil {
			errCh <- err
			return
		}
		recordCh <- append(header[:], payload...)
		_ = server.Close()
	}()

	config := &tls.Config{
		ServerName: "cover.example",
		RootCAs:    x509.NewCertPool(),
	}
	tlsConn, err := newWebH2TLSClientConn(client, config, profile, newWebH2UTLSSessionCache(config))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err == nil {
		t.Fatal("capture peer unexpectedly completed TLS handshake")
	}
	select {
	case record := <-recordCh:
		return record
	case err := <-errCh:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	return nil
}

func parseTLSClientHello(record []byte) (parsedClientHello, error) {
	var result parsedClientHello
	if len(record) < 9 || record[0] != 22 {
		return result, errors.New("not a TLS handshake record")
	}
	recordLength := int(binary.BigEndian.Uint16(record[3:5]))
	if recordLength != len(record)-5 || record[5] != 1 {
		return result, errors.New("not a complete ClientHello record")
	}
	handshakeLength := int(record[6])<<16 | int(record[7])<<8 | int(record[8])
	if handshakeLength+4 > recordLength {
		return result, io.ErrUnexpectedEOF
	}
	data := record[9 : 9+handshakeLength]
	if len(data) < 35 {
		return result, io.ErrUnexpectedEOF
	}
	data = data[34:] // legacy_version and random
	var err error
	data, err = skipUint8Vector(data)
	if err != nil {
		return result, err
	}
	var ciphers []byte
	ciphers, data, err = takeUint16Vector(data)
	if err != nil || len(ciphers)%2 != 0 {
		return result, io.ErrUnexpectedEOF
	}
	for len(ciphers) > 0 {
		result.cipherSuites = append(result.cipherSuites, binary.BigEndian.Uint16(ciphers[:2]))
		ciphers = ciphers[2:]
	}
	data, err = skipUint8Vector(data) // compression methods
	if err != nil {
		return result, err
	}
	var extensions []byte
	extensions, _, err = takeUint16Vector(data)
	if err != nil {
		return result, err
	}
	for len(extensions) > 0 {
		if len(extensions) < 4 {
			return result, io.ErrUnexpectedEOF
		}
		id := binary.BigEndian.Uint16(extensions[:2])
		length := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if length > len(extensions) {
			return result, io.ErrUnexpectedEOF
		}
		body := extensions[:length]
		extensions = extensions[length:]
		result.extensions = append(result.extensions, id)
		if id == 16 {
			result.alpn, err = parseALPNExtension(body)
			if err != nil {
				return result, err
			}
		}
	}
	return result, nil
}

func parseALPNExtension(data []byte) ([]string, error) {
	protocols, rest, err := takeUint16Vector(data)
	if err != nil || len(rest) != 0 {
		return nil, io.ErrUnexpectedEOF
	}
	var result []string
	for len(protocols) > 0 {
		length := int(protocols[0])
		protocols = protocols[1:]
		if length == 0 || length > len(protocols) {
			return nil, io.ErrUnexpectedEOF
		}
		result = append(result, string(protocols[:length]))
		protocols = protocols[length:]
	}
	return result, nil
}

func skipUint8Vector(data []byte) ([]byte, error) {
	if len(data) < 1 || int(data[0])+1 > len(data) {
		return nil, io.ErrUnexpectedEOF
	}
	return data[int(data[0])+1:], nil
}

func takeUint16Vector(data []byte) (vector, rest []byte, err error) {
	if len(data) < 2 {
		return nil, nil, io.ErrUnexpectedEOF
	}
	length := int(binary.BigEndian.Uint16(data[:2]))
	if length > len(data)-2 {
		return nil, nil, io.ErrUnexpectedEOF
	}
	return data[2 : 2+length], data[2+length:], nil
}

func withoutGREASE(values []uint16) []uint16 {
	result := make([]uint16, 0, len(values))
	for _, value := range values {
		if !isGREASE(value) {
			result = append(result, value)
		}
	}
	return result
}

func containsGREASE(values []uint16) bool {
	for _, value := range values {
		if isGREASE(value) {
			return true
		}
	}
	return false
}

func isGREASE(value uint16) bool { return value&0x0f0f == 0x0a0a }

func containsUint16(values []uint16, want uint16) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
