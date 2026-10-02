package cover

import (
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// NewReverseProxyHandlerWithPublicOrigin returns an opt-in reverse proxy for
// an upstream site configured to serve public's HTTPS virtual host. Routing
// and TLS still use upstream; public supplies only the outbound Host and the
// trusted X-Forwarded-Host/Proto values. Both URLs must be root origins.
//
// Origin, Referer, cookies, redirects, and content are never rewritten. The
// upstream must generate its own public URLs and retain its CSRF/Origin checks;
// an absent Origin is not evidence that a request is safe. Its trusted-header
// whitelist must use only the proxy-owned forwarding fields, not arbitrary
// client headers or backend-specific client-IP aliases.
func NewReverseProxyHandlerWithPublicOrigin(upstream, public *url.URL, transport http.RoundTripper) (http.Handler, error) {
	target, err := normalizePublicOriginURL(upstream, false)
	if err != nil {
		return nil, err
	}
	publicURL, err := normalizePublicOriginURL(public, true)
	if err != nil {
		return nil, err
	}
	return &publicOriginHandler{
		proxy:     newReverseProxyHandler(target, transport, publicURL.Host),
		authority: publicURL.Host,
	}, nil
}

// A fresh URL and canonical strings own all configuration used after the
// constructor returns. Caller mutations cannot change policy or routing.
func normalizePublicOriginURL(origin *url.URL, public bool) (*url.URL, error) {
	invalid := errors.New("public-origin reverse proxy requires valid root origins")
	if origin == nil {
		return nil, invalid
	}
	scheme := strings.ToLower(origin.Scheme)
	if scheme != "https" && (public || scheme != "http") {
		return nil, invalid
	}
	if origin.Path != "" && origin.Path != "/" || origin.RawPath != "" ||
		origin.RawQuery != "" || origin.ForceQuery || origin.User != nil || origin.Opaque != "" ||
		origin.Fragment != "" || origin.RawFragment != "" || origin.OmitHost {
		return nil, invalid
	}
	authority, err := canonicalOriginAuthority(origin.Host, scheme)
	if err != nil {
		return nil, invalid
	}
	return &url.URL{Scheme: scheme, Host: authority, Path: origin.Path}, nil
}

type publicOriginHandler struct {
	proxy     http.Handler
	authority string
}

func (h *publicOriginHandler) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if request == nil {
		http.Error(w, http.StatusText(http.StatusMisdirectedRequest), http.StatusMisdirectedRequest)
		return
	}
	authority, err := canonicalOriginAuthority(request.Host, "https")
	if err != nil || authority != h.authority {
		http.Error(w, http.StatusText(http.StatusMisdirectedRequest), http.StatusMisdirectedRequest)
		return
	}
	// Inspect the original request before ReverseProxy's hop filtering can
	// erase security metadata, even if the nominated field is absent.
	nominations := collectConnectionNominations(request.Header)
	_, originNominated := nominations["origin"]
	_, refererNominated := nominations["referer"]
	if originNominated || refererNominated || !h.acceptsOrigin(request.Header) {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	// Do not wrap the ResponseWriter: its streaming/Hijacker capabilities and
	// the existing WebSocket/response-body owners remain unchanged.
	h.proxy.ServeHTTP(w, request)
}

func (h *publicOriginHandler) acceptsOrigin(header http.Header) bool {
	present := false
	count := 0
	value := ""
	for field, values := range header {
		if !httpToken(field) || !strings.EqualFold(field, "Origin") {
			continue
		}
		present = true
		for _, entry := range values {
			count++
			if count > 1 {
				return false
			}
			value = entry
		}
	}
	if !present {
		return true
	}
	value = strings.Trim(value, " \t")
	if count != 1 || value == "" || len(value) > len("https://")+maxOriginAuthorityLength || strings.ContainsAny(value, "?#") {
		return false
	}
	origin, err := url.Parse(value)
	if err != nil || !strings.EqualFold(origin.Scheme, "https") || origin.Host == "" ||
		origin.Path != "" || origin.RawPath != "" || origin.RawQuery != "" || origin.ForceQuery ||
		origin.User != nil || origin.Opaque != "" || origin.Fragment != "" || origin.RawFragment != "" || origin.OmitHost {
		return false
	}
	authority, err := canonicalOriginAuthority(origin.Host, "https")
	return err == nil && authority == h.authority
}

// A DNS name is at most 253 bytes, with an optional colon and five port
// digits. Accept only conventional ASCII DNS or exact IP literals: legacy
// numeric/hex IPv4 aliases and DNS resolution are deliberately not involved.
const maxOriginAuthorityLength = 259

func canonicalOriginAuthority(authority, scheme string) (string, error) {
	invalid := errors.New("invalid origin authority")
	if authority == "" || len(authority) > maxOriginAuthorityLength {
		return "", invalid
	}
	for index := range authority {
		if authority[index] < '!' || authority[index] >= 127 {
			return "", invalid
		}
	}
	if strings.ContainsAny(authority, "%\\/?#@") {
		return "", invalid
	}
	host, port := authority, ""
	if authority[0] == '[' {
		end := strings.IndexByte(authority, ']')
		if end < 2 {
			return "", invalid
		}
		addr, err := netip.ParseAddr(authority[1:end])
		if err != nil || addr.Is4() || addr.Zone() != "" {
			return "", invalid
		}
		host = "[" + addr.String() + "]"
		if suffix := authority[end+1:]; suffix != "" {
			if suffix[0] != ':' || len(suffix) == 1 {
				return "", invalid
			}
			port = suffix[1:]
		}
	} else {
		if strings.ContainsAny(authority, "[]") || strings.Count(authority, ":") > 1 {
			return "", invalid
		}
		if index := strings.IndexByte(authority, ':'); index >= 0 {
			host, port = authority[:index], authority[index+1:]
			if port == "" {
				return "", invalid
			}
		}
		if addr, err := netip.ParseAddr(host); err == nil && addr.Is4() {
			host = addr.String()
		} else {
			host = strings.ToLower(host)
			if !validOriginDNSName(host) {
				return "", invalid
			}
		}
	}
	if port != "" {
		if len(port) > 5 || port[0] == '0' {
			return "", invalid
		}
		for index := range port {
			if port[index] < '0' || port[index] > '9' {
				return "", invalid
			}
		}
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return "", invalid
		}
		if scheme == "https" && number == 443 || scheme == "http" && number == 80 {
			port = ""
		}
	}
	if port != "" {
		return host + ":" + port, nil
	}
	return host, nil
}

func validOriginDNSName(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := range label {
			char := label[index]
			if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' {
				continue
			}
			return false
		}
	}
	terminal := labels[len(labels)-1]
	decimal := true
	for index := range terminal {
		decimal = decimal && terminal[index] >= '0' && terminal[index] <= '9'
	}
	if decimal {
		return false
	}
	if strings.HasPrefix(terminal, "0x") {
		hexadecimal := true
		for index := 2; index < len(terminal); index++ {
			char := terminal[index]
			hexadecimal = hexadecimal && (char >= '0' && char <= '9' || char >= 'a' && char <= 'f')
		}
		if hexadecimal {
			return false
		}
	}
	return true
}

func removePublicOriginForwardingHeaders(header http.Header) {
	var scratch [64]byte
	folded := scratch[:0]
	for field := range header {
		if !httpToken(field) {
			continue
		}
		folded = foldASCIIHeaderName(folded, field)
		name := string(folded)
		if name == "forwarded" || name == "x-real-ip" || strings.HasPrefix(name, "x-forwarded-") {
			delete(header, field)
		}
	}
}
