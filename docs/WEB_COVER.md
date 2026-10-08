# Web-cover mode

AutoCAR v1.0.1 introduced an experimental, opt-in `web` relay mode for deployments
that need a genuine HTTPS origin and reliable TCP service across both UDP-capable and
UDP-blocked networks. It is intended for lawful privacy, normal website
compatibility, and service continuity on infrastructure the operator owns or is
authorized to use.

Current source builds default to a `web` relay and `web-auto` for clients,
`doctor`, and `bench-client`; the historical v1.0.1 binary retains native/auto
defaults. The relay still requires exactly one explicit `--cover-root` or
`--cover-upstream`. `init` defaults to a paired web/web-auto bundle with a
dedicated `server/cover/index.html`; `init --protocol native` retains the original
native/auto bundle. Existing explicit native/auto JSON is unchanged.

Validate the application's required TCP and UDP paths before deployment; see
[default migration and rollback](DEPLOYMENT.md#11-migrating-to-web-cover-defaults).
Coordinate the protocol change on both endpoints, or explicitly pin native/auto
before upgrading an existing native deployment. Web clients and relays must
both support the required web features; v1.0.0 supports native `autocar/2` only.
Web mode never silently downgrades to that native protocol. Changing defaults
does not certify passive-fingerprint quality.

It is not an “undetectable” mode. Standard HTTP does not make all TLS, QUIC,
HTTP framing, packet-size, timing, traffic-volume, endpoint, or application
patterns identical to a browser. Do not use this feature to scan third-party
systems, bypass authorization, or impersonate a site you do not control.

## What is on the wire

One domain and one numeric port provide two ordinary web transports:

| Network path | Public cover | Authenticated tunnel |
| --- | --- | --- |
| TCP | HTTPS with HTTP/1.1 and HTTP/2 over TLS 1.2 or 1.3 | TLS 1.3-only HTTP/2 `CONNECT` for TCP |
| UDP | HTTP/3 over TLS 1.3 | standard HTTP/3 `CONNECT` for TCP; RFC 9298 `CONNECT-UDP` with HTTP Datagrams for UDP |

HTTP/1.1 is a cover-only protocol; it is never upgraded into an AutoCAR
tunnel. HTTP/1.1 and HTTP/2 cover responses advertise the bound HTTP/3 service
with `Alt-Svc`. Source builds after v1.0.1 apply the same bound-port policy to
HTTP/3 cover responses from the combined listener, including informational and
final responses. The bound value overrides an upstream website's stale or
unrelated alternative service. Authenticated tunnel responses are not wrapped;
standalone `ListenWebH3` continues to leave advertisement to its configured cover.
The H2 and H3 clients reuse warm connections and multiplex
independent CONNECT streams. AutoCAR's H2 client requires TLS 1.3. A TLS 1.2
HTTP/2 CONNECT presented to the public origin is always treated as cover,
including when it carries an otherwise valid ticket: the handler removes
`Proxy-Authorization` before delegation and never dials its authority.

Public physical-connection limits are separate from authenticated tunnel-stream
limits, and the combined TCP/UDP server shares its global and per-source
connection allowance. Source builds after v1.0.1 reject an excess H3 connection
with `H3_EXCESSIVE_LOAD` (`0x107`), rather than reusing the native relay's code,
which means `H3_INTERNAL_ERROR` in [HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html#section-8.1).
Rejection happens before HTTP dispatch;
the existing admitted connection remains usable and closing it releases capacity.
This is overload handling, not a tunnel authentication response.

### Website WebSocket support in source builds

Source builds after v1.0.1 also forward valid HTTP/1.1 WebSocket upgrades to
the configured `--cover-upstream` origin. This is website traffic, never an
AutoCAR tunnel or a requester-selected upstream. It works on the public TCP
listener with TLS 1.2 or 1.3; static cover and H2/H3 extended CONNECT behavior
are unchanged. An HTTPS website's ordinary H2 connection can remain reusable
while its WebSocket handshake uses H1.

The initial upgrade allowlist is deliberately narrow: body-free H1.1 GET,
one WebSocket Upgrade value, one valid Connection token list containing
Upgrade, version 13, and one canonical base64 key decoding to 16 bytes.
Ambiguous/duplicate fields, other upgrade protocols, body/transfer coding,
Connection close, and nominations of required or negotiation handshake fields
are not upgraded. Parseable, printable malformed handshakes continue as
scrubbed ordinary requests to the same fixed website. Go's existing HTTP
parser or reverse proxy can reject invalid raw/header characters before this
rewrite policy runs; those inputs do not promise an origin request, and the
proxy's early error remains generic 502. Connection-nominated fields and
authorization headers are removed; only the validated
`Connection: Upgrade` / `Upgrade: websocket`
pair is restored. Origin, cookies and ordinary safe negotiation fields remain
end-to-end; the website is responsible for its own access and Origin policy.
An application requiring forwarded Authorization headers remains incompatible
with the cover's intentional credential-stripping policy.

A final 101 must match the validated request and its key, contain the correct
accept value, and supply a duplex body. Unexpected, mismatched or non-duplex
101 responses produce the same generic 502 and close their upstream body.
This follows the [RFC 6455 opening-handshake mechanism](https://www.rfc-editor.org/rfc/rfc6455.html#section-4),
with the additional body-free and single-field restrictions described above.
After the handshake, bytes are relayed without interpreting application frames;
subprotocol and extension negotiation remain the website/client's policy.

Ordinary-response scrubbing can only use nominations still exposed by the
upstream transport. Go's native response parser removes the entire Connection
field when it sees `close`, so additional nominations in that same field are
not available to this handler. This existing parser boundary is unchanged;
explicit authorization-header stripping does not depend on those nominations.

Client disconnection releases the upgraded connection's admission slot.
Server Close or Serve-context cancellation aborts owned physical TCP sockets,
including hijacked upgrades, and cancels their request contexts. This is an
abort operation, not a graceful WebSocket close-frame exchange, and does not
close the shared destination dialer or upstream transport. Ordinary public
responses retain the bound Alt-Svc policy described above; an actual hijacked
101 is written by the reverse proxy's raw upgrade path and is not promised
the same bound-header override.

H2 preserves a client upload half-close while the destination's reply drains.
When the destination itself reaches EOF, H2 finishes that CONNECT response and
stops any remaining upload on that stream; the HTTP handler interface cannot
finish its response while continuing to receive an independent upload. Other
streams on the same connection remain usable. Applications that need to keep
uploading after receiving a destination EOF require the H3 stream transport.

Canceled H2 requests and H3 send-side stream errors close the destination directly,
including when both relay workers are blocked on destination I/O. Server or
physical-connection shutdown also releases H3 destinations after a response
FIN. After a clean response FIN, resetting only that H3 stream still cannot
directly interrupt an already blocked destination upload write through the
current QUIC API. The server's `--destination-write-timeout` now bounds that
pending write, releasing the stream slot without closing usable siblings.
Its default is `5m`; `0` selects that default and negative values are invalid.
This is bounded cleanup, not immediate reset detection.

The limit is the completion deadline of each TCP destination write, in chunks
of at most 32 KiB—not a kernel-level no-progress timer or a total upload limit.
After a chunk completes successfully, the next write gets a new budget.
Partial-write errors remain errors. Deadlines are cleared after writes, do not run while no write
is pending, and never change destination read deadlines. Native QUIC/TLS TCP
tunnels share this setting; UDP and ordinary cover traffic do not. See
[deployment settings](DEPLOYMENT.md) for CLI and JSON examples.

H2's handshake budget covers both TLS negotiation and the initial HTTP/2
preface/SETTINGS write. Caller cancellation or client shutdown also interrupts
that initialization, before the connection enters the reusable session pool.

Source builds additionally bound H2 physical writes with a separate
`--h2-write-timeout` (default `30s`, zero selects the default). It applies to
explicit `h2` and `web-auto`'s H2 fallback, including shared control-frame
writes; a stalled peer can no longer hold that writer indefinitely. This is
not an idle or per-stream deadline. A physical TLS write timeout can end all
streams on the affected connection, while ordinary stream cancellation must
preserve healthy siblings. See [timeout semantics and configuration](DEPLOYMENT.md)
for partial-progress and cleanup boundaries. This setting is not in v1.0.1.

There is no `autocar/2` ALPN or AutoCAR binary stream header on these paths.
The web ALPNs are `h2`, `h3`, and `http/1.1`. Native and web transports remain
separate modes and are not wire-compatible.

## Relay configuration

The relay defaults to web and requires exactly one explicit cover source. There
is no automatic working-directory or credential-directory cover. Use a dedicated
public-only directory, such as the generated `server/cover/`; never serve the
bundle's `server/` directory or the repository root.

### Static directory

```bash
./autocar server \
  --protocol web \
  --listen :443 \
  --tcp-listen :443 \
  --cover-root /srv/www \
  --cert /etc/autocar/server.crt \
  --key /etc/autocar/server.key \
  --token-file /etc/autocar/relay-token
```

The static handler serves `GET` and `HEAD`. Other methods receive the same
ordinary `405 Method Not Allowed` behavior whether they came from a random web
client or from an invalid tunnel probe.

Source builds after v1.0.1 confine each static request to `--cover-root` using
Go's [traversal-resistant file API](https://go.dev/blog/osroot). Relative symbolic
links that stay inside the root continue to work; links outside the root and
absolute symbolic links (even those pointing back inside it) are not served.
Dot-prefixed path components such as `.env` and `.git` return ordinary `404`
responses and are omitted from directory listings. This policy applies to
normalized, decoded URL paths; backslash paths are rejected, and Windows
also rejects colon paths to prevent alternate-data-stream access. The root-level
`/.well-known/` directory remains public, including ACME challenge files, but
dot-prefixed entries beneath it are still hidden. Normal index pages,
directory redirects/listings, `HEAD`, and byte ranges retain standard HTTP
file-server behavior.

The root handle is opened and closed per request, so deploying a replacement
site at the configured directory takes effect on subsequent requests without
leaving a long-lived handler-owned descriptor. This is not a filesystem sandbox:
mount points, hard links and public aliases to hidden content are not separated
by this policy. Keep the site tree public-only and the configured directory and
its parent under trusted control;
do not mount credentials or device files inside it. On upgrade, replace any
absolute site links with confined relative links or ordinary copied files.

Source builds after v1.0.1 send `OPTIONS *` through the configured cover handler
on HTTP/1.1, HTTP/2, and HTTP/3, instead of letting the TCP server return a
separate automatic response. Static cover therefore returns its ordinary `405`
with `Allow: GET, HEAD`; the combined listener applies its normal bound-port
`Alt-Svc` policy to this response too.

### Fixed upstream origin

```bash
./autocar server \
  --protocol web \
  --listen :443 \
  --tcp-listen :443 \
  --cover-upstream https://origin.example.net \
  --cert /etc/autocar/server.crt \
  --key /etc/autocar/server.key \
  --token-file /etc/autocar/relay-token
```

The upstream must be a fixed `http://` or `https://` origin that you are
authorized to proxy. The requester may choose the path, query, and ordinary
end-to-end headers, but cannot choose the upstream authority. The proxy rewrites
`Host` to the configured origin and removes `Authorization`,
`Proxy-Authorization`, and hop-by-hop headers. It returns a generic `502` if
the upstream cannot be reached. Consequently, an upstream that requires an
`Authorization` request header is not suitable without a separate authorized
front end.

Source builds after v1.0.1 preserve declared end-to-end request trailers for
nonempty streamed uploads through the fixed-origin and public-origin proxies.
For example, a website can receive a late `Content-Digest` after consuming the
upload. Values become available only after successful body EOF; the proxy does
not buffer the complete upload, verify its digest, or promote trailers into
headers. HTTP/2 and HTTP/3 uploads with a positive length use chunked framing
when forwarded to HTTP/1.1 so that their trailers remain available. The incoming
body's length checks still apply. Automatic body replay is disabled for these
trailer-bearing upstream requests.

Both proxy modes remove invalid, hop-by-hop, connection-nominated and credential
trailer fields, including `Authorization`, `Proxy-Authorization` and
`Proxy-Authentication-Info`, at declaration and EOF. Public-origin mode also
removes untrusted forwarding trailers at EOF. Only initially declared safe
fields are forwarded; late unannounced fields, empty-content trailer exchanges
and custom transports that deep-clone the outgoing request again are not
covered by this compatibility guarantee. Custom request bodies must finalize
trailers before `Read` returns EOF, not mutate them concurrently from `Close`.
Static cover, authenticated tunnel payloads and the published v1.0.1 binary
are unchanged. This is upload compatibility, not a traffic-identification claim.

Source builds after v1.0.1 disable automatic compression negotiation and response
decompression on the proxy's private default upstream transport. The visitor's
`Accept-Encoding` remains unchanged: explicitly requested gzip still works, and
the origin's encoded bytes, `Content-Encoding`, length, digest and ETag remain
together. This avoids rewriting `no-transform` content while retaining metadata
for the old bytes; see [HTTP message transformations](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.7).
It does not verify the website's digest or establish browser-like fingerprints.
Applications supplying a custom RoundTripper retain their own negotiation/decoding
policy and must configure transparent forwarding themselves. Static cover,
authenticated tunnel payloads and the published v1.0.1 binary are unchanged.

#### Optional fixed public origin in source builds

Source builds after v1.0.1 can separate the website's public HTTP identity
from the fixed upstream connection address:

```bash
./autocar server \
  --protocol web --listen :443 --tcp-listen :443 \
  --cover-upstream https://origin.example.net \
  --cover-public-origin https://www.example.com \
  --cert /etc/autocar/server.crt --key /etc/autocar/server.key \
  --token-file /etc/autocar/relay-token
```

This is opt-in, upstream-only, and not part of the v1.0.1 binary. Without
`--cover-public-origin`, the existing upstream-Host and base-path/query behavior
is unchanged. With it, both configured URLs must be root origins (empty path
or `/`, no query, user information or fragment); the public origin must use
HTTPS. Use canonical ASCII DNS names (including already encoded punycode),
IPv4, or bracketed IPv6, with an optional numeric port from 1 to 65535.
Trailing dots, zone IDs, nonstandard numeric IP aliases and leading-zero ports
are rejected; no DNS or IDNA conversion is performed during validation.
DNS case and explicit default ports are equivalent for the public guard.

The upstream URL still controls dialing, TLS certificate verification and
SNI. Only the outgoing HTTP `Host` changes to the configured public authority.
Incoming `Forwarded`, all `X-Forwarded-*` headers and `X-Real-IP` are removed
from headers and declared request trailers;
the proxy generates only fixed `X-Forwarded-Host` and `X-Forwarded-Proto: https`.
It does not forward the visitor's IP address. Configure the backend to accept
this public virtual host, generate public canonical URLs, and trust **only**
these two relay-generated headers from this relay. Other backend-specific
trust headers are not a universal allowlist: do not trust arbitrary client
headers or expose an internal control plane as the website.

Cover requests with a different Host receive ordinary `421 Misdirected
Request`. If an Origin header is present it must contain exactly one valid
same-public HTTPS origin; foreign, null, empty or ambiguous values receive
ordinary `403 Forbidden`. A Connection nomination of Origin or Referer also
receives `403`, before hop-header stripping can hide it. This opt-in mode is
for same-origin websites, not cross-origin CORS applications. Authenticated
tunnel dispatch is unchanged: these guards apply only to the website handler.

Cookie, Set-Cookie, Location, Origin, Referer and HTML are **not rewritten**.
The website remains responsible for CSRF tokens, session authentication,
cookie domains/attributes and its own Origin policy, including requests with
no Origin. Origin guards inspect HTTP headers, not trailer values; the backend
must not merge security or trust trailers into request headers. A backend that
compares Origin and Host lexically can still reject
equivalent noncanonical spellings; the proxy deliberately preserves Origin
bytes. Third-party redirects are passed through, not followed by the proxy.
This mode cannot make an arbitrary third-party site compatible or establish
browser-like traffic fingerprints. `--check` validates it offline; JSON uses
the same `cover-public-origin` key. Remove the flag/key (or explicitly pass
`--cover-public-origin=`) to restore the default mode.

For an actual `OPTIONS *` request, source builds after v1.0.1 preserve the
asterisk request-target at the fixed upstream authority. The configured base
path and query are not added: this request concerns the origin as a whole, not
a resource below that base path. Resource requests such as `OPTIONS /*`, an
encoded asterisk in a path, or an asterisk in a query keep the usual configured
path/query joining. Visitor-controlled authority still cannot select another
upstream, and `Origin`/`Referer` are not rewritten to bypass website policy.

Response credential filtering also covers trailers, including fields that an
upstream adds only when its body ends. Ordinary end-to-end response trailers
remain available, and the body is still streamed rather than buffered in full.
This is defensive handling of upstream metadata, not an additional tunnel
authentication mechanism.

Source builds after v1.0.1 retain the original response's `Connection`
nominations when filtering trailer declarations and fields discovered later at
EOF or Close, including replacement trailer maps. A connection-specific field
cannot reappear just because its declaration was removed before the body ended.
This depends on the upstream transport exposing those nominations; the native
parser's `Connection: close` limitation described above is unchanged.

The same source builds remove the relay-owned `Proxy-Authentication-Info`
namespace from cover request headers and upstream final, informational,
trailer, and validated WebSocket responses. This prevents an upstream's metadata
from being presented as relay authentication metadata; it is not a new proof mechanism.
Ordinary website `Authentication-Info` and `WWW-Authenticate` fields are retained
unless nominated as connection-specific. Authenticated tunnel proofs are not
subject to this cover-only filter.

Source builds also apply that filter to upstream informational responses,
including `103 Early Hints`, before forwarding them. Ordinary `Link` hints and
other end-to-end fields remain available; credentials, hop-by-hop fields and
fields named by `Connection` do not bypass filtering through an early response.
This hardening is not included in v1.0.1.

Source-built H3 clients also consume up to five non-final `1xx` responses before
checking the final CONNECT or CONNECT-UDP response and its authentication proof.
This permits ordinary informational responses without treating them as tunnel
authentication failures. A sixth informational response is rejected; each hint
does not restart the existing establishment deadline. Informational headers are
never accepted as a replacement for the final signed proof. This client fix is
not included in v1.0.1.

In web mode:

- `--listen` is the UDP/H3 bind address and `--tcp-listen` is the TCP/H1/H2
  bind address; if omitted, `--tcp-listen` inherits `--listen`;
- TCP and UDP must use the same numeric port;
- `--disable-tcp-fallback` is rejected because H2/TCP is part of the mode's
  reliability contract;
- `--client-ca` is rejected because a normal public cover must be reachable
  without a TLS client certificate;
- the public TCP cover accepts TLS 1.2 through TLS 1.3, while authenticated H2
  tunnels and H3 remain TLS 1.3-only; and
- the normal destination policy still resolves remotely and rejects disallowed
  IP ranges and ports before opening an egress socket.

Use a certificate whose SAN covers the client-visible domain. A publicly
trusted certificate and meaningful site content usually provide better normal
web compatibility than a self-signed certificate and an empty directory, but
certificate trust is an operator choice, not an AutoCAR bypass: clients must
still explicitly choose `--ca` or `--system-roots`.

## Client transports

`web-auto` is the default for `client`, `doctor`, and `bench-client` in current
source builds. The explicit setting below also works with an already configured
web relay and makes the protocol family visible in saved commands.

Recommended configuration:

```bash
./autocar client \
  --server relay.example.com:443 \
  --system-roots \
  --token-file /etc/autocar/relay-token \
  --transport web-auto \
  --h3-fingerprint chrome-2026-08 \
  --quic-attempt-timeout 5s \
  --open-timeout 15s \
  --fallback-cooldown 30s
```

The three web transport choices are:

| `--transport` | Behavior |
| --- | --- |
| `web-auto` | For TCP, try H3 first and use H2 during an H3-failure cooldown; for UDP, require H3 CONNECT-UDP with no H2 fallback |
| `h3` | Require HTTP/3 over UDP for TCP CONNECT and CONNECT-UDP; no H2 fallback |
| `h2` | Require HTTPS/HTTP/2 over TCP CONNECT; no H3 attempt and no UDP support |

`--h3-fingerprint=chrome-2026-08` is the default for `web-auto` and `h3`. It
enables the fixed full client QUIC/TLS handshake profile and zero-length source
CID supplied by the pinned `github.com/apernet/quic-go` fork. The profile is
locked to QUIC v1 because its fixed version-information transport parameter is
part of that v1 handshake image.
`--h3-fingerprint=native` disables ChromeParrot inside that same fork as an
explicit interoperability and rollback choice. Here `native` names only the H3
fingerprint fallback; it does not select AutoCAR's native `autocar/2` protocol.

For `web-auto`, `0 < --quic-attempt-timeout < --open-timeout` is required.
When the relay name resolves to both address families, H3 interleaves IPv6 and
IPv4 candidates and starts them with a short stagger; each candidate retains
its own UDP socket so a blackholed first address cannot consume the entire H3
budget before a working family is tried.

Source builds after v1.0.1 share the result of a cold H2 or H3 physical connection
attempt with all callers already waiting on it. A failed handshake does not
make those callers start replacement handshakes one after another. A later
invocation may retry, subject to the existing `web-auto` cooldown policy.
H2 callers register before queuing for session selection, so they retain
that same completed failure even if it arrives before their selection turn;
new callers after publication can retry without an indefinite failure cache.
The shared attempt belongs to the client and retains its configured physical
dial timeout; canceling one caller stops only that caller's wait, not the
attempt needed by other callers. H2 keeps its TCP-connect timeout separate
from the existing TLS/H2 initialization budget; its bounded TLS retry after
HelloRetryRequest still uses the original remaining initialization budget.
If all callers abandon it, initialization can continue until its configured
timeout or client shutdown. A successful unclaimed H2 connection can remain
pooled, but does not send CONNECT or generate application authentication until
a live caller reserves its first stream. That caller alone owns bootstrap;
subsequent callers retain the existing short connection-bound credentials.
Client Close cancels and joins owned dialing and detached session-cleanup
workers before returning. Concurrent H2 Close callers wait for the same
completed closure and result, including late physical dial results. This
does not claim synchronous termination of every dependency goroutine; custom
TLS callbacks must return, and operations ignoring cancellation cannot be
forcibly interrupted. A failed TCP dial's non-nil connection is closed before
its failure is published; a nil successful result fails closed. This
does not change authentication, wire profiles, timeout defaults or sibling
stream ownership, and is not a general connection-speed or browser-equivalence
claim. The published v1.0.1 binary does not contain this change.

Source builds also recheck a queued H3 caller's cancellation before physical
connection selection and authentication reservation. A canceled caller must
not initiate a new shared handshake or claim an otherwise Fresh session.
`web-auto` rejects and closes a logical CONNECT-UDP result returned after its
caller cancellation or primary opening budget; this never triggers H2 UDP
fallback or resets the TCP cooldown. Successful established packets remain
detached from the caller's temporary opening context.

Source builds also preserve the opening context's cancellation cause for H3
CONNECT-UDP I/O failures and recheck cancellation after verifying a successful
TCP or UDP response, including at the final stream handoff lock. A rejected
handoff cancels only that request stream and releases its reservation; proven
connection authentication and sibling streams remain usable. Cancellation
after successful ownership transfer does not close the established stream.
These changes are not included in the published v1.0.1 binary.

Both web TCP handlers reject and close a destination connection returned after
the configured destination dial deadline, even if a custom dialer reports
success. The existing authenticated 502 response and connection-bound session
are retained, so a later healthy request can reuse that session. This does not
change authentication, wire profiles, or timeout defaults and is not included
in the published v1.0.1 binary.

After a failed H3 attempt, new TCP streams avoid repeating the UDP timeout.
`--fallback-cooldown` is a base duration; each failure independently selects a
retry point within +/-20% so clients do not probe in a fixed synchronized
cadence. Once that interval expires, exactly one concurrent caller probes H3
while the others continue over H2. An authenticated target rejection is
evidence that H3 itself is alive, so it is returned to the caller rather than
retried over H2.

`--fallback-server` belongs only to native `--transport=auto` and is rejected
for web transports. H3 and H2 use the same `--server` host and port. Web
transports do not accept `--client-cert`/`--client-key`. Native application
pacing negotiation does not apply to H2 or H3 web streams; diagnostics report
both pacing fields as `not-applicable`, and `--pacing=fixed-rate` is rejected.

`web-auto` and explicit `h3` expose SOCKS5 UDP through H3 CONNECT-UDP. Explicit
`h2` does not advertise UDP. The H3-to-H2 fallback carries only new TCP
streams: UDP never falls back to H2 and fails when H3 is unavailable.

For an established SOCKS association, opening a slow new H3 UDP target does
not serialize sends to another warm target while scheduler capacity remains.
Aliases are grouped using the same canonical target identity as CONNECT-UDP.
This keeps connection authentication and all server destination/admission
checks intact; it neither retries packets nor caches native DNS resolutions.
The frontend queue counts active and waiting packets together (32 total), with
at most eight workers and a 256 KiB payload-plus-address cap. One target can use
at most half the packet/byte budget. Multiple busy targets may still fill the
shared queue, in which case packets are dropped. Close interrupts and joins
pending sends before the SOCKS association is released. Custom packet
transports retain serial sending unless they explicitly opt in to this
concurrency/close contract; see [Architecture](ARCHITECTURE.md).

Only a newly authenticated CONNECT-UDP response is fresh evidence that the H3
path has recovered. Sending on a cached UDP target merely queues a datagram
locally; it does not clear the TCP fallback cooldown or change the last
successful transport. A newly authenticated target rejection proves path
health without being counted as a successful target connection.

## CONNECT-UDP boundary

The H3 UDP path follows
[RFC 9298](https://www.rfc-editor.org/rfc/rfc9298.html)'s Extended CONNECT
shape:

- `:protocol` is `connect-udp`;
- the URI uses the default
  `/.well-known/masque/udp/{target_host}/{target_port}/` template;
- `Capsule-Protocol` is negotiated as `?1`; and
- each HTTP Datagram starts with Context ID `0`.

One normalized UDP target owns one H3 request stream and one connected relay
UDP socket. A logical SOCKS5 association opens target streams lazily and reuses
the stream for later datagrams to the same target. Target count, client-global
and server-global session count, per-source server sessions, and receive queues
are bounded. The relay applies the UDP destination policy, resolves once, and
freezes the session to one successfully opened numeric endpoint; replies from
other sources cannot enter that target stream.

A signed target rejection (`502`) or admission rejection (`503`), and local
target/session capacity limits, fail only that datagram send. The SOCKS5 frontend
drops the packet and retains the association and its other live targets; it
does not retry the failed packet. Later packets can use a target after capacity
is released. Typed causes remain available to direct PacketConn callers through
`errors.Is` / `errors.As`, with `transport.ErrPacketTargetUnavailable` marking
this narrow recoverable case. Authentication, cancellation, connection and
unknown errors remain terminal. A successful local enqueue still does not
prove delivery or refresh path health.

The current maximum UDP payload is 1,150 bytes. This leaves room in the
mandatory 1,200-byte QUIC path for QUIC and DATAGRAM framing, the HTTP
quarter-stream ID, and Context ID `0`. A larger logical payload would not be
portable to a minimum-MTU path. Oversized payloads are rejected. This
implementation does not fragment CONNECT-UDP payloads and does
not implement a Capsule data fallback, so it requires negotiated H3 HTTP
Datagrams. These limits are intentionally different from native mode's `ACDG`
fragmentation and 4,096-byte logical payload.

## Per-connection authentication

The configured relay token is input to HKDF-SHA-256, producing a key dedicated
to web-cover authentication. The first AutoCAR CONNECT or CONNECT-UDP opening
attempt on each physical H2/TLS or H3/QUIC connection is the sole bootstrap
leader. It uses the original bounded bearer with a timestamp, a
cryptographically random 16-byte client nonce, and 206 to 1,453 bytes of
authenticated random padding. After the `Bearer ` prefix and base64url
encoding, the complete `Proxy-Authorization` value ranges from 385 to 2,047
bytes. Other concurrent callers wait for this exchange instead of sending
another full bearer.

The server answers a valid bootstrap with an exact 54-byte
`Proxy-Authentication-Info` value. It contains a fresh 16-byte server nonce and
a 16-byte truncated HMAC-SHA-256 tag in `nextnonce=<base64url>` form. The proof
binds the full request, authenticated claims, and HTTP status. A valid signed
`400`, `502`, or `503` therefore establishes the connection just like a `200`;
the client installs authentication state before returning that HTTP error.

Both sides use the client and server nonces with HKDF-SHA-256 to derive a
256-bit key scoped to that physical connection. Each later CONNECT or
CONNECT-UDP sends an exact 41-byte `Bearer` value containing version, a nonzero
big-endian `uint64` sequence, and a 16-byte request tag. Its exact 44-byte
response proof contains the same version and sequence plus a status-bound tag.
The client allocates sequence numbers monotonically across concurrent streams;
the server's 128-position sliding bitmap accepts bounded out-of-order arrival
once and rejects duplicates and values that have fallen behind the window.
Ticket allocation waits when a new sequence would overtake the oldest
unresolved authentication exchange by 128 positions. This wait respects the
request deadline and connection closure; established streams do not retain a
ticket reservation. H2 CONNECT, H3 CONNECT and CONNECT-UDP use the same rule.

The state belongs to the actual `*tls.Conn` or `*quic.Conn`. H3 TCP CONNECT and
CONNECT-UDP therefore share one sequence space and key. A reconnect, TLS/QUIC
resumption onto a replacement connection, or the connection opened after H2
GOAWAY performs a new full bootstrap. A QUIC path migration that remains the
same QUIC connection retains the existing state.

The full ticket's clock window remains 60 seconds in either direction, and
accepted full-ticket nonces remain in the bounded server-wide H2/H3 replay
cache for that complete window. A duplicate, expired, malformed, wrong-key,
over-capacity, or invalid continuation credential is not treated as a tunnel
request. AutoCAR removes `Proxy-Authorization` and passes the request to the
configured cover handler without proactively closing the server connection or
sending an authentication challenge. Authentication still completes before
stream admission, DNS resolution, or destination dialing.

The client accepts exactly one status-bound bootstrap or continuation proof
before exposing a stream. A missing, duplicate, malformed, or mismatched proof
makes the connection state ambiguous, so it closes the entire physical
connection and wakes bootstrap waiters to select a replacement.

This behavior reduces the information available to unauthenticated active
probes; it does not make passive traffic analysis impossible. Server and client
clocks must be synchronized closely enough to satisfy the acceptance window.

## Fingerprint boundary

The H3 client uses the fixed `chrome-2026-08` profile by default. AutoCAR obtains
that profile from the `github.com/apernet/quic-go` fork,
pinned to `v0.61.1-0.20260806010916-184d081eef3e`. It applies the fork's
ChromeParrot client handshake image—including ClientHello, client transport
parameters and Initial packetization—and uses a zero-length client source CID.
ChromeParrot is client-only: it does not turn the AutoCAR relay into a particular
Chrome-facing CDN/server implementation, and it does not make H3 SETTINGS,
CONNECT/authentication traffic, packet sizes, connection reuse or timing match
Chrome. The `native` rollback profile disables this client image.

The fixed H3 Chrome profile also disables TLS session resumption inside the
pinned fork. Supplying `tls.Config.ClientSessionCache` does not change that:
each replacement QUIC connection performs a full TLS handshake. The H3 `native`
profile can resume TLS when a caller-provided cache has a valid ticket and the
server permits it; a nil cache or `SessionTicketsDisabled` retains full
handshakes. Neither profile enables 0-RTT. Reusing an already-open QUIC
connection for another stream is connection reuse, not TLS resumption. Every
replacement physical connection still starts fresh proxy authentication,
including when its TLS session resumes.

The H3 loopback reconnect regression checks these distinct behaviors with the
same client and server, an actual received-ticket signal, and both peers' TLS
state. It does not measure browser similarity. The real-browser calibration
starts a fresh browser profile for each sample and does not include a controlled
warm reconnect, so its results cannot establish a resumption advantage or deficit.

The H2 client separately uses the fixed `chrome-133` uTLS ClientHello profile.
That describes only its TLS ClientHello; H2 settings, header order, flow control,
connection reuse, payload sizes and timing retain their implementation behavior.
Source builds after v1.0.1 also support ordinary TLS 1.3 session resumption for
this profile when the caller enables a TLS session cache. An empty cache keeps
the fixed cold ClientHello shape; a valid cached ticket adds uTLS's native
`pre_shared_key` extension and binder as the last extension, as required by
[RFC 8446 section 4.2.11](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.11).
The cache is private to one configured H2 client. A nil caller cache or
`SessionTicketsDisabled` keeps full handshakes. This does not enable 0-RTT:
every new physical connection completes TLS and starts fresh proxy authentication,
even when TLS resumes; connection-scoped proxy tickets are never inherited.
The pinned uTLS implementation cannot rebuild a populated PSK after a TLS 1.3
HelloRetryRequest. For this narrowly recognized library limitation, the H2 client
closes the failed socket and retries once on a fresh connection without a ticket,
within the same remaining initialization timeout. Certificate/hostname checks,
TLS 1.3 and h2 are still mandatory; unrelated TLS failures are not retried.
The library may invalidate the failed cached ticket. This compatibility fallback
is a full handshake, not successful HRR resumption or a browser-equivalence claim.

Resumption retains the previously verified TLS session rather than repeating a
full certificate exchange or calling `VerifyPeerCertificate` again. Callers
requiring fresh per-connection certificate policy must disable session tickets;
the native profile additionally supports `VerifyConnection`. Cached tickets are
not an unconditional privacy improvement: reusing a ticket can let passive
observers correlate connections
([RFC 8446 appendix C.4](https://www.rfc-editor.org/rfc/rfc8446.html#appendix-C.4)).
The bounded loopback regression verifies actual client/server resumption,
cold/warm ClientHello policy, and fresh authentication. It is not a browser
comparison or evidence of lower classifier accuracy.

Authenticated H2 and H3 CONNECT requests explicitly suppress the Go HTTP
libraries' default `User-Agent` and automatic `Accept-Encoding: gzip` values.
AutoCAR does not invent browser headers until the complete request-header set
and ordering have been measured and implemented as one coherent profile.

Using the same maintained handshake implementation as the comparator removes
some known stock-QUIC differences, but it is not independent evidence of a
classification advantage and does not make the two application protocols wire
compatible. Therefore the project does not claim that web-cover traffic is
indistinguishable from a browser. A defensible result requires a versioned,
reproducible capture and a classifier evaluated on held-out runs. Until such a
gate passes, passive-fingerprint superiority is unproven.

The optional research corpus, safety boundary, minimum sample counts, and
decision rule are specified in
[STEALTH-BENCHMARK.md](STEALTH-BENCHMARK.md). A smoke run validates the tools;
it is not a comparative result. The complete 31,500-PCAP campaign and real-browser
comparison have not been completed for v1.0.1. The earlier 65-capture calibration
remains `insufficient_evidence` and belongs only to its recorded source snapshot.
Separating [ordinary release checks](RELEASING.md) from that optional research
gate does not change those results or permit stronger claims.

## Transport continuity and validation limits

AutoCAR can present one functioning web origin across normal H1/H2 over TCP and H3 over
UDP, while `web-auto` can keep new TCP proxy flows working through genuine H2
when the UDP path is blocked. This fallback applies to new TCP proxy flows;
it does not move UDP datagrams to H2 or migrate an established application stream.

Transport continuity does not establish browser indistinguishability or a
passive-fingerprint advantage. Any evaluation must pin its binaries and
configuration, serve equivalent cover content, separate active-probe behavior
from passive classification, and report failures and confidence intervals
rather than turn a single successful run into a product claim.

The dependency relationship must remain explicit in such a report: AutoCAR web
H3 uses the pinned QUIC fork's client profile. Shared implementation details
are part of provenance, not independent evidence of anti-identification quality.

## Safe validation

Validate only on loopback, an isolated Docker network, or machines and domains
you own or are explicitly authorized to test. Do not point probe tools at
unrelated public addresses.

```bash
# Confirm the public TCP cover and advertised H3 endpoint.
curl --http1.1 https://relay.example.com/
curl --http2 https://relay.example.com/

# Confirm each authenticated TCP path.
./autocar doctor [connection flags] --transport h3 \
  --target example.com:443 --json
./autocar doctor [connection flags] --transport h2 \
  --target example.com:443 --json

# Confirm automatic selection under the deployment's own UDP-block test.
./autocar doctor [connection flags] --transport web-auto \
  --target example.com:443 --json
```

`doctor` opens an authenticated target TCP connection and reports the path that
actually succeeded. It does not prove application correctness, browser
indistinguishability, or comparative resistance to classification. When
testing UDP failure, apply packet filtering only inside an isolated namespace,
container network, or dedicated test host; do not alter a shared production
host's firewall.

For CONNECT-UDP, use an owned UDP echo or DNS fixture inside the same isolated
lab and test both `h3` and `web-auto`. Then block only the lab's UDP forwarding
and verify that TCP uses H2 while the UDP association fails; H2 success is not
evidence of UDP fallback.
