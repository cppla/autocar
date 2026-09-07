# AutoCAR wire protocols

AutoCAR has two intentionally separate wire families:

- native protocol v2 is an AutoCAR-owned protocol carried by TLS 1.3 with the
  `autocar/2` ALPN; and
- web-cover v1 uses normal HTTPS/HTTP semantics with `http/1.1`, `h2`, and `h3`
  ALPNs and connection-scoped HMAC credentials.

Neither family provides third-party proxy protocol or AutoCAR v1 compatibility.
A relay selects one family with `server --protocol=native|web`; clients must select a matching
native (`auto|quic|tls`) or web (`web-auto|h3|h2`) transport.

## Native protocol v2

The QUIC transport uses one bidirectional stream per TCP flow or UDP control
association. The TCP/TLS fallback uses one TLS connection per TCP flow and the
same stream request/response format. UDP payloads are available only on QUIC.

All integers are unsigned, big-endian. Receivers validate fixed headers and all
attacker-controlled sizes before allocation.

### Stream header

Every request and response begins with 36 bytes:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | magic `AUTO` (`0x4155544f`) |
| 4 | 1 | version `2` |
| 5 | 1 | kind: `1` request, `2` response |
| 6 | 2 | request network or response status |
| 8 | 2 | body length 1 |
| 10 | 2 | body length 2; zero in responses |
| 12 | 8 | `MaxTx`, bytes/s |
| 20 | 8 | `MaxRx`, bytes/s |
| 28 | 4 | UDP request nonce / assigned session ID; otherwise zero |
| 32 | 1 | initiator sender mode |
| 33 | 1 | initiator sender profile |
| 34 | 1 | responder sender mode; zero in requests |
| 35 | 1 | responder sender profile; zero in requests |

The maximum accepted rate is `1,000,000,000,000` bytes/s. This is a parser
bound, not a recommended operational rate.

Rate and sender-mode fields carry negotiated pacing metadata on QUIC. The
current TLS/TCP fallback sends zero rate fields and reports unspecified sender
metadata; it uses the same bounded CONNECT framing but not QUIC pacing.

#### Enums

Networks: `1=tcp`, `2=tcp4`, `3=tcp6`, `4=udp association`.

Statuses: `0=ok`, `1=bad request`, `2=unauthorized`, `3=destination
unavailable`, `4=busy`, `5=internal`.

Sender modes: `0=unspecified`, `1=adaptive`, `2=reno/bypass`,
`3=fixed-rate`.

Profiles: `0=unspecified`, `1=conservative`, `2=balanced`, `3=aggressive`.

### TCP CONNECT

Request body 1 is the shared token (16–1,024 bytes). Body 2 is a `host:port`
target (1–1,024 bytes). Session ID must be zero. On QUIC, the initiator reports
its configured sender mode/profile and optional fixed-rate requests; TLS leaves
those fields zero/unspecified.

The relay authenticates before resolving or dialing. On QUIC success it responds
with effective directional rates and both sender identities; on TLS fallback
those fields are zero/unspecified. The stream then becomes unframed application
bytes:

```text
client                                         relay
  | request(token, target, rate metadata)        |
  |--------------------------------------------->|
  |        authenticate, policy, resolve, dial   |
  | response(ok, sender metadata; zero on TLS)   |
  |<---------------------------------------------|
  |<============= raw byte stream =============>|
```

`MaxTx` always describes initiator-to-responder. `MaxRx` describes
responder-to-initiator. A nonzero QUIC response value means fixed-rate pacing
was selected for that direction. QUIC response metadata—not local
configuration—is the source of truth for benchmark telemetry. Fixed-rate is not
available on TLS.

An error response ends the stream. Messages are stable and bounded; the relay
does not disclose DNS results or operating-system error strings.

### UDP association control

A UDP request has network `4`, an empty address, and a random nonzero request
nonce in the Session ID field. Its body contains only the token. The nonce does
not reserve or choose the runtime session. On success the relay allocates an
independent, nonzero ID that is unique among active associations on that QUIC
connection and returns it in the response. Both directions use this assigned ID
in subsequent `ACDG` frames.

The control stream stays open as the association lease. Closing it destroys the
corresponding socket, removes the assigned ID and discards all incomplete
reassembly state for that ID before a later association can reuse it.

### `ACDG` DATAGRAM format

Every fragment has a 20-byte header followed by the repeated address and a
payload slice:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | magic `ACDG` (`0x41434447`) |
| 4 | 1 | DATAGRAM version `1` |
| 5 | 1 | flags; bit 0 marks relay response |
| 6 | 4 | session ID |
| 10 | 4 | message ID |
| 14 | 2 | zero-based fragment index |
| 16 | 2 | fragment count |
| 18 | 2 | address length |
| 20 | variable | UTF-8 `host:port`, then fragment payload |

Client-to-relay addresses are destinations. Relay-to-client addresses are the
actual remote sources. Address metadata is repeated so a fragment can never
inherit routing state from another message.

Bounds:

- logical payload: 4,096 bytes;
- fragments per message: 256;
- address: 1,024 bytes with numeric port 1–65,535;
- frame budget used by the runtime: a conservative 1,200 bytes;
- reassembly: finite message count, total buffered bytes and fixed TTL.

Reassembly identity includes session, message and direction. Metadata conflict
or a duplicate index with different bytes purges that identity. An exact
duplicate is idempotent only while that incomplete assembly still exists. The
completed key has no replay tombstone, so replaying a complete one-fragment
message or complete fragment set can deliver the UDP payload again. QUIC
DATAGRAM is unreliable: missing fragments cause expiry, not retransmission.

### Transport security and replay

- TLS 1.3 and normal certificate verification are mandatory.
- QUIC 0-RTT is disabled, so CONNECT requests and tokens are never sent as
  replayable early data.
- A token is authenticated on every control stream; the first valid stream also
  ends the connection's pre-authentication lifetime.
- TCP fallback uses the same ALPN and request parser, but does not advertise UDP
  or carry QUIC sender-pacing metadata.

## Web-cover protocol v1

Web-cover presents one HTTPS origin over TCP and UDP on the same numeric port:

| Protocol | Network | Ordinary request | Authenticated tunnel |
| --- | --- | --- | --- |
| HTTP/1.1 | TCP/TLS 1.2 or 1.3 | configured cover | never a tunnel |
| HTTP/2 | TCP/TLS 1.2 or 1.3 | configured cover | TLS 1.3-only standard `CONNECT` stream for TCP |
| HTTP/3 | QUIC/UDP/TLS 1.3 | configured cover | standard `CONNECT` for TCP; RFC 9298 `CONNECT-UDP` with HTTP Datagrams for UDP |

HTTP/1.1 and HTTP/2 cover responses include an `Alt-Svc` value for the bound H3
port. Only H2 and H3 requests with method `CONNECT`, an empty path and query,
and exactly one valid `Proxy-Authorization` value are eligible to become a TCP
tunnel; H2 additionally requires TLS 1.3. A TLS 1.2 CONNECT is never eligible,
even with an otherwise valid ticket: its credential is removed before the
request is delegated to the cover handler. The CONNECT authority is the
normalized `host:port` target. A `200` response begins full-duplex bytes on the
HTTP stream; there is no AutoCAR binary stream preface. H3 additionally
recognizes an authenticated Extended CONNECT with `:protocol=connect-udp` as
described below.

An authenticated request that exceeds stream admission receives generic HTTP
`503`; an allowed request whose destination cannot be opened receives generic
HTTP `502`. These responses are available only after a valid credential has
passed. The server authenticates before acquiring admission, resolving a host,
or dialing a destination.

### Web connection authentication

The shared token is not placed directly in the web request. Both sides first
derive a web-only 256-bit key with HKDF-SHA-256 using the context
`autocar web-cover auth v1`. The first tunnel-eligible CONNECT on each physical
H2/TLS or H3/QUIC connection carries a bounded, variable-size binary ticket
encoded with unpadded base64url after the `Bearer` scheme:

| Field | Size | Meaning |
| --- | ---: | --- |
| version | 1 byte | ticket version `1` |
| timestamp | 8 bytes | unsigned Unix seconds, big-endian |
| nonce | 16 bytes | cryptographically random for this connection bootstrap |
| sender mode/profile | 2 bytes | bounded metadata; zero for current web CLI paths |
| `MaxTx` / `MaxRx` | 16 bytes | bounded metadata; zero for current web CLI paths |
| padding length | 2 bytes | unsigned big-endian length in the range 206..1453 |
| random padding | 206..1453 bytes | cryptographically random bytes generated for the bootstrap |
| MAC | 32 bytes | HMAC-SHA-256 over the bound request transcript, claims, version, padding length and padding bytes |

After the `Bearer ` prefix and unpadded base64url encoding, the complete
`Proxy-Authorization` field value is 385..2047 bytes. The length-prefixed HMAC
transcript binds a fixed protocol label, `h2` or `h3`, method,
extended-CONNECT protocol value, normalized authority, path, timestamp, nonce,
bounded metadata, ticket version, padding length, and padding bytes.
Consequently, a full ticket cannot be moved between H2 and H3 or reused for a
different target. The authenticated random padding varies only the bootstrap
request-header length; it does not alter the CONNECT payload or relax parser
bounds.

After accepting that full ticket, the server returns exactly one
`Proxy-Authentication-Info` bootstrap value. Its raw value is version (1 byte),
a fresh server nonce (16 bytes), and a 16-byte truncated HMAC-SHA-256 tag. In
the `nextnonce=<base64url>` field syntax the complete value is exactly 54 bytes.
The tag binds the full request transcript and claims, response status, version,
and server nonce. This applies to an authenticated `200` and to authenticated
`400`, `502`, or `503` responses: a valid signed response establishes the
connection authentication before the client reports the HTTP error.

Client and server then derive a 256-bit connection key with HKDF-SHA-256 from
the web-only key and the concatenated client and server nonces, using the
context `autocar web-cover connection auth v1`. Later CONNECT and CONNECT-UDP
streams on that physical connection carry a compact 25-byte ticket:

| Field | Size | Meaning |
| --- | ---: | --- |
| version | 1 byte | connection-ticket version `1` |
| sequence | 8 bytes | nonzero unsigned integer, big-endian |
| tag | 16 bytes | truncated HMAC-SHA-256 under the connection key |

The complete continuation `Proxy-Authorization` value is exactly 41 bytes:
`Bearer ` followed by the unpadded base64url ticket. Its tag binds the H2/H3
transport, method, extended-CONNECT protocol value, normalized authority, path,
version, and sequence. The corresponding response proof uses the same
version/sequence/tag sizes and is exactly 44 bytes in
`nextnonce=<base64url>` form; its tag additionally binds the HTTP status.

The client allocates strictly increasing `uint64` sequence numbers, starting at
1, across concurrent streams on the connection. Send failures may leave gaps;
numbers are never reused. The server retains a 128-position sliding replay
bitmap: a valid out-of-order sequence within the retained window is accepted
once, while a duplicate or a sequence older than the window is rejected.

Before allocating a continuation ticket, the client waits until its sequence
would be fewer than 128 positions ahead of the oldest unresolved authentication
exchange. Completed newer exchanges cannot advance that oldest position. The
reservation is released after response verification or request abandonment;
waiting honors establishment cancellation and connection closure. This bounds
authentication reordering without limiting the lifetime of established streams
or widening the server's replay window.

Connection authentication state is attached to the actual `*tls.Conn` or
`*quic.Conn`, not an address. H3 TCP CONNECT and CONNECT-UDP streams therefore
share the same QUIC-connection state. A replacement H2 or H3 connection,
including the connection selected after H2 GOAWAY, must bootstrap again. A QUIC
path change that remains the same QUIC connection does not reauthenticate.
TLS/QUIC resumption alone never transfers this state to a new connection.

The client verifies the one bootstrap or continuation response value and its
status binding before exposing the stream. Missing, duplicate, malformed, or
mismatched proof makes the connection-authentication state ambiguous, so the
client closes that whole physical connection and any waiters retry on a new
one. On the server, an authentication miss is instead stripped and delegated
to cover without proactively closing the connection.

The full bootstrap ticket's acceptance window is 60 seconds before or after the
server clock. The combined H2/H3 server shares one bounded full-ticket nonce
cache. An accepted nonce is retained through its complete validity window; a
replay or a full cache fails closed into cover. Operators must keep clocks
synchronized.

If a request is missing the credential, has the wrong key, is malformed,
expired, replayed, or otherwise invalid, the handler removes
`Proxy-Authorization` and delegates it to the configured cover. It does not
return a `407`, an AutoCAR product string, or a distinct authentication status.
The actual cover response still depends on the configured static directory or
upstream origin and is not promised to be byte-for-byte identical for every
possible request.

### H3 CONNECT-UDP

Web-cover UDP uses RFC 9298 Extended CONNECT and HTTP Datagrams. It is available
only on H3; H2 has no UDP tunnel role. A request has:

```text
:method = CONNECT
:protocol = connect-udp
:authority = relay origin authority
:path = /.well-known/masque/udp/{target_host}/{target_port}/
Capsule-Protocol: ?1
Proxy-Authorization: Bearer <connection bootstrap or continuation ticket>
```

The path uses RFC 9298's default URI template. Template values use simple
string expansion; bytes outside the RFC 3986 unreserved set are percent-encoded.
An IPv6 target therefore appears without authority brackets inside the path and
with each colon encoded. Query parameters and zone identifiers are rejected.

The HMAC binding includes `h3`, `CONNECT`, `connect-udp`, the relay origin
authority, and the complete escaped path. Authentication is checked before the
path is parsed, admission is acquired, or DNS is invoked. After authentication,
the server validates the template and `Capsule-Protocol`, applies the normal UDP
destination policy, resolves the target once, and connects one UDP socket to one
successfully selected numeric endpoint.

A successful response is 2xx with `Capsule-Protocol: ?1`. Each HTTP Datagram
contains a QUIC variable-length Context ID followed by the UDP payload. This
version accepts only Context ID `0`; other contexts are ignored. The maximum
payload is 1,150 bytes so QUIC/DATAGRAM framing, the HTTP quarter-stream ID,
and Context ID `0` stay within a conservative
1,200-byte QUIC path budget. Oversized payloads are rejected, not fragmented.

Each canonical target uses one authenticated H3 request stream.
A client PacketConn creates those streams lazily, reuses a live stream for the
same target, and applies bounded per-PacketConn targets, client-global sessions,
server-global/per-source sessions, and receive queues. Closing the stream closes
its UDP socket and releases admission. Capsule data fallback and CONNECT-UDP
over H2 are not implemented; negotiated H3 HTTP Datagram and Extended CONNECT
settings are required.

### Web automatic fallback

`web-auto` first opens the standard CONNECT stream over H3. A transport failure
or attempt timeout permits the same new TCP flow to be opened over H2/TCP. A
valid HTTP response, including an authenticated target failure, proves that H3
is reachable and therefore does not trigger transport fallback. After a
transport failure, a cooldown sends new TCP flows directly through H2. Its
configured duration is a base randomized independently by +/-20% after each
failure; after that interval exactly one concurrent flow probes H3.

SOCKS5 UDP in `web-auto` always uses H3 CONNECT-UDP. It never enters the H2
fallback or changes the TCP fallback circuit; it fails when the H3 path or HTTP
Datagram negotiation is unavailable. Explicit `h3` supports CONNECT-UDP, while
explicit `h2` does not advertise UDP.

This is a reliability policy, not a wire downgrade: each new physical H2 or H3
connection performs a fresh full bootstrap and normal certificate verification;
later streams use only that connection's short credentials. It also is not a
generic UDP-over-TCP fallback. Web paths do not carry native pacing negotiation,
and diagnostics report pacing as `not-applicable`.

QUIC 0-RTT is disabled. AutoCAR H2 clients and all H3 connections use TLS 1.3
with normal certificate and name verification. The public H1/H2 server accepts
TLS 1.2 for ordinary cover compatibility, but the handler excludes every TLS
1.2 request from the tunnel path. The public cover cannot require a TLS client
certificate, so web mode rejects mTLS; the dynamic HMAC ticket remains the
tunnel authorization layer.

## Compatibility policy

Changing a native field meaning, authentication exchange or post-response
framing requires a new native ALPN/version. Changing the web ticket transcript,
eligibility rules, or authenticated stream semantics requires a new web-cover
version with an explicit migration plan. AutoCAR intentionally provides no
third-party compatibility mode, legacy QUIC alias, or silent cross-family
downgrade. During a breaking upgrade, run old and new endpoints on separate ports and move clients
explicitly.
