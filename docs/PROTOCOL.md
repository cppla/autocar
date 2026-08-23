# AutoCAR protocol v2

AutoCAR v2 is an AutoCAR-owned protocol carried by TLS 1.3. Its ALPN is
`autocar/2`. It is not compatible with Hysteria v2 or AutoCAR v1.

The QUIC transport uses one bidirectional stream per TCP flow or UDP control
association. The TCP/TLS fallback uses one TLS connection per TCP flow and the
same stream request/response format. UDP payloads are available only on QUIC.

All integers are unsigned, big-endian. Receivers validate fixed headers and all
attacker-controlled sizes before allocation.

## Stream header

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

### Enums

Networks: `1=tcp`, `2=tcp4`, `3=tcp6`, `4=udp association`.

Statuses: `0=ok`, `1=bad request`, `2=unauthorized`, `3=destination
unavailable`, `4=busy`, `5=internal`.

Sender modes: `0=unspecified`, `1=adaptive`, `2=reno/bypass`,
`3=fixed-rate`.

Profiles: `0=unspecified`, `1=conservative`, `2=balanced`, `3=aggressive`.

## TCP CONNECT

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

## UDP association control

A UDP request has network `4`, an empty address, and a random nonzero request
nonce in the Session ID field. Its body contains only the token. The nonce does
not reserve or choose the runtime session. On success the relay allocates an
independent, nonzero ID that is unique among active associations on that QUIC
connection and returns it in the response. Both directions use this assigned ID
in subsequent `ACDG` frames.

The control stream stays open as the association lease. Closing it destroys the
corresponding socket, removes the assigned ID and discards all incomplete
reassembly state for that ID before a later association can reuse it.

## `ACDG` DATAGRAM format

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

## Transport security and replay

- TLS 1.3 and normal certificate verification are mandatory.
- QUIC 0-RTT is disabled, so CONNECT requests and tokens are never sent as
  replayable early data.
- A token is authenticated on every control stream; the first valid stream also
  ends the connection's pre-authentication lifetime.
- TCP fallback uses the same ALPN and request parser, but does not advertise UDP
  or carry QUIC sender-pacing metadata.

## Compatibility policy

Changing any field meaning, authentication exchange or post-response framing
requires a new ALPN/version. AutoCAR v2 intentionally provides no Hysteria mode,
legacy QUIC alias or protocol downgrade. During a breaking upgrade, run old and
new endpoints on separate ports and move clients explicitly.
