# Deployment guide

AutoCAR has two trusted endpoints: a local proxy client and a relay. Native mode
prefers AutoCAR v2 over QUIC/UDP and can use a separate native TLS/TCP listener.
Experimental, opt-in web-cover mode presents one normal website over H1/H2/TCP
and H3/UDP and can carry new TCP flows over H2 when UDP is unavailable. Choose one relay protocol
per endpoint and configure clients to match it. The defaults remain a `native`
relay and an `auto` client; installing v1.0.1 does not enable web-cover.

## 1. Build and create credentials

```bash
go build -trimpath -o autocar ./cmd/autocar
sudo install -o root -g root -m 0755 autocar /usr/local/bin/autocar

# Once per host; use your distribution's equivalent if useradd is unavailable.
sudo useradd --system --user-group --home-dir /nonexistent \
  --shell /usr/sbin/nologin autocar
sudo install -d -o autocar -g autocar -m 0700 /etc/autocar
sudo -u autocar /usr/local/bin/autocar token --out /etc/autocar/relay-token
sudo -u autocar /usr/local/bin/autocar cert \
  --hosts relay.example.com,203.0.113.10 \
  --cert /etc/autocar/server.crt \
  --key /etc/autocar/server.key
```

Keep the private key only on the relay. Copy the token and trust anchor through
an authenticated channel. The relay process must be able to traverse the
credential directory and read its files: the private key must be a regular file
with mode exactly `0600`, and the token must have no group/other permission bits
(`autocar token` creates it as `0600`). Generate or install them as the runtime
user rather than leaving root-owned `0600` files for `User=autocar`. Do not reuse
the relay token as a local proxy password.

On each client, install the copied token with no group/other permission bits and
make both token and CA certificate readable by that client's runtime user. The
client paths below assume that ownership has already been set correctly.

External certificates are supported as long as their SAN covers the configured
server name and the client trusts the issuing CA. AutoCAR performs normal chain,
name and validity checks and has no certificate-verification bypass.

## 2. Native relay

```bash
sudo -u autocar /usr/local/bin/autocar server \
  --listen :8443 \
  --tcp-listen :8443 \
  --cert /etc/autocar/server.crt \
  --key /etc/autocar/server.key \
  --token-file /etc/autocar/relay-token \
  --pacing adaptive \
  --pacing-profile balanced
```

This manual example uses an unprivileged port. UDP and TCP may use the same port
number; open both protocols in the host/cloud firewall. `--disable-tcp-fallback`
removes the TCP listener; do this only after testing every client network.

The relay defaults to denying loopback, private, link-local, multicast,
unspecified and IANA special-purpose destinations plus SMTP submission ports.
Use `--allow-private` only when the relay is intentionally allowed to reach
RFC1918/ULA/CGNAT targets. It never opens loopback or link-local metadata
services. Add deployment-specific blocks with `--deny-cidrs` and
`--deny-ports`.

Resource controls include `--max-connections`, `--max-client-connections`,
`--max-streams` and `--max-client-fallback-connections`. `--max-streams` is one
global admission budget shared by the QUIC and TLS listeners; enabling fallback
does not double the configured stream capacity.

QUIC UDP associations have separate bounded controls:

- `--max-udp-sessions` globally and `--max-client-udp-sessions` per source;
- `--max-udp-destinations` for each association;
- `--udp-receive-queue` for each bounded datagram work queue; and
- `--udp-reassembly-ttl`, `--max-udp-reassembly-messages`, and
  `--max-udp-reassembly-bytes` for incomplete messages on each QUIC connection.

All UDP limits must be positive, and the per-source session limit cannot exceed
the global UDP session limit. Start conservatively, watch memory/file
descriptors and put host-level per-source UDP rate limits in front of a public
relay.

## 3. Web-cover relay

Use web-cover only with a domain and site content you own or are authorized to
serve. The static form is:

```bash
sudo -u autocar /usr/local/bin/autocar server \
  --protocol web \
  --listen :8443 \
  --tcp-listen :8443 \
  --cover-root /srv/autocar-cover \
  --cert /etc/autocar/server.crt \
  --key /etc/autocar/server.key \
  --token-file /etc/autocar/relay-token
```

For a fixed authorized origin, replace `--cover-root` with, for example,
`--cover-upstream https://origin.example.net`. The two flags are mutually
exclusive and exactly one is required. The reverse proxy fixes the upstream
scheme and authority, rewrites `Host`, strips authorization and hop-by-hop
headers, and preserves the request path and query. Treat that origin as an
Internet-facing application; do not point it at metadata or control-plane
services.

`--listen` binds H3/UDP and `--tcp-listen` binds HTTPS/H1/H2. They must use the
same numeric port; if `--tcp-listen` is omitted it inherits `--listen`. Open both
TCP and UDP in the deployment firewall. `--disable-tcp-fallback` is invalid in
web mode because H2/TCP is part of the mode. `--client-ca` is also invalid: a
normal cover origin must complete TLS without requesting a client certificate.
The public TCP listener accepts TLS 1.2 and TLS 1.3 so ordinary website probes
can negotiate either version. Authenticated H2 tunnels remain TLS 1.3-only; a
TLS 1.2 CONNECT has its credential stripped and is handled only by the cover.
H3 remains TLS 1.3.

Web mode uses the same remote resolver and destination policy as native mode,
and shares one `--max-streams` admission budget across H2 and H3 tunnels. H3
CONNECT-UDP also uses `--max-udp-sessions`,
`--max-client-udp-sessions`, `--max-udp-destinations`, and
`--udp-receive-queue`. In web mode one UDP target consumes one request stream
and one UDP session; `--max-udp-destinations` bounds the numeric candidates
returned for that one target before a single endpoint is fixed. Native
reassembly flags do not apply because web datagrams are not fragmented. Native
connection/session flags do not substitute for ordinary public-web controls.
Apply host/container file-descriptor, memory, CPU, connection, request-rate,
and bandwidth limits appropriate to the exposed cover site.

Public cover compatibility is best checked with a real SAN-valid certificate,
an ordinary site, TLS 1.2 and TLS 1.3 H1/H2 probes, and an H3 client. Include a
TLS 1.2 CONNECT carrying a syntactically valid ticket in an owned-lab test and
verify that it receives cover behavior without any destination dial. A private
CA remains supported for closed deployments, but its handshake is not
representative of a broadly trusted public website.

## 4. Client

### Native client

Pinned/private CA:

```bash
./autocar client \
  --server relay.example.com:8443 \
  --ca /etc/autocar/server.crt \
  --token-file /etc/autocar/relay-token \
  --transport auto \
  --pacing adaptive \
  --pacing-profile balanced
```

For a public CA, replace `--ca` with the explicit `--system-roots`. If the
connection address and certificate name differ, set `--server-name`.

`auto` gives the full QUIC attempt a budget and then uses TLS for new TCP flows.
`--quic-attempt-timeout` must be shorter than `--open-timeout` so fallback keeps
time to succeed. `--fallback-cooldown` prevents every new TCP connection from
paying the same UDP blackhole timeout. Use `--transport=quic` to require UDP or
`--transport=tls` to require TCP. TLS mode does not offer SOCKS5 UDP ASSOCIATE;
`auto` advertises UDP, but an association is still QUIC-only and fails when QUIC
is unavailable rather than crossing the TLS fallback.

### Web-cover client

```bash
./autocar client \
  --server relay.example.com:8443 \
  --system-roots \
  --token-file /etc/autocar/relay-token \
  --transport web-auto \
  --h3-fingerprint chrome-2026-08 \
  --quic-attempt-timeout 5s \
  --open-timeout 15s \
  --fallback-cooldown 30s
```

Use `--ca /path/to/ca.pem` instead of `--system-roots` for a private trust
anchor. `web-auto` tries standard H3 CONNECT first and switches a new TCP flow
to standard H2 CONNECT after an H3 transport failure. During the cooldown, new
TCP flows use H2 without repeating the UDP wait. The configured cooldown is a
base with independent +/-20% jitter; after it, exactly one caller probes H3.
Use `--transport=h3` or `--transport=h2` to require one path during diagnosis.

`chrome-2026-08` is the default H3 fingerprint. It uses the exactly pinned
`github.com/apernet/quic-go` fork for the complete client
QUIC/TLS handshake profile and a zero-length source CID. Use
`--h3-fingerprint=native` only as an interoperability or rollback diagnostic; it
disables ChromeParrot within the same web-H3 fork and does not select native
`autocar/2`. The profile is client-only and does not claim to reproduce server
behavior, H3 SETTINGS, CONNECT traffic or timing.

H3 and H2 use the same `--server` address, so `--fallback-server` is not valid
with web transports. Web transports reject `--client-cert/--client-key` and
`--pacing=fixed-rate`; native pacing metadata is reported as
`not-applicable`. Both `web-auto` and explicit `h3` advertise SOCKS5 UDP using
H3 RFC 9298 CONNECT-UDP. Explicit `h2` does not. The H3-to-H2 policy is for TCP
streams only: UDP fails when H3 is unavailable and never enters H2. Full
behavior and limits are in [WEB_COVER.md](WEB_COVER.md).

Default local endpoints are loopback-only SOCKS5 `127.0.0.1:1080` and HTTP
`127.0.0.1:8080`. Use `socks5h://` when the relay should resolve names.

Before leaving a client running, verify a real authenticated relay path with
the same connection flags:

```bash
./autocar doctor \
  --server relay.example.com:8443 \
  --ca /etc/autocar/server.crt \
  --token-file /etc/autocar/relay-token \
  --transport web-auto \
  --target example.com:443 \
  --json
```

This opens the target TCP connection through the tunnel; it does not merely
check a local listener. The result identifies the selected transport and
elapsed time. Native QUIC also reports sender/rate negotiation; web H2/H3
reports pacing as `not-applicable`. Exit status is `0` for success, `1` for a
failed live probe and `2` for invalid arguments or local configuration. Failed
JSON results expose only a stable code and redacted description; use human mode
when detailed local diagnostics are required.

Native auto-mode logs expose only stable fallback/recovery event and reason
codes, never tokens, full targets, relay addresses or raw transport errors. Its
event callbacks are asynchronous, serialized and backed by a bounded queue;
consumers that fall behind should read the concurrency-safe snapshot as the
authoritative latest state. The most recently completed native path is tracked
separately from QUIC circuit health.

## 5. Pacing

Use `adaptive-balanced` first. `conservative` reduces probing on shared or
shallow-buffer paths; `aggressive` should be enabled only after measuring both
throughput and queue delay. `reno` disables the AutoCAR pacing layer and leaves
the native upstream quic-go path as the baseline. Web H3 uses the separate pinned
fork and does not participate in native pacing negotiation.

Fixed-rate is appropriate only for a measured, provisioned link:

```bash
# Relay policy: finite limits in both directions and explicit client opt-in.
./autocar server [credential/policy flags] \
  --pacing fixed-rate \
  --max-upload-mbps 80 \
  --max-download-mbps 250 \
  --allow-client-rates

# Client request, no higher than its measured access link.
./autocar client [connection flags] \
  --transport quic \
  --pacing fixed-rate \
  --upload-mbps 60 \
  --download-mbps 200
```

The protocol response reports the actual directional rates. These settings are
cooperative sender pacing, not an authorization boundary. Enforce tenant quotas
with `tc`, nftables or cloud policers. Fixed-rate negotiation exists only on
QUIC: explicit `tls` is rejected, while an `auto` TCP flow that falls back to TLS
is unpaced. Select `quic` when the rate behavior is required.

## 6. mTLS and local proxy authentication

To require a client certificate, configure `--client-ca` on the relay and
`--client-cert/--client-key` on the client. The shared token remains a second
authorization factor. This is available only in native mode. Web-cover rejects
mTLS on both sides so that ordinary visitors can reach the cover site; its
per-request HMAC ticket remains mandatory for tunnel access.

SOCKS5 username/password and HTTP Basic are cleartext on the local hop. Keep
those listeners on loopback or enable the local HTTPS proxy. A non-loopback
plaintext listener requires an explicit override and should still be protected
by a trusted private network/firewall.

## 7. systemd example

`/etc/systemd/system/autocar.service`:

```ini
[Unit]
Description=AutoCAR relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=autocar
Group=autocar
ExecStart=/usr/local/bin/autocar server --listen=:443 --tcp-listen=:443 --cert=/etc/autocar/server.crt --key=/etc/autocar/server.key --token-file=/etc/autocar/relay-token --pacing=adaptive --pacing-profile=balanced
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/etc/autocar
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

The two capability lines are needed only because this example binds UDP and TCP
port 443 as an unprivileged user. Alternatively bind both listeners to a port at
or above 1024, remove those lines and redirect/publish the port outside the
process.

For web-cover, use the same hardening but select web protocol and an authorized
cover source:

```ini
ExecStart=/usr/local/bin/autocar server --protocol=web --listen=:443 --tcp-listen=:443 --cover-root=/srv/autocar-cover --cert=/etc/autocar/server.crt --key=/etc/autocar/server.key --token-file=/etc/autocar/relay-token
```

Add the cover directory to `ReadOnlyPaths` (or an equivalent read-only bind) and
ensure `User=autocar` can traverse and read it.

## 8. Container

```bash
docker build -t autocar:local .

# For rootful Docker on Linux, prepare a separate bind mount readable by the
# image's numeric runtime UID without weakening the key/token modes.
sudo install -d -o 65532 -g 65532 -m 0700 /etc/autocar-container
sudo install -o 65532 -g 65532 -m 0644 \
  /etc/autocar/server.crt /etc/autocar-container/server.crt
sudo install -o 65532 -g 65532 -m 0600 \
  /etc/autocar/server.key /etc/autocar-container/server.key
sudo install -o 65532 -g 65532 -m 0600 \
  /etc/autocar/relay-token /etc/autocar-container/relay-token

docker run --rm \
  -p 443:8443/udp -p 443:8443/tcp \
  -v /etc/autocar-container:/etc/autocar:ro \
  autocar:local server \
  --listen=:8443 --tcp-listen=:8443 \
  --cert=/etc/autocar/server.crt \
  --key=/etc/autocar/server.key \
  --token-file=/etc/autocar/relay-token
```

For a static web-cover container, mount the authorized site read-only and add
the web flags while keeping both TCP and UDP port publications:

```bash
docker run --rm \
  -p 443:8443/udp -p 443:8443/tcp \
  -v /etc/autocar-container:/etc/autocar:ro \
  -v /srv/autocar-cover:/srv/www:ro \
  autocar:local server \
  --protocol=web \
  --listen=:8443 --tcp-listen=:8443 \
  --cover-root=/srv/www \
  --cert=/etc/autocar/server.crt \
  --key=/etc/autocar/server.key \
  --token-file=/etc/autocar/relay-token
```

The image runs as UID/GID `65532` and exposes `8443`, so mounting the root-owned
systemd credential directory directly would normally be unreadable. Rootless or
user-namespace-remapped Docker uses a different host-ID mapping; prepare the
mount for the mapped runtime UID instead, and publish a non-privileged host port
unless the rootless runtime has been explicitly authorized to bind `443`. The
image does not need host networking. Apply memory, CPU, PID and file-descriptor
limits appropriate to the configured connection limits.

## 9. Validation and upgrade

Before production:

```bash
go test ./...
go test -race ./...
./autocar doctor [client flags] --target target.example:443 --json
./autocar bench-client [client flags] --target target.example:9000 --json
```

Also test TCP and UDP firewall rules separately, an invalid token, an invalid
certificate, UDP blackhole fallback, destination-policy rejection, and shutdown
under load. For native mode, test SOCKS5 UDP separately. For web mode, verify
ordinary H1/H2/H3 cover behavior and explicit `h3`, explicit `h2`, and
`web-auto` TCP paths. Verify CONNECT-UDP with an owned UDP fixture over `h3` and
`web-auto`, including its 1,150-byte boundary and expected failure while H3 is
blocked. Run active probes only against loopback, isolated Docker networks, or
systems you own or are explicitly authorized to test; never scan unrelated
public endpoints.

A low-memory remote Linux host may run a non-release active smoke from an
already loaded, matching image pair:

```bash
STEALTH_RELEASE_GATE=0 STEALTH_RUN_ROLE=remote-linux \
  STEALTH_EXECUTION_HOST=198.51.100.10:22 \
  STEALTH_AUTOCAR_IMAGE=autocar:smoke \
  STEALTH_LAB_IMAGE=autocar-stealth-lab:smoke \
  ./scripts/stealth-active.sh
```

Both image variables are mandatory together, and the harness must be launched
from a direct session to the host named by `STEALTH_EXECUTION_HOST` and from a
valid AutoCAR Git checkout so it can record source-state stability. This
avoids compiling on that host but is smoke evidence only: the optional research
gate rejects prebuilt images because it must build from the exact frozen Git archive.
Remote manifests also record the ED25519 host-key fingerprint derived from the
machine's `/etc/ssh/ssh_host_ed25519_key.pub`; release evidence must match the
endpoint and fingerprint frozen in the preregistration. See
[STEALTH-BENCHMARK.md](STEALTH-BENCHMARK.md) for the research evidence contract,
and [RELEASING.md](RELEASING.md) for ordinary release quality checks.

`autocar/2` and web-cover do not provide third-party proxy or AutoCAR v1 compatibility.
The shared web-H3 QUIC implementation does not change that protocol boundary.
For a rolling breaking upgrade, start the new relay on a second UDP/TCP port,
move clients, verify each selected transport independently, and then retire the
old endpoint. There is no silent protocol-family downgrade.

## 10. v1.0.0 to v1.0.1 upgrade and rollback

The version number v1.0.0 is not the retired AutoCAR v1 wire protocol. Both
v1.0.0 and v1.0.1 native endpoints use `autocar/2`; web-cover is new in v1.0.1
and requires matching web-capable endpoints. Keep the existing native
configuration when a feature change is not intended.

1. Download the archive for the host architecture and verify its entry in the
   release's `SHA256SUMS`. Record `autocar version` and retain the previous
   executable, service definition, token, certificate, and configuration in a
   protected backup. Do not put secrets in a release report.
2. Test v1.0.1 on a separate, explicitly permitted TCP/UDP port with the same
   certificate trust and destination policy. For a native rolling upgrade,
   test the old client against the new relay and the new client against the
   old relay for every transport actually used: `quic`, `tls`, `auto`, and
   SOCKS5 UDP where required. A successful `doctor` only checks a TCP open;
   also exercise application traffic and UDP separately.
3. Replace one endpoint at a time, restart its managed service, and rerun those
   checks before proceeding. Restarting an endpoint disconnects its current
   streams; drain or schedule an interruption where needed.
4. To try web-cover, keep the native endpoint available on its original port
   and bring up a separate v1.0.1 `--protocol web` endpoint. Move only opted-in
   clients to `web-auto`, `h3`, or `h2`. Check cover responses, authenticated
   TCP, H3 CONNECT-UDP's 1,150-byte boundary, invalid credentials and the H3-to-H2
   new-flow fallback before wider use. Web mode does not support mTLS or H2 UDP.
5. For a native rollback, restore the recorded v1.0.0 executable and native
   service configuration, restart, and repeat the same path checks. For a web
   rollback, move clients back to the retained native endpoint/configuration
   first; a v1.0.0 executable cannot consume web flags or speak the web protocol.
   Do not overwrite working keys or tokens merely to roll back a binary.

These are deployment acceptance steps, not a claim that every operating
system, network, or application has been tested. Cross-compiled release
archives alone are not native runtime validation for their target platform.
