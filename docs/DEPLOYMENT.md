# Deployment guide

AutoCAR has two trusted endpoints: a local proxy client and a relay. The
preferred path is AutoCAR v2 over QUIC/UDP; a separate TLS/TCP listener can
carry new TCP flows when UDP is unavailable.

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

## 2. Relay

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

## 3. Client

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

Default local endpoints are loopback-only SOCKS5 `127.0.0.1:1080` and HTTP
`127.0.0.1:8080`. Use `socks5h://` when the relay should resolve names.

Before leaving a client running, verify a real authenticated relay path with
the same connection flags:

```bash
./autocar doctor \
  --server relay.example.com:8443 \
  --ca /etc/autocar/server.crt \
  --token-file /etc/autocar/relay-token \
  --transport auto \
  --target example.com:443 \
  --json
```

This opens the target TCP connection through the tunnel; it does not merely
check a local listener. The result identifies the selected transport, both
directional pacing policies, negotiated fixed-rate ceilings, elapsed time and
the last fallback transition when applicable. Exit status is `0` for success,
`1` for a failed live probe and `2` for invalid arguments or local
configuration. Failed JSON results expose only a stable code and redacted
description; use human mode when detailed local diagnostics are required.
Auto-mode client logs expose only stable fallback/recovery event and reason
codes, never tokens, full targets, relay addresses or raw transport errors.
Event callbacks are asynchronous, serialized and backed by a bounded queue;
consumers that fall behind should read the concurrency-safe snapshot as the
authoritative latest state. The most recently completed path is tracked
separately from QUIC circuit health.

## 4. Pacing

Use `adaptive-balanced` first. `conservative` reduces probing on shared or
shallow-buffer paths; `aggressive` should be enabled only after measuring both
throughput and queue delay. `reno` disables the AutoCAR pacing layer and leaves
the upstream quic-go path as the baseline.

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

## 5. mTLS and local proxy authentication

To require a client certificate, configure `--client-ca` on the relay and
`--client-cert/--client-key` on the client. The shared token remains a second
authorization factor.

SOCKS5 username/password and HTTP Basic are cleartext on the local hop. Keep
those listeners on loopback or enable the local HTTPS proxy. A non-loopback
plaintext listener requires an explicit override and should still be protected
by a trusted private network/firewall.

## 6. systemd example

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

## 7. Container

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

The image runs as UID/GID `65532` and exposes `8443`, so mounting the root-owned
systemd credential directory directly would normally be unreadable. Rootless or
user-namespace-remapped Docker uses a different host-ID mapping; prepare the
mount for the mapped runtime UID instead, and publish a non-privileged host port
unless the rootless runtime has been explicitly authorized to bind `443`. The
image does not need host networking. Apply memory, CPU, PID and file-descriptor
limits appropriate to the configured connection limits.

## 8. Validation and upgrade

Before production:

```bash
go test ./...
go test -race ./...
./autocar doctor [client flags] --target target.example:443 --json
./autocar bench-client [client flags] --target target.example:9000 --json
```

Also test UDP and TCP firewall rules separately, an invalid token, an invalid
certificate, UDP blackhole fallback, SOCKS5 UDP, destination-policy rejection
and shutdown under load.

`autocar/2` is incompatible with Hysteria and AutoCAR v1. For a rolling breaking
upgrade, start the new relay on a second UDP/TCP port, move clients, verify QUIC
and fallback independently, and then retire the old endpoint. There is no silent
protocol downgrade.
