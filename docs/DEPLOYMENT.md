# Deployment guide

AutoCAR has two roles: a relay near the desired destinations and a client-side
process exposing local SOCKS5 and HTTP(S) proxies. The default path is Hysteria
v2 over HTTP/3/QUIC on UDP. A separate TLS 1.3/TCP listener can use the same
numeric port for new-flow fallback.

## 1. Build and install

AutoCAR requires the Go version declared in `go.mod`:

```sh
make check
make build
sudo install -m 0755 bin/autocar /usr/local/bin/autocar
```

The binary is statically buildable with `CGO_ENABLED=0`; `make cross-build`
produces cross-platform artifacts. Linux is the primary relay target. The
local proxy also builds on macOS and Windows.

## 2. Create credentials

Create a dedicated unprivileged account and a private configuration directory.
AutoCAR rejects secret/key files that are accessible by group or other users.

```sh
sudo useradd --system --home /var/lib/autocar --shell /usr/sbin/nologin autocar
sudo install -d -o autocar -g autocar -m 0700 /etc/autocar

sudo -u autocar autocar token --out=/etc/autocar/relay-token
sudo -u autocar autocar cert \
  --hosts=relay.example.com,203.0.113.10 \
  --cert=/etc/autocar/server.crt \
  --key=/etc/autocar/server.key
```

The bundled certificate command creates an ECDSA P-256 self-signed
certificate. Copy its certificate (never the private key) and the token to
each client over a trusted independent channel. Use the certificate as `--ca`.
For a public-CA certificate, clients can explicitly choose `--system-roots`.
There is no certificate-verification bypass. Default Chrome QUIC fingerprinting
supports ECDSA P-256/P-384 and RSA relay certificates but intentionally does not
advertise Ed25519. If an external issuer supplies an Ed25519 leaf, every
Hysteria client must use `--disable-chrome-parrot`; AutoCAR adds this exact hint
to a matching TLS handshake failure. Prefer P-256/P-384/RSA so the secure default can
remain enabled.

Keep token, private key, optional client key, and obfuscation secret out of the
repository and container image. Give each secret a distinct random value; do
not reuse the relay token as a Salamander password or local-proxy password.

## 3. Run the relay with default BBR

This is a complete foreground example using the default Hysteria engine,
BBRv1 `standard`, UDP proxying, neutral HTTP/3 cover, and TLS fallback:

```sh
sudo -u autocar autocar server \
  --listen=:8443 \
  --quic-engine=hy2 \
  --tcp-listen=:8443 \
  --cert=/etc/autocar/server.crt \
  --key=/etc/autocar/server.key \
  --token-file=/etc/autocar/relay-token \
  --congestion=bbr \
  --bbr-profile=standard \
  --max-upload-mbps=0 \
  --max-download-mbps=0 \
  --max-connections=256 \
  --max-client-connections=32 \
  --max-client-fallback-connections=32 \
  --max-streams=1024 \
  --max-uni-streams=8 \
  --max-outbound-tcp=1024 \
  --max-outbound-udp=256 \
  --max-client-tcp-handlers=128 \
  --max-client-udp-sessions=64 \
  --handshake-timeout=10s \
  --udp-idle-timeout=60s \
  --masquerade-name="Example Service"
```

The relay ignores client bandwidth hints by default, so this selects BBR rather
than a guessed or client-forced Brutal rate. Enabling client hints is a separate
explicit opt-in described below and requires two finite relay ceilings.
`--bbr-profile=conservative` is a good first choice on shared/shallow-buffer
links; `aggressive` should be reserved for measured controlled paths.
`--congestion=reno` offers a loss-based baseline. Controller settings affect
only traffic sent by the endpoint on which they are configured.

Production deployments often use port 443. Permit both UDP and TCP. Binding a
low port as non-root requires a narrow capability such as
`CAP_NET_BIND_SERVICE`, or one-to-one UDP and TCP port forwarding. A load
balancer must use UDP/TCP pass-through; terminating TLS or HTTP/3 in front of
AutoCAR changes the required end-to-end protocol.

### Destination policy

The relay rejects loopback, link-local, multicast, unspecified, RFC1918, ULA,
CGNAT, translation, documentation, benchmarking, reserved, and other
special-use destinations by default. It also denies ports 25, 465, and 587.

- `--allow-private` permits RFC1918/ULA/CGNAT but never loopback, link-local, or
  the built-in special-use denylist. Use it only on a relay dedicated to
  trusted users.
- `--deny-cidrs` adds deployment-specific IPs/CIDRs such as cloud control-plane
  ranges.
- `--deny-ports=none` clears the port denylist and is a deliberate security
  policy change.
- `--disable-udp` disables Hysteria UDP sessions and SOCKS5 UDP ASSOCIATE.

TCP hostnames are resolved once into approved numeric dial candidates. UDP is
resolved and filtered during the permission check and again on every outbound
write, preventing DNS rebinding from bypassing the egress policy.

## 4. Run the client

The default `auto` mode first uses Hysteria v2 and falls back to TLS/TCP for new
TCP flows when UDP is unavailable:

```sh
autocar client \
  --server=relay.example.com:443 \
  --transport=auto \
  --ca=/etc/autocar/relay-ca.crt \
  --token-file=/etc/autocar/relay-token \
  --congestion=bbr \
  --bbr-profile=standard \
  --upload-mbps=0 \
  --download-mbps=0 \
  --fast-open=false \
  --max-pending-opens=256 \
  --socks=127.0.0.1:1080 \
  --http=127.0.0.1:8080
```

`--transport=hy2` and its alias `--transport=quic` require UDP and do not fall
back. `--transport=tls` diagnoses the fallback directly. If TCP uses a
different address, set `--fallback-server`.

Fast Open defaults to off so a destination refusal is returned before the
application sees an established proxy connection. `--fast-open=true` can
reduce a round trip for write-first protocols, but defers the relay dial result
until the first read and should be enabled only after testing application error
handling.

`--quic-attempt-timeout` bounds the primary UDP attempt,
`--fallback-cooldown` controls how long new TCP flows prefer TLS after a UDP
failure, and `--open-timeout` bounds the whole proxy open. In `auto`, keep
`0 < --quic-attempt-timeout < --open-timeout` so fallback retains time. A
relay destination error or authentication failure does not open the fallback
circuit. `--max-pending-opens` bounds Hysteria core operations that cannot be
interrupted through its public API; canceled callers return immediately, but
their late workers retain a slot until the core returns or the session closes.

Fallback is not live migration. A stream already returned to an application
fails if its QUIC connection becomes unusable; the application must retry, and
the new TCP flow can use TLS. SOCKS5 UDP has no TLS/TCP fallback.

Application examples:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
curl --proxy http://127.0.0.1:8080 https://example.com/
```

The SOCKS5 frontend supports CONNECT and UDP ASSOCIATE, but not BIND. The HTTP
proxy supports absolute-form `http://` and CONNECT. Absolute-form `https://`
is rejected; HTTPS destinations use CONNECT, leaving application TLS end to
end. AutoCAR never installs an interception CA.

## 5. Opt into negotiated Brutal

Use Brutal only after measuring the access link and only where reserving that
rate is permitted. The client values request the two directional rates; relay
values set negotiation ceilings for cooperating clients:

```sh
# Relay: bound negotiated Brutal targets
autocar server [relay options] \
  --allow-client-bandwidth \
  --max-upload-mbps=20 \
  --max-download-mbps=100

# Client: truthful measured capacities
autocar client [client options] \
  --upload-mbps=20 \
  --download-mbps=100
```

A zero client value keeps BBR/Reno in that direction. With non-zero client and
relay values, the lower value wins. Set `--disable-loss-compensation` on both
roles to disable the five-second ACK/loss compensation in both directions.
Without `--allow-client-bandwidth`, the server ignores all client hints and
forces its configured BBR/Reno behavior. The opt-in is rejected unless both
server ceilings are non-zero.

Brutal can send about 1.25 times the requested rate under measured loss. It is
not congestion-fair; an exaggerated value can starve other traffic, waste
capacity, and trigger a provider policer. Relay negotiation ceilings are an
important guardrail for the official client, but they are not a traffic
policer: use host or cloud rate limiting when a hard, non-bypassable ceiling is
required.

## 6. Choose one probe-resistance form

### Plain HTTP/3 cover

With no obfuscation secret, the relay is a valid HTTP/3 endpoint.
Unauthenticated probes receive the neutral site named by `--masquerade-name`.
The client uses Hysteria's Chrome-oriented QUIC fingerprint by default;
normally `--disable-chrome-parrot` is intended for diagnostics. It is also
required when the relay deliberately uses an Ed25519 certificate; ECDSA P-256
(including `autocar cert`) and RSA work with the default fingerprint.

### Salamander-obfuscated UDP

Generate a separate secret and install the same 0600 file on both endpoints:

```sh
sudo -u autocar autocar token --out=/etc/autocar/obfs-password

# Add to both relay and client commands:
--obfs-password-file=/etc/autocar/obfs-password
```

The alternative `AUTOCAR_OBFS_PASSWORD` environment variable is supported but
must be protected from service-manager and process-environment disclosure.
Salamander requires the `hy2` engine and changes the outer UDP packet form.
An ordinary HTTP/3 probe can no longer reach the inner cover page; cover and
Salamander are alternative observable modes. The TCP fallback is unaffected.

Neither mode guarantees that a network operator cannot classify, rate-limit,
or block the relay. Endpoint IP, timing, volume, packet sizes, and TCP/UDP use
remain visible.

## 7. Firewall and UDP rate limits

Allow both protocols on the relay's selected port, restricted by source ranges
when possible:

```sh
sudo ufw allow from 198.51.100.0/24 to any port 443 proto udp
sudo ufw allow from 198.51.100.0/24 to any port 443 proto tcp
```

`--max-connections` bounds all accepted QUIC sessions, including
unauthenticated cover traffic; `--max-client-connections` prevents one
return-path-validated source key from occupying the whole connection budget.
The key is one IPv4 address or one IPv6 `/64`, preventing ordinary IPv6 address
rotation from bypassing the budget.
`--max-streams` bounds incoming streams per QUIC connection.
The same value is the global TLS/TCP fallback connection gate, while
`--max-client-fallback-connections` prevents one IPv4 address or IPv6 `/64`
from occupying it during the TLS handshake or relay lifetime. Its zero default
selects the smaller of 32 and `--max-streams`; set a positive value only when
the measured client concurrency requires a different source budget.
`--max-uni-streams` separately limits Hysteria/HTTP/3 control
streams, while `--handshake-timeout` closes an accepted connection that does
not authenticate in time and also bounds the initial TCP target header. A
global pending-TCP-handler gate prevents slow streams from bypassing the
listener-wide `--max-outbound-tcp` backstop. The
`--max-client-tcp-handlers` source budget is shared across QUIC connections,
so one authenticated source cannot occupy the complete global gate. HTTP
request headers are rejected above 16 KiB before body allocation. UDP sessions
are admitted before fragment state is allocated, with both `--max-outbound-udp` global and
`--max-client-udp-sessions` per-authenticated-source-key limits shared across
QUIC connections. IPv4 is keyed per address and IPv6 per `/64`. Clients behind
the same NAT or routed prefix share all three per-source
connection/TCP/UDP budgets;
increase them only after measuring legitimate concurrency, while retaining the
global caps as protection against source-address rotation.
Fragment count and reassembled size are also bounded. Capacity is released on
close. QUIC Retry validates the source address before a bounded handshake slot
is allocated. Initial packets still consume kernel and link work, so combine
these controls with a host/cloud UDP rate guard. The following nftables fragment is a template
for an existing firewall. It drops per-source UDP above 25 MiB/s (about
210 Mbit/s) with an 8 MiB burst, then leaves the accept/drop policy to the
site's normal filter chain:

```nft
table inet autocar_guard {
    chain input {
        type filter hook input priority -5; policy accept;

        udp dport 443 meter autocar_udp4 {
            ip saddr limit rate over 25 mbytes/second burst 8 mbytes
        } drop

        udp dport 443 meter autocar_udp6 {
            ip6 saddr limit rate over 25 mbytes/second burst 8 mbytes
        } drop
    }
}
```

Validate nftables syntax on the target distribution before loading it. Set the
limit above the largest authorized Brutal sender rate plus protocol overhead;
a lower firewall ceiling silently invalidates the negotiated rate. Also apply
provider edge limits because host rules cannot recover bandwidth already
consumed upstream. Keep SSH/management access in a separately tested rule set.

SOCKS5 UDP ASSOCIATE returns a dynamically allocated local UDP port. If the
client proxy runs in a container, ordinary fixed TCP port publishing does not
publish that dynamic UDP endpoint. Use a host-local client process or a
carefully firewalled host-network deployment for applications that need SOCKS
UDP.

## 8. Hardened systemd relay

```ini
[Unit]
Description=AutoCAR relay
After=network-online.target
Wants=network-online.target

[Service]
User=autocar
Group=autocar
ExecStart=/usr/local/bin/autocar server --listen=:443 --quic-engine=hy2 --tcp-listen=:443 --cert=/etc/autocar/server.crt --key=/etc/autocar/server.key --token-file=/etc/autocar/relay-token --congestion=bbr --bbr-profile=standard --max-upload-mbps=0 --max-download-mbps=0 --masquerade-name=Example-Service
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
```

Run `systemd-analyze security autocar.service`, adapt restrictions to the host,
then test UDP and TCP separately. A watchdog should probe both because a green
TCP fallback does not prove that Hysteria UDP is reachable.

## 9. Local proxy exposure

Unauthenticated local proxy listeners are restricted to loopback. To expose a
listener on another interface, configure credentials and explicitly
acknowledge that SOCKS username/password and HTTP Basic are cleartext on those
listeners:

```sh
AUTOCAR_PROXY_USER=alice autocar client [client options] \
  --proxy-password-file=/etc/autocar/proxy-password \
  --allow-public-plaintext \
  --socks=0.0.0.0:1080 \
  --http=0.0.0.0:8080
```

Prefer the TLS-protected local HTTPS proxy across an untrusted LAN:

```sh
autocar cert \
  --hosts=localhost,127.0.0.1 \
  --cert=proxy.crt --key=proxy.key

autocar client [client options] \
  --socks= --http= \
  --https=127.0.0.1:8444 \
  --proxy-cert=proxy.crt \
  --proxy-key=proxy.key

curl --proxy https://127.0.0.1:8444 \
  --proxy-cacert proxy.crt https://example.com/
```

Local proxy credentials protect the listener; they do not replace the relay
token or X.509 verification. Use host firewall rules even with authentication.

## 10. Optional mutual TLS

The token remains mandatory. mTLS adds a client-certificate factor:

```sh
# Relay
autocar server [relay options] \
  --client-ca=/etc/autocar/client-ca.crt

# Client
autocar client [client options] \
  --client-cert=/etc/autocar/client.crt \
  --client-key=/etc/autocar/client.key
```

Issue distinct client certificates from a private CA so identities can be
audited and rotated independently. AutoCAR has no CRL, OCSP, or certificate
denylist; revocation requires rotating the accepted client CA/certificates and
the token if it was exposed.

## 11. Wire migration from original AutoCAR QUIC

`--transport=quic` now aliases Hysteria v2. It does not speak the original
AutoCAR v1 QUIC wire. Upgrade UDP client and server together. For temporary
compatibility, make both selections explicit:

```sh
# Old v1 UDP engine
autocar server [relay options] --quic-engine=legacy
autocar client [client options] --transport=legacy-quic
```

One address cannot host both UDP engines. For a staged migration, bind Hysteria
to a second UDP port, move clients, then retire the legacy port. The separate
TLS/TCP fallback remains AutoCAR v1, so `auto` can still provide new-flow TCP
reachability during a UDP mismatch. Legacy QUIC has no BBR/Brutal integration
or UDP ASSOCIATE.

## 12. Containers and operations

The image uses a multi-stage build, a `scratch` runtime, numeric UID/GID 65532,
and no Linux capabilities. `docker-compose.yml` publishes relay UDP and TCP and
publishes local proxy TCP listeners only on host loopback. Prepare 0600 files
under `./secrets`, make them readable by the configured container UID, and use
the `server` or `client` profile. Do not publish the cleartext client proxy on
a public host address.

Operational checklist:

- rotate relay token and optional obfuscation secret with a coordinated restart;
- independently test Hysteria UDP and fallback TCP after every firewall, NAT,
  certificate, or load-balancer change;
- retain the controller/capacity configuration with benchmark results and
  remeasure after route or provider changes;
- monitor process restarts, CPU, memory, file descriptors, UDP drops, firewall
  counters, and link saturation;
- keep Go, modules, the host kernel, and container base/build images patched;
  and
- continue using HTTPS, SSH, or another end-to-end application protocol because
  the relay necessarily sees requested destinations and destination-side
  plaintext.

AutoCAR currently has no unauthenticated metrics endpoint and intentionally
does not log payloads or credentials. It also has no port hopping, Mimic,
user-facing ECH configuration, kernel-transparent TCP mode, or FEC. Do not
describe it as unidentifiable or unblockable.
