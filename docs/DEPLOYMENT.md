# Deployment guide

AutoCAR has two roles: a public relay close to the desired destinations and a
client-side process that exposes local SOCKS5 and HTTP(S) proxy listeners. The
preferred data path is QUIC over UDP; TCP with TLS 1.3 can listen on the same
port as a fallback.

## 1. Build and install

AutoCAR requires the Go version declared in `go.mod`.

```sh
make check
make build
sudo install -m 0755 bin/autocar /usr/local/bin/autocar
```

The binary is statically buildable with `CGO_ENABLED=0`. Cross-platform
artifacts can be produced with `make cross-build`. Linux is the primary
deployment target; the local proxy also builds on macOS and Windows.

## 2. Create relay credentials

Create a dedicated account and a private configuration directory. Secret
files are rejected if they are accessible by group or other users.

```sh
sudo useradd --system --home /var/lib/autocar --shell /usr/sbin/nologin autocar
sudo install -d -o autocar -g autocar -m 0700 /etc/autocar
sudo -u autocar autocar token --out /etc/autocar/relay-token
sudo -u autocar autocar cert \
  --hosts relay.example.com,203.0.113.10 \
  --cert /etc/autocar/server.crt \
  --key /etc/autocar/server.key
```

The bundled `cert` command creates an ECDSA P-256 self-signed certificate. Its
certificate file must be copied to each client over a trusted, independent
channel and used as `--ca`. For a public-CA certificate, clients may explicitly
select `--system-roots`; AutoCAR never offers an option to skip verification.

Keep the private key and token on the relay. Back them up as secrets, not in
the repository or container image.

## 3. Run the relay

For an initial foreground run on an unprivileged high port:

```sh
sudo -u autocar autocar server \
  --listen :8443 \
  --tcp-listen :8443 \
  --cert /etc/autocar/server.crt \
  --key /etc/autocar/server.key \
  --token-file /etc/autocar/relay-token
```

Permit both UDP and TCP on the chosen port. Production deployments commonly
use 443 because restrictive networks are more likely to permit it. Binding a
port below 1024 as a non-root process requires a narrowly scoped capability
such as `CAP_NET_BIND_SERVICE`, or a firewall/load-balancer mapping from 443 to
8443.

A minimal hardened systemd service is:

```ini
[Unit]
Description=AutoCAR relay
After=network-online.target
Wants=network-online.target

[Service]
User=autocar
Group=autocar
ExecStart=/usr/local/bin/autocar server --listen=:443 --tcp-listen=:443 --cert=/etc/autocar/server.crt --key=/etc/autocar/server.key --token-file=/etc/autocar/relay-token
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

The relay rejects loopback, link-local, multicast, unspecified, RFC1918, ULA,
CGNAT and IANA special-use destinations by default. It also denies ports 25,
465 and 587. `--allow-private` permits private/ULA/CGNAT targets but never
loopback, link-local or the explicitly denied special-use prefixes; use it only
for a relay dedicated to trusted users. `--deny-cidrs` adds deployment-specific
blocked IPs or CIDRs (for example, a cloud-provider control-plane range).
`--deny-ports=none` removes the port denylist and should be treated as a
deliberate security-policy change.

## 4. Run the client

Place the relay certificate and the same token on the client, with the token
owned by the local AutoCAR account and mode `0600`:

```sh
autocar client \
  --server relay.example.com:443 \
  --transport auto \
  --ca /etc/autocar/relay-ca.crt \
  --token-file /etc/autocar/relay-token \
  --socks 127.0.0.1:1080 \
  --http 127.0.0.1:8080
```

`auto` first uses QUIC. If that path fails, it uses the TLS/TCP listener; a
short circuit-breaker cooldown prevents every new flow from repeatedly
waiting for an unavailable UDP path. `--transport=quic` and
`--transport=tls` are useful for diagnosis. If the TCP fallback uses a
different address, set `--fallback-server`. `--quic-attempt-timeout` bounds
the whole QUIC phase, while `--dial-timeout` bounds network establishment and
`--open-timeout` bounds the overall proxy open operation. Keep the overall
timeout comfortably larger than the QUIC budget so TLS has time to complete;
the defaults also leave the relay's destination dial timeout inside that
budget on a normally responsive path.

Fallback is connection-establishment behavior, not live stream migration. If
UDP disappears after a QUIC stream has already been returned to an
application, that stream fails and the application must retry; newly opened
streams use TLS while the QUIC circuit is open. Arbitrary TCP bytes cannot be
safely replayed onto a different transport without application cooperation.

Application examples:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
curl --proxy http://127.0.0.1:8080 https://example.com/
```

The SOCKS5 frontend currently supports CONNECT, not BIND or UDP ASSOCIATE.
The HTTP proxy supports absolute-form `http://` requests and CONNECT.
Absolute-form `https://` is rejected: HTTPS destinations must use CONNECT, so
their application TLS remains end to end between the application and
destination. AutoCAR does not install a CA or intercept destination TLS.

The optional `--https` listener encrypts the hop from an application to the
local proxy. It requires `--proxy-cert` and `--proxy-key`:

```sh
autocar cert --hosts localhost,127.0.0.1 --cert proxy.crt --key proxy.key
autocar client [relay options] \
  --socks= --http= --https 127.0.0.1:8444 \
  --proxy-cert proxy.crt --proxy-key proxy.key
curl --proxy https://127.0.0.1:8444 --proxy-cacert proxy.crt https://example.com/
```

Unauthenticated proxy listeners are restricted to loopback. To expose one on
another interface, set a username and a permission-restricted password file:

```sh
AUTOCAR_PROXY_USER=alice autocar client [relay options] \
  --proxy-password-file /etc/autocar/proxy-password \
  --allow-public-plaintext \
  --socks 0.0.0.0:1080 --http 0.0.0.0:8080
```

SOCKS5 uses username/password authentication and the HTTP proxy uses Basic
proxy authentication. Both transmit local-proxy credentials without transport
encryption, which is why a non-loopback listener requires the explicit
`--allow-public-plaintext` acknowledgement. These credentials protect the
local listener; they do not replace the relay token or TLS certificate
validation. Add host firewall rules even when authentication is enabled, and
prefer the HTTPS proxy listener across any untrusted local network.

## 5. Optional mutual TLS

The shared token is mandatory. mTLS adds a client-certificate factor. Generate
a separate client certificate, install its certificate (not its key) as the
relay client trust anchor, and start the roles with:

```sh
# Relay
autocar server [server options] --client-ca /etc/autocar/client.crt

# Client
autocar client [client options] \
  --client-cert /etc/autocar/client.crt \
  --client-key /etc/autocar/client.key
```

For multiple clients, use a conventional private CA and issue distinct client
certificates so identities remain auditable and can be migrated independently.
Protocol v1 does not implement CRL, OCSP, or a certificate denylist; revoking a
compromised client therefore requires rotating the accepted client CA and the
remaining client certificates (and rotating the shared token when exposed).

## 6. Containers and Compose

The image uses a multi-stage build and a `scratch` runtime. It includes the
system CA bundle, contains only the binary and CA file, and runs as numeric UID
and GID 65532 with no Linux capabilities.

`docker-compose.yml` provides separate `server` and `client` profiles. Prepare
the expected files under `./secrets`, keep token/password/key files at mode
`0600`, and make them readable by the configured container UID. For example:

```sh
mkdir -p secrets
bin/autocar token --out secrets/relay-token
bin/autocar cert --hosts relay.example.com \
  --cert secrets/server.crt --key secrets/server.key
cp secrets/server.crt secrets/relay-ca.crt
bin/autocar token --out secrets/proxy-password
sudo chown -R 65532:65532 secrets

docker compose --profile server up --build -d
```

For a client host, set `AUTOCAR_RELAY`, `AUTOCAR_SERVER_NAME` and a non-default
`AUTOCAR_PROXY_USER`, then run `docker compose --profile client up --build -d`.
Compose publishes the local proxy ports only on host loopback, while proxy
authentication is still mandatory inside the container because its listener
binds the container interface. The Compose command also sets
`--allow-public-plaintext` explicitly: SOCKS5 username/password and HTTP Basic
proxy credentials are not encrypted on that container-side listener. The
loopback-only host publishing and Docker network boundary are therefore part
of this example's security model. Do not change those port mappings to a
public host address; use the local HTTPS proxy listener or another encrypted
hop if clients must cross an untrusted network.

If host files cannot be owned by UID 65532, set `AUTOCAR_UID` and
`AUTOCAR_GID` to their owner. The Dockerfile's default process remains
non-root; do not set the Compose user to root merely to work around secret-file
permissions.

## 7. Operations and limits

- Rotate a token by updating both ends during a coordinated restart. There is
  no multi-token grace period in protocol v1.
- The current release emits lifecycle and fatal-command logs, but deliberately
  has no unauthenticated metrics endpoint and does not log every hostile
  request. Monitor restarts with the process supervisor, use firewall counters
  and bounded external probes for reachability, and alert on host CPU, memory,
  file-descriptor and network saturation. Built-in aggregate auth/dial/stream
  metrics remain future work; logs intentionally avoid payload, credentials,
  destinations and internal dial details.
- Keep Go and module dependencies patched. CI runs unit/race tests and CodeQL;
  those checks complement rather than replace dependency and host patching.
- Test UDP and TCP reachability independently after every firewall, NAT or
  load-balancer change.
- A relay sees requested destinations and any destination-side plaintext.
  Continue using HTTPS, SSH or another end-to-end protocol for sensitive data.
- Observers still see relay IPs, packet sizes, timing and whether UDP/TLS is in
  use. No protocol can promise that a network operator will never rate-limit
  or block it. AutoCAR's TCP/TLS fallback improves reachability but is not an
  undetectability guarantee.
