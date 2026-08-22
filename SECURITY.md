# Security policy

## Supported versions

Until the first stable release, only the latest commit on `main` receives
security fixes.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's
private vulnerability reporting feature for this repository. Include the
affected version, reproduction steps, impact, and any suggested mitigation.

## Security guarantees and limits

AutoCAR protects the client-to-relay hop with authenticated TLS 1.3. QUIC
always uses TLS 1.3; the TCP fallback uses TLS 1.3 explicitly. The client never
offers an option to skip certificate verification. A private CA or a publicly
trusted certificate must be configured, and mutual TLS can be required by the
server.

The tunnel protects payload confidentiality and integrity against passive
observers and active network attackers, assuming the configured CA, private
keys, token, endpoints, operating systems, and dependencies are not
compromised. It does not hide endpoint IP addresses, packet sizes, timing, or
the fact that UDP or TLS is in use. The relay can observe destination metadata
and any destination traffic that is itself unencrypted. End-to-end HTTPS
remains encrypted between the application and the destination.

No transport can guarantee that a network operator will not rate-limit or
block it. AutoCAR provides a standards-compliant TCP/TLS fallback for networks
where UDP is unavailable; it deliberately does not impersonate unrelated
protocols or claim to be undetectable.

The relay blocks private, loopback, link-local, multicast, and unspecified
destinations by default, and denies common SMTP submission ports. Operators
should keep these defaults unless they fully trust every authenticated client.
Deployment-specific control-plane and metadata ranges can be added with
`--deny-cidrs`, especially before enabling private destinations.

TLS private-key files must be regular files and mode `0600` on Unix. Shared
relay tokens and local-proxy passwords must contain at least 16 bytes; use the
bundled `autocar token` command to generate high-entropy values.
