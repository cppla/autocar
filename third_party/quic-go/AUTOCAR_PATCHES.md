# AutoCAR security hardening

This directory is based on AutoCAR's pinned
`github.com/apernet/quic-go` pseudo-version
`v0.61.1-0.20260806010916-184d081eef3e` and remains licensed under the MIT
license in `LICENSE`.

AutoCAR adds one narrow HTTP/3 server hook: `StreamAdmission` runs immediately
after a bidirectional stream is accepted, before a handler goroutine is started
or the first frame type is read. It can reject a stream or return a callback
that releases process-wide capacity when handling ends.

The Hysteria server adapter uses this hook to apply its global handler budget
and first-byte deadline before `StreamDispatcher` peeks the frame type. Without
that ordering, a peer could open many streams and send an incomplete frame type
without entering Hysteria's normal TCP request handler. Its dispatcher handles
the TCP relay synchronously in quic-go's existing per-stream worker so the
release callback cannot run while the destination header or relay is still
active.

The pre-handshake server path also cancels `ConnContext`, closes a just-created
qlog trace and releases the Initial packet if connection-ID generation fails.
This preserves admission-slot accounting even during a system randomness
failure before a connection object exists.

The testdata helper generates an ephemeral ECDSA P-256 CA and leaf in a private
temporary directory at runtime. Fixed test private-key files are deliberately
excluded from the fork.
