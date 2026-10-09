# syntax=docker/dockerfile:1

# This helper is never a workload endpoint.  The campaign driver uses its
# tcpdump/ip/tc binaries only inside explicitly labelled container namespaces.
# Reuse the already-pinned Alpine base used by stealth-lab.Dockerfile.
FROM golang:1.27.2-alpine3.24@sha256:85dc1069ac644ea3c527b177303a406eb3358192816cd7f9e5848eb658851673

RUN apk add --no-cache iproute2 tcpdump

ENTRYPOINT ["/bin/sh"]
CMD ["-c", "exit 2"]
