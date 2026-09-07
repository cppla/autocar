# syntax=docker/dockerfile:1

# This helper is never a workload endpoint.  The campaign driver uses its
# tcpdump/ip/tc binaries only inside explicitly labelled container namespaces.
# Reuse the already-pinned Alpine base used by stealth-lab.Dockerfile.
FROM golang:1.27.1-alpine3.24@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125

RUN apk add --no-cache iproute2 tcpdump

ENTRYPOINT ["/bin/sh"]
CMD ["-c", "exit 2"]
