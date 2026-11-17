# syntax=docker/dockerfile:1

# This helper is never a workload endpoint.  The campaign driver uses its
# tcpdump/ip/tc binaries only inside explicitly labelled container namespaces.
# Reuse the already-pinned Alpine base used by stealth-lab.Dockerfile.
FROM golang:1.27.4-alpine3.24@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf

RUN apk add --no-cache iproute2 tcpdump

ENTRYPOINT ["/bin/sh"]
CMD ["-c", "exit 2"]
