# syntax=docker/dockerfile:1

# This helper is never a workload endpoint.  The campaign driver uses its
# tcpdump/ip/tc binaries only inside explicitly labelled container namespaces.
# Reuse the already-pinned Alpine base used by stealth-lab.Dockerfile.
FROM golang:1.27.3-alpine3.24@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb

RUN apk add --no-cache iproute2 tcpdump

ENTRYPOINT ["/bin/sh"]
CMD ["-c", "exit 2"]
