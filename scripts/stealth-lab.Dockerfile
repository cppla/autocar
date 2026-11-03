# syntax=docker/dockerfile:1

# Keep the builder aligned with the product Dockerfile so the probe uses the
# same module graph and Go toolchain. The runtime is scratch: the test gateway,
# origin, probe, and control server require no shell or ambient packages.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine3.24@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath -o /out/stealth-probe ./scripts/stealth-probe

FROM scratch

COPY --from=build /out/stealth-probe /stealth-probe

USER 65532:65532
ENTRYPOINT ["/stealth-probe"]
