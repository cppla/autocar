# syntax=docker/dockerfile:1

# Keep the builder aligned with the product Dockerfile so the probe uses the
# same module graph and Go toolchain. The runtime is scratch: the test gateway,
# origin, probe, and control server require no shell or ambient packages.
FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine3.24@sha256:85dc1069ac644ea3c527b177303a406eb3358192816cd7f9e5848eb658851673 AS build

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
