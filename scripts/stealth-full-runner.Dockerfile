# syntax=docker/dockerfile:1

# Build both formal-campaign clients from the same pinned Go toolchain and
# module graph. The launcher records the resulting immutable image ID, then
# extracts the two binaries for campaign provenance.
FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine3.24@sha256:85dc1069ac644ea3c527b177303a406eb3358192816cd7f9e5848eb658851673 AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION
ARG COMMIT
ARG BUILD_DATE

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
      go build -trimpath \
      -ldflags="-s -w -X github.com/cppla/autocar/internal/version.Version=${VERSION} -X github.com/cppla/autocar/internal/version.Commit=${COMMIT} -X github.com/cppla/autocar/internal/version.Date=${BUILD_DATE}" \
      -o /out/autocar ./cmd/autocar \
    && CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
      go build -trimpath -ldflags="-s -w" \
      -o /out/stealth-pilot ./scripts/stealth-pilot

FROM scratch

ARG COMMIT=unknown
LABEL org.opencontainers.image.title="AutoCAR formal stealth campaign runner" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build --chown=65532:65532 /out/autocar /autocar
COPY --from=build --chown=65532:65532 /out/stealth-pilot /stealth-pilot

USER 65532:65532
ENTRYPOINT ["/stealth-pilot"]
