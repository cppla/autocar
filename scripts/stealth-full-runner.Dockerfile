# syntax=docker/dockerfile:1

# Build both formal-campaign clients from the same pinned Go toolchain and
# module graph. The launcher records the resulting immutable image ID, then
# extracts the two binaries for campaign provenance.
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine3.24@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build

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
