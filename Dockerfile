# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /src
RUN apk add --no-cache ca-certificates

COPY go.mod go.sum ./
# Local replace directives are resolved during go mod download, so make the
# audited module forks available before dependency resolution.
COPY third_party ./third_party
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath \
    -ldflags="-s -w -X github.com/cppla/autocar/internal/version.Version=${VERSION} -X github.com/cppla/autocar/internal/version.Commit=${COMMIT} -X github.com/cppla/autocar/internal/version.Date=${BUILD_DATE}" \
    -o /out/autocar ./cmd/autocar

FROM --platform=$TARGETPLATFORM scratch

LABEL org.opencontainers.image.source="https://github.com/cppla/autocar" \
      org.opencontainers.image.description="Secure dual-ended QUIC/TLS TCP and UDP accelerator" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /out/autocar /autocar
COPY --from=build /src/LICENSE /licenses/autocar-LICENSE
COPY --from=build /src/THIRD_PARTY_NOTICES.md /licenses/THIRD_PARTY_NOTICES.md

USER 65532:65532
EXPOSE 8443/tcp 8443/udp 1080/tcp 8080/tcp
ENTRYPOINT ["/autocar"]
