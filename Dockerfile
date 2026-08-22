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
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath \
    -ldflags="-s -w -X github.com/cppla/autocar/internal/version.Version=${VERSION} -X github.com/cppla/autocar/internal/version.Commit=${COMMIT} -X github.com/cppla/autocar/internal/version.Date=${BUILD_DATE}" \
    -o /out/autocar ./cmd/autocar

FROM --platform=$TARGETPLATFORM scratch

LABEL org.opencontainers.image.source="https://github.com/cppla/autocar" \
      org.opencontainers.image.description="Authenticated dual-ended QUIC/TLS TCP proxy" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /out/autocar /autocar

USER 65532:65532
EXPOSE 8443/tcp 8443/udp 1080/tcp 8080/tcp
ENTRYPOINT ["/autocar"]
