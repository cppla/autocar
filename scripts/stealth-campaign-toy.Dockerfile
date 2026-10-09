# syntax=docker/dockerfile:1
FROM golang:1.27.2-alpine3.24@sha256:85dc1069ac644ea3c527b177303a406eb3358192816cd7f9e5848eb658851673 AS build
WORKDIR /src
COPY scripts/stealth-campaign-toy/main.go .
RUN CGO_ENABLED=0 GO111MODULE=off go build -trimpath -o /out/stealth-campaign-toy ./main.go

FROM scratch
COPY --from=build /out/stealth-campaign-toy /stealth-campaign-toy
USER 65532:65532
ENTRYPOINT ["/stealth-campaign-toy"]
