# syntax=docker/dockerfile:1
FROM golang:1.27.1-alpine3.24@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build
WORKDIR /src
COPY scripts/stealth-campaign-toy/main.go .
RUN CGO_ENABLED=0 GO111MODULE=off go build -trimpath -o /out/stealth-campaign-toy ./main.go

FROM scratch
COPY --from=build /out/stealth-campaign-toy /stealth-campaign-toy
USER 65532:65532
ENTRYPOINT ["/stealth-campaign-toy"]
