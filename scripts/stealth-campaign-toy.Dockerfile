# syntax=docker/dockerfile:1
FROM golang:1.27.3-alpine3.24@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
WORKDIR /src
COPY scripts/stealth-campaign-toy/main.go .
RUN CGO_ENABLED=0 GO111MODULE=off go build -trimpath -o /out/stealth-campaign-toy ./main.go

FROM scratch
COPY --from=build /out/stealth-campaign-toy /stealth-campaign-toy
USER 65532:65532
ENTRYPOINT ["/stealth-campaign-toy"]
