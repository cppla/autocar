# syntax=docker/dockerfile:1
FROM golang:1.27.4-alpine3.24@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build
WORKDIR /src
COPY scripts/stealth-campaign-toy/main.go .
RUN CGO_ENABLED=0 GO111MODULE=off go build -trimpath -o /out/stealth-campaign-toy ./main.go

FROM scratch
COPY --from=build /out/stealth-campaign-toy /stealth-campaign-toy
USER 65532:65532
ENTRYPOINT ["/stealth-campaign-toy"]
