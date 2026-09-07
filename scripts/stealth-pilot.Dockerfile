# The two static Linux binaries are compiled by stealth-pilot.sh with
# GOPROXY=off before this image is built. FROM scratch and --network=none keep
# pilot image construction independent of registries and package mirrors.
FROM scratch

ARG REVISION=unknown
LABEL org.opencontainers.image.title="AutoCAR isolated stealth pilot helper" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="MIT"

COPY --chown=65532:65532 autocar /autocar
COPY --chown=65532:65532 stealth-pilot /stealth-pilot

USER 65532:65532
ENTRYPOINT ["/stealth-pilot"]
