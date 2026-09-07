# The runtime image is intentionally small. Both direct tools are version
# pinned, while the base is locked to the reviewed Alpine 3.24 multi-architecture
# image index. Network access is only needed while apk installs these packages;
# extraction runs with --network none.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN apk add --no-cache \
      python3=3.14.7-r1 \
      tshark=4.6.6-r0 \
    && python3 --version \
    && tshark --version >/dev/null

ENV PYTHONDONTWRITEBYTECODE=1

CMD ["/bin/false"]
