# syntax=docker/dockerfile:1

# Build one browser family per immutable runner image. BASE_IMAGE is deliberately
# mandatory and must include a sha256 digest; browser and driver versions are
# exact package/release versions, never floating channels.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG BASE_IMAGE
ARG BROWSER_FAMILY
ARG BROWSER_PACKAGE_VERSION
ARG WEBDRIVER_PACKAGE_VERSION
ARG WEBDRIVER_ARCHIVE_SHA256=""
ARG TARGETARCH

LABEL org.opencontainers.image.title="AutoCAR real-browser workload runner" \
      org.opencontainers.image.description="Isolated W3C WebDriver H2/H3 evidence runner" \
      org.opencontainers.image.licenses="MIT" \
      com.cppla.autocar.browser-family="${BROWSER_FAMILY}" \
      com.cppla.autocar.browser-package-version="${BROWSER_PACKAGE_VERSION}" \
      com.cppla.autocar.webdriver-package-version="${WEBDRIVER_PACKAGE_VERSION}"

COPY scripts/stealth-browser/run_cover.py /campaign/run_cover.py
COPY scripts/stealth-browser/write_lock.py /campaign/write_lock.py

RUN set -eu; \
    printf '%s' "${BASE_IMAGE}" | grep -Eq '@sha256:[0-9a-f]{64}$' || { echo 'BASE_IMAGE must be digest-pinned' >&2; exit 2; }; \
    case "${BROWSER_FAMILY}" in chromium|firefox-esr) ;; *) echo 'BROWSER_FAMILY must be chromium or firefox-esr' >&2; exit 2 ;; esac; \
    printf '%s' "${BROWSER_PACKAGE_VERSION}" | grep -Eq '^[A-Za-z0-9.+:~_-]+$' || { echo 'BROWSER_PACKAGE_VERSION must be exact' >&2; exit 2; }; \
    printf '%s' "${WEBDRIVER_PACKAGE_VERSION}" | grep -Eq '^[A-Za-z0-9.+:~_-]+$' || { echo 'WEBDRIVER_PACKAGE_VERSION must be exact' >&2; exit 2; }; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates python3; \
    if [ "${BROWSER_FAMILY}" = chromium ]; then \
        apt-get install -y --no-install-recommends \
            "chromium=${BROWSER_PACKAGE_VERSION}" \
            "chromium-driver=${WEBDRIVER_PACKAGE_VERSION}" \
            fonts-liberation; \
        test "$(dpkg-query -W -f='${Version}' chromium)" = "${BROWSER_PACKAGE_VERSION}"; \
        test "$(dpkg-query -W -f='${Version}' chromium-driver)" = "${WEBDRIVER_PACKAGE_VERSION}"; \
    else \
        printf '%s' "${WEBDRIVER_ARCHIVE_SHA256}" | grep -Eq '^[0-9a-f]{64}$' || { echo 'Firefox requires exact WEBDRIVER_ARCHIVE_SHA256' >&2; exit 2; }; \
        apt-get install -y --no-install-recommends \
            "firefox-esr=${BROWSER_PACKAGE_VERSION}" \
            curl gzip tar fonts-liberation; \
        test "$(dpkg-query -W -f='${Version}' firefox-esr)" = "${BROWSER_PACKAGE_VERSION}"; \
        case "${TARGETARCH}" in \
            amd64) gecko_arch=linux64 ;; \
            arm64) gecko_arch=linux-aarch64 ;; \
            *) echo 'Firefox runner supports TARGETARCH amd64 or arm64 only' >&2; exit 2 ;; \
        esac; \
        archive=/tmp/geckodriver.tar.gz; \
        curl --proto '=https' --tlsv1.2 -fsSL \
            "https://github.com/mozilla/geckodriver/releases/download/v${WEBDRIVER_PACKAGE_VERSION}/geckodriver-v${WEBDRIVER_PACKAGE_VERSION}-${gecko_arch}.tar.gz" \
            -o "$archive"; \
        printf '%s  %s\n' "${WEBDRIVER_ARCHIVE_SHA256}" "$archive" | sha256sum -c -; \
        tar -xzf "$archive" -C /usr/local/bin geckodriver; \
        chmod 0555 /usr/local/bin/geckodriver; \
        rm -f "$archive"; \
    fi; \
    chmod 0555 /campaign/run_cover.py /campaign/write_lock.py; \
    ln -s /campaign/run_cover.py /campaign/run-cover; \
    python3 /campaign/run_cover.py --self-test >/dev/null; \
    if [ "${BROWSER_FAMILY}" = chromium ]; then \
        python3 /campaign/write_lock.py \
            --browser chromium \
            --browser-binary /usr/lib/chromium/chromium \
            --webdriver-binary /usr/bin/chromedriver \
            --browser-package-version "${BROWSER_PACKAGE_VERSION}" \
            --webdriver-package-version "${WEBDRIVER_PACKAGE_VERSION}" \
            --output /campaign/browser-lock.json >/dev/null; \
    else \
        python3 /campaign/write_lock.py \
            --browser firefox-esr \
            --browser-binary /usr/lib/firefox-esr/firefox-esr \
            --webdriver-binary /usr/local/bin/geckodriver \
            --browser-package-version "${BROWSER_PACKAGE_VERSION}" \
            --webdriver-package-version "${WEBDRIVER_PACKAGE_VERSION}" \
            --output /campaign/browser-lock.json >/dev/null; \
    fi; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/* /campaign/write_lock.py

ENV HOME=/tmp \
    STEALTH_BROWSER_LOCK=/campaign/browser-lock.json \
    STEALTH_BROWSER_RUNTIME=/tmp/stealth-browser

USER 65532:65532
ENTRYPOINT ["/campaign/run-cover"]
