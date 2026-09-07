#!/usr/bin/env python3
"""Run one isolated, provenance-checked real-browser HTTP workload.

The runtime uses only Python's standard library and the W3C WebDriver HTTP
protocol.  It never invokes a shell.  Successful workload execution writes one
compact JSON receipt to stdout; diagnostics and failures go to stderr.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener


SCHEMA_VERSION = 1
KIND = "real-browser-workload"
RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_VERSION_RE = re.compile(r"^[\x20-\x7e]{1,240}$")
DOTTED_VERSION_RE = re.compile(
    r"(?<![A-Za-z0-9_.])([0-9]+(?:\.[0-9]+){1,3})(?:[A-Za-z]+)?(?![A-Za-z0-9_.])"
)
BROWSER_NAMES = {
    "chromium": "Chromium",
    "firefox-esr": "Firefox",
}
ALLOWED_EXECUTABLES = {
    ("chromium", "browser"): {"chromium", "chromium-browser", "chrome", "google-chrome"},
    ("chromium", "webdriver"): {"chromedriver"},
    ("firefox-esr", "browser"): {"firefox", "firefox-esr"},
    ("firefox-esr", "webdriver"): {"geckodriver"},
}
WORKLOAD_SPECS = {
    "idle": {"requests": 1, "response_bytes": 0, "upload_bytes": 0},
    "download_1k": {"requests": 1, "response_bytes": 1024, "upload_bytes": 0},
    "download_128k": {"requests": 1, "response_bytes": 128 * 1024, "upload_bytes": 0},
    "download_1m": {"requests": 1, "response_bytes": 1024 * 1024, "upload_bytes": 0},
    "upload_1m": {"requests": 1, "response_bytes": 32, "upload_bytes": 1024 * 1024},
    "parallel_20": {"requests": 20, "response_bytes": 20 * 1024, "upload_bytes": 0},
    "interactive": {"requests": 8, "response_bytes": 8 * 512, "upload_bytes": 8 * 256},
    # The campaign driver names its auxiliary H2 control browser_h2.  Keep the
    # name in the receipt while executing the frozen 128 KiB download.
    "browser_h2": {"requests": 1, "response_bytes": 128 * 1024, "upload_bytes": 0},
}
LOCK_FIELDS = {
    "schema_version",
    "browser",
    "client_implementation",
    "implementation_version",
    "browser_binary",
    "browser_binary_sha256",
    "webdriver_binary",
    "webdriver_version",
    "webdriver_binary_sha256",
    "browser_package_version",
    "webdriver_package_version",
}
SUCCESS_FIELDS = {
    "schema_version",
    "status",
    "kind",
    "client_implementation",
    "implementation_version",
    "browser_binary_sha256",
    "protocol",
    "workload",
    "sample_seed",
    "next_hop_protocols",
    "request_count",
    "response_bytes",
    "result_sha256",
}


BOOTSTRAP_VERIFY_SCRIPT = r"""
const expectedSeed = String(arguments[0]);
const query = new URLSearchParams(window.location.search);
const marker = document.querySelector('meta[name="autocar-stealth-bootstrap"]');
const icons = Array.from(document.querySelectorAll('link[rel~="icon"]'));
const navigation = performance.getEntriesByType("navigation");
return {
  ok: (
    document.readyState === "complete" &&
    document.contentType === "text/html" &&
    window.location.pathname === "/" &&
    query.size === 1 &&
    query.get("autocar_browser_sample") === expectedSeed &&
    marker !== null && marker.getAttribute("content") === "v1" &&
    document.title === "AutoCAR Stealth Fixture" &&
    icons.length === 1 && icons[0].getAttribute("href") === "data:," &&
    navigation.length === 1
  ),
  sample_seed: Number(query.get("autocar_browser_sample")),
  next_hop_protocol: navigation.length === 1 ? String(navigation[0].nextHopProtocol || "") : "",
};
"""


WORKLOAD_SCRIPT = r"""
const workload = arguments[0];
const sampleSeed = Number(arguments[1]);
const idleMilliseconds = Number(arguments[2]);
const done = arguments[arguments.length - 1];

(async () => {
  performance.setResourceTimingBufferSize(256);
  performance.clearResourceTimings();
  const observations = [];
  let responseBytes = 0;
  let uploadBytes = 0;

  const mask64 = (1n << 64n) - 1n;
  const splitMixIncrement = 0x9e3779b97f4a7c15n;
  const domainMultiplier = 0xd1b54a32d192ed03n;

  function fixtureBody(size) {
    const value = new Uint8Array(size);
    for (let index = 0; index < size; index += 1) {
      value[index] = (index * 31 + 17) % 251;
    }
    return value;
  }

  // This is byte-for-byte the uint64 SplitMix fixture in stealth-pilot.  BigInt
  // is required because JavaScript Number cannot represent the 64-bit state.
  function seededFixtureBody(size, requestIndex, domain) {
    const value = new Uint8Array(size);
    let state = (
      BigInt(sampleSeed) ^
      (((BigInt(requestIndex) + 1n) * splitMixIncrement) & mask64) ^
      ((BigInt(domain) * domainMultiplier) & mask64)
    ) & mask64;
    for (let index = 0; index < size; index += 1) {
      state = (state + splitMixIncrement) & mask64;
      let mixed = state;
      mixed = ((mixed ^ (mixed >> 30n)) * 0xbf58476d1ce4e5b9n) & mask64;
      mixed = ((mixed ^ (mixed >> 27n)) * 0x94d049bb133111ebn) & mask64;
      mixed = (mixed ^ (mixed >> 31n)) & mask64;
      value[index] = Number((mixed >> 56n) & 0xffn);
    }
    return value;
  }

  function equalBytes(actual, expected) {
    if (actual.length !== expected.length) {
      return false;
    }
    for (let index = 0; index < actual.length; index += 1) {
      if (actual[index] !== expected[index]) {
        return false;
      }
    }
    return true;
  }

  async function exchange(index, kind, size) {
    let path;
    let expectedResponse;
    const options = {
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      headers: {"Accept": "application/octet-stream", "Cache-Control": "no-store"},
    };
    if (kind === "download") {
      path = `/bytes/${size}`;
      expectedResponse = fixtureBody(size);
    } else if (kind === "upload") {
      path = `/upload/${size}`;
      expectedResponse = seededFixtureBody(32, index, 2);
      options.method = "POST";
      options.body = seededFixtureBody(size, index, 1);
      options.headers["Content-Type"] = "application/octet-stream";
      uploadBytes += size;
    } else if (kind === "echo") {
      path = "/exchange/256/512";
      expectedResponse = seededFixtureBody(512, index, 4);
      options.method = "POST";
      options.body = seededFixtureBody(256, index, 3);
      options.headers["Content-Type"] = "application/octet-stream";
      uploadBytes += size;
    } else {
      throw new Error(`unsupported exchange kind ${kind}`);
    }
    const target = new URL(path, window.location.href);
    target.searchParams.set("seed", String(sampleSeed));
    target.searchParams.set("request", String(index));
    const response = await fetch(target.toString(), options);
    if (!response.ok) {
      throw new Error(`request ${index} returned HTTP ${response.status}`);
    }
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (!equalBytes(bytes, expectedResponse)) {
      throw new Error(`request ${index} returned a mismatched ${bytes.byteLength}-byte payload`);
    }
    responseBytes += bytes.byteLength;
    observations.push(index);
  }

  if (workload === "idle") {
    await exchange(0, "download", 0);
    await new Promise((resolve) => setTimeout(resolve, idleMilliseconds));
  } else if (workload === "download_1k") {
    await exchange(0, "download", 1024);
  } else if (workload === "download_128k" || workload === "browser_h2") {
    await exchange(0, "download", 128 * 1024);
  } else if (workload === "download_1m") {
    await exchange(0, "download", 1024 * 1024);
  } else if (workload === "upload_1m") {
    await exchange(0, "upload", 1024 * 1024);
  } else if (workload === "parallel_20") {
    await Promise.all(Array.from({length: 20}, (_, index) => exchange(index, "download", 1024)));
  } else if (workload === "interactive") {
    for (let index = 0; index < 8; index += 1) {
      await exchange(index, "echo", 256);
    }
  } else {
    throw new Error(`unsupported workload ${workload}`);
  }

  // Resource Timing entries are queued synchronously by fetch completion, but
  // allow one rendering turn before reading them in both browser engines.
  await new Promise((resolve) => requestAnimationFrame(() => resolve()));
  const resources = performance.getEntriesByType("resource")
    .filter((entry) => {
      try {
        const query = new URL(entry.name).searchParams;
        return query.get("seed") === String(sampleSeed) && query.has("request");
      } catch (_) {
        return false;
      }
    })
    .map((entry) => {
      const url = new URL(entry.name);
      return {
        request_index: Number(url.searchParams.get("request")),
        next_hop_protocol: String(entry.nextHopProtocol || ""),
      };
    })
    .sort((left, right) => left.request_index - right.request_index);
  done({
    ok: true,
    request_count: observations.length,
    response_bytes: responseBytes,
    upload_bytes: uploadBytes,
    resources: resources,
  });
})().catch((error) => done({ok: false, error: String(error && error.message || error)}));
"""


class RunnerError(RuntimeError):
    pass


class UsageError(RunnerError):
    pass


class StrictArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise UsageError(message)


@dataclass(frozen=True)
class ServerAddress:
    ip: str
    port: int

    @property
    def authority(self) -> str:
        return "%s:%d" % (self.ip, self.port)


@dataclass(frozen=True)
class ExecutableIdentity:
    path: str
    version: str
    sha256: str


@dataclass(frozen=True)
class BrowserIdentity:
    browser: str
    client_implementation: str
    implementation_version: str
    browser_binary: str
    browser_binary_sha256: str
    webdriver_binary: str
    webdriver_version: str
    webdriver_binary_sha256: str


def compact_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_json_sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(compact_json(value).encode("utf-8")).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_server(value: str) -> ServerAddress:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9.]+:[0-9]+", value):
        raise UsageError("--server must be a numeric RFC1918 IPv4 address and port")
    host, port_text = value.rsplit(":", 1)
    try:
        address = ipaddress.IPv4Address(host)
        port = int(port_text, 10)
    except (ipaddress.AddressValueError, ValueError) as error:
        raise UsageError("--server must be a numeric RFC1918 IPv4 address and port") from error
    if not any(address in network for network in RFC1918):
        raise UsageError("--server address is outside RFC1918 space")
    if not 1 <= port <= 65535:
        raise UsageError("--server port must be in 1..65535")
    return ServerAddress(str(address), port)


def parse_seed(value: str) -> int:
    if not re.fullmatch(r"[0-9]+", value or ""):
        raise UsageError("--seed must be an integer in 0..2147483647")
    number = int(value, 10)
    if not 0 <= number <= 0x7FFFFFFF:
        raise UsageError("--seed must be an integer in 0..2147483647")
    return number


def bounded_number(value: str, label: str, minimum: int, maximum: int) -> int:
    if not re.fullmatch(r"[0-9]+", value or ""):
        raise UsageError("%s must be an integer" % label)
    number = int(value, 10)
    if not minimum <= number <= maximum:
        raise UsageError("%s must be in %d..%d" % (label, minimum, maximum))
    return number


def parse_certificate_spki_sha256(value: str) -> str:
    """Return one canonical Chrome SPKI SHA-256 pin or fail closed."""
    message = "--certificate-spki-sha256 must be canonical Base64 for exactly 32 bytes"
    if not isinstance(value, str) or len(value) != 44 or not value.endswith("="):
        raise UsageError(message)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise UsageError(message) from error
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise UsageError(message)
    return value


def validate_certificate_spki_usage(
    browser: str, protocol: str, certificate_spki_sha256: Optional[str]
) -> Optional[str]:
    if browser == "chromium" and protocol == "h3":
        if certificate_spki_sha256 is None:
            raise UsageError(
                "Chromium H3 requires --certificate-spki-sha256 for the lab certificate"
            )
        return parse_certificate_spki_sha256(certificate_spki_sha256)
    if certificate_spki_sha256 is not None:
        raise UsageError(
            "--certificate-spki-sha256 is allowed only with --browser chromium --protocol h3"
        )
    return None


def json_object(data: bytes, label: str) -> Dict[str, Any]:
    def unique(pairs: Iterable[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise RunnerError("%s contains duplicate key %r" % (label, key))
            result[key] = value
        return result

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RunnerError("%s is not valid JSON" % label) from error
    if not isinstance(value, dict):
        raise RunnerError("%s must be a JSON object" % label)
    return value


def executable_path(value: Any, browser: str, role: str) -> Path:
    if not isinstance(value, str) or not value.startswith("/"):
        raise RunnerError("%s binary path must be absolute" % role)
    if any(ord(character) < 0x20 for character in value):
        raise RunnerError("%s binary path contains control characters" % role)
    # Requiring a known basename also rejects shell command strings such as
    # '/bin/sh -c ...'.  subprocess is always called with an argv array below.
    path = Path(value)
    if path.name not in ALLOWED_EXECUTABLES[(browser, role)]:
        raise RunnerError("unexpected %s executable name %r" % (role, path.name))
    try:
        canonical = path.resolve(strict=True)
    except (FileNotFoundError, OSError) as error:
        raise RunnerError("%s executable is missing" % role) from error
    if not canonical.is_file() or not os.access(str(canonical), os.X_OK):
        raise RunnerError("%s executable is not an executable regular file" % role)
    return canonical


def executable_identity(path: Path, version_arguments: Sequence[str]) -> ExecutableIdentity:
    try:
        completed = subprocess.run(
            [str(path), *version_arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=8,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"},
            text=True,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RunnerError("cannot read executable version for %s" % path) from error
    if completed.returncode != 0:
        raise RunnerError("version command failed for %s" % path)
    lines = [line.strip() for line in (completed.stdout + "\n" + completed.stderr).splitlines() if line.strip()]
    if not lines or not SAFE_VERSION_RE.fullmatch(lines[0]):
        raise RunnerError("executable returned an invalid version string")
    return ExecutableIdentity(str(path), lines[0], file_sha256(path))


def load_browser_identity(lock_path: Path, expected_browser: Optional[str] = None) -> BrowserIdentity:
    try:
        raw = json_object(lock_path.read_bytes(), "browser lock")
    except (FileNotFoundError, OSError) as error:
        raise RunnerError("browser lock is missing or unreadable") from error
    if set(raw) != LOCK_FIELDS or raw.get("schema_version") != SCHEMA_VERSION:
        raise RunnerError("browser lock has an unsupported schema")
    browser = raw.get("browser")
    if browser not in BROWSER_NAMES or (expected_browser is not None and browser != expected_browser):
        raise RunnerError("browser lock does not match the requested browser")
    if raw.get("client_implementation") != BROWSER_NAMES[browser]:
        raise RunnerError("browser lock client implementation is inconsistent")
    implementation_version = raw.get("implementation_version")
    if not isinstance(implementation_version, str) or not SAFE_VERSION_RE.fullmatch(implementation_version):
        raise RunnerError("browser lock implementation version is invalid")
    browser_path = executable_path(raw.get("browser_binary"), browser, "browser")
    webdriver_path = executable_path(raw.get("webdriver_binary"), browser, "webdriver")
    actual_browser = executable_identity(browser_path, ("--version",))
    actual_webdriver = executable_identity(webdriver_path, ("--version",))
    expected = {
        "browser_binary": actual_browser.path,
        "implementation_version": actual_browser.version,
        "browser_binary_sha256": actual_browser.sha256,
        "webdriver_binary": actual_webdriver.path,
        "webdriver_version": actual_webdriver.version,
        "webdriver_binary_sha256": actual_webdriver.sha256,
    }
    for field, value in expected.items():
        if raw.get(field) != value:
            raise RunnerError("browser lock mismatch for %s" % field)
    for field in ("browser_package_version", "webdriver_package_version"):
        if not isinstance(raw.get(field), str) or not SAFE_VERSION_RE.fullmatch(raw[field]):
            raise RunnerError("browser lock %s is invalid" % field)
    return BrowserIdentity(
        browser=browser,
        client_implementation=BROWSER_NAMES[browser],
        implementation_version=actual_browser.version,
        browser_binary=actual_browser.path,
        browser_binary_sha256=actual_browser.sha256,
        webdriver_binary=actual_webdriver.path,
        webdriver_version=actual_webdriver.version,
        webdriver_binary_sha256=actual_webdriver.sha256,
    )


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def geckodriver_needs_system_access(version: str) -> bool:
    match = re.search(r"\b(\d+)\.(\d+)\.(\d+)\b", version)
    return bool(match and tuple(int(part) for part in match.groups()) >= (0, 37, 1))


def driver_command(identity: BrowserIdentity, port: int) -> List[str]:
    if identity.browser == "chromium":
        return [identity.webdriver_binary, "--port=%d" % port, "--allowed-ips=127.0.0.1"]
    result = [identity.webdriver_binary, "--host", "127.0.0.1", "--port", str(port)]
    if geckodriver_needs_system_access(identity.webdriver_version):
        result.append("--allow-system-access")
    return result


def browser_capabilities(
    identity: BrowserIdentity,
    protocol: str,
    server: ServerAddress,
    profile_directory: Path,
    accept_insecure_certs: bool,
    certificate_spki_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    certificate_spki_sha256 = validate_certificate_spki_usage(
        identity.browser, protocol, certificate_spki_sha256
    )
    common: Dict[str, Any] = {
        "acceptInsecureCerts": accept_insecure_certs,
        "pageLoadStrategy": "normal",
    }
    if identity.browser == "chromium":
        arguments = [
            "--headless=new",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
            "--metrics-recording-only",
            "--user-data-dir=%s" % profile_directory,
        ]
        if protocol == "h3":
            arguments.extend(
                [
                    "--enable-quic",
                    "--origin-to-force-quic-on=%s" % server.authority,
                    "--ignore-certificate-errors-spki-list=%s" % certificate_spki_sha256,
                ]
            )
        else:
            arguments.append("--disable-quic")
        common.update(
            {
                "browserName": "chrome",
                "goog:chromeOptions": {
                    "binary": identity.browser_binary,
                    "args": arguments,
                    "prefs": {"profile.default_content_setting_values.notifications": 2},
                },
            }
        )
        return common

    preferences: Dict[str, Any] = {
        "browser.shell.checkDefaultBrowser": False,
        "browser.startup.page": 0,
        "datareporting.healthreport.uploadEnabled": False,
        "network.captive-portal-service.enabled": False,
        "network.http.http3.enable": protocol == "h3",
        "network.http.speculative-parallel-limit": 0,
        "toolkit.telemetry.enabled": False,
    }
    if protocol == "h3":
        preferences["network.http.http3.alt-svc-mapping-for-testing"] = '%s;h3=":%d"' % (
            server.ip,
            server.port,
        )
        preferences["network.http.http3.force-use-alt-svc-mapping-for-testing"] = True
        preferences["network.http.http3.disable_when_third_party_roots_found"] = False
    common.update(
        {
            "browserName": "firefox",
            "moz:firefoxOptions": {
                "binary": identity.browser_binary,
                "args": ["-headless"],
                "prefs": preferences,
            },
        }
    )
    return common


class WebDriverClient:
    def __init__(self, port: int, timeout: int) -> None:
        self.base = "http://127.0.0.1:%d" % port
        self.timeout = timeout
        self.opener = build_opener(ProxyHandler({}))

    def request(self, method: str, path: str, payload: Optional[Mapping[str, Any]] = None) -> Any:
        data = None if payload is None else compact_json(payload).encode("utf-8")
        request = Request(
            self.base + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json; charset=utf-8"},
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                document = json_object(response.read(), "WebDriver response")
        except HTTPError as error:
            body = error.read()
            try:
                document = json_object(body, "WebDriver error")
                detail = document.get("value", document)
            except RunnerError:
                detail = "HTTP %d" % error.code
            raise RunnerError("WebDriver command failed: %s" % diagnostic(detail)) from error
        except (URLError, OSError) as error:
            raise RunnerError("WebDriver connection failed") from error
        value = document.get("value")
        if isinstance(value, dict) and value.get("error"):
            raise RunnerError("WebDriver command failed: %s" % diagnostic(value))
        return value

    def wait_ready(self, process: subprocess.Popen[Any], seconds: int = 12) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RunnerError("WebDriver exited before becoming ready")
            try:
                value = self.request("GET", "/status")
                # A malformed or legacy-looking status body is not proof that
                # the local driver is ready.  Require the W3C readiness bit so
                # session creation cannot race a partially initialized driver.
                if isinstance(value, dict) and value.get("ready") is True:
                    return
            except RunnerError:
                pass
            time.sleep(0.05)
        raise RunnerError("WebDriver did not become ready")

    def create_session(self, capabilities: Mapping[str, Any]) -> Tuple[str, Dict[str, Any]]:
        value = self.request("POST", "/session", {"capabilities": {"alwaysMatch": capabilities}})
        if not isinstance(value, dict):
            raise RunnerError("WebDriver returned an invalid session")
        session_id = value.get("sessionId")
        returned = value.get("capabilities", {})
        if not isinstance(session_id, str) or not session_id or not isinstance(returned, dict):
            raise RunnerError("WebDriver returned incomplete session metadata")
        return session_id, returned


def diagnostic(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("message") or value.get("error") or compact_json(value)
    text = " ".join(str(value).split())
    return text[:300] or "unknown error"


def stop_process_group(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=3)
    except (OSError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass


def numeric_version(value: str) -> str:
    matches = list(DOTTED_VERSION_RE.finditer(value))
    if len(matches) != 1:
        raise RunnerError("browser version must contain exactly one complete dotted release")
    return matches[0].group(1)


def validate_session_identity(identity: BrowserIdentity, capabilities: Mapping[str, Any]) -> str:
    returned_name = str(capabilities.get("browserName", "")).lower()
    expected_names = {"chrome", "chromium"} if identity.browser == "chromium" else {"firefox"}
    if returned_name not in expected_names:
        raise RunnerError("WebDriver session used an unexpected browser")
    returned_version = str(capabilities.get("browserVersion", ""))
    session_display = diagnostic(returned_version)[:120]
    locked_display = diagnostic(identity.implementation_version)[:120]
    try:
        session_release = numeric_version(returned_version)
        locked_release = numeric_version(identity.implementation_version)
    except RunnerError as error:
        raise RunnerError(
            "cannot compare WebDriver and locked browser versions "
            "(session=%r, locked=%r): %s"
            % (session_display, locked_display, error)
        ) from error
    if session_release != locked_release:
        raise RunnerError(
            "WebDriver browser version differs from the locked executable "
            "(session=%r, locked=%r)" % (session_display, locked_display)
        )
    return returned_version


def validate_workload_result(value: Any, workload: str, protocol: str) -> Dict[str, Any]:
    if not isinstance(value, dict) or value.get("ok") is not True:
        detail = value.get("error") if isinstance(value, dict) else value
        raise RunnerError("browser workload failed: %s" % diagnostic(detail))
    spec = WORKLOAD_SPECS[workload]
    resources = value.get("resources")
    if not isinstance(resources, list) or len(resources) != spec["requests"]:
        raise RunnerError("Resource Timing entry count does not match the workload")
    protocols: List[str] = []
    indexes = set()
    for resource in resources:
        if not isinstance(resource, dict):
            raise RunnerError("Resource Timing result is malformed")
        index = resource.get("request_index")
        next_hop = resource.get("next_hop_protocol")
        if not isinstance(index, int) or isinstance(index, bool) or index in indexes:
            raise RunnerError("Resource Timing request indexes are invalid")
        indexes.add(index)
        if next_hop != protocol:
            raise RunnerError(
                "Resource Timing protocol mismatch: got %r, expected %r" % (next_hop, protocol)
            )
        protocols.append(next_hop)
    if indexes != set(range(spec["requests"])):
        raise RunnerError("Resource Timing entries do not cover every request")
    for field in ("request_count", "response_bytes", "upload_bytes"):
        measured = value.get(field)
        expected = spec[field.replace("request_count", "requests")]
        if not isinstance(measured, int) or isinstance(measured, bool) or measured != expected:
            raise RunnerError("browser workload %s does not match its frozen definition" % field)
    return {
        "next_hop_protocols": protocols,
        "request_count": spec["requests"],
        "response_bytes": spec["response_bytes"],
        "upload_bytes": spec["upload_bytes"],
        "resource_indexes": sorted(indexes),
    }


def validate_bootstrap_result(value: Any, protocol: str, seed: int) -> None:
    if not isinstance(value, dict) or set(value) != {
        "ok", "sample_seed", "next_hop_protocol"
    }:
        raise RunnerError("browser bootstrap validation result is malformed")
    if value.get("ok") is not True or value.get("sample_seed") != seed:
        raise RunnerError("browser bootstrap document differs from the frozen fixture")
    if value.get("next_hop_protocol") != protocol:
        raise RunnerError(
            "bootstrap navigation protocol mismatch: got %r, expected %r"
            % (value.get("next_hop_protocol"), protocol)
        )


def workload_receipt(
    identity: BrowserIdentity,
    protocol: str,
    workload: str,
    seed: int,
    result: Mapping[str, Any],
) -> Dict[str, Any]:
    result_document = {
        "protocol": protocol,
        "workload": workload,
        "sample_seed": seed,
        "request_count": result["request_count"],
        "response_bytes": result["response_bytes"],
        "upload_bytes": result["upload_bytes"],
        "resources": [
            {"request_index": index, "next_hop_protocol": next_hop}
            for index, next_hop in zip(result["resource_indexes"], result["next_hop_protocols"])
        ],
    }
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "status": "pass",
        "kind": KIND,
        "client_implementation": identity.client_implementation,
        "implementation_version": identity.implementation_version,
        "browser_binary_sha256": identity.browser_binary_sha256,
        "protocol": protocol,
        "workload": workload,
        "sample_seed": seed,
        "next_hop_protocols": list(result["next_hop_protocols"]),
        "request_count": result["request_count"],
        "response_bytes": result["response_bytes"],
        "result_sha256": canonical_json_sha256(result_document),
    }
    if set(receipt) != SUCCESS_FIELDS:
        raise AssertionError("success receipt fields changed")
    return receipt


def execute_browser_workload(args: argparse.Namespace) -> Dict[str, Any]:
    server = parse_server(args.server)
    identity = load_browser_identity(Path(args.browser_lock), args.browser)
    profile_root = Path(args.runtime_directory)
    if not profile_root.is_absolute() or profile_root == Path("/"):
        raise UsageError("--runtime-directory must be an absolute non-root path")
    profile_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sample-", dir=str(profile_root)) as temporary:
        temporary_path = Path(temporary)
        port = free_loopback_port()
        environment = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(temporary_path),
            "XDG_CACHE_HOME": str(temporary_path / "cache"),
            "XDG_CONFIG_HOME": str(temporary_path / "config"),
            "TMPDIR": str(temporary_path),
            "LANG": "C.UTF-8",
            "NO_PROXY": "*",
            "no_proxy": "*",
        }
        process = subprocess.Popen(
            driver_command(identity, port),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
            start_new_session=True,
        )
        client = WebDriverClient(port, args.webdriver_timeout)
        session_id: Optional[str] = None
        try:
            client.wait_ready(process)
            capabilities = browser_capabilities(
                identity,
                args.protocol,
                server,
                temporary_path / "browser-profile",
                args.accept_insecure_certs,
                args.certificate_spki_sha256,
            )
            session_id, returned = client.create_session(capabilities)
            validate_session_identity(identity, returned)
            client.request(
                "POST",
                "/session/%s/timeouts" % session_id,
                {"pageLoad": args.workload_timeout * 1000, "script": args.workload_timeout * 1000},
            )
            page = "https://%s/?autocar_browser_sample=%d" % (server.authority, args.seed)
            client.request("POST", "/session/%s/url" % session_id, {"url": page})
            bootstrap_result = client.request(
                "POST",
                "/session/%s/execute/sync" % session_id,
                {"script": BOOTSTRAP_VERIFY_SCRIPT, "args": [args.seed]},
            )
            validate_bootstrap_result(bootstrap_result, args.protocol, args.seed)
            raw_result = client.request(
                "POST",
                "/session/%s/execute/async" % session_id,
                {"script": WORKLOAD_SCRIPT, "args": [args.workload, args.seed, args.idle_milliseconds]},
            )
            checked = validate_workload_result(raw_result, args.workload, args.protocol)
            return workload_receipt(identity, args.protocol, args.workload, args.seed, checked)
        finally:
            if session_id is not None:
                try:
                    client.request("DELETE", "/session/%s" % session_id)
                except RunnerError:
                    pass
            stop_process_group(process)


def parser() -> StrictArgumentParser:
    result = StrictArgumentParser(description="run one isolated real-browser workload")
    result.add_argument("--browser", required=True, choices=tuple(BROWSER_NAMES))
    result.add_argument("--protocol", required=True, choices=("h3", "h2"))
    result.add_argument("--server", required=True)
    result.add_argument("--workload", required=True, choices=tuple(WORKLOAD_SPECS))
    result.add_argument("--seed", required=True, type=parse_seed)
    result.add_argument(
        "--browser-lock", default=os.environ.get("STEALTH_BROWSER_LOCK", "/campaign/browser-lock.json")
    )
    result.add_argument(
        "--runtime-directory",
        default=os.environ.get("STEALTH_BROWSER_RUNTIME", "/tmp/stealth-browser"),
    )
    result.add_argument(
        "--webdriver-timeout", default=15, type=lambda value: bounded_number(value, "--webdriver-timeout", 1, 60)
    )
    result.add_argument(
        "--workload-timeout", default=45, type=lambda value: bounded_number(value, "--workload-timeout", 5, 300)
    )
    result.add_argument(
        "--idle-milliseconds", default=1200, type=lambda value: bounded_number(value, "--idle-milliseconds", 100, 10000)
    )
    result.add_argument("--accept-insecure-certs", action="store_true")
    result.add_argument(
        "--certificate-spki-sha256",
        type=parse_certificate_spki_sha256,
        help="canonical Base64 SHA-256 of the leaf certificate SPKI; Chromium H3 only",
    )
    return result


def identity_parser() -> StrictArgumentParser:
    result = StrictArgumentParser(description="print the locked browser campaign identity")
    result.add_argument(
        "--browser-lock", default=os.environ.get("STEALTH_BROWSER_LOCK", "/campaign/browser-lock.json")
    )
    return result


def self_test() -> None:
    assert parse_server("10.1.2.3:443").authority == "10.1.2.3:443"
    assert parse_server("172.16.0.1:8443").port == 8443
    assert numeric_version("Mozilla Firefox 140.15.0esr") == "140.15.0"
    assert numeric_version("Chromium 152.0.7977.75") == "152.0.7977.75"
    try:
        numeric_version("Mozilla Firefox 140.15.0.1.2")
    except RunnerError:
        pass
    else:
        raise AssertionError("extra browser version component was accepted")
    for unsafe in (
        "8.8.8.8:443",
        "127.0.0.1:443",
        "169.254.1.1:443",
        "10.0.0.1:443;id",
        "https://10.0.0.1:443",
        "[fd00::1]:443",
    ):
        try:
            parse_server(unsafe)
        except RunnerError:
            pass
        else:
            raise AssertionError("unsafe server accepted: %s" % unsafe)
    assert set(WORKLOAD_SPECS) == {
        "idle", "download_1k", "download_128k", "download_1m", "upload_1m",
        "parallel_20", "interactive", "browser_h2",
    }
    value = {
        "ok": True,
        "request_count": 1,
        "response_bytes": 128 * 1024,
        "upload_bytes": 0,
        "resources": [{"request_index": 0, "next_hop_protocol": "h2"}],
    }
    checked = validate_workload_result(value, "browser_h2", "h2")
    assert checked["response_bytes"] == 128 * 1024
    validate_bootstrap_result(
        {"ok": True, "sample_seed": 7, "next_hop_protocol": "h2"}, "h2", 7
    )
    try:
        validate_workload_result(value, "browser_h2", "h3")
    except RunnerError:
        pass
    else:
        raise AssertionError("protocol mismatch was accepted")
    fake = BrowserIdentity(
        "chromium", "Chromium", "Chromium 123.4.5.6", "/usr/lib/chromium/chromium",
        "a" * 64, "/usr/bin/chromedriver", "ChromeDriver 123.4.5.6", "b" * 64,
    )
    receipt = workload_receipt(fake, "h2", "browser_h2", 7, checked)
    assert set(receipt) == SUCCESS_FIELDS and receipt["workload"] == "browser_h2"
    assert SHA256_RE.fullmatch(receipt["result_sha256"])
    assert "--disable-quic" in browser_capabilities(
        fake, "h2", parse_server("10.0.0.1:443"), Path("/tmp/profile"), False, None
    )["goog:chromeOptions"]["args"]
    pin = base64.b64encode(bytes(range(32))).decode("ascii")
    assert "--ignore-certificate-errors-spki-list=%s" % pin in browser_capabilities(
        fake, "h3", parse_server("10.0.0.1:443"), Path("/tmp/profile"), True, pin
    )["goog:chromeOptions"]["args"]
    firefox = BrowserIdentity(
        "firefox-esr", "Firefox", "Mozilla Firefox 140.15.0esr",
        "/usr/lib/firefox-esr/firefox-esr", "c" * 64,
        "/usr/local/bin/geckodriver", "geckodriver 0.37.1", "d" * 64,
    )
    firefox_server = parse_server("10.0.0.2:8443")
    firefox_h3_prefs = browser_capabilities(
        firefox, "h3", firefox_server, Path("/tmp/profile"), True, None
    )["moz:firefoxOptions"]["prefs"]
    assert firefox_h3_prefs["network.http.http3.alt-svc-mapping-for-testing"] == (
        '10.0.0.2;h3=":8443"'
    )
    assert firefox_h3_prefs[
        "network.http.http3.disable_when_third_party_roots_found"
    ] is False
    firefox_h2_prefs = browser_capabilities(
        firefox, "h2", firefox_server, Path("/tmp/profile"), True, None
    )["moz:firefoxOptions"]["prefs"]
    for h3_only_preference in (
        "network.http.http3.alt-svc-mapping-for-testing",
        "network.http.http3.force-use-alt-svc-mapping-for-testing",
        "network.http.http3.disable_when_third_party_roots_found",
    ):
        assert h3_only_preference not in firefox_h2_prefs
    try:
        executable_path("/bin/sh -c id", "chromium", "browser")
    except RunnerError:
        pass
    else:
        raise AssertionError("shell command string was accepted as a binary")


def main(argv: Optional[Sequence[str]] = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    try:
        if values == ["--self-test"]:
            self_test()
            print(compact_json({"schema_version": 1, "status": "pass", "self_test": True}))
            return 0
        if values and values[0] == "identity":
            args = identity_parser().parse_args(values[1:])
            identity = load_browser_identity(Path(args.browser_lock))
            print(
                compact_json(
                    {
                        "client_implementation": identity.client_implementation,
                        "implementation_version": identity.implementation_version,
                        "browser_binary_sha256": identity.browser_binary_sha256,
                    }
                )
            )
            return 0
        args = parser().parse_args(values)
        validate_certificate_spki_usage(
            args.browser, args.protocol, args.certificate_spki_sha256
        )
        receipt = execute_browser_workload(args)
        print(compact_json(receipt))
        return 0
    except UsageError as error:
        print("stealth-browser: %s" % diagnostic(error), file=sys.stderr)
        return 2
    except (RunnerError, OSError, subprocess.SubprocessError) as error:
        print("stealth-browser: %s" % diagnostic(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
