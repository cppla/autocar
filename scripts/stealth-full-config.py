#!/usr/bin/env python3
"""Generate and audit the frozen local-Docker full stealth lab configuration.

This module deliberately keeps authentication values out of retained metadata.
The token and Hysteria credentials remain only in the mode-0700 inputs tree;
effective descriptors contain commitments, never plaintext secrets.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import runpy
import ssl
import subprocess
import tempfile
from typing import Any, Dict, Iterable, Mapping, Sequence


PRODUCTS = ("cover", "autocar", "hysteria2")
COVER_WEBDRIVER_TIMEOUT_SECONDS = 60
LABEL_KEY = "com.cppla.autocar.stealth-campaign"
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
SHA_RE = re.compile(r"[0-9a-f]{64}")
IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}")
USER_RE = re.compile(r"[1-9][0-9]*(?::[1-9][0-9]*)?")
CAPTURE_HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}")
FORBIDDEN_MARKERS = ("replace-before", "replace-with", "placeholder", "todo")
MANIFEST_FIELDS = (
    "sample_id", "product", "scenario", "workload", "wire_profile", "run_id",
    "seed", "pcap", "client_ip", "server_ip", "client_implementation",
    "server_implementation", "implementation_version", "runner_image_id",
    "server_container_id", "capture_host", "docker_engine_fingerprint",
)
RFC1918 = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="prepare or audit a formal stealth lab")
    commands = root.add_subparsers(dest="command", required=True)

    generate = commands.add_parser("generate")
    required = (
        "lab-dir", "inputs-root", "campaign-output", "metadata-output", "full-output-dir",
        "autocar-effective-output", "hysteria-effective-output", "caddy-output",
        "nginx-output", "campaign-id", "network", "capture-image",
        "runner-image", "chromium-image", "firefox-image", "capture-host", "user",
        "origin-container", "origin-ip", "caddy-container", "caddy-ip",
        "nginx-container", "nginx-ip", "autocar-container", "autocar-ip",
        "hysteria-container", "hysteria-ip", "cert", "key", "token",
        "autocar-binary", "hysteria-binary", "hysteria-client-config",
        "hysteria-server-config", "autocar-version", "hysteria-version",
        "hysteria-expected-sha256", "chromium-client-implementation",
        "chromium-version", "chromium-binary-sha256", "chromium-spki-sha256",
        "firefox-client-implementation", "firefox-version", "firefox-binary-sha256",
        "caddy-image", "nginx-image",
        "preregistration-recorded-at",
    )
    for name in required:
        generate.add_argument("--" + name, required=True)

    verify = commands.add_parser("verify-calibration")
    verify.add_argument("--lab-dir", required=True)
    verify.add_argument("--campaign-dir", required=True)
    verify.add_argument("--metadata", required=True)
    verify.add_argument("--config", required=True)
    verify.add_argument("--token", required=True)
    verify.add_argument("--output", required=True)

    ready = commands.add_parser("verify-ready")
    ready.add_argument("--lab-dir", required=True)

    journal = commands.add_parser("write-ownership-journal")
    for name in (
        "lab-dir", "campaign-id", "network", "origin-container",
        "caddy-container", "nginx-container", "autocar-container",
        "hysteria-container", "extractor-container",
    ):
        journal.add_argument("--" + name, required=True)

    status = commands.add_parser("status")
    status.add_argument("--lab-dir", required=True)

    value = commands.add_parser("value")
    value.add_argument("--metadata", required=True)
    value.add_argument("--field", required=True, choices=(
        "campaign_id", "ownership_label", "network", "origin_container",
        "caddy_container", "nginx_container", "autocar_container",
        "hysteria_container", "capture_image", "runner_image",
        "chromium_image", "firefox_image",
    ))

    journal_value = commands.add_parser("journal-value")
    journal_value.add_argument("--journal", required=True)
    journal_value.add_argument("--field", required=True, choices=(
        "campaign_id", "ownership_label", "network", "origin_container",
        "caddy_container", "nginx_container", "autocar_container",
        "hysteria_container", "extractor_container",
    ))

    commands.add_parser("self-test")
    return root


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "generate":
        generate(args)
    elif args.command == "verify-calibration":
        verify_calibration(args)
    elif args.command == "verify-ready":
        print(compact_json(verify_ready(Path(args.lab_dir))))
    elif args.command == "write-ownership-journal":
        write_ownership_journal(args)
    elif args.command == "status":
        print(compact_json(read_status(Path(args.lab_dir))))
    elif args.command == "value":
        value = read_metadata(Path(args.metadata))[args.field]
        if not isinstance(value, str) or "\n" in value or "\r" in value:
            fail("metadata field is not a safe scalar")
        print(value)
    elif args.command == "journal-value":
        value = read_ownership_journal(Path(args.journal))[args.field]
        print(value)
    else:
        self_test()
    return 0


def write_ownership_journal(args: argparse.Namespace) -> None:
    lab_dir = Path(args.lab_dir).resolve(strict=True)
    if lab_dir == Path("/") or not lab_dir.is_dir():
        fail("ownership journal requires an existing non-root lab directory")
    names = {}
    for field in (
        "campaign_id", "network", "origin_container", "caddy_container",
        "nginx_container", "autocar_container", "hysteria_container",
        "extractor_container",
    ):
        names[field] = require_name(getattr(args, field), f"journal {field}")
    value = {
        "schema_version": 1,
        "status": "preparing",
        "created_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lab_dir": str(lab_dir),
        "campaign_id": names["campaign_id"],
        "ownership_label": f"{LABEL_KEY}={names['campaign_id']}",
        "network": names["network"],
        "origin_container": names["origin_container"],
        "caddy_container": names["caddy_container"],
        "nginx_container": names["nginx_container"],
        "autocar_container": names["autocar_container"],
        "hysteria_container": names["hysteria_container"],
        "extractor_container": names["extractor_container"],
    }
    write_json(lab_dir / "ownership-journal.json", value)


def read_ownership_journal(path: Path) -> Dict[str, Any]:
    path = path.resolve(strict=True)
    value = read_json(path)
    expected = {
        "schema_version", "status", "created_at", "lab_dir", "campaign_id",
        "ownership_label", "network", "origin_container", "caddy_container",
        "nginx_container", "autocar_container", "hysteria_container",
        "extractor_container",
    }
    if set(value) != expected or value.get("schema_version") != 1 or value.get("status") != "preparing":
        fail("ownership journal has an unsupported schema")
    lab_dir = Path(require_text(value.get("lab_dir"), "journal lab directory")).resolve(strict=True)
    if path != lab_dir / "ownership-journal.json":
        fail("ownership journal path does not match its lab directory")
    campaign_id = require_name(value.get("campaign_id"), "journal campaign ID")
    if value.get("ownership_label") != f"{LABEL_KEY}={campaign_id}":
        fail("ownership journal label is inconsistent")
    utc_timestamp(value.get("created_at"), "journal created_at")
    for field in (
        "network", "origin_container", "caddy_container", "nginx_container",
        "autocar_container", "hysteria_container", "extractor_container",
    ):
        require_name(value.get(field), f"journal {field}")
    return value


def generate(args: argparse.Namespace) -> None:
    lab_dir = Path(args.lab_dir).resolve(strict=True)
    inputs = Path(args.inputs_root).resolve(strict=True)
    if lab_dir == Path("/") or inputs == Path("/") or not inputs.is_dir():
        fail("lab and inputs roots must be existing non-root directories")
    under(lab_dir, inputs, "inputs root")
    full_output_dir = Path(args.full_output_dir).resolve(strict=False)
    under(lab_dir, full_output_dir, "full output directory")
    if full_output_dir.exists():
        fail("full output directory must not exist during lab generation")
    for field in (
        "campaign_id", "network", "origin_container", "caddy_container",
        "nginx_container", "autocar_container", "hysteria_container",
    ):
        require_name(getattr(args, field), field)
    if not USER_RE.fullmatch(args.user):
        fail("user must be a non-root numeric UID or UID:GID")
    images = {
        name: immutable_image_id(getattr(args, name))
        for name in ("capture_image", "runner_image", "chromium_image", "firefox_image")
    }
    pinned_servers = {
        "caddy_image": require_digest_ref(args.caddy_image, "caddy image"),
        "nginx_image": require_digest_ref(args.nginx_image, "nginx image"),
    }
    endpoints = {
        name: private_ip(getattr(args, name + "_ip"))
        for name in ("origin", "caddy", "nginx", "autocar", "hysteria")
    }
    if len(set(endpoints.values())) != len(endpoints):
        fail("all full-lab endpoint IPs must be distinct")
    files = {
        name: checked_file(inputs, Path(getattr(args, name)).resolve(strict=True), name)
        for name in (
            "cert", "key", "token", "autocar_binary", "hysteria_binary",
            "hysteria_client_config", "hysteria_server_config",
        )
    }
    if sha256(files["hysteria_binary"]) != args.hysteria_expected_sha256:
        fail("Hysteria binary does not match the pinned official checksum")
    if not SHA_RE.fullmatch(args.hysteria_expected_sha256):
        fail("Hysteria checksum is malformed")
    for field in (
        "autocar_version", "hysteria_version", "chromium_client_implementation",
        "chromium_version", "firefox_client_implementation", "firefox_version",
    ):
        require_text(getattr(args, field), field)
    capture_host = require_capture_host(args.capture_host)
    preregistration_recorded_at = utc_timestamp(
        args.preregistration_recorded_at, "preregistration-recorded-at"
    )
    if args.chromium_client_implementation != "Chromium":
        fail("Chromium lock identity is inconsistent")
    if args.firefox_client_implementation != "Firefox":
        fail("Firefox ESR lock identity is inconsistent")
    for field in ("chromium_binary_sha256", "firefox_binary_sha256"):
        if not SHA_RE.fullmatch(getattr(args, field)):
            fail(f"{field} is malformed")
    chromium_spki_sha256 = require_spki_sha256(
        args.chromium_spki_sha256, "Chromium certificate SPKI SHA-256"
    )
    verify_numeric_sans(files["cert"], endpoints["caddy"], endpoints["nginx"])

    caddy_path = output_under(inputs, args.caddy_output, "Caddy output")
    nginx_path = output_under(inputs, args.nginx_output, "nginx output")
    write_text(caddy_path, caddy_config(endpoints["caddy"], endpoints["origin"]))
    write_text(nginx_path, nginx_config(endpoints["origin"]))

    auth_hash = sha256(files["token"])
    autocar_effective_path = output_under(
        inputs, args.autocar_effective_output, "AutoCAR effective output"
    )
    hysteria_effective_path = output_under(
        inputs, args.hysteria_effective_output, "Hysteria effective output"
    )
    autocar_effective = {
        "schema_version": 1,
        "evidence_class": "formal_full_lab",
        "product": "autocar",
        "implementation_version": args.autocar_version,
        "binary_sha256": sha256(files["autocar_binary"]),
        "transport": "h3",
        "h3_fingerprint": "chrome-2026-08",
        "relay": f"{endpoints['autocar']}:8443",
        "origin": f"http://{endpoints['origin']}:8080",
        "server_name": "cover.test",
        "certificate_sha256": sha256(files["cert"]),
        "private_key_sha256": sha256(files["key"]),
        "token_sha256": auth_hash,
    }
    hysteria_effective = {
        "schema_version": 1,
        "evidence_class": "formal_full_lab",
        "product": "hysteria2",
        "implementation_version": args.hysteria_version,
        "binary_sha256": sha256(files["hysteria_binary"]),
        "profile": "standard",
        "chrome_quic_parrot": True,
        "gecko": False,
        "relay": f"{endpoints['hysteria']}:8443",
        "origin": f"http://{endpoints['origin']}:8080",
        "server_name": "cover.test",
        "certificate_sha256": sha256(files["cert"]),
        "private_key_sha256": sha256(files["key"]),
        "auth_sha256": auth_hash,
        "client_config_sha256": sha256(files["hysteria_client_config"]),
        "server_config_sha256": sha256(files["hysteria_server_config"]),
    }
    write_json(autocar_effective_path, autocar_effective)
    write_json(hysteria_effective_path, hysteria_effective)

    campaign: Dict[str, Any] = {
        "schema_version": 1,
        "campaign_id": args.campaign_id,
        "lab": {
            "docker_network": args.network,
            "ownership_label": f"{LABEL_KEY}={args.campaign_id}",
            "capture_image": images["capture_image"],
            "capture_host": capture_host,
            "interface": "eth0",
            "allowed_mount_roots": [str(inputs)],
            "minimum_packets": 5,
            "workload_timeout_seconds": 120,
            "runner_memory_mb": 896,
            "runner_pids_limit": 512,
        },
        "provenance": {
            "preregistration_recorded_at": preregistration_recorded_at,
            "autocar_binary": str(files["autocar_binary"]),
            "autocar_config": str(autocar_effective_path),
            "hysteria2_binary": str(files["hysteria_binary"]),
            "hysteria2_config": str(hysteria_effective_path),
        },
        "products": {
            "cover": {"variants": [
                browser_variant(
                    "chromium-caddy", "chromium", args.chromium_client_implementation,
                    args.chromium_version, args.chromium_binary_sha256,
                    images["chromium_image"], args.caddy_container,
                    endpoints["caddy"], "Caddy 2.10.2", (), chromium_spki_sha256,
                ),
                browser_variant(
                    "firefox-esr-nginx", "firefox-esr", args.firefox_client_implementation,
                    args.firefox_version, args.firefox_binary_sha256,
                    images["firefox_image"], args.nginx_container,
                    endpoints["nginx"], "nginx-quic 1.29.1", (), None,
                ),
            ]},
            "autocar": {"variants": [{
                "name": "autocar-v101-web-h3",
                "client_implementation": "AutoCAR v1.0.1 WebH3Client",
                "server_implementation": "AutoCAR v1.0.1 web H3 server",
                "implementation_version": args.autocar_version,
                "real_browser": False,
                "runner_image": images["runner_image"],
                "server_container": args.autocar_container,
                "server_ip": str(endpoints["autocar"]),
                "server_port": 8443,
                "transport": "udp",
                "command": [
                    "/stealth-pilot", "proxy-workload", "--client", "autocar",
                    "--client-bin", "/autocar", "--server", "{server_ip}:{server_port}",
                    "--server-name", "cover.test", "--ca", "/pilot/server.crt",
                    "--token-file", "/pilot/token", "--proxy-listen", "127.0.0.1:18080",
                    "--origin", f"http://{endpoints['origin']}:8080",
                    "--workload", "{workload}", "--seed", "{sample_seed}",
                ],
                "environment": {},
                "mounts": [
                    {"source": str(files["cert"]), "target": "/pilot/server.crt", "read_only": True},
                    {"source": str(files["token"]), "target": "/pilot/token", "read_only": True},
                ],
                "user": args.user,
            }]},
            "hysteria2": {"variants": [{
                "name": "hysteria2-v2122-standard",
                "client_implementation": "official Hysteria 2 v2.12.2 client",
                "server_implementation": "official Hysteria 2 v2.12.2 reverse-proxy masquerade",
                "implementation_version": args.hysteria_version,
                "real_browser": False,
                "runner_image": images["runner_image"],
                "server_container": args.hysteria_container,
                "server_ip": str(endpoints["hysteria"]),
                "server_port": 8443,
                "transport": "udp",
                "command": [
                    "/stealth-pilot", "proxy-workload", "--client", "hysteria2",
                    "--client-bin", "/hysteria", "--client-config", "/pilot/hysteria-client.yaml",
                    "--server", "{server_ip}:{server_port}",
                    "--proxy-listen", "127.0.0.1:18080",
                    "--origin", f"http://{endpoints['origin']}:8080",
                    "--workload", "{workload}", "--seed", "{sample_seed}",
                ],
                "environment": {},
                "mounts": [
                    {"source": str(files["cert"]), "target": "/pilot/server.crt", "read_only": True},
                    {"source": str(files["hysteria_binary"]), "target": "/hysteria", "read_only": True},
                    {"source": str(files["hysteria_client_config"]), "target": "/pilot/hysteria-client.yaml", "read_only": True},
                ],
                "user": args.user,
            }]},
        },
    }
    assert_no_markers(campaign)
    campaign_path = output_under(inputs, args.campaign_output, "campaign output")
    write_json(campaign_path, campaign)

    metadata = {
        "schema_version": 1,
        "status": "configured",
        "campaign_id": args.campaign_id,
        "ownership_label": f"{LABEL_KEY}={args.campaign_id}",
        "network": args.network,
        "capture_host": capture_host,
        "subnet": str(ipaddress.ip_network(f"{endpoints['origin']}/24", strict=False)),
        "lab_dir": str(lab_dir),
        "inputs_root": str(inputs),
        "campaign_config": str(campaign_path),
        "calibration_dir": str(lab_dir / "calibration"),
        "full_output_dir": str(full_output_dir),
        "origin_container": args.origin_container,
        "caddy_container": args.caddy_container,
        "nginx_container": args.nginx_container,
        "autocar_container": args.autocar_container,
        "hysteria_container": args.hysteria_container,
        "capture_image": images["capture_image"],
        "runner_image": images["runner_image"],
        "chromium_image": images["chromium_image"],
        "firefox_image": images["firefox_image"],
        "caddy_image": pinned_servers["caddy_image"],
        "nginx_image": pinned_servers["nginx_image"],
        "endpoints": {name: str(address) for name, address in endpoints.items()},
        "browser_binary_sha256": {
            "chromium": args.chromium_binary_sha256,
            "firefox-esr": args.firefox_binary_sha256,
        },
        "chromium_certificate_spki_sha256": chromium_spki_sha256,
        "config_sha256": sha256(campaign_path),
    }
    assert_no_markers(metadata)
    metadata_path = Path(args.metadata_output).resolve(strict=False)
    under(lab_dir, metadata_path, "metadata output")
    write_json(metadata_path, metadata)


def browser_variant(
    name: str,
    browser: str,
    client: str,
    version: str,
    browser_binary_sha256: str,
    image: str,
    server_container: str,
    server_ip: ipaddress.IPv4Address,
    server_implementation: str,
    mounts: Sequence[Mapping[str, Any]],
    certificate_spki_sha256: str | None,
) -> Dict[str, Any]:
    common = [
        "/campaign/run-cover", "--browser", browser, "--server",
        "{server_ip}:{server_port}", "--seed", "{sample_seed}",
        "--accept-insecure-certs", "--webdriver-timeout",
        str(COVER_WEBDRIVER_TIMEOUT_SECONDS),
    ]
    h3_command = common[:3] + ["--protocol", "h3"] + common[3:8] + [
        "--workload", "{workload}",
    ] + common[8:]
    if browser == "chromium":
        if certificate_spki_sha256 is None:
            fail("Chromium H3 variant is missing its certificate SPKI pin")
        h3_command.extend(["--certificate-spki-sha256", certificate_spki_sha256])
    elif certificate_spki_sha256 is not None:
        fail("certificate SPKI pin must not be added to a non-Chromium variant")
    h2_command = common[:3] + ["--protocol", "h2"] + common[3:8] + [
        "--workload", "browser_h2",
    ] + common[8:]
    return {
        "name": name,
        "client_implementation": client,
        "server_implementation": server_implementation,
        "implementation_version": version,
        "real_browser": True,
        "browser_binary_sha256": browser_binary_sha256,
        "runner_image": image,
        "server_container": server_container,
        "server_ip": str(server_ip),
        "server_port": 8443,
        "transport": "udp",
        "command": h3_command,
        "h2_command": h2_command,
        "environment": {},
        "mounts": list(mounts),
        "user": "65532:65532",
    }


def caddy_config(caddy_ip: ipaddress.IPv4Address, origin_ip: ipaddress.IPv4Address) -> str:
    return f"""{{
    admin off
    auto_https off
    servers {{
        protocols h1 h2 h3
    }}
}}

https://{caddy_ip}:8443 {{
    tls /campaign/server.crt /campaign/server.key
    header Alt-Svc \"h3=\\\":8443\\\"; ma=86400\"
    reverse_proxy http://{origin_ip}:8080
}}
"""


def nginx_config(origin_ip: ipaddress.IPv4Address) -> str:
    return f"""worker_processes 1;
pid /tmp/nginx.pid;
error_log /dev/stderr notice;

events {{ worker_connections 1024; }}

http {{
    access_log /dev/stdout;
    client_max_body_size 2m;
    client_body_temp_path /tmp/client-body;
    proxy_temp_path /tmp/proxy;
    fastcgi_temp_path /tmp/fastcgi;
    uwsgi_temp_path /tmp/uwsgi;
    scgi_temp_path /tmp/scgi;
    server {{
        listen 8443 ssl;
        listen 8443 quic reuseport;
        http2 on;
        ssl_protocols TLSv1.3;
        ssl_certificate /campaign/server.crt;
        ssl_certificate_key /campaign/server.key;
        add_header Alt-Svc 'h3=\":8443\"; ma=86400' always;
        location / {{
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-For \"\";
            proxy_pass http://{origin_ip}:8080;
        }}
    }}
}}
"""


def verify_calibration(args: argparse.Namespace) -> None:
    lab_dir = Path(args.lab_dir).resolve(strict=True)
    campaign_dir = Path(args.campaign_dir).resolve(strict=True)
    metadata_path = Path(args.metadata).resolve(strict=True)
    config_path = Path(args.config).resolve(strict=True)
    token_path = Path(args.token).resolve(strict=True)
    result = audit_calibration(
        lab_dir, campaign_dir, metadata_path, config_path, token_path
    )
    output = Path(args.output).resolve(strict=False)
    if output != lab_dir / "lab-state.json":
        fail("lab state output must be the fixed lab-state.json path")
    if output.exists():
        fail("refusing to overwrite existing lab state")
    write_json(output, result)
    print(compact_json(result))


def verify_ready(lab_dir: Path) -> Dict[str, Any]:
    """Revalidate all calibration evidence without repairing or writing anything."""
    lab_dir = lab_dir.resolve(strict=True)
    metadata_path = lab_dir / "lab-metadata.json"
    metadata = read_metadata(metadata_path)
    if Path(metadata["lab_dir"]).resolve(strict=True) != lab_dir:
        fail("metadata lab directory does not match the requested lab")
    campaign_dir = Path(metadata["calibration_dir"]).resolve(strict=True)
    config_path = Path(metadata["campaign_config"]).resolve(strict=True)
    token_path = Path(metadata["inputs_root"]).resolve(strict=True) / "token"
    expected = audit_calibration(
        lab_dir, campaign_dir, metadata_path, config_path, token_path
    )
    state_path = lab_dir / "lab-state.json"
    state = read_json(state_path.resolve(strict=True))
    if state != expected:
        fail("lab calibration state does not exactly match revalidated evidence")
    return {
        "schema_version": 1,
        "status": "ready",
        "campaign_id": metadata["campaign_id"],
        "claim_status": "insufficient_evidence",
        "full_capture_started": False,
        "calibration_pcaps": 65,
    }


def audit_calibration(
    lab_dir: Path, campaign_dir: Path, metadata_path: Path,
    config_path: Path, token_path: Path,
) -> Dict[str, Any]:
    lab_dir = lab_dir.resolve(strict=True)
    campaign_dir = campaign_dir.resolve(strict=True)
    metadata_path = metadata_path.resolve(strict=True)
    config_path = config_path.resolve(strict=True)
    token_path = token_path.resolve(strict=True)
    for path, label in (
        (campaign_dir, "campaign directory"), (metadata_path, "metadata"),
        (config_path, "config"), (token_path, "token"),
    ):
        under(lab_dir, path, label)
    metadata = read_metadata(metadata_path)
    inputs = Path(metadata["inputs_root"]).resolve(strict=True)
    expected_paths = {
        "lab": Path(metadata["lab_dir"]).resolve(strict=True),
        "metadata": lab_dir / "lab-metadata.json",
        "calibration": Path(metadata["calibration_dir"]).resolve(strict=True),
        "config": Path(metadata["campaign_config"]).resolve(strict=True),
        "token": inputs / "token",
        "full": Path(metadata["full_output_dir"]).resolve(strict=False),
    }
    actual_paths = {
        "lab": lab_dir, "metadata": metadata_path, "calibration": campaign_dir,
        "config": config_path, "token": token_path, "full": lab_dir / "full-campaign",
    }
    for name in expected_paths:
        if actual_paths[name] != expected_paths[name]:
            fail(f"fixed lab evidence path is inconsistent: {name}")
    journal_path = lab_dir / "ownership-journal.json"
    if journal_path.is_file():
        journal = read_ownership_journal(journal_path)
        for field in (
            "campaign_id", "ownership_label", "network", "origin_container",
            "caddy_container", "nginx_container", "autocar_container",
            "hysteria_container",
        ):
            if journal[field] != metadata[field]:
                fail(f"ownership journal and metadata disagree on {field}")
    config_digest = sha256(config_path)
    if metadata["config_sha256"] != config_digest:
        fail("campaign config changed after lab generation")
    raw_config = read_json(config_path)
    campaign = campaign_api()
    try:
        validated_config = campaign["validate_config"](raw_config, config_path.parent)
    except Exception as error:
        fail(f"campaign configuration is invalid: {error}")
    validate_config_metadata_binding(raw_config, validated_config, metadata, inputs)

    prereg_path = Path(__file__).resolve().parent.parent / "testdata/stealth/preregistration.json"
    prereg = read_json(prereg_path.resolve(strict=True))
    try:
        campaign["validate_preregistration"](prereg)
    except Exception as error:
        fail(f"checked-in preregistration is invalid: {error}")
    cells = [
        (item["scenario"], item["workload"], item["wire_profile"])
        for item in prereg["required_common_cells"]
    ]

    plan_path = campaign_dir / "plan.json"
    capture_state_path = campaign_dir / "state.json"
    campaign_path = campaign_dir / "campaign.json"
    manifest_path = campaign_dir / "capture-manifest.csv"
    ledger_path = campaign_dir / "events.jsonl"
    plan = read_json(plan_path.resolve(strict=True))
    if set(plan) != {"schema_version", "created_at", "identity", "safety"} or plan.get("schema_version") != 1:
        fail("calibration plan has an unsupported schema")
    parse_iso_time(plan.get("created_at"), "calibration plan creation time")
    identity = plan.get("identity")
    identity_fields = {
        "schema_version", "campaign_id", "mode", "groups",
        "samples_per_product_cell_group", "schedule_seed", "cells",
        "include_cover_h2", "required_sample_count", "auxiliary_sample_count",
        "total_sample_count", "schedule_sha256", "configuration_sha256",
        "preregistration_sha256", "source", "docker",
    }
    if not isinstance(identity, dict) or set(identity) != identity_fields:
        fail("calibration plan identity has an unsupported schema")
    expected_cells = [list(item) for item in cells]
    if (
        identity.get("schema_version") != 1
        or identity.get("campaign_id") != metadata["campaign_id"]
        or identity.get("mode") != "calibration"
        or identity.get("groups") != 1
        or identity.get("samples_per_product_cell_group") != 1
        or identity.get("schedule_seed") != 20260904
        or identity.get("cells") != expected_cells
        or identity.get("include_cover_h2") is not True
        or identity.get("required_sample_count") != 63
        or identity.get("auxiliary_sample_count") != 2
        or identity.get("total_sample_count") != 65
        or identity.get("configuration_sha256") != config_digest
        or identity.get("preregistration_sha256") != sha256(prereg_path)
    ):
        fail("calibration plan does not exactly cover the frozen 21 cells and H2 controls")
    expected_safety = {
        "local_docker_context": True,
        "internal_bridge_only": True,
        "host_interface_capture": False,
        "host_qdisc_modified": False,
        "fresh_network_namespace_per_sample": True,
        "exact_endpoint_bpf": True,
        "shell_command_strings": False,
        "workload_writable_bind_mounts": False,
        "capture_output_bind_mount_only": True,
    }
    if plan.get("safety") != expected_safety:
        fail("calibration plan safety contract changed")
    validate_plan_source(identity["source"], raw_config, prereg_path)
    runtime = validate_plan_runtime(identity["docker"], validated_config, metadata)
    try:
        samples = campaign["build_schedule"](
            prereg, validated_config["products"], cells, 1, 1,
            identity["schedule_seed"], True,
        )
        schedule_digest = campaign["schedule_digest"](samples)
    except Exception as error:
        fail(f"cannot replay frozen calibration schedule: {error}")
    if identity.get("schedule_sha256") != schedule_digest or len(samples) != 65:
        fail("calibration plan schedule cannot be replayed exactly")

    capture_state = read_json(capture_state_path.resolve(strict=True))
    if set(capture_state) != {
        "schema_version", "status", "capture_started_at", "capture_completed_at",
        "completed_samples", "total_samples", "last_error",
    } or (
        capture_state.get("schema_version") != 1
        or capture_state.get("status") != "complete"
        or capture_state.get("completed_samples") != 65
        or capture_state.get("total_samples") != 65
        or capture_state.get("last_error") is not None
    ):
        fail("calibration capture state is not exactly complete")
    started = parse_iso_time(capture_state.get("capture_started_at"), "calibration capture start")
    completed = parse_iso_time(capture_state.get("capture_completed_at"), "calibration capture completion")
    if completed < started:
        fail("calibration completion precedes capture start")

    rows = read_manifest(manifest_path)
    completions, pcap_hashes, pcap_set_digest, browser_variants = replay_ledger(
        ledger_path, campaign_dir, rows, samples, validated_config, runtime, campaign
    )
    if len(completions) != 65 or len(pcap_hashes) != 65:
        fail("calibration does not contain 65 unique ledger-bound PCAPs")
    expected_browser_variants = {
        variant.name for variant in validated_config["products"]["cover"]
    }
    if (
        browser_variants["h2"] != expected_browser_variants
        or browser_variants["h3"] != expected_browser_variants
    ):
        fail("calibration lacks ledger-bound H2/H3 evidence for both browsers")

    campaign_document = read_json(campaign_path.resolve(strict=True))
    validate_calibration_campaign(
        campaign_document, metadata, identity, manifest_path, validated_config
    )
    readiness_hashes = validate_browser_readiness(
        lab_dir, validated_config, campaign
    )
    token = token_path.read_bytes().strip()
    if not token:
        fail("token is empty")
    for retained in (metadata_path, config_path, plan_path, campaign_path, ledger_path):
        if token in retained.read_bytes():
            fail(f"authentication secret leaked into {retained.name}")
    return {
        "schema_version": 1,
        "status": "calibrated",
        "claim_status": "insufficient_evidence",
        "full_capture_started": False,
        "campaign_id": metadata["campaign_id"],
        "metadata_sha256": sha256(metadata_path),
        "config_sha256": config_digest,
        "calibration_plan_sha256": sha256(plan_path),
        "calibration_capture_state_sha256": sha256(capture_state_path),
        "calibration_campaign_sha256": sha256(campaign_path),
        "calibration_manifest_sha256": sha256(manifest_path),
        "calibration_ledger_sha256": sha256(ledger_path),
        "calibration_pcap_set_sha256": pcap_set_digest,
        "browser_readiness_sha256": readiness_hashes,
        "calibration_pcaps": 65,
        "required_pcaps": 63,
        "auxiliary_h2_pcaps": 2,
        "unique_pcap_sha256": 65,
    }


def campaign_api() -> Dict[str, Any]:
    return runpy.run_path(str(Path(__file__).with_name("stealth-campaign.py")))


def validate_config_metadata_binding(
    raw: Mapping[str, Any], config: Mapping[str, Any],
    metadata: Mapping[str, Any], inputs: Path,
) -> None:
    lab = raw.get("lab")
    if not isinstance(lab, dict) or (
        raw.get("campaign_id") != metadata["campaign_id"]
        or lab.get("docker_network") != metadata["network"]
        or lab.get("ownership_label") != metadata["ownership_label"]
        or lab.get("capture_image") != metadata["capture_image"]
        or lab.get("capture_host") != metadata["capture_host"]
        or lab.get("allowed_mount_roots") != [str(inputs)]
    ):
        fail("campaign configuration is not bound to lab metadata")
    expected_endpoints: Dict[str, str] = {}
    expected_containers: Dict[str, str] = {}
    for product in PRODUCTS:
        for variant in config["products"][product]:
            endpoint_key = (
                "caddy" if variant.name == "chromium-caddy" else
                "nginx" if variant.name == "firefox-esr-nginx" else product
            )
            if endpoint_key == "hysteria2":
                endpoint_key = "hysteria"
            expected_endpoints[endpoint_key] = variant.server_ip
            expected_containers[endpoint_key] = variant.server_container
            if product == "autocar" and variant.runner_image != metadata["runner_image"]:
                fail("AutoCAR runner image differs from metadata")
            if product == "hysteria2" and variant.runner_image != metadata["runner_image"]:
                fail("Hysteria runner image differs from metadata")
            if variant.name == "chromium-caddy" and variant.runner_image != metadata["chromium_image"]:
                fail("Chromium runner image differs from metadata")
            if variant.name == "firefox-esr-nginx" and variant.runner_image != metadata["firefox_image"]:
                fail("Firefox runner image differs from metadata")
    if expected_endpoints != {
        key: metadata["endpoints"][key]
        for key in ("caddy", "nginx", "autocar", "hysteria")
    }:
        fail("configured server endpoints differ from metadata")
    if expected_containers != {
        key: metadata[f"{key}_container"]
        for key in ("caddy", "nginx", "autocar", "hysteria")
    }:
        fail("configured server containers differ from metadata")


def validate_plan_source(
    source: Any, raw_config: Mapping[str, Any], prereg_path: Path,
) -> None:
    if not isinstance(source, dict) or set(source) != {
        "git_head", "git_tree", "git_dirty", "preregistration",
        "preregistration_recorded_at", "files",
    }:
        fail("calibration source snapshot has an unsupported schema")
    for field in ("git_head", "git_tree"):
        if not isinstance(source.get(field), str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", source[field]):
            fail(f"calibration source {field} is malformed")
    if source.get("git_dirty") is not False:
        fail("calibration source snapshot was not clean")
    repo = Path(__file__).resolve().parent.parent
    if (
        source.get("git_head") != git_scalar(repo, "rev-parse", "--verify", "HEAD")
        or source.get("git_tree") != git_scalar(repo, "rev-parse", "HEAD^{tree}")
    ):
        fail("current Git revision differs from calibrated source")
    expected_prereg = file_snapshot(prereg_path)
    if source.get("preregistration") != expected_prereg:
        fail("calibration preregistration snapshot changed")
    provenance = raw_config.get("provenance")
    if not isinstance(provenance, dict) or (
        source.get("preregistration_recorded_at")
        != provenance.get("preregistration_recorded_at")
    ):
        fail("calibration preregistration time is not bound to configuration")
    files = source.get("files")
    expected_names = {
        "autocar_binary", "autocar_config", "hysteria2_binary", "hysteria2_config"
    }
    if not isinstance(files, dict) or set(files) != expected_names:
        fail("calibration provenance file set changed")
    for name in expected_names:
        configured = Path(require_text(provenance.get(name), name)).resolve(strict=True)
        if files[name] != file_snapshot(configured):
            fail(f"calibration provenance file changed: {name}")


def validate_plan_runtime(
    runtime: Any, config: Mapping[str, Any], metadata: Mapping[str, Any],
) -> Dict[str, Any]:
    fields = {
        "context", "endpoint_scheme", "engine_fingerprint", "network_id",
        "network_name", "network_subnets", "capture_host", "capture_image",
        "helper_versions", "runner_images", "servers",
    }
    if not isinstance(runtime, dict) or set(runtime) != fields:
        fail("calibration Docker runtime snapshot has an unsupported schema")
    if (
        runtime.get("endpoint_scheme") != "unix"
        or runtime.get("network_name") != metadata["network"]
        or runtime.get("capture_host") != metadata["capture_host"]
        or not SHA_RE.fullmatch(str(runtime.get("engine_fingerprint", "")))
        or not re.fullmatch(r"[0-9a-f]{64}", str(runtime.get("network_id", "")))
    ):
        fail("calibration Docker runtime binding changed")
    capture_image = runtime.get("capture_image")
    if not isinstance(capture_image, dict) or capture_image.get("id") != metadata["capture_image"]:
        fail("calibration capture image binding changed")
    subnets = runtime.get("network_subnets")
    if subnets != [metadata["subnet"]]:
        fail("calibration Docker subnet binding changed")
    runner_images = runtime.get("runner_images")
    servers = runtime.get("servers")
    if not isinstance(runner_images, dict) or not isinstance(servers, dict):
        fail("calibration Docker runtime lacks image/server provenance")
    expected_runner_keys = set()
    expected_server_names = set()
    for product in PRODUCTS:
        for variant in config["products"][product]:
            key = f"{product}/{variant.name}"
            expected_runner_keys.add(key)
            image = runner_images.get(key)
            if not isinstance(image, dict) or image.get("id") != variant.runner_image:
                fail(f"calibration runner image changed for {key}")
            expected_server_names.add(variant.server_container)
            server = servers.get(variant.server_container)
            if (
                not isinstance(server, dict)
                or server.get("ip") != variant.server_ip
                or not re.fullmatch(r"[0-9a-f]{64}", str(server.get("id", "")))
                or not IMAGE_ID_RE.fullmatch(str(server.get("image_id", "")))
            ):
                fail(f"calibration server binding changed for {variant.name}")
    if set(runner_images) != expected_runner_keys or set(servers) != expected_server_names:
        fail("calibration Docker runtime contains unexpected images or servers")
    return runtime


def read_manifest(path: Path) -> list[Dict[str, str]]:
    try:
        with path.resolve(strict=True).open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if tuple(reader.fieldnames or ()) != MANIFEST_FIELDS:
                fail("calibration manifest header changed")
            rows = list(reader)
    except (OSError, UnicodeError, csv.Error) as error:
        raise SystemExit("cannot parse calibration capture manifest") from error
    if len(rows) != 65:
        fail("calibration manifest must contain exactly 65 rows")
    for row in rows:
        if set(row) != set(MANIFEST_FIELDS) or any(
            not isinstance(value, str) or not value
            or any(character in value for character in "\x00\r\n")
            for value in row.values()
        ):
            fail("calibration manifest contains an unsafe or incomplete row")
    return rows


def replay_ledger(
    ledger_path: Path, campaign_dir: Path, rows: Sequence[Mapping[str, str]],
    samples: Sequence[Any], config: Mapping[str, Any], runtime: Mapping[str, Any],
    campaign: Mapping[str, Any],
) -> tuple[Dict[str, Mapping[str, Any]], set[str], str, Dict[str, set[str]]]:
    try:
        contents = ledger_path.resolve(strict=True).read_bytes()
    except OSError as error:
        raise SystemExit("cannot read calibration event ledger") from error
    if not contents or not contents.endswith(b"\n"):
        fail("calibration event ledger is not newline-committed")
    try:
        lines = contents.decode("utf-8").splitlines()
        events = [json.loads(line) for line in lines]
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SystemExit("calibration event ledger is malformed") from error
    if len(rows) != len(samples):
        fail("calibration manifest and replayed plan sizes differ")
    row_by_id = {row["sample_id"]: row for row in rows}
    if len(row_by_id) != 65 or list(row_by_id) != [sample.sample_id for sample in samples]:
        fail("calibration manifest is not bound to the replayed plan order")
    completions: Dict[str, Mapping[str, Any]] = {}
    pcap_hashes: set[str] = set()
    pcap_commitments = hashlib.sha256()
    browser_variants: Dict[str, set[str]] = {"h2": set(), "h3": set()}
    subnets = [ipaddress.ip_network(value) for value in runtime["network_subnets"]]
    known_samples = {sample.sample_id for sample in samples}
    event_cursor = 0
    for sample in samples:
        variant = config["products"][sample.product][sample.variant_index]
        attempt_open = False
        while True:
            if event_cursor >= len(events):
                fail(f"calibration ledger ends before completion of {sample.sample_id}")
            event = events[event_cursor]
            event_cursor += 1
            if not isinstance(event, dict):
                fail("calibration ledger event must be an object")
            sample_id = event.get("sample_id")
            if sample_id not in known_samples:
                fail(f"calibration ledger references unknown sample {sample_id!r}")
            if sample_id != sample.sample_id:
                fail(
                    f"calibration ledger sample is duplicated or out of plan order: "
                    f"expected {sample.sample_id}, found {sample_id}"
                )
            event_kind = event.get("event")
            if event_kind == "sample_started":
                if set(event) != {"event", "at", "sample_id", "variant"} or (
                    event.get("variant") != variant.name
                ):
                    fail(f"calibration start schema changed for {sample.sample_id}")
                parse_iso_time(event.get("at"), "sample start")
                if attempt_open:
                    fail(
                        f"calibration contains more than one attempt for "
                        f"{sample.sample_id}"
                    )
                attempt_open = True
                continue
            if event_kind == "sample_failed":
                if not attempt_open:
                    fail(f"calibration failure has no preceding start for {sample.sample_id}")
                if set(event) != {"event", "at", "sample_id", "reason"}:
                    fail(f"calibration failure schema changed for {sample.sample_id}")
                parse_iso_time(event.get("at"), "sample failure")
                require_text(event.get("reason"), "sample failure reason")
                fail(
                    f"calibration contains a failed attempt for {sample.sample_id}; "
                    "retry-selected evidence is not admissible"
                )
            if event_kind != "sample_complete":
                fail(f"unsupported calibration ledger event {event_kind!r}")
            if not attempt_open:
                fail(f"calibration completion has no preceding start for {sample.sample_id}")
            complete_event = event
            break
        expected_complete_fields = {
            "event", "at", "sample_id", "variant", "packets", "pcap_sha256",
            "pcap_bytes", "manifest_row",
        }
        if variant.real_browser:
            expected_complete_fields.add("workload_receipt")
        if not isinstance(complete_event, dict) or set(complete_event) != expected_complete_fields:
            fail(f"calibration completion schema changed for {sample.sample_id}")
        if (
            complete_event.get("event") != "sample_complete"
            or complete_event.get("sample_id") != sample.sample_id
            or complete_event.get("variant") != variant.name
        ):
            fail(f"calibration completion does not match plan sample {sample.sample_id}")
        parse_iso_time(complete_event.get("at"), "sample completion")
        row = row_by_id[sample.sample_id]
        expected_sample = {
            "sample_id": sample.sample_id,
            "product": sample.product,
            "scenario": sample.scenario,
            "workload": sample.workload,
            "wire_profile": sample.wire_profile,
            "run_id": sample.run_id,
            "seed": sample.seed,
            "pcap": f"pcaps/{sample.sample_id}.pcap",
        }
        if any(row.get(field) != value for field, value in expected_sample.items()):
            fail(f"calibration manifest row changed for {sample.sample_id}")
        expected_runner = runtime["runner_images"][f"{sample.product}/{variant.name}"]["id"]
        expected_server = runtime["servers"][variant.server_container]
        expected_provenance = {
            "client_implementation": variant.client_implementation,
            "server_implementation": variant.server_implementation,
            "implementation_version": variant.implementation_version,
            "runner_image_id": expected_runner,
            "server_container_id": expected_server["id"],
            "capture_host": runtime["capture_host"],
            "docker_engine_fingerprint": runtime["engine_fingerprint"],
            "server_ip": variant.server_ip,
        }
        if any(row.get(field) != value for field, value in expected_provenance.items()):
            fail(f"calibration provenance changed for {sample.sample_id}")
        client_ip = private_ip(row["client_ip"])
        if not any(client_ip in subnet for subnet in subnets):
            fail(f"calibration client IP escaped the lab subnet for {sample.sample_id}")
        if complete_event.get("manifest_row") != dict(row):
            fail(f"calibration ledger row differs from manifest for {sample.sample_id}")
        pcap = (campaign_dir / row["pcap"]).resolve(strict=True)
        under(campaign_dir, pcap, "calibration PCAP")
        if pcap.is_symlink() or not pcap.is_file():
            fail(f"calibration PCAP is not a regular file for {sample.sample_id}")
        digest = sha256(pcap)
        packet_count = pcap_packet_count(pcap)
        if (
            complete_event.get("pcap_sha256") != digest
            or complete_event.get("pcap_bytes") != pcap.stat().st_size
            or complete_event.get("packets") != packet_count
            or packet_count < 5
        ):
            fail(f"calibration PCAP is not bound to ledger for {sample.sample_id}")
        if digest in pcap_hashes:
            fail("calibration contains duplicate PCAP bytes")
        pcap_hashes.add(digest)
        pcap_commitments.update(f"{sample.sample_id},{digest}\n".encode("ascii"))
        if variant.real_browser:
            try:
                campaign["validate_browser_receipt"](
                    complete_event["workload_receipt"], sample, variant
                )
            except Exception as error:
                fail(
                    f"browser receipt failed replay for {sample.sample_id}: {error}; "
                    f"expected_protocol={sample.wire_profile!r} "
                    f"recorded={complete_event['workload_receipt'].get('next_hop_protocols')!r}"
                )
            browser_variants[sample.wire_profile].add(variant.name)
        completions[sample.sample_id] = complete_event
    if event_cursor != len(events):
        event = events[event_cursor]
        sample_id = event.get("sample_id") if isinstance(event, dict) else None
        if sample_id not in known_samples:
            fail(f"calibration ledger references unknown sample {sample_id!r}")
        fail("calibration ledger contains duplicate or out-of-order events after completion")
    return completions, pcap_hashes, pcap_commitments.hexdigest(), browser_variants


def validate_calibration_campaign(
    value: Mapping[str, Any], metadata: Mapping[str, Any], identity: Mapping[str, Any],
    manifest_path: Path, config: Mapping[str, Any],
) -> None:
    expected_fields = {
        "schema_version", "status", "campaign_id", "claim_scope",
        "autocar_commit", "preregistration_git_commit", "preregistration_sha256",
        "preregistration_recorded_before_capture", "preregistration_recorded_at",
        "capture_manifest_sha256", "products", "driver", "capture_started_at",
        "capture_completed_at",
    }
    if set(value) != expected_fields or (
        value.get("schema_version") != 1
        or value.get("status") != "insufficient_evidence"
        or value.get("campaign_id") != metadata["campaign_id"]
        or value.get("claim_scope") != "hysteria2-v2.12.2-standard"
        or value.get("capture_manifest_sha256") != sha256(manifest_path)
        or value.get("preregistration_recorded_before_capture") is not True
    ):
        fail("calibration campaign summary is not fail-closed insufficient_evidence")
    if value.get("autocar_commit") != identity["source"]["git_head"] or (
        value.get("preregistration_git_commit") != identity["source"]["git_head"]
    ):
        fail("calibration campaign Git provenance changed")
    driver = value.get("driver")
    if not isinstance(driver, dict) or (
        driver.get("mode") != "calibration"
        or driver.get("configuration_sha256") != identity["configuration_sha256"]
        or driver.get("schedule_sha256") != identity["schedule_sha256"]
        or driver.get("required_samples") != 63
        or driver.get("auxiliary_samples") != 2
        or driver.get("completed_samples") != 65
        or driver.get("host_interface_capture") is not False
        or driver.get("host_qdisc_modified") is not False
        or driver.get("fresh_network_namespace_per_sample") is not True
    ):
        fail("calibration campaign driver summary changed")
    cover = value.get("products", {}).get("cover", {}) if isinstance(value.get("products"), dict) else {}
    expected_clients = sorted(
        variant.client_implementation for variant in config["products"]["cover"]
    )
    expected_servers = sorted(
        variant.server_implementation for variant in config["products"]["cover"]
    )
    if (
        cover.get("client_implementations") != expected_clients
        or cover.get("server_implementations") != expected_servers
        or cover.get("real_browser_h2_h3_present") is not False
    ):
        fail("calibration cover summary changed")
    parse_iso_time(value.get("capture_started_at"), "campaign capture start")
    parse_iso_time(value.get("capture_completed_at"), "campaign capture completion")


def validate_browser_readiness(
    lab_dir: Path, config: Mapping[str, Any], campaign: Mapping[str, Any],
) -> Dict[str, str]:
    result: Dict[str, str] = {}
    Sample = campaign["Sample"]
    for variant_index, variant in enumerate(config["products"]["cover"]):
        try:
            browser_index = variant.command.index("--browser") + 1
            browser = variant.command[browser_index]
        except (ValueError, IndexError) as error:
            raise SystemExit("browser variant lacks a fixed browser identity") from error
        if browser not in {"chromium", "firefox-esr"}:
            fail("readiness evidence uses an unsupported browser family")
        for protocol, workload in (("h3", "download_128k"), ("h2", "browser_h2")):
            path = lab_dir / "logs" / f"browser-{browser}-{protocol}-readiness.json"
            receipt = read_json(path.resolve(strict=True))
            sample = Sample(
                f"readiness-{browser}-{protocol}", "cover", "readiness", workload,
                protocol, "readiness", "readiness", 20260904, variant_index,
                protocol == "h2",
            )
            try:
                campaign["validate_browser_receipt"](receipt, sample, variant)
            except Exception as error:
                fail(f"browser {browser} {protocol} readiness receipt failed replay: {error}")
            result[f"{browser}-{protocol}"] = sha256(path)
    return dict(sorted(result.items()))


def pcap_packet_count(path: Path) -> int:
    data = path.read_bytes()
    if len(data) < 24:
        fail(f"calibration PCAP is truncated: {path.name}")
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        byteorder = "little"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        byteorder = "big"
    else:
        fail(f"calibration capture is not classic PCAP: {path.name}")
    offset = 24
    packets = 0
    while offset < len(data):
        if len(data) - offset < 16:
            fail(f"calibration PCAP has a truncated packet header: {path.name}")
        included = int.from_bytes(data[offset + 8:offset + 12], byteorder)
        original = int.from_bytes(data[offset + 12:offset + 16], byteorder)
        if included <= 0 or original < included or included > len(data) - offset - 16:
            fail(f"calibration PCAP has an invalid packet record: {path.name}")
        offset += 16 + included
        packets += 1
    if offset != len(data):
        fail(f"calibration PCAP has trailing bytes: {path.name}")
    return packets


def file_snapshot(path: Path) -> Dict[str, Any]:
    if not path.is_file() or path.stat().st_size <= 0:
        fail(f"evidence file is empty or missing: {path.name}")
    return {"name": path.name, "sha256": sha256(path), "bytes": path.stat().st_size}


def parse_iso_time(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str) or not value:
        fail(f"{label} must be an ISO-8601 timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise SystemExit(f"{label} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        fail(f"{label} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def git_scalar(repo: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *arguments], text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    value = completed.stdout.strip()
    if completed.returncode != 0 or not value or "\n" in value or "\r" in value:
        fail("cannot read current Git provenance")
    return value


def read_status(lab_dir: Path) -> Dict[str, Any]:
    lab_dir = lab_dir.resolve(strict=True)
    metadata_path = lab_dir / "lab-metadata.json"
    state_path = lab_dir / "lab-state.json"
    if not metadata_path.is_file():
        journal = read_ownership_journal(lab_dir / "ownership-journal.json")
        return {
            "schema_version": 1,
            "lab_dir": str(lab_dir),
            "campaign_id": journal["campaign_id"],
            "configured": False,
            "calibrated": False,
            "status": "preparing_or_interrupted",
            "ownership_journal": journal,
            "full": None,
        }
    metadata = read_metadata(metadata_path)
    if Path(metadata["lab_dir"]).resolve(strict=True) != lab_dir:
        fail("metadata lab directory does not match the requested lab")
    result: Dict[str, Any] = {
        "schema_version": 1,
        "lab_dir": str(lab_dir),
        "campaign_id": metadata["campaign_id"],
        "configured": True,
        "config_sha256_matches": sha256(Path(metadata["campaign_config"])) == metadata["config_sha256"],
        "calibrated": False,
        "capture_host": metadata["capture_host"],
    }
    if state_path.is_file():
        state = read_json(state_path)
        result["calibrated"] = state.get("status") == "calibrated"
        result["calibration"] = state
    full_output = Path(metadata["full_output_dir"])
    if full_output.is_dir():
        full_state = full_output / "state.json"
        full_campaign = full_output / "campaign.json"
        result["full"] = {
            "output": str(full_output),
            "state": read_json(full_state) if full_state.is_file() else None,
            "campaign": read_json(full_campaign) if full_campaign.is_file() else None,
        }
    else:
        result["full"] = None
    return result


def read_metadata(path: Path) -> Dict[str, Any]:
    value = read_json(path.resolve(strict=True))
    required = {
        "schema_version", "status", "campaign_id", "ownership_label", "network",
        "capture_host", "subnet", "lab_dir", "inputs_root", "campaign_config", "calibration_dir",
        "full_output_dir",
        "origin_container", "caddy_container", "nginx_container", "autocar_container",
        "hysteria_container", "capture_image", "runner_image", "chromium_image",
        "firefox_image", "caddy_image", "nginx_image", "endpoints",
        "browser_binary_sha256", "chromium_certificate_spki_sha256", "config_sha256",
    }
    if set(value) != required or value.get("schema_version") != 1 or value.get("status") != "configured":
        fail("lab metadata has an unsupported schema")
    require_name(value.get("campaign_id"), "metadata campaign ID")
    if value.get("ownership_label") != f"{LABEL_KEY}={value['campaign_id']}":
        fail("metadata ownership label is inconsistent")
    require_name(value.get("network"), "metadata network")
    require_capture_host(value.get("capture_host"))
    for field in (
        "origin_container", "caddy_container", "nginx_container",
        "autocar_container", "hysteria_container",
    ):
        require_name(value.get(field), f"metadata {field}")
    for field in ("capture_image", "runner_image", "chromium_image", "firefox_image"):
        immutable_image_id(value.get(field))
    require_digest_ref(value.get("caddy_image"), "metadata Caddy image")
    require_digest_ref(value.get("nginx_image"), "metadata nginx image")
    endpoints = value.get("endpoints")
    if not isinstance(endpoints, dict) or set(endpoints) != {
        "origin", "caddy", "nginx", "autocar", "hysteria"
    }:
        fail("metadata endpoints have an unsupported schema")
    addresses = {name: private_ip(endpoint) for name, endpoint in endpoints.items()}
    if len(set(addresses.values())) != len(addresses):
        fail("metadata endpoints are not distinct")
    expected_subnet = str(ipaddress.ip_network(f"{addresses['origin']}/24", strict=False))
    if value.get("subnet") != expected_subnet or any(
        address not in ipaddress.ip_network(expected_subnet) for address in addresses.values()
    ):
        fail("metadata subnet and endpoint bindings differ")
    browser_hashes = value.get("browser_binary_sha256")
    if not isinstance(browser_hashes, dict) or set(browser_hashes) != {"chromium", "firefox-esr"} or any(
        not isinstance(digest, str) or not SHA_RE.fullmatch(digest)
        for digest in browser_hashes.values()
    ):
        fail("metadata browser binary checksums are malformed")
    if not SHA_RE.fullmatch(str(value.get("config_sha256", ""))):
        fail("metadata configuration checksum is malformed")
    require_spki_sha256(
        value.get("chromium_certificate_spki_sha256"),
        "metadata Chromium certificate SPKI SHA-256",
    )
    lab_dir = Path(value["lab_dir"]).resolve(strict=True)
    for field in ("inputs_root", "campaign_config", "calibration_dir", "full_output_dir"):
        under(lab_dir, Path(value[field]).resolve(strict=False), f"metadata {field}")
    return value


def verify_numeric_sans(cert: Path, *addresses: ipaddress.IPv4Address) -> None:
    try:
        decoded = ssl._ssl._test_decode_cert(str(cert))  # type: ignore[attr-defined]
    except (OSError, ssl.SSLError, ValueError) as error:
        raise SystemExit("cannot decode cover certificate") from error
    sans = {
        value for kind, value in decoded.get("subjectAltName", ()) if kind == "IP Address"
    }
    missing = {str(address) for address in addresses}.difference(sans)
    if missing:
        fail("cover certificate lacks numeric IP SANs: " + ", ".join(sorted(missing)))


def checked_file(root: Path, path: Path, label: str) -> Path:
    under(root, path, label)
    if not path.is_file() or path.stat().st_size <= 0:
        fail(f"{label} must be a non-empty regular file")
    return path


def output_under(root: Path, value: str, label: str) -> Path:
    path = Path(value).resolve(strict=False)
    under(root, path, label)
    if path.exists():
        fail(f"refusing to overwrite existing {label}")
    return path


def under(root: Path, path: Path, label: str) -> Path:
    try:
        path.relative_to(root)
    except ValueError as error:
        raise SystemExit(f"{label} is outside {root}") from error
    return path


def private_ip(value: str) -> ipaddress.IPv4Address:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise SystemExit(f"invalid RFC1918 IP {value!r}") from error
    if not isinstance(address, ipaddress.IPv4Address) or not any(address in block for block in RFC1918):
        fail(f"IP is outside RFC1918: {value}")
    return address


def immutable_image_id(value: Any) -> str:
    if not isinstance(value, str) or not IMAGE_ID_RE.fullmatch(value):
        fail("runner and capture images must be immutable sha256 IDs")
    return value


def require_digest_ref(value: str, label: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./_-]*@sha256:[0-9a-f]{64}", value):
        fail(f"{label} must be an immutable repository digest")
    return value


def require_name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not NAME_RE.fullmatch(value):
        fail(f"{label} contains unsupported characters")
    return value


def require_text(value: Any, label: str) -> str:
    if (
        not isinstance(value, str) or not value or value != value.strip()
        or "\n" in value or "\r" in value or "\x00" in value
    ):
        fail(f"{label} must be a non-empty single-line value")
    return value


def require_capture_host(value: Any) -> str:
    if not isinstance(value, str) or not CAPTURE_HOST_RE.fullmatch(value):
        fail("capture host must be a safe single-line host identifier")
    return value


def require_spki_sha256(value: Any, label: str) -> str:
    message = f"{label} must be canonical Base64 for exactly 32 bytes"
    if not isinstance(value, str) or len(value) != 44 or not value.endswith("="):
        fail(message)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise SystemExit(message) from error
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        fail(message)
    return value


def require_safe_output_text(value: str) -> str:
    return require_text(value, "version output")


def utc_timestamp(value: str, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value
    ):
        fail(f"{label} must be an exact whole-second UTC timestamp")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError as error:
        raise SystemExit(f"{label} is not a valid UTC timestamp") from error
    if parsed > dt.datetime.now(dt.timezone.utc):
        fail(f"{label} cannot be in the future")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compact_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def assert_no_markers(value: Mapping[str, Any]) -> None:
    text = json.dumps(value, sort_keys=True).lower()
    for marker in FORBIDDEN_MARKERS:
        if marker in text:
            fail(f"generated data contains forbidden marker {marker!r}")


def write_text(path: Path, value: str) -> None:
    write_bytes(path, value.encode("utf-8"), 0o600)


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    write_bytes(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"), 0o600)


def write_bytes(path: Path, value: bytes, mode: int) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        if path.exists():
            fail(f"refusing to overwrite {path}")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_json(path: Path) -> Dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"cannot parse {path}") from error
    if not isinstance(value, dict):
        fail(f"{path.name} must be a JSON object")
    return value


def build_self_test_calibration(
    root: Path, inputs: Path, raw_config: Mapping[str, Any],
    campaign: Mapping[str, Any],
) -> None:
    prereg_path = Path(__file__).resolve().parent.parent / "testdata/stealth/preregistration.json"
    prereg = read_json(prereg_path)
    validated = campaign["validate_config"](raw_config, inputs)
    cells = [
        (item["scenario"], item["workload"], item["wire_profile"])
        for item in prereg["required_common_cells"]
    ]
    samples = campaign["build_schedule"](
        prereg, validated["products"], cells, 1, 1, 20260904, True
    )
    runner_images = {}
    servers = {}
    for product in PRODUCTS:
        for variant in validated["products"][product]:
            runner_images[f"{product}/{variant.name}"] = {
                "id": variant.runner_image, "repo_digests": []
            }
            if variant.server_container not in servers:
                servers[variant.server_container] = {
                    "id": hashlib.sha256(
                        f"container:{variant.server_container}".encode()
                    ).hexdigest(),
                    "image_id": "sha256:" + hashlib.sha256(
                        f"image:{variant.server_container}".encode()
                    ).hexdigest(),
                    "ip": variant.server_ip,
                }
    runtime = {
        "context": "default",
        "endpoint_scheme": "unix",
        "engine_fingerprint": "9" * 64,
        "network_id": "a" * 64,
        "network_name": raw_config["lab"]["docker_network"],
        "network_subnets": ["10.242.90.0/24"],
        "capture_host": raw_config["lab"]["capture_host"],
        "capture_image": {"id": raw_config["lab"]["capture_image"], "repo_digests": []},
        "helper_versions": {"tcpdump": "test", "tc": "test", "ip": "test", "sleep": "test"},
        "runner_images": runner_images,
        "servers": servers,
    }
    provenance = raw_config["provenance"]
    source = {
        "git_head": git_scalar(Path(__file__).resolve().parent.parent, "rev-parse", "--verify", "HEAD"),
        "git_tree": git_scalar(Path(__file__).resolve().parent.parent, "rev-parse", "HEAD^{tree}"),
        "git_dirty": False,
        "preregistration": file_snapshot(prereg_path),
        "preregistration_recorded_at": provenance["preregistration_recorded_at"],
        "files": {
            name: file_snapshot(Path(provenance[name]))
            for name in (
                "autocar_binary", "autocar_config", "hysteria2_binary",
                "hysteria2_config",
            )
        },
    }
    identity = {
        "schema_version": 1,
        "campaign_id": raw_config["campaign_id"],
        "mode": "calibration",
        "groups": 1,
        "samples_per_product_cell_group": 1,
        "schedule_seed": 20260904,
        "cells": [list(item) for item in cells],
        "include_cover_h2": True,
        "required_sample_count": 63,
        "auxiliary_sample_count": 2,
        "total_sample_count": 65,
        "schedule_sha256": campaign["schedule_digest"](samples),
        "configuration_sha256": sha256(inputs / "campaign.json"),
        "preregistration_sha256": sha256(prereg_path),
        "source": source,
        "docker": runtime,
    }
    calibration = root / "calibration"
    pcaps = calibration / "pcaps"
    pcaps.mkdir(parents=True, mode=0o700)
    plan = {
        "schema_version": 1,
        "created_at": "2026-09-02T00:00:00Z",
        "identity": identity,
        "safety": {
            "local_docker_context": True,
            "internal_bridge_only": True,
            "host_interface_capture": False,
            "host_qdisc_modified": False,
            "fresh_network_namespace_per_sample": True,
            "exact_endpoint_bpf": True,
            "shell_command_strings": False,
            "workload_writable_bind_mounts": False,
            "capture_output_bind_mount_only": True,
        },
    }
    capture_state = {
        "schema_version": 1,
        "status": "complete",
        "capture_started_at": "2026-09-02T00:00:01Z",
        "capture_completed_at": "2026-09-02T00:10:00Z",
        "completed_samples": 65,
        "total_samples": 65,
        "last_error": None,
    }
    write_json(calibration / "plan.json", plan)
    write_json(calibration / "state.json", capture_state)
    rows = []
    completions = {}
    events = []
    for index, sample in enumerate(samples):
        variant = validated["products"][sample.product][sample.variant_index]
        pcap = pcaps / f"{sample.sample_id}.pcap"
        write_bytes(pcap, self_test_pcap(index), 0o600)
        row = {
            "sample_id": sample.sample_id,
            "product": sample.product,
            "scenario": sample.scenario,
            "workload": sample.workload,
            "wire_profile": sample.wire_profile,
            "run_id": sample.run_id,
            "seed": sample.seed,
            "pcap": f"pcaps/{sample.sample_id}.pcap",
            "client_ip": f"10.242.90.{100 + index % 100}",
            "server_ip": variant.server_ip,
            "client_implementation": variant.client_implementation,
            "server_implementation": variant.server_implementation,
            "implementation_version": variant.implementation_version,
            "runner_image_id": runtime["runner_images"][f"{sample.product}/{variant.name}"]["id"],
            "server_container_id": runtime["servers"][variant.server_container]["id"],
            "capture_host": runtime["capture_host"],
            "docker_engine_fingerprint": runtime["engine_fingerprint"],
        }
        complete: Dict[str, Any] = {
            "event": "sample_complete",
            "at": "2026-09-02T00:00:03Z",
            "sample_id": sample.sample_id,
            "variant": variant.name,
            "packets": 5,
            "pcap_sha256": sha256(pcap),
            "pcap_bytes": pcap.stat().st_size,
            "manifest_row": row,
        }
        if variant.real_browser:
            complete["workload_receipt"] = self_test_browser_receipt(
                sample, variant, campaign["BROWSER_WORKLOAD_SPECS"]
            )
        started_event = {
            "event": "sample_started", "at": "2026-09-02T00:00:02Z",
            "sample_id": sample.sample_id, "variant": variant.name,
        }
        events.append(started_event)
        events.append(complete)
        rows.append(row)
        completions[sample.sample_id] = complete
    manifest_path = calibration / "capture-manifest.csv"
    with manifest_path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=MANIFEST_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    os.chmod(manifest_path, 0o600)
    write_bytes(
        calibration / "events.jsonl",
        b"".join(
            (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode()
            for event in events
        ),
        0o600,
    )
    campaign["update_campaign"](
        calibration / "campaign.json", validated, prereg, identity, source,
        capture_state, manifest_path, samples, completions,
    )
    logs = root / "logs"
    logs.mkdir(mode=0o700)
    Sample = campaign["Sample"]
    for variant_index, variant in enumerate(validated["products"]["cover"]):
        browser = variant.command[variant.command.index("--browser") + 1]
        for protocol, workload in (("h3", "download_128k"), ("h2", "browser_h2")):
            sample = Sample(
                f"readiness-{browser}-{protocol}", "cover", "readiness", workload,
                protocol, "readiness", "readiness", 20260904, variant_index,
                protocol == "h2",
            )
            write_json(
                logs / f"browser-{browser}-{protocol}-readiness.json",
                self_test_browser_receipt(
                    sample, variant, campaign["BROWSER_WORKLOAD_SPECS"]
                ),
            )


def self_test_browser_receipt(
    sample: Any, variant: Any, specs: Mapping[str, Mapping[str, int]],
) -> Dict[str, Any]:
    spec = specs[sample.workload]
    protocols = [sample.wire_profile] * spec["requests"]
    result_document = {
        "protocol": sample.wire_profile,
        "workload": sample.workload,
        "sample_seed": sample.sample_seed,
        "request_count": spec["requests"],
        "response_bytes": spec["response_bytes"],
        "upload_bytes": spec["upload_bytes"],
        "resources": [
            {"request_index": index, "next_hop_protocol": protocol}
            for index, protocol in enumerate(protocols)
        ],
    }
    return {
        "schema_version": 1,
        "status": "pass",
        "kind": "real-browser-workload",
        "client_implementation": variant.client_implementation,
        "implementation_version": variant.implementation_version,
        "browser_binary_sha256": variant.browser_binary_sha256,
        "protocol": sample.wire_profile,
        "workload": sample.workload,
        "sample_seed": sample.sample_seed,
        "next_hop_protocols": protocols,
        "request_count": spec["requests"],
        "response_bytes": spec["response_bytes"],
        "result_sha256": hashlib.sha256(json.dumps(
            result_document, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("utf-8")).hexdigest(),
    }


def self_test_pcap(index: int) -> bytes:
    header = (
        b"\xd4\xc3\xb2\xa1" + (2).to_bytes(2, "little")
        + (4).to_bytes(2, "little") + (0).to_bytes(4, "little") * 2
        + (65535).to_bytes(4, "little") + (1).to_bytes(4, "little")
    )
    records = []
    for packet in range(5):
        payload = hashlib.sha256(f"{index}:{packet}".encode()).digest()
        length = len(payload)
        records.append(
            (index + 1).to_bytes(4, "little") + packet.to_bytes(4, "little")
            + length.to_bytes(4, "little") * 2 + payload
        )
    return header + b"".join(records)


def assert_ready_rejects_tamper(root: Path, path: Path, kind: str) -> None:
    original = path.read_bytes()
    if kind == "config":
        tampered = original + b" "
    elif kind == "manifest":
        tampered = original.replace(b"local-linux-docker", b"other-linux-docker", 1)
    else:
        value = json.loads(original)
        if kind == "plan":
            value["identity"]["schedule_seed"] += 1
        elif kind == "state":
            value["claim_status"] = "pass"
        else:
            raise AssertionError("unsupported tamper fixture")
        tampered = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    path.write_bytes(tampered)
    try:
        verify_ready(root)
    except SystemExit:
        pass
    else:
        raise AssertionError(f"verify-ready accepted tampered {kind}")
    finally:
        path.write_bytes(original)
    verify_ready(root)


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="stealth-full-config-test.") as directory:
        root = Path(directory)
        inputs = root / "inputs"
        inputs.mkdir(mode=0o700)
        # ssl._test_decode_cert requires a real certificate. Generate one only
        # when openssl is available; pure config construction is tested below
        # through a temporary monkeypatch to keep the self-test offline.
        for name, body in {
            "server.crt": "test certificate",
            "server.key": "test key",
            "token": "self-test-secret",
            "autocar": "binary-a",
            "hysteria": "binary-h",
            "hysteria-client.yaml": "auth: self-test-secret",
            "hysteria-server.yaml": "password: self-test-secret",
        }.items():
            (inputs / name).write_text(body, encoding="utf-8")
        original = verify_numeric_sans
        globals()["verify_numeric_sans"] = lambda *_: None
        try:
            args = argparse.Namespace(
                command="generate", lab_dir=str(root), inputs_root=str(inputs),
                campaign_output=str(inputs / "campaign.json"),
                metadata_output=str(root / "lab-metadata.json"),
                full_output_dir=str(root / "full-campaign"),
                autocar_effective_output=str(inputs / "autocar-effective.json"),
                hysteria_effective_output=str(inputs / "hysteria-effective.json"),
                caddy_output=str(inputs / "Caddyfile"), nginx_output=str(inputs / "nginx.conf"),
                campaign_id="full-self-test", network="full-self-test",
                capture_image="sha256:" + "1" * 64, runner_image="sha256:" + "2" * 64,
                chromium_image="sha256:" + "3" * 64, firefox_image="sha256:" + "4" * 64,
                capture_host="local-linux-docker", user="65532:65532",
                origin_container="origin", origin_ip="10.242.90.40",
                caddy_container="caddy", caddy_ip="10.242.90.10",
                nginx_container="nginx", nginx_ip="10.242.90.11",
                autocar_container="autocar", autocar_ip="10.242.90.20",
                hysteria_container="hysteria", hysteria_ip="10.242.90.30",
                cert=str(inputs / "server.crt"), key=str(inputs / "server.key"),
                token=str(inputs / "token"), autocar_binary=str(inputs / "autocar"),
                hysteria_binary=str(inputs / "hysteria"),
                hysteria_client_config=str(inputs / "hysteria-client.yaml"),
                hysteria_server_config=str(inputs / "hysteria-server.yaml"),
                autocar_version="autocar v1.0.1-self-test", hysteria_version="v2.12.2-619a6f8",
                hysteria_expected_sha256=sha256(inputs / "hysteria"),
                chromium_client_implementation="Chromium", chromium_version="Chromium 140.0.1",
                chromium_binary_sha256="5" * 64,
                chromium_spki_sha256=base64.b64encode(b"\x07" * 32).decode("ascii"),
                firefox_client_implementation="Firefox", firefox_version="Mozilla Firefox 140.0",
                firefox_binary_sha256="6" * 64,
                caddy_image="caddy@sha256:" + "7" * 64,
                nginx_image="nginx@sha256:" + "8" * 64,
                preregistration_recorded_at="2026-09-01T00:00:00Z",
            )
            write_ownership_journal(argparse.Namespace(
                lab_dir=str(root), campaign_id=args.campaign_id, network=args.network,
                origin_container=args.origin_container, caddy_container=args.caddy_container,
                nginx_container=args.nginx_container, autocar_container=args.autocar_container,
                hysteria_container=args.hysteria_container,
                extractor_container="extractor",
            ))
            generate(args)
        finally:
            globals()["verify_numeric_sans"] = original
        config = read_json(inputs / "campaign.json")
        campaign_module = runpy.run_path(str(Path(__file__).with_name("stealth-campaign.py")))
        campaign_module["validate_config"](config, inputs)
        if set(config["products"]) != set(PRODUCTS):
            fail("self-test product set differs from the formal campaign")
        cover = config["products"]["cover"]["variants"]
        if len(cover) != 2 or any(not item["real_browser"] or not item["h2_command"] for item in cover):
            fail("self-test lacks two real-browser H3/H2 variants")
        if {item["h2_command"][item["h2_command"].index("--workload") + 1] for item in cover} != {"browser_h2"}:
            fail("self-test H2 commands do not preserve browser_h2 metadata")
        lab_timeout = config["lab"]["workload_timeout_seconds"]
        if lab_timeout != 120:
            fail("self-test campaign workload timeout changed")
        for item in cover:
            for command_field in ("command", "h2_command"):
                command = item[command_field]
                if command.count("--webdriver-timeout") != 1:
                    fail(
                        f"self-test {item['name']} {command_field} does not contain "
                        "exactly one explicit WebDriver timeout"
                    )
                timeout_index = command.index("--webdriver-timeout")
                if (
                    timeout_index + 1 >= len(command)
                    or command[timeout_index + 1]
                    != str(COVER_WEBDRIVER_TIMEOUT_SECONDS)
                ):
                    fail(
                        f"self-test {item['name']} {command_field} WebDriver timeout "
                        "is not the frozen 60 seconds"
                    )
                if COVER_WEBDRIVER_TIMEOUT_SECONDS > lab_timeout:
                    fail(
                        f"self-test {item['name']} {command_field} WebDriver timeout "
                        "exceeds the campaign workload timeout"
                    )
                if "--workload-timeout" in command:
                    fail(
                        f"self-test {item['name']} {command_field} overrides the "
                        "browser workload timeout"
                    )
        chromium_variant = next(item for item in cover if item["name"] == "chromium-caddy")
        firefox_variant = next(item for item in cover if item["name"] == "firefox-esr-nginx")
        if chromium_variant["command"].count("--certificate-spki-sha256") != 1:
            fail("self-test Chromium H3 command does not contain exactly one SPKI pin")
        if chromium_variant["h2_command"].count("--certificate-spki-sha256") != 0:
            fail("self-test Chromium H2 command contains an SPKI pin")
        if any(
            "--certificate-spki-sha256" in command
            for command in (firefox_variant["command"], firefox_variant["h2_command"])
        ):
            fail("self-test Firefox commands contain a Chromium SPKI pin")
        retained = b"".join(
            path.read_bytes()
            for path in (
                inputs / "campaign.json", inputs / "autocar-effective.json",
                inputs / "hysteria-effective.json", root / "lab-metadata.json",
            )
        )
        if b"self-test-secret" in retained:
            fail("self-test found an authentication secret in retained metadata")
        metadata = read_metadata(root / "lab-metadata.json")
        if metadata["campaign_id"] != "full-self-test":
            fail("self-test metadata round-trip failed")
        if metadata["chromium_certificate_spki_sha256"] != args.chromium_spki_sha256:
            fail("self-test metadata does not bind the Chromium certificate SPKI pin")
        build_self_test_calibration(root, inputs, config, campaign_module)
        ledger_path = root / "calibration" / "events.jsonl"
        original_ledger = ledger_path.read_bytes()
        clean_events = [json.loads(line) for line in original_ledger.splitlines()]
        failed_event = {
            "event": "sample_failed", "at": clean_events[0]["at"],
            "sample_id": clean_events[0]["sample_id"], "reason": "self-test failure",
        }
        invalid_histories = (
            [clean_events[0], failed_event, *clean_events],
            [clean_events[0], *clean_events],
            clean_events[1:],
            clean_events[:-1],
            [*clean_events[2:4], *clean_events[:2], *clean_events[4:]],
        )
        for history in invalid_histories:
            ledger_path.write_text(
                "".join(json.dumps(event) + "\n" for event in history), encoding="utf-8",
            )
            try:
                audit_calibration(
                    root, root / "calibration", root / "lab-metadata.json",
                    inputs / "campaign.json", inputs / "token",
                )
            except SystemExit:
                pass
            else:
                raise AssertionError("calibration accepted retry-selected or unordered history")
            finally:
                ledger_path.write_bytes(original_ledger)
        expected_state = audit_calibration(
            root, root / "calibration", root / "lab-metadata.json",
            inputs / "campaign.json", inputs / "token",
        )
        write_json(root / "lab-state.json", expected_state)
        if verify_ready(root).get("status") != "ready":
            fail("self-test ready gate did not accept intact calibration evidence")
        assert_ready_rejects_tamper(root, inputs / "campaign.json", "config")
        assert_ready_rejects_tamper(root, root / "calibration" / "plan.json", "plan")
        assert_ready_rejects_tamper(
            root, root / "calibration" / "capture-manifest.csv", "manifest"
        )
        assert_ready_rejects_tamper(root, root / "lab-state.json", "state")
    print(compact_json({"schema_version": 1, "status": "pass", "self_test": True}))


def fail(message: str) -> None:
    raise SystemExit(message)


if __name__ == "__main__":
    raise SystemExit(main())
