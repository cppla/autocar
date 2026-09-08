#!/usr/bin/env python3
"""Exercise exact Linux release binaries on one owned, internal Docker network.

No host ports, host firewall changes, public targets, source builds or capture
corpus. The previous binary must come from the checksum-verified v1.0.0 archive.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time
import uuid


IMAGE = "alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"
LABEL = "com.cppla.autocar.release-smoke"
PREVIOUS_COMMIT = "d12aad63e746c354f1b1a75c7e9bc44c712b60e0"


def command(args, *, timeout=60, check=True):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {args[0]}\n{result.stdout}\n{result.stderr}")
    return result


class Lab:
    def __init__(self, directory, platform):
        self.directory = directory
        self.platform = platform
        self.identity = "autocar-release-" + uuid.uuid4().hex[:16]
        self.network = None
        self.containers = []
        self.checks = []
        self.sequence = 0

    def __enter__(self):
        command(["docker", "image", "inspect", IMAGE], check=False)
        command(["docker", "pull", "--platform", self.platform, IMAGE], timeout=180)
        self.network = self.identity
        try:
            command(["docker", "network", "create", "--internal", "--label",
                     f"{LABEL}={self.identity}", self.network])
        except BaseException:
            self.remove("network", self.network)
            raise
        return self

    def remove(self, kind, reference):
        fmt = "{{ index .Config.Labels \"" + LABEL + "\" }}" if kind == "container" else "{{ index .Labels \"" + LABEL + "\" }}"
        found = command(["docker", kind, "inspect", "--format", fmt, reference], check=False)
        if found.returncode:
            if re.search(r"No such (container|network)|network .+ not found", found.stderr, re.IGNORECASE):
                return
            raise RuntimeError(f"cannot verify owned {kind} {reference}")
        if found.stdout.strip() != self.identity:
            raise RuntimeError(f"refusing cleanup of unowned {kind} {reference}")
        args = ["docker", kind, "rm"] + (["--force"] if kind == "container" else []) + [reference]
        command(args)

    def __exit__(self, exc_type, exc, traceback):
        errors = []
        for name in reversed(self.containers):
            try:
                self.remove("container", name)
            except Exception as error:
                errors.append(str(error))
        if self.network:
            try:
                self.remove("network", self.network)
            except Exception as error:
                errors.append(str(error))
        if errors:
            raise RuntimeError("release smoke cleanup failed: " + "; ".join(errors)) from exc

    def run(self, binary, args, *, alias=None, background=False, writable=False, check=True):
        self.sequence += 1
        name = self.identity + "-" + str(self.sequence)
        options = ["docker", "create", "--name", name, "--label", f"{LABEL}={self.identity}",
                   "--platform", self.platform, "--network", self.network,
                   "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                   "--user", f"{os.getuid()}:{os.getgid()}",
                   "--mount", f"type=bind,src={binary},dst=/autocar,readonly",
                   "--mount", f"type=bind,src={self.directory},dst=/fixture" + ("" if writable else ",readonly")]
        if alias:
            options += ["--network-alias", alias]
        # Pre-register the unique name: create may succeed remotely even if the
        # local CLI times out before returning the container ID.
        reference = name
        self.containers.append(reference)
        command(options + ["--entrypoint", "/autocar", IMAGE] + args)
        command(["docker", "start", reference])
        if background:
            return reference
        waited = command(["docker", "wait", reference], timeout=60)
        logs = command(["docker", "logs", reference])
        logs.returncode = int(waited.stdout.strip())
        if check and logs.returncode:
            raise RuntimeError(f"release binary command failed ({args[0]}): {logs.stdout}\n{logs.stderr}")
        return logs

    def stop(self, reference):
        command(["docker", "stop", "--time", "5", reference])
        self.remove("container", reference)
        self.containers.remove(reference)

    def ready(self, reference, markers):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            logs = command(["docker", "logs", reference])
            text = logs.stdout + logs.stderr
            if all(marker in text for marker in markers):
                return
            running = command(["docker", "inspect", "--format", "{{.State.Running}}", reference]).stdout.strip()
            if running != "true":
                raise RuntimeError("fixture exited before ready: " + text)
            time.sleep(0.1)
        raise RuntimeError("fixture startup deadline exceeded")

    def benchmark(self, binary, stage, mode, *, wrong_token=False):
        for direction in (["download"] if wrong_token else ["download", "upload"]):
            result = self.run(binary, ["bench-client", "--transport=" + mode, "--server=relay:8443",
                             "--server-name=relay", "--ca=/fixture/server.crt",
                             "--token-file=/fixture/" + ("wrong-token" if wrong_token else "token"),
                             "--target=target:9000", "--bytes=65536", "--iterations=3", "--warmup=0",
                             "--timeout=15s", "--mode=" + direction, "--json"], check=not wrong_token)
            if wrong_token:
                rejected = result.stdout + result.stderr
                if result.returncode != 1 or not re.search(r"authentication failed.*status 2|server authentication failed", rejected):
                    raise RuntimeError("wrong token did not produce an authentication rejection: " + result.stderr)
            else:
                output = json.loads(result.stdout)
                selected = "h3" if mode == "web-auto" else mode
                validate_benchmark(output, mode, selected, direction)
            self.checks.append({"stage": stage, "transport": mode, "direction": direction,
                                "authentication": "rejected" if wrong_token else "accepted", "status": "pass"})


def validate_benchmark(output, mode, selected, direction):
    expected = {"mode": direction, "transport": mode, "selected_transport": selected,
                "target": "target:9000", "bytes_per_iteration": 65536, "iterations": 3}
    if any(output.get(key) != value for key, value in expected.items()):
        raise RuntimeError("benchmark result does not match requested path and payload")
    for key in ("results_mbps", "durations_ms"):
        values = output.get(key)
        if not isinstance(values, list) or len(values) != 3 or any(
            type(value) not in (float, int) or not math.isfinite(value) or value <= 0 for value in values
        ):
            raise RuntimeError("benchmark result is missing positive finite measurements")


def validate_checks(checks):
    expected = set()
    for stage in ("baseline", "upgrade", "rollback"):
        for client in ("v1.0.0-client", "new-client"):
            for mode in ("quic", "tls"):
                for direction in ("download", "upload"):
                    expected.add((stage + "/" + client, mode, direction, "accepted", "pass"))
        for mode in ("quic", "tls"):
            expected.add((stage + "/invalid-token", mode, "download", "rejected", "pass"))
    for mode in ("h2", "h3", "web-auto"):
        for direction in ("download", "upload"):
            expected.add(("experimental-web", mode, direction, "accepted", "pass"))
    for mode in ("h2", "h3"):
        expected.add(("experimental-web/invalid-token", mode, "download", "rejected", "pass"))
    actual = [(item["stage"], item["transport"], item["direction"], item["authentication"], item["status"]) for item in checks]
    if len(actual) != len(expected) or set(actual) != expected:
        raise RuntimeError("release smoke matrix is incomplete or duplicated")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current", required=True, type=Path)
    parser.add_argument("--previous", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--build-date", required=True)
    parser.add_argument("--platform", choices=["linux/amd64", "linux/arm64"], default="linux/amd64")
    args = parser.parse_args()
    if not re.fullmatch(r"v\d+\.\d+\.\d+", args.version) or not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        parser.error("expected release version and full commit SHA")
    current, previous = args.current.resolve(strict=True), args.previous.resolve(strict=True)
    for binary in (current, previous):
        if not binary.is_file() or not os.access(binary, os.X_OK):
            parser.error("release binary must be an executable regular file")
    with tempfile.TemporaryDirectory(prefix="autocar-release-smoke-") as temporary:
        directory = Path(temporary)
        for name in ("token", "wrong-token"):
            path = directory / name
            path.write_text(secrets.token_urlsafe(32) + "\n")
            path.chmod(0o600)
        site = directory / "site"
        site.mkdir()
        (site / "index.html").write_text("<!doctype html><title>Release fixture</title>release smoke\n")
        with Lab(directory, args.platform) as lab:
            actual = lab.run(current, ["version"]).stdout.strip()
            expected = f"autocar {args.version} (commit {args.commit}, built {args.build_date}, {args.platform}, "
            if not actual.startswith(expected) or not actual.endswith(")"):
                raise RuntimeError("release metadata mismatch: " + actual)
            old = lab.run(previous, ["version"]).stdout.strip()
            if not old.startswith(f"autocar v1.0.0 (commit {PREVIOUS_COMMIT}, "):
                raise RuntimeError("previous binary is not the verified v1.0.0 release")
            lab.run(current, ["cert", "--hosts=relay", "--cert=/fixture/server.crt", "--key=/fixture/server.key"], writable=True)
            target = lab.run(current, ["bench-server", "--listen=:9000", "--allow-public-benchmark",
                            "--max-bytes=1048576", "--max-connections=4"], alias="target", background=True)
            lab.ready(target, ["benchmark server listening"])
            common = ["server", "--listen=:8443", "--tcp-listen=:8443", "--cert=/fixture/server.crt",
                      "--key=/fixture/server.key", "--token-file=/fixture/token", "--allow-private",
                      "--deny-ports=none", "--max-streams=16", "--max-connections=8", "--max-client-connections=8"]
            for stage, server_binary in (("baseline", previous), ("upgrade", current), ("rollback", previous)):
                relay = lab.run(server_binary, common, alias="relay", background=True)
                lab.ready(relay, ["transport=quic", "transport=tls"])
                for client_name, client_binary in (("v1.0.0-client", previous), ("new-client", current)):
                    for mode in ("quic", "tls"):
                        lab.benchmark(client_binary, stage + "/" + client_name, mode)
                for mode in ("quic", "tls"):
                    lab.benchmark(current, stage + "/invalid-token", mode, wrong_token=True)
                lab.stop(relay)
            relay = lab.run(current, common + ["--protocol=web", "--cover-root=/fixture/site"], alias="relay", background=True)
            lab.ready(relay, ["transport=h3", "transport=h2"])
            for mode in ("h2", "h3", "web-auto"):
                lab.benchmark(current, "experimental-web", mode)
            for mode in ("h2", "h3"):
                lab.benchmark(current, "experimental-web/invalid-token", mode, wrong_token=True)
            lab.stop(relay)
            validate_checks(lab.checks)
            result = {"status": "pass", "version": args.version, "commit": args.commit,
                      "build_date": args.build_date, "platform": args.platform,
                      "current_binary_sha256": hashlib.sha256(current.read_bytes()).hexdigest(),
                      "previous_binary_sha256": hashlib.sha256(previous.read_bytes()).hexdigest(),
                      "checks": lab.checks, "check_count": len(lab.checks),
                      "scope": "native upgrade and rollback, authenticated TCP upload/download, experimental web TCP; no comparative claim"}
        # Print PASS only after all resources have been successfully cleaned up.
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
