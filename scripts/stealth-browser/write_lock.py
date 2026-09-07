#!/usr/bin/env python3
"""Create the immutable executable identity lock used by run_cover.py."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
from typing import Optional, Sequence

import run_cover


def parser() -> run_cover.StrictArgumentParser:
    result = run_cover.StrictArgumentParser(description="write a browser executable identity lock")
    result.add_argument("--browser", required=True, choices=tuple(run_cover.BROWSER_NAMES))
    result.add_argument("--browser-binary", required=True)
    result.add_argument("--webdriver-binary", required=True)
    result.add_argument("--browser-package-version", required=True)
    result.add_argument("--webdriver-package-version", required=True)
    result.add_argument("--implementation-version")
    result.add_argument("--output", required=True)
    return result


def package_version(value: str, label: str) -> str:
    if not run_cover.SAFE_VERSION_RE.fullmatch(value or ""):
        raise run_cover.UsageError("%s is not an exact printable version" % label)
    return value


def create_lock(args: object) -> dict:
    browser = args.browser
    browser_path = run_cover.executable_path(args.browser_binary, browser, "browser")
    webdriver_path = run_cover.executable_path(args.webdriver_binary, browser, "webdriver")
    browser_identity = run_cover.executable_identity(browser_path, ("--version",))
    webdriver_identity = run_cover.executable_identity(webdriver_path, ("--version",))
    implementation_version = args.implementation_version or browser_identity.version
    if implementation_version != browser_identity.version:
        raise run_cover.UsageError(
            "--implementation-version must exactly equal the browser --version output"
        )
    value = {
        "schema_version": run_cover.SCHEMA_VERSION,
        "browser": browser,
        "client_implementation": run_cover.BROWSER_NAMES[browser],
        "implementation_version": implementation_version,
        "browser_binary": browser_identity.path,
        "browser_binary_sha256": browser_identity.sha256,
        "webdriver_binary": webdriver_identity.path,
        "webdriver_version": webdriver_identity.version,
        "webdriver_binary_sha256": webdriver_identity.sha256,
        "browser_package_version": package_version(
            args.browser_package_version, "--browser-package-version"
        ),
        "webdriver_package_version": package_version(
            args.webdriver_package_version, "--webdriver-package-version"
        ),
    }
    if set(value) != run_cover.LOCK_FIELDS:
        raise AssertionError("browser lock fields changed")
    return value


def write_atomic(path: Path, value: dict) -> None:
    if not path.is_absolute() or path == Path("/"):
        raise run_cover.UsageError("--output must be an absolute non-root path")
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(run_cover.compact_json(value) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o444)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        args = parser().parse_args(argv)
        value = create_lock(args)
        write_atomic(Path(args.output), value)
        print(run_cover.compact_json(value))
        return 0
    except (run_cover.RunnerError, OSError) as error:
        print("stealth-browser-lock: %s" % run_cover.diagnostic(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
