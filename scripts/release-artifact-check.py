#!/usr/bin/env python3
"""Validate ordinary release metadata and archives, without comparative claims."""

import argparse
from datetime import datetime
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile


TARGETS = {
    "autocar-linux-amd64.tar.gz": ("linux", "amd64", "autocar"),
    "autocar-linux-arm64.tar.gz": ("linux", "arm64", "autocar"),
    "autocar-darwin-arm64.tar.gz": ("darwin", "arm64", "autocar"),
    "autocar-windows-amd64.zip": ("windows", "amd64", "autocar.exe"),
}
MAX_MEMBER_BYTES = 256 * 1024 * 1024


def validate_metadata(version, commit, build_date):
    number = r"(?:0|[1-9][0-9]*)"
    identifier = r"[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*"
    if len(version) > 128 or not re.fullmatch(
        rf"v{number}\.{number}\.{number}(?:-{identifier})?(?:\+{identifier})?", version
    ):
        raise ValueError("release version must be a v-prefixed semantic version")
    prerelease = version.partition("+")[0].partition("-")[2]
    if any(part.isdigit() and len(part) > 1 and part.startswith("0") for part in prerelease.split(".")):
        raise ValueError("numeric prerelease identifiers must not contain leading zeroes")
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", commit):
        raise ValueError("release commit must be the full lowercase Git object ID")
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", build_date):
        raise ValueError("release build date must be UTC YYYY-MM-DDTHH:MM:SSZ")
    datetime.strptime(build_date, "%Y-%m-%dT%H:%M:%SZ")


def read_archive(path, binary_name):
    expected = {binary_name, "LICENSE", "THIRD_PARTY_NOTICES.md"}
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"archive must be a regular file: {path.name}")
    contents = {}
    if path.name.endswith(".zip"):
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                if member.filename not in expected or member.filename in contents:
                    raise ValueError(f"unexpected or duplicate archive member: {member.filename}")
                mode = member.external_attr >> 16
                if member.is_dir() or stat.S_IFMT(mode) not in (0, stat.S_IFREG) or member.flag_bits & 1:
                    raise ValueError(f"archive member is not an unencrypted regular file: {member.filename}")
                if member.file_size > MAX_MEMBER_BYTES:
                    raise ValueError(f"archive member exceeds size limit: {member.filename}")
                contents[member.filename] = archive.read(member)
    else:
        with tarfile.open(path, "r:gz") as archive:
            for member in archive:
                if member.name not in expected or member.name in contents:
                    raise ValueError(f"unexpected or duplicate archive member: {member.name}")
                if not member.isfile() or member.size > MAX_MEMBER_BYTES:
                    raise ValueError(f"archive member is not a bounded regular file: {member.name}")
                if member.name == binary_name and not member.mode & 0o111:
                    raise ValueError("archive binary must have executable permission")
                contents[member.name] = archive.extractfile(member).read()
    if set(contents) != expected:
        raise ValueError(f"archive members do not match release contract: {path.name}")
    if not contents[binary_name]:
        raise ValueError(f"archive binary is empty: {path.name}")
    return contents


def validate_build_info(output, target_os, target_arch, commit):
    settings = {}
    command_path = None
    module_path = None
    for line in output.splitlines():
        columns = line.strip().split("\t")
        if len(columns) >= 2 and columns[0] == "path":
            command_path = columns[1]
        elif len(columns) >= 2 and columns[0] == "mod":
            module_path = columns[1]
        elif len(columns) == 2 and columns[0] == "build" and "=" in columns[1]:
            key, value = columns[1].split("=", 1)
            if key in settings:
                raise ValueError(f"duplicate binary build setting: {key}")
            settings[key] = value
    if command_path != "github.com/cppla/autocar/cmd/autocar" or module_path != "github.com/cppla/autocar":
        raise ValueError("binary is not the expected AutoCAR main module")
    required = {
        "-buildmode": "exe", "-trimpath": "true", "CGO_ENABLED": "0",
        "GOOS": target_os, "GOARCH": target_arch,
        "vcs": "git", "vcs.revision": commit, "vcs.modified": "false",
    }
    for key, expected in required.items():
        if settings.get(key) != expected:
            raise ValueError(f"binary build setting {key} must be {expected!r}; got {settings.get(key)!r}")


def validate_archives(repo, dist, commit, go):
    archive_names = {
        path.name for path in dist.iterdir()
        if path.name.endswith((".tar.gz", ".zip"))
    }
    if archive_names != set(TARGETS):
        raise ValueError("release directory must contain exactly the four expected platform archives")
    legal_files = {name: (repo / name).read_bytes() for name in ("LICENSE", "THIRD_PARTY_NOTICES.md")}
    with tempfile.TemporaryDirectory(prefix="autocar-release-verify-") as temporary:
        for filename, (target_os, target_arch, binary_name) in TARGETS.items():
            contents = read_archive(dist / filename, binary_name)
            for name, expected in legal_files.items():
                if contents[name] != expected:
                    raise ValueError(f"archive {filename} has stale or changed {name}")
            binary = Path(temporary) / f"{target_os}-{target_arch}-{binary_name}"
            binary.write_bytes(contents[binary_name])
            result = subprocess.run(
                [go, "version", "-m", str(binary)], check=True, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
            )
            # Go omits ldflags from build info for trimpath builds. Runtime smoke
            # checks separately verify the injected release version/date/commit.
            validate_build_info(result.stdout, target_os, target_arch, commit)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--build-date", required=True)
    parser.add_argument("--metadata-only", action="store_true")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--go", default="go")
    args = parser.parse_args()
    try:
        validate_metadata(args.version, args.commit, args.build_date)
        if not args.metadata_only:
            validate_archives(args.repo_root, args.dist, args.commit, args.go)
    except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(f"release validation failed: {error}", file=sys.stderr)
        return 1
    print("release metadata validated" if args.metadata_only else "four release archives validated (no comparative claim)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
