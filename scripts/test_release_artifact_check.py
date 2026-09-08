#!/usr/bin/env python3
"""Bounded release archive validation tests; no builds or network access."""

import importlib.util
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile


SPEC = importlib.util.spec_from_file_location("release_artifact_check", Path(__file__).with_name("release-artifact-check.py"))
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)
COMMIT = "a" * 40
VERSION = "v1.0.1"
BUILD_DATE = "2026-09-08T00:00:00Z"


def build_info(target_os="linux", target_arch="amd64", **overrides):
    settings = {
        "-buildmode": "exe", "-trimpath": "true", "CGO_ENABLED": "0",
        "GOOS": target_os, "GOARCH": target_arch, "vcs": "git",
        "vcs.revision": COMMIT, "vcs.modified": "false",
    }
    settings.update(overrides)
    return "\n".join([
        "binary: go1.25.13", "\tpath\tgithub.com/cppla/autocar/cmd/autocar",
        "\tmod\tgithub.com/cppla/autocar\t(devel)",
        *(f"\tbuild\t{key}={value}" for key, value in settings.items()),
    ])


class ReleaseMetadataTests(unittest.TestCase):
    def test_release_and_prerelease_metadata(self):
        for version in (VERSION, "v1.0.1-rc.1", "v1.0.1+build.1"):
            CHECK.validate_metadata(version, COMMIT, BUILD_DATE)

    def test_invalid_metadata_is_rejected(self):
        cases = [
            ("dev", COMMIT, BUILD_DATE), ("1.0.1", COMMIT, BUILD_DATE),
            ("v01.0.1", COMMIT, BUILD_DATE), ("v1.0.1;echo", COMMIT, BUILD_DATE),
            ("v1.0.1-01", COMMIT, BUILD_DATE),
            (VERSION, "unknown", BUILD_DATE), (VERSION, COMMIT[:7], BUILD_DATE),
            (VERSION, COMMIT, "unknown"), (VERSION, COMMIT, "2026-02-30T00:00:00Z"),
            (VERSION, COMMIT, "2026-09-08T08:00:00+08:00"),
        ]
        for values in cases:
            with self.subTest(values=values), self.assertRaises(ValueError):
                CHECK.validate_metadata(*values)

    def test_build_info_valid_for_every_platform(self):
        for target_os, target_arch, _ in CHECK.TARGETS.values():
            CHECK.validate_build_info(build_info(target_os, target_arch), target_os, target_arch, COMMIT)

    def test_build_info_rejects_wrong_or_dirty_binary(self):
        cases = [
            {"GOOS": "windows"}, {"GOARCH": "arm64"}, {"CGO_ENABLED": "1"},
            {"-trimpath": "false"}, {"vcs.revision": "b" * 40},
            {"vcs.modified": "true"}, {"-buildmode": "shared"},
        ]
        for settings in cases:
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                CHECK.validate_build_info(build_info(**settings), "linux", "amd64", COMMIT)

    def test_build_info_rejects_missing_and_duplicate_settings(self):
        for output in (
            build_info().replace("\tbuild\tvcs.modified=false", ""),
            build_info() + "\n\tbuild\tvcs.modified=false",
            build_info().replace("github.com/cppla/autocar/cmd/autocar", "example.invalid/tool"),
        ):
            with self.subTest(output=output), self.assertRaises(ValueError):
                CHECK.validate_build_info(output, "linux", "amd64", COMMIT)


class ReleaseArchiveTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="autocar-release-archive-test-")
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        self.dist = self.repo / "dist"
        self.dist.mkdir()
        self.legal = {"LICENSE": b"test license\n", "THIRD_PARTY_NOTICES.md": b"test notices\n"}
        for name, contents in self.legal.items():
            (self.repo / name).write_bytes(contents)
        for filename, (_, _, binary_name) in CHECK.TARGETS.items():
            self.write_archive(filename, [(binary_name, b"test binary"), *self.legal.items()])

    def write_archive(self, filename, members):
        path = self.dist / filename
        if filename.endswith(".zip"):
            with zipfile.ZipFile(path, "w") as archive:
                for name, contents in members:
                    archive.writestr(name, contents)
        else:
            with tarfile.open(path, "w:gz") as archive:
                for name, contents in members:
                    info = tarfile.TarInfo(name)
                    info.size = len(contents)
                    info.mode = 0o755 if name == "autocar" else 0o644
                    archive.addfile(info, io.BytesIO(contents))
        return path

    def validate(self):
        def inspect_binary(command, **kwargs):
            name = Path(command[-1]).name
            target_os, target_arch, _ = name.split("-", 2)
            return subprocess.CompletedProcess(command, 0, stdout=build_info(target_os, target_arch), stderr="")
        with patch.object(CHECK.subprocess, "run", side_effect=inspect_binary) as inspect:
            CHECK.validate_archives(self.repo, self.dist, COMMIT, "go")
            return inspect

    def test_all_archives_and_legal_files_match(self):
        inspect = self.validate()
        self.assertEqual(inspect.call_count, 4)

    def test_missing_archive_is_rejected(self):
        (self.dist / "autocar-linux-arm64.tar.gz").unlink()
        with self.assertRaisesRegex(ValueError, "exactly the four"):
            self.validate()

    def test_extra_archive_is_rejected(self):
        (self.dist / "stale.zip").write_bytes(b"old")
        with self.assertRaisesRegex(ValueError, "exactly the four"):
            self.validate()

    def test_stale_notice_is_rejected(self):
        (self.repo / "THIRD_PARTY_NOTICES.md").write_bytes(b"new notices")
        with self.assertRaisesRegex(ValueError, "stale or changed THIRD_PARTY_NOTICES"):
            self.validate()

    def test_extra_duplicate_or_missing_members_are_rejected(self):
        base = [("autocar", b"binary"), *self.legal.items()]
        for members in (base + [("../outside", b"no")], base + [("autocar", b"duplicate")], base[:-1]):
            with self.subTest(members=members):
                path = self.write_archive("autocar-linux-amd64.tar.gz", members)
                with self.assertRaises(ValueError):
                    CHECK.read_archive(path, "autocar")

    def test_zip_traversal_is_rejected(self):
        path = self.write_archive("autocar-windows-amd64.zip", [("autocar.exe", b"binary"), *self.legal.items(), ("../outside", b"no")])
        with self.assertRaisesRegex(ValueError, "unexpected"):
            CHECK.read_archive(path, "autocar.exe")

    def test_tar_symlink_is_rejected(self):
        path = self.dist / "autocar-linux-amd64.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            info = tarfile.TarInfo("autocar")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../outside"
            archive.addfile(info)
        with self.assertRaisesRegex(ValueError, "bounded regular"):
            CHECK.read_archive(path, "autocar")

    def test_zip_symlink_is_rejected(self):
        path = self.dist / "autocar-windows-amd64.zip"
        with zipfile.ZipFile(path, "w") as archive:
            info = zipfile.ZipInfo("autocar.exe")
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            archive.writestr(info, "../../outside")
        with self.assertRaisesRegex(ValueError, "unencrypted regular"):
            CHECK.read_archive(path, "autocar.exe")

    def test_empty_binary_is_rejected(self):
        path = self.write_archive("autocar-linux-amd64.tar.gz", [("autocar", b""), *self.legal.items()])
        with self.assertRaisesRegex(ValueError, "empty"):
            CHECK.read_archive(path, "autocar")

    def test_non_executable_tar_binary_is_rejected(self):
        path = self.dist / "autocar-linux-amd64.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            info = tarfile.TarInfo("autocar")
            info.mode = 0o644
            archive.addfile(info)
        with self.assertRaisesRegex(ValueError, "executable permission"):
            CHECK.read_archive(path, "autocar")

    def test_archive_symlink_is_rejected(self):
        path = self.dist / "symlink.tar.gz"
        path.symlink_to(self.dist / "autocar-linux-amd64.tar.gz")
        with self.assertRaisesRegex(ValueError, "regular file"):
            CHECK.read_archive(path, "autocar")

    def test_non_go_binary_is_rejected(self):
        with patch.object(CHECK.subprocess, "run", side_effect=subprocess.CalledProcessError(1, ["go", "version"])):
            with self.assertRaises(subprocess.CalledProcessError):
                CHECK.validate_archives(self.repo, self.dist, COMMIT, "go")


if __name__ == "__main__":
    unittest.main()
