#!/usr/bin/env python3
"""Test the actual release recipe without compiling or publishing artifacts."""

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve()
MAKEFILE = SCRIPT.parent.parent / "Makefile"
VERSION = "release-recipe-test"
BUILD_DATE = "2026-01-01T00:00:00Z"


def mock_build():
    """Stand in for recursive make, recording its inputs outside the checkout."""
    Path(os.environ["AUTOCAR_RELEASE_TEST_REPORT"]).write_text(
        json.dumps(sys.argv[2:]), encoding="utf-8"
    )
    if os.environ.get("AUTOCAR_RELEASE_TEST_MUTATE") == "1":
        Path("changed-source.txt").write_text("source changed\n", encoding="utf-8")
    return int(os.environ.get("AUTOCAR_RELEASE_TEST_EXIT", "0"))


class ReleaseRecipeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="autocar-release-recipe-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.report = self.root / "builder-arguments.json"
        self.env = os.environ.copy()
        # Keep the isolated fixture independent of an enclosing make/Git invocation.
        for key in tuple(self.env):
            if key.startswith("GIT_") or key in {"MAKEFLAGS", "MFLAGS", "MAKELEVEL"}:
                del self.env[key]
        self.env["AUTOCAR_RELEASE_TEST_REPORT"] = str(self.report)
        self.env["AUTOCAR_RELEASE_TEST_EXIT"] = "0"
        self.env["AUTOCAR_RELEASE_TEST_MUTATE"] = "0"
        self.git("init", "-q")
        self.git(
            "-c", "user.name=Release Recipe Test",
            "-c", "user.email=release-test@example.invalid",
            "-c", "commit.gpgsign=false",
            "-c", "core.hooksPath=/dev/null",
            "commit", "--allow-empty", "-qm", "isolated release fixture",
        )
        self.commit = self.git("rev-parse", "HEAD").stdout.strip()

    def git(self, *args):
        return subprocess.run(
            ["git", *args], cwd=self.repo, env=self.env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        )

    def release(self):
        builder = shlex.join([sys.executable, str(SCRIPT), "--mock-build"])
        return subprocess.run(
            [
                shutil.which("make") or "make", "--no-print-directory",
                "-f", str(MAKEFILE), "-o", "release-evidence-check", "release",
                f"MAKE={builder}", f"VERSION={VERSION}", f"BUILD_DATE={BUILD_DATE}",
            ],
            cwd=self.repo, env=self.env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
        )

    def assert_builder_arguments(self):
        self.assertEqual(
            json.loads(self.report.read_text(encoding="utf-8")),
            ["cross-build", f"VERSION={VERSION}", f"COMMIT={self.commit}",
             f"BUILD_DATE={BUILD_DATE}"],
        )

    def test_build_failure_is_not_masked_by_clean_source(self):
        self.env["AUTOCAR_RELEASE_TEST_EXIT"] = "7"
        result = self.release()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assert_builder_arguments()
        self.assertEqual(self.git("status", "--porcelain").stdout, "")

    def test_success_forwards_frozen_metadata_without_building_artifacts(self):
        result = self.release()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assert_builder_arguments()
        self.assertEqual(sorted(path.name for path in self.repo.iterdir()), [".git"])

    def test_changed_source_after_build_is_rejected(self):
        self.env["AUTOCAR_RELEASE_TEST_MUTATE"] = "1"
        result = self.release()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assert_builder_arguments()
        self.assertIn("release source changed while archives were built", result.stdout)

    def test_dirty_source_is_rejected_before_build(self):
        (self.repo / "untracked-source.txt").write_text("dirty\n", encoding="utf-8")
        result = self.release()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.report.exists(), result.stdout)
        self.assertIn("release checkout became dirty", result.stdout)


if __name__ == "__main__":
    if sys.argv[1:2] == ["--mock-build"]:
        raise SystemExit(mock_build())
    unittest.main()
