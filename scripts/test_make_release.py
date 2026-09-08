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
VERSION = "v1.0.1"
BUILD_DATE = "2026-01-01T00:00:00Z"


def mock_build():
    """Stand in for recursive make, recording its inputs outside the checkout."""
    report = Path(os.environ["AUTOCAR_RELEASE_TEST_REPORT"])
    calls = json.loads(report.read_text(encoding="utf-8")) if report.exists() else []
    calls.append(sys.argv[2:])
    report.write_text(json.dumps(calls), encoding="utf-8")
    stage = sys.argv[2]
    if os.environ.get("AUTOCAR_RELEASE_TEST_MUTATE") == stage:
        Path("changed-source.txt").write_text("source changed\n", encoding="utf-8")
    if os.environ.get("AUTOCAR_RELEASE_TEST_CHANGE_HEAD") == stage:
        subprocess.run(
            ["git", "-c", "user.name=Release Recipe Test", "-c",
             "user.email=release-test@example.invalid", "-c", "commit.gpgsign=false",
             "-c", "core.hooksPath=/dev/null", "commit", "--allow-empty", "-qm", "changed HEAD"],
            check=True,
        )
    return 7 if os.environ.get("AUTOCAR_RELEASE_TEST_FAIL") == stage else 0


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
        self.env["AUTOCAR_RELEASE_TEST_FAIL"] = ""
        self.env["AUTOCAR_RELEASE_TEST_MUTATE"] = ""
        self.env["AUTOCAR_RELEASE_TEST_CHANGE_HEAD"] = ""
        for key in tuple(self.env):
            if key.startswith("STEALTH_"):
                del self.env[key]
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

    def release(self, target="release"):
        builder = shlex.join([sys.executable, str(SCRIPT), "--mock-build"])
        return subprocess.run(
            [
                shutil.which("make") or "make", "--no-print-directory",
                "-f", str(MAKEFILE), "-o", "stealth-tools-check", target,
                f"MAKE={builder}", f"VERSION={VERSION}", f"BUILD_DATE={BUILD_DATE}",
                "COMMIT=caller-must-not-override-head",
            ],
            cwd=self.repo, env=self.env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
        )

    def calls(self):
        return json.loads(self.report.read_text(encoding="utf-8")) if self.report.exists() else []

    def assert_stages(self, *stages):
        expected = []
        for stage in stages:
            metadata = [] if stage == "release-quality-check" else [
                f"VERSION={VERSION}", f"COMMIT={self.commit}", f"BUILD_DATE={BUILD_DATE}",
            ]
            expected.append([stage, *metadata])
        self.assertEqual(self.calls(), expected)

    def test_build_failure_is_not_masked_by_clean_source(self):
        self.env["AUTOCAR_RELEASE_TEST_FAIL"] = "cross-build"
        result = self.release()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assert_stages("release-metadata-check", "release-quality-check", "cross-build")
        self.assertEqual(self.git("status", "--porcelain").stdout, "")

    def test_success_forwards_frozen_metadata_without_building_artifacts(self):
        result = self.release()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assert_stages("release-metadata-check", "release-quality-check", "cross-build", "release-artifact-check")
        self.assertEqual(sorted(path.name for path in self.repo.iterdir()), [".git"])

    def test_changed_source_after_build_is_rejected(self):
        self.env["AUTOCAR_RELEASE_TEST_MUTATE"] = "cross-build"
        result = self.release()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assert_stages("release-metadata-check", "release-quality-check", "cross-build", "release-artifact-check")
        self.assertIn("release source changed while archives were built", result.stdout)

    def test_dirty_source_is_rejected_before_build(self):
        (self.repo / "untracked-source.txt").write_text("dirty\n", encoding="utf-8")
        result = self.release()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.report.exists(), result.stdout)
        self.assertIn("release checkout became dirty", result.stdout)

    def test_quality_failure_prevents_build(self):
        self.env["AUTOCAR_RELEASE_TEST_FAIL"] = "release-quality-check"
        result = self.release()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assert_stages("release-metadata-check", "release-quality-check")

    def test_bad_metadata_prevents_quality_checks_and_build(self):
        self.env["AUTOCAR_RELEASE_TEST_FAIL"] = "release-metadata-check"
        result = self.release()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assert_stages("release-metadata-check")

    def test_archive_validation_failure_is_not_masked(self):
        self.env["AUTOCAR_RELEASE_TEST_FAIL"] = "release-artifact-check"
        result = self.release()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assert_stages("release-metadata-check", "release-quality-check", "cross-build", "release-artifact-check")

    def test_source_change_during_quality_checks_prevents_build(self):
        self.env["AUTOCAR_RELEASE_TEST_MUTATE"] = "release-quality-check"
        result = self.release()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assert_stages("release-metadata-check", "release-quality-check")
        self.assertIn("release source changed during quality checks", result.stdout)

    def test_clean_head_change_during_quality_checks_prevents_build(self):
        self.env["AUTOCAR_RELEASE_TEST_CHANGE_HEAD"] = "release-quality-check"
        result = self.release()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.git("status", "--porcelain").stdout, "")
        self.assert_stages("release-metadata-check", "release-quality-check")
        self.assertIn("release source changed during quality checks", result.stdout)

    def test_clean_head_change_during_build_is_rejected(self):
        self.env["AUTOCAR_RELEASE_TEST_CHANGE_HEAD"] = "cross-build"
        result = self.release()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.git("status", "--porcelain").stdout, "")
        self.assertIn("release source changed while archives were built", result.stdout)

    def test_ordinary_release_does_not_require_comparative_evidence(self):
        result = self.release()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("release-evidence-check", [call[0] for call in self.calls()])
        self.assertNotIn("STEALTH_LOCAL_ACTIVE", result.stdout)

    def test_comparative_release_still_fails_closed_without_evidence(self):
        self.env["AUTOCAR_RELEASE_TEST_FAIL"] = "release-evidence-check"
        result = self.release("release-with-evidence")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.calls(), [["release-evidence-check"]])

    def test_comparative_evidence_gate_requires_original_inputs(self):
        result = self.release("release-evidence-check")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.report.exists(), result.stdout)
        self.assertIn("set STEALTH_LOCAL_ACTIVE=", result.stdout)

    def test_comparative_release_runs_evidence_before_ordinary_release(self):
        result = self.release("release-with-evidence")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.calls(), [
            ["release-evidence-check"], ["release", f"VERSION={VERSION}", f"BUILD_DATE={BUILD_DATE}"],
        ])

    def test_comparative_release_rejects_changed_evidence_head(self):
        self.env["AUTOCAR_RELEASE_TEST_CHANGE_HEAD"] = "release-evidence-check"
        result = self.release("release-with-evidence")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.calls(), [["release-evidence-check"]])
        self.assertIn("comparative release source changed during evidence checks", result.stdout)

    def test_comparative_release_rejects_changed_packaging_head(self):
        self.env["AUTOCAR_RELEASE_TEST_CHANGE_HEAD"] = "release"
        result = self.release("release-with-evidence")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("comparative release source changed during packaging", result.stdout)

    def test_quality_target_preserves_all_required_stages(self):
        result = subprocess.run(
            [shutil.which("make") or "make", "-n", "--no-print-directory", "-f", str(MAKEFILE),
             "release-quality-check", "MAKE=echo"], cwd=self.repo, env=self.env,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        for command in ("echo check", "echo race", "echo stealth-tools-check", "./scripts/govulncheck.sh"):
            self.assertIn(command, result.stdout)


if __name__ == "__main__":
    if sys.argv[1:2] == ["--mock-build"]:
        raise SystemExit(mock_build())
    unittest.main()
