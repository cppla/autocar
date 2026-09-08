#!/usr/bin/env python3
"""Fail-closed checks for the release smoke harness; no Docker or Go processes."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "release_smoke", Path(__file__).with_name("release-smoke.py")
)
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)
VERSION = "v1.0.1"
COMMIT = "a" * 40
BUILD_DATE = "2026-09-08T00:00:00Z"


def completed(stdout="", stderr="", code=0):
    return subprocess.CompletedProcess(["mock-only"], code, stdout, stderr)


def benchmark_output(mode="quic", direction="download"):
    return {
        "mode": direction,
        "transport": mode,
        "selected_transport": "h3" if mode == "web-auto" else mode,
        "target": "target:9000",
        "bytes_per_iteration": 65536,
        "iterations": 3,
        "results_mbps": [1.5, 2.5, 3.5],
        "durations_ms": [349.525, 209.715, 149.796],
    }


class BenchmarkValidationTests(unittest.TestCase):
    def setUp(self):
        self.lab = smoke.Lab(Path("/fixture-not-mounted"), "linux/amd64")

    def test_accepted_paths_validate_each_direction_and_owned_target(self):
        for mode in ("quic", "tls", "h2", "h3", "web-auto"):
            with self.subTest(mode=mode):
                def execute(binary, args, **kwargs):
                    self.assertIn("--server=relay:8443", args)
                    self.assertIn("--target=target:9000", args)
                    self.assertIn("--token-file=/fixture/token", args)
                    self.assertTrue(kwargs["check"])
                    direction = next(value.split("=", 1)[1] for value in args if value.startswith("--mode="))
                    return completed(json.dumps(benchmark_output(mode, direction)))

                with mock.patch.object(self.lab, "run", side_effect=execute):
                    self.lab.benchmark(Path("/not-executed"), "stage", mode)
        self.assertEqual(len(self.lab.checks), 10)
        self.assertEqual({check["direction"] for check in self.lab.checks}, {"upload", "download"})

    def test_incomplete_or_wrong_payload_cannot_pass(self):
        invalid = [
            {"selected_transport": "direct"},
            {"mode": "upload"},
            {"transport": "direct"},
            {"target": "public.example:443"},
            {"bytes_per_iteration": 1},
            {"iterations": 2},
            {"results_mbps": [1, 2]},
            {"results_mbps": "123"},
            {"results_mbps": [1, 0, 2]},
            {"results_mbps": [1, -1, 2]},
            {"results_mbps": [1, float("nan"), 2]},
            {"results_mbps": [1, float("inf"), 2]},
            {"results_mbps": [1, True, 2]},
            {"durations_ms": None},
            {"durations_ms": []},
            {"durations_ms": [1, 0, 2]},
            {"durations_ms": [1, float("nan"), 2]},
        ]
        for changes in invalid:
            with self.subTest(changes=changes):
                payload = benchmark_output() | changes
                self.lab.checks.clear()
                with mock.patch.object(self.lab, "run", return_value=completed(json.dumps(payload))):
                    with self.assertRaises((ValueError, RuntimeError, TypeError)):
                        self.lab.benchmark(Path("/not-executed"), "stage", "quic")
                self.assertEqual(self.lab.checks, [])

    def test_authentication_rejection_is_distinct_from_transport_failure(self):
        for mode, error in (
            ("quic", "tunnel: remote error: authentication failed (status 2)"),
            ("tls", "tunnel: remote error: authentication failed (status 2)"),
            ("h2", "tunnel: web-cover H2 server authentication failed"),
            ("h3", "tunnel: web-cover H3 server authentication failed"),
        ):
            with self.subTest(mode=mode):
                self.lab.checks.clear()
                with mock.patch.object(self.lab, "run", return_value=completed(stderr=error, code=1)) as run:
                    self.lab.benchmark(Path("/not-executed"), "bad-token", mode, wrong_token=True)
                self.assertFalse(run.call_args.kwargs["check"])
                self.assertIn("--token-file=/fixture/wrong-token", run.call_args.args[1])
                self.assertEqual(self.lab.checks[0]["authentication"], "rejected")

        for error, code in (
            ("authentication failed", 0),
            ("connection refused", 1),
            ("authentication deadline exceeded", 1),
            ("authentication failed", 2),
        ):
            with self.subTest(error=error, code=code):
                self.lab.checks.clear()
                with mock.patch.object(self.lab, "run", return_value=completed(stderr=error, code=code)):
                    with self.assertRaises(RuntimeError):
                        self.lab.benchmark(Path("/not-executed"), "bad-token", "quic", wrong_token=True)
                self.assertEqual(self.lab.checks, [])


class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.lab = smoke.Lab(Path("/fixture-not-mounted"), "linux/amd64")

    def test_unowned_resource_is_never_removed(self):
        for kind in ("container", "network"):
            with self.subTest(kind=kind):
                with mock.patch.object(smoke, "command", return_value=completed("not-our-label")) as command:
                    with self.assertRaisesRegex(RuntimeError, "unowned"):
                        self.lab.remove(kind, "not-our-resource")
                self.assertEqual(command.call_count, 1)
                self.assertEqual(command.call_args.args[0][1:3], [kind, "inspect"])

    def test_body_failure_cleans_exact_owned_resources_in_reverse_order(self):
        self.lab.containers = ["owned-first", "owned-second"]
        self.lab.network = "owned-network"

        def execute(args, **kwargs):
            return completed(self.lab.identity if "inspect" in args else "")

        with mock.patch.object(smoke.Lab, "__enter__", return_value=self.lab):
            with mock.patch.object(smoke, "command", side_effect=execute) as command:
                with self.assertRaisesRegex(RuntimeError, "probe failed"):
                    with self.lab:
                        raise RuntimeError("probe failed")
        removals = [call.args[0] for call in command.call_args_list if "rm" in call.args[0]]
        self.assertEqual(removals, [
            ["docker", "container", "rm", "--force", "owned-second"],
            ["docker", "container", "rm", "--force", "owned-first"],
            ["docker", "network", "rm", "owned-network"],
        ])

    def test_create_options_keep_fixtures_internal_and_unprivileged(self):
        self.lab.network = "owned-network"
        with mock.patch.object(smoke, "command", side_effect=[completed("container-id"), completed()]) as command:
            reference = self.lab.run(Path("/release-binary"), ["server"], background=True)
        self.assertEqual(reference, self.lab.identity + "-1")
        create = command.call_args_list[0].args[0]
        for option in ("--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true"):
            self.assertIn(option, create)
        self.assertEqual(create[create.index("--network") + 1], "owned-network")
        self.assertNotIn("--privileged", create)
        self.assertNotIn("--publish", create)
        self.assertNotIn("-p", create)
        mounts = [create[index + 1] for index, value in enumerate(create) if value == "--mount"]
        self.assertEqual(len(mounts), 2)
        self.assertTrue(all(value.endswith(",readonly") for value in mounts))

    def test_removing_middle_container_does_not_reuse_an_existing_name(self):
        def execute(args, **kwargs):
            return completed(self.lab.identity if "inspect" in args else "")

        with mock.patch.object(smoke, "command", side_effect=execute):
            first = self.lab.run(Path("/release-binary"), ["server"], background=True)
            second = self.lab.run(Path("/release-binary"), ["server"], background=True)
            self.lab.stop(first)
            third = self.lab.run(Path("/release-binary"), ["server"], background=True)
        self.assertEqual(len({first, second, third}), 3)
        self.assertEqual(self.lab.containers, [second, third])

    def test_cleanup_ignores_only_confirmed_absence_not_daemon_failures(self):
        for kind, error in (("container", "Error: No such container: already-gone"),
                            ("network", "Error response from daemon: network already-gone not found")):
            with self.subTest(kind=kind):
                with mock.patch.object(smoke, "command", return_value=completed(stderr=error, code=1)) as command:
                    self.lab.remove(kind, "already-gone")
                self.assertEqual(command.call_count, 1)
        with mock.patch.object(smoke, "command", return_value=completed(stderr="cannot connect to Docker daemon", code=1)):
            with self.assertRaisesRegex(RuntimeError, "cannot verify"):
                self.lab.remove("container", "unknown-state")

    def test_uncertain_container_creation_still_cleans_owned_side_effect(self):
        created = set()

        def execute(args, **kwargs):
            if args[1] == "create":
                created.add(args[args.index("--name") + 1])
                raise subprocess.TimeoutExpired(args, 60)
            if args[1:3] == ["container", "inspect"]:
                return completed(self.lab.identity, code=0 if args[-1] in created else 1)
            if args[1:3] == ["container", "rm"]:
                created.remove(args[-1])
                return completed()
            raise AssertionError(args)

        with mock.patch.object(smoke.Lab, "__enter__", return_value=self.lab):
            with mock.patch.object(smoke, "command", side_effect=execute):
                with self.assertRaises((RuntimeError, subprocess.TimeoutExpired)):
                    with self.lab:
                        self.lab.run(Path("/release-binary"), ["server"], background=True)
        self.assertEqual(created, set(), "uncertain docker create leaked the owned container")

    def test_uncertain_network_creation_cleans_owned_side_effect(self):
        created = set()

        def execute(args, **kwargs):
            if args[1:3] == ["network", "create"]:
                self.assertIn("--internal", args)
                created.add(args[-1])
                raise subprocess.TimeoutExpired(args, 60)
            if args[1:3] == ["network", "inspect"]:
                return completed(self.lab.identity, code=0 if args[-1] in created else 1)
            if args[1:3] == ["network", "rm"]:
                created.remove(args[-1])
                return completed()
            return completed()

        with mock.patch.object(smoke, "command", side_effect=execute):
            with self.assertRaises((RuntimeError, subprocess.TimeoutExpired)):
                with self.lab:
                    self.fail("timed-out network setup must not enter the fixture body")
        self.assertEqual(created, set(), "failed __enter__ leaked the owned network")


class MainMatrixTests(unittest.TestCase):
    def exercise_main(self, corruption=None, cleanup_failure=False):
        original_benchmark = smoke.Lab.benchmark
        generated_tokens = []

        class MockLab(smoke.Lab):
            def __enter__(self):
                for name in ("token", "wrong-token"):
                    self_test.assertEqual((self.directory / name).stat().st_mode & 0o777, 0o600)
                    generated_tokens.append((self.directory / name).read_text().strip())
                self_test.assertNotEqual((self.directory / "token").read_text(), (self.directory / "wrong-token").read_text())
                return self

            def __exit__(self, *args):
                if cleanup_failure:
                    raise RuntimeError("controlled cleanup failure")

            def run(self, binary, args, **kwargs):
                if args[0] == "version":
                    if binary.name == "previous":
                        version = "v9.9.9" if corruption == "previous-metadata" else "v1.0.0"
                        return completed(f"autocar {version} (commit {smoke.PREVIOUS_COMMIT}, built earlier, linux/amd64, go1.25.13)")
                    commit = "b" * 40 if corruption == "current-metadata" else COMMIT
                    return completed(f"autocar {VERSION} (commit {commit}, built {BUILD_DATE}, linux/amd64, go1.25.13)")
                if args[0] == "bench-client":
                    options = dict(value[2:].split("=", 1) for value in args if value.startswith("--") and "=" in value)
                    if options["token-file"].endswith("wrong-token"):
                        mode = options["transport"]
                        error = (f"tunnel: web-cover {mode.upper()} server authentication failed" if mode in ("h2", "h3")
                                 else "tunnel: remote error: authentication failed (status 2)")
                        return completed(stderr=error, code=1)
                    return completed(json.dumps(benchmark_output(options["transport"], options["mode"])))
                return "mock-container" if kwargs.get("background") else completed()

            def ready(self, *args):
                pass

            def stop(self, *args):
                pass

            def benchmark(self, binary, stage, mode, **kwargs):
                original_benchmark(self, binary, stage, mode, **kwargs)
                if stage == "experimental-web/invalid-token" and mode == "h3":
                    if corruption == "missing":
                        self.checks.pop()
                    elif corruption == "duplicate":
                        self.checks.append(self.checks[-1].copy())
                    elif corruption == "wrong-stage":
                        self.checks[-1]["stage"] = "not-the-requested-matrix"

        self_test = self
        output = io.StringIO()
        with tempfile.TemporaryDirectory(prefix="release-smoke-unit-") as directory:
            root = Path(directory)
            for name in ("current", "previous"):
                binary = root / name
                binary.write_bytes(b"test fixture; never executed\n")
                binary.chmod(0o700)
            args = ["release-smoke.py", "--current", str(root / "current"), "--previous", str(root / "previous"),
                    "--version", VERSION, "--commit", COMMIT, "--build-date", BUILD_DATE]
            with mock.patch.object(sys, "argv", args), mock.patch.object(smoke, "Lab", MockLab):
                with contextlib.redirect_stdout(output):
                    try:
                        smoke.main()
                    except Exception:
                        self.assertEqual(output.getvalue(), "", "PASS was printed before a failure")
                        raise
        self.assertFalse(any(token in output.getvalue() for token in generated_tokens))
        return json.loads(output.getvalue())

    def test_full_matrix_contains_exactly_38_checks(self):
        result = self.exercise_main()
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["check_count"], 38)
        self.assertEqual(len(result["checks"]), 38)
        self.assertEqual(sum(check["authentication"] == "accepted" for check in result["checks"]), 30)
        self.assertEqual(sum(check["authentication"] == "rejected" for check in result["checks"]), 8)

    def test_unexpected_binary_metadata_cannot_pass(self):
        for corruption in ("current-metadata", "previous-metadata"):
            with self.subTest(corruption=corruption):
                with self.assertRaises(RuntimeError):
                    self.exercise_main(corruption)

    def test_incomplete_duplicate_or_changed_matrix_cannot_pass(self):
        for corruption in ("missing", "duplicate", "wrong-stage"):
            with self.subTest(corruption=corruption):
                with self.assertRaises((RuntimeError, ValueError)):
                    self.exercise_main(corruption)

    def test_cleanup_failure_cannot_emit_pass(self):
        with self.assertRaisesRegex(RuntimeError, "cleanup failure"):
            self.exercise_main(cleanup_failure=True)


if __name__ == "__main__":
    unittest.main()
