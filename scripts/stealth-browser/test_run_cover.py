#!/usr/bin/env python3
"""Offline unit tests for the real-browser runner; no browser or network is used."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import run_cover  # noqa: E402
import write_lock  # noqa: E402


SPKI_PIN = base64.b64encode(hashlib.sha256(b"browser-test-spki").digest()).decode("ascii")


def seeded_fixture_body(size: int, seed: int, request_index: int, domain: int) -> bytes:
    mask = (1 << 64) - 1
    state = (
        seed
        ^ (((request_index + 1) * 0x9E3779B97F4A7C15) & mask)
        ^ ((domain * 0xD1B54A32D192ED03) & mask)
    ) & mask
    result = bytearray(size)
    for index in range(size):
        state = (state + 0x9E3779B97F4A7C15) & mask
        value = state
        value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & mask
        value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & mask
        value = (value ^ (value >> 31)) & mask
        result[index] = value >> 56
    return bytes(result)


class BrowserRunnerTest(unittest.TestCase):
    def test_private_server_parser_is_strict(self) -> None:
        self.assertEqual(run_cover.parse_server("10.2.3.4:8443").authority, "10.2.3.4:8443")
        self.assertEqual(run_cover.parse_server("172.31.255.254:1").port, 1)
        self.assertEqual(run_cover.parse_server("192.168.1.1:65535").ip, "192.168.1.1")
        for value in (
            "8.8.8.8:443",
            "127.0.0.1:443",
            "169.254.1.1:443",
            "172.32.0.1:443",
            "10.0.0.1:0",
            "10.0.0.1:65536",
            "10.0.0.1:443;id",
            "10.0.0.1:443 && id",
            "https://10.0.0.1:443",
            "private.example:443",
            "[fd00::1]:443",
        ):
            with self.subTest(value=value), self.assertRaises(run_cover.RunnerError):
                run_cover.parse_server(value)

    def test_frozen_workload_matrix_and_sizes(self) -> None:
        self.assertEqual(
            set(run_cover.WORKLOAD_SPECS),
            {
                "idle",
                "download_1k",
                "download_128k",
                "download_1m",
                "upload_1m",
                "parallel_20",
                "interactive",
                "browser_h2",
            },
        )
        self.assertEqual(
            run_cover.WORKLOAD_SPECS["upload_1m"],
            {"requests": 1, "response_bytes": 32, "upload_bytes": 1 << 20},
        )
        self.assertEqual(
            run_cover.WORKLOAD_SPECS["interactive"],
            {"requests": 8, "response_bytes": 4096, "upload_bytes": 2048},
        )
        self.assertEqual(
            run_cover.WORKLOAD_SPECS["browser_h2"],
            run_cover.WORKLOAD_SPECS["download_128k"],
        )

    def test_checked_in_amd64_build_inputs_are_exact(self) -> None:
        pins = json.loads((HERE / "versions.debian13-amd64.json").read_text(encoding="utf-8"))
        self.assertRegex(pins["base_image"], r"@sha256:[0-9a-f]{64}$")
        self.assertEqual(
            pins["chromium"]["browser_package_version"],
            pins["chromium"]["webdriver_package_version"],
        )
        self.assertRegex(
            pins["firefox-esr"]["webdriver_archive_sha256"], r"^[0-9a-f]{64}$"
        )
        self.assertEqual(pins["firefox-esr"]["webdriver_package_version"], "0.36.0")

    def test_splitmix_reference_vector_and_javascript_contract(self) -> None:
        self.assertEqual(
            seeded_fixture_body(16, 42, 3, 1).hex(),
            "a48ffa4c89f2700e5609847199968fd3",
        )
        for token in (
            "0x9e3779b97f4a7c15n",
            "0xd1b54a32d192ed03n",
            "0xbf58476d1ce4e5b9n",
            "0x94d049bb133111ebn",
            'path = "/exchange/256/512"',
            'target.searchParams.set("seed"',
            'target.searchParams.set("request"',
        ):
            self.assertIn(token, run_cover.WORKLOAD_SCRIPT)

    def test_bootstrap_document_and_navigation_protocol_are_fail_closed(self) -> None:
        for token in (
            'meta[name="autocar-stealth-bootstrap"]',
            'marker.getAttribute("content") === "v1"',
            'icons[0].getAttribute("href") === "data:,"',
            'query.get("autocar_browser_sample") === expectedSeed',
            'performance.getEntriesByType("navigation")',
        ):
            self.assertIn(token, run_cover.BOOTSTRAP_VERIFY_SCRIPT)
        valid = {"ok": True, "sample_seed": 42, "next_hop_protocol": "h3"}
        self.assertIsNone(run_cover.validate_bootstrap_result(valid, "h3", 42))
        for broken in (
            {**valid, "ok": False},
            {**valid, "sample_seed": 43},
            {**valid, "next_hop_protocol": "h2"},
            {**valid, "extra": True},
            [valid],
        ):
            with self.subTest(broken=broken), self.assertRaises(run_cover.RunnerError):
                run_cover.validate_bootstrap_result(broken, "h3", 42)

    def test_resource_timing_protocol_is_fail_closed(self) -> None:
        value = {
            "ok": True,
            "request_count": 1,
            "response_bytes": 1024,
            "upload_bytes": 0,
            "resources": [{"request_index": 0, "next_hop_protocol": "h3"}],
        }
        checked = run_cover.validate_workload_result(value, "download_1k", "h3")
        self.assertEqual(checked["next_hop_protocols"], ["h3"])
        for broken in (
            {**value, "resources": []},
            {**value, "resources": [{"request_index": 0, "next_hop_protocol": "h2"}]},
            {**value, "resources": [{"request_index": 0, "next_hop_protocol": ""}]},
            {**value, "response_bytes": 1023},
            {**value, "request_count": True},
            {**value, "upload_bytes": False},
        ):
            with self.subTest(broken=broken), self.assertRaises(run_cover.RunnerError):
                run_cover.validate_workload_result(broken, "download_1k", "h3")

    def test_browser_h2_receipt_preserves_auxiliary_label(self) -> None:
        identity = run_cover.BrowserIdentity(
            browser="firefox-esr",
            client_implementation="Firefox",
            implementation_version="Mozilla Firefox 140.14.0esr",
            browser_binary="/usr/lib/firefox-esr/firefox-esr",
            browser_binary_sha256="a" * 64,
            webdriver_binary="/usr/local/bin/geckodriver",
            webdriver_version="geckodriver 0.37.1",
            webdriver_binary_sha256="b" * 64,
        )
        raw = {
            "ok": True,
            "request_count": 1,
            "response_bytes": 128 * 1024,
            "upload_bytes": 0,
            "resources": [{"request_index": 0, "next_hop_protocol": "h2"}],
        }
        checked = run_cover.validate_workload_result(raw, "browser_h2", "h2")
        receipt = run_cover.workload_receipt(identity, "h2", "browser_h2", 91, checked)
        self.assertEqual(set(receipt), run_cover.SUCCESS_FIELDS)
        self.assertEqual(receipt["workload"], "browser_h2")
        self.assertEqual(receipt["response_bytes"], 128 * 1024)
        expected_document = {
            "protocol": "h2",
            "workload": "browser_h2",
            "sample_seed": 91,
            "request_count": 1,
            "response_bytes": 128 * 1024,
            "upload_bytes": 0,
            "resources": [{"request_index": 0, "next_hop_protocol": "h2"}],
        }
        self.assertEqual(
            receipt["result_sha256"], run_cover.canonical_json_sha256(expected_document)
        )
        self.assertNotIn("server", receipt)

    def test_capabilities_select_and_later_verify_protocol(self) -> None:
        server = run_cover.parse_server("10.20.30.40:8443")
        chromium = run_cover.BrowserIdentity(
            "chromium", "Chromium", "Chromium 151.0.1.2", "/usr/lib/chromium/chromium",
            "a" * 64, "/usr/bin/chromedriver", "ChromeDriver 151.0.1.2", "b" * 64,
        )
        h3 = run_cover.browser_capabilities(
            chromium, "h3", server, Path("/tmp/profile"), True, SPKI_PIN
        )
        self.assertIn("--origin-to-force-quic-on=10.20.30.40:8443", h3["goog:chromeOptions"]["args"])
        self.assertIn(
            "--ignore-certificate-errors-spki-list=" + SPKI_PIN,
            h3["goog:chromeOptions"]["args"],
        )
        h2 = run_cover.browser_capabilities(
            chromium, "h2", server, Path("/tmp/profile"), False, None
        )
        self.assertIn("--disable-quic", h2["goog:chromeOptions"]["args"])
        self.assertFalse(
            any(
                argument.startswith("--ignore-certificate-errors-spki-list=")
                for argument in h2["goog:chromeOptions"]["args"]
            )
        )
        firefox = run_cover.BrowserIdentity(
            "firefox-esr", "Firefox", "Mozilla Firefox 140.14.0esr", "/usr/lib/firefox-esr/firefox-esr",
            "c" * 64, "/usr/local/bin/geckodriver", "geckodriver 0.37.1", "d" * 64,
        )
        firefox_h3 = run_cover.browser_capabilities(
            firefox, "h3", server, Path("/tmp/profile"), True, None
        )
        prefs = firefox_h3["moz:firefoxOptions"]["prefs"]
        self.assertTrue(prefs["network.http.http3.enable"])
        self.assertEqual(
            prefs["network.http.http3.alt-svc-mapping-for-testing"],
            '10.20.30.40;h3=":8443"',
        )
        self.assertTrue(
            prefs["network.http.http3.force-use-alt-svc-mapping-for-testing"]
        )
        self.assertIs(
            prefs["network.http.http3.disable_when_third_party_roots_found"], False
        )
        firefox_h2_prefs = run_cover.browser_capabilities(
            firefox, "h2", server, Path("/tmp/profile"), True, None
        )["moz:firefoxOptions"]["prefs"]
        self.assertFalse(firefox_h2_prefs["network.http.http3.enable"])
        for h3_only_preference in (
            "network.http.http3.alt-svc-mapping-for-testing",
            "network.http.http3.force-use-alt-svc-mapping-for-testing",
            "network.http.http3.disable_when_third_party_roots_found",
        ):
            with self.subTest(h3_only_preference=h3_only_preference):
                self.assertNotIn(h3_only_preference, firefox_h2_prefs)

        wrong_protocol = {
            "ok": True,
            "request_count": 1,
            "response_bytes": 1024,
            "upload_bytes": 0,
            "resources": [{"request_index": 0, "next_hop_protocol": "h2"}],
        }
        with self.assertRaises(run_cover.RunnerError):
            run_cover.validate_workload_result(wrong_protocol, "download_1k", "h3")

    def test_session_version_comparison_preserves_full_esr_release(self) -> None:
        firefox = run_cover.BrowserIdentity(
            "firefox-esr", "Firefox", "Mozilla Firefox 140.15.0esr",
            "/usr/lib/firefox-esr/firefox-esr", "a" * 64,
            "/usr/local/bin/geckodriver", "geckodriver 0.36.0", "b" * 64,
        )
        self.assertEqual(
            run_cover.numeric_version(firefox.implementation_version), "140.15.0"
        )
        self.assertEqual(
            run_cover.validate_session_identity(
                firefox, {"browserName": "firefox", "browserVersion": "140.15.0"}
            ),
            "140.15.0",
        )
        with self.assertRaisesRegex(
            run_cover.RunnerError, r"session='140\.15\.1'.*locked='Mozilla Firefox 140\.15\.0esr'"
        ):
            run_cover.validate_session_identity(
                firefox, {"browserName": "firefox", "browserVersion": "140.15.1"}
            )
        self.assertEqual(
            run_cover.numeric_version("Chromium 152.0.7977.75"), "152.0.7977.75"
        )
        for malformed in (
            "Mozilla Firefox 140",
            "Mozilla Firefox 140.15.0.1.2",
            "Mozilla Firefox 140.15.0esr1",
            "Mozilla Firefox x140.15.0",
            "Mozilla Firefox 140.15.0 engine 1.2.3",
        ):
            with self.subTest(malformed=malformed), self.assertRaises(run_cover.RunnerError):
                run_cover.numeric_version(malformed)

    def test_spki_pin_is_canonical_and_chromium_h3_only(self) -> None:
        self.assertEqual(run_cover.parse_certificate_spki_sha256(SPKI_PIN), SPKI_PIN)
        for malformed in ("", "A" * 44, "A" * 42 + "==", SPKI_PIN[:-1], SPKI_PIN + "\n"):
            with self.subTest(malformed=malformed), self.assertRaises(run_cover.UsageError):
                run_cover.parse_certificate_spki_sha256(malformed)
        with self.assertRaises(run_cover.UsageError):
            run_cover.validate_certificate_spki_usage("chromium", "h3", None)
        for browser, protocol in (
            ("chromium", "h2"),
            ("firefox-esr", "h3"),
            ("firefox-esr", "h2"),
        ):
            with self.subTest(browser=browser, protocol=protocol), self.assertRaises(
                run_cover.UsageError
            ):
                run_cover.validate_certificate_spki_usage(browser, protocol, SPKI_PIN)

    def test_lock_and_identity_are_bound_to_executable_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            browser = root / "chromium"
            driver = root / "chromedriver"
            browser.write_text("#!%s\nprint('Chromium 151.0.1.2')\n" % sys.executable, encoding="utf-8")
            driver.write_text("#!%s\nprint('ChromeDriver 151.0.1.2')\n" % sys.executable, encoding="utf-8")
            browser.chmod(browser.stat().st_mode | stat.S_IXUSR)
            driver.chmod(driver.stat().st_mode | stat.S_IXUSR)
            lock_path = root / "browser-lock.json"
            arguments = SimpleNamespace(
                browser="chromium",
                browser_binary=str(browser),
                webdriver_binary=str(driver),
                browser_package_version="151.0.1.2-1~deb13u1",
                webdriver_package_version="151.0.1.2-1~deb13u1",
                implementation_version=None,
            )
            lock = write_lock.create_lock(arguments)
            write_lock.write_atomic(lock_path, lock)
            identity = run_cover.load_browser_identity(lock_path, "chromium")
            self.assertEqual(identity.client_implementation, "Chromium")
            self.assertEqual(identity.implementation_version, "Chromium 151.0.1.2")
            self.assertEqual(identity.browser_binary_sha256, hashlib.sha256(browser.read_bytes()).hexdigest())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(run_cover.main(["identity", "--browser-lock", str(lock_path)]), 0)
            rendered = output.getvalue()
            self.assertEqual(rendered.count("\n"), 1)
            self.assertEqual(
                set(json.loads(rendered)),
                {"client_implementation", "implementation_version", "browser_binary_sha256"},
            )
            browser.write_text(browser.read_text(encoding="utf-8") + "# changed\n", encoding="utf-8")
            with self.assertRaises(run_cover.RunnerError):
                run_cover.load_browser_identity(lock_path, "chromium")

    def test_shell_command_path_is_rejected_and_driver_command_is_argv(self) -> None:
        with self.assertRaises(run_cover.RunnerError):
            run_cover.executable_path("/bin/sh -c id", "chromium", "browser")
        identity = run_cover.BrowserIdentity(
            "chromium", "Chromium", "Chromium 151.0.1.2", "/usr/lib/chromium/chromium",
            "a" * 64, "/usr/bin/chromedriver", "ChromeDriver 151.0.1.2", "b" * 64,
        )
        command = run_cover.driver_command(identity, 49151)
        self.assertIsInstance(command, list)
        self.assertEqual(command[0], "/usr/bin/chromedriver")
        self.assertNotIn("sh", [Path(part).name for part in command])

    def test_webdriver_readiness_requires_explicit_w3c_ready_true(self) -> None:
        client = run_cover.WebDriverClient(49151, 1)
        process = mock.Mock()
        process.poll.return_value = None
        with mock.patch.object(client, "request", side_effect=[None, {}, {"ready": False}, {"ready": True}]) as request:
            with mock.patch.object(run_cover.time, "sleep"):
                client.wait_ready(process, seconds=1)
        self.assertEqual(request.call_count, 4)

    def test_browser_validates_captured_bootstrap_before_business_workload(self) -> None:
        identity = run_cover.BrowserIdentity(
            "chromium", "Chromium", "Chromium 151.0.1.2",
            "/usr/lib/chromium/chromium", "a" * 64,
            "/usr/bin/chromedriver", "ChromeDriver 151.0.1.2", "b" * 64,
        )
        raw_workload = {
            "ok": True,
            "request_count": 1,
            "response_bytes": 1024,
            "upload_bytes": 0,
            "resources": [{"request_index": 0, "next_hop_protocol": "h3"}],
        }
        webdriver = mock.Mock()
        webdriver.create_session.return_value = (
            "session-1", {"browserName": "chrome", "browserVersion": "151.0.1.2"}
        )
        webdriver.request.side_effect = [
            None,
            None,
            {"ok": True, "sample_seed": 5, "next_hop_protocol": "h3"},
            raw_workload,
            None,
        ]
        process = mock.Mock()
        process.poll.return_value = None
        args = SimpleNamespace(
            server="10.0.0.2:8443", browser_lock="/ignored/browser-lock.json",
            browser="chromium", runtime_directory="", webdriver_timeout=15,
            protocol="h3", accept_insecure_certs=True,
            certificate_spki_sha256=SPKI_PIN, workload_timeout=45,
            seed=5, workload="download_1k", idle_milliseconds=1200,
        )
        with tempfile.TemporaryDirectory() as directory:
            args.runtime_directory = directory
            with mock.patch.object(run_cover, "load_browser_identity", return_value=identity), \
                    mock.patch.object(run_cover, "free_loopback_port", return_value=49151), \
                    mock.patch.object(run_cover.subprocess, "Popen", return_value=process), \
                    mock.patch.object(run_cover, "WebDriverClient", return_value=webdriver), \
                    mock.patch.object(run_cover, "stop_process_group"):
                receipt = run_cover.execute_browser_workload(args)
        self.assertEqual(receipt["workload"], "download_1k")
        calls = [(call.args[0], call.args[1]) for call in webdriver.request.call_args_list]
        self.assertEqual(
            calls,
            [
                ("POST", "/session/session-1/timeouts"),
                ("POST", "/session/session-1/url"),
                ("POST", "/session/session-1/execute/sync"),
                ("POST", "/session/session-1/execute/async"),
                ("DELETE", "/session/session-1"),
            ],
        )
        navigation_payload = webdriver.request.call_args_list[1].args[2]
        self.assertEqual(
            navigation_payload["url"],
            "https://10.0.0.2:8443/?autocar_browser_sample=5",
        )

    def test_success_stdout_is_exactly_one_compact_receipt_and_failure_is_silent(self) -> None:
        identity = run_cover.BrowserIdentity(
            "chromium", "Chromium", "Chromium 151.0.1.2", "/usr/lib/chromium/chromium",
            "a" * 64, "/usr/bin/chromedriver", "ChromeDriver 151.0.1.2", "b" * 64,
        )
        checked = {
            "next_hop_protocols": ["h3"],
            "request_count": 1,
            "response_bytes": 1024,
            "upload_bytes": 0,
            "resource_indexes": [0],
        }
        receipt = run_cover.workload_receipt(identity, "h3", "download_1k", 5, checked)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(run_cover, "execute_browser_workload", return_value=receipt):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = run_cover.main(
                    [
                        "--browser", "chromium", "--protocol", "h3", "--server",
                        "10.0.0.2:8443", "--workload", "download_1k", "--seed", "5",
                        "--certificate-spki-sha256", SPKI_PIN,
                    ]
                )
        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(stdout.getvalue(), run_cover.compact_json(receipt) + "\n")
        self.assertNotIn(": ", stdout.getvalue())

        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = run_cover.main(
                [
                    "--browser", "chromium", "--protocol", "h3", "--server",
                    "8.8.8.8:443", "--workload", "idle", "--seed", "1",
                    "--certificate-spki-sha256", SPKI_PIN,
                ]
            )
        self.assertEqual(code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("outside RFC1918", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
