#!/usr/bin/env python3
"""Exercise dependency policy in disposable fixtures, without Go or network access."""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parent
BOUNDARY = (SCRIPTS / "check-dependency-boundary.sh").read_text(encoding="utf-8")
PINS = dict(re.findall(r"^readonly (ALLOWED_[A-Z_]+)='([^']+)'$", BOUNDARY, re.MULTILINE))
# Until the real pin is published, only these disposable test copies receive a
# synthetic pseudo-version. The production script must still reject its TODO.
FORK_VERSION = PINS["ALLOWED_UTLS_VERSION"]
if FORK_VERSION.startswith("TODO_"):
    FORK_VERSION = "v1.8.3-0.20261008120000-0123456789ab"


class DependencyBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="autocar-dependency-boundary-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.script = self.root / "check.sh"
        self.script.write_text(
            BOUNDARY.replace(PINS["ALLOWED_UTLS_VERSION"], FORK_VERSION), encoding="utf-8"
        )
        self.upstream = PINS["ALLOWED_UTLS_MODULE"]
        self.fork = PINS["ALLOWED_UTLS_REPLACEMENT"]
        self.replacement = f"replace {self.upstream} => {self.fork} {FORK_VERSION}"
        self.module = (
            "module example.invalid/fixture\n\ngo 1.27.1\n\nrequire (\n"
            f"\t{PINS['ALLOWED_WEB_QUIC_MODULE']} {PINS['ALLOWED_WEB_QUIC_VERSION']}\n"
            f"\t{self.upstream} {PINS['ALLOWED_UTLS_UPSTREAM_VERSION']}\n"
            ")\n\n" + self.replacement + "\n"
        )

    def check(self, module=None):
        (self.root / "go.mod").write_text(module or self.module, encoding="utf-8")
        return subprocess.run(
            ["bash", str(self.script)], cwd=self.root, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
        )

    def test_exact_remote_pin_passes(self):
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_block_replacement_and_comments_pass(self):
        block = f"replace (\n\t{self.upstream} => {self.fork} {FORK_VERSION} // frozen\n)"
        result = self.check(self.module.replace(self.replacement, block))
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_original_import_and_official_native_quic_remain_allowed(self):
        (self.root / "main.go").write_text(
            f'package fixture\nimport _ "{self.upstream}"\n'
            'import _ "github.com/quic-go/quic-go"\n', encoding="utf-8"
        )
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_missing_changed_scoped_or_duplicate_replacement_fails(self):
        replacements = {
            "missing": "",
            "other owner": self.replacement.replace(self.fork, "github.com/other/utls"),
            "different version": self.replacement.replace(FORK_VERSION, "v1.0.0"),
            "branch": self.replacement.replace(FORK_VERSION, "main"),
            "local relative": f"replace {self.upstream} => ../utls",
            "local absolute": f"replace {self.upstream} => /tmp/utls",
            "version scoped": self.replacement.replace(" =>", " v1.8.2 =>"),
            "duplicate": self.replacement + "\n" + self.replacement,
            "reversed": f"replace {self.fork} => {self.upstream} {FORK_VERSION}",
        }
        for label, replacement in replacements.items():
            with self.subTest(label=label):
                result = self.check(self.module.replace(self.replacement, replacement))
                self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_upstream_baseline_drift_fails(self):
        result = self.check(self.module.replace(PINS["ALLOWED_UTLS_UPSTREAM_VERSION"], "v1.8.2"))
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_quoted_or_escaped_module_tokens_cannot_bypass_policy(self):
        escaped_upstream = r'"github.com/refraction-networking/\x75tls"'
        escaped_fork = r'"github.com/cppla/\u0075tls"'
        extras = {
            "escaped scoped override": (
                f"replace {escaped_upstream} {PINS['ALLOWED_UTLS_UPSTREAM_VERSION']}"
                " => github.com/other/utls v1.8.2"
            ),
            "escaped dual identity": f"require {escaped_fork} v1.8.2",
            "escaped local path": r'replace example.invalid/other => "\x2e/other"',
            "quoted local path": 'replace example.invalid/other => "./other"',
            "quoted token": 'require "example.invalid/other" v1.0.0',
            "raw quoted token": f"require {chr(96)}example.invalid/other{chr(96)} v1.0.0",
        }
        for label, extra in extras.items():
            with self.subTest(label=label):
                result = self.check(self.module + "\n" + extra + "\n")
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("unquoted, unescaped canonical tokens", result.stdout)

    def test_quotes_and_backslashes_in_module_comments_remain_allowed(self):
        result = self.check(self.module + r'// "quoted", \escaped and `raw` comment' + "\n")
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_escaped_import_paths_cannot_bypass_policy(self):
        sources = (
            r'package fixture; import "github.com/cppla/\x75tls"',
            r'package fixture; import _ "github.com/\u0063ppla/utls"',
            r'package fixture; import alias "github.com/cppla\x2futls"',
            'package fixture\nimport (\n'
            r' _ "github.com/cppla/\165tls"' + '\n)\n',
            r'package fixture; import ("fmt"; alias "github.com/cppla/\x75tls")',
            r'package fixture; import /* comment */ "github.com/cppla/\x75tls"',
        )
        for source in sources:
            with self.subTest(source=source):
                (self.root / "main.go").write_text(source + "\n", encoding="utf-8")
                result = self.check()
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("escaped import path", result.stdout)

    def test_import_like_comments_and_literals_are_not_imports(self):
        (self.root / "main.go").write_text(
            'package fixture\nimport (\n\t"fmt"\n)\n'
            r'// import "github.com/cppla/\x75tls"' + "\n"
            r'/* import ("github.com/cppla/\x75tls") */' + "\n"
            r'var text = "import \"github.com/cppla/\\x75tls\""' + "\n"
            + 'var raw = ' + chr(96) + r'import "github.com/cppla/\x75tls"' + chr(96) + "\n"
            + r"var quote = '\"'" + "\n",
            encoding="utf-8",
        )
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_fork_cannot_be_required_or_imported_directly(self):
        result = self.check(self.module + f"\nrequire {self.fork} {FORK_VERSION}\n")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        (self.root / "main.go").write_text(
            f'package fixture\nimport _ "{self.fork}"\n', encoding="utf-8"
        )
        result = self.check()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("imports the replacement path directly", result.stdout)

    def test_web_quic_pin_and_no_replacement_policy_remain_enforced(self):
        changed = self.module.replace(PINS["ALLOWED_WEB_QUIC_VERSION"], "v0.63.0")
        replaced = self.module + (
            f"\nreplace {PINS['ALLOWED_WEB_QUIC_MODULE']} => github.com/cppla/quic-go v0.63.0\n"
        )
        for module in (changed, replaced):
            result = self.check(module)
            self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_unrelated_local_replace_still_fails(self):
        result = self.check(self.module + "\nreplace example.invalid/other => ./other\n")
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_copied_utls_sources_fail(self):
        for relative in (
            "third_party/utls", "vendor/github.com/refraction-networking/utls",
            "vendor/github.com/cppla/utls",
        ):
            with self.subTest(path=relative):
                directory = self.root / relative
                directory.mkdir(parents=True)
                result = self.check()
                self.assertNotEqual(result.returncode, 0, result.stdout)
                directory.rmdir()

    def test_unpublished_placeholder_fails_closed(self):
        self.script.write_text(
            BOUNDARY.replace(PINS["ALLOWED_UTLS_VERSION"], "TODO_PUBLISHED_CPPLA_UTLS_VERSION"),
            encoding="utf-8",
        )
        result = self.check(self.module.replace(FORK_VERSION, "TODO_PUBLISHED_CPPLA_UTLS_VERSION"))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("published version has not been pinned", result.stdout)

    def test_allowlist_itself_cannot_pin_a_branch(self):
        self.script.write_text(
            BOUNDARY.replace(PINS["ALLOWED_UTLS_VERSION"], "main"), encoding="utf-8"
        )
        result = self.check(self.module.replace(FORK_VERSION, "main"))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("exact published pseudo-version", result.stdout)


class UpstreamAdvisoryGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="autocar-advisory-gate-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def check(self, content=None):
        output = self.root / "query.json"
        if content is not None:
            output.write_text(content, encoding="utf-8")
        return subprocess.run(
            ["bash", str(SCRIPTS / "check-upstream-advisories.sh"), str(output)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
        )

    def test_no_osv_passes(self):
        result = self.check('{\n  "config": {}\n}\n{\n  "progress": {"message": "done"}\n}\n')
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_osv_fails_for_review(self):
        result = self.check(
            '{\n  "config": {}\n}\n{\n  "osv": {"id": "GO-0000-0000"}\n}\n'
        )
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("advisory candidates", result.stdout)

    def test_unreadable_query_fails_instead_of_being_clean(self):
        result = self.check()
        self.assertGreater(result.returncode, 1, result.stdout)
        self.assertIn("could not inspect", result.stdout)


class VulnerabilityWrapperTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="autocar-govuln-wrapper-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.env = os.environ.copy()
        self.env["RUNNER_TEMP"] = str(self.root)
        self.env["PATH"] = str(self.root) + os.pathsep + self.env["PATH"]
        self.env["AUTOCAR_TEST_UPSTREAM_VERSION"] = PINS["ALLOWED_UTLS_UPSTREAM_VERSION"]
        tool = self.root / "fake-govulncheck"
        tool.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n', encoding="utf-8")
        tool.chmod(0o755)
        self.env["AUTOCAR_TEST_VULN_TOOL"] = str(tool)
        fake_go = self.root / "go"
        fake_go.write_text(
            '#!/bin/sh\nset -eu\ncase "$1" in\n'
            'install) cp "$AUTOCAR_TEST_VULN_TOOL" "$GOBIN/govulncheck" ;;\n'
            'list) printf "%s\\n" "$AUTOCAR_TEST_UPSTREAM_VERSION" ;;\n'
            '*) exit 99 ;;\nesac\n', encoding="utf-8",
        )
        fake_go.chmod(0o755)

    def run_wrapper(self, *args):
        return subprocess.run(
            ["bash", str(SCRIPTS / "govulncheck.sh"), *args], cwd=self.root,
            env=self.env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=10,
        )

    def test_source_scan_stays_source_scan(self):
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout.splitlines(), ["./..."])

    def test_query_uses_original_baseline_and_is_not_a_source_scan(self):
        result = self.run_wrapper("--upstream-utls")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout.splitlines(), [
            "-mode=query", "-json",
            f"{PINS['ALLOWED_UTLS_MODULE']}@{PINS['ALLOWED_UTLS_UPSTREAM_VERSION']}",
        ])

    def test_missing_baseline_and_unknown_options_fail(self):
        self.env["AUTOCAR_TEST_UPSTREAM_VERSION"] = ""
        self.assertNotEqual(self.run_wrapper("--upstream-utls").returncode, 0)
        self.assertEqual(self.run_wrapper("--ignore").returncode, 2)

    def test_query_and_source_tool_errors_propagate(self):
        Path(self.env["AUTOCAR_TEST_VULN_TOOL"]).write_text(
            '#!/bin/sh\nexit 42\n', encoding="utf-8"
        )
        for args in ((), ("--upstream-utls",)):
            with self.subTest(args=args):
                result = self.run_wrapper(*args)
                self.assertEqual(result.returncode, 42, result.stdout)

    def test_install_error_propagates(self):
        (self.root / "go").write_text('#!/bin/sh\nexit 43\n', encoding="utf-8")
        result = self.run_wrapper("--upstream-utls")
        self.assertEqual(result.returncode, 43, result.stdout)

    def test_module_query_error_propagates_even_with_partial_output(self):
        (self.root / "go").write_text(
            '#!/bin/sh\nset -eu\ncase "$1" in\n'
            'install) cp "$AUTOCAR_TEST_VULN_TOOL" "$GOBIN/govulncheck" ;;\n'
            'list) printf "%s\\n" "$AUTOCAR_TEST_UPSTREAM_VERSION"; exit 44 ;;\n'
            '*) exit 99 ;;\nesac\n', encoding="utf-8",
        )
        result = self.run_wrapper("--upstream-utls")
        self.assertEqual(result.returncode, 44, result.stdout)


if __name__ == "__main__":
    unittest.main()
