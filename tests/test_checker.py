"""Deterministic checks for the inventory; no PHP service or exploit is required."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "oneshot-checker.py"
spec = importlib.util.spec_from_file_location("oneshot_checker", SCRIPT)
assert spec and spec.loader
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class ReleaseAndConfigurationTests(unittest.TestCase):
    def test_upstream_boundaries(self):
        self.assertEqual(checker.release_status("PHP 8.5.11"), "BELOW_UPSTREAM_FIX")
        self.assertEqual(checker.release_status("PHP 8.5.12"), "FIXED_UPSTREAM")
        self.assertEqual(checker.release_status("8.4.26"), "BELOW_UPSTREAM_FIX")
        self.assertEqual(checker.release_status("8.4.27"), "FIXED_UPSTREAM")
        self.assertEqual(checker.release_status("8.5.12RC1"), "PRERELEASE_REVIEW")
        self.assertEqual(checker.release_status("8.1.30"), "OUTSIDE_SUPPORTED_MATRIX")

    def test_setting_parsers(self):
        self.assertIs(checker.enabled("On"), True)
        self.assertIs(checker.enabled("0"), False)
        self.assertIsNone(checker.enabled(None))
        self.assertEqual(checker.size_bytes("128M"), 128 * 1024 * 1024)
        self.assertEqual(checker.size_bytes("-1"), -1)
        self.assertIsNone(checker.size_bytes("unavailable"))

    def test_php_cli_parses_effective_settings(self):
        output = ("PHP Version => 8.5.12\nServer API => Command Line Interface\n"
                  "memory_limit => 128M => 128M\n"
                  "session.upload_progress.enabled => On => On\n")
        result = SimpleNamespace(returncode=0, stdout=output, stderr="")
        with patch.object(checker.shutil, "which", return_value=sys.executable), \
             patch.object(checker.subprocess, "run", return_value=result):
            report = checker.php_cli("php", None)
        self.assertEqual(report["version"], "8.5.12")
        self.assertEqual(report["settings"]["memory_limit"], "128M")
        self.assertEqual(report["settings"]["session.upload_progress.enabled"], "On")


class SourceAndPathTests(unittest.TestCase):
    def test_comment_text_is_masked_but_code_is_preserved(self):
        source = ("<?php\n"
                  "// ini_set('session.serialize_handler', 'php'); session_start();\n"
                  "/* unserialize($_POST['x']); */\n"
                  "ini_set('session.serialize_handler', 'php');\n"
                  "session_start();\n")
        masked = checker.mask_php_comments(source)
        self.assertEqual(len(masked), len(source))
        self.assertEqual(masked.count("ini_set"), 1)
        self.assertNotIn("unserialize", masked)

    def test_three_path_leads_and_115560_published_pattern(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "index.php").write_text(
                "<?php\n"
                "ini_set('session.serialize_handler', 'php');\n"
                "session_start();\n"
                "include $_GET['page'];\n"
                "unserialize($_POST['value']);\n"
                "class Example { function __destruct() {} }\n",
                encoding="utf-8",
            )
            scan = checker.source_scan(root, 2000)
        runtime = {"kind": "web", "version": "8.5.12", "sapi": "apache2handler",
                   "settings": {"memory_limit": "128M", "post_max_size": "256M",
                                "session.upload_progress.enabled": "On",
                                "session.serialize_handler": "php_serialize",
                                "session.save_handler": "files"}}
        result = checker.findings(runtime, [scan])
        self.assertEqual(result["CVE-2026-109618"]["release"], "FIXED_UPSTREAM")
        self.assertEqual(result["handler_mismatch_CVE-2026-115560"]["status"],
                         "PUBLISHED_PREREQUISITES_OBSERVED")
        cli_profile = dict(runtime, kind="cli")
        self.assertEqual(checker.findings(cli_profile, [scan])["handler_mismatch_CVE-2026-115560"]["status"],
                         "CLI_PROFILE_MATCH_REVIEW")
        self.assertEqual(result["upload_progress_include"]["status"], "SOURCE_AND_STORAGE_LEADS_REVIEW")
        self.assertEqual(result["var_destroy"]["status"], "SOURCE_LEADS_REVIEW")

    def test_upload_progress_disabled_breaks_published_path(self):
        runtime = {"kind": "web", "version": "8.5.12", "sapi": "fpm-fcgi",
                   "settings": {"session.upload_progress.enabled": "Off",
                                "session.serialize_handler": "php_serialize"}}
        result = checker.findings(runtime, [])
        self.assertEqual(result["handler_mismatch_CVE-2026-115560"]["status"],
                         "PUBLISHED_PATH_DISABLED_BY_CONFIG")
        self.assertEqual(result["upload_progress_include"]["status"], "UPLOAD_PROGRESS_DISABLED")

    def test_unreadable_source_is_reported(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "blocked.php").write_text("<?php session_start();", encoding="utf-8")
            original = Path.read_text

            def read_or_fail(path, *args, **kwargs):
                if path.name == "blocked.php":
                    raise PermissionError("simulated unreadable source")
                return original(path, *args, **kwargs)

            with patch.object(Path, "read_text", read_or_fail):
                scan = checker.source_scan(root, 2000)
        self.assertEqual(scan["read_error_count"], 1)
        self.assertEqual(scan["files_scanned"], 0)

    def test_unscanned_source_is_never_labelled_clear(self):
        runtime = {"kind": "cli", "version": "8.5.12", "sapi": "CLI",
                   "settings": {"session.upload_progress.enabled": "On",
                                "session.serialize_handler": "php"}}
        result = checker.findings(runtime, [])
        for path in ("handler_mismatch_CVE-2026-115560", "upload_progress_include", "var_destroy"):
            self.assertEqual(result[path]["status"], "SOURCE_NOT_SCANNED")

    def test_truncated_source_without_leads_is_incomplete(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a.php").write_text("<?php echo 1;", encoding="utf-8")
            (root / "b.php").write_text("<?php echo 2;", encoding="utf-8")
            scan = checker.source_scan(root, 1)
        self.assertTrue(scan["truncated"])
        runtime = {"kind": "web", "version": "8.5.12", "sapi": "cli-server",
                   "settings": {"session.upload_progress.enabled": "On",
                                "session.serialize_handler": "php"}}
        result = checker.findings(runtime, [scan])
        self.assertEqual(result["handler_mismatch_CVE-2026-115560"]["status"], "INCOMPLETE_SOURCE_SCAN")


class HttpAndProbeTests(unittest.TestCase):
    def test_origin_check(self):
        self.assertTrue(checker.same_origin("https://example.test/x", "https://example.test/y"))
        self.assertFalse(checker.same_origin("https://example.test/x", "http://example.test/x"))
        self.assertFalse(checker.same_origin("https://example.test/x", "https://other.test/x"))

    def test_web_probe_checks_token_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def fake_fetch(url, timeout, insecure):
                staged = list(root.glob("oneshot-audit-*.php"))
                self.assertEqual(len(staged), 1)
                token = staged[0].stem.removeprefix("oneshot-audit-")
                body = json.dumps({"token": token, "version": "8.5.12", "sapi": "cli-server",
                                   "settings": {"session.upload_progress.enabled": "1"}}).encode()
                return {"status": 200, "body": body}
            with patch.object(checker, "fetch", side_effect=fake_fetch):
                report = checker.web_probe("http://127.0.0.1:8080/index.php", temp, 5, False)
            self.assertEqual(report["version"], "8.5.12")
            self.assertEqual(list(root.glob("oneshot-audit-*.php")), [])

    def test_wrong_diagnostic_token_is_rejected_and_cleaned_up(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            response = {"status": 200, "body": b'{"token":"wrong","settings":{}}'}
            with patch.object(checker, "fetch", return_value=response):
                with self.assertRaises(ValueError):
                    checker.web_probe("http://localhost:8080/index.php", temp, 5, False)
            self.assertEqual(list(root.glob("oneshot-audit-*.php")), [])

    def test_remote_hidden_version_is_unknown(self):
        page = {"url": "http://example.test/index.php", "status": 200,
                "headers": {}, "body": b"<p>PHP Version 8.5.11 is mentioned in an article</p>"}
        with patch.object(checker, "fetch", return_value=page):
            report = checker.remote_inventory(page["url"], 5, False, False)
        self.assertEqual(report["core_release"], "UNKNOWN_VERSION")

    def test_remote_disclosed_header_is_classified(self):
        page = {"url": "http://example.test/index.php", "status": 200,
                "headers": {"X-Powered-By": "PHP/8.5.12"}, "body": b"ready"}
        with patch.object(checker, "fetch", return_value=page):
            report = checker.remote_inventory(page["url"], 5, False, False)
        self.assertEqual(report["core_release"], "FIXED_UPSTREAM")

    def test_phpinfo_body_requires_diagnostic_signature(self):
        page = {"url": "http://example.test/phpinfo.php", "status": 200,
                "headers": {}, "body": b"<title>phpinfo()</title><h1>PHP Version 8.5.11</h1>"}
        with patch.object(checker, "fetch", return_value=page):
            report = checker.remote_inventory(page["url"], 5, False, False)
        self.assertEqual(report["core_release"], "BELOW_UPSTREAM_FIX")

    def test_remote_connection_failure_is_an_error(self):
        failed = {"url": "http://example.test/", "status": None,
                  "headers": {}, "body": b"", "error": "connection refused"}
        with patch.object(checker, "fetch", return_value=failed):
            with self.assertRaises(ValueError):
                checker.remote_inventory(failed["url"], 5, False, False)


if __name__ == "__main__":
    unittest.main()
