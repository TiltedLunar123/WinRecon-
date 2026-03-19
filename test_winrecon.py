"""
Tests for WinRecon — Windows Security Auditing & Hardening Toolkit
===================================================================
Covers: Finding class, calculate_score, _esc, run_command,
        reg_read, parse_arguments, output parsing logic,
        load_custom_keywords, and exit codes.

These tests are cross-platform: mocked where Windows APIs are needed.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Allow importing winrecon on non-Windows by mocking winreg before import
if sys.platform != "win32":
    sys.modules["winreg"] = MagicMock()

import winrecon
from winrecon import (
    EXIT_CRITICAL,
    EXIT_SUCCESS,
    EXIT_WARNING,
    Finding,
    _esc,
    calculate_score,
)


class TestFinding(unittest.TestCase):
    def test_creation(self) -> None:
        f = Finding("TST-001", "Test", "Test finding", "critical", "A test.", detail="d", remediation="r")
        self.assertEqual(f.check_id, "TST-001")
        self.assertEqual(f.category, "Test")
        self.assertEqual(f.severity, "CRITICAL")  # uppercased
        self.assertEqual(f.detail, "d")
        self.assertEqual(f.remediation, "r")

    def test_to_dict(self) -> None:
        f = Finding("TST-001", "Cat", "Title", "WARNING", "Desc", detail="det", remediation="rem")
        d = f.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["check_id"], "TST-001")
        self.assertEqual(d["severity"], "WARNING")
        self.assertEqual(d["detail"], "det")
        self.assertEqual(d["remediation"], "rem")

    def test_severity_uppercase(self) -> None:
        f = Finding("X-001", "C", "T", "info", "D")
        self.assertEqual(f.severity, "INFO")

    def test_default_fields(self) -> None:
        f = Finding("X-001", "C", "T", "PASS", "D")
        self.assertEqual(f.detail, "")
        self.assertEqual(f.remediation, "")


class TestCalculateScore(unittest.TestCase):
    def test_perfect_score(self) -> None:
        findings = [
            Finding("A-001", "C", "T", "PASS", "D"),
            Finding("A-002", "C", "T", "PASS", "D"),
            Finding("A-003", "C", "T", "INFO", "D"),
        ]
        result = calculate_score(findings)
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["grade"], "A")
        self.assertEqual(result["critical"], 0)
        self.assertEqual(result["warning"], 0)
        self.assertEqual(result["pass"], 2)
        self.assertEqual(result["info"], 1)
        self.assertEqual(result["total_findings"], 3)

    def test_critical_deduction(self) -> None:
        findings = [Finding("C-001", "C", "T", "CRITICAL", "D")]
        result = calculate_score(findings)
        self.assertEqual(result["score"], 80)
        self.assertEqual(result["grade"], "B")
        self.assertEqual(result["critical"], 1)

    def test_warning_deduction(self) -> None:
        findings = [Finding("W-001", "C", "T", "WARNING", "D")]
        result = calculate_score(findings)
        self.assertEqual(result["score"], 90)
        self.assertEqual(result["grade"], "A")
        self.assertEqual(result["warning"], 1)

    def test_floor_at_zero(self) -> None:
        findings = [Finding(f"C-{i:03d}", "C", "T", "CRITICAL", "D") for i in range(10)]
        result = calculate_score(findings)
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["grade"], "F")

    def test_mixed_findings(self) -> None:
        findings = [
            Finding("C-001", "C", "T", "CRITICAL", "D"),
            Finding("C-002", "C", "T", "CRITICAL", "D"),
            Finding("W-001", "C", "T", "WARNING", "D"),
            Finding("P-001", "C", "T", "PASS", "D"),
            Finding("I-001", "C", "T", "INFO", "D"),
        ]
        result = calculate_score(findings)
        # 100 - 20 - 20 - 10 = 50
        self.assertEqual(result["score"], 50)
        self.assertEqual(result["grade"], "D")
        self.assertEqual(result["critical"], 2)
        self.assertEqual(result["warning"], 1)
        self.assertEqual(result["pass"], 1)
        self.assertEqual(result["info"], 1)
        self.assertEqual(result["total_findings"], 5)

    def test_empty_findings(self) -> None:
        result = calculate_score([])
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["grade"], "A")
        self.assertEqual(result["total_findings"], 0)

    def test_grade_boundaries(self) -> None:
        # Grade B: 80-89
        findings_b = [Finding("C-001", "C", "T", "CRITICAL", "D")]
        self.assertEqual(calculate_score(findings_b)["grade"], "B")

        # Grade C: 60-79 (3 warnings = 100-30 = 70)
        findings_c = [Finding(f"W-{i:03d}", "C", "T", "WARNING", "D") for i in range(3)]
        self.assertEqual(calculate_score(findings_c)["grade"], "C")

        findings_c2 = [
            Finding("C-001", "C", "T", "CRITICAL", "D"),
            Finding("W-001", "C", "T", "WARNING", "D"),
        ]
        self.assertEqual(calculate_score(findings_c2)["grade"], "C")  # 100-20-10=70

        # Grade D: 40-59
        findings_d = [
            Finding("C-001", "C", "T", "CRITICAL", "D"),
            Finding("C-002", "C", "T", "CRITICAL", "D"),
            Finding("W-001", "C", "T", "WARNING", "D"),
            Finding("W-002", "C", "T", "WARNING", "D"),
        ]
        self.assertEqual(calculate_score(findings_d)["grade"], "D")  # 100-40-20=40


class TestHtmlEscape(unittest.TestCase):
    def test_basic_escaping(self) -> None:
        self.assertEqual(_esc("<script>alert('xss')</script>"),
                         "&lt;script&gt;alert('xss')&lt;/script&gt;")

    def test_ampersand(self) -> None:
        self.assertEqual(_esc("A & B"), "A &amp; B")

    def test_quotes(self) -> None:
        self.assertEqual(_esc('He said "hello"'), "He said &quot;hello&quot;")

    def test_no_escaping_needed(self) -> None:
        self.assertEqual(_esc("plain text"), "plain text")

    def test_empty_string(self) -> None:
        self.assertEqual(_esc(""), "")

    def test_combined(self) -> None:
        self.assertEqual(_esc('<a href="x">&</a>'),
                         '&lt;a href=&quot;x&quot;&gt;&amp;&lt;/a&gt;')


class TestRunCommand(unittest.TestCase):
    @patch("winrecon.subprocess.run")
    def test_success(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(stdout="hello world\n")
        result = winrecon.run_command("echo hello world")
        self.assertEqual(result, "hello world")

    @patch("winrecon.subprocess.run")
    def test_timeout(self, mock_run: MagicMock) -> None:
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="test", timeout=60)
        result = winrecon.run_command("slow_command")
        self.assertEqual(result, "")

    @patch("winrecon.subprocess.run")
    def test_exception(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = OSError("command not found")
        result = winrecon.run_command("nonexistent")
        self.assertEqual(result, "")

    @patch("winrecon.subprocess.run")
    def test_custom_timeout(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(stdout="ok\n")
        winrecon.run_command("cmd", timeout=120)
        _, kwargs = mock_run.call_args
        self.assertEqual(kwargs["timeout"], 120)


class TestRegRead(unittest.TestCase):
    @patch("winrecon.winreg")
    def test_success(self, mock_winreg: MagicMock) -> None:
        mock_key = MagicMock()
        mock_winreg.OpenKey.return_value.__enter__ = MagicMock(return_value=mock_key)
        mock_winreg.OpenKey.return_value.__exit__ = MagicMock(return_value=False)
        mock_winreg.QueryValueEx.return_value = (42, 4)
        result = winrecon.reg_read(mock_winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Test", "Value")
        self.assertEqual(result, 42)

    @patch("winrecon.winreg")
    def test_missing_key(self, mock_winreg: MagicMock) -> None:
        mock_winreg.OpenKey.side_effect = FileNotFoundError
        result = winrecon.reg_read(mock_winreg.HKEY_LOCAL_MACHINE, r"MISSING", "Value", default="fallback")
        self.assertEqual(result, "fallback")

    @patch("winrecon.winreg")
    def test_os_error(self, mock_winreg: MagicMock) -> None:
        mock_winreg.OpenKey.side_effect = OSError
        result = winrecon.reg_read(mock_winreg.HKEY_LOCAL_MACHINE, r"BAD", "Value", default=None)
        self.assertIsNone(result)


class TestRegEnumValues(unittest.TestCase):
    @patch("winrecon.winreg")
    def test_empty(self, mock_winreg: MagicMock) -> None:
        mock_winreg.OpenKey.side_effect = FileNotFoundError
        result = winrecon.reg_enum_values(mock_winreg.HKEY_LOCAL_MACHINE, r"MISSING")
        self.assertEqual(result, {})


class TestLoadCustomKeywords(unittest.TestCase):
    def test_load_valid_keywords(self) -> None:
        original_keywords = winrecon.SUSPICIOUS_TASK_KEYWORDS[:]
        original_paths = winrecon.TRUSTED_TASK_PATHS[:]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump({
                "suspicious_keywords": ["custom_keyword_1", "custom_keyword_2"],
                "trusted_paths": ["\\Custom\\"],
            }, f)
            tmp_path = f.name

        try:
            log = MagicMock()
            winrecon.load_custom_keywords(tmp_path, log)
            self.assertEqual(winrecon.SUSPICIOUS_TASK_KEYWORDS, ["custom_keyword_1", "custom_keyword_2"])
            self.assertEqual(winrecon.TRUSTED_TASK_PATHS, ["\\Custom\\"])
        finally:
            winrecon.SUSPICIOUS_TASK_KEYWORDS = original_keywords
            winrecon.TRUSTED_TASK_PATHS = original_paths
            os.unlink(tmp_path)

    def test_load_invalid_json(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            f.write("not json{{{")
            tmp_path = f.name

        try:
            log = MagicMock()
            with self.assertRaises(SystemExit):
                winrecon.load_custom_keywords(tmp_path, log)
        finally:
            os.unlink(tmp_path)

    def test_load_missing_file(self) -> None:
        log = MagicMock()
        with self.assertRaises(SystemExit):
            winrecon.load_custom_keywords("/nonexistent/path.json", log)


class TestExportJson(unittest.TestCase):
    def test_valid_json_output(self) -> None:
        system_info = {
            "hostname": "TEST",
            "os": "Windows-Test",
            "is_admin": False,
            "scan_time": "2026-03-19 10:00:00",
        }
        findings = [
            Finding("TST-001", "Test", "Test finding", "PASS", "Description"),
            Finding("TST-002", "Test", "Warning finding", "WARNING", "Desc", remediation="Fix it"),
        ]
        score_data = calculate_score(findings)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmp_path = Path(f.name)

        try:
            log = MagicMock()
            winrecon.export_json(system_info, findings, score_data, tmp_path, log)

            with open(tmp_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            self.assertEqual(data["tool"], "WinRecon")
            self.assertEqual(data["version"], winrecon.VERSION)
            self.assertEqual(len(data["findings"]), 2)
            self.assertEqual(data["score"]["score"], 90)
            self.assertEqual(data["score"]["grade"], "A")
        finally:
            os.unlink(tmp_path)


class TestExitCodes(unittest.TestCase):
    def test_exit_code_values(self) -> None:
        self.assertEqual(EXIT_SUCCESS, 0)
        self.assertEqual(EXIT_WARNING, 1)
        self.assertEqual(EXIT_CRITICAL, 2)
        self.assertEqual(winrecon.EXIT_ERROR, 3)

    def test_critical_findings_return_code(self) -> None:
        score = calculate_score([Finding("C-001", "C", "T", "CRITICAL", "D")])
        if score["critical"] > 0:
            code = EXIT_CRITICAL
        elif score["warning"] > 0:
            code = EXIT_WARNING
        else:
            code = EXIT_SUCCESS
        self.assertEqual(code, EXIT_CRITICAL)

    def test_warning_findings_return_code(self) -> None:
        score = calculate_score([Finding("W-001", "C", "T", "WARNING", "D")])
        if score["critical"] > 0:
            code = EXIT_CRITICAL
        elif score["warning"] > 0:
            code = EXIT_WARNING
        else:
            code = EXIT_SUCCESS
        self.assertEqual(code, EXIT_WARNING)

    def test_clean_findings_return_code(self) -> None:
        score = calculate_score([Finding("P-001", "C", "T", "PASS", "D")])
        if score["critical"] > 0:
            code = EXIT_CRITICAL
        elif score["warning"] > 0:
            code = EXIT_WARNING
        else:
            code = EXIT_SUCCESS
        self.assertEqual(code, EXIT_SUCCESS)


class TestParseArguments(unittest.TestCase):
    def test_defaults(self) -> None:
        with patch("sys.argv", ["winrecon.py"]):
            args = winrecon.parse_arguments()
            self.assertFalse(args.json_only)
            self.assertFalse(args.no_html)
            self.assertFalse(args.verbose)
            self.assertFalse(args.quiet)
            self.assertEqual(args.timeout, winrecon.DEFAULT_TIMEOUT)
            self.assertIsNone(args.keywords_file)

    def test_custom_timeout(self) -> None:
        with patch("sys.argv", ["winrecon.py", "--timeout", "120"]):
            args = winrecon.parse_arguments()
            self.assertEqual(args.timeout, 120)

    def test_quiet_flag(self) -> None:
        with patch("sys.argv", ["winrecon.py", "--quiet"]):
            args = winrecon.parse_arguments()
            self.assertTrue(args.quiet)

    def test_keywords_file(self) -> None:
        with patch("sys.argv", ["winrecon.py", "--keywords-file", "custom.json"]):
            args = winrecon.parse_arguments()
            self.assertEqual(args.keywords_file, "custom.json")

    def test_short_flags(self) -> None:
        with patch("sys.argv", ["winrecon.py", "-q", "-t", "30", "-o", "/tmp/out"]):
            args = winrecon.parse_arguments()
            self.assertTrue(args.quiet)
            self.assertEqual(args.timeout, 30)
            self.assertEqual(args.output_dir, "/tmp/out")


class TestSeverityWeight(unittest.TestCase):
    def test_weights_defined(self) -> None:
        self.assertEqual(winrecon.SEVERITY_WEIGHT["CRITICAL"], 20)
        self.assertEqual(winrecon.SEVERITY_WEIGHT["WARNING"], 10)
        self.assertEqual(winrecon.SEVERITY_WEIGHT["INFO"], 0)
        self.assertEqual(winrecon.SEVERITY_WEIGHT["PASS"], 0)


class TestGenerateHtmlReport(unittest.TestCase):
    def test_html_output_created(self) -> None:
        system_info = {
            "hostname": "TEST",
            "os": "Windows-Test",
            "os_version": "10.0",
            "architecture": "AMD64",
            "current_user": "tester",
            "is_admin": True,
            "python_version": "3.11",
            "scan_time": "2026-03-19 10:00:00",
            "domain": "WORKGROUP",
            "ip_addresses": ["192.168.1.1"],
            "processor": "Test CPU",
        }
        findings = [
            Finding("TST-001", "Test", "All good", "PASS", "Everything is fine."),
            Finding("TST-002", "Test", "Issue found", "CRITICAL", "Bad thing.",
                    detail="Details here", remediation="Fix it."),
        ]
        score_data = calculate_score(findings)

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            tmp_path = Path(f.name)

        try:
            log = MagicMock()
            winrecon.generate_html_report(system_info, findings, score_data, tmp_path, log)

            content = tmp_path.read_text(encoding="utf-8")
            self.assertIn("<!DOCTYPE html>", content)
            self.assertIn("WinRecon", content)
            self.assertIn("TEST", content)
            self.assertIn("CRITICAL", content)
            self.assertIn("PASS", content)
            self.assertIn("Fix it.", content)
            self.assertIn("80/100", content)
        finally:
            os.unlink(tmp_path)

    def test_html_escapes_xss(self) -> None:
        system_info = {
            "hostname": "<script>alert(1)</script>",
            "os": "Win",
            "os_version": "10",
            "architecture": "x64",
            "current_user": "user",
            "is_admin": False,
            "python_version": "3.11",
            "scan_time": "2026-01-01 00:00:00",
            "domain": "DOM",
            "ip_addresses": ["127.0.0.1"],
            "processor": "CPU",
        }
        findings = [Finding("X-001", "X", "<img onerror=alert(1)>", "PASS", "D")]
        score_data = calculate_score(findings)

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            tmp_path = Path(f.name)

        try:
            log = MagicMock()
            winrecon.generate_html_report(system_info, findings, score_data, tmp_path, log)
            content = tmp_path.read_text(encoding="utf-8")
            self.assertNotIn("<script>", content)
            self.assertNotIn("<img onerror", content)
            self.assertIn("&lt;script&gt;", content)
        finally:
            os.unlink(tmp_path)


if __name__ == "__main__":
    unittest.main()
