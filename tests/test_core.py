"""Tests for winrecon.core. Finding, scoring, escaping, and utilities."""

import sys
import unittest
from unittest.mock import MagicMock, patch

# Allow importing on non-Windows by mocking winreg before import
if sys.platform != "win32":
    sys.modules["winreg"] = MagicMock()

import winrecon.core as core_mod
from winrecon.core import (
    EXIT_CRITICAL,
    EXIT_ERROR,
    EXIT_SUCCESS,
    EXIT_WARNING,
    SEVERITY_WEIGHT,
    Finding,
    _esc,
    calculate_score,
)


class TestFinding(unittest.TestCase):
    def test_creation(self) -> None:
        f = Finding("TST-001", "Test", "Test finding", "critical", "A test.", detail="d", remediation="r")
        self.assertEqual(f.check_id, "TST-001")
        self.assertEqual(f.category, "Test")
        self.assertEqual(f.severity, "CRITICAL")
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
        findings_b = [Finding("C-001", "C", "T", "CRITICAL", "D")]
        self.assertEqual(calculate_score(findings_b)["grade"], "B")

        findings_c = [Finding(f"W-{i:03d}", "C", "T", "WARNING", "D") for i in range(3)]
        self.assertEqual(calculate_score(findings_c)["grade"], "C")

        findings_c2 = [
            Finding("C-001", "C", "T", "CRITICAL", "D"),
            Finding("W-001", "C", "T", "WARNING", "D"),
        ]
        self.assertEqual(calculate_score(findings_c2)["grade"], "C")

        findings_d = [
            Finding("C-001", "C", "T", "CRITICAL", "D"),
            Finding("C-002", "C", "T", "CRITICAL", "D"),
            Finding("W-001", "C", "T", "WARNING", "D"),
            Finding("W-002", "C", "T", "WARNING", "D"),
        ]
        self.assertEqual(calculate_score(findings_d)["grade"], "D")


class TestHtmlEscape(unittest.TestCase):
    def test_basic_escaping(self) -> None:
        self.assertEqual(_esc("<script>alert('xss')</script>"),
                         "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;")

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
    @patch("winrecon.core.subprocess.run")
    def test_success(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(stdout="hello world\n")
        result = core_mod.run_command("echo hello world")
        self.assertEqual(result, "hello world")

    @patch("winrecon.core.subprocess.run")
    def test_timeout(self, mock_run: MagicMock) -> None:
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="test", timeout=60)
        result = core_mod.run_command("slow_command")
        self.assertEqual(result, "")

    @patch("winrecon.core.subprocess.run")
    def test_exception(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = OSError("command not found")
        result = core_mod.run_command("nonexistent")
        self.assertEqual(result, "")

    @patch("winrecon.core.subprocess.run")
    def test_custom_timeout(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(stdout="ok\n")
        core_mod.run_command("cmd", timeout=120)
        _, kwargs = mock_run.call_args
        self.assertEqual(kwargs["timeout"], 120)


class TestRegRead(unittest.TestCase):
    @patch("winrecon.core.winreg")
    def test_success(self, mock_winreg: MagicMock) -> None:
        mock_key = MagicMock()
        mock_winreg.OpenKey.return_value.__enter__ = MagicMock(return_value=mock_key)
        mock_winreg.OpenKey.return_value.__exit__ = MagicMock(return_value=False)
        mock_winreg.QueryValueEx.return_value = (42, 4)
        result = core_mod.reg_read(mock_winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Test", "Value")
        self.assertEqual(result, 42)

    @patch("winrecon.core.winreg")
    def test_missing_key(self, mock_winreg: MagicMock) -> None:
        mock_winreg.OpenKey.side_effect = FileNotFoundError
        result = core_mod.reg_read(mock_winreg.HKEY_LOCAL_MACHINE, r"MISSING", "Value", default="fallback")
        self.assertEqual(result, "fallback")

    @patch("winrecon.core.winreg")
    def test_os_error(self, mock_winreg: MagicMock) -> None:
        mock_winreg.OpenKey.side_effect = OSError
        result = core_mod.reg_read(mock_winreg.HKEY_LOCAL_MACHINE, r"BAD", "Value", default=None)
        self.assertIsNone(result)


class TestRegEnumValues(unittest.TestCase):
    @patch("winrecon.core.winreg")
    def test_empty(self, mock_winreg: MagicMock) -> None:
        mock_winreg.OpenKey.side_effect = FileNotFoundError
        result = core_mod.reg_enum_values(mock_winreg.HKEY_LOCAL_MACHINE, r"MISSING")
        self.assertEqual(result, {})


class TestExitCodes(unittest.TestCase):
    def test_exit_code_values(self) -> None:
        self.assertEqual(EXIT_SUCCESS, 0)
        self.assertEqual(EXIT_WARNING, 1)
        self.assertEqual(EXIT_CRITICAL, 2)
        self.assertEqual(EXIT_ERROR, 3)

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


class TestSeverityWeight(unittest.TestCase):
    def test_weights_defined(self) -> None:
        self.assertEqual(SEVERITY_WEIGHT["CRITICAL"], 20)
        self.assertEqual(SEVERITY_WEIGHT["WARNING"], 10)
        self.assertEqual(SEVERITY_WEIGHT["INFO"], 0)
        self.assertEqual(SEVERITY_WEIGHT["PASS"], 0)


if __name__ == "__main__":
    unittest.main()
