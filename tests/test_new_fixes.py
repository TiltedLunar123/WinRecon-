"""Tests for v4.1.0 fixes — severity validation, repr/eq, timeout passthrough,
duplicate check IDs, empty report, schema validation, run_all_checks error handling."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

if sys.platform != "win32":
    sys.modules["winreg"] = MagicMock()

from winrecon.core import (
    VALID_SEVERITIES,
    Finding,
    _esc,
    calculate_score,
)
from winrecon.reporting import export_json, generate_html_report


class TestFindingSeverityValidation(unittest.TestCase):
    def test_valid_severities_accepted(self) -> None:
        for sev in ("CRITICAL", "WARNING", "INFO", "PASS"):
            f = Finding("T-001", "Test", "Title", sev, "Desc")
            self.assertEqual(f.severity, sev)

    def test_lowercase_severity_normalized(self) -> None:
        f = Finding("T-001", "Test", "Title", "critical", "Desc")
        self.assertEqual(f.severity, "CRITICAL")

    def test_invalid_severity_raises(self) -> None:
        with self.assertRaises(ValueError):
            Finding("T-001", "Test", "Title", "HIGH", "Desc")

    def test_invalid_severity_message(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            Finding("T-001", "Test", "Title", "DANGER", "Desc")
        self.assertIn("DANGER", str(ctx.exception))

    def test_valid_severities_constant(self) -> None:
        self.assertEqual(VALID_SEVERITIES, {"CRITICAL", "WARNING", "INFO", "PASS"})


class TestFindingReprAndEq(unittest.TestCase):
    def test_repr(self) -> None:
        f = Finding("TST-001", "Cat", "My Title", "PASS", "Desc")
        r = repr(f)
        self.assertIn("TST-001", r)
        self.assertIn("PASS", r)
        self.assertIn("My Title", r)

    def test_eq_same(self) -> None:
        f1 = Finding("T-001", "C", "Title", "PASS", "D", detail="x", remediation="y")
        f2 = Finding("T-001", "C", "Title", "PASS", "D", detail="x", remediation="y")
        self.assertEqual(f1, f2)

    def test_eq_different(self) -> None:
        f1 = Finding("T-001", "C", "Title", "PASS", "D")
        f2 = Finding("T-002", "C", "Title", "PASS", "D")
        self.assertNotEqual(f1, f2)

    def test_eq_not_finding(self) -> None:
        f = Finding("T-001", "C", "Title", "PASS", "D")
        self.assertNotEqual(f, "not a finding")


class TestEscSingleQuotes(unittest.TestCase):
    def test_single_quotes_escaped(self) -> None:
        result = _esc("it's a test")
        self.assertNotIn("'", result)
        self.assertIn("&#x27;", result)

    def test_double_quotes_escaped(self) -> None:
        result = _esc('say "hello"')
        self.assertIn("&quot;", result)


class TestTimeoutPassthrough(unittest.TestCase):
    @patch("winrecon.core.subprocess.run")
    def test_default_timeout_used(self, mock_run: MagicMock) -> None:
        from winrecon.core import DEFAULT_TIMEOUT, run_command
        mock_run.return_value = MagicMock(stdout="ok\n", stderr="")
        run_command("echo test")
        _, kwargs = mock_run.call_args
        self.assertEqual(kwargs["timeout"], DEFAULT_TIMEOUT)

    @patch("winrecon.core.subprocess.run")
    def test_custom_timeout_used(self, mock_run: MagicMock) -> None:
        from winrecon.core import run_command
        mock_run.return_value = MagicMock(stdout="ok\n", stderr="")
        run_command("echo test", timeout=999)
        _, kwargs = mock_run.call_args
        self.assertEqual(kwargs["timeout"], 999)

    @patch("winrecon.core.subprocess.run")
    def test_runtime_default_timeout_change(self, mock_run: MagicMock) -> None:
        import winrecon.core as core
        mock_run.return_value = MagicMock(stdout="ok\n", stderr="")
        original = core.DEFAULT_TIMEOUT
        try:
            core.DEFAULT_TIMEOUT = 200
            core.run_command("echo test")
            _, kwargs = mock_run.call_args
            self.assertEqual(kwargs["timeout"], 200)
        finally:
            core.DEFAULT_TIMEOUT = original


class TestStderrLogging(unittest.TestCase):
    @patch("winrecon.core.subprocess.run")
    def test_stderr_logged(self, mock_run: MagicMock) -> None:
        from winrecon.core import run_command
        mock_run.return_value = MagicMock(stdout="ok\n", stderr="some warning\n")
        with patch("winrecon.core.logging.getLogger") as mock_logger:
            mock_log = MagicMock()
            mock_logger.return_value = mock_log
            run_command("test_cmd")
            debug_calls = [str(c) for c in mock_log.debug.call_args_list]
            self.assertTrue(any("stderr" in c.lower() or "warning" in c.lower() for c in debug_calls))


class TestDuplicateCheckIds(unittest.TestCase):
    @patch("winrecon.checks.run_command")
    def test_local_users_unique_ids(self, mock_cmd: MagicMock) -> None:
        from winrecon.checks import check_local_users
        mock_cmd.return_value = (
            "Node,Disabled,Lockout,Name,PasswordChangeable,PasswordExpires,PasswordRequired,SID\n"
            "PC,FALSE,FALSE,TestUser,TRUE,TRUE,TRUE,S-1-5-21-123-1001\n"
        )
        findings = check_local_users(MagicMock())
        ids = [f.check_id for f in findings]
        # Info summary should be USR-006, not USR-001
        self.assertIn("USR-006", ids)

    @patch("winrecon.checks.run_command")
    def test_open_ports_unique_ids(self, mock_cmd: MagicMock) -> None:
        from winrecon.checks import check_open_ports
        mock_cmd.return_value = (
            "  TCP    0.0.0.0:80       0.0.0.0:0       LISTENING       1234\n"
        )
        findings = check_open_ports(MagicMock())
        ids = [f.check_id for f in findings]
        # Summary should be NET-002, not NET-001
        self.assertIn("NET-002", ids)


class TestEmptyHtmlReport(unittest.TestCase):
    def test_empty_findings_html(self) -> None:
        system_info = {
            "hostname": "TEST",
            "os": "Windows-Test",
            "os_version": "10.0",
            "architecture": "AMD64",
            "current_user": "tester",
            "is_admin": True,
            "python_version": "3.11",
            "scan_time": "2026-04-08 12:00:00",
            "domain": "WORKGROUP",
            "ip_addresses": ["10.0.0.1"],
            "processor": "CPU",
        }
        findings = []  # type: ignore[var-annotated]
        score_data = calculate_score(findings)

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            tmp_path = Path(f.name)
        try:
            log = MagicMock()
            generate_html_report(system_info, findings, score_data, tmp_path, log)
            content = tmp_path.read_text(encoding="utf-8")
            self.assertIn("<!DOCTYPE html>", content)
            self.assertIn("100/100", content)
        finally:
            os.unlink(tmp_path)


class TestSchemaValidation(unittest.TestCase):
    def test_json_output_matches_schema(self) -> None:
        system_info = {
            "hostname": "TEST",
            "os": "Windows-Test",
            "os_version": "10.0",
            "architecture": "AMD64",
            "processor": "CPU",
            "current_user": "tester",
            "is_admin": True,
            "python_version": "3.11",
            "scan_time": "2026-04-08 12:00:00",
            "domain": "WORKGROUP",
            "ip_addresses": ["10.0.0.1"],
        }
        findings = [
            Finding("TST-001", "Test", "Test finding", "PASS", "OK"),
            Finding("TST-002", "Test", "Warning", "WARNING", "Bad", remediation="Fix"),
        ]
        score_data = calculate_score(findings)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmp_path = Path(f.name)
        try:
            log = MagicMock()
            export_json(system_info, findings, score_data, tmp_path, log)
            with open(tmp_path, encoding="utf-8") as fh:
                data = json.load(fh)

            # Validate required top-level keys
            for key in ("tool", "version", "author", "system_info", "score", "findings"):
                self.assertIn(key, data)

            # Validate system_info required keys
            for key in ("hostname", "os", "os_version", "architecture",
                        "current_user", "is_admin", "python_version", "scan_time"):
                self.assertIn(key, data["system_info"])

            # Validate score keys
            for key in ("score", "grade", "critical", "warning", "pass", "info", "total_findings"):
                self.assertIn(key, data["score"])
            self.assertTrue(0 <= data["score"]["score"] <= 100)
            self.assertIn(data["score"]["grade"], ("A", "B", "C", "D", "F"))

            # Validate findings
            for finding in data["findings"]:
                for key in ("check_id", "category", "title", "severity", "description"):
                    self.assertIn(key, finding)
                self.assertIn(finding["severity"], ("CRITICAL", "WARNING", "INFO", "PASS"))
        finally:
            os.unlink(tmp_path)


class TestRunAllChecksErrorHandling(unittest.TestCase):
    @patch("winrecon.checks.reg_enum_values")
    @patch("winrecon.checks.reg_read")
    @patch("winrecon.checks.run_command")
    def test_check_exception_produces_finding(
        self, mock_cmd: MagicMock, mock_reg: MagicMock, mock_enum: MagicMock
    ) -> None:
        from winrecon.checks import run_all_checks

        call_count = [0]

        def failing_run_command(cmd: str, **kwargs: object) -> str:
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("Simulated failure")
            return ""

        mock_cmd.side_effect = failing_run_command
        mock_reg.return_value = None
        mock_enum.return_value = {}

        log = MagicMock()
        findings = run_all_checks(log)
        error_findings = [f for f in findings if f.check_id == "ERR-000"]
        self.assertTrue(len(error_findings) >= 1)


class TestHostnameAtScanTime(unittest.TestCase):
    def test_get_hostname_callable(self) -> None:
        from winrecon.core import _get_hostname
        result = _get_hostname()
        self.assertIsInstance(result, str)
        self.assertTrue(len(result) > 0)

    def test_hostname_shared_between_modules(self) -> None:
        from winrecon.checks import _get_hostname as checks_hostname
        from winrecon.core import _get_hostname as core_hostname
        self.assertIs(checks_hostname, core_hostname)


class TestFindingHash(unittest.TestCase):
    def test_hashable(self) -> None:
        f = Finding("T-001", "Test", "Title", "INFO", "Desc")
        h = hash(f)
        self.assertIsInstance(h, int)

    def test_equal_findings_same_hash(self) -> None:
        f1 = Finding("T-001", "Test", "Title", "INFO", "Desc")
        f2 = Finding("T-001", "Test", "Title", "INFO", "Desc")
        self.assertEqual(hash(f1), hash(f2))

    def test_usable_in_set(self) -> None:
        f1 = Finding("T-001", "Test", "Title", "INFO", "Desc")
        f2 = Finding("T-001", "Test", "Title", "INFO", "Desc")
        f3 = Finding("T-002", "Test", "Other", "WARNING", "Different")
        s = {f1, f2, f3}
        self.assertEqual(len(s), 2)

    def test_different_findings_different_hash(self) -> None:
        f1 = Finding("T-001", "Test", "Title", "INFO", "Desc")
        f2 = Finding("T-002", "Test", "Title", "INFO", "Desc")
        self.assertNotEqual(hash(f1), hash(f2))


class TestAdmCheckIdUnique(unittest.TestCase):
    @patch("winrecon.checks.run_command")
    def test_admin_check_ids_distinct(self, mock_cmd: MagicMock) -> None:
        from winrecon.checks import check_local_admins
        mock_cmd.return_value = (
            "Alias name     Administrators\n"
            "Comment        ...\n\n"
            "---\n"
            "Administrator\n"
            "JohnDoe\n"
            "The command completed successfully.\n"
        )
        log = MagicMock()
        findings = check_local_admins(log)
        ids = [f.check_id for f in findings]
        self.assertIn("ADM-002", ids)
        self.assertNotIn("ADM-001", ids)

    @patch("winrecon.checks.run_command")
    def test_admin_failure_uses_adm001(self, mock_cmd: MagicMock) -> None:
        from winrecon.checks import check_local_admins
        mock_cmd.return_value = ""
        log = MagicMock()
        findings = check_local_admins(log)
        ids = [f.check_id for f in findings]
        self.assertIn("ADM-001", ids)


class TestTimeoutValidation(unittest.TestCase):
    def test_negative_timeout_rejected(self) -> None:
        from winrecon.cli import parse_arguments
        with patch("sys.argv", ["winrecon", "--timeout", "-5"]), self.assertRaises(SystemExit):
            parse_arguments()

    def test_zero_timeout_rejected(self) -> None:
        from winrecon.cli import parse_arguments
        with patch("sys.argv", ["winrecon", "--timeout", "0"]), self.assertRaises(SystemExit):
            parse_arguments()

    def test_positive_timeout_accepted(self) -> None:
        from winrecon.cli import parse_arguments
        with patch("sys.argv", ["winrecon", "--timeout", "30"]):
            args = parse_arguments()
            self.assertEqual(args.timeout, 30)


class TestIpFiltering(unittest.TestCase):
    @patch("winrecon.checks.socket")
    @patch("winrecon.checks.is_admin", return_value=False)
    def test_filters_link_local_and_apipa(self, _admin: MagicMock, mock_socket: MagicMock) -> None:
        from winrecon.checks import collect_system_info
        mock_socket.gethostname.return_value = "testhost"
        mock_socket.getaddrinfo.return_value = [
            (0, 0, 0, "", ("192.168.1.10", 0)),
            (0, 0, 0, "", ("127.0.0.1", 0)),
            (0, 0, 0, "", ("fe80::1", 0)),
            (0, 0, 0, "", ("169.254.100.5", 0)),
            (0, 0, 0, "", ("::1", 0)),
            (0, 0, 0, "", ("10.0.0.1", 0)),
        ]
        log = MagicMock()
        info = collect_system_info(log)
        self.assertIn("192.168.1.10", info["ip_addresses"])
        self.assertIn("10.0.0.1", info["ip_addresses"])
        self.assertNotIn("127.0.0.1", info["ip_addresses"])
        self.assertNotIn("fe80::1", info["ip_addresses"])
        self.assertNotIn("169.254.100.5", info["ip_addresses"])
        self.assertNotIn("::1", info["ip_addresses"])


class TestPasswordPolicyThreshold(unittest.TestCase):
    @patch("winrecon.checks.run_command")
    def test_length_12_still_warns(self, mock_cmd: MagicMock) -> None:
        from winrecon.checks import check_password_policy
        mock_cmd.return_value = (
            "Minimum password length: 12\n"
            "Lockout threshold: 5\n"
            "Length of password history maintained: 24\n"
        )
        log = MagicMock()
        findings = check_password_policy(log)
        pwd_findings = [f for f in findings if f.check_id == "PWD-002"]
        self.assertEqual(len(pwd_findings), 1)
        self.assertEqual(pwd_findings[0].severity, "WARNING")
        self.assertIn("14", pwd_findings[0].title)

    @patch("winrecon.checks.run_command")
    def test_length_14_passes(self, mock_cmd: MagicMock) -> None:
        from winrecon.checks import check_password_policy
        mock_cmd.return_value = (
            "Minimum password length: 14\n"
            "Lockout threshold: 5\n"
            "Length of password history maintained: 24\n"
        )
        log = MagicMock()
        findings = check_password_policy(log)
        pwd_findings = [f for f in findings if f.check_id == "PWD-002"]
        self.assertEqual(len(pwd_findings), 1)
        self.assertEqual(pwd_findings[0].severity, "PASS")


if __name__ == "__main__":
    unittest.main()
