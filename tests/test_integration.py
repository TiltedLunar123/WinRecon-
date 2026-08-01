"""Integration tests, mock full scan workflows end-to-end."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

if sys.platform != "win32":
    sys.modules["winreg"] = MagicMock()

from winrecon.checks import (
    check_firewall,
    check_local_admins,
    check_local_users,
    check_open_ports,
    check_password_policy,
    check_scheduled_tasks,
    collect_system_info,
    run_all_checks,
)
from winrecon.core import (
    Finding,
    calculate_score,
)
from winrecon.reporting import export_json, generate_html_report


class TestFullScanWorkflow(unittest.TestCase):
    """Integration test: mock all system commands and run the full pipeline."""

    MOCK_RESPONSES = {
        'wmic useraccount where "LocalAccount=True" get Name,Disabled,Lockout,PasswordChangeable,PasswordExpires,PasswordRequired,SID /format:csv':
            "Node,Disabled,Lockout,Name,PasswordChangeable,PasswordExpires,PasswordRequired,SID\n"
            "PC,FALSE,FALSE,Administrator,TRUE,FALSE,TRUE,S-1-5-21-123-500\n"
            "PC,TRUE,FALSE,Guest,TRUE,FALSE,FALSE,S-1-5-21-123-501\n"
            "PC,FALSE,FALSE,User1,TRUE,TRUE,TRUE,S-1-5-21-123-1001\n",
        "net localgroup Administrators":
            "Alias name     Administrators\n"
            "Comment        Members\n\n"
            "---------------\n"
            "Administrator\n"
            "The command completed successfully.\n",
        "net accounts":
            "Minimum password length:          8\n"
            "Lockout threshold:                 5\n"
            "Length of password history maintained: 12\n",
        "netstat -ano -p TCP":
            "  TCP    0.0.0.0:80       0.0.0.0:0       LISTENING       1234\n"
            "  TCP    0.0.0.0:443      0.0.0.0:0       LISTENING       1234\n",
        "netsh advfirewall show allprofiles state":
            "Domain Profile Settings:\n  State  ON\n"
            "Private Profile Settings:\n  State  ON\n"
            "Public Profile Settings:\n  State  ON\n",
        "sc query mrxsmb10": "STATE : STOPPED",
        "auditpol /get /category:*": "",
        "wmic qfe get InstalledOn /format:csv": "",
        "schtasks /query /fo CSV /v": "",
        "sc query EventLog": "STATE : 4  RUNNING",
        "net share": "",
    }

    def _mock_run_command(self, cmd: str, timeout: int = 60) -> str:
        for key, response in self.MOCK_RESPONSES.items():
            if key in cmd:
                return response
        return ""

    def _mock_reg_read(self, hive: int, key_path: str, value_name: str, default: object = None) -> object:
        return default

    def _mock_reg_enum_values(self, hive: int, key_path: str) -> dict:
        return {}

    @patch("winrecon.checks.reg_enum_values")
    @patch("winrecon.checks.reg_read")
    @patch("winrecon.checks.run_command")
    def test_full_scan_produces_valid_output(
        self,
        mock_cmd: MagicMock,
        mock_reg: MagicMock,
        mock_enum: MagicMock,
    ) -> None:
        mock_cmd.side_effect = self._mock_run_command
        mock_reg.side_effect = self._mock_reg_read
        mock_enum.side_effect = self._mock_reg_enum_values

        log = MagicMock()

        findings = run_all_checks(log)
        self.assertIsInstance(findings, list)
        self.assertTrue(len(findings) > 0)
        for f in findings:
            self.assertIsInstance(f, Finding)
            self.assertIn(f.severity, ("CRITICAL", "WARNING", "INFO", "PASS"))

        score_data = calculate_score(findings)
        self.assertIn("score", score_data)
        self.assertIn("grade", score_data)
        self.assertTrue(0 <= score_data["score"] <= 100)

    @patch("winrecon.checks.reg_enum_values")
    @patch("winrecon.checks.reg_read")
    @patch("winrecon.checks.run_command")
    def test_full_scan_json_export(
        self,
        mock_cmd: MagicMock,
        mock_reg: MagicMock,
        mock_enum: MagicMock,
    ) -> None:
        mock_cmd.side_effect = self._mock_run_command
        mock_reg.side_effect = self._mock_reg_read
        mock_enum.side_effect = self._mock_reg_enum_values

        log = MagicMock()
        system_info = {
            "hostname": "TESTPC",
            "os": "Windows-Test",
            "is_admin": True,
            "scan_time": "2026-03-20 12:00:00",
        }

        findings = run_all_checks(log)
        score_data = calculate_score(findings)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmp_path = Path(f.name)

        try:
            export_json(system_info, findings, score_data, tmp_path, log)
            with open(tmp_path, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data["tool"], "WinRecon")
            self.assertIsInstance(data["findings"], list)
            self.assertTrue(len(data["findings"]) > 0)
            self.assertIn("score", data["score"])
        finally:
            os.unlink(tmp_path)

    @patch("winrecon.checks.reg_enum_values")
    @patch("winrecon.checks.reg_read")
    @patch("winrecon.checks.run_command")
    def test_full_scan_html_export(
        self,
        mock_cmd: MagicMock,
        mock_reg: MagicMock,
        mock_enum: MagicMock,
    ) -> None:
        mock_cmd.side_effect = self._mock_run_command
        mock_reg.side_effect = self._mock_reg_read
        mock_enum.side_effect = self._mock_reg_enum_values

        log = MagicMock()
        system_info = {
            "hostname": "TESTPC",
            "os": "Windows-Test",
            "os_version": "10.0",
            "architecture": "AMD64",
            "current_user": "tester",
            "is_admin": True,
            "python_version": "3.11",
            "scan_time": "2026-03-20 12:00:00",
            "domain": "WORKGROUP",
            "ip_addresses": ["10.0.0.1"],
            "processor": "TestCPU",
        }

        findings = run_all_checks(log)
        score_data = calculate_score(findings)

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            tmp_path = Path(f.name)

        try:
            generate_html_report(system_info, findings, score_data, tmp_path, log)
            content = tmp_path.read_text(encoding="utf-8")
            self.assertIn("<!DOCTYPE html>", content)
            self.assertIn("WinRecon", content)
            self.assertIn("TESTPC", content)
        finally:
            os.unlink(tmp_path)


class TestCustomKeywordsIntegration(unittest.TestCase):
    """Test that custom keywords flow through to scheduled task checks."""

    @patch("winrecon.checks.run_command")
    def test_custom_keywords_used_in_check(self, mock_cmd: MagicMock) -> None:
        csv_output = (
            '"HostName","TaskName","Task To Run","Status","Author"\n'
            '"PC","\\CustomTask","custom_evil_marker.exe","Ready","SYSTEM"\n'
        )
        mock_cmd.return_value = csv_output
        log = MagicMock()

        # Without custom keywords, should not flag
        findings_default = check_scheduled_tasks(log)
        flagged_default = [f for f in findings_default if f.severity in ("WARNING", "CRITICAL") and "suspicious" in f.title.lower()]

        # With custom keywords, should flag
        findings_custom = check_scheduled_tasks(
            log,
            suspicious_keywords=["custom_evil_marker"],
            trusted_paths=[],
        )
        flagged_custom = [f for f in findings_custom if f.severity in ("WARNING", "CRITICAL") and "suspicious" in f.title.lower()]

        self.assertEqual(len(flagged_default), 0)
        self.assertEqual(len(flagged_custom), 1)


class TestIndividualChecksMocked(unittest.TestCase):
    """Test individual security checks with mocked system commands."""

    @patch("winrecon.checks.run_command")
    def test_check_local_users_guest_enabled(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = (
            "Node,Disabled,Lockout,Name,PasswordChangeable,PasswordExpires,PasswordRequired,SID\n"
            "PC,FALSE,FALSE,Guest,TRUE,FALSE,TRUE,S-1-5-21-123-501\n"
        )
        log = MagicMock()
        findings = check_local_users(log)
        critical = [f for f in findings if f.severity == "CRITICAL" and "Guest" in f.title]
        self.assertTrue(len(critical) >= 1)

    @patch("winrecon.checks.run_command")
    def test_check_local_admins_excessive(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = (
            "Alias name     Administrators\n"
            "Comment        Members\n\n"
            "---------------\n"
            "Admin1\nAdmin2\nAdmin3\nAdmin4\n"
            "The command completed successfully.\n"
        )
        log = MagicMock()
        findings = check_local_admins(log)
        critical = [f for f in findings if f.severity == "CRITICAL"]
        self.assertTrue(len(critical) >= 1)

    @patch("winrecon.checks.run_command")
    def test_check_password_policy_weak(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = (
            "Minimum password length:          0\n"
            "Lockout threshold:                 Never\n"
            "Length of password history maintained: None\n"
        )
        log = MagicMock()
        findings = check_password_policy(log)
        critical = [f for f in findings if f.severity == "CRITICAL"]
        self.assertTrue(len(critical) >= 2)  # weak password + no lockout

    @patch("winrecon.checks.run_command")
    def test_check_open_ports_risky(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = (
            "  TCP    0.0.0.0:3389     0.0.0.0:0       LISTENING       5678\n"
        )
        log = MagicMock()
        findings = check_open_ports(log)
        rdp_findings = [f for f in findings if "3389" in f.title]
        self.assertTrue(len(rdp_findings) >= 1)

    @patch("winrecon.checks.run_command")
    def test_check_firewall_all_on(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = (
            "Domain Profile Settings:\n  State  ON\n"
            "Private Profile Settings:\n  State  ON\n"
            "Public Profile Settings:\n  State  ON\n"
        )
        log = MagicMock()
        findings = check_firewall(log)
        passed = [f for f in findings if f.severity == "PASS"]
        self.assertTrue(len(passed) >= 1)

    @patch("winrecon.checks.run_command")
    def test_check_firewall_disabled(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = (
            "Domain Profile Settings:\n  State  OFF\n"
            "Private Profile Settings:\n  State  ON\n"
            "Public Profile Settings:\n  State  ON\n"
        )
        log = MagicMock()
        findings = check_firewall(log)
        critical = [f for f in findings if f.severity == "CRITICAL"]
        self.assertTrue(len(critical) >= 1)

    @patch("winrecon.checks.run_command")
    def test_check_empty_command_output(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = ""
        log = MagicMock()
        findings = check_local_users(log)
        self.assertTrue(len(findings) >= 1)
        self.assertTrue(any(f.severity == "WARNING" for f in findings))


class TestCollectSystemInfo(unittest.TestCase):
    def test_collect_returns_expected_keys(self) -> None:
        log = MagicMock()
        info = collect_system_info(log)
        expected_keys = [
            "hostname", "os", "os_version", "architecture",
            "current_user", "is_admin", "python_version",
            "scan_time", "domain", "ip_addresses",
        ]
        for key in expected_keys:
            self.assertIn(key, info)


if __name__ == "__main__":
    unittest.main()
