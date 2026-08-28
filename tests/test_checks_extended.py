"""Extended tests for individual security checks in winrecon.checks."""

import sys
import unittest
from unittest.mock import MagicMock, patch

if sys.platform != "win32":
    sys.modules["winreg"] = MagicMock()

from winrecon.checks import (
    check_antivirus,
    check_audit_policy,
    check_bitlocker,
    check_credential_guard,
    check_event_log_service,
    check_installed_software,
    check_local_admins,
    check_network_shares,
    check_password_policy,
    check_powershell_settings,
    check_rdp,
    check_scheduled_tasks,
    check_secure_boot,
    check_smb_v1,
    check_startup_programs,
    check_uac,
    check_windows_update,
)


class TestCheckSmbV1(unittest.TestCase):
    @patch("winrecon.checks.run_command")
    @patch("winrecon.checks.reg_read")
    def test_smb1_disabled(self, mock_reg: MagicMock, mock_cmd: MagicMock) -> None:
        mock_reg.return_value = 0
        mock_cmd.return_value = "STATE : STOPPED"
        findings = check_smb_v1(MagicMock())
        self.assertTrue(any(f.severity == "PASS" for f in findings))

    @patch("winrecon.checks.run_command")
    @patch("winrecon.checks.reg_read")
    def test_smb1_enabled(self, mock_reg: MagicMock, mock_cmd: MagicMock) -> None:
        mock_reg.return_value = 1
        mock_cmd.return_value = "STATE : 4  RUNNING"
        findings = check_smb_v1(MagicMock())
        self.assertTrue(any(f.severity == "CRITICAL" for f in findings))

    @patch("winrecon.checks.run_command")
    @patch("winrecon.checks.reg_read")
    def test_smb1_not_found(self, mock_reg: MagicMock, mock_cmd: MagicMock) -> None:
        mock_reg.return_value = None
        mock_cmd.return_value = "STATE : STOPPED"
        findings = check_smb_v1(MagicMock())
        self.assertTrue(any(f.severity == "INFO" for f in findings))


class TestCheckRdp(unittest.TestCase):
    @patch("winrecon.checks.reg_read")
    def test_rdp_disabled(self, mock_reg: MagicMock) -> None:
        mock_reg.return_value = 1  # fDenyTSConnections=1 means disabled
        findings = check_rdp(MagicMock())
        self.assertTrue(any(f.severity == "PASS" for f in findings))

    @patch("winrecon.checks.reg_read")
    def test_rdp_enabled_with_nla(self, mock_reg: MagicMock) -> None:
        def side_effect(hive: int, key: str, val: str, default: object = None) -> object:
            if "fDenyTSConnections" in val:
                return 0
            if "UserAuthentication" in val:
                return 1
            return default
        mock_reg.side_effect = side_effect
        findings = check_rdp(MagicMock())
        self.assertTrue(any(f.severity == "WARNING" for f in findings))

    @patch("winrecon.checks.reg_read")
    def test_rdp_enabled_without_nla(self, mock_reg: MagicMock) -> None:
        def side_effect(hive: int, key: str, val: str, default: object = None) -> object:
            if "fDenyTSConnections" in val:
                return 0
            return 0
        mock_reg.side_effect = side_effect
        findings = check_rdp(MagicMock())
        self.assertTrue(any(f.severity == "CRITICAL" for f in findings))


class TestCheckAuditPolicy(unittest.TestCase):
    @patch("winrecon.checks.run_command")
    def test_audit_configured(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = (
            "  Logon                           Success and Failure\n"
            "  Logoff                          Success\n"
            "  Account Lockout                 Success\n"
            "  User Account Management         Success and Failure\n"
            "  Security Group Management       Success\n"
            "  Process Creation                Success\n"
            "  Audit Policy Change             Success\n"
            "  Sensitive Privilege Use          Success\n"
        )
        findings = check_audit_policy(MagicMock())
        passed = [f for f in findings if f.severity == "PASS"]
        self.assertTrue(len(passed) >= 1)

    @patch("winrecon.checks.run_command")
    def test_audit_empty(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = ""
        findings = check_audit_policy(MagicMock())
        self.assertTrue(any(f.severity == "WARNING" for f in findings))

    @patch("winrecon.checks.run_command")
    def test_audit_many_disabled(self, mock_cmd: MagicMock) -> None:
        lines = "\n".join(f"  Subcategory {i}          No Auditing" for i in range(20))
        mock_cmd.return_value = lines
        findings = check_audit_policy(MagicMock())
        warning = [f for f in findings if f.severity == "WARNING"]
        self.assertTrue(len(warning) >= 1)


class TestCheckWindowsUpdate(unittest.TestCase):
    @patch("winrecon.checks.run_command")
    def test_recent_update(self, mock_cmd: MagicMock) -> None:
        import datetime
        recent = (datetime.datetime.now() - datetime.timedelta(days=5)).strftime("%m/%d/%Y")
        mock_cmd.return_value = f"Node,InstalledOn\nPC,{recent}\n"
        findings = check_windows_update(MagicMock())
        self.assertTrue(any(f.severity == "PASS" for f in findings))

    @patch("winrecon.checks.run_command")
    def test_old_update(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = "Node,InstalledOn\nPC,01/01/2020\n"
        findings = check_windows_update(MagicMock())
        self.assertTrue(any(f.severity == "CRITICAL" for f in findings))

    @patch("winrecon.checks.run_command")
    def test_empty_updates(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = ""
        findings = check_windows_update(MagicMock())
        self.assertTrue(any(f.severity == "WARNING" for f in findings))


class TestCheckAntivirus(unittest.TestCase):
    @patch("winrecon.checks.run_command")
    def test_defender_active(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = "RTP:True\nAMS:True\nAE:True\nSigAge:1\nLastScan:2026-03-20"
        findings = check_antivirus(MagicMock())
        passed = [f for f in findings if f.severity == "PASS"]
        self.assertTrue(len(passed) >= 1)

    @patch("winrecon.checks.run_command")
    def test_defender_disabled(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = "RTP:False\nAMS:True\nAE:True\nSigAge:1\n"
        findings = check_antivirus(MagicMock())
        self.assertTrue(any(f.severity == "CRITICAL" for f in findings))

    @patch("winrecon.checks.run_command")
    def test_av_not_enabled(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = "RTP:False\nAE:False\nSigAge:0\n"
        findings = check_antivirus(MagicMock())
        self.assertTrue(any(f.severity == "CRITICAL" for f in findings))

    @patch("winrecon.checks.run_command")
    def test_old_signatures(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = "RTP:True\nAE:True\nSigAge:15\n"
        findings = check_antivirus(MagicMock())
        self.assertTrue(any(f.severity == "CRITICAL" and "signature" in f.title.lower() for f in findings))

    @patch("winrecon.checks.run_command")
    def test_defender_error(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = "ERROR:Access denied"
        findings = check_antivirus(MagicMock())
        self.assertTrue(any(f.severity == "WARNING" for f in findings))


class TestCheckScheduledTasks(unittest.TestCase):
    @patch("winrecon.checks.run_command")
    def test_suspicious_task_found(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = (
            '"HostName","TaskName","Task To Run","Status","Author"\n'
            '"PC","\\EvilTask","powershell.exe -enc SGVsbG8=","Ready","SYSTEM"\n'
        )
        findings = check_scheduled_tasks(MagicMock())
        flagged = [f for f in findings if "suspicious" in f.title.lower()]
        self.assertTrue(len(flagged) >= 1)

    @patch("winrecon.checks.run_command")
    def test_trusted_task_skipped(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = (
            '"HostName","TaskName","Task To Run","Status","Author"\n'
            '"PC","\\Microsoft\\Windows\\Update","powershell.exe -enc foo","Ready","SYSTEM"\n'
        )
        findings = check_scheduled_tasks(MagicMock())
        # Microsoft tasks are trusted, so no suspicious findings even though command matches
        suspicious = [f for f in findings if f.severity in ("WARNING", "CRITICAL") and "suspicious" in f.title.lower()]
        self.assertEqual(len(suspicious), 0)
        # Should report "No suspicious" as PASS
        passed = [f for f in findings if f.severity == "PASS"]
        self.assertTrue(len(passed) >= 1)


class TestCheckStartupPrograms(unittest.TestCase):
    @patch("winrecon.checks.reg_enum_values")
    def test_no_entries(self, mock_enum: MagicMock) -> None:
        mock_enum.return_value = {}
        findings = check_startup_programs(MagicMock())
        self.assertTrue(len(findings) >= 1)

    @patch("winrecon.checks.reg_enum_values")
    def test_suspicious_entry(self, mock_enum: MagicMock) -> None:
        def side_effect(hive: int, path: str) -> dict:
            if "Run" in path and "RunOnce" not in path:
                return {"MalwareLoader": r"C:\Users\Public\AppData\Local\Temp\evil.exe"}
            return {}
        mock_enum.side_effect = side_effect
        findings = check_startup_programs(MagicMock())
        critical = [f for f in findings if f.severity == "CRITICAL"]
        self.assertTrue(len(critical) >= 1)


class TestCheckPowerShell(unittest.TestCase):
    @patch("winrecon.checks.reg_read")
    @patch("winrecon.checks.run_command")
    def test_restrictive_policy(self, mock_cmd: MagicMock, mock_reg: MagicMock) -> None:
        mock_cmd.return_value = "AllSigned"
        mock_reg.return_value = 1
        findings = check_powershell_settings(MagicMock())
        passed = [f for f in findings if f.severity == "PASS"]
        self.assertTrue(len(passed) >= 1)

    @patch("winrecon.checks.reg_read")
    @patch("winrecon.checks.run_command")
    def test_bypass_policy(self, mock_cmd: MagicMock, mock_reg: MagicMock) -> None:
        mock_cmd.return_value = "Bypass"
        mock_reg.return_value = 0
        findings = check_powershell_settings(MagicMock())
        warnings = [f for f in findings if f.severity == "WARNING"]
        self.assertTrue(len(warnings) >= 1)


class TestCheckUac(unittest.TestCase):
    @patch("winrecon.checks.reg_read")
    def test_uac_enabled(self, mock_reg: MagicMock) -> None:
        mock_reg.return_value = 1
        findings = check_uac(MagicMock())
        self.assertTrue(any(f.severity == "PASS" for f in findings))

    @patch("winrecon.checks.reg_read")
    def test_uac_disabled(self, mock_reg: MagicMock) -> None:
        mock_reg.return_value = 0
        findings = check_uac(MagicMock())
        self.assertTrue(any(f.severity == "CRITICAL" for f in findings))

    @patch("winrecon.checks.reg_read")
    def test_uac_no_prompt(self, mock_reg: MagicMock) -> None:
        call_count = [0]
        def side_effect(hive: int, key: str, val: str, default: object = None) -> object:
            call_count[0] += 1
            if "EnableLUA" in val:
                return 1
            if "ConsentPromptBehaviorAdmin" in val:
                return 0
            return default
        mock_reg.side_effect = side_effect
        findings = check_uac(MagicMock())
        warnings = [f for f in findings if f.severity == "WARNING"]
        self.assertTrue(len(warnings) >= 1)


class TestCheckBitlocker(unittest.TestCase):
    @patch("winrecon.checks.run_command")
    def test_bitlocker_on(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = "C:|On|100|FullyEncrypted"
        findings = check_bitlocker(MagicMock())
        self.assertTrue(any(f.severity == "PASS" for f in findings))

    @patch("winrecon.checks.run_command")
    def test_bitlocker_off(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = "C:|Off|0|FullyDecrypted"
        findings = check_bitlocker(MagicMock())
        self.assertTrue(any(f.severity == "CRITICAL" for f in findings))

    @patch("winrecon.checks.run_command")
    def test_bitlocker_error(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = "ERROR:Access denied"
        findings = check_bitlocker(MagicMock())
        self.assertTrue(any(f.severity == "WARNING" for f in findings))


class TestCheckCredentialGuard(unittest.TestCase):
    @patch("winrecon.checks.run_command")
    @patch("winrecon.checks.reg_read")
    def test_cg_running(self, mock_reg: MagicMock, mock_cmd: MagicMock) -> None:
        mock_reg.return_value = None
        mock_cmd.return_value = "VSM:2\nCG:1"
        findings = check_credential_guard(MagicMock())
        self.assertTrue(any(f.severity == "PASS" for f in findings))

    @patch("winrecon.checks.run_command")
    @patch("winrecon.checks.reg_read")
    def test_cg_configured_not_running(self, mock_reg: MagicMock, mock_cmd: MagicMock) -> None:
        mock_reg.return_value = 1
        mock_cmd.return_value = "ERROR:Not supported"
        findings = check_credential_guard(MagicMock())
        self.assertTrue(any(f.severity == "WARNING" for f in findings))

    @patch("winrecon.checks.run_command")
    @patch("winrecon.checks.reg_read")
    def test_cg_not_configured(self, mock_reg: MagicMock, mock_cmd: MagicMock) -> None:
        mock_reg.return_value = None
        mock_cmd.return_value = "ERROR:Not found"
        findings = check_credential_guard(MagicMock())
        self.assertTrue(any(f.severity == "WARNING" for f in findings))


class TestCheckSecureBoot(unittest.TestCase):
    @patch("winrecon.checks.run_command")
    def test_secure_boot_enabled(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = "True"
        findings = check_secure_boot(MagicMock())
        self.assertTrue(any(f.severity == "PASS" for f in findings))

    @patch("winrecon.checks.run_command")
    def test_secure_boot_disabled(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = "False"
        findings = check_secure_boot(MagicMock())
        self.assertTrue(any(f.severity == "WARNING" for f in findings))

    @patch("winrecon.checks.run_command")
    def test_secure_boot_unknown(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = "ERROR"
        findings = check_secure_boot(MagicMock())
        self.assertTrue(any(f.severity == "INFO" for f in findings))


class TestCheckNetworkShares(unittest.TestCase):
    @patch("winrecon.checks.run_command")
    def test_only_admin_shares(self, mock_cmd: MagicMock) -> None:
        # net share output has 4 header lines (name, separator, blank, blank), then data
        mock_cmd.return_value = (
            "Share name   Resource                        Remark\n"
            "\n"
            "-------------------------------------------------------------------------------\n"
            "\n"
            "C$           C:\\\n"
            "ADMIN$       C:\\Windows\n"
            "IPC$\n"
            "The command completed successfully.\n"
        )
        findings = check_network_shares(MagicMock())
        # All shares end with $ so they're admin shares
        self.assertTrue(any(f.severity == "PASS" or f.severity == "INFO" for f in findings))

    @patch("winrecon.checks.run_command")
    def test_user_shares_present(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = (
            "Share name   Resource\n"
            "----------   --------\n"
            "\n"
            "\n"
            "PublicShare   D:\\Public\n"
            "C$            C:\\\n"
            "The command completed successfully.\n"
        )
        findings = check_network_shares(MagicMock())
        info_or_warn = [f for f in findings if f.severity in ("INFO", "WARNING")]
        self.assertTrue(len(info_or_warn) >= 1)


class TestCheckEventLog(unittest.TestCase):
    @patch("winrecon.checks.run_command")
    def test_event_log_running(self, mock_cmd: MagicMock) -> None:
        def side_effect(cmd: str, **kwargs: object) -> str:
            if "sc query" in cmd:
                return "STATE : 4  RUNNING"
            if "Get-WinEvent" in cmd:
                return "Size:5242880\nMax:209715200\nRecords:12345"
            return ""
        mock_cmd.side_effect = side_effect
        findings = check_event_log_service(MagicMock())
        passed = [f for f in findings if f.severity == "PASS"]
        self.assertTrue(len(passed) >= 1)

    @patch("winrecon.checks.run_command")
    def test_event_log_stopped(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = "STATE : 1  STOPPED"
        findings = check_event_log_service(MagicMock())
        self.assertTrue(any(f.severity == "CRITICAL" for f in findings))

    @patch("winrecon.checks.run_command")
    def test_small_security_log(self, mock_cmd: MagicMock) -> None:
        def side_effect(cmd: str, **kwargs: object) -> str:
            if "sc query" in cmd:
                return "STATE : 4  RUNNING"
            if "Get-WinEvent" in cmd:
                return "Size:1048576\nMax:20971520\nRecords:500"
            return ""
        mock_cmd.side_effect = side_effect
        findings = check_event_log_service(MagicMock())
        warnings = [f for f in findings if f.severity == "WARNING"]
        self.assertTrue(len(warnings) >= 1)


class TestCheckInstalledSoftware(unittest.TestCase):
    @patch("winrecon.checks.winreg")
    def test_no_software_found(self, mock_winreg: MagicMock) -> None:
        mock_winreg.OpenKey.side_effect = FileNotFoundError
        mock_winreg.HKEY_LOCAL_MACHINE = 0x80000002
        mock_winreg.HKEY_CURRENT_USER = 0x80000001
        findings = check_installed_software(MagicMock())
        self.assertTrue(len(findings) >= 1)
        self.assertTrue(any("0 installed" in f.title for f in findings))


class TestCheckLocalAdmins(unittest.TestCase):
    @patch("winrecon.checks.run_command")
    def test_query_failure_uses_adm001(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = ""
        findings = check_local_admins(MagicMock())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].check_id, "ADM-001")

    @patch("winrecon.checks.run_command")
    def test_result_uses_distinct_id(self, mock_cmd: MagicMock) -> None:
        mock_cmd.return_value = (
            "Members\n-------\nAdministrator\njude\n"
            "The command completed successfully."
        )
        findings = check_local_admins(MagicMock())
        self.assertEqual(len(findings), 1)
        # The real result must not collide with the query-failure id.
        self.assertEqual(findings[0].check_id, "ADM-002")
        self.assertNotEqual(findings[0].check_id, "ADM-001")


class TestCheckPasswordPolicy(unittest.TestCase):
    @patch("winrecon.checks.run_command")
    def test_midrange_length_wording_is_consistent(self, mock_cmd: MagicMock) -> None:
        # 10 lands in the 8..11 band, which references the CIS 14 baseline.
        mock_cmd.return_value = "Minimum password length: 10"
        findings = check_password_policy(MagicMock())
        pwd = next(f for f in findings if f.check_id == "PWD-002")
        self.assertIn("14", pwd.title)
        self.assertNotIn("12", pwd.title)
        self.assertIn("14", pwd.description)


if __name__ == "__main__":
    unittest.main()
