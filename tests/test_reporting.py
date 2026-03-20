"""Tests for winrecon.reporting — HTML and JSON report generation."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

if sys.platform != "win32":
    sys.modules["winreg"] = MagicMock()

from winrecon.core import VERSION, Finding, calculate_score
from winrecon.reporting import export_json, generate_html_report


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
            export_json(system_info, findings, score_data, tmp_path, log)

            with open(tmp_path, encoding="utf-8") as fh:
                data = json.load(fh)

            self.assertEqual(data["tool"], "WinRecon")
            self.assertEqual(data["version"], VERSION)
            self.assertEqual(len(data["findings"]), 2)
            self.assertEqual(data["score"]["score"], 90)
            self.assertEqual(data["score"]["grade"], "A")
        finally:
            os.unlink(tmp_path)


class TestGenerateHtmlReport(unittest.TestCase):
    def _make_system_info(self, **overrides: object) -> dict:
        info = {
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
        info.update(overrides)
        return info

    def test_html_output_created(self) -> None:
        system_info = self._make_system_info()
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
            generate_html_report(system_info, findings, score_data, tmp_path, log)

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
        system_info = self._make_system_info(
            hostname="<script>alert(1)</script>",
            is_admin=False,
        )
        findings = [Finding("X-001", "X", "<img onerror=alert(1)>", "PASS", "D")]
        score_data = calculate_score(findings)

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            tmp_path = Path(f.name)

        try:
            log = MagicMock()
            generate_html_report(system_info, findings, score_data, tmp_path, log)
            content = tmp_path.read_text(encoding="utf-8")
            self.assertNotIn("<script>", content)
            self.assertNotIn("<img onerror", content)
            self.assertIn("&lt;script&gt;", content)
        finally:
            os.unlink(tmp_path)


if __name__ == "__main__":
    unittest.main()
