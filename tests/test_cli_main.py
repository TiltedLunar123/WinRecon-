"""Tests for winrecon.cli.main — end-to-end CLI workflow."""

import logging
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

if sys.platform != "win32":
    sys.modules["winreg"] = MagicMock()

from winrecon.cli import main, setup_logging
from winrecon.core import EXIT_SUCCESS, EXIT_WARNING, TOOL_NAME, Finding


def _cleanup_logger() -> None:
    """Remove all handlers from WinRecon logger to release file locks."""
    logger = logging.getLogger(TOOL_NAME)
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)


class TestSetupLogging(unittest.TestCase):
    def tearDown(self) -> None:
        _cleanup_logger()

    def test_creates_logger(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logging(Path(tmpdir))
            self.assertEqual(logger.name, "WinRecon")
            self.assertTrue(len(logger.handlers) >= 2)
            _cleanup_logger()

    def test_verbose_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logging(Path(tmpdir), verbose=True)
            self.assertTrue(len(logger.handlers) >= 2)
            _cleanup_logger()

    def test_quiet_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logging(Path(tmpdir), quiet=True)
            self.assertTrue(len(logger.handlers) >= 2)
            _cleanup_logger()


class TestMainFunction(unittest.TestCase):
    @patch("winrecon.cli.run_all_checks")
    @patch("winrecon.cli.collect_system_info")
    @patch("winrecon.cli.is_admin")
    @patch("winrecon.cli.export_json")
    @patch("winrecon.cli.generate_html_report")
    @patch("sys.platform", "win32")
    def test_main_clean_run(
        self,
        mock_html: MagicMock,
        mock_json: MagicMock,
        mock_admin: MagicMock,
        mock_sysinfo: MagicMock,
        mock_checks: MagicMock,
    ) -> None:
        mock_admin.return_value = True
        mock_sysinfo.return_value = {
            "hostname": "TEST",
            "os": "Windows-Test",
            "is_admin": True,
            "scan_time": "2026-03-20 12:00:00",
            "os_version": "10.0",
            "architecture": "AMD64",
            "current_user": "tester",
            "python_version": "3.11",
            "domain": "WORKGROUP",
            "ip_addresses": ["10.0.0.1"],
            "processor": "CPU",
        }
        mock_checks.return_value = [
            Finding("P-001", "Test", "All good", "PASS", "OK"),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("sys.argv", ["winrecon", "--quiet", "-o", tmpdir]):
                result = main()
            _cleanup_logger()

        self.assertEqual(result, EXIT_SUCCESS)
        mock_json.assert_called_once()
        mock_html.assert_called_once()

    @patch("winrecon.cli.run_all_checks")
    @patch("winrecon.cli.collect_system_info")
    @patch("winrecon.cli.is_admin")
    @patch("winrecon.cli.export_json")
    @patch("winrecon.cli.generate_html_report")
    @patch("sys.platform", "win32")
    def test_main_json_only(
        self,
        mock_html: MagicMock,
        mock_json: MagicMock,
        mock_admin: MagicMock,
        mock_sysinfo: MagicMock,
        mock_checks: MagicMock,
    ) -> None:
        mock_admin.return_value = False
        mock_sysinfo.return_value = {
            "hostname": "TEST",
            "os": "Windows-Test",
            "is_admin": False,
            "scan_time": "2026-03-20 12:00:00",
        }
        mock_checks.return_value = [
            Finding("W-001", "Test", "Warning", "WARNING", "Warn"),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("sys.argv", ["winrecon", "--quiet", "--json-only", "-o", tmpdir]):
                result = main()
            _cleanup_logger()

        self.assertEqual(result, EXIT_WARNING)
        mock_json.assert_called_once()
        mock_html.assert_not_called()

    @patch("winrecon.cli.run_all_checks")
    @patch("winrecon.cli.collect_system_info")
    @patch("winrecon.cli.is_admin")
    @patch("winrecon.cli.export_json")
    @patch("winrecon.cli.generate_html_report")
    @patch("winrecon.cli.load_custom_keywords")
    @patch("sys.platform", "win32")
    def test_main_with_keywords_file(
        self,
        mock_load_kw: MagicMock,
        mock_html: MagicMock,
        mock_json: MagicMock,
        mock_admin: MagicMock,
        mock_sysinfo: MagicMock,
        mock_checks: MagicMock,
    ) -> None:
        mock_admin.return_value = True
        mock_sysinfo.return_value = {
            "hostname": "TEST",
            "os": "Windows-Test",
            "is_admin": True,
            "scan_time": "2026-03-20 12:00:00",
        }
        mock_checks.return_value = [Finding("P-001", "T", "T", "PASS", "OK")]
        mock_load_kw.return_value = (["custom_kw"], ["\\Custom\\"])

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("sys.argv", ["winrecon", "--quiet", "--keywords-file", "kw.json", "-o", tmpdir]):
                result = main()
            _cleanup_logger()

        self.assertEqual(result, EXIT_SUCCESS)
        mock_load_kw.assert_called_once()


if __name__ == "__main__":
    unittest.main()
