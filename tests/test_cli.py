"""Tests for winrecon.cli — argument parsing, keyword loading, banner."""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

if sys.platform != "win32":
    sys.modules["winreg"] = MagicMock()

from winrecon.cli import load_custom_keywords, parse_arguments
from winrecon.core import DEFAULT_TIMEOUT


class TestParseArguments(unittest.TestCase):
    def test_defaults(self) -> None:
        with patch("sys.argv", ["winrecon"]):
            args = parse_arguments()
            self.assertFalse(args.json_only)
            self.assertFalse(args.no_html)
            self.assertFalse(args.verbose)
            self.assertFalse(args.quiet)
            self.assertEqual(args.timeout, DEFAULT_TIMEOUT)
            self.assertIsNone(args.keywords_file)

    def test_custom_timeout(self) -> None:
        with patch("sys.argv", ["winrecon", "--timeout", "120"]):
            args = parse_arguments()
            self.assertEqual(args.timeout, 120)

    def test_zero_timeout_rejected(self) -> None:
        with patch("sys.argv", ["winrecon", "--timeout", "0"]), self.assertRaises(SystemExit):
            parse_arguments()

    def test_negative_timeout_rejected(self) -> None:
        with patch("sys.argv", ["winrecon", "--timeout", "-5"]), self.assertRaises(SystemExit):
            parse_arguments()

    def test_quiet_flag(self) -> None:
        with patch("sys.argv", ["winrecon", "--quiet"]):
            args = parse_arguments()
            self.assertTrue(args.quiet)

    def test_keywords_file(self) -> None:
        with patch("sys.argv", ["winrecon", "--keywords-file", "custom.json"]):
            args = parse_arguments()
            self.assertEqual(args.keywords_file, "custom.json")

    def test_short_flags(self) -> None:
        with patch("sys.argv", ["winrecon", "-q", "-t", "30", "-o", "/tmp/out"]):
            args = parse_arguments()
            self.assertTrue(args.quiet)
            self.assertEqual(args.timeout, 30)
            self.assertEqual(args.output_dir, "/tmp/out")


class TestLoadCustomKeywords(unittest.TestCase):
    def test_load_valid_keywords(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump({
                "suspicious_keywords": ["custom_keyword_1", "custom_keyword_2"],
                "trusted_paths": ["\\Custom\\"],
            }, f)
            tmp_path = f.name

        try:
            log = MagicMock()
            keywords, paths = load_custom_keywords(tmp_path, log)
            self.assertEqual(keywords, ["custom_keyword_1", "custom_keyword_2"])
            self.assertEqual(paths, ["\\Custom\\"])
        finally:
            os.unlink(tmp_path)

    def test_load_partial_keywords(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump({"suspicious_keywords": ["only_keywords"]}, f)
            tmp_path = f.name

        try:
            log = MagicMock()
            keywords, paths = load_custom_keywords(tmp_path, log)
            self.assertEqual(keywords, ["only_keywords"])
            self.assertIsNone(paths)
        finally:
            os.unlink(tmp_path)

    def test_load_invalid_json(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            f.write("not json{{{")
            tmp_path = f.name

        try:
            log = MagicMock()
            with self.assertRaises(SystemExit):
                load_custom_keywords(tmp_path, log)
        finally:
            os.unlink(tmp_path)

    def test_load_missing_file(self) -> None:
        log = MagicMock()
        with self.assertRaises(SystemExit):
            load_custom_keywords("/nonexistent/path.json", log)


if __name__ == "__main__":
    unittest.main()
