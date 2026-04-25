"""Command-line interface and entry point for WinRecon."""

import argparse
import datetime
import json
import logging
import os
import platform
import sys
from pathlib import Path
from typing import List, Optional, Tuple

import winrecon.core as _core_mod
from winrecon.checks import collect_system_info, run_all_checks
from winrecon.core import (
    AUTHOR,
    DEFAULT_SUSPICIOUS_TASK_KEYWORDS,
    DEFAULT_TIMEOUT,
    DEFAULT_TRUSTED_TASK_PATHS,
    EXIT_CRITICAL,
    EXIT_ERROR,
    EXIT_SUCCESS,
    EXIT_WARNING,
    TOOL_NAME,
    VERSION,
    calculate_score,
    is_admin,
)
from winrecon.reporting import export_json, generate_html_report


def _get_hostname() -> str:
    return platform.node()


def setup_logging(output_dir: Path, verbose: bool = False, quiet: bool = False) -> logging.Logger:
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    logger = logging.getLogger(TOOL_NAME)
    logger.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler(sys.stdout)
    if quiet:
        console_handler.setLevel(logging.CRITICAL + 1)
    elif verbose:
        console_handler.setLevel(logging.DEBUG)
    else:
        console_handler.setLevel(logging.INFO)
    console_fmt = logging.Formatter("[%(levelname)-8s] %(message)s")
    console_handler.setFormatter(console_fmt)
    logger.addHandler(console_handler)

    log_file = output_dir / f"winrecon_{timestamp}.log"
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_fmt)
    logger.addHandler(file_handler)

    return logger


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=f"{TOOL_NAME} v{VERSION} by {AUTHOR} — Windows Security Auditing & Hardening Toolkit",
        epilog="Run with Administrator privileges for complete results.",
    )
    parser.add_argument(
        "--output-dir", "-o",
        type=str,
        default=os.path.join(os.getcwd(), "winrecon_reports"),
        help="Directory for output reports (default: ./winrecon_reports)",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Export JSON only, skip HTML report generation.",
    )
    parser.add_argument(
        "--no-html",
        action="store_true",
        help="Skip HTML report generation.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose console output (DEBUG level).",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress all console output (log file is still written).",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Timeout in seconds for each system command (default: {DEFAULT_TIMEOUT}).",
    )
    parser.add_argument(
        "--keywords-file",
        type=str,
        default=None,
        help="Path to a JSON file with custom suspicious keyword lists (overrides built-in defaults).",
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"{TOOL_NAME} v{VERSION} by {AUTHOR}",
    )
    return parser.parse_args()


def print_banner() -> None:
    banner = rf"""
    ╔══════════════════════════════════════════════════════╗
    ║                                                      ║
    ║   ██╗    ██╗██╗███╗   ██╗██████╗ ███████╗ ██████╗    ║
    ║   ██║    ██║██║████╗  ██║██╔══██╗██╔════╝██╔════╝    ║
    ║   ██║ █╗ ██║██║██╔██╗ ██║██████╔╝█████╗  ██║         ║
    ║   ██║███╗██║██║██║╚██╗██║██╔══██╗██╔══╝  ██║         ║
    ║   ╚███╔███╔╝██║██║ ╚████║██║  ██║███████╗╚██████╗    ║
    ║    ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝ ╚═════╝    ║
    ║                                                      ║
    ║   Windows Security Auditing & Hardening Toolkit      ║
    ║   Version {VERSION}    Author: {AUTHOR}          ║
    ║                                                      ║
    ╚══════════════════════════════════════════════════════╝
    """
    print(banner)


def load_custom_keywords(
    filepath: str,
    log: logging.Logger,
) -> Tuple[Optional[List[str]], Optional[List[str]]]:
    """Load custom keywords from a JSON file. Returns (keywords, trusted_paths)."""
    try:
        with open(filepath, encoding="utf-8") as fh:
            data = json.load(fh)
        keywords = data.get("suspicious_keywords")
        paths = data.get("trusted_paths")
        if keywords is not None:
            log.info("Loaded %d custom suspicious keywords.", len(keywords))
        if paths is not None:
            log.info("Loaded %d custom trusted paths.", len(paths))
        return keywords, paths
    except (json.JSONDecodeError, OSError) as exc:
        log.error("Failed to load keywords file '%s': %s", filepath, exc)
        raise SystemExit(EXIT_ERROR) from exc


def write_reports(
    system_info: dict,
    findings: list,
    score_data: dict,
    output_dir: Path,
    hostname: str,
    timestamp: str,
    json_only: bool,
    no_html: bool,
    log: logging.Logger,
) -> Tuple[List[Path], List[Tuple[str, str]]]:
    saved_paths: List[Path] = []
    failed_writes: List[Tuple[str, str]] = []

    json_path = output_dir / f"winrecon_{hostname}_{timestamp}.json"
    try:
        export_json(system_info, findings, score_data, json_path, log)
        saved_paths.append(json_path)
    except OSError as exc:
        failed_writes.append(("JSON", str(exc)))
        log.error("Failed to write JSON report %s: %s", json_path, exc)

    if not json_only and not no_html:
        html_path = output_dir / f"winrecon_{hostname}_{timestamp}.html"
        try:
            generate_html_report(system_info, findings, score_data, html_path, log)
            saved_paths.append(html_path)
        except OSError as exc:
            failed_writes.append(("HTML", str(exc)))
            log.error("Failed to write HTML report %s: %s", html_path, exc)

    log.info("-" * 55)
    if saved_paths and not failed_writes:
        log.info("Reports saved to: %s", output_dir.resolve())
    elif saved_paths and failed_writes:
        log.warning(
            "Partial success: wrote %d report(s) to %s; %d failed (%s)",
            len(saved_paths), output_dir.resolve(),
            len(failed_writes), ", ".join(name for name, _ in failed_writes),
        )
    else:
        log.error("No reports were written to %s", output_dir.resolve())
    log.info("Done.")
    return saved_paths, failed_writes


def main() -> int:
    if sys.platform != "win32":
        print("[ERROR] WinRecon is designed for Windows systems only.")
        return EXIT_ERROR

    if sys.version_info < (3, 8):
        print("[ERROR] WinRecon requires Python 3.8 or higher.")
        return EXIT_ERROR

    args = parse_arguments()

    if not args.quiet:
        print_banner()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    log = setup_logging(output_dir, verbose=args.verbose, quiet=args.quiet)

    log.info("%s v%s by %s starting...", TOOL_NAME, VERSION, AUTHOR)
    log.info("Output directory: %s", output_dir.resolve())

    suspicious_keywords: List[str] = list(DEFAULT_SUSPICIOUS_TASK_KEYWORDS)
    trusted_paths: List[str] = list(DEFAULT_TRUSTED_TASK_PATHS)

    if args.keywords_file:
        custom_keywords, custom_paths = load_custom_keywords(args.keywords_file, log)
        if custom_keywords is not None:
            suspicious_keywords = custom_keywords
        if custom_paths is not None:
            trusted_paths = custom_paths

    # Apply user-specified command timeout globally
    if args.timeout != DEFAULT_TIMEOUT:
        _core_mod.DEFAULT_TIMEOUT = args.timeout
        log.info("Command timeout set to %d seconds.", args.timeout)

    if not is_admin():
        log.warning("NOT running as Administrator. Some checks will be limited.")
        log.warning("   For full results, right-click → Run as Administrator.")
    else:
        log.info("Running with Administrator privileges.")

    system_info = collect_system_info(log)

    log.info("=" * 55)
    log.info("  STARTING SECURITY AUDIT")
    log.info("=" * 55)

    findings = run_all_checks(log, suspicious_keywords, trusted_paths)
    score_data = calculate_score(findings)

    log.info("=" * 55)
    log.info("  AUDIT COMPLETE")
    log.info("=" * 55)
    log.info("  Security Score: %d/100 (Grade: %s)", score_data["score"], score_data["grade"])
    log.info(
        "  Critical: %d  |  Warnings: %d  |  Passed: %d  |  Info: %d",
        score_data["critical"], score_data["warning"], score_data["pass"], score_data["info"],
    )
    log.info("  Total findings: %d", score_data["total_findings"])

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    hostname = _get_hostname()
    write_reports(
        system_info, findings, score_data,
        output_dir, hostname, timestamp,
        json_only=args.json_only, no_html=args.no_html,
        log=log,
    )

    if not args.quiet:
        print(f"\n{'═' * 55}")
        print(f"  SECURITY SCORE: {score_data['score']}/100  (Grade: {score_data['grade']})")
        print(f"  Critical: {score_data['critical']}  |  Warnings: {score_data['warning']}  "
              f"|  Passed: {score_data['pass']}  |  Info: {score_data['info']}")
        print(f"{'═' * 55}")
        print(f"\nReports: {output_dir.resolve()}\n")

    if score_data["critical"] > 0:
        return EXIT_CRITICAL
    elif score_data["warning"] > 0:
        return EXIT_WARNING
    return EXIT_SUCCESS
