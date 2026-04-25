# Changelog

All notable changes to WinRecon are documented here.

## [Unreleased]

### Fixed
- `Finding` class is now hashable; equal findings hash equal so they can be deduplicated via `set` (closes #13)
- `check_local_admins` now uses `ADM-002` for the member-count finding so the success and failure cases no longer share `ADM-001` (closes #4)
- Password policy `PWD-002` messaging is consistent: title and description both reference 14 characters (CIS) instead of mixing 12 and 14 (closes #5)
- Defender `SigAge` parse failures now emit a `WARNING` instead of being silently dropped (closes #19)
- Report writes are wrapped per-file: the "Reports saved" line only appears when each requested report actually lands; partial and total failures are reported separately (closes #22)
- `system_info.scan_time` is now an RFC 3339 timestamp with UTC offset, matching the JSON schema declaration (closes #16)
- IPv6 link-local (`fe80:`) and IPv4 APIPA (`169.254.`) addresses are now excluded from `system_info.ip_addresses` (closes #12)

### Changed
- Extracted `winrecon.cli.write_reports` so the per-file try/except logic is independently testable

## [4.1.0] - 2026-04-08

### Fixed
- **`--timeout` flag now works** — previously accepted but silently ignored; command timeout is now applied globally to all system commands
- **Python 3.8 runtime crash** — replaced PEP 585 `set[int]` / `set[str]` syntax with `typing.Set` for 3.8 compatibility
- **Duplicate check IDs** — `USR-001` and `NET-001` were each used for two different findings; split into `USR-001`/`USR-006` and `NET-001`/`NET-002`
- **HTML escaping** — replaced hand-rolled `_esc()` with stdlib `html.escape()` (now escapes single quotes)
- **Schema version mismatch** — `winrecon_schema.json` was stuck at v3.1.0, now matches project version
- **Copyright year** — README now matches LICENSE (2026)
- **HOSTNAME captured at import time** — now resolved at scan time via `_get_hostname()`
- **`sys.exit()` in `main()`** — replaced with `return EXIT_ERROR` for testability
- **stderr silently discarded** — `run_command()` now logs stderr output at DEBUG level

### Added
- **Severity validation** — `Finding` now raises `ValueError` for invalid severity values
- **`Finding.__repr__` and `__eq__`** — improved debugging and test assertions
- **8 additional trusted vendor paths** — Realtek, Samsung, AMD, Qualcomm, Cisco, Logitech, ASUS, Acer
- **Python 3.13 support** — added to CI matrix and pyproject.toml classifiers
- **Security CI job** — Bandit and pip-audit now run in CI pipeline
- **Full Python version matrix** — CI now tests 3.8, 3.9, 3.10, 3.11, 3.12, 3.13
- **`CONTRIBUTING.md`** — development setup and contribution guidelines
- **New unit tests** — severity validation, `__repr__`/`__eq__`, empty HTML report, schema validation, timeout passthrough, `run_all_checks` error handling

### Changed
- **Removed broad `bypass` keyword** — standalone "bypass" caused false positives; specific variants (`-ep bypass`, `-executionpolicy bypass`) are still detected
- **CI installs via `pip install -e ".[dev]"`** instead of manual dependency listing
- **`Optional` type hints** — replaced `= None  # type: ignore` with proper `Optional[List[str]]`

## [4.0.0] - 2026-03-26

### Added
- Modular package structure (`winrecon/` package with `core`, `checks`, `cli`, `reporting` modules)
- 20 security checks with comprehensive coverage
- Strict CI with ruff, mypy, and pytest
- 101 tests at 90%+ coverage
- Typed package (`py.typed` marker)

## [3.1.0] - 2026-03-25

### Added
- Test suite, CI pipeline, type hints, new CLI flags

## [3.0.0] - 2026-03-24

### Added
- 5 new security checks, expanded detection
