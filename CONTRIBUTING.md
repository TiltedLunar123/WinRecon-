# Contributing to WinRecon

Thanks for your interest in contributing to WinRecon!

## Development Setup

```bash
# Clone the repo
git clone https://github.com/TiltedLunar123/WinRecon.git
cd WinRecon

# Install in development mode with dev dependencies
pip install -e ".[dev]"
```

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=winrecon --cov-report=term-missing --cov-fail-under=80

# Lint
python -m ruff check winrecon/ tests/

# Type check
python -m mypy winrecon/ --ignore-missing-imports --check-untyped-defs
```

## Adding a New Security Check

1. Add the check function in `winrecon/checks.py` following the existing pattern
2. Register it in the `checks` list inside `run_all_checks()`
3. Use unique check IDs (format: `ABC-NNN`)
4. Include remediation guidance for any WARNING or CRITICAL finding
5. Add unit tests in `tests/test_checks_extended.py`
6. Update the README table with the new check

## Code Style

- Follow existing patterns in the codebase
- Use type hints on all function signatures
- Target Python 3.8+ compatibility (use `typing.List` not `list[...]`)
- Run `ruff check` before submitting

## Pull Requests

1. Fork the repo and create a feature branch
2. Make your changes with tests
3. Ensure all tests pass and coverage stays above 80%
4. Submit a PR with a clear description of the changes

## Reporting Issues

Open an issue on GitHub with:
- WinRecon version (`python -m winrecon --version`)
- Windows version
- Steps to reproduce
- Expected vs actual behavior
