"""WinRecon — Windows Security Auditing & Hardening Toolkit."""

from winrecon.checks import (
    collect_system_info,
    run_all_checks,
)
from winrecon.cli import (
    load_custom_keywords,
    main,
    parse_arguments,
    print_banner,
    setup_logging,
)
from winrecon.core import (
    AUTHOR,
    DEFAULT_SUSPICIOUS_TASK_KEYWORDS,
    DEFAULT_TIMEOUT,
    DEFAULT_TRUSTED_TASK_PATHS,
    EXIT_CRITICAL,
    EXIT_ERROR,
    EXIT_SUCCESS,
    EXIT_WARNING,
    RISKY_PORTS,
    SEVERITY_WEIGHT,
    TOOL_NAME,
    VERSION,
    Finding,
    _esc,
    calculate_score,
    is_admin,
    reg_enum_values,
    reg_read,
    run_command,
)
from winrecon.reporting import (
    export_json,
    generate_html_report,
)

# Backward-compatible aliases
SUSPICIOUS_TASK_KEYWORDS = list(DEFAULT_SUSPICIOUS_TASK_KEYWORDS)
TRUSTED_TASK_PATHS = list(DEFAULT_TRUSTED_TASK_PATHS)

__version__ = VERSION
__all__ = [
    "AUTHOR",
    "DEFAULT_SUSPICIOUS_TASK_KEYWORDS",
    "DEFAULT_TIMEOUT",
    "DEFAULT_TRUSTED_TASK_PATHS",
    "EXIT_CRITICAL",
    "EXIT_ERROR",
    "EXIT_SUCCESS",
    "EXIT_WARNING",
    "Finding",
    "RISKY_PORTS",
    "SEVERITY_WEIGHT",
    "SUSPICIOUS_TASK_KEYWORDS",
    "TOOL_NAME",
    "TRUSTED_TASK_PATHS",
    "VERSION",
    "_esc",
    "calculate_score",
    "collect_system_info",
    "export_json",
    "generate_html_report",
    "is_admin",
    "load_custom_keywords",
    "main",
    "parse_arguments",
    "print_banner",
    "reg_enum_values",
    "reg_read",
    "run_all_checks",
    "run_command",
    "setup_logging",
]
