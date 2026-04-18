"""Core types, constants, and utility functions for WinRecon."""

import ctypes
import html as _html_mod
import logging
import subprocess
import sys
from typing import Any, Dict, List, Optional

if sys.platform == "win32":
    import winreg

VERSION = "4.1.0"
TOOL_NAME = "WinRecon"
AUTHOR = "JUDE HILGENDORF"

# Exit codes
EXIT_SUCCESS = 0
EXIT_WARNING = 1
EXIT_CRITICAL = 2
EXIT_ERROR = 3

# Default command timeout (seconds)
DEFAULT_TIMEOUT = 60

SEVERITY_WEIGHT: Dict[str, int] = {
    "CRITICAL": 20,
    "WARNING": 10,
    "INFO": 0,
    "PASS": 0,
}

RISKY_PORTS: Dict[int, str] = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP (open relay risk)",
    135: "RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    1434: "MSSQL Browser",
    3389: "RDP",
    5800: "VNC HTTP",
    5900: "VNC",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
}

DEFAULT_SUSPICIOUS_TASK_KEYWORDS: List[str] = [
    # Encoded / obfuscated commands
    "powershell.exe -e",
    "powershell.exe -enc",
    "powershell.exe -encodedcommand",
    "frombase64string",
    # Command execution
    "cmd.exe /c",
    "cmd.exe /k",
    "mshta",
    "wscript",
    "cscript",
    # LOLBins (Living off the Land Binaries)
    "certutil",
    "bitsadmin",
    "regsvr32",
    "rundll32",
    "msiexec /q",
    "msxsl",
    "cmstp",
    "installutil",
    "regasm",
    "regsvcs",
    # Script execution / download cradles
    "downloadstring",
    "downloadfile",
    "invoke-expression",
    "invoke-webrequest",
    "iex(",
    "iwr ",
    "start-bitstransfer",
    "net.webclient",
    # Evasion techniques
    "-noprofile",
    "-noexit",
    "-windowstyle hidden",
    "-w hidden",
    "-ep bypass",
    "-executionpolicy bypass",
    # Suspicious paths
    "temp\\",
    "appdata\\",
    "%temp%",
    "%appdata%",
    "\\public\\",
    # C2 / exfil indicators
    "pastebin.com",
    "raw.githubusercontent",
    "discord.com/api/webhooks",
    "ngrok.io",
]

DEFAULT_TRUSTED_TASK_PATHS: List[str] = [
    "\\Microsoft\\",
    "\\Apple\\",
    "\\Google\\",
    "\\Mozilla\\",
    "\\Adobe\\",
    "\\Intel\\",
    "\\NVIDIA\\",
    "\\Lenovo\\",
    "\\Dell\\",
    "\\HP\\",
    "\\Realtek\\",
    "\\Samsung\\",
    "\\AMD\\",
    "\\Qualcomm\\",
    "\\Cisco\\",
    "\\Logitech\\",
    "\\ASUS\\",
    "\\Acer\\",
]


VALID_SEVERITIES = {"CRITICAL", "WARNING", "INFO", "PASS"}


class Finding:
    """Represents a single security finding from a WinRecon check."""

    def __init__(
        self,
        check_id: str,
        category: str,
        title: str,
        severity: str,
        description: str,
        detail: str = "",
        remediation: str = "",
    ) -> None:
        self.check_id = check_id
        self.category = category
        self.title = title
        self.severity = severity.upper()
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity {self.severity!r}; must be one of {VALID_SEVERITIES}"
            )
        self.description = description
        self.detail = detail
        self.remediation = remediation

    def to_dict(self) -> Dict[str, str]:
        return {
            "check_id": self.check_id,
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "detail": self.detail,
            "remediation": self.remediation,
        }

    def __repr__(self) -> str:
        return f"Finding({self.check_id!r}, {self.severity!r}, {self.title!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Finding):
            return NotImplemented
        return self.to_dict() == other.to_dict()

    def __hash__(self) -> int:
        return hash((
            self.check_id, self.category, self.title,
            self.severity, self.description, self.detail,
            self.remediation,
        ))


def _get_hostname() -> str:
    import platform as _platform
    return _platform.node()


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin() != 0)  # type: ignore[attr-defined]
    except Exception as exc:
        logging.getLogger(TOOL_NAME).debug("Admin check failed: %s", exc)
        return False


def run_command(cmd: str, timeout: Optional[int] = None) -> str:
    if timeout is None:
        timeout = DEFAULT_TIMEOUT
    log = logging.getLogger(TOOL_NAME)
    try:
        cflags = 0
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            cflags = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=True,
            creationflags=cflags,
        )
        if result.stderr and result.stderr.strip():
            log.debug("Command stderr: %s — %s", cmd[:80], result.stderr.strip()[:200])
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        log.debug("Command timed out after %ds: %s", timeout, cmd)
        return ""
    except Exception as exc:
        log.debug("Command failed: %s — %s", cmd[:80], exc)
        return ""


def reg_read(hive: int, key_path: str, value_name: str, default: Any = None) -> Any:
    try:
        with winreg.OpenKey(hive, key_path) as key:
            data, _ = winreg.QueryValueEx(key, value_name)
            return data
    except (FileNotFoundError, OSError):
        return default


def reg_enum_values(hive: int, key_path: str) -> Dict[str, Any]:
    results: Dict[str, Any] = {}
    try:
        with winreg.OpenKey(hive, key_path) as key:
            index = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(key, index)
                    results[name] = data
                    index += 1
                except OSError:
                    break
    except (FileNotFoundError, OSError):
        pass
    return results


def calculate_score(findings: List[Finding]) -> Dict[str, Any]:
    score = 100
    crit_count = 0
    warn_count = 0
    pass_count = 0
    info_count = 0

    for f in findings:
        if f.severity == "CRITICAL":
            score -= SEVERITY_WEIGHT["CRITICAL"]
            crit_count += 1
        elif f.severity == "WARNING":
            score -= SEVERITY_WEIGHT["WARNING"]
            warn_count += 1
        elif f.severity == "PASS":
            pass_count += 1
        else:
            info_count += 1

    score = max(0, min(100, score))
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    return {
        "score": score,
        "grade": grade,
        "critical": crit_count,
        "warning": warn_count,
        "pass": pass_count,
        "info": info_count,
        "total_findings": len(findings),
    }


def _esc(text: str) -> str:
    """Escape text for safe HTML embedding."""
    return _html_mod.escape(text, quote=True)
