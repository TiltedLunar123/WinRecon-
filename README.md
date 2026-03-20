

# 🛡️ WinRecon — Windows Security Auditing & Hardening Toolkit

![Version](https://img.shields.io/badge/version-4.0.0-purple)
![Python](https://img.shields.io/badge/python-3.8%2B-purple)
![Platform](https://img.shields.io/badge/platform-Windows-purple)
![License](https://img.shields.io/badge/license-MIT-purple)
![Author](https://img.shields.io/badge/author-Jude%20Hilgendorf-purple)

**WinRecon** is a zero-dependency Windows security auditing tool that performs **20 automated security checks**, scores your system's overall security posture, and generates a professional **purple-themed inline HTML report** alongside a structured JSON export.

Built entirely on the Python standard library. No installs. No pip. No internet required. Just run it.

---

## 📸 Report Preview

The generated HTML report features:

- **Deep purple dark theme** — easy on the eyes, professional presentation
- **Security score dashboard** — letter grade (A–F) with 0–100 numeric score
- **Color-coded severity badges** — CRITICAL (red), WARNING (amber), PASS (green), INFO (purple)
- **Expandable finding details** — technical evidence, registry values, command output
- **Remediation guidance** — actionable fix commands for every issue found
- **100% inline HTML** — single self-contained file, no external CSS/JS/fonts, opens instantly in any browser

---

## ⚡ Quick Start

```bash
# Install (optional — or just run directly)
pip install .

# Basic scan (creates ./winrecon_reports/ with HTML + JSON)
python -m winrecon

# Custom output directory
python -m winrecon --output-dir C:\SecurityReports

# JSON export only (skip HTML)
python -m winrecon --json-only

# Show version
python -m winrecon --version

# Legacy entry point (still works)
python -m winrecon
```

> **Important:** Run as **Administrator** for full results. Right-click your terminal and select **Run as Administrator**, or use an elevated PowerShell prompt. WinRecon will still work without admin privileges but some checks will return limited data.

---

## 🔍 Security Checks Performed

WinRecon runs **20 comprehensive security audits** across the following categories:

| # | Check | What It Does |
|---|-------|-------------|
| 1 | **Local User Accounts** | Enumerates all local accounts. Flags enabled Guest accounts, accounts without passwords, and non-expiring passwords. |
| 2 | **Local Administrators** | Lists members of the Administrators group. Flags excessive admin membership (lateral movement risk). |
| 3 | **Password Policy** | Audits minimum length, lockout threshold, and password history enforcement against CIS benchmarks. |
| 4 | **Open Ports** | Identifies all listening TCP ports. Flags dangerous ports (RDP, SMB, Telnet, FTP, VNC, WinRM, MSSQL). |
| 5 | **Windows Firewall** | Checks firewall status across all profiles (Domain, Private, Public). Flags any disabled profile. |
| 6 | **SMBv1 Protocol** | Detects if the insecure SMBv1 protocol is enabled (EternalBlue, WannaCry, NotPetya vulnerability). |
| 7 | **RDP Configuration** | Checks if Remote Desktop is enabled and whether Network Level Authentication (NLA) is enforced. |
| 8 | **Audit Policy** | Verifies critical audit subcategories (Logon, Account Management, Process Creation, etc.) are configured. |
| 9 | **Windows Update** | Determines when the last hotfix was installed. Flags systems that haven't been patched in 30+ days. |
| 10 | **Antivirus Status** | Queries Windows Defender for real-time protection status and signature age. |
| 11 | **Scheduled Tasks** | Scans all scheduled tasks for suspicious commands (encoded PowerShell, certutil, temp paths, etc.). |
| 12 | **Startup Programs** | Enumerates registry Run/RunOnce keys. Flags entries referencing temp directories or known malicious patterns. |
| 13 | **PowerShell Security** | Checks execution policy, script block logging, and module logging configuration. |
| 14 | **UAC Settings** | Verifies User Account Control is enabled and checks the admin consent prompt behavior. |
| 15 | **BitLocker Encryption** | Checks if system volumes are encrypted with BitLocker. Flags unprotected drives. |
| 16 | **Credential Guard** | Detects whether Windows Credential Guard is running to protect cached credentials from pass-the-hash attacks. |
| 17 | **Secure Boot** | Verifies UEFI Secure Boot is enabled to protect against boot-level malware and rootkits. |
| 18 | **Network Shares** | Enumerates network shares and flags user-created shares that may expose sensitive data. |
| 19 | **Event Log Service** | Verifies the Windows Event Log service is running and checks Security log retention size. |
| 20 | **Software Inventory** | Enumerates all installed applications for asset management and vulnerability assessment. |

---

## 📊 Scoring System

WinRecon calculates a **security score from 0 to 100** based on findings:

| Severity | Point Deduction | Description |
|----------|----------------|-------------|
| **CRITICAL** | -20 points | Immediate security risk requiring urgent remediation |
| **WARNING** | -10 points | Security weakness that should be addressed |
| **INFO** | 0 points | Informational finding for awareness |
| **PASS** | 0 points | Check passed — meets security baseline |

### Grade Scale

| Score | Grade | Meaning |
|-------|-------|---------|
| 90–100 | **A** | Excellent security posture |
| 80–89 | **B** | Good — minor improvements recommended |
| 60–79 | **C** | Fair — several issues need attention |
| 40–59 | **D** | Poor — significant security gaps |
| 0–39 | **F** | Critical — system is at serious risk |

---

## 📁 Output Files

Every scan produces the following files in the output directory (default `./winrecon_reports/`):

```
winrecon_reports/
├── winrecon_HOSTNAME_2025-01-15_14-30-00.html    # Full visual report (inline HTML)
├── winrecon_HOSTNAME_2025-01-15_14-30-00.json    # Structured data export
└── winrecon_2025-01-15_14-30-00.log              # Detailed execution log
```

### HTML Report
- Single self-contained file with **all styles inline**
- No external dependencies — works offline, opens in any browser instantly
- Purple dark theme with color-coded severity badges
- Includes system info, score dashboard, and all findings with remediation steps

### JSON Export
- Machine-readable structured output
- Contains system info, score breakdown, and all findings
- Suitable for ingestion into SIEMs, dashboards, or compliance pipelines

### Log File
- Full debug-level execution log
- Records every check performed, errors encountered, and timing details
- Useful for troubleshooting or audit trail purposes

---

## 🖥️ Command-Line Options

```
usage: WinRecon [-h] [--output-dir OUTPUT_DIR] [--json-only] [--no-html]
                [--verbose] [--quiet] [--timeout TIMEOUT]
                [--keywords-file FILE] [--version]

WinRecon v4.0.0 by JUDE HILGENDORF — Windows Security Auditing & Hardening Toolkit

options:
  -h, --help            show this help message and exit
  --output-dir, -o      Directory for output reports (default: ./winrecon_reports)
  --json-only           Export JSON only, skip HTML report generation
  --no-html             Skip HTML report generation
  --verbose             Enable verbose console output (DEBUG level)
  --quiet, -q           Suppress all console output (log file is still written)
  --timeout, -t         Timeout in seconds for each system command (default: 60)
  --keywords-file       Path to a JSON file with custom suspicious keyword lists
  --version, -v         show program's version number and exit
```

---

## 📋 Requirements

| Requirement | Details |
|-------------|---------|
| **Operating System** | Windows 10 / 11 / Server 2016+ |
| **Python** | 3.8 or higher |
| **Dependencies** | None — standard library only |
| **Privileges** | Administrator recommended (works with limited results as standard user) |

### What Requires Admin?

| Check | Standard User | Administrator |
|-------|:------------:|:------------:|
| Local User Accounts | ✅ | ✅ |
| Local Administrators | ✅ | ✅ |
| Password Policy | ⚠️ Limited | ✅ |
| Open Ports | ✅ | ✅ |
| Windows Firewall | ⚠️ Limited | ✅ |
| SMBv1 Protocol | ✅ | ✅ |
| RDP Configuration | ✅ | ✅ |
| Audit Policy | ❌ Denied | ✅ |
| Windows Update | ✅ | ✅ |
| Antivirus Status | ⚠️ Limited | ✅ |
| Scheduled Tasks | ⚠️ Limited | ✅ |
| Startup Programs | ✅ | ✅ |
| PowerShell Security | ✅ | ✅ |
| UAC Settings | ✅ | ✅ |
| BitLocker Encryption | ❌ Denied | ✅ |
| Credential Guard | ⚠️ Limited | ✅ |
| Secure Boot | ✅ | ✅ |
| Network Shares | ✅ | ✅ |
| Event Log Service | ✅ | ✅ |
| Software Inventory | ✅ | ✅ |

---

## 🚀 Usage Examples

### Basic Security Audit
```powershell
# Open an elevated PowerShell prompt, then:
python -m winrecon
```

### Save Reports to a Specific Folder
```powershell
python -m winrecon --output-dir "C:\Audits\Q1-2025"
```

### JSON Only (for Automated Pipelines)
```powershell
python -m winrecon --json-only --output-dir "C:\Audits\automated"
```

### Integration with Other Tools
```powershell
# Run scan and parse JSON output programmatically
python -m winrecon --json-only -o C:\temp\scan

# Then in your pipeline:
$results = Get-Content "C:\temp\scan\winrecon_*.json" | ConvertFrom-Json
$results.score
$results.findings | Where-Object { $_.severity -eq "CRITICAL" }
```

### Quiet Mode for Scheduled Tasks
```powershell
# Silent scan — output only goes to log file
python -m winrecon --quiet --output-dir "C:\Audits"
```

### Custom Timeout
```powershell
# Increase command timeout for slow systems
python -m winrecon --timeout 120
```

### Custom Suspicious Keywords
```powershell
# Override built-in suspicious keywords with your own list
python -m winrecon --keywords-file custom_keywords.json
```

The keywords file format:
```json
{
  "suspicious_keywords": ["custom_pattern_1", "custom_pattern_2"],
  "trusted_paths": ["\\MyVendor\\", "\\TrustedApp\\"]
}
```

### Scheduled Recurring Audit
```powershell
# Create a scheduled task to run weekly audits
schtasks /create /tn "WinRecon Weekly Audit" /tr "python C:\Tools\winrecon.py --quiet --output-dir C:\Audits" /sc weekly /d MON /st 06:00 /ru SYSTEM
```

---

## 🔧 How It Works

```
┌─────────────────────────────────────────────────┐
│                   WinRecon                       │
│              JUDE HILGENDORF                     │
├─────────────────────────────────────────────────┤
│                                                  │
│  1. System Information Collection               │
│     └─ Hostname, OS, IPs, User, Domain          │
│                                                  │
│  2. Security Checks (20 modules)                │
│     ├─ Registry queries (winreg)                │
│     ├─ System commands (wmic, netstat, net, etc)│
│     ├─ PowerShell queries (Defender, policies)  │
│     └─ Service state checks (sc query)          │
│                                                  │
│  3. Scoring Engine                               │
│     └─ 0-100 score with A-F letter grade        │
│                                                  │
│  4. Report Generation                            │
│     ├─ Inline HTML (purple theme, single file)  │
│     ├─ JSON (structured, machine-readable)      │
│     └─ Log file (debug-level trace)             │
│                                                  │
└─────────────────────────────────────────────────┘
```

---

## 🛑 Suspicious Patterns Detected

WinRecon scans scheduled tasks and startup entries for these known attack indicators:

| Category | Patterns |
|----------|----------|
| **Encoded Commands** | `powershell -enc`, `-encodedcommand`, `bypass`, `-noprofile`, `frombase64string` |
| **Living-off-the-Land** | `mshta`, `certutil`, `bitsadmin`, `regsvr32`, `rundll32`, `msiexec /q`, `msxsl`, `cmstp`, `installutil`, `regasm`, `regsvcs` |
| **Script Execution** | `wscript`, `cscript`, `invoke-expression`, `iex(`, `downloadstring`, `downloadfile`, `invoke-webrequest`, `start-bitstransfer`, `net.webclient` |
| **Suspicious Paths** | `%temp%`, `%appdata%`, `appdata\local\temp`, `temp\`, `\public\` |
| **C2 Indicators** | `pastebin.com`, `raw.githubusercontent`, `discord.com/api/webhooks`, `ngrok.io` |
| **Stealth Techniques** | `-windowstyle hidden`, `-w hidden`, `cmd.exe /c`, `cmd.exe /k`, `-noexit`, `-ep bypass` |

---

## 📝 JSON Output Schema

```json
{
  "tool": "WinRecon",
  "version": "4.0.0",
  "author": "JUDE HILGENDORF",
  "system_info": {
    "hostname": "WORKSTATION-01",
    "os": "Windows-10-10.0.19045-SP0",
    "os_version": "10.0.19045",
    "architecture": "AMD64",
    "processor": "Intel64 Family 6 ...",
    "current_user": "admin",
    "is_admin": true,
    "python_version": "3.11.5",
    "scan_time": "2025-01-15 14:30:00",
    "domain": "WORKGROUP",
    "ip_addresses": ["192.168.1.100"]
  },
  "score": {
    "score": 65,
    "grade": "C",
    "critical": 2,
    "warning": 3,
    "pass": 8,
    "info": 4,
    "total_findings": 17
  },
  "findings": [
    {
      "check_id": "USR-002",
      "category": "User Accounts",
      "title": "Guest account 'Guest' is ENABLED",
      "severity": "CRITICAL",
      "description": "The built-in Guest account is enabled...",
      "detail": "SID: S-1-5-21-...-501",
      "remediation": "Disable the Guest account: net user Guest /active:no"
    }
  ]
}
```

---

## ⚖️ License

```
MIT License

Copyright (c) 2025 JUDE HILGENDORF

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## ⚠️ Disclaimer

WinRecon is designed for **authorized security assessments only**. Always ensure you have explicit permission before auditing any system. The author assumes no liability for misuse or damage resulting from the use of this tool. Use responsibly and in accordance with applicable laws and organizational policies.

---

## 👤 Author

**JUDE HILGENDORF**

---

## 🔢 Exit Codes

WinRecon returns meaningful exit codes for scripting and CI/CD integration:

| Code | Meaning |
|------|---------|
| `0` | All checks passed (no critical or warning findings) |
| `1` | Warning-level findings detected |
| `2` | Critical-level findings detected |
| `3` | Runtime error (invalid arguments, missing files, etc.) |

```powershell
# Example: fail a CI pipeline if critical findings exist
python -m winrecon --quiet --json-only
if ($LASTEXITCODE -eq 2) { Write-Error "Critical security issues found!" }
```

---

## 🧪 Testing

WinRecon includes a comprehensive test suite with 101 tests covering core logic and integration workflows:

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
python -m pytest tests/ -v

# Run with coverage (enforced at 80% minimum)
python -m pytest tests/ --cov=winrecon --cov-report=term-missing --cov-fail-under=80

# Lint
python -m ruff check winrecon/ tests/

# Type check
python -m mypy winrecon/ --ignore-missing-imports --check-untyped-defs
```

Tests cover: `Finding` class, `calculate_score()`, `_esc()` HTML escaping, `run_command()`, `reg_read()`, `parse_arguments()`, JSON/HTML report generation (including XSS prevention), custom keyword loading, exit codes, all 20 security checks (mocked), full scan integration workflows, and CLI `main()` function.

---

## 🗺️ Roadmap

- [x] BitLocker encryption status verification
- [x] Windows Credential Guard detection
- [x] Network share permission analysis
- [x] Event log service health and retention checks
- [x] Secure Boot verification
- [ ] Active Directory domain checks (when domain-joined)
- [ ] Certificate store auditing
- [ ] PDF report export option
- [ ] Compliance mapping (CIS, NIST, STIG)
- [ ] Delta/comparison reports between scans
- [ ] Remote system scanning via WinRM
```