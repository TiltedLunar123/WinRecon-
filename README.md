# WinRecon

Windows security auditing toolkit. Runs 20 checks against the machine it is on, scores
what it finds, and writes an HTML report you can open without installing anything.

![Version](https://img.shields.io/badge/version-4.1.0-purple)
![Python](https://img.shields.io/badge/python-3.8%2B-purple)
![Platform](https://img.shields.io/badge/platform-Windows-purple)
![License](https://img.shields.io/badge/license-MIT-purple)

It is standard library only. No pip install, no internet, nothing to set up on a machine
you are auditing. That was the whole point: a lot of the auditing tools I wanted to run
during lab work needed a package manager and network access, which is exactly what you
do not have on a locked-down box.

## Running it

```bash
python -m winrecon
```

That drops an HTML report, a JSON file, and a log into `./winrecon_reports/`.

Run it from an elevated prompt if you can. It works fine as a standard user, but five of
the checks come back with partial data and two return nothing at all, so the score you
get is not really comparable to an admin run.

```bash
python -m winrecon --output-dir C:\SecurityReports
python -m winrecon --json-only          # skip the HTML
python -m winrecon --quiet              # log file only, for scheduled runs
python -m winrecon --timeout 120        # slower machines need this
```

Full flag list:

```
--output-dir, -o      where reports go (default: ./winrecon_reports)
--json-only           export JSON, skip the HTML report
--no-html             skip the HTML report
--verbose             DEBUG-level console output
--quiet, -q           no console output at all, log file still written
--timeout, -t         per-command timeout in seconds (default: 60)
--keywords-file       JSON file with your own suspicious keyword lists
--version, -v         print version and exit
```

## What it checks

| # | Check | What it looks at |
|---|-------|------------------|
| 1 | Local user accounts | Enabled Guest accounts, blank passwords, non-expiring passwords |
| 2 | Local administrators | Members of the Administrators group, flagged when the list gets long |
| 3 | Password policy | Minimum length, lockout threshold, history, against CIS values |
| 4 | Open ports | Listening TCP ports, flagging RDP, SMB, Telnet, FTP, VNC, WinRM, MSSQL |
| 5 | Windows Firewall | Status per profile (Domain, Private, Public) |
| 6 | SMBv1 | Whether it is still enabled |
| 7 | RDP | Enabled or not, and whether NLA is enforced |
| 8 | Audit policy | Logon, account management, process creation and other subcategories |
| 9 | Windows Update | Date of the last hotfix, flagged past 30 days |
| 10 | Antivirus | Defender real-time protection state and signature age |
| 11 | Scheduled tasks | Task actions matched against the suspicious patterns below |
| 12 | Startup programs | Run and RunOnce keys, flagging temp paths |
| 13 | PowerShell | Execution policy, script block logging, module logging |
| 14 | UAC | Enabled, plus the admin consent prompt behaviour |
| 15 | BitLocker | Whether system volumes are encrypted |
| 16 | Credential Guard | Running or not |
| 17 | Secure Boot | UEFI Secure Boot state |
| 18 | Network shares | Shares present, flagging user-created ones |
| 19 | Event Log service | Running, and the Security log retention size |
| 20 | Installed software | Inventory, for asset and vulnerability work |

Checks 11 and 12 match against known-bad command patterns: encoded PowerShell
(`-enc`, `frombase64string`, `-ep bypass`), living-off-the-land binaries (`mshta`,
`certutil`, `bitsadmin`, `regsvr32`, `rundll32`, `installutil`), script hosts and
download cradles (`wscript`, `iex(`, `downloadstring`, `net.webclient`), temp and public
paths, C2-ish destinations (`pastebin.com`, `raw.githubusercontent`, Discord webhooks,
`ngrok.io`), and hidden-window flags. You can replace the whole list with
`--keywords-file`:

```json
{
  "suspicious_keywords": ["custom_pattern_1", "custom_pattern_2"],
  "trusted_paths": ["\\MyVendor\\", "\\TrustedApp\\"]
}
```

## What needs admin

| Check | Standard user | Administrator |
|-------|---------------|---------------|
| Password policy | limited | full |
| Windows Firewall | limited | full |
| Audit policy | denied | full |
| Antivirus | limited | full |
| Scheduled tasks | limited | full |
| BitLocker | denied | full |
| Credential Guard | limited | full |

The other 13 return the same data either way.

## Scoring

Starts at 100. Every CRITICAL finding takes off 20, every WARNING takes off 10. PASS and
INFO findings do not move the number. Grades are A at 90 and up, B at 80, C at 60, D at
40, F below that.

The score is a rough signal, not a compliance verdict. A machine with one critical
finding and nothing else wrong lands at 80, which is a B, and that is not really a B if
the critical finding is SMBv1.

## Output

The HTML report is a single self-contained file. All CSS is inline, there are no
external fonts or scripts, and it opens offline in any browser. That matters more than
it sounds like it should when you are handing a report to someone whose machine you do
not control.

The JSON export carries the same data in a structure meant for ingestion:

```json
{
  "tool": "WinRecon",
  "version": "4.1.0",
  "system_info": {
    "hostname": "WORKSTATION-01",
    "os": "Windows-10-10.0.19045-SP0",
    "is_admin": true,
    "scan_time": "2025-01-15 14:30:00",
    "ip_addresses": ["192.168.1.100"]
  },
  "score": { "score": 65, "grade": "C", "critical": 2, "warning": 3, "pass": 8, "info": 4 },
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

There is a JSON Schema in `winrecon_schema.json` if you want to validate it.

## Exit codes

`0` clean, `1` warnings, `2` criticals, `3` the tool itself failed. Enough to gate a
pipeline on:

```powershell
python -m winrecon --quiet --json-only
if ($LASTEXITCODE -eq 2) { Write-Error "Critical security issues found" }
```

## Requirements

Windows 10, 11, or Server 2016 and up, with Python 3.8 or newer. No third-party
packages.

## Tests

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
python -m pytest tests/ --cov=winrecon --cov-fail-under=80
python -m ruff check winrecon/ tests/
python -m mypy winrecon/ --ignore-missing-imports --check-untyped-defs
```

Coverage is enforced at 80%. CI runs the suite on Windows against Python 3.8 through
3.13, so a change that only works on a recent version gets caught there rather than by
whoever runs it on an old build.

## Still to do

Domain checks when the machine is domain-joined, certificate store auditing, and
mapping findings to CIS and STIG identifiers. Remote scanning over WinRM keeps coming
up and I keep deciding it is a different tool.

## Licence and use

MIT, see [LICENSE](LICENSE).

Only run this against machines you are responsible for or have written permission to
audit.
