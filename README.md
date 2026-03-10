# 🔍 WinRecon — Python Windows Auditing Toolkit

> **Author:** Jude Hilgendorf  
> **GitHub:** [github.com/TiltedLunar123](https://github.com/TiltedLunar123)

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11%2FServer-0078D6?logo=windows)
![License](https://img.shields.io/badge/License-MIT-green)

A single-file Python toolkit that performs a comprehensive security audit of Windows systems — checking for misconfigurations, user account issues, network exposure, missing patches, privilege escalation vectors, and more.

---

## 🎯 What It Checks

| # | Module | Description |
|---|--------|-------------|
| 1 | **System Information** | OS, hostname, architecture, uptime, BIOS, RAM |
| 2 | **Users & Groups** | Local accounts, admin group members, password-less accounts |
| 3 | **Password Policy** | Minimum length, expiry, lockout threshold |
| 4 | **Network Configuration** | Adapters, DNS cache, ARP table, routes |
| 5 | **Open Ports** | Listening ports, established connections, risky port flagging |
| 6 | **Firewall Status** | Per-profile state (Domain/Private/Public), default actions |
| 7 | **Antivirus / Defender** | Real-time protection, signature age, third-party AV |
| 8 | **Installed Software** | Full enumeration from registry |
| 9 | **Running Services** | Active services + risky service detection |
| 10 | **Scheduled Tasks** | Non-Microsoft tasks (persistence check) |
| 11 | **Startup Programs** | Auto-start entries |
| 12 | **Network Shares** | SMB shares enumeration |
| 13 | **Windows Updates** | Last 10 hotfixes, patch currency check |
| 14 | **Security Policy** | UAC, RDP, NLA, SMBv1, AutoRun, Script Host, PS ExecutionPolicy |
| 15 | **Event Logs** | Failed logins, account lockouts, cleared audit logs |
| 16 | **Privilege Escalation** | Unquoted service paths, AlwaysInstallElevated, writable PATH dirs |

---

## ⚡ Quick Start

# Clone the repo
git clone https://github.com/TiltedLunar123/WinRecon.git
cd WinRecon

# Run (recommend: elevated / admin terminal)
python winrecon.py

No dependencies — uses only the Python standard library + built-in Windows tools (netstat, ipconfig, net, PowerShell).

📋 Requirements
Python 3.8+
Windows 10 / 11 / Server 2016+
Administrator privileges recommended for full audit (runs in limited mode without)
📄 Output
Terminal
Color-coded terminal output with severity indicators:

[✓]  — Passed / secure configuration
[!]  — Warning-level finding
[!!] — Critical finding
JSON Report
Automatically exports a full JSON report:

winrecon_HOSTNAME_20250615_143022.json
📸 Example Output
text

══════════════════════════════════════════════════════════════════════
  [ FINDINGS SUMMARY ]
══════════════════════════════════════════════════════════════════════

    Critical                      : 2
    Warnings                      : 5
    Informational                 : 1

  ▸ Critical Findings
  ──────────────────────────────────────────────────
    [!!] Firewall Public profile disabled
    [!!] SMBv1 protocol is enabled

  ▸ Warnings
  ──────────────────────────────────────────────────
    [!] Password min length = 0
    [!] No account lockout threshold
    [!] Port 3389 (RDP) listening
    [!] Risky service running: RemoteRegistry
    [!] RDP NLA is disabled
🏗️ Project Structure

WinRecon/
├── winrecon.py      # Complete toolkit (single file)
└── README.md        # This file
⚠️ Disclaimer
This tool is intended for authorized security auditing only. Only run WinRecon on systems you own or have explicit written permission to audit. The author is not responsible for misuse.

📜 License
MIT License — see LICENSE for details.

Built for defenders. Stay secure. 🛡️

---

## Key Design Decisions

1. **Single file** — zero friction, clone-and-run, no `pip install` needed
2. **Modular functions** — each audit area is its own function, easy to extend
3. **Dual output** — pretty color terminal output **+** machine-readable JSON export
4. **Severity system** — findings tagged CRITICAL / WARNING / INFO with a summary at the end
5. **Graceful degradation** — runs without admin (limited), catches all exceptions per-module so one failure doesn't kill the scan
6. **Platform gate** — clean exit message if accidentally run on Linux/Mac
