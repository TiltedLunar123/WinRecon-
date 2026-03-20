"""Security check functions for WinRecon."""

import csv
import datetime
import getpass
import io
import json
import logging
import os
import platform
import socket
import sys
from typing import Any, Dict, List

if sys.platform == "win32":
    import winreg

from winrecon.core import (
    DEFAULT_SUSPICIOUS_TASK_KEYWORDS,
    DEFAULT_TRUSTED_TASK_PATHS,
    RISKY_PORTS,
    Finding,
    is_admin,
    reg_enum_values,
    reg_read,
    run_command,
)

HOSTNAME = platform.node()


def collect_system_info(log: logging.Logger) -> Dict[str, Any]:
    log.info("Collecting system information...")
    info: Dict[str, Any] = {
        "hostname": HOSTNAME,
        "os": platform.platform(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "current_user": getpass.getuser(),
        "is_admin": is_admin(),
        "python_version": platform.python_version(),
        "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "domain": os.environ.get("USERDOMAIN", "N/A"),
        "ip_addresses": [],
    }
    try:
        hostname = socket.gethostname()
        addrs = socket.getaddrinfo(hostname, None)
        ips = sorted(set(
            addr[4][0] for addr in addrs
            if not addr[4][0].startswith("::") and addr[4][0] != "127.0.0.1"
        ))
        info["ip_addresses"] = ips if ips else ["Could not determine"]
    except Exception:
        info["ip_addresses"] = ["Could not determine"]
    log.debug("System info collected: %s", json.dumps(info, indent=2))
    return info


def check_local_users(log: logging.Logger) -> List[Finding]:
    log.info("Checking local user accounts...")
    findings: List[Finding] = []
    output = run_command(
        'wmic useraccount where "LocalAccount=True" get '
        'Name,Disabled,Lockout,PasswordChangeable,PasswordExpires,PasswordRequired,SID '
        '/format:csv'
    )
    if not output:
        findings.append(Finding(
            "USR-001", "User Accounts", "Unable to enumerate local users",
            "WARNING",
            "Could not query local user accounts. Run as Administrator.",
            remediation="Re-run WinRecon with Administrator privileges."
        ))
        return findings

    reader = csv.DictReader(io.StringIO(output))
    user_count = 0
    for row in reader:
        if not row.get("Name"):
            continue
        user_count += 1
        name = row["Name"].strip()
        disabled = row.get("Disabled", "").strip().upper() == "TRUE"
        pwd_required = row.get("PasswordRequired", "").strip().upper() == "TRUE"
        pwd_expires = row.get("PasswordExpires", "").strip().upper() == "TRUE"
        sid = row.get("SID", "").strip()

        if name.lower() == "guest" and not disabled:
            findings.append(Finding(
                "USR-002", "User Accounts", f"Guest account '{name}' is ENABLED",
                "CRITICAL",
                "The built-in Guest account is enabled. This provides unauthenticated access.",
                detail=f"SID: {sid}",
                remediation="Disable the Guest account: net user Guest /active:no"
            ))

        if sid.endswith("-500") and not disabled:
            findings.append(Finding(
                "USR-003", "User Accounts",
                f"Built-in Administrator account '{name}' is ENABLED",
                "WARNING",
                "The default Administrator account is active. It is a common brute-force target.",
                detail=f"SID: {sid}",
                remediation="Rename or disable the built-in Administrator account and use a named admin account."
            ))

        if not disabled and not pwd_required:
            findings.append(Finding(
                "USR-004", "User Accounts",
                f"Account '{name}' does not require a password",
                "CRITICAL",
                "This account can authenticate with a blank password.",
                remediation=f'Set a password: net user "{name}" * or enforce password policy.'
            ))

        if not disabled and not pwd_expires and not sid.endswith("-500"):
            findings.append(Finding(
                "USR-005", "User Accounts",
                f"Password for '{name}' never expires",
                "WARNING",
                "Non-rotating passwords increase compromise risk over time.",
                remediation=f"Set password expiration: wmic useraccount where Name='{name}' set PasswordExpires=True"
            ))

    if user_count > 0:
        findings.append(Finding(
            "USR-001", "User Accounts",
            f"Enumerated {user_count} local user account(s)",
            "INFO",
            f"Total local accounts found: {user_count}.",
        ))
    return findings


def check_local_admins(log: logging.Logger) -> List[Finding]:
    log.info("Checking local Administrators group membership...")
    findings: List[Finding] = []
    output = run_command("net localgroup Administrators")
    if not output:
        findings.append(Finding(
            "ADM-001", "Admin Accounts", "Unable to query Administrators group",
            "WARNING", "Could not enumerate local Administrators group.",
            remediation="Run as Administrator."
        ))
        return findings

    lines = output.splitlines()
    members: List[str] = []
    in_members = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("---"):
            in_members = True
            continue
        if in_members:
            if stripped == "" or stripped.startswith("The command"):
                break
            members.append(stripped)

    severity = "CRITICAL" if len(members) > 3 else ("WARNING" if len(members) > 2 else "PASS")
    findings.append(Finding(
        "ADM-001", "Admin Accounts",
        f"Local Administrators group has {len(members)} member(s)",
        severity,
        "Excessive local admin accounts increase lateral movement risk.",
        detail="Members: " + ", ".join(members),
        remediation="Remove unnecessary accounts from the Administrators group. Follow least privilege."
    ))
    return findings


def check_password_policy(log: logging.Logger) -> List[Finding]:
    log.info("Checking password policy...")
    findings: List[Finding] = []
    output = run_command("net accounts")
    if not output:
        findings.append(Finding(
            "PWD-001", "Password Policy", "Unable to retrieve password policy",
            "WARNING", "Could not query local password policy.",
            remediation="Run as Administrator."
        ))
        return findings

    policy: Dict[str, str] = {}
    for line in output.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            policy[key.strip().lower()] = value.strip()

    detail_text = "\n".join(f"{k}: {v}" for k, v in policy.items())

    min_len_str = policy.get("minimum password length", "0")
    try:
        min_len = int(min_len_str)
    except ValueError:
        min_len = 0

    if min_len < 8:
        findings.append(Finding(
            "PWD-002", "Password Policy",
            f"Minimum password length is {min_len} (should be >= 12)",
            "CRITICAL" if min_len < 6 else "WARNING",
            "Short passwords are easily brute-forced.",
            detail=detail_text,
            remediation="Set minimum password length to 12+: net accounts /minpwlen:12"
        ))
    elif min_len < 12:
        findings.append(Finding(
            "PWD-002", "Password Policy",
            f"Minimum password length is {min_len} (recommended >= 12)",
            "WARNING",
            "CIS benchmarks recommend a minimum of 14 characters.",
            detail=detail_text,
            remediation="Increase minimum password length: net accounts /minpwlen:14"
        ))
    else:
        findings.append(Finding(
            "PWD-002", "Password Policy",
            f"Minimum password length is {min_len} — meets baseline",
            "PASS",
            "Password length meets or exceeds CIS recommendations.",
            detail=detail_text,
        ))

    lockout_str = policy.get("lockout threshold", "Never")
    if lockout_str.lower() == "never":
        findings.append(Finding(
            "PWD-003", "Password Policy",
            "Account lockout threshold is not configured",
            "CRITICAL",
            "Without lockout, accounts are vulnerable to unlimited brute-force attempts.",
            remediation="Set lockout threshold: net accounts /lockoutthreshold:5"
        ))
    else:
        try:
            lockout_val = int(lockout_str)
            if lockout_val > 10:
                findings.append(Finding(
                    "PWD-003", "Password Policy",
                    f"Account lockout threshold is {lockout_val} (recommended <= 5)",
                    "WARNING",
                    "A high lockout threshold still allows many brute-force attempts.",
                    remediation="Lower lockout threshold: net accounts /lockoutthreshold:5"
                ))
            else:
                findings.append(Finding(
                    "PWD-003", "Password Policy",
                    f"Account lockout threshold is {lockout_val} — acceptable",
                    "PASS",
                    "Lockout threshold is configured within recommended range.",
                ))
        except ValueError:
            pass

    history_str = policy.get("length of password history maintained", "None")
    if history_str.lower() == "none" or history_str == "0":
        findings.append(Finding(
            "PWD-004", "Password Policy",
            "Password history is not enforced",
            "WARNING",
            "Users can reuse old passwords immediately.",
            remediation="Enforce password history: net accounts /uniquepw:24"
        ))
    return findings


def check_open_ports(log: logging.Logger) -> List[Finding]:
    log.info("Checking open / listening ports...")
    findings: List[Finding] = []
    output = run_command("netstat -ano -p TCP")
    if not output:
        findings.append(Finding(
            "NET-001", "Network", "Unable to enumerate listening ports",
            "WARNING", "Could not run netstat.",
        ))
        return findings

    listening: List[Dict[str, Any]] = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[3].upper() == "LISTENING":
            local_addr = parts[1]
            pid = parts[4]
            port_str = local_addr.rsplit(":", 1)[-1]
            try:
                port = int(port_str)
            except ValueError:
                continue
            bind_addr = local_addr.rsplit(":", 1)[0]
            listening.append({
                "port": port,
                "bind": bind_addr,
                "pid": pid,
                "label": RISKY_PORTS.get(port, ""),
            })

    seen_ports: set[int] = set()
    unique_listening: List[Dict[str, Any]] = []
    for entry in listening:
        if entry["port"] not in seen_ports:
            seen_ports.add(entry["port"])
            unique_listening.append(entry)

    findings.append(Finding(
        "NET-001", "Network",
        f"Found {len(unique_listening)} unique listening TCP port(s)",
        "INFO",
        "Listening ports represent the system's attack surface.",
        detail="\n".join(
            f"Port {e['port']:>5}  Bind: {e['bind']:<20}  PID: {e['pid']:<8}  {e['label']}"
            for e in sorted(unique_listening, key=lambda x: x["port"])
        ),
    ))

    for entry in unique_listening:
        if entry["port"] in RISKY_PORTS:
            is_any_bind = entry["bind"] in ("0.0.0.0", "[::]", "")
            severity = "CRITICAL" if is_any_bind else "WARNING"
            findings.append(Finding(
                f"NET-{entry['port']:04d}", "Network",
                f"Risky port {entry['port']} ({RISKY_PORTS[entry['port']]}) is listening"
                + (" on ALL interfaces" if is_any_bind else ""),
                severity,
                f"Port {entry['port']} ({RISKY_PORTS[entry['port']]}) is commonly targeted by attackers.",
                detail=f"Bind: {entry['bind']}  PID: {entry['pid']}",
                remediation="Disable the service if not needed, or restrict with firewall rules."
            ))
    return findings


def check_firewall(log: logging.Logger) -> List[Finding]:
    log.info("Checking Windows Firewall status...")
    findings: List[Finding] = []
    output = run_command("netsh advfirewall show allprofiles state")
    if not output:
        findings.append(Finding(
            "FW-001", "Firewall", "Unable to query firewall status",
            "WARNING", "Could not determine Windows Firewall state.",
            remediation="Run as Administrator."
        ))
        return findings

    profiles_found: Dict[str, str] = {}
    current_profile = None
    for line in output.splitlines():
        line_stripped = line.strip()
        if "Profile Settings" in line_stripped:
            current_profile = line_stripped.split()[0]
        if "State" in line_stripped and current_profile:
            state = line_stripped.split()[-1].upper()
            profiles_found[current_profile] = state
            current_profile = None

    all_on = True
    for profile, state in profiles_found.items():
        if state != "ON":
            all_on = False
            findings.append(Finding(
                "FW-002", "Firewall",
                f"Firewall is DISABLED for {profile} profile",
                "CRITICAL",
                f"The {profile} firewall profile is off. The system is unprotected on that network type.",
                remediation=f"Enable firewall: netsh advfirewall set {profile.lower().replace(' ','')} state on"
            ))

    if all_on and profiles_found:
        findings.append(Finding(
            "FW-001", "Firewall",
            f"Windows Firewall is ON for all {len(profiles_found)} profile(s)",
            "PASS",
            "All firewall profiles are active.",
            detail=", ".join(f"{p}: {s}" for p, s in profiles_found.items()),
        ))
    elif not profiles_found:
        findings.append(Finding(
            "FW-001", "Firewall",
            "Could not parse firewall profile states",
            "WARNING", "Firewall status is unknown.",
        ))
    return findings


def check_smb_v1(log: logging.Logger) -> List[Finding]:
    log.info("Checking SMBv1 status...")
    findings: List[Finding] = []
    smb1_val = reg_read(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "SMB1",
        default=None,
    )
    mrxsmb10 = run_command("sc query mrxsmb10")
    mrxsmb10_running = "RUNNING" in mrxsmb10.upper() if mrxsmb10 else False

    if smb1_val == 0 and not mrxsmb10_running:
        findings.append(Finding(
            "SMB-001", "SMB Security", "SMBv1 is DISABLED",
            "PASS",
            "SMBv1 is disabled. This mitigates EternalBlue and related exploits.",
        ))
    elif smb1_val is None and not mrxsmb10_running:
        findings.append(Finding(
            "SMB-001", "SMB Security",
            "SMBv1 registry key not found — likely disabled by default",
            "INFO",
            "Modern Windows versions disable SMBv1 by default. Verify manually.",
            remediation="Explicitly disable: Set-SmbServerConfiguration -EnableSMB1Protocol $false"
        ))
    else:
        findings.append(Finding(
            "SMB-001", "SMB Security", "SMBv1 appears ENABLED",
            "CRITICAL",
            "SMBv1 is vulnerable to EternalBlue (MS17-010), WannaCry, NotPetya, and more.",
            detail=f"Registry SMB1 value: {smb1_val}, mrxsmb10 service running: {mrxsmb10_running}",
            remediation="Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"
        ))
    return findings


def check_rdp(log: logging.Logger) -> List[Finding]:
    log.info("Checking RDP configuration...")
    findings: List[Finding] = []
    rdp_enabled = reg_read(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Terminal Server",
        "fDenyTSConnections",
        default=1,
    )
    nla_enabled = reg_read(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
        "UserAuthentication",
        default=0,
    )
    if rdp_enabled == 0:
        if nla_enabled == 1:
            findings.append(Finding(
                "RDP-001", "Remote Access", "RDP is ENABLED with NLA (Network Level Authentication)",
                "WARNING",
                "RDP is active but NLA is enforced, which reduces brute-force risk.",
                remediation="If RDP is not needed, disable it. If needed, restrict by IP via firewall."
            ))
        else:
            findings.append(Finding(
                "RDP-001", "Remote Access", "RDP is ENABLED without NLA",
                "CRITICAL",
                "RDP without NLA is highly vulnerable to brute-force and BlueKeep-type exploits.",
                remediation="Enable NLA or disable RDP if not needed."
            ))
    else:
        findings.append(Finding(
            "RDP-001", "Remote Access", "RDP is DISABLED",
            "PASS",
            "Remote Desktop Protocol is not accepting connections.",
        ))
    return findings


def check_audit_policy(log: logging.Logger) -> List[Finding]:
    log.info("Checking audit policy...")
    findings: List[Finding] = []
    output = run_command("auditpol /get /category:*")
    if not output:
        findings.append(Finding(
            "AUD-001", "Audit Policy", "Unable to query audit policy",
            "WARNING",
            "Could not retrieve audit policy. Requires Administrator privileges.",
            remediation="Run as Administrator."
        ))
        return findings

    critical_subcategories: Dict[str, bool] = {
        "Logon": False,
        "Logoff": False,
        "Account Lockout": False,
        "User Account Management": False,
        "Security Group Management": False,
        "Process Creation": False,
        "Audit Policy Change": False,
        "Sensitive Privilege Use": False,
    }

    no_auditing_count = 0
    total_count = 0
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("System") or stripped.startswith("Category"):
            continue
        for subcat in critical_subcategories:
            if subcat.lower() in stripped.lower() and "no auditing" not in stripped.lower():
                critical_subcategories[subcat] = True
        if "No Auditing" in stripped:
            no_auditing_count += 1
        total_count += 1

    missing = [k for k, v in critical_subcategories.items() if not v]
    if missing:
        findings.append(Finding(
            "AUD-002", "Audit Policy",
            f"{len(missing)} critical audit subcategories are NOT configured",
            "CRITICAL" if len(missing) > 4 else "WARNING",
            "Missing audit policies create blind spots for incident response and forensics.",
            detail="Not audited: " + ", ".join(missing),
            remediation='Enable auditing: auditpol /set /subcategory:"Logon" /success:enable /failure:enable'
        ))
    else:
        findings.append(Finding(
            "AUD-002", "Audit Policy",
            "All critical audit subcategories are configured",
            "PASS",
            "Key security events are being logged.",
        ))

    if total_count > 0:
        pct_disabled = round((no_auditing_count / total_count) * 100)
        if pct_disabled > 50:
            findings.append(Finding(
                "AUD-003", "Audit Policy",
                f"{pct_disabled}% of audit subcategories have 'No Auditing'",
                "WARNING",
                "A large portion of auditable events are not being logged.",
                remediation="Review and enable audit policies per CIS benchmarks."
            ))
    return findings


def check_windows_update(log: logging.Logger) -> List[Finding]:
    log.info("Checking Windows Update status...")
    findings: List[Finding] = []
    output = run_command('wmic qfe get InstalledOn /format:csv')
    if not output:
        findings.append(Finding(
            "UPD-001", "Windows Update", "Unable to query installed updates",
            "WARNING", "Could not determine update history.",
            remediation="Run as Administrator or check Windows Update settings manually."
        ))
        return findings

    dates: List[datetime.datetime] = []
    reader = csv.DictReader(io.StringIO(output))
    for row in reader:
        date_str = row.get("InstalledOn", "").strip()
        if not date_str:
            continue
        for fmt in ("%m/%d/%Y", "%Y-%m-%d", "%d/%m/%Y", "%m-%d-%Y"):
            try:
                dt = datetime.datetime.strptime(date_str, fmt)
                dates.append(dt)
                break
            except ValueError:
                continue

    if dates:
        latest = max(dates)
        days_ago = (datetime.datetime.now() - latest).days
        findings.append(Finding(
            "UPD-001", "Windows Update",
            f"Last hotfix installed {days_ago} day(s) ago ({latest.strftime('%Y-%m-%d')})",
            "CRITICAL" if days_ago > 90 else ("WARNING" if days_ago > 30 else "PASS"),
            "Systems without recent patches are vulnerable to known exploits.",
            detail=f"Most recent hotfix date: {latest.strftime('%Y-%m-%d')} ({days_ago} days ago). "
                   f"Total hotfixes found: {len(dates)}.",
            remediation="Run Windows Update immediately if patches are overdue."
        ))
    else:
        findings.append(Finding(
            "UPD-001", "Windows Update",
            "No hotfix installation dates could be parsed",
            "WARNING", "Update status is unknown.",
        ))
    return findings


def check_antivirus(log: logging.Logger) -> List[Finding]:
    log.info("Checking antivirus status...")
    findings: List[Finding] = []
    defender_output = run_command(
        'powershell -NoProfile -Command "'
        'try { $s = Get-MpComputerStatus; '
        'Write-Output \\"RTP:$($s.RealTimeProtectionEnabled)\\"; '
        'Write-Output \\"AMS:$($s.AMServiceEnabled)\\"; '
        'Write-Output \\"AE:$($s.AntivirusEnabled)\\"; '
        'Write-Output \\"SigAge:$($s.AntivirusSignatureAge)\\"; '
        'Write-Output \\"LastScan:$($s.QuickScanEndTime)\\" '
        '} catch { Write-Output \\"ERROR:$($_.Exception.Message)\\" }'
        '"'
    )
    if "ERROR" in defender_output or not defender_output:
        findings.append(Finding(
            "AV-001", "Antivirus", "Could not query Windows Defender status",
            "WARNING",
            "Windows Defender may be managed by third-party AV or query failed.",
            remediation="Verify antivirus is installed and running."
        ))
        return findings

    parsed: Dict[str, str] = {}
    for line in defender_output.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            parsed[key.strip()] = val.strip()

    rtp = parsed.get("RTP", "").upper() == "TRUE"
    av_enabled = parsed.get("AE", "").upper() == "TRUE"
    sig_age_str = parsed.get("SigAge", "0")
    try:
        sig_age = int(sig_age_str)
    except ValueError:
        sig_age = -1

    if not av_enabled:
        findings.append(Finding(
            "AV-002", "Antivirus", "Windows Defender antivirus is DISABLED",
            "CRITICAL",
            "No real-time antivirus protection detected.",
            remediation="Enable Defender or install a reputable antivirus solution."
        ))
    elif not rtp:
        findings.append(Finding(
            "AV-002", "Antivirus", "Real-time protection is DISABLED",
            "CRITICAL",
            "Defender is installed but real-time scanning is off.",
            remediation="Enable real-time protection in Windows Security settings."
        ))
    else:
        findings.append(Finding(
            "AV-002", "Antivirus", "Windows Defender is active with real-time protection",
            "PASS",
            "Real-time antivirus protection is enabled.",
        ))

    if sig_age > 7:
        findings.append(Finding(
            "AV-003", "Antivirus",
            f"Antivirus signatures are {sig_age} day(s) old",
            "CRITICAL" if sig_age > 14 else "WARNING",
            "Outdated signatures miss recently discovered malware.",
            remediation="Update signatures: Update-MpSignature"
        ))
    elif sig_age >= 0:
        findings.append(Finding(
            "AV-003", "Antivirus",
            f"Antivirus signatures are {sig_age} day(s) old — current",
            "PASS",
            "Signatures are up to date.",
        ))
    return findings


def check_scheduled_tasks(
    log: logging.Logger,
    suspicious_keywords: List[str] = None,  # type: ignore[assignment]
    trusted_paths: List[str] = None,  # type: ignore[assignment]
) -> List[Finding]:
    log.info("Checking scheduled tasks for suspicious entries...")
    if suspicious_keywords is None:
        suspicious_keywords = DEFAULT_SUSPICIOUS_TASK_KEYWORDS
    if trusted_paths is None:
        trusted_paths = DEFAULT_TRUSTED_TASK_PATHS

    findings: List[Finding] = []
    output = run_command('schtasks /query /fo CSV /v')
    if not output:
        findings.append(Finding(
            "TSK-001", "Scheduled Tasks", "Unable to query scheduled tasks",
            "WARNING", "Could not enumerate scheduled tasks.",
            remediation="Run as Administrator."
        ))
        return findings

    try:
        reader = csv.DictReader(io.StringIO(output))
        suspicious: List[Dict[str, Any]] = []
        total = 0
        for row in reader:
            task_name = row.get("TaskName", "").strip()
            action = row.get("Task To Run", "").strip()
            status = row.get("Status", "").strip()
            author = row.get("Author", "").strip()
            if not task_name or not action:
                continue
            total += 1
            is_trusted = any(tp.lower() in task_name.lower() for tp in trusted_paths)
            if is_trusted:
                continue
            action_lower = action.lower()
            matched_keywords = [kw for kw in suspicious_keywords if kw in action_lower]
            if matched_keywords:
                suspicious.append({
                    "name": task_name,
                    "action": action[:200],
                    "author": author,
                    "status": status,
                    "matched": matched_keywords,
                })

        if suspicious:
            detail_lines = []
            for s in suspicious[:20]:
                detail_lines.append(
                    f"Task: {s['name']}\n"
                    f"  Action: {s['action']}\n"
                    f"  Author: {s['author']}\n"
                    f"  Triggers: {', '.join(s['matched'])}"
                )
            findings.append(Finding(
                "TSK-002", "Scheduled Tasks",
                f"Found {len(suspicious)} potentially suspicious scheduled task(s)",
                "WARNING" if len(suspicious) < 5 else "CRITICAL",
                "Scheduled tasks with suspicious commands may indicate persistence mechanisms.",
                detail="\n---\n".join(detail_lines),
                remediation="Review each flagged task. Remove unknown or unauthorized tasks."
            ))
        else:
            findings.append(Finding(
                "TSK-002", "Scheduled Tasks",
                f"No suspicious scheduled tasks found (scanned {total})",
                "PASS",
                "No tasks matched known suspicious patterns.",
            ))
    except Exception as exc:
        log.debug("Scheduled task parsing error: %s", exc)
        findings.append(Finding(
            "TSK-001", "Scheduled Tasks", "Error parsing scheduled tasks",
            "WARNING", f"Parsing error: {exc}",
        ))
    return findings


def check_startup_programs(log: logging.Logger) -> List[Finding]:
    log.info("Checking startup programs...")
    findings: List[Finding] = []
    startup_locations = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
    ]

    all_entries: List[Dict[str, str]] = []
    for hive, path, label in startup_locations:
        values = reg_enum_values(hive, path)
        for name, data in values.items():
            all_entries.append({
                "location": label,
                "name": name,
                "command": str(data)[:200],
            })

    findings.append(Finding(
        "STP-001", "Startup Programs",
        f"Found {len(all_entries)} startup program(s) in registry Run keys",
        "WARNING" if len(all_entries) > 8 else "INFO",
        "Startup entries can be used for persistence by malware.",
        detail="\n".join(
            f"[{e['location']}] {e['name']}: {e['command']}" for e in all_entries
        ) if all_entries else "No startup entries found.",
        remediation="Review each entry. Remove unknown or unauthorized startup programs."
    ))

    for entry in all_entries:
        cmd_lower = entry["command"].lower()
        if any(kw in cmd_lower for kw in ["%temp%", "\\temp\\", "appdata\\local\\temp", "pastebin", "downloadstring"]):
            findings.append(Finding(
                "STP-002", "Startup Programs",
                f"Suspicious startup entry: {entry['name']}",
                "CRITICAL",
                "This startup entry references a temp directory or known suspicious pattern.",
                detail=f"Location: {entry['location']}\nCommand: {entry['command']}",
                remediation="Investigate this entry immediately. It may indicate malware persistence."
            ))
    return findings


def check_powershell_settings(log: logging.Logger) -> List[Finding]:
    log.info("Checking PowerShell security settings...")
    findings: List[Finding] = []
    exec_policy = run_command(
        'powershell -NoProfile -Command "Get-ExecutionPolicy"'
    ).strip()

    if exec_policy:
        if exec_policy.lower() in ("unrestricted", "bypass"):
            findings.append(Finding(
                "PS-001", "PowerShell", f"Execution policy is '{exec_policy}'",
                "WARNING",
                "Unrestricted execution policy allows any script to run without prompts.",
                remediation="Set to RemoteSigned or AllSigned: Set-ExecutionPolicy RemoteSigned -Force"
            ))
        else:
            findings.append(Finding(
                "PS-001", "PowerShell", f"Execution policy is '{exec_policy}'",
                "PASS" if exec_policy.lower() in ("restricted", "allsigned") else "INFO",
                "Execution policy provides baseline script control.",
            ))

    script_block_logging = reg_read(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "EnableScriptBlockLogging",
        default=0,
    )
    if script_block_logging == 1:
        findings.append(Finding(
            "PS-002", "PowerShell", "Script block logging is ENABLED",
            "PASS",
            "PowerShell commands are being logged for forensic analysis.",
        ))
    else:
        findings.append(Finding(
            "PS-002", "PowerShell", "Script block logging is DISABLED",
            "WARNING",
            "Without script block logging, malicious PowerShell activity is invisible to defenders.",
            remediation="Enable via GPO or registry: "
                        "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging "
                        "EnableScriptBlockLogging = 1"
        ))

    module_logging = reg_read(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
        "EnableModuleLogging",
        default=0,
    )
    if module_logging != 1:
        findings.append(Finding(
            "PS-003", "PowerShell", "Module logging is DISABLED",
            "INFO",
            "PowerShell module logging provides additional visibility into cmdlet usage.",
            remediation="Enable via GPO for enhanced logging."
        ))
    return findings


def check_uac(log: logging.Logger) -> List[Finding]:
    log.info("Checking UAC settings...")
    findings: List[Finding] = []
    uac_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    enable_lua = reg_read(winreg.HKEY_LOCAL_MACHINE, uac_key, "EnableLUA", default=1)
    consent_admin = reg_read(winreg.HKEY_LOCAL_MACHINE, uac_key, "ConsentPromptBehaviorAdmin", default=5)

    if enable_lua == 0:
        findings.append(Finding(
            "UAC-001", "UAC", "User Account Control is DISABLED",
            "CRITICAL",
            "UAC is turned off. All programs run with full privileges without prompting.",
            remediation="Enable UAC: Set EnableLUA to 1 in "
                        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
        ))
    else:
        findings.append(Finding(
            "UAC-001", "UAC", "User Account Control is ENABLED",
            "PASS",
            "UAC is active and will prompt for elevation.",
        ))

    if consent_admin == 0 and enable_lua == 1:
        findings.append(Finding(
            "UAC-002", "UAC", "UAC admin prompt is set to 'Elevate without prompting'",
            "WARNING",
            "Admin users can elevate without a UAC prompt, weakening the security boundary.",
            remediation="Set ConsentPromptBehaviorAdmin to 2 (prompt for consent on secure desktop)."
        ))
    return findings


def check_bitlocker(log: logging.Logger) -> List[Finding]:
    log.info("Checking BitLocker encryption status...")
    findings: List[Finding] = []
    output = run_command(
        'powershell -NoProfile -Command "'
        'try { $vols = Get-BitLockerVolume -ErrorAction Stop; '
        'foreach ($v in $vols) { '
        'Write-Output \\"$($v.MountPoint)|$($v.ProtectionStatus)|$($v.EncryptionPercentage)|$($v.VolumeStatus)\\" '
        '} } catch { Write-Output \\"ERROR:$($_.Exception.Message)\\" }'
        '"'
    )
    if not output or "ERROR" in output:
        findings.append(Finding(
            "BL-001", "Disk Encryption", "Unable to query BitLocker status",
            "WARNING",
            "Could not determine BitLocker encryption state. Requires Administrator privileges.",
            remediation="Run as Administrator, or check BitLocker status via manage-bde -status"
        ))
        return findings

    any_unprotected = False
    for line in output.splitlines():
        parts = line.strip().split("|")
        if len(parts) < 4:
            continue
        mount, protection, pct, status = parts[0], parts[1], parts[2], parts[3]
        if protection.strip().upper() == "ON":
            findings.append(Finding(
                "BL-002", "Disk Encryption",
                f"BitLocker is ON for {mount.strip()} ({pct.strip()}% encrypted)",
                "PASS",
                f"Volume {mount.strip()} is protected by BitLocker.",
                detail=f"Volume Status: {status.strip()}"
            ))
        else:
            any_unprotected = True
            findings.append(Finding(
                "BL-002", "Disk Encryption",
                f"BitLocker is OFF for {mount.strip()}",
                "CRITICAL",
                f"Volume {mount.strip()} is NOT encrypted. Data at rest is exposed if the device is lost or stolen.",
                detail=f"Protection: {protection.strip()}, Volume Status: {status.strip()}",
                remediation=f"Enable BitLocker: manage-bde -on {mount.strip()}"
            ))

    if not any_unprotected and findings:
        pass  # all volumes protected
    elif not findings:
        findings.append(Finding(
            "BL-001", "Disk Encryption", "No BitLocker volumes detected",
            "INFO", "BitLocker may not be available on this edition of Windows.",
        ))
    return findings


def check_credential_guard(log: logging.Logger) -> List[Finding]:
    log.info("Checking Credential Guard status...")
    findings: List[Finding] = []
    cg_val = reg_read(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\LSA",
        "LsaCfgFlags",
        default=None,
    )
    device_guard_output = run_command(
        'powershell -NoProfile -Command "'
        'try { $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction Stop; '
        'Write-Output \\"VSM:$($dg.VirtualizationBasedSecurityStatus)\\"; '
        'Write-Output \\"CG:$($dg.SecurityServicesRunning -join \',\')\\" '
        '} catch { Write-Output \\"ERROR:$($_.Exception.Message)\\" }'
        '"'
    )

    cg_running = False
    if device_guard_output and "ERROR" not in device_guard_output:
        for line in device_guard_output.splitlines():
            if line.startswith("CG:") and "1" in line.partition(":")[2]:
                cg_running = True

    if cg_running:
        findings.append(Finding(
            "CG-001", "Credential Guard", "Credential Guard is RUNNING",
            "PASS",
            "Windows Credential Guard is active, protecting NTLM hashes and Kerberos tickets from theft.",
        ))
    elif cg_val is not None and cg_val > 0:
        findings.append(Finding(
            "CG-001", "Credential Guard", "Credential Guard is configured but may not be running",
            "WARNING",
            "LsaCfgFlags is set but Credential Guard was not confirmed running. A reboot may be required.",
            detail=f"LsaCfgFlags: {cg_val}",
            remediation="Reboot the system, then verify with msinfo32 or Get-CimInstance Win32_DeviceGuard."
        ))
    else:
        findings.append(Finding(
            "CG-001", "Credential Guard",
            "Credential Guard is NOT configured",
            "WARNING",
            "Credential Guard protects cached credentials from pass-the-hash and pass-the-ticket attacks.",
            remediation="Enable via Group Policy: Computer Config > Admin Templates > System > Device Guard > "
                        "Turn On Virtualization Based Security > Credential Guard: Enabled with UEFI lock"
        ))
    return findings


def check_secure_boot(log: logging.Logger) -> List[Finding]:
    log.info("Checking Secure Boot status...")
    findings: List[Finding] = []
    output = run_command(
        'powershell -NoProfile -Command "try { Confirm-SecureBootUEFI } catch { Write-Output ERROR }"'
    )
    if output.strip().upper() == "TRUE":
        findings.append(Finding(
            "SB-001", "Secure Boot", "Secure Boot is ENABLED",
            "PASS",
            "UEFI Secure Boot is active, protecting against boot-level malware and rootkits.",
        ))
    elif output.strip().upper() == "FALSE":
        findings.append(Finding(
            "SB-001", "Secure Boot", "Secure Boot is DISABLED",
            "WARNING",
            "Without Secure Boot, the system is vulnerable to bootkits and firmware-level malware.",
            remediation="Enable Secure Boot in UEFI/BIOS firmware settings."
        ))
    else:
        findings.append(Finding(
            "SB-001", "Secure Boot", "Could not determine Secure Boot status",
            "INFO",
            "Secure Boot query failed. The system may use legacy BIOS instead of UEFI.",
        ))
    return findings


def check_network_shares(log: logging.Logger) -> List[Finding]:
    log.info("Checking network shares...")
    findings: List[Finding] = []
    output = run_command("net share")
    if not output:
        findings.append(Finding(
            "SHR-001", "Network Shares", "Unable to enumerate network shares",
            "WARNING", "Could not query network shares.",
            remediation="Run as Administrator."
        ))
        return findings

    shares: List[str] = []
    for line in output.splitlines()[4:]:  # skip header lines
        parts = line.split()
        if not parts:
            continue
        share_name = parts[0].strip()
        if share_name.startswith("The command") or share_name == "":
            break
        shares.append(share_name)

    admin_shares = [s for s in shares if s.endswith("$")]
    user_shares = [s for s in shares if not s.endswith("$")]

    if user_shares:
        findings.append(Finding(
            "SHR-002", "Network Shares",
            f"Found {len(user_shares)} user-created network share(s)",
            "WARNING" if len(user_shares) > 3 else "INFO",
            "User-created shares may expose sensitive data to the network.",
            detail="Shares: " + ", ".join(user_shares),
            remediation="Review each share and remove unnecessary ones. Restrict permissions with: "
                        "net share ShareName /grant:DOMAIN\\User,READ"
        ))
    else:
        findings.append(Finding(
            "SHR-002", "Network Shares",
            "No user-created network shares found",
            "PASS",
            "Only default administrative shares are present.",
            detail="Administrative shares: " + ", ".join(admin_shares) if admin_shares else "None",
        ))
    return findings


def check_event_log_service(log: logging.Logger) -> List[Finding]:
    log.info("Checking Windows Event Log service...")
    findings: List[Finding] = []
    output = run_command("sc query EventLog")
    if not output:
        findings.append(Finding(
            "EVT-001", "Event Logging", "Unable to query Event Log service",
            "WARNING", "Could not determine Event Log service state.",
        ))
        return findings

    running = "RUNNING" in output.upper()
    if running:
        findings.append(Finding(
            "EVT-001", "Event Logging", "Windows Event Log service is RUNNING",
            "PASS", "The Event Log service is active and recording security events.",
        ))
    else:
        findings.append(Finding(
            "EVT-001", "Event Logging", "Windows Event Log service is NOT running",
            "CRITICAL",
            "The Event Log service is stopped. Security events are not being recorded. "
            "This could indicate tampering.",
            remediation="Start the service: net start EventLog"
        ))

    sec_log_output = run_command(
        'powershell -NoProfile -Command "'
        'try { $l = Get-WinEvent -ListLog Security -ErrorAction Stop; '
        'Write-Output \\"Size:$($l.FileSize)\\"; '
        'Write-Output \\"Max:$($l.MaximumSizeInBytes)\\"; '
        'Write-Output \\"Records:$($l.RecordCount)\\" '
        '} catch { Write-Output \\"ERROR\\" }'
        '"'
    )
    if sec_log_output and "ERROR" not in sec_log_output:
        parsed: Dict[str, str] = {}
        for line in sec_log_output.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                parsed[k.strip()] = v.strip()
        try:
            max_bytes = int(parsed.get("Max", "0"))
            max_mb = max_bytes / (1024 * 1024)
            records = parsed.get("Records", "unknown")
            if max_mb < 64:
                findings.append(Finding(
                    "EVT-002", "Event Logging",
                    f"Security log max size is only {max_mb:.0f} MB ({records} records)",
                    "WARNING",
                    "A small Security log can be overwritten quickly, destroying forensic evidence.",
                    detail=f"Max size: {max_mb:.0f} MB, Records: {records}",
                    remediation="Increase Security log size: wevtutil sl Security /ms:209715200 (200 MB)"
                ))
            else:
                findings.append(Finding(
                    "EVT-002", "Event Logging",
                    f"Security log max size is {max_mb:.0f} MB ({records} records)",
                    "PASS",
                    "Security log size is adequate for forensic retention.",
                ))
        except (ValueError, TypeError):
            pass
    return findings


def check_installed_software(log: logging.Logger) -> List[Finding]:
    log.info("Inventorying installed software...")
    findings: List[Finding] = []
    uninstall_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    software: List[Dict[str, str]] = []
    for hive, path in uninstall_paths:
        try:
            with winreg.OpenKey(hive, path) as key:
                subkey_count = winreg.QueryInfoKey(key)[0]
                for i in range(subkey_count):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            try:
                                name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                            except (FileNotFoundError, OSError):
                                continue
                            try:
                                version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                            except (FileNotFoundError, OSError):
                                version = "Unknown"
                            try:
                                publisher = winreg.QueryValueEx(subkey, "Publisher")[0]
                            except (FileNotFoundError, OSError):
                                publisher = "Unknown"
                            if name.strip():
                                software.append({
                                    "name": name.strip(),
                                    "version": str(version).strip(),
                                    "publisher": str(publisher).strip(),
                                })
                    except OSError:
                        continue
        except (FileNotFoundError, OSError):
            continue

    seen: set[str] = set()
    unique: List[Dict[str, str]] = []
    for sw in software:
        k = sw["name"].lower()
        if k not in seen:
            seen.add(k)
            unique.append(sw)
    unique.sort(key=lambda x: x["name"].lower())

    findings.append(Finding(
        "SW-001", "Software Inventory",
        f"Found {len(unique)} installed application(s)",
        "INFO",
        "Software inventory for asset management and vulnerability assessment.",
        detail="\n".join(
            f"{sw['name']} v{sw['version']} ({sw['publisher']})" for sw in unique[:50]
        ) + (f"\n... and {len(unique) - 50} more" if len(unique) > 50 else ""),
    ))
    return findings


def run_all_checks(
    log: logging.Logger,
    suspicious_keywords: List[str] = None,  # type: ignore[assignment]
    trusted_paths: List[str] = None,  # type: ignore[assignment]
) -> List[Finding]:
    if suspicious_keywords is None:
        suspicious_keywords = DEFAULT_SUSPICIOUS_TASK_KEYWORDS
    if trusted_paths is None:
        trusted_paths = DEFAULT_TRUSTED_TASK_PATHS

    all_findings: List[Finding] = []
    checks = [
        ("Local User Accounts", lambda lg: check_local_users(lg)),
        ("Local Administrators", lambda lg: check_local_admins(lg)),
        ("Password Policy", lambda lg: check_password_policy(lg)),
        ("Open Ports", lambda lg: check_open_ports(lg)),
        ("Firewall Status", lambda lg: check_firewall(lg)),
        ("SMBv1 Protocol", lambda lg: check_smb_v1(lg)),
        ("RDP Configuration", lambda lg: check_rdp(lg)),
        ("Audit Policy", lambda lg: check_audit_policy(lg)),
        ("Windows Update", lambda lg: check_windows_update(lg)),
        ("Antivirus Status", lambda lg: check_antivirus(lg)),
        ("Scheduled Tasks", lambda lg: check_scheduled_tasks(lg, suspicious_keywords, trusted_paths)),
        ("Startup Programs", lambda lg: check_startup_programs(lg)),
        ("PowerShell Security", lambda lg: check_powershell_settings(lg)),
        ("UAC Settings", lambda lg: check_uac(lg)),
        ("BitLocker Encryption", lambda lg: check_bitlocker(lg)),
        ("Credential Guard", lambda lg: check_credential_guard(lg)),
        ("Secure Boot", lambda lg: check_secure_boot(lg)),
        ("Network Shares", lambda lg: check_network_shares(lg)),
        ("Event Log Service", lambda lg: check_event_log_service(lg)),
        ("Installed Software", lambda lg: check_installed_software(lg)),
    ]

    for name, check_func in checks:
        log.info("─" * 50)
        try:
            results = check_func(log)
            all_findings.extend(results)
            crit = sum(1 for f in results if f.severity == "CRITICAL")
            warn = sum(1 for f in results if f.severity == "WARNING")
            if crit:
                log.info("  └─ %s: %d finding(s) — %d CRITICAL", name, len(results), crit)
            elif warn:
                log.info("  └─ %s: %d finding(s) — %d WARNING(s)", name, len(results), warn)
            else:
                log.info("  └─ %s: %d finding(s) — OK", name, len(results))
        except Exception as exc:
            log.error("  └─ %s: CHECK FAILED — %s", name, exc)
            all_findings.append(Finding(
                "ERR-000", name, f"Check failed: {name}",
                "WARNING",
                f"This check encountered an error: {exc}",
                remediation="Review the log file for details. Ensure you have Administrator privileges."
            ))
    return all_findings
