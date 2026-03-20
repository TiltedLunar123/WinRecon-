"""Report generation (HTML and JSON) for WinRecon."""

import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

from winrecon.core import (
    AUTHOR,
    TOOL_NAME,
    VERSION,
    Finding,
    _esc,
)


def generate_html_report(
    system_info: Dict[str, Any],
    findings: List[Finding],
    score_data: Dict[str, Any],
    output_path: Path,
    log: logging.Logger,
) -> None:
    log.info("Generating HTML report: %s", output_path)

    severity_colors = {
        "CRITICAL": "#ff4d6a",
        "WARNING": "#ffb347",
        "INFO": "#a78bfa",
        "PASS": "#34d399",
    }

    if score_data["score"] >= 80:
        score_color = "#34d399"
    elif score_data["score"] >= 60:
        score_color = "#ffb347"
    else:
        score_color = "#ff4d6a"

    categories: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        categories[f.category].append(f)

    findings_html_parts: List[str] = []
    for category, cat_findings in categories.items():
        findings_html_parts.append(f'<h2 style="color:#c084fc;font-size:1.4em;margin:28px 0 12px 0;padding-bottom:8px;border-bottom:2px solid #2d1b4e;">{_esc(category)}</h2>')
        for f in cat_findings:
            color = severity_colors.get(f.severity, "#6b7280")
            detail_html = ""
            if f.detail:
                escaped_detail = _esc(f.detail).replace("\n", "<br>")
                detail_html = (
                    f'<div style="background:#1a0a2e;padding:12px;border-radius:6px;'
                    f'font-family:Consolas,Courier New,monospace;font-size:0.85em;margin-top:10px;'
                    f'overflow-x:auto;word-break:break-all;color:#d8b4fe;">'
                    f'<strong style="color:#c084fc;">Details:</strong><br>{escaped_detail}</div>'
                )
            remediation_html = ""
            if f.remediation:
                escaped_rem = _esc(f.remediation)
                remediation_html = (
                    f'<div style="margin-top:10px;padding:10px 14px;background:#1e1040;'
                    f'border-left:3px solid #a78bfa;border-radius:4px;font-size:0.9em;color:#e0d4f5;">'
                    f'<strong style="color:#c084fc;">Remediation:</strong> {escaped_rem}</div>'
                )
            findings_html_parts.append(
                f'<div style="background:#1e1040;border:1px solid #3b1f6e;border-radius:8px;margin-bottom:12px;overflow:hidden;">'
                f'<div style="padding:14px 18px;background:#2d1b4e;display:flex;align-items:center;gap:10px;flex-wrap:wrap;">'
                f'<span style="padding:3px 10px;border-radius:4px;font-size:0.75em;font-weight:700;color:#fff;text-transform:uppercase;letter-spacing:0.5px;white-space:nowrap;background-color:{color};">{f.severity}</span>'
                f'<span style="color:#8b7aaa;font-size:0.85em;font-family:monospace;">[{_esc(f.check_id)}]</span>'
                f'<span style="font-weight:600;color:#e0d4f5;">{_esc(f.title)}</span>'
                f'</div>'
                f'<div style="padding:14px 18px;color:#d0c4e8;">'
                f'<p style="margin-bottom:10px;">{_esc(f.description)}</p>'
                f'{detail_html}'
                f'{remediation_html}'
                f'</div>'
                f'</div>'
            )

    findings_html = "\n".join(findings_html_parts)
    ip_html = _esc(", ".join(system_info.get("ip_addresses", [])))
    admin_badge = "Yes &#10004;" if system_info["is_admin"] else "No &#9888;"

    html = (
        '<!DOCTYPE html>'
        '<html lang="en">'
        '<head>'
        '<meta charset="UTF-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1.0">'
        f'<title>WinRecon Security Audit Report - {_esc(system_info["hostname"])}</title>'
        '</head>'
        '<body style="margin:0;padding:0;font-family:Segoe UI,Tahoma,Geneva,Verdana,sans-serif;'
        'background:#0d0015;color:#d0c4e8;line-height:1.6;">'
        '<div style="max-width:1100px;margin:0 auto;padding:20px;">'
        # Header
        '<div style="background:linear-gradient(135deg,#1a0a2e 0%,#2d1b4e 100%);'
        'border:1px solid #3b1f6e;border-radius:12px;padding:30px;margin-bottom:24px;text-align:center;">'
        f'<h1 style="font-size:2.2em;color:#c084fc;margin:0 0 8px 0;">&#128737; {TOOL_NAME} Security Audit Report</h1>'
        f'<div style="color:#8b7aaa;font-size:1.1em;">{_esc(system_info["hostname"])} &mdash; {_esc(system_info["scan_time"])}</div>'
        f'<div style="color:#6b5b8a;font-size:0.85em;margin-top:6px;">Created by {AUTHOR}</div>'
        '</div>'
        # Dashboard
        '<div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr 1fr;gap:16px;margin-bottom:24px;">'
        # Score card
        f'<div style="background:linear-gradient(135deg,#1a0a2e 0%,#2d1b4e 100%);'
        f'border:2px solid {score_color};border-radius:10px;padding:20px;text-align:center;">'
        f'<div style="font-size:2.4em;font-weight:700;color:{score_color};margin-bottom:4px;">{score_data["score"]}/100</div>'
        f'<div style="font-size:0.85em;color:#8b7aaa;text-transform:uppercase;letter-spacing:1px;">Security Score ({score_data["grade"]})</div>'
        '</div>'
        # Critical card
        '<div style="background:#1e1040;border:1px solid #3b1f6e;border-radius:10px;padding:20px;text-align:center;">'
        f'<div style="font-size:2.4em;font-weight:700;color:#ff4d6a;margin-bottom:4px;">{score_data["critical"]}</div>'
        '<div style="font-size:0.85em;color:#8b7aaa;text-transform:uppercase;letter-spacing:1px;">Critical</div>'
        '</div>'
        # Warning card
        '<div style="background:#1e1040;border:1px solid #3b1f6e;border-radius:10px;padding:20px;text-align:center;">'
        f'<div style="font-size:2.4em;font-weight:700;color:#ffb347;margin-bottom:4px;">{score_data["warning"]}</div>'
        '<div style="font-size:0.85em;color:#8b7aaa;text-transform:uppercase;letter-spacing:1px;">Warnings</div>'
        '</div>'
        # Pass card
        '<div style="background:#1e1040;border:1px solid #3b1f6e;border-radius:10px;padding:20px;text-align:center;">'
        f'<div style="font-size:2.4em;font-weight:700;color:#34d399;margin-bottom:4px;">{score_data["pass"]}</div>'
        '<div style="font-size:0.85em;color:#8b7aaa;text-transform:uppercase;letter-spacing:1px;">Passed</div>'
        '</div>'
        # Info card
        '<div style="background:#1e1040;border:1px solid #3b1f6e;border-radius:10px;padding:20px;text-align:center;">'
        f'<div style="font-size:2.4em;font-weight:700;color:#a78bfa;margin-bottom:4px;">{score_data["info"]}</div>'
        '<div style="font-size:0.85em;color:#8b7aaa;text-transform:uppercase;letter-spacing:1px;">Info</div>'
        '</div>'
        '</div>'
        # System Info
        '<div style="background:#1e1040;border:1px solid #3b1f6e;border-radius:10px;padding:20px;margin-bottom:24px;">'
        '<h2 style="color:#c084fc;margin:0 0 12px 0;font-size:1.3em;">System Information</h2>'
        '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">'
        f'<div style="padding:6px 12px;background:#1a0a2e;border-radius:6px;font-size:0.9em;"><strong style="color:#c084fc;">Hostname:</strong> {_esc(system_info["hostname"])}</div>'
        f'<div style="padding:6px 12px;background:#1a0a2e;border-radius:6px;font-size:0.9em;"><strong style="color:#c084fc;">OS:</strong> {_esc(system_info["os"])}</div>'
        f'<div style="padding:6px 12px;background:#1a0a2e;border-radius:6px;font-size:0.9em;"><strong style="color:#c084fc;">Version:</strong> {_esc(system_info["os_version"])}</div>'
        f'<div style="padding:6px 12px;background:#1a0a2e;border-radius:6px;font-size:0.9em;"><strong style="color:#c084fc;">Architecture:</strong> {_esc(system_info["architecture"])}</div>'
        f'<div style="padding:6px 12px;background:#1a0a2e;border-radius:6px;font-size:0.9em;"><strong style="color:#c084fc;">Current User:</strong> {_esc(system_info["current_user"])}</div>'
        f'<div style="padding:6px 12px;background:#1a0a2e;border-radius:6px;font-size:0.9em;"><strong style="color:#c084fc;">Admin Privileges:</strong> {admin_badge}</div>'
        f'<div style="padding:6px 12px;background:#1a0a2e;border-radius:6px;font-size:0.9em;"><strong style="color:#c084fc;">Domain:</strong> {_esc(system_info["domain"])}</div>'
        f'<div style="padding:6px 12px;background:#1a0a2e;border-radius:6px;font-size:0.9em;"><strong style="color:#c084fc;">IP Addresses:</strong> {ip_html}</div>'
        '</div>'
        '</div>'
        # Findings
        f'{findings_html}'
        # Footer
        '<div style="text-align:center;padding:20px;color:#5b4f6e;font-size:0.85em;margin-top:30px;border-top:1px solid #2d1b4e;">'
        f'Generated by {TOOL_NAME} v{VERSION} &mdash; Author: {AUTHOR} &mdash; {_esc(system_info["scan_time"])}<br>'
        'This report is for authorized security assessment purposes only.'
        '</div>'
        '</div>'
        '</body>'
        '</html>'
    )

    output_path.write_text(html, encoding="utf-8")
    log.info("HTML report saved: %s", output_path)


def export_json(
    system_info: Dict[str, Any],
    findings: List[Finding],
    score_data: Dict[str, Any],
    output_path: Path,
    log: logging.Logger,
) -> None:
    log.info("Exporting JSON report: %s", output_path)
    data = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "author": AUTHOR,
        "system_info": system_info,
        "score": score_data,
        "findings": [f.to_dict() for f in findings],
    }
    output_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    log.info("JSON report saved: %s", output_path)
