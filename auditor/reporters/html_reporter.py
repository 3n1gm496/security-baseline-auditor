"""HTML reporter — elegant visual report."""

from __future__ import annotations

import html
import logging
import os
from typing import List

from auditor.models import AuditResult, CheckStatus, Severity

logger = logging.getLogger(__name__)

SEVERITY_BADGE = {
    "critical": "#dc3545",
    "high": "#e74c3c",
    "medium": "#f39c12",
    "low": "#3498db",
    "info": "#95a5a6",
}

STATUS_BADGE = {
    "pass": "#27ae60",
    "fail": "#e74c3c",
    "warn": "#f39c12",
    "error": "#8e44ad",
    "skip": "#95a5a6",
}


class HtmlReporter:
    """Export audit results as an elegant HTML report."""

    def export(self, result: AuditResult, output_dir: str) -> str:
        os.makedirs(output_dir, exist_ok=True)
        filename = f"sbaudit-report-{result.timestamp[:19].replace(':', '-')}.html"
        filepath = os.path.join(output_dir, filename)

        content = self._render(result)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        logger.info("HTML report exported: %s", filepath)
        return filepath

    def _render(self, result: AuditResult) -> str:
        summary = result.summary
        host = result.host_info

        sections = []
        sections.append(self._section_host(host))
        sections.append(self._section_network(result))
        sections.append(self._section_findings(result))
        sections.append(self._section_secrets(result))
        sections.append(self._section_file_perms(result))
        sections.append(self._section_remediation(result))

        risk_color = SEVERITY_BADGE.get(summary["risk_label"].lower(), "#333")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Baseline Audit Report</title>
<style>
  :root {{
    --bg: #f8f9fa; --card: #fff; --border: #dee2e6;
    --text: #212529; --muted: #6c757d;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  h1 {{ font-size: 1.8rem; margin-bottom: 0.5rem; }}
  h2 {{ font-size: 1.3rem; margin: 1.5rem 0 0.8rem; border-bottom: 2px solid var(--border); padding-bottom: 0.3rem; }}
  .meta {{ color: var(--muted); font-size: 0.9rem; margin-bottom: 1.5rem; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem; margin-bottom: 1rem; }}
  .score-box {{ text-align: center; padding: 1.5rem; border-radius: 8px; color: #fff; font-size: 2rem; font-weight: bold; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 1rem; }}
  .stat {{ text-align: center; }}
  .stat .num {{ font-size: 1.8rem; font-weight: bold; }}
  .stat .label {{ color: var(--muted); font-size: 0.85rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
  th, td {{ padding: 0.5rem 0.7rem; text-align: left; border-bottom: 1px solid var(--border); }}
  th {{ background: #f1f3f5; font-weight: 600; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; color: #fff; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }}
  .evidence {{ font-family: monospace; font-size: 0.8rem; color: var(--muted); word-break: break-all; }}
  .remediation {{ font-size: 0.85rem; color: #155724; background: #d4edda; padding: 0.4rem 0.6rem; border-radius: 4px; margin-top: 0.3rem; }}
  footer {{ text-align: center; color: var(--muted); font-size: 0.8rem; margin-top: 2rem; }}
</style>
</head>
<body>
<div class="container">
  <h1>Security Baseline Audit Report</h1>
  <div class="meta">
    Generated: {html.escape(result.timestamp)} &middot;
    Mode: {html.escape(result.scan_mode)} &middot;
    Duration: {result.duration_seconds}s
  </div>

  <div class="grid">
    <div class="card score-box" style="background:{risk_color}">
      {summary['risk_score']}/100<br>
      <span style="font-size:1rem">{summary['risk_label']}</span>
    </div>
    <div class="card stat"><div class="num">{summary['total_checks']}</div><div class="label">Total Checks</div></div>
    <div class="card stat"><div class="num">{summary['status_counts'].get('fail', 0)}</div><div class="label">Failed</div></div>
    <div class="card stat"><div class="num">{summary['secrets_found']}</div><div class="label">Secrets Found</div></div>
    <div class="card stat"><div class="num">{summary['public_ports']}</div><div class="label">Public Ports</div></div>
  </div>

  {''.join(sections)}

  <footer>
    security-baseline-auditor &mdash; Defensive, read-only security audit tool
  </footer>
</div>
</body>
</html>"""

    def _badge(self, text: str, color: str) -> str:
        return f'<span class="badge" style="background:{color}">{html.escape(text)}</span>'

    def _section_host(self, host) -> str:
        if not host:
            return ""
        return f"""
  <h2>Host Information</h2>
  <div class="card">
    <table>
      <tr><th>Hostname</th><td>{html.escape(host.hostname)}</td></tr>
      <tr><th>OS</th><td>{html.escape(host.os_name)} ({html.escape(host.os_family)})</td></tr>
      <tr><th>Kernel</th><td>{html.escape(host.kernel_version)}</td></tr>
      <tr><th>Architecture</th><td>{html.escape(host.architecture)}</td></tr>
      <tr><th>Uptime</th><td>{html.escape(host.uptime)}</td></tr>
      <tr><th>Local Users</th><td>{html.escape(', '.join(host.local_users[:10]))}</td></tr>
      <tr><th>Security Tools</th><td>{html.escape(', '.join(host.security_tools) or 'None detected')}</td></tr>
    </table>
  </div>"""

    def _section_network(self, result: AuditResult) -> str:
        if not result.listening_ports:
            return ""
        rows = ""
        for p in result.listening_ports:
            pub = self._badge("PUBLIC", "#e74c3c") if p.is_public else self._badge("local", "#27ae60")
            rows += f"""<tr>
        <td>{html.escape(p.protocol)}</td>
        <td>{html.escape(p.local_address)}</td>
        <td>{p.local_port}</td>
        <td>{p.pid or '-'}</td>
        <td>{html.escape(p.process_name or '-')}</td>
        <td>{html.escape(p.user or '-')}</td>
        <td>{pub}</td>
      </tr>"""
        return f"""
  <h2>Network Exposure ({len(result.listening_ports)} ports)</h2>
  <div class="card">
    <table>
      <tr><th>Proto</th><th>Address</th><th>Port</th><th>PID</th><th>Process</th><th>User</th><th>Binding</th></tr>
      {rows}
    </table>
  </div>"""

    def _section_findings(self, result: AuditResult) -> str:
        if not result.findings:
            return ""
        rows = ""
        for f in result.findings:
            sev_color = SEVERITY_BADGE.get(f.severity.value, "#333")
            st_color = STATUS_BADGE.get(f.status.value, "#333")
            evidence = ""
            if f.status in (CheckStatus.FAIL, CheckStatus.WARN) and f.evidence:
                evidence = f'<div class="evidence">{html.escape(f.evidence[:200])}</div>'
            rows += f"""<tr>
        <td>{self._badge(f.status.value, st_color)}</td>
        <td>{self._badge(f.severity.value, sev_color)}</td>
        <td>{html.escape(f.check_id)}</td>
        <td>{html.escape(f.title)}{evidence}</td>
      </tr>"""
        return f"""
  <h2>Hardening Checks ({len(result.findings)})</h2>
  <div class="card">
    <table>
      <tr><th>Status</th><th>Severity</th><th>ID</th><th>Title</th></tr>
      {rows}
    </table>
  </div>"""

    def _section_secrets(self, result: AuditResult) -> str:
        if not result.secret_findings:
            return ""
        rows = ""
        for s in result.secret_findings:
            sev_color = SEVERITY_BADGE.get(s.severity.value, "#333")
            rows += f"""<tr>
        <td>{self._badge(s.severity.value, sev_color)}</td>
        <td>{html.escape(s.pattern_name)}</td>
        <td>{html.escape(s.file_path)}:{s.line_number}</td>
        <td class="evidence">{html.escape(s.masked_value)}</td>
      </tr>"""
        return f"""
  <h2>Secret Exposure ({len(result.secret_findings)})</h2>
  <div class="card">
    <table>
      <tr><th>Severity</th><th>Pattern</th><th>Location</th><th>Value (masked)</th></tr>
      {rows}
    </table>
  </div>"""

    def _section_file_perms(self, result: AuditResult) -> str:
        if not result.file_permission_findings:
            return ""
        rows = ""
        for f in result.file_permission_findings:
            sev_color = SEVERITY_BADGE.get(f.severity.value, "#333")
            rows += f"""<tr>
        <td>{self._badge(f.severity.value, sev_color)}</td>
        <td>{html.escape(f.issue)}</td>
        <td>{html.escape(f.file_path)}</td>
        <td>{html.escape(f.current_permissions)}</td>
      </tr>"""
        return f"""
  <h2>File Permission Issues ({len(result.file_permission_findings)})</h2>
  <div class="card">
    <table>
      <tr><th>Severity</th><th>Issue</th><th>Path</th><th>Permissions</th></tr>
      {rows}
    </table>
  </div>"""

    def _section_remediation(self, result: AuditResult) -> str:
        top = result.top_remediation
        if not top:
            return ""
        items = ""
        for i, item in enumerate(top, 1):
            sev_color = SEVERITY_BADGE.get(item["severity"], "#333")
            items += f"""<tr>
        <td>{i}</td>
        <td>{self._badge(item['severity'], sev_color)}</td>
        <td>{html.escape(item['title'])}</td>
        <td><div class="remediation">{html.escape(item['remediation'])}</div></td>
      </tr>"""
        return f"""
  <h2>Top Remediation Actions</h2>
  <div class="card">
    <table>
      <tr><th>#</th><th>Severity</th><th>Finding</th><th>Remediation</th></tr>
      {items}
    </table>
  </div>"""
