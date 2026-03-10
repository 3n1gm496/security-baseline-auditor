"""Markdown reporter — export for ticketing systems (Jira, Confluence, etc.)."""

from __future__ import annotations

import logging
import os

from auditor.models import AuditResult, CheckStatus

logger = logging.getLogger(__name__)


class MarkdownReporter:
    """Export audit results as Markdown."""

    def export(self, result: AuditResult, output_dir: str) -> str:
        os.makedirs(output_dir, exist_ok=True)
        filename = f"sbaudit-report-{result.timestamp[:19].replace(':', '-')}.md"
        filepath = os.path.join(output_dir, filename)

        content = self._render(result)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        logger.info("Markdown report exported: %s", filepath)
        return filepath

    def _render(self, result: AuditResult) -> str:
        summary = result.summary
        host = result.host_info
        lines = []

        lines.append("# Security Baseline Audit Report\n")
        lines.append(f"**Timestamp:** {result.timestamp}  ")
        lines.append(f"**Scan mode:** {result.scan_mode}  ")
        lines.append(f"**Duration:** {result.duration_seconds}s  ")
        lines.append(f"**Risk Score:** {summary['risk_score']}/100 ({summary['risk_label']})\n")

        # Summary table
        lines.append("## Summary\n")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Total checks | {summary['total_checks']} |")
        for status, count in summary["status_counts"].items():
            lines.append(f"| {status.upper()} | {count} |")
        lines.append(f"| Secrets found | {summary['secrets_found']} |")
        lines.append(f"| File permission issues | {summary['file_permission_issues']} |")
        lines.append(f"| Listening ports | {summary['listening_ports']} ({summary['public_ports']} public) |")
        lines.append("")

        # Host info
        if host:
            lines.append("## Host Information\n")
            lines.append("| Property | Value |")
            lines.append("|----------|-------|")
            lines.append(f"| Hostname | {host.hostname} |")
            lines.append(f"| OS | {host.os_name} ({host.os_family}) |")
            lines.append(f"| Kernel | {host.kernel_version} |")
            lines.append(f"| Architecture | {host.architecture} |")
            lines.append(f"| Uptime | {host.uptime} |")
            lines.append(f"| Local users | {', '.join(host.local_users[:10])} |")
            lines.append(f"| Security tools | {', '.join(host.security_tools) or 'None'} |")
            lines.append("")

        # Network
        if result.listening_ports:
            lines.append("## Network Exposure\n")
            lines.append("| Proto | Address | Port | PID | Process | User | Public |")
            lines.append("|-------|---------|------|-----|---------|------|--------|")
            for p in result.listening_ports:
                pub = "**YES**" if p.is_public else "no"
                lines.append(
                    f"| {p.protocol} | {p.local_address} | {p.local_port} | "
                    f"{p.pid or '-'} | {p.process_name or '-'} | "
                    f"{p.user or '-'} | {pub} |"
                )
            lines.append("")

        # Findings
        if result.findings:
            lines.append("## Hardening Checks\n")
            lines.append("| Status | Severity | ID | Title |")
            lines.append("|--------|----------|----|-------|")
            for f in result.findings:
                status_icon = {"pass": "PASS", "fail": "**FAIL**", "warn": "WARN",
                               "error": "ERR", "skip": "SKIP"}.get(f.status.value, f.status.value)
                lines.append(
                    f"| {status_icon} | {f.severity.value.upper()} | "
                    f"{f.check_id} | {f.title} |"
                )
            lines.append("")

            # Detail for failed/warn
            failed = [f for f in result.findings
                      if f.status in (CheckStatus.FAIL, CheckStatus.WARN)]
            if failed:
                lines.append("### Finding Details\n")
                for f in failed:
                    lines.append(f"#### {f.check_id} — {f.title}\n")
                    lines.append(f"- **Severity:** {f.severity.value.upper()}")
                    lines.append(f"- **Status:** {f.status.value.upper()}")
                    lines.append(f"- **Description:** {f.description}")
                    if f.evidence:
                        lines.append(f"- **Evidence:** `{f.evidence[:200]}`")
                    if f.remediation:
                        lines.append(f"- **Remediation:** {f.remediation}")
                    lines.append("")

        # Secrets
        if result.secret_findings:
            lines.append("## Secret Exposure\n")
            lines.append("| Severity | Pattern | Location | Value (masked) |")
            lines.append("|----------|---------|----------|----------------|")
            for s in result.secret_findings:
                lines.append(
                    f"| {s.severity.value.upper()} | {s.pattern_name} | "
                    f"`{s.file_path}:{s.line_number}` | `{s.masked_value}` |"
                )
            lines.append("")

        # File permissions
        if result.file_permission_findings:
            lines.append("## File Permission Issues\n")
            lines.append("| Severity | Issue | Path | Permissions |")
            lines.append("|----------|-------|------|-------------|")
            for f in result.file_permission_findings:
                lines.append(
                    f"| {f.severity.value.upper()} | {f.issue} | "
                    f"`{f.file_path}` | {f.current_permissions} |"
                )
            lines.append("")

        # Top remediation
        top = result.top_remediation
        if top:
            lines.append("## Top Remediation Actions\n")
            for i, item in enumerate(top, 1):
                lines.append(
                    f"{i}. **[{item['severity'].upper()}]** {item['title']}  ")
                lines.append(f"   > {item['remediation']}\n")

        lines.append("---\n")
        lines.append("*Generated by security-baseline-auditor*\n")

        return "\n".join(lines)
