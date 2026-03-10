"""Console reporter — human-readable terminal output."""

from __future__ import annotations

import sys
from typing import TextIO

from auditor.models import AuditResult, CheckStatus, Severity


# ANSI color codes
class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"


SEVERITY_COLORS = {
    Severity.CRITICAL: Color.RED + Color.BOLD,
    Severity.HIGH: Color.RED,
    Severity.MEDIUM: Color.YELLOW,
    Severity.LOW: Color.CYAN,
    Severity.INFO: Color.GRAY,
}

STATUS_SYMBOLS = {
    CheckStatus.PASS: Color.GREEN + "[PASS]" + Color.RESET,
    CheckStatus.FAIL: Color.RED + "[FAIL]" + Color.RESET,
    CheckStatus.WARN: Color.YELLOW + "[WARN]" + Color.RESET,
    CheckStatus.ERROR: Color.MAGENTA + "[ERR ]" + Color.RESET,
    CheckStatus.SKIP: Color.GRAY + "[SKIP]" + Color.RESET,
}


class ConsoleReporter:
    """Outputs audit results to the terminal."""

    def report(self, result: AuditResult, stream: TextIO | None = None) -> None:
        out = stream or sys.stdout
        self._print_header(result, out)
        self._print_host_info(result, out)
        self._print_network(result, out)
        self._print_findings(result, out)
        self._print_secrets(result, out)
        self._print_file_permissions(result, out)
        self._print_summary(result, out)

    def _print_header(self, result: AuditResult, out: TextIO) -> None:
        out.write("\n")
        out.write(f"{Color.BOLD}{'=' * 70}{Color.RESET}\n")
        out.write(f"{Color.BOLD}  SECURITY BASELINE AUDIT REPORT{Color.RESET}\n")
        out.write(f"{Color.BOLD}{'=' * 70}{Color.RESET}\n")
        out.write(f"  Timestamp : {result.timestamp}\n")
        out.write(f"  Scan mode : {result.scan_mode}\n")
        out.write(f"  Duration  : {result.duration_seconds}s\n")
        out.write(f"{'=' * 70}\n\n")

    def _print_host_info(self, result: AuditResult, out: TextIO) -> None:
        if not result.host_info:
            return
        hi = result.host_info
        out.write(f"{Color.BOLD}[HOST INFORMATION]{Color.RESET}\n")
        out.write(f"  Hostname      : {hi.hostname}\n")
        out.write(f"  OS            : {hi.os_name} ({hi.os_family})\n")
        out.write(f"  Kernel        : {hi.kernel_version}\n")
        out.write(f"  Architecture  : {hi.architecture}\n")
        out.write(f"  Uptime        : {hi.uptime}\n")
        out.write(f"  Local users   : {', '.join(hi.local_users[:10]) or 'N/A'}\n")
        out.write(f"  Security tools: {', '.join(hi.security_tools) or 'None detected'}\n")
        out.write("\n")

    def _print_network(self, result: AuditResult, out: TextIO) -> None:
        if not result.listening_ports:
            return
        out.write(f"{Color.BOLD}[NETWORK EXPOSURE]{Color.RESET}\n")
        out.write(f"  {'Proto':<6} {'Address':<20} {'Port':<7} {'PID':<8} {'Process':<15} {'User':<12} {'Public'}\n")
        out.write(f"  {'-' * 80}\n")
        for p in result.listening_ports:
            public_flag = f"{Color.RED}YES{Color.RESET}" if p.is_public else "no"
            out.write(
                f"  {p.protocol:<6} {p.local_address:<20} {p.local_port:<7} "
                f"{str(p.pid or '-'):<8} {p.process_name or '-':<15} "
                f"{p.user or '-':<12} {public_flag}\n"
            )
        out.write("\n")

    def _print_findings(self, result: AuditResult, out: TextIO) -> None:
        if not result.findings:
            return
        out.write(f"{Color.BOLD}[HARDENING CHECKS]{Color.RESET}\n")
        for f in result.findings:
            status_str = STATUS_SYMBOLS.get(f.status, f"[{f.status.value}]")
            sev_color = SEVERITY_COLORS.get(f.severity, "")
            out.write(
                f"  {status_str} {sev_color}{f.severity.value.upper():<8}{Color.RESET} "
                f"{f.check_id:<10} {f.title}\n"
            )
            if f.status in (CheckStatus.FAIL, CheckStatus.WARN) and f.evidence:
                evidence_short = f.evidence[:120].replace("\n", " | ")
                out.write(f"           {Color.GRAY}Evidence: {evidence_short}{Color.RESET}\n")
        out.write("\n")

    def _print_secrets(self, result: AuditResult, out: TextIO) -> None:
        if not result.secret_findings:
            return
        out.write(f"{Color.BOLD}[SECRET EXPOSURE]{Color.RESET}\n")
        for s in result.secret_findings:
            sev_color = SEVERITY_COLORS.get(s.severity, "")
            out.write(
                f"  {Color.RED}[!]{Color.RESET} {sev_color}{s.severity.value.upper():<8}{Color.RESET} "
                f"{s.pattern_name:<25} {s.file_path}:{s.line_number}\n"
            )
            out.write(f"           {Color.GRAY}Value: {s.masked_value}{Color.RESET}\n")
        out.write("\n")

    def _print_file_permissions(self, result: AuditResult, out: TextIO) -> None:
        if not result.file_permission_findings:
            return
        out.write(f"{Color.BOLD}[FILE PERMISSIONS]{Color.RESET}\n")
        for f in result.file_permission_findings:
            sev_color = SEVERITY_COLORS.get(f.severity, "")
            out.write(
                f"  {Color.YELLOW}[!]{Color.RESET} {sev_color}{f.severity.value.upper():<8}{Color.RESET} "
                f"{f.issue}\n"
            )
            out.write(f"           Path: {f.file_path} (current: {f.current_permissions})\n")
        out.write("\n")

    def _print_summary(self, result: AuditResult, out: TextIO) -> None:
        summary = result.summary
        score = summary["risk_score"]
        label = summary["risk_label"]

        # Color for risk label
        if label == "CRITICAL":
            label_color = Color.RED + Color.BOLD
        elif label == "HIGH":
            label_color = Color.RED
        elif label == "MODERATE":
            label_color = Color.YELLOW
        else:
            label_color = Color.GREEN

        out.write(f"{Color.BOLD}{'=' * 70}{Color.RESET}\n")
        out.write(f"{Color.BOLD}  SUMMARY{Color.RESET}\n")
        out.write(f"{'=' * 70}\n")
        out.write(f"  Total checks       : {summary['total_checks']}\n")
        for status, count in summary["status_counts"].items():
            out.write(f"    {status:<10}       : {count}\n")
        out.write(f"  Secrets found      : {summary['secrets_found']}\n")
        out.write(f"  File perm issues   : {summary['file_permission_issues']}\n")
        out.write(f"  Listening ports    : {summary['listening_ports']} ({summary['public_ports']} public)\n")
        out.write(f"\n  {Color.BOLD}Risk Score: {label_color}{score}/100 ({label}){Color.RESET}\n")

        # Top remediation
        top = result.top_remediation
        if top:
            out.write(f"\n{Color.BOLD}  TOP REMEDIATION ACTIONS:{Color.RESET}\n")
            for i, item in enumerate(top, 1):
                sev = item["severity"].upper()
                out.write(f"    {i:>2}. [{sev}] {item['title']}\n")
                out.write(f"        -> {item['remediation']}\n")

        out.write(f"\n{'=' * 70}\n\n")
