"""CLI entry point for security-baseline-auditor (sbaudit)."""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from typing import List, Optional

from auditor import __version__
from auditor.models import AuditResult, Severity
from auditor.rules.engine import registry
from auditor.utils.platform import get_os_family, is_root

# Import all check modules to trigger registration
import auditor.checks.linux.hardening  # noqa: F401
import auditor.checks.windows.hardening  # noqa: F401
import auditor.checks.macos.hardening  # noqa: F401
import auditor.collectors.host_info  # noqa: F401
import auditor.collectors.network  # noqa: F401
import auditor.checks.secrets  # noqa: F401
import auditor.checks.file_permissions  # noqa: F401

logger = logging.getLogger("sbaudit")


def parse_severity(value: str) -> Severity:
    try:
        return Severity(value.lower())
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid severity: {value}. "
            f"Choose from: info, low, medium, high, critical"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sbaudit",
        description=(
            "security-baseline-auditor — Defensive, read-only local "
            "security audit tool for Linux, macOS and Windows."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--quick", action="store_true", default=False,
        help="Run only quick checks (subset of full audit).",
    )
    mode_group.add_argument(
        "--full", action="store_true", default=True,
        help="Run all checks (default).",
    )

    parser.add_argument(
        "--paths", nargs="+", default=None,
        help="Directories to scan for secrets and file permissions.",
    )
    parser.add_argument(
        "--exclude", nargs="+", default=None,
        help="Directories or patterns to exclude from scanning.",
    )
    parser.add_argument(
        "--format", dest="output_format", choices=["json", "html", "md"],
        default=None,
        help="Export format (in addition to console output).",
    )
    parser.add_argument(
        "--output", dest="output_dir", default=None,
        help="Output directory for exported reports.",
    )
    parser.add_argument(
        "--severity-threshold", type=parse_severity, default=None,
        help="Minimum severity to report (info, low, medium, high, critical).",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", default=False,
        help="Enable verbose/debug logging.",
    )

    return parser


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def run_audit(args: argparse.Namespace) -> AuditResult:
    """Execute the audit and return results."""
    os_family = get_os_family()
    logger.info("Detected OS family: %s", os_family)
    logger.info("Running as root: %s", is_root())

    start_time = time.time()
    result = AuditResult(scan_mode="quick" if args.quick else "full")

    # Collect host info
    from auditor.collectors.host_info import collect_host_info
    result.host_info = collect_host_info()
    logger.info("Host: %s (%s %s)", result.host_info.hostname,
                result.host_info.os_name, result.host_info.os_version)

    # Collect network exposure
    from auditor.collectors.network import collect_listening_ports
    result.listening_ports = collect_listening_ports()
    logger.info("Listening ports found: %d", len(result.listening_ports))

    # Run hardening checks
    findings = registry.run_checks(
        os_family=os_family,
        quick_only=args.quick,
        severity_threshold=args.severity_threshold,
    )
    result.findings = findings
    logger.info("Checks executed: %d findings", len(findings))

    # Secret scanning
    from auditor.checks.secrets import scan_secrets
    scan_paths = args.paths or _default_secret_paths(os_family)
    exclude = args.exclude or []
    result.secret_findings = scan_secrets(scan_paths, exclude)
    logger.info("Secrets found: %d", len(result.secret_findings))

    # File permissions audit
    from auditor.checks.file_permissions import audit_file_permissions
    result.file_permission_findings = audit_file_permissions(os_family)
    logger.info("File permission issues: %d",
                len(result.file_permission_findings))

    result.duration_seconds = round(time.time() - start_time, 2)
    return result


def _default_secret_paths(os_family: str) -> List[str]:
    home = os.path.expanduser("~")
    paths = [home]
    if os_family == "linux":
        paths.extend(["/etc", "/opt", "/var/www"])
    elif os_family == "darwin":
        paths.extend(["/etc", "/opt", "/usr/local"])
    elif os_family == "windows":
        paths.extend([
            os.path.join(os.environ.get("SYSTEMDRIVE", "C:"), "Users"),
        ])
    return [p for p in paths if os.path.isdir(p)]


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.verbose)

    logger.info("security-baseline-auditor v%s starting...", __version__)

    try:
        result = run_audit(args)
    except KeyboardInterrupt:
        logger.info("Audit interrupted by user.")
        return 130
    except Exception as exc:
        logger.error("Audit failed: %s", exc, exc_info=True)
        return 2

    # Console output
    from auditor.reporters.console import ConsoleReporter
    ConsoleReporter().report(result)

    # Export if requested
    if args.output_format:
        output_dir = args.output_dir or "."
        os.makedirs(output_dir, exist_ok=True)

        if args.output_format == "json":
            from auditor.reporters.json_reporter import JsonReporter
            JsonReporter().export(result, output_dir)
        elif args.output_format == "html":
            from auditor.reporters.html_reporter import HtmlReporter
            HtmlReporter().export(result, output_dir)
        elif args.output_format == "md":
            from auditor.reporters.markdown_reporter import MarkdownReporter
            MarkdownReporter().export(result, output_dir)

    # Exit code non-zero if HIGH/CRITICAL found
    if result.has_high_or_critical():
        logger.warning("HIGH/CRITICAL findings detected — exit code 1")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
