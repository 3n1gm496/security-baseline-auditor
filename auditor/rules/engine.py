"""Rule engine for evaluating security checks."""

from __future__ import annotations

import logging
from typing import Callable, Dict, List, Optional

from auditor.models import CheckStatus, Finding, Severity

logger = logging.getLogger(__name__)


class CheckRegistry:
    """Registry for security checks.

    Checks are registered as callables that return a list of Finding objects.
    Each check is tagged with an OS family (linux, windows, darwin, all).
    """

    def __init__(self) -> None:
        self._checks: List[Dict] = []

    def register(
        self,
        check_id: str,
        os_family: str = "all",
        category: str = "general",
        quick: bool = True,
    ) -> Callable:
        """Decorator to register a check function."""
        def decorator(func: Callable[[], List[Finding]]) -> Callable:
            self._checks.append({
                "check_id": check_id,
                "os_family": os_family,
                "category": category,
                "quick": quick,
                "func": func,
            })
            return func
        return decorator

    def get_checks(
        self,
        os_family: str,
        quick_only: bool = False,
        categories: Optional[List[str]] = None,
    ) -> List[Dict]:
        result = []
        for check in self._checks:
            if check["os_family"] not in (os_family, "all"):
                continue
            if quick_only and not check["quick"]:
                continue
            if categories and check["category"] not in categories:
                continue
            result.append(check)
        return result

    def run_checks(
        self,
        os_family: str,
        quick_only: bool = False,
        categories: Optional[List[str]] = None,
        severity_threshold: Optional[Severity] = None,
    ) -> List[Finding]:
        checks = self.get_checks(os_family, quick_only, categories)
        findings: List[Finding] = []

        for check in checks:
            check_id = check["check_id"]
            try:
                logger.debug("Running check: %s", check_id)
                results = check["func"]()
                for f in results:
                    f.os_family = os_family
                    if severity_threshold and f.severity < severity_threshold:
                        continue
                    findings.append(f)
            except Exception as exc:
                logger.warning("Check %s failed: %s", check_id, exc)
                findings.append(Finding(
                    check_id=check_id,
                    title=f"Check {check_id} error",
                    description=f"Check failed with error: {exc}",
                    severity=Severity.INFO,
                    status=CheckStatus.ERROR,
                    evidence=str(exc),
                    category=check.get("category", ""),
                ))

        return findings


# Global registry instance
registry = CheckRegistry()
