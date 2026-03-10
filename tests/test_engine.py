"""Unit tests for auditor.rules.engine."""

import pytest

from auditor.models import CheckStatus, Finding, Severity
from auditor.rules.engine import CheckRegistry


class TestCheckRegistry:
    def _make_registry(self):
        reg = CheckRegistry()

        @reg.register("T-001", os_family="linux", category="hardening", quick=True)
        def check_linux_quick():
            return [Finding("T-001", "Linux Quick", "D", Severity.LOW, CheckStatus.PASS)]

        @reg.register("T-002", os_family="linux", category="hardening", quick=False)
        def check_linux_full():
            return [Finding("T-002", "Linux Full", "D", Severity.HIGH, CheckStatus.FAIL)]

        @reg.register("T-003", os_family="windows", category="hardening", quick=True)
        def check_windows():
            return [Finding("T-003", "Windows", "D", Severity.MEDIUM, CheckStatus.WARN)]

        @reg.register("T-004", os_family="all", category="general", quick=True)
        def check_all():
            return [Finding("T-004", "All OS", "D", Severity.INFO, CheckStatus.PASS)]

        @reg.register("T-005", os_family="linux", category="hardening", quick=True)
        def check_error():
            raise RuntimeError("Simulated error")

        return reg

    def test_get_checks_linux(self):
        reg = self._make_registry()
        checks = reg.get_checks("linux")
        ids = [c["check_id"] for c in checks]
        assert "T-001" in ids
        assert "T-002" in ids
        assert "T-004" in ids  # all
        assert "T-003" not in ids  # windows only

    def test_get_checks_quick_only(self):
        reg = self._make_registry()
        checks = reg.get_checks("linux", quick_only=True)
        ids = [c["check_id"] for c in checks]
        assert "T-001" in ids
        assert "T-002" not in ids  # not quick

    def test_get_checks_by_category(self):
        reg = self._make_registry()
        checks = reg.get_checks("linux", categories=["general"])
        ids = [c["check_id"] for c in checks]
        assert "T-004" in ids
        assert "T-001" not in ids

    def test_run_checks(self):
        reg = self._make_registry()
        findings = reg.run_checks("linux")
        assert len(findings) >= 3  # T-001, T-002, T-004, T-005 (error)

    def test_run_checks_error_handling(self):
        reg = self._make_registry()
        findings = reg.run_checks("linux")
        error_findings = [f for f in findings if f.status == CheckStatus.ERROR]
        assert len(error_findings) == 1
        assert "T-005" in error_findings[0].check_id

    def test_severity_threshold(self):
        reg = self._make_registry()
        findings = reg.run_checks("linux", severity_threshold=Severity.HIGH)
        # Only HIGH and above should be included (T-002 is HIGH FAIL)
        for f in findings:
            if f.status != CheckStatus.ERROR:
                assert f.severity >= Severity.HIGH

    def test_run_checks_windows(self):
        reg = self._make_registry()
        findings = reg.run_checks("windows")
        ids = [f.check_id for f in findings]
        assert "T-003" in ids
        assert "T-004" in ids
        assert "T-001" not in ids
