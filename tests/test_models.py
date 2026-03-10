"""Unit tests for auditor.models."""

import json
import pytest

from auditor.models import (
    AuditResult,
    CheckStatus,
    FilePermissionFinding,
    Finding,
    HostInfo,
    ListeningPort,
    SecretFinding,
    Severity,
)


class TestSeverity:
    def test_score_values(self):
        assert Severity.INFO.score == 0
        assert Severity.LOW.score == 1
        assert Severity.MEDIUM.score == 3
        assert Severity.HIGH.score == 5
        assert Severity.CRITICAL.score == 10

    def test_comparison(self):
        assert Severity.LOW < Severity.HIGH
        assert Severity.CRITICAL > Severity.MEDIUM
        assert Severity.INFO <= Severity.INFO
        assert Severity.HIGH >= Severity.MEDIUM

    def test_from_value(self):
        assert Severity("info") == Severity.INFO
        assert Severity("critical") == Severity.CRITICAL


class TestFinding:
    def test_to_dict(self):
        f = Finding(
            check_id="TEST-001",
            title="Test finding",
            description="A test",
            severity=Severity.HIGH,
            status=CheckStatus.FAIL,
            evidence="some evidence",
            remediation="fix it",
            category="test",
        )
        d = f.to_dict()
        assert d["severity"] == "high"
        assert d["status"] == "fail"
        assert d["check_id"] == "TEST-001"
        assert d["remediation"] == "fix it"

    def test_default_fields(self):
        f = Finding(
            check_id="X", title="T", description="D",
            severity=Severity.INFO, status=CheckStatus.PASS,
        )
        assert f.evidence == ""
        assert f.metadata == {}


class TestHostInfo:
    def test_to_dict(self):
        h = HostInfo(hostname="test-host", os_name="Linux", os_family="linux")
        d = h.to_dict()
        assert d["hostname"] == "test-host"
        assert isinstance(d["local_users"], list)


class TestListeningPort:
    def test_to_dict(self):
        p = ListeningPort(
            protocol="tcp", local_address="0.0.0.0",
            local_port=22, is_public=True,
        )
        d = p.to_dict()
        assert d["is_public"] is True
        assert d["local_port"] == 22


class TestAuditResult:
    def _make_result(self, findings=None, secrets=None, file_perms=None):
        return AuditResult(
            host_info=HostInfo(hostname="test"),
            findings=findings or [],
            secret_findings=secrets or [],
            file_permission_findings=file_perms or [],
        )

    def test_risk_score_empty(self):
        r = self._make_result()
        assert r.risk_score == 0.0

    def test_risk_score_with_findings(self):
        findings = [
            Finding("A", "T", "D", Severity.CRITICAL, CheckStatus.FAIL),
            Finding("B", "T", "D", Severity.HIGH, CheckStatus.FAIL),
        ]
        r = self._make_result(findings=findings)
        # raw = 10 + 5 = 15, score = 15*100/50 = 30.0
        assert r.risk_score == 30.0

    def test_risk_score_capped_at_100(self):
        findings = [
            Finding(f"C{i}", "T", "D", Severity.CRITICAL, CheckStatus.FAIL)
            for i in range(10)
        ]
        r = self._make_result(findings=findings)
        assert r.risk_score == 100.0

    def test_risk_label(self):
        r = self._make_result()
        assert r.risk_label == "LOW"

    def test_has_high_or_critical(self):
        r = self._make_result(findings=[
            Finding("A", "T", "D", Severity.LOW, CheckStatus.FAIL),
        ])
        assert r.has_high_or_critical() is False

        r2 = self._make_result(findings=[
            Finding("A", "T", "D", Severity.HIGH, CheckStatus.FAIL),
        ])
        assert r2.has_high_or_critical() is True

    def test_has_high_from_secrets(self):
        r = self._make_result(secrets=[
            SecretFinding("f.py", "AWS Key", severity=Severity.CRITICAL),
        ])
        assert r.has_high_or_critical() is True

    def test_summary(self):
        findings = [
            Finding("A", "T", "D", Severity.HIGH, CheckStatus.FAIL),
            Finding("B", "T", "D", Severity.INFO, CheckStatus.PASS),
        ]
        r = self._make_result(findings=findings)
        s = r.summary
        assert s["total_checks"] == 2
        assert s["status_counts"]["fail"] == 1
        assert s["status_counts"]["pass"] == 1

    def test_top_remediation(self):
        findings = [
            Finding("A", "T", "D", Severity.CRITICAL, CheckStatus.FAIL, remediation="Fix A"),
            Finding("B", "T", "D", Severity.LOW, CheckStatus.FAIL, remediation="Fix B"),
            Finding("C", "T", "D", Severity.HIGH, CheckStatus.FAIL, remediation="Fix C"),
        ]
        r = self._make_result(findings=findings)
        top = r.top_remediation
        assert len(top) == 3
        assert top[0]["severity"] == "critical"
        assert top[1]["severity"] == "high"

    def test_to_json(self):
        r = self._make_result()
        j = r.to_json()
        data = json.loads(j)
        assert "summary" in data
        assert "timestamp" in data

    def test_pass_findings_not_counted_in_score(self):
        findings = [
            Finding("A", "T", "D", Severity.HIGH, CheckStatus.PASS),
        ]
        r = self._make_result(findings=findings)
        assert r.risk_score == 0.0
