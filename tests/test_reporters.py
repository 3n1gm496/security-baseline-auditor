"""Unit tests for reporters."""

import io
import json
import os
import tempfile

import pytest

from auditor.models import (
    AuditResult, CheckStatus, Finding, HostInfo,
    ListeningPort, SecretFinding, Severity,
)
from auditor.reporters.console import ConsoleReporter
from auditor.reporters.json_reporter import JsonReporter
from auditor.reporters.html_reporter import HtmlReporter
from auditor.reporters.markdown_reporter import MarkdownReporter


def _sample_result() -> AuditResult:
    return AuditResult(
        host_info=HostInfo(
            hostname="test-host", os_name="Ubuntu 22.04",
            os_family="linux", kernel_version="5.15.0",
            architecture="x86_64", uptime="up 3 days",
            local_users=["root", "ubuntu"],
            security_tools=["ufw", "apparmor"],
        ),
        listening_ports=[
            ListeningPort("tcp", "0.0.0.0", 22, 1234, "sshd", "root", "/usr/sbin/sshd", True),
            ListeningPort("tcp", "127.0.0.1", 5432, 5678, "postgres", "postgres", "", False),
        ],
        findings=[
            Finding("LIN-001", "SSH Root Login", "Root login enabled",
                    Severity.HIGH, CheckStatus.FAIL, "PermitRootLogin yes",
                    "Set PermitRootLogin no", "hardening"),
            Finding("LIN-002", "SSH Password Auth", "Password auth OK",
                    Severity.INFO, CheckStatus.PASS, category="hardening"),
        ],
        secret_findings=[
            SecretFinding("/home/user/.env", "AWS Access Key", 3, "AKIA****...", Severity.CRITICAL),
        ],
        scan_mode="full",
        duration_seconds=2.5,
    )


class TestConsoleReporter:
    def test_report_outputs(self):
        result = _sample_result()
        buf = io.StringIO()
        ConsoleReporter().report(result, stream=buf)
        output = buf.getvalue()
        assert "SECURITY BASELINE AUDIT REPORT" in output
        assert "test-host" in output
        assert "LIN-001" in output
        assert "Risk Score" in output

    def test_report_empty_result(self):
        result = AuditResult()
        buf = io.StringIO()
        ConsoleReporter().report(result, stream=buf)
        output = buf.getvalue()
        assert "SUMMARY" in output


class TestJsonReporter:
    def test_export(self):
        result = _sample_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = JsonReporter().export(result, tmpdir)
            assert os.path.isfile(path)
            with open(path) as f:
                data = json.load(f)
            assert data["host_info"]["hostname"] == "test-host"
            assert len(data["findings"]) == 2
            assert "summary" in data


class TestHtmlReporter:
    def test_export(self):
        result = _sample_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = HtmlReporter().export(result, tmpdir)
            assert os.path.isfile(path)
            with open(path) as f:
                content = f.read()
            assert "<!DOCTYPE html>" in content
            assert "test-host" in content
            assert "LIN-001" in content
            assert "SECURITY BASELINE" in content.upper() or "Security Baseline" in content


class TestMarkdownReporter:
    def test_export(self):
        result = _sample_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = MarkdownReporter().export(result, tmpdir)
            assert os.path.isfile(path)
            with open(path) as f:
                content = f.read()
            assert "# Security Baseline Audit Report" in content
            assert "test-host" in content
            assert "LIN-001" in content
            assert "| Proto |" in content
