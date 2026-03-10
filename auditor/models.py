"""Core data models for security-baseline-auditor."""

from __future__ import annotations

import datetime
import enum
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


class Severity(enum.Enum):
    """Finding severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def score(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 3,
            Severity.HIGH: 5,
            Severity.CRITICAL: 10,
        }[self]

    def __lt__(self, other: "Severity") -> bool:
        return self.score < other.score

    def __le__(self, other: "Severity") -> bool:
        return self.score <= other.score

    def __gt__(self, other: "Severity") -> bool:
        return self.score > other.score

    def __ge__(self, other: "Severity") -> bool:
        return self.score >= other.score


class CheckStatus(enum.Enum):
    """Result status of a check."""
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    ERROR = "error"
    SKIP = "skip"


@dataclass
class Finding:
    """A single audit finding."""
    check_id: str
    title: str
    description: str
    severity: Severity
    status: CheckStatus
    evidence: str = ""
    remediation: str = ""
    category: str = ""
    os_family: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        return d


@dataclass
class HostInfo:
    """Collected host information."""
    hostname: str = ""
    os_name: str = ""
    os_version: str = ""
    os_family: str = ""
    kernel_version: str = ""
    architecture: str = ""
    uptime: str = ""
    local_users: List[str] = field(default_factory=list)
    security_tools: List[str] = field(default_factory=list)
    installed_software: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ListeningPort:
    """A listening network port."""
    protocol: str = ""
    local_address: str = ""
    local_port: int = 0
    pid: Optional[int] = None
    process_name: str = ""
    user: str = ""
    executable_path: str = ""
    is_public: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecretFinding:
    """A detected secret or credential."""
    file_path: str
    pattern_name: str
    line_number: int = 0
    masked_value: str = ""
    severity: Severity = Severity.HIGH

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class FilePermissionFinding:
    """A file permission issue."""
    file_path: str
    issue: str
    current_permissions: str = ""
    expected_permissions: str = ""
    severity: Severity = Severity.MEDIUM

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class AuditResult:
    """Complete audit result."""
    timestamp: str = field(default_factory=lambda: datetime.datetime.now(
        datetime.timezone.utc).isoformat())
    host_info: Optional[HostInfo] = None
    listening_ports: List[ListeningPort] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    secret_findings: List[SecretFinding] = field(default_factory=list)
    file_permission_findings: List[FilePermissionFinding] = field(
        default_factory=list)
    scan_mode: str = "full"
    duration_seconds: float = 0.0

    @property
    def risk_score(self) -> float:
        """Calculate overall risk score (0-100).

        Formula:
            raw = sum(severity.score for each FAIL/WARN finding)
                + sum(severity.score for secrets)
                + sum(severity.score for file permission issues)
            normalized = min(100, raw * 100 / max_possible)

        max_possible is calibrated to 50 severity points (~5 critical findings).
        """
        raw = sum(
            f.severity.score for f in self.findings
            if f.status in (CheckStatus.FAIL, CheckStatus.WARN)
        )
        raw += sum(s.severity.score for s in self.secret_findings)
        raw += sum(f.severity.score for f in self.file_permission_findings)
        max_possible = 50
        return min(100.0, round(raw * 100 / max_possible, 1))

    @property
    def risk_label(self) -> str:
        score = self.risk_score
        if score <= 10:
            return "LOW"
        elif score <= 30:
            return "MODERATE"
        elif score <= 60:
            return "HIGH"
        else:
            return "CRITICAL"

    @property
    def top_remediation(self) -> List[Dict[str, str]]:
        failed = [
            f for f in self.findings
            if f.status in (CheckStatus.FAIL, CheckStatus.WARN) and f.remediation
        ]
        failed.sort(key=lambda f: f.severity, reverse=True)
        return [
            {"check_id": f.check_id, "title": f.title,
             "severity": f.severity.value, "remediation": f.remediation}
            for f in failed[:10]
        ]

    @property
    def summary(self) -> Dict[str, Any]:
        status_counts: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {}
        for f in self.findings:
            status_counts[f.status.value] = status_counts.get(f.status.value, 0) + 1
            if f.status in (CheckStatus.FAIL, CheckStatus.WARN):
                severity_counts[f.severity.value] = severity_counts.get(
                    f.severity.value, 0) + 1
        return {
            "total_checks": len(self.findings),
            "status_counts": status_counts,
            "severity_counts": severity_counts,
            "secrets_found": len(self.secret_findings),
            "file_permission_issues": len(self.file_permission_findings),
            "listening_ports": len(self.listening_ports),
            "public_ports": sum(1 for p in self.listening_ports if p.is_public),
            "risk_score": self.risk_score,
            "risk_label": self.risk_label,
        }

    def has_high_or_critical(self) -> bool:
        for f in self.findings:
            if f.status in (CheckStatus.FAIL, CheckStatus.WARN) and \
               f.severity in (Severity.HIGH, Severity.CRITICAL):
                return True
        for s in self.secret_findings:
            if s.severity in (Severity.HIGH, Severity.CRITICAL):
                return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "host_info": self.host_info.to_dict() if self.host_info else None,
            "listening_ports": [p.to_dict() for p in self.listening_ports],
            "findings": [f.to_dict() for f in self.findings],
            "secret_findings": [s.to_dict() for s in self.secret_findings],
            "file_permission_findings": [
                f.to_dict() for f in self.file_permission_findings],
            "summary": self.summary,
            "top_remediation": self.top_remediation,
            "scan_mode": self.scan_mode,
            "duration_seconds": self.duration_seconds,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
