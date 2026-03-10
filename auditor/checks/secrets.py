"""Secret exposure scanner — detects hardcoded credentials, keys, tokens."""

from __future__ import annotations

import fnmatch
import logging
import os
import re
from typing import Dict, List, Pattern, Tuple

from auditor.models import SecretFinding, Severity
from auditor.utils.platform import mask_secret

logger = logging.getLogger(__name__)

# Maximum file size to scan (1 MB)
MAX_FILE_SIZE = 1 * 1024 * 1024

# File extensions to scan
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".rb", ".go", ".java", ".php", ".sh", ".bash",
    ".zsh", ".yml", ".yaml", ".json", ".xml", ".toml", ".ini", ".cfg",
    ".conf", ".env", ".properties", ".tf", ".hcl", ".dockerfile",
    ".txt", ".md", ".csv", ".sql", ".ps1", ".bat", ".cmd",
}

# Files to always scan regardless of extension
SCAN_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.staging",
    ".env.development", ".env.test", ".bashrc", ".bash_profile",
    ".zshrc", ".profile", "credentials", "config",
    ".aws/credentials", ".aws/config", ".netrc", ".pgpass",
    ".docker/config.json", "id_rsa", "id_ed25519", "id_ecdsa",
}

# Default denylist paths
DEFAULT_DENYLIST = [
    "*/.git/*", "*/node_modules/*", "*/__pycache__/*",
    "*/.venv/*", "*/venv/*", "*/.tox/*", "*/dist/*",
    "*/build/*", "*/.mypy_cache/*", "*/.pytest_cache/*",
    "*/vendor/*", "*/.cargo/*", "*/.npm/*",
]

# Secret patterns: (name, regex, severity)
SECRET_PATTERNS: List[Tuple[str, Pattern, Severity]] = [
    (
        "AWS Access Key",
        re.compile(r'(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}'),
        Severity.CRITICAL,
    ),
    (
        "AWS Secret Key",
        re.compile(r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\s]*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
        Severity.CRITICAL,
    ),
    (
        "GitHub Token",
        re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}'),
        Severity.HIGH,
    ),
    (
        "GitLab Token",
        re.compile(r'glpat-[A-Za-z0-9\-_]{20,}'),
        Severity.HIGH,
    ),
    (
        "Generic API Key",
        re.compile(r'(?i)(?:api[_\-]?key|apikey)[\s]*[=:]\s*["\']?([A-Za-z0-9\-_]{20,})["\']?'),
        Severity.MEDIUM,
    ),
    (
        "Generic Secret/Token",
        re.compile(r'(?i)(?:secret|token|password|passwd|pwd)[\s]*[=:]\s*["\']?([^\s"\']{8,})["\']?'),
        Severity.MEDIUM,
    ),
    (
        "Private Key (PEM)",
        re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
        Severity.CRITICAL,
    ),
    (
        "Slack Token",
        re.compile(r'xox[bpors]-[A-Za-z0-9\-]{10,}'),
        Severity.HIGH,
    ),
    (
        "Stripe Key",
        re.compile(r'(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}'),
        Severity.HIGH,
    ),
    (
        "Google API Key",
        re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        Severity.HIGH,
    ),
    (
        "Heroku API Key",
        re.compile(r'(?i)heroku[_\-]?api[_\-]?key[\s]*[=:]\s*["\']?([0-9a-f\-]{36})["\']?'),
        Severity.HIGH,
    ),
    (
        "JWT Token",
        re.compile(r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'),
        Severity.MEDIUM,
    ),
    (
        "Database Connection String",
        re.compile(r'(?i)(?:mysql|postgres|postgresql|mongodb|redis|mssql)://[^\s"\']+:[^\s"\']+@'),
        Severity.HIGH,
    ),
]


def scan_secrets(
    paths: List[str],
    exclude: List[str] | None = None,
    max_files: int = 10000,
) -> List[SecretFinding]:
    """Scan directories for exposed secrets.

    Args:
        paths: List of directories to scan.
        exclude: Additional glob patterns to exclude.
        max_files: Maximum number of files to scan.

    Returns:
        List of SecretFinding objects.
    """
    denylist = DEFAULT_DENYLIST + (exclude or [])
    findings: List[SecretFinding] = []
    files_scanned = 0

    for base_path in paths:
        if not os.path.isdir(base_path):
            continue
        for root, dirs, files in os.walk(base_path, followlinks=False):
            # Skip denied directories
            dirs[:] = [
                d for d in dirs
                if not _matches_denylist(os.path.join(root, d), denylist)
            ]

            for fname in files:
                if files_scanned >= max_files:
                    logger.info("Max files limit reached (%d)", max_files)
                    return findings

                fpath = os.path.join(root, fname)
                if _matches_denylist(fpath, denylist):
                    continue
                if not _should_scan(fname):
                    continue

                try:
                    fsize = os.path.getsize(fpath)
                    if fsize > MAX_FILE_SIZE or fsize == 0:
                        continue
                except OSError:
                    continue

                file_findings = _scan_file(fpath)
                findings.extend(file_findings)
                files_scanned += 1

    logger.info("Secret scan: %d files scanned, %d findings",
                files_scanned, len(findings))
    return findings


def _matches_denylist(path: str, denylist: List[str]) -> bool:
    """Check if path matches any denylist pattern."""
    for pattern in denylist:
        if fnmatch.fnmatch(path, pattern):
            return True
    return False


def _should_scan(filename: str) -> bool:
    """Check if a file should be scanned based on name/extension."""
    if filename in SCAN_FILENAMES or any(
        filename.endswith(f) for f in SCAN_FILENAMES
    ):
        return True
    _, ext = os.path.splitext(filename)
    return ext.lower() in SCAN_EXTENSIONS


def _scan_file(filepath: str) -> List[SecretFinding]:
    """Scan a single file for secret patterns."""
    findings: List[SecretFinding] = []
    try:
        with open(filepath, "r", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                for name, pattern, severity in SECRET_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        # Get the matched value for masking
                        matched_text = match.group(1) if match.lastindex else match.group(0)
                        findings.append(SecretFinding(
                            file_path=filepath,
                            pattern_name=name,
                            line_number=line_num,
                            masked_value=mask_secret(matched_text),
                            severity=severity,
                        ))
    except (OSError, PermissionError) as e:
        logger.debug("Cannot read file %s: %s", filepath, e)
    return findings
