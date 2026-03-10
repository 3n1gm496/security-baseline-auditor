"""File permissions audit — detects world-writable files, insecure keys, etc."""

from __future__ import annotations

import glob
import logging
import os
import stat
from typing import List

from auditor.models import FilePermissionFinding, Severity
from auditor.utils.platform import get_os_family, run_command

logger = logging.getLogger(__name__)


def audit_file_permissions(os_family: str | None = None) -> List[FilePermissionFinding]:
    """Audit file permissions for common security issues.

    Args:
        os_family: OS family override. Auto-detected if None.

    Returns:
        List of FilePermissionFinding objects.
    """
    if os_family is None:
        os_family = get_os_family()

    findings: List[FilePermissionFinding] = []

    if os_family in ("linux", "darwin"):
        findings.extend(_check_private_keys())
        findings.extend(_check_world_writable_sensitive())
        findings.extend(_check_startup_scripts())
        findings.extend(_check_ssh_dir_permissions())
        findings.extend(_check_home_dir_permissions())
    elif os_family == "windows":
        findings.extend(_check_windows_permissions())

    return findings


def _check_private_keys() -> List[FilePermissionFinding]:
    """Check private key files for insecure permissions."""
    findings: List[FilePermissionFinding] = []
    home = os.path.expanduser("~")
    key_patterns = [
        os.path.join(home, ".ssh", "id_*"),
        os.path.join(home, ".ssh", "*.pem"),
        "/etc/ssh/ssh_host_*_key",
    ]

    for pattern in key_patterns:
        for key_path in glob.glob(pattern):
            if key_path.endswith(".pub"):
                continue
            try:
                st = os.stat(key_path)
                mode = oct(st.st_mode)[-3:]
                # Private keys should be 600 or 400
                if st.st_mode & (stat.S_IRGRP | stat.S_IWGRP |
                                 stat.S_IROTH | stat.S_IWOTH |
                                 stat.S_IXOTH | stat.S_IXGRP):
                    findings.append(FilePermissionFinding(
                        file_path=key_path,
                        issue="Private key has insecure permissions",
                        current_permissions=mode,
                        expected_permissions="600 or 400",
                        severity=Severity.HIGH,
                    ))
            except (OSError, PermissionError):
                pass

    return findings


def _check_world_writable_sensitive() -> List[FilePermissionFinding]:
    """Check for world-writable files in sensitive directories."""
    findings: List[FilePermissionFinding] = []
    sensitive_dirs = [
        "/etc", "/usr/local/bin", "/usr/local/sbin",
        "/usr/bin", "/usr/sbin",
    ]

    for dir_path in sensitive_dirs:
        if not os.path.isdir(dir_path):
            continue
        try:
            for entry in os.scandir(dir_path):
                if not entry.is_file():
                    continue
                try:
                    st = entry.stat()
                    if st.st_mode & stat.S_IWOTH:
                        mode = oct(st.st_mode)[-3:]
                        findings.append(FilePermissionFinding(
                            file_path=entry.path,
                            issue="World-writable file in sensitive directory",
                            current_permissions=mode,
                            expected_permissions="Not world-writable",
                            severity=Severity.MEDIUM,
                        ))
                except (OSError, PermissionError):
                    pass
        except (OSError, PermissionError):
            pass

    return findings


def _check_startup_scripts() -> List[FilePermissionFinding]:
    """Check startup scripts for insecure permissions."""
    findings: List[FilePermissionFinding] = []
    startup_dirs = [
        "/etc/init.d",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ]

    for dir_path in startup_dirs:
        if not os.path.isdir(dir_path):
            continue
        try:
            for entry in os.scandir(dir_path):
                if not entry.is_file():
                    continue
                try:
                    st = entry.stat()
                    # Check if writable by group or others
                    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                        mode = oct(st.st_mode)[-3:]
                        findings.append(FilePermissionFinding(
                            file_path=entry.path,
                            issue="Startup/cron script modifiable by non-root",
                            current_permissions=mode,
                            expected_permissions="755 or stricter",
                            severity=Severity.HIGH,
                        ))
                except (OSError, PermissionError):
                    pass
        except (OSError, PermissionError):
            pass

    return findings


def _check_ssh_dir_permissions() -> List[FilePermissionFinding]:
    """Check ~/.ssh directory permissions."""
    findings: List[FilePermissionFinding] = []
    ssh_dir = os.path.expanduser("~/.ssh")

    if not os.path.isdir(ssh_dir):
        return findings

    try:
        st = os.stat(ssh_dir)
        mode = oct(st.st_mode)[-3:]
        if st.st_mode & (stat.S_IRGRP | stat.S_IWGRP |
                         stat.S_IROTH | stat.S_IWOTH |
                         stat.S_IXGRP | stat.S_IXOTH):
            findings.append(FilePermissionFinding(
                file_path=ssh_dir,
                issue="~/.ssh directory has insecure permissions",
                current_permissions=mode,
                expected_permissions="700",
                severity=Severity.HIGH,
            ))
    except (OSError, PermissionError):
        pass

    # Check authorized_keys
    auth_keys = os.path.join(ssh_dir, "authorized_keys")
    if os.path.isfile(auth_keys):
        try:
            st = os.stat(auth_keys)
            mode = oct(st.st_mode)[-3:]
            if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                findings.append(FilePermissionFinding(
                    file_path=auth_keys,
                    issue="authorized_keys writable by group/others",
                    current_permissions=mode,
                    expected_permissions="600",
                    severity=Severity.HIGH,
                ))
        except (OSError, PermissionError):
            pass

    return findings


def _check_home_dir_permissions() -> List[FilePermissionFinding]:
    """Check home directory permissions."""
    findings: List[FilePermissionFinding] = []
    home = os.path.expanduser("~")
    try:
        st = os.stat(home)
        if st.st_mode & stat.S_IWOTH:
            mode = oct(st.st_mode)[-3:]
            findings.append(FilePermissionFinding(
                file_path=home,
                issue="Home directory is world-writable",
                current_permissions=mode,
                expected_permissions="750 or stricter",
                severity=Severity.HIGH,
            ))
    except (OSError, PermissionError):
        pass

    return findings


def _check_windows_permissions() -> List[FilePermissionFinding]:
    """Check file permissions on Windows (basic checks)."""
    findings: List[FilePermissionFinding] = []

    # Check common sensitive paths
    user_profile = os.environ.get("USERPROFILE", "")
    if not user_profile:
        return findings

    sensitive_files = [
        os.path.join(user_profile, ".ssh", "id_rsa"),
        os.path.join(user_profile, ".ssh", "id_ed25519"),
        os.path.join(user_profile, ".aws", "credentials"),
        os.path.join(user_profile, ".azure", "credentials"),
    ]

    for fpath in sensitive_files:
        if os.path.isfile(fpath):
            # On Windows, use icacls to check
            rc, out, _ = run_command(["icacls", fpath])
            if rc == 0 and "Everyone" in out:
                findings.append(FilePermissionFinding(
                    file_path=fpath,
                    issue="Sensitive file accessible by Everyone",
                    current_permissions=out.strip()[:200],
                    expected_permissions="Owner-only access",
                    severity=Severity.HIGH,
                ))

    return findings
