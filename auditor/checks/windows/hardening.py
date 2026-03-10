"""Windows hardening checks — 12 real checks for RDP, Defender, firewall, etc."""

from __future__ import annotations

import logging
import os
from typing import List

from auditor.models import CheckStatus, Finding, Severity
from auditor.rules.engine import registry
from auditor.utils.platform import run_command

logger = logging.getLogger(__name__)


def _ps(command: str, timeout: int = 15) -> tuple:
    """Run a PowerShell command and return (rc, stdout, stderr)."""
    return run_command(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# WIN-001  Windows Defender status
# ---------------------------------------------------------------------------
@registry.register("WIN-001", os_family="windows", category="hardening")
def check_defender_status() -> List[Finding]:
    """Check if Windows Defender real-time protection is enabled."""
    rc, out, _ = _ps(
        "(Get-MpComputerStatus).RealTimeProtectionEnabled"
    )
    if rc != 0:
        return [Finding(
            check_id="WIN-001", title="Windows Defender status",
            description="Cannot query Windows Defender status.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    if "True" in out:
        return [Finding(
            check_id="WIN-001", title="Windows Defender: real-time protection ON",
            description="Windows Defender real-time protection is enabled.",
            severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
        )]
    return [Finding(
        check_id="WIN-001", title="Windows Defender: real-time protection OFF",
        description="Windows Defender real-time protection is disabled.",
        severity=Severity.CRITICAL, status=CheckStatus.FAIL,
        evidence=out.strip(),
        remediation="Enable Defender: Set-MpPreference -DisableRealtimeMonitoring $false",
        category="hardening",
    )]


# ---------------------------------------------------------------------------
# WIN-002  Windows Firewall profiles
# ---------------------------------------------------------------------------
@registry.register("WIN-002", os_family="windows", category="hardening")
def check_firewall_profiles() -> List[Finding]:
    """Check if all Windows Firewall profiles are enabled."""
    rc, out, _ = _ps(
        "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"
    )
    if rc != 0:
        return [Finding(
            check_id="WIN-002", title="Windows Firewall profiles",
            description="Cannot query firewall profiles.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    disabled = []
    import json
    try:
        profiles = json.loads(out)
        if isinstance(profiles, dict):
            profiles = [profiles]
        for p in profiles:
            if not p.get("Enabled", True):
                disabled.append(p.get("Name", "Unknown"))
    except (json.JSONDecodeError, TypeError):
        pass

    if disabled:
        return [Finding(
            check_id="WIN-002", title="Windows Firewall: profiles disabled",
            description=f"Firewall profiles disabled: {', '.join(disabled)}.",
            severity=Severity.HIGH, status=CheckStatus.FAIL,
            evidence=f"Disabled profiles: {', '.join(disabled)}",
            remediation="Enable all profiles: Set-NetFirewallProfile -All -Enabled True",
            category="hardening",
        )]
    return [Finding(
        check_id="WIN-002", title="Windows Firewall: all profiles enabled",
        description="All Windows Firewall profiles are enabled.",
        severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
    )]


# ---------------------------------------------------------------------------
# WIN-003  RDP status
# ---------------------------------------------------------------------------
@registry.register("WIN-003", os_family="windows", category="hardening")
def check_rdp_status() -> List[Finding]:
    """Check if Remote Desktop is enabled."""
    rc, out, _ = _ps(
        "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections"
    )
    if rc != 0:
        return [Finding(
            check_id="WIN-003", title="RDP status",
            description="Cannot query RDP status.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    value = out.strip()
    if value == "0":
        return [Finding(
            check_id="WIN-003", title="RDP: enabled",
            description="Remote Desktop Protocol is enabled.",
            severity=Severity.MEDIUM, status=CheckStatus.WARN,
            evidence="fDenyTSConnections = 0",
            remediation="Disable RDP if not needed, or restrict via NLA and firewall rules.",
            category="hardening",
        )]
    return [Finding(
        check_id="WIN-003", title="RDP: disabled",
        description="Remote Desktop Protocol is disabled.",
        severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
    )]


# ---------------------------------------------------------------------------
# WIN-004  PowerShell execution policy
# ---------------------------------------------------------------------------
@registry.register("WIN-004", os_family="windows", category="hardening")
def check_ps_execution_policy() -> List[Finding]:
    """Check PowerShell execution policy."""
    rc, out, _ = _ps("Get-ExecutionPolicy")
    if rc != 0:
        return [Finding(
            check_id="WIN-004", title="PowerShell execution policy",
            description="Cannot query execution policy.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    policy = out.strip().lower()
    if policy in ("unrestricted", "bypass"):
        return [Finding(
            check_id="WIN-004", title="PowerShell: unrestricted execution policy",
            description=f"PowerShell execution policy is '{policy}', allowing any script.",
            severity=Severity.HIGH, status=CheckStatus.FAIL,
            evidence=f"ExecutionPolicy: {policy}",
            remediation="Set-ExecutionPolicy RemoteSigned -Scope LocalMachine",
            category="hardening",
        )]
    return [Finding(
        check_id="WIN-004", title="PowerShell execution policy OK",
        description=f"PowerShell execution policy: {policy}.",
        severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
    )]


# ---------------------------------------------------------------------------
# WIN-005  BitLocker status
# ---------------------------------------------------------------------------
@registry.register("WIN-005", os_family="windows", category="hardening")
def check_bitlocker() -> List[Finding]:
    """Check BitLocker encryption status on system drive."""
    rc, out, _ = _ps(
        "(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus"
    )
    if rc != 0:
        return [Finding(
            check_id="WIN-005", title="BitLocker status",
            description="Cannot query BitLocker status (may require admin).",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    if "On" in out or "1" in out:
        return [Finding(
            check_id="WIN-005", title="BitLocker: enabled",
            description="BitLocker encryption is active on the system drive.",
            severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
        )]
    return [Finding(
        check_id="WIN-005", title="BitLocker: not enabled",
        description="BitLocker encryption is not active on the system drive.",
        severity=Severity.HIGH, status=CheckStatus.FAIL,
        remediation="Enable BitLocker: manage-bde -on C:",
        category="hardening",
    )]


# ---------------------------------------------------------------------------
# WIN-006  Guest account status
# ---------------------------------------------------------------------------
@registry.register("WIN-006", os_family="windows", category="hardening")
def check_guest_account() -> List[Finding]:
    """Check if the Guest account is disabled."""
    rc, out, _ = _ps(
        "(Get-LocalUser -Name Guest).Enabled"
    )
    if rc != 0:
        return [Finding(
            check_id="WIN-006", title="Guest account status",
            description="Cannot query Guest account.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    if "True" in out:
        return [Finding(
            check_id="WIN-006", title="Guest account: enabled",
            description="The Guest account is enabled, which is a security risk.",
            severity=Severity.MEDIUM, status=CheckStatus.FAIL,
            remediation="Disable-LocalUser -Name Guest",
            category="hardening",
        )]
    return [Finding(
        check_id="WIN-006", title="Guest account: disabled",
        description="The Guest account is properly disabled.",
        severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
    )]


# ---------------------------------------------------------------------------
# WIN-007  Autorun / AutoPlay
# ---------------------------------------------------------------------------
@registry.register("WIN-007", os_family="windows", category="hardening")
def check_autorun() -> List[Finding]:
    """Check if AutoRun is disabled."""
    rc, out, _ = _ps(
        "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue).NoDriveTypeAutoRun"
    )
    if rc != 0 or not out.strip():
        return [Finding(
            check_id="WIN-007", title="AutoRun: not restricted",
            description="AutoRun policy is not configured.",
            severity=Severity.MEDIUM, status=CheckStatus.WARN,
            remediation="Set NoDriveTypeAutoRun to 255 via Group Policy or registry.",
            category="hardening",
        )]
    try:
        value = int(out.strip())
        if value == 255:
            return [Finding(
                check_id="WIN-007", title="AutoRun: disabled for all drives",
                description="AutoRun is disabled for all drive types.",
                severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
            )]
    except ValueError:
        pass
    return [Finding(
        check_id="WIN-007", title="AutoRun: partially restricted",
        description="AutoRun is not fully disabled for all drive types.",
        severity=Severity.LOW, status=CheckStatus.WARN,
        evidence=f"NoDriveTypeAutoRun = {out.strip()}",
        remediation="Set NoDriveTypeAutoRun to 255.",
        category="hardening",
    )]


# ---------------------------------------------------------------------------
# WIN-008  SMBv1 protocol
# ---------------------------------------------------------------------------
@registry.register("WIN-008", os_family="windows", category="hardening")
def check_smbv1() -> List[Finding]:
    """Check if SMBv1 is disabled."""
    rc, out, _ = _ps(
        "(Get-SmbServerConfiguration).EnableSMB1Protocol"
    )
    if rc != 0:
        return [Finding(
            check_id="WIN-008", title="SMBv1 status",
            description="Cannot query SMBv1 status.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    if "True" in out:
        return [Finding(
            check_id="WIN-008", title="SMBv1: enabled",
            description="SMBv1 is enabled. It is vulnerable to EternalBlue and other exploits.",
            severity=Severity.CRITICAL, status=CheckStatus.FAIL,
            remediation="Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
            category="hardening",
        )]
    return [Finding(
        check_id="WIN-008", title="SMBv1: disabled",
        description="SMBv1 is properly disabled.",
        severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
    )]


# ---------------------------------------------------------------------------
# WIN-009  Windows Update service
# ---------------------------------------------------------------------------
@registry.register("WIN-009", os_family="windows", category="hardening")
def check_windows_update_service() -> List[Finding]:
    """Check if Windows Update service is running."""
    rc, out, _ = _ps(
        "(Get-Service wuauserv).Status"
    )
    if rc != 0:
        return [Finding(
            check_id="WIN-009", title="Windows Update service",
            description="Cannot query Windows Update service.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    status = out.strip().lower()
    if status != "running":
        return [Finding(
            check_id="WIN-009", title="Windows Update service: not running",
            description=f"Windows Update service status: {status}.",
            severity=Severity.MEDIUM, status=CheckStatus.WARN,
            remediation="Start-Service wuauserv; Set-Service wuauserv -StartupType Automatic",
            category="hardening",
        )]
    return [Finding(
        check_id="WIN-009", title="Windows Update service: running",
        description="Windows Update service is running.",
        severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
    )]


# ---------------------------------------------------------------------------
# WIN-010  Audit policy: logon events
# ---------------------------------------------------------------------------
@registry.register("WIN-010", os_family="windows", category="hardening")
def check_audit_logon() -> List[Finding]:
    """Check if logon event auditing is enabled."""
    rc, out, _ = _ps(
        "auditpol /get /category:'Logon/Logoff' 2>$null"
    )
    if rc != 0:
        return [Finding(
            check_id="WIN-010", title="Audit policy: logon events",
            description="Cannot query audit policy.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    if "No Auditing" in out:
        return [Finding(
            check_id="WIN-010", title="Audit policy: logon events not audited",
            description="Logon/Logoff events are not being audited.",
            severity=Severity.MEDIUM, status=CheckStatus.WARN,
            evidence=out.strip()[:300],
            remediation="auditpol /set /subcategory:'Logon' /success:enable /failure:enable",
            category="hardening",
        )]
    return [Finding(
        check_id="WIN-010", title="Audit policy: logon events audited",
        description="Logon/Logoff auditing is configured.",
        severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
    )]


# ---------------------------------------------------------------------------
# WIN-011  Screen lock timeout
# ---------------------------------------------------------------------------
@registry.register("WIN-011", os_family="windows", category="hardening")
def check_screen_lock() -> List[Finding]:
    """Check screen lock / screensaver timeout."""
    rc, out, _ = _ps(
        "(Get-ItemProperty 'HKCU:\\Control Panel\\Desktop' -Name ScreenSaveTimeOut -ErrorAction SilentlyContinue).ScreenSaveTimeOut"
    )
    if rc != 0 or not out.strip():
        return [Finding(
            check_id="WIN-011", title="Screen lock: not configured",
            description="No screen lock timeout is configured.",
            severity=Severity.LOW, status=CheckStatus.WARN,
            remediation="Configure screen lock timeout via Group Policy or registry.",
            category="hardening",
        )]
    try:
        timeout = int(out.strip())
        if timeout > 900:
            return [Finding(
                check_id="WIN-011", title="Screen lock: timeout too long",
                description=f"Screen lock timeout is {timeout}s (>{900}s recommended max).",
                severity=Severity.LOW, status=CheckStatus.WARN,
                evidence=f"ScreenSaveTimeOut = {timeout}",
                remediation="Set screen lock timeout to 900 seconds or less.",
                category="hardening",
            )]
    except ValueError:
        pass
    return [Finding(
        check_id="WIN-011", title="Screen lock: configured",
        description="Screen lock timeout is properly configured.",
        severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
    )]


# ---------------------------------------------------------------------------
# WIN-012  Remote Registry service
# ---------------------------------------------------------------------------
@registry.register("WIN-012", os_family="windows", category="hardening")
def check_remote_registry() -> List[Finding]:
    """Check if Remote Registry service is disabled."""
    rc, out, _ = _ps(
        "(Get-Service RemoteRegistry -ErrorAction SilentlyContinue).Status"
    )
    if rc != 0 or not out.strip():
        return [Finding(
            check_id="WIN-012", title="Remote Registry service",
            description="Cannot query Remote Registry service.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    status = out.strip().lower()
    if status == "running":
        return [Finding(
            check_id="WIN-012", title="Remote Registry: running",
            description="Remote Registry service is running, allowing remote registry access.",
            severity=Severity.MEDIUM, status=CheckStatus.WARN,
            remediation="Stop-Service RemoteRegistry; Set-Service RemoteRegistry -StartupType Disabled",
            category="hardening",
        )]
    return [Finding(
        check_id="WIN-012", title="Remote Registry: stopped",
        description="Remote Registry service is not running.",
        severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
    )]
