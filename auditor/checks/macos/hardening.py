"""macOS hardening checks — 10 real checks for FileVault, firewall, etc."""

from __future__ import annotations

import glob
import logging
import os
from typing import List

from auditor.models import CheckStatus, Finding, Severity
from auditor.rules.engine import registry
from auditor.utils.platform import run_command

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# MAC-001  FileVault disk encryption
# ---------------------------------------------------------------------------
@registry.register("MAC-001", os_family="darwin", category="hardening")
def check_filevault() -> List[Finding]:
    """Check if FileVault disk encryption is enabled."""
    rc, out, _ = run_command(["fdesetup", "status"])
    if rc != 0:
        return [Finding(
            check_id="MAC-001", title="FileVault status",
            description="Cannot query FileVault status (may require admin).",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    if "On" in out:
        return [Finding(
            check_id="MAC-001", title="FileVault: enabled",
            description="FileVault disk encryption is active.",
            severity=Severity.INFO, status=CheckStatus.PASS,
            evidence=out.strip(), category="hardening",
        )]
    return [Finding(
        check_id="MAC-001", title="FileVault: not enabled",
        description="FileVault disk encryption is not active.",
        severity=Severity.HIGH, status=CheckStatus.FAIL,
        evidence=out.strip(),
        remediation="Enable FileVault: sudo fdesetup enable",
        category="hardening",
    )]


# ---------------------------------------------------------------------------
# MAC-002  macOS Firewall
# ---------------------------------------------------------------------------
@registry.register("MAC-002", os_family="darwin", category="hardening")
def check_macos_firewall() -> List[Finding]:
    """Check if macOS application firewall is enabled."""
    rc, out, _ = run_command(
        ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"]
    )
    if rc != 0:
        return [Finding(
            check_id="MAC-002", title="macOS Firewall status",
            description="Cannot query firewall status.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    if "enabled" in out.lower():
        return [Finding(
            check_id="MAC-002", title="macOS Firewall: enabled",
            description="The application firewall is enabled.",
            severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
        )]
    return [Finding(
        check_id="MAC-002", title="macOS Firewall: disabled",
        description="The application firewall is not enabled.",
        severity=Severity.HIGH, status=CheckStatus.FAIL,
        remediation="Enable firewall: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
        category="hardening",
    )]


# ---------------------------------------------------------------------------
# MAC-003  Firewall stealth mode
# ---------------------------------------------------------------------------
@registry.register("MAC-003", os_family="darwin", category="hardening")
def check_stealth_mode() -> List[Finding]:
    """Check if firewall stealth mode is enabled."""
    rc, out, _ = run_command(
        ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"]
    )
    if rc != 0:
        return [Finding(
            check_id="MAC-003", title="Stealth mode",
            description="Cannot query stealth mode.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    if "enabled" in out.lower():
        return [Finding(
            check_id="MAC-003", title="Stealth mode: enabled",
            description="Firewall stealth mode is enabled.",
            severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
        )]
    return [Finding(
        check_id="MAC-003", title="Stealth mode: disabled",
        description="Firewall stealth mode is not enabled.",
        severity=Severity.LOW, status=CheckStatus.WARN,
        remediation="Enable: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on",
        category="hardening",
    )]


# ---------------------------------------------------------------------------
# MAC-004  Automatic login
# ---------------------------------------------------------------------------
@registry.register("MAC-004", os_family="darwin", category="hardening")
def check_auto_login() -> List[Finding]:
    """Check if automatic login is disabled."""
    rc, out, _ = run_command(
        ["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"]
    )
    if rc != 0:
        # Key not found = auto login disabled
        return [Finding(
            check_id="MAC-004", title="Automatic login: disabled",
            description="Automatic login is not configured.",
            severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
        )]
    return [Finding(
        check_id="MAC-004", title="Automatic login: enabled",
        description=f"Automatic login is enabled for user: {out.strip()}.",
        severity=Severity.HIGH, status=CheckStatus.FAIL,
        evidence=f"autoLoginUser = {out.strip()}",
        remediation="Disable automatic login in System Preferences > Users & Groups.",
        category="hardening",
    )]


# ---------------------------------------------------------------------------
# MAC-005  Screen saver password
# ---------------------------------------------------------------------------
@registry.register("MAC-005", os_family="darwin", category="hardening")
def check_screensaver_password() -> List[Finding]:
    """Check if screen saver requires password."""
    rc, out, _ = run_command(
        ["defaults", "read", "com.apple.screensaver", "askForPassword"]
    )
    if rc == 0 and out.strip() == "1":
        return [Finding(
            check_id="MAC-005", title="Screen saver password: required",
            description="Screen saver requires password to unlock.",
            severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
        )]
    return [Finding(
        check_id="MAC-005", title="Screen saver password: not required",
        description="Screen saver does not require a password.",
        severity=Severity.MEDIUM, status=CheckStatus.WARN,
        remediation="Enable: defaults write com.apple.screensaver askForPassword -int 1",
        category="hardening",
    )]


# ---------------------------------------------------------------------------
# MAC-006  Remote login (SSH)
# ---------------------------------------------------------------------------
@registry.register("MAC-006", os_family="darwin", category="hardening")
def check_remote_login() -> List[Finding]:
    """Check if Remote Login (SSH) is enabled."""
    rc, out, _ = run_command(["systemsetup", "-getremotelogin"])
    if rc != 0:
        return [Finding(
            check_id="MAC-006", title="Remote Login (SSH)",
            description="Cannot query Remote Login status.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    if "on" in out.lower():
        return [Finding(
            check_id="MAC-006", title="Remote Login (SSH): enabled",
            description="SSH remote login is enabled.",
            severity=Severity.MEDIUM, status=CheckStatus.WARN,
            evidence=out.strip(),
            remediation="Disable if not needed: sudo systemsetup -setremotelogin off",
            category="hardening",
        )]
    return [Finding(
        check_id="MAC-006", title="Remote Login (SSH): disabled",
        description="SSH remote login is disabled.",
        severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
    )]


# ---------------------------------------------------------------------------
# MAC-007  Gatekeeper
# ---------------------------------------------------------------------------
@registry.register("MAC-007", os_family="darwin", category="hardening")
def check_gatekeeper() -> List[Finding]:
    """Check if Gatekeeper is enabled."""
    rc, out, _ = run_command(["spctl", "--status"])
    if rc != 0:
        return [Finding(
            check_id="MAC-007", title="Gatekeeper status",
            description="Cannot query Gatekeeper status.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    if "enabled" in out.lower():
        return [Finding(
            check_id="MAC-007", title="Gatekeeper: enabled",
            description="Gatekeeper is enabled.",
            severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
        )]
    return [Finding(
        check_id="MAC-007", title="Gatekeeper: disabled",
        description="Gatekeeper is disabled, allowing unsigned apps.",
        severity=Severity.HIGH, status=CheckStatus.FAIL,
        remediation="Enable: sudo spctl --master-enable",
        category="hardening",
    )]


# ---------------------------------------------------------------------------
# MAC-008  SIP (System Integrity Protection)
# ---------------------------------------------------------------------------
@registry.register("MAC-008", os_family="darwin", category="hardening")
def check_sip() -> List[Finding]:
    """Check System Integrity Protection status."""
    rc, out, _ = run_command(["csrutil", "status"])
    if rc != 0:
        return [Finding(
            check_id="MAC-008", title="SIP status",
            description="Cannot query SIP status.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    if "enabled" in out.lower():
        return [Finding(
            check_id="MAC-008", title="SIP: enabled",
            description="System Integrity Protection is enabled.",
            severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
        )]
    return [Finding(
        check_id="MAC-008", title="SIP: disabled",
        description="System Integrity Protection is disabled.",
        severity=Severity.CRITICAL, status=CheckStatus.FAIL,
        remediation="Re-enable SIP from Recovery Mode: csrutil enable",
        category="hardening",
    )]


# ---------------------------------------------------------------------------
# MAC-009  Launch Agents/Daemons (third-party)
# ---------------------------------------------------------------------------
@registry.register("MAC-009", os_family="darwin", category="hardening", quick=False)
def check_launch_agents() -> List[Finding]:
    """Check for third-party launch agents and daemons."""
    dirs = [
        os.path.expanduser("~/Library/LaunchAgents"),
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
    ]
    third_party = []
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for f in os.listdir(d):
            if f.endswith(".plist") and not f.startswith("com.apple."):
                third_party.append(os.path.join(d, f))

    if third_party:
        return [Finding(
            check_id="MAC-009", title="Third-party Launch Agents/Daemons found",
            description=f"Found {len(third_party)} non-Apple launch agents/daemons.",
            severity=Severity.LOW, status=CheckStatus.WARN,
            evidence="\n".join(third_party[:15]),
            remediation="Review each item and remove any that are unknown or unnecessary.",
            category="hardening",
        )]
    return [Finding(
        check_id="MAC-009", title="No third-party Launch Agents/Daemons",
        description="No non-Apple launch agents or daemons found.",
        severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
    )]


# ---------------------------------------------------------------------------
# MAC-010  Software Update: automatic check
# ---------------------------------------------------------------------------
@registry.register("MAC-010", os_family="darwin", category="hardening")
def check_software_update() -> List[Finding]:
    """Check if automatic software update checking is enabled."""
    rc, out, _ = run_command(
        ["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate",
         "AutomaticCheckEnabled"]
    )
    if rc == 0 and out.strip() == "1":
        return [Finding(
            check_id="MAC-010", title="Software Update: auto-check enabled",
            description="Automatic software update checking is enabled.",
            severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
        )]
    return [Finding(
        check_id="MAC-010", title="Software Update: auto-check disabled",
        description="Automatic software update checking is not enabled.",
        severity=Severity.MEDIUM, status=CheckStatus.WARN,
        remediation="Enable: sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true",
        category="hardening",
    )]
