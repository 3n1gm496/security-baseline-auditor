"""Linux hardening checks — 18 real checks for SSH, sudoers, firewall, etc."""

from __future__ import annotations

import glob
import logging
import os
import re
import stat
from typing import List

from auditor.models import CheckStatus, Finding, Severity
from auditor.rules.engine import registry
from auditor.utils.platform import file_exists, read_file, run_command

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# LIN-001  SSH: PermitRootLogin
# ---------------------------------------------------------------------------
@registry.register("LIN-001", os_family="linux", category="hardening")
def check_ssh_root_login() -> List[Finding]:
    """Check if SSH allows root login."""
    config = read_file("/etc/ssh/sshd_config")
    if config is None:
        return [Finding(
            check_id="LIN-001", title="SSH: PermitRootLogin",
            description="Cannot read sshd_config.",
            severity=Severity.INFO, status=CheckStatus.SKIP,
            category="hardening",
        )]
    match = re.search(r'^\s*PermitRootLogin\s+(\S+)', config, re.MULTILINE)
    value = match.group(1).lower() if match else "prohibit-password"
    if value in ("yes",):
        return [Finding(
            check_id="LIN-001", title="SSH: PermitRootLogin enabled",
            description="SSH allows direct root login, which is a security risk.",
            severity=Severity.HIGH, status=CheckStatus.FAIL,
            evidence=f"PermitRootLogin {value}",
            remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd.",
            category="hardening",
        )]
    return [Finding(
        check_id="LIN-001", title="SSH: PermitRootLogin disabled",
        description="SSH root login is properly restricted.",
        severity=Severity.INFO, status=CheckStatus.PASS,
        evidence=f"PermitRootLogin {value}", category="hardening",
    )]


# ---------------------------------------------------------------------------
# LIN-002  SSH: PasswordAuthentication
# ---------------------------------------------------------------------------
@registry.register("LIN-002", os_family="linux", category="hardening")
def check_ssh_password_auth() -> List[Finding]:
    """Check if SSH allows password authentication."""
    config = read_file("/etc/ssh/sshd_config")
    if config is None:
        return [Finding(
            check_id="LIN-002", title="SSH: PasswordAuthentication",
            description="Cannot read sshd_config.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    match = re.search(r'^\s*PasswordAuthentication\s+(\S+)', config, re.MULTILINE)
    value = match.group(1).lower() if match else "yes"
    if value == "yes":
        return [Finding(
            check_id="LIN-002", title="SSH: PasswordAuthentication enabled",
            description="SSH allows password-based login. Key-based auth is more secure.",
            severity=Severity.MEDIUM, status=CheckStatus.WARN,
            evidence=f"PasswordAuthentication {value}",
            remediation="Set 'PasswordAuthentication no' in /etc/ssh/sshd_config.",
            category="hardening",
        )]
    return [Finding(
        check_id="LIN-002", title="SSH: PasswordAuthentication disabled",
        description="SSH password authentication is disabled.",
        severity=Severity.INFO, status=CheckStatus.PASS,
        evidence=f"PasswordAuthentication {value}", category="hardening",
    )]


# ---------------------------------------------------------------------------
# LIN-003  SSH: Protocol version
# ---------------------------------------------------------------------------
@registry.register("LIN-003", os_family="linux", category="hardening")
def check_ssh_protocol() -> List[Finding]:
    """Check SSH protocol version (legacy check)."""
    config = read_file("/etc/ssh/sshd_config")
    if config is None:
        return [Finding(
            check_id="LIN-003", title="SSH: Protocol version",
            description="Cannot read sshd_config.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    match = re.search(r'^\s*Protocol\s+(\S+)', config, re.MULTILINE)
    if match and "1" in match.group(1):
        return [Finding(
            check_id="LIN-003", title="SSH: Insecure protocol version",
            description="SSH protocol version 1 is enabled, which is insecure.",
            severity=Severity.CRITICAL, status=CheckStatus.FAIL,
            evidence=f"Protocol {match.group(1)}",
            remediation="Remove 'Protocol 1' from sshd_config (modern SSH defaults to v2).",
            category="hardening",
        )]
    return [Finding(
        check_id="LIN-003", title="SSH: Protocol version OK",
        description="SSH uses protocol version 2 (default in modern OpenSSH).",
        severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
    )]


# ---------------------------------------------------------------------------
# LIN-004  SSH: X11Forwarding
# ---------------------------------------------------------------------------
@registry.register("LIN-004", os_family="linux", category="hardening")
def check_ssh_x11() -> List[Finding]:
    """Check if SSH X11 forwarding is enabled."""
    config = read_file("/etc/ssh/sshd_config")
    if config is None:
        return [Finding(
            check_id="LIN-004", title="SSH: X11Forwarding",
            description="Cannot read sshd_config.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    match = re.search(r'^\s*X11Forwarding\s+(\S+)', config, re.MULTILINE)
    value = match.group(1).lower() if match else "no"
    if value == "yes":
        return [Finding(
            check_id="LIN-004", title="SSH: X11Forwarding enabled",
            description="X11 forwarding can be exploited for display hijacking.",
            severity=Severity.LOW, status=CheckStatus.WARN,
            evidence=f"X11Forwarding {value}",
            remediation="Set 'X11Forwarding no' in /etc/ssh/sshd_config unless needed.",
            category="hardening",
        )]
    return [Finding(
        check_id="LIN-004", title="SSH: X11Forwarding disabled",
        description="X11 forwarding is disabled.",
        severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
    )]


# ---------------------------------------------------------------------------
# LIN-005  Sudoers: NOPASSWD entries
# ---------------------------------------------------------------------------
@registry.register("LIN-005", os_family="linux", category="hardening")
def check_sudoers_nopasswd() -> List[Finding]:
    """Check for NOPASSWD entries in sudoers."""
    findings: List[Finding] = []
    sudoers_files = ["/etc/sudoers"] + glob.glob("/etc/sudoers.d/*")
    nopasswd_entries = []

    for path in sudoers_files:
        content = read_file(path)
        if content is None:
            continue
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "NOPASSWD" in stripped:
                nopasswd_entries.append(f"{path}:{i}: {stripped}")

    if nopasswd_entries:
        return [Finding(
            check_id="LIN-005", title="Sudoers: NOPASSWD entries found",
            description="NOPASSWD allows sudo without password, weakening security.",
            severity=Severity.MEDIUM, status=CheckStatus.WARN,
            evidence="\n".join(nopasswd_entries[:10]),
            remediation="Review NOPASSWD entries and remove unnecessary ones.",
            category="hardening",
        )]
    return [Finding(
        check_id="LIN-005", title="Sudoers: No NOPASSWD entries",
        description="No NOPASSWD entries found in sudoers configuration.",
        severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
    )]


# ---------------------------------------------------------------------------
# LIN-006  Sensitive file permissions: /etc/shadow
# ---------------------------------------------------------------------------
@registry.register("LIN-006", os_family="linux", category="hardening")
def check_shadow_permissions() -> List[Finding]:
    """Check /etc/shadow file permissions."""
    path = "/etc/shadow"
    if not os.path.exists(path):
        return [Finding(
            check_id="LIN-006", title="Shadow file permissions",
            description="/etc/shadow not found.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    try:
        st = os.stat(path)
        mode = oct(st.st_mode)[-3:]
        if st.st_mode & (stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH):
            return [Finding(
                check_id="LIN-006", title="Shadow file: world-accessible",
                description="/etc/shadow is readable or writable by others.",
                severity=Severity.CRITICAL, status=CheckStatus.FAIL,
                evidence=f"Permissions: {mode}",
                remediation="Run: chmod 640 /etc/shadow && chown root:shadow /etc/shadow",
                category="hardening",
            )]
        return [Finding(
            check_id="LIN-006", title="Shadow file permissions OK",
            description="/etc/shadow has appropriate permissions.",
            severity=Severity.INFO, status=CheckStatus.PASS,
            evidence=f"Permissions: {mode}", category="hardening",
        )]
    except PermissionError:
        return [Finding(
            check_id="LIN-006", title="Shadow file permissions",
            description="Cannot stat /etc/shadow (permission denied — likely OK).",
            severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
        )]


# ---------------------------------------------------------------------------
# LIN-007  Firewall: UFW / firewalld status
# ---------------------------------------------------------------------------
@registry.register("LIN-007", os_family="linux", category="hardening")
def check_firewall_status() -> List[Finding]:
    """Check if a firewall is active."""
    # Try UFW
    rc, out, _ = run_command(["ufw", "status"])
    if rc == 0:
        if "active" in out.lower() and "inactive" not in out.lower():
            return [Finding(
                check_id="LIN-007", title="Firewall: UFW active",
                description="UFW firewall is active.",
                severity=Severity.INFO, status=CheckStatus.PASS,
                evidence=out.strip()[:200], category="hardening",
            )]
        else:
            return [Finding(
                check_id="LIN-007", title="Firewall: UFW inactive",
                description="UFW firewall is installed but not active.",
                severity=Severity.HIGH, status=CheckStatus.FAIL,
                evidence=out.strip()[:200],
                remediation="Enable UFW: sudo ufw enable",
                category="hardening",
            )]

    # Try firewalld
    rc, out, _ = run_command(["firewall-cmd", "--state"])
    if rc == 0 and "running" in out.lower():
        return [Finding(
            check_id="LIN-007", title="Firewall: firewalld active",
            description="firewalld is running.",
            severity=Severity.INFO, status=CheckStatus.PASS,
            evidence=out.strip(), category="hardening",
        )]

    # Try iptables
    rc, out, _ = run_command(["iptables", "-L", "-n"])
    if rc == 0:
        rules = [l for l in out.splitlines() if l.strip() and not l.startswith("Chain") and not l.startswith("target")]
        if len(rules) > 0:
            return [Finding(
                check_id="LIN-007", title="Firewall: iptables rules present",
                description="iptables has active rules.",
                severity=Severity.INFO, status=CheckStatus.PASS,
                evidence=f"{len(rules)} rules found", category="hardening",
            )]

    return [Finding(
        check_id="LIN-007", title="Firewall: No active firewall detected",
        description="No active firewall (UFW, firewalld, iptables) was detected.",
        severity=Severity.HIGH, status=CheckStatus.FAIL,
        remediation="Install and enable a firewall: sudo apt install ufw && sudo ufw enable",
        category="hardening",
    )]


# ---------------------------------------------------------------------------
# LIN-008  SUID/SGID suspicious binaries
# ---------------------------------------------------------------------------
@registry.register("LIN-008", os_family="linux", category="hardening", quick=False)
def check_suid_sgid() -> List[Finding]:
    """Scan for unusual SUID/SGID binaries."""
    # Known safe SUID binaries
    known_suid = {
        "/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/su",
        "/usr/bin/newgrp", "/usr/bin/chsh", "/usr/bin/chfn",
        "/usr/bin/gpasswd", "/usr/bin/mount", "/usr/bin/umount",
        "/usr/bin/pkexec", "/usr/bin/crontab", "/usr/bin/at",
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        "/usr/lib/openssh/ssh-keysign",
        "/usr/sbin/pppd", "/usr/sbin/unix_chkpwd",
        "/usr/bin/fusermount", "/usr/bin/fusermount3",
        "/snap/snapd/current/usr/lib/snapd/snap-confine",
    }

    rc, out, _ = run_command(
        ["find", "/usr", "/bin", "/sbin", "-perm", "/6000", "-type", "f"],
        timeout=60,
    )
    if rc != 0 and not out:
        return [Finding(
            check_id="LIN-008", title="SUID/SGID scan",
            description="Could not scan for SUID/SGID binaries.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]

    suspicious = []
    for line in out.strip().splitlines():
        path = line.strip()
        if path and path not in known_suid:
            # Also allow paths that start with known prefixes
            if not any(path.startswith(k.rsplit("/", 1)[0]) for k in known_suid
                       if "/" in k):
                suspicious.append(path)

    if suspicious:
        return [Finding(
            check_id="LIN-008", title="SUID/SGID: Suspicious binaries found",
            description=f"Found {len(suspicious)} SUID/SGID binaries not in the known-safe list.",
            severity=Severity.MEDIUM, status=CheckStatus.WARN,
            evidence="\n".join(suspicious[:20]),
            remediation="Review each binary and remove SUID/SGID bit if unnecessary: chmod u-s <file>",
            category="hardening",
        )]
    return [Finding(
        check_id="LIN-008", title="SUID/SGID: No suspicious binaries",
        description="All SUID/SGID binaries are in the known-safe list.",
        severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
    )]


# ---------------------------------------------------------------------------
# LIN-009  Enabled services check
# ---------------------------------------------------------------------------
@registry.register("LIN-009", os_family="linux", category="hardening")
def check_enabled_services() -> List[Finding]:
    """Check for potentially risky enabled services."""
    risky_services = [
        "telnet", "rsh", "rlogin", "rexec", "tftp",
        "vsftpd", "proftpd", "xinetd", "avahi-daemon",
    ]
    rc, out, _ = run_command(["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-pager"])
    if rc != 0:
        return [Finding(
            check_id="LIN-009", title="Enabled services check",
            description="Cannot list enabled services.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]

    found_risky = []
    for line in out.splitlines():
        for svc in risky_services:
            if svc in line.lower() and "enabled" in line.lower():
                found_risky.append(line.strip())

    if found_risky:
        return [Finding(
            check_id="LIN-009", title="Risky services enabled",
            description="Potentially insecure services are enabled at boot.",
            severity=Severity.MEDIUM, status=CheckStatus.WARN,
            evidence="\n".join(found_risky),
            remediation="Disable unnecessary services: sudo systemctl disable <service>",
            category="hardening",
        )]
    return [Finding(
        check_id="LIN-009", title="No risky services enabled",
        description="No known risky services are enabled.",
        severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
    )]


# ---------------------------------------------------------------------------
# LIN-010  Kernel: IP forwarding
# ---------------------------------------------------------------------------
@registry.register("LIN-010", os_family="linux", category="hardening")
def check_ip_forwarding() -> List[Finding]:
    """Check if IP forwarding is enabled."""
    content = read_file("/proc/sys/net/ipv4/ip_forward")
    if content is None:
        return [Finding(
            check_id="LIN-010", title="IP forwarding check",
            description="Cannot read /proc/sys/net/ipv4/ip_forward.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    value = content.strip()
    if value == "1":
        return [Finding(
            check_id="LIN-010", title="IP forwarding enabled",
            description="IPv4 forwarding is enabled. This is risky unless the host is a router.",
            severity=Severity.MEDIUM, status=CheckStatus.WARN,
            evidence="net.ipv4.ip_forward = 1",
            remediation="Disable if not needed: sysctl -w net.ipv4.ip_forward=0",
            category="hardening",
        )]
    return [Finding(
        check_id="LIN-010", title="IP forwarding disabled",
        description="IPv4 forwarding is disabled.",
        severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
    )]


# ---------------------------------------------------------------------------
# LIN-011  Core dumps
# ---------------------------------------------------------------------------
@registry.register("LIN-011", os_family="linux", category="hardening")
def check_core_dumps() -> List[Finding]:
    """Check if core dumps are restricted."""
    limits_conf = read_file("/etc/security/limits.conf")
    sysctl_content = read_file("/proc/sys/fs/suid_dumpable")

    core_restricted = False
    if limits_conf and "* hard core 0" in limits_conf:
        core_restricted = True
    if sysctl_content and sysctl_content.strip() == "0":
        core_restricted = True

    if not core_restricted:
        return [Finding(
            check_id="LIN-011", title="Core dumps not restricted",
            description="Core dumps may contain sensitive data and are not fully restricted.",
            severity=Severity.LOW, status=CheckStatus.WARN,
            remediation="Add '* hard core 0' to /etc/security/limits.conf and set fs.suid_dumpable=0.",
            category="hardening",
        )]
    return [Finding(
        check_id="LIN-011", title="Core dumps restricted",
        description="Core dumps are properly restricted.",
        severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
    )]


# ---------------------------------------------------------------------------
# LIN-012  /tmp mount options (noexec, nosuid)
# ---------------------------------------------------------------------------
@registry.register("LIN-012", os_family="linux", category="hardening")
def check_tmp_mount() -> List[Finding]:
    """Check /tmp mount options."""
    rc, out, _ = run_command(["findmnt", "-n", "-o", "OPTIONS", "/tmp"])
    if rc != 0:
        return [Finding(
            check_id="LIN-012", title="/tmp mount options",
            description="Cannot determine /tmp mount options.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    options = out.strip().lower()
    issues = []
    if "noexec" not in options:
        issues.append("noexec missing")
    if "nosuid" not in options:
        issues.append("nosuid missing")

    if issues:
        return [Finding(
            check_id="LIN-012", title="/tmp mount: missing hardening options",
            description=f"/tmp is missing mount options: {', '.join(issues)}.",
            severity=Severity.LOW, status=CheckStatus.WARN,
            evidence=f"Current options: {options}",
            remediation="Add noexec,nosuid,nodev to /tmp mount in /etc/fstab.",
            category="hardening",
        )]
    return [Finding(
        check_id="LIN-012", title="/tmp mount options OK",
        description="/tmp has noexec and nosuid mount options.",
        severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
    )]


# ---------------------------------------------------------------------------
# LIN-013  Automatic security updates
# ---------------------------------------------------------------------------
@registry.register("LIN-013", os_family="linux", category="hardening")
def check_auto_updates() -> List[Finding]:
    """Check if automatic security updates are configured."""
    # Debian/Ubuntu: unattended-upgrades
    apt_conf = read_file("/etc/apt/apt.conf.d/20auto-upgrades")
    if apt_conf and 'Unattended-Upgrade "1"' in apt_conf:
        return [Finding(
            check_id="LIN-013", title="Automatic updates: enabled",
            description="Unattended-upgrades is configured.",
            severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
        )]

    # RHEL/CentOS: dnf-automatic
    rc, out, _ = run_command(["systemctl", "is-enabled", "dnf-automatic.timer"])
    if rc == 0 and "enabled" in out:
        return [Finding(
            check_id="LIN-013", title="Automatic updates: dnf-automatic enabled",
            description="dnf-automatic timer is enabled.",
            severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
        )]

    return [Finding(
        check_id="LIN-013", title="Automatic updates: not configured",
        description="No automatic security update mechanism detected.",
        severity=Severity.MEDIUM, status=CheckStatus.WARN,
        remediation="Install and configure unattended-upgrades (Debian/Ubuntu) or dnf-automatic (RHEL).",
        category="hardening",
    )]


# ---------------------------------------------------------------------------
# LIN-014  Password policy: minimum length
# ---------------------------------------------------------------------------
@registry.register("LIN-014", os_family="linux", category="hardening")
def check_password_policy() -> List[Finding]:
    """Check PAM password minimum length."""
    pam_files = [
        "/etc/pam.d/common-password",
        "/etc/pam.d/system-auth",
        "/etc/security/pwquality.conf",
    ]
    min_len = None
    for path in pam_files:
        content = read_file(path)
        if content is None:
            continue
        match = re.search(r'minlen\s*=?\s*(\d+)', content)
        if match:
            min_len = int(match.group(1))
            break

    if min_len is None:
        return [Finding(
            check_id="LIN-014", title="Password policy: not configured",
            description="No password minimum length policy found.",
            severity=Severity.MEDIUM, status=CheckStatus.WARN,
            remediation="Configure minlen in /etc/security/pwquality.conf (recommended: 12+).",
            category="hardening",
        )]
    if min_len < 8:
        return [Finding(
            check_id="LIN-014", title="Password policy: weak minimum length",
            description=f"Password minimum length is {min_len}, which is too short.",
            severity=Severity.MEDIUM, status=CheckStatus.WARN,
            evidence=f"minlen={min_len}",
            remediation="Set minlen=12 or higher in /etc/security/pwquality.conf.",
            category="hardening",
        )]
    return [Finding(
        check_id="LIN-014", title="Password policy: OK",
        description=f"Password minimum length is {min_len}.",
        severity=Severity.INFO, status=CheckStatus.PASS,
        evidence=f"minlen={min_len}", category="hardening",
    )]


# ---------------------------------------------------------------------------
# LIN-015  SSH: MaxAuthTries
# ---------------------------------------------------------------------------
@registry.register("LIN-015", os_family="linux", category="hardening")
def check_ssh_max_auth_tries() -> List[Finding]:
    """Check SSH MaxAuthTries setting."""
    config = read_file("/etc/ssh/sshd_config")
    if config is None:
        return [Finding(
            check_id="LIN-015", title="SSH: MaxAuthTries",
            description="Cannot read sshd_config.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    match = re.search(r'^\s*MaxAuthTries\s+(\d+)', config, re.MULTILINE)
    value = int(match.group(1)) if match else 6
    if value > 4:
        return [Finding(
            check_id="LIN-015", title="SSH: MaxAuthTries too high",
            description=f"MaxAuthTries is {value}. Recommended: 3-4.",
            severity=Severity.LOW, status=CheckStatus.WARN,
            evidence=f"MaxAuthTries {value}",
            remediation="Set 'MaxAuthTries 3' in /etc/ssh/sshd_config.",
            category="hardening",
        )]
    return [Finding(
        check_id="LIN-015", title="SSH: MaxAuthTries OK",
        description=f"MaxAuthTries is {value}.",
        severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
    )]


# ---------------------------------------------------------------------------
# LIN-016  /etc/passwd permissions
# ---------------------------------------------------------------------------
@registry.register("LIN-016", os_family="linux", category="hardening")
def check_passwd_permissions() -> List[Finding]:
    """Check /etc/passwd file permissions."""
    path = "/etc/passwd"
    if not os.path.exists(path):
        return [Finding(
            check_id="LIN-016", title="/etc/passwd permissions",
            description="/etc/passwd not found.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    st = os.stat(path)
    mode = oct(st.st_mode)[-3:]
    if st.st_mode & stat.S_IWOTH:
        return [Finding(
            check_id="LIN-016", title="/etc/passwd: world-writable",
            description="/etc/passwd is writable by others.",
            severity=Severity.CRITICAL, status=CheckStatus.FAIL,
            evidence=f"Permissions: {mode}",
            remediation="Run: chmod 644 /etc/passwd",
            category="hardening",
        )]
    return [Finding(
        check_id="LIN-016", title="/etc/passwd permissions OK",
        description=f"/etc/passwd permissions: {mode}.",
        severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
    )]


# ---------------------------------------------------------------------------
# LIN-017  Kernel: ASLR
# ---------------------------------------------------------------------------
@registry.register("LIN-017", os_family="linux", category="hardening")
def check_aslr() -> List[Finding]:
    """Check if ASLR (Address Space Layout Randomization) is enabled."""
    content = read_file("/proc/sys/kernel/randomize_va_space")
    if content is None:
        return [Finding(
            check_id="LIN-017", title="ASLR check",
            description="Cannot read ASLR setting.",
            severity=Severity.INFO, status=CheckStatus.SKIP, category="hardening",
        )]
    value = content.strip()
    if value != "2":
        return [Finding(
            check_id="LIN-017", title="ASLR: not fully enabled",
            description=f"ASLR value is {value}. Full randomization requires 2.",
            severity=Severity.HIGH, status=CheckStatus.FAIL,
            evidence=f"randomize_va_space = {value}",
            remediation="Enable full ASLR: sysctl -w kernel.randomize_va_space=2",
            category="hardening",
        )]
    return [Finding(
        check_id="LIN-017", title="ASLR: fully enabled",
        description="ASLR is set to full randomization (2).",
        severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
    )]


# ---------------------------------------------------------------------------
# LIN-018  Login banner / legal warning
# ---------------------------------------------------------------------------
@registry.register("LIN-018", os_family="linux", category="hardening", quick=False)
def check_login_banner() -> List[Finding]:
    """Check if a login banner is configured."""
    banner_files = ["/etc/issue", "/etc/issue.net", "/etc/motd"]
    has_banner = False
    for path in banner_files:
        content = read_file(path)
        if content and len(content.strip()) > 10:
            has_banner = True
            break

    config = read_file("/etc/ssh/sshd_config")
    if config:
        match = re.search(r'^\s*Banner\s+(\S+)', config, re.MULTILINE)
        if match and match.group(1) != "none":
            has_banner = True

    if not has_banner:
        return [Finding(
            check_id="LIN-018", title="Login banner: not configured",
            description="No login warning banner is configured.",
            severity=Severity.LOW, status=CheckStatus.WARN,
            remediation="Configure a legal warning banner in /etc/issue and set 'Banner /etc/issue.net' in sshd_config.",
            category="hardening",
        )]
    return [Finding(
        check_id="LIN-018", title="Login banner: configured",
        description="A login banner is configured.",
        severity=Severity.INFO, status=CheckStatus.PASS, category="hardening",
    )]
