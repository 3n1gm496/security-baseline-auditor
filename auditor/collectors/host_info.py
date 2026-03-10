"""Host information collector — gathers OS, kernel, users, security tools."""

from __future__ import annotations

import logging
import os
import platform
import shutil
from typing import List

from auditor.models import HostInfo
from auditor.utils.platform import get_os_family, run_command

logger = logging.getLogger(__name__)


def collect_host_info() -> HostInfo:
    """Collect host information for the current machine."""
    os_family = get_os_family()
    info = HostInfo(
        hostname=platform.node(),
        os_name=platform.system(),
        os_version=platform.version(),
        os_family=os_family,
        kernel_version=platform.release(),
        architecture=platform.machine(),
    )

    if os_family == "linux":
        _collect_linux(info)
    elif os_family == "darwin":
        _collect_darwin(info)
    elif os_family == "windows":
        _collect_windows(info)

    return info


def _collect_linux(info: HostInfo) -> None:
    """Collect Linux-specific host information."""
    # Uptime
    rc, out, _ = run_command(["uptime", "-p"])
    if rc == 0:
        info.uptime = out.strip()

    # Pretty OS name from os-release
    try:
        with open("/etc/os-release", "r") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    info.os_name = line.split("=", 1)[1].strip().strip('"')
                    break
    except FileNotFoundError:
        pass

    # Local users (from /etc/passwd, UID >= 1000 or 0)
    try:
        with open("/etc/passwd", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 3:
                    uid = int(parts[2])
                    if uid == 0 or uid >= 1000:
                        info.local_users.append(parts[0])
    except (FileNotFoundError, ValueError):
        pass

    # Security tools detection
    _detect_security_tools_linux(info)


def _detect_security_tools_linux(info: HostInfo) -> None:
    """Detect installed security tools on Linux."""
    tools = {
        "ufw": "ufw",
        "firewalld": "firewall-cmd",
        "iptables": "iptables",
        "nftables": "nft",
        "apparmor": "apparmor_status",
        "selinux": "getenforce",
        "fail2ban": "fail2ban-client",
        "clamav": "clamscan",
        "rkhunter": "rkhunter",
        "chkrootkit": "chkrootkit",
        "aide": "aide",
        "auditd": "auditctl",
        "ossec": "ossec-control",
    }
    for name, binary in tools.items():
        if shutil.which(binary):
            info.security_tools.append(name)


def _collect_darwin(info: HostInfo) -> None:
    """Collect macOS-specific host information."""
    rc, out, _ = run_command(["sw_vers", "-productVersion"])
    if rc == 0:
        info.os_version = out.strip()
        info.os_name = f"macOS {out.strip()}"

    rc, out, _ = run_command(["uptime"])
    if rc == 0:
        info.uptime = out.strip()

    # Local users
    rc, out, _ = run_command(["dscl", ".", "-list", "/Users"])
    if rc == 0:
        for user in out.strip().splitlines():
            user = user.strip()
            if user and not user.startswith("_"):
                info.local_users.append(user)

    # Security tools
    tools_mac = {
        "filevault": "fdesetup",
        "xprotect": "/usr/libexec/XProtect",
        "gatekeeper": "spctl",
        "little-snitch": "/Library/Little Snitch",
    }
    for name, path in tools_mac.items():
        if shutil.which(path) or os.path.exists(path):
            info.security_tools.append(name)


def _collect_windows(info: HostInfo) -> None:
    """Collect Windows-specific host information."""
    rc, out, _ = run_command(
        ["powershell", "-Command",
         "(Get-CimInstance Win32_OperatingSystem).Caption"]
    )
    if rc == 0:
        info.os_name = out.strip()

    rc, out, _ = run_command(
        ["powershell", "-Command",
         "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime"]
    )
    if rc == 0:
        info.uptime = out.strip()

    # Local users
    rc, out, _ = run_command(
        ["powershell", "-Command",
         "Get-LocalUser | Select-Object -ExpandProperty Name"]
    )
    if rc == 0:
        info.local_users = [u.strip() for u in out.strip().splitlines() if u.strip()]

    # Security tools
    tools_win = ["WindowsDefender", "BitLocker", "Windows Firewall"]
    rc, out, _ = run_command(
        ["powershell", "-Command",
         "Get-MpComputerStatus | Select-Object -ExpandProperty AMServiceEnabled"]
    )
    if rc == 0 and "True" in out:
        info.security_tools.append("Windows Defender")

    rc, out, _ = run_command(
        ["powershell", "-Command",
         "Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled"]
    )
    if rc == 0 and "True" in out:
        info.security_tools.append("Windows Firewall")
