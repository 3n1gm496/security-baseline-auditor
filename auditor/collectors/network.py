"""Network exposure collector — lists listening ports and associated processes."""

from __future__ import annotations

import logging
import os
import re
from typing import List

from auditor.models import ListeningPort
from auditor.utils.platform import get_os_family, run_command

logger = logging.getLogger(__name__)


def collect_listening_ports() -> List[ListeningPort]:
    """Collect all listening ports on the local machine."""
    os_family = get_os_family()
    if os_family == "linux":
        return _collect_linux()
    elif os_family == "darwin":
        return _collect_darwin()
    elif os_family == "windows":
        return _collect_windows()
    return []


def _is_public_address(address: str) -> bool:
    """Check if an address is bound to all interfaces (public)."""
    return address in ("0.0.0.0", "::", "*", "0.0.0.0/0", "::/0", "")


def _collect_linux() -> List[ListeningPort]:
    """Collect listening ports on Linux using ss."""
    ports: List[ListeningPort] = []

    # Try ss first
    rc, out, _ = run_command(["ss", "-tlnp"])
    if rc == 0:
        ports.extend(_parse_ss_output(out, "tcp"))

    rc, out, _ = run_command(["ss", "-ulnp"])
    if rc == 0:
        ports.extend(_parse_ss_output(out, "udp"))

    if not ports:
        # Fallback to netstat
        rc, out, _ = run_command(["netstat", "-tlnp"])
        if rc == 0:
            ports.extend(_parse_netstat_linux(out, "tcp"))
        rc, out, _ = run_command(["netstat", "-ulnp"])
        if rc == 0:
            ports.extend(_parse_netstat_linux(out, "udp"))

    # Enrich with process info from /proc
    for port in ports:
        if port.pid:
            _enrich_from_proc(port)

    return ports


def _parse_ss_output(output: str, protocol: str) -> List[ListeningPort]:
    """Parse ss output."""
    ports: List[ListeningPort] = []
    for line in output.strip().splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) < 5:
            continue
        local = parts[3]
        # Parse address:port
        addr, port_str = _split_address_port(local)
        try:
            port_num = int(port_str)
        except (ValueError, TypeError):
            continue

        lp = ListeningPort(
            protocol=protocol,
            local_address=addr,
            local_port=port_num,
            is_public=_is_public_address(addr),
        )

        # Parse process info: users:(("sshd",pid=1234,fd=3))
        if len(parts) >= 6:
            proc_info = parts[-1]
            pid_match = re.search(r'pid=(\d+)', proc_info)
            name_match = re.search(r'\("([^"]+)"', proc_info)
            if pid_match:
                lp.pid = int(pid_match.group(1))
            if name_match:
                lp.process_name = name_match.group(1)

        ports.append(lp)
    return ports


def _parse_netstat_linux(output: str, protocol: str) -> List[ListeningPort]:
    """Parse netstat output on Linux."""
    ports: List[ListeningPort] = []
    for line in output.strip().splitlines()[2:]:  # skip headers
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        addr, port_str = _split_address_port(local)
        try:
            port_num = int(port_str)
        except (ValueError, TypeError):
            continue

        lp = ListeningPort(
            protocol=protocol,
            local_address=addr,
            local_port=port_num,
            is_public=_is_public_address(addr),
        )

        # PID/Program
        if len(parts) >= 7:
            pid_prog = parts[6]
            if "/" in pid_prog:
                pid_str, prog = pid_prog.split("/", 1)
                try:
                    lp.pid = int(pid_str)
                except ValueError:
                    pass
                lp.process_name = prog

        ports.append(lp)
    return ports


def _split_address_port(addr_port: str) -> tuple:
    """Split address:port, handling IPv6 [addr]:port."""
    if addr_port.startswith("["):
        # IPv6
        bracket_end = addr_port.rfind("]")
        if bracket_end >= 0:
            addr = addr_port[1:bracket_end]
            port = addr_port[bracket_end + 2:]  # skip ]:
            return addr, port
    # IPv4 or simple
    if ":" in addr_port:
        idx = addr_port.rfind(":")
        return addr_port[:idx], addr_port[idx + 1:]
    return addr_port, "0"


def _enrich_from_proc(port: ListeningPort) -> None:
    """Enrich port info from /proc on Linux."""
    if not port.pid:
        return
    try:
        exe_path = os.readlink(f"/proc/{port.pid}/exe")
        port.executable_path = exe_path
    except (OSError, PermissionError):
        pass
    try:
        with open(f"/proc/{port.pid}/status", "r") as f:
            for line in f:
                if line.startswith("Uid:"):
                    uid = line.split()[1]
                    # Resolve UID to username
                    try:
                        import pwd
                        port.user = pwd.getpwuid(int(uid)).pw_name
                    except (KeyError, ImportError):
                        port.user = uid
                    break
    except (OSError, PermissionError):
        pass


def _collect_darwin() -> List[ListeningPort]:
    """Collect listening ports on macOS using lsof."""
    ports: List[ListeningPort] = []
    rc, out, _ = run_command(["lsof", "-iTCP", "-sTCP:LISTEN", "-nP"])
    if rc != 0:
        return ports

    for line in out.strip().splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        process_name = parts[0]
        try:
            pid = int(parts[1])
        except ValueError:
            pid = None
        user = parts[2]
        name_field = parts[8]

        # Parse address:port from NAME field
        addr, port_str = _split_address_port(name_field)
        try:
            port_num = int(port_str)
        except (ValueError, TypeError):
            continue

        ports.append(ListeningPort(
            protocol="tcp",
            local_address=addr,
            local_port=port_num,
            pid=pid,
            process_name=process_name,
            user=user,
            is_public=_is_public_address(addr),
        ))

    return ports


def _collect_windows() -> List[ListeningPort]:
    """Collect listening ports on Windows using netstat."""
    ports: List[ListeningPort] = []
    rc, out, _ = run_command(["netstat", "-ano", "-p", "TCP"])
    if rc != 0:
        return ports

    for line in out.strip().splitlines():
        line = line.strip()
        if "LISTENING" not in line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        local = parts[1]
        addr, port_str = _split_address_port(local)
        try:
            port_num = int(port_str)
            pid = int(parts[4])
        except (ValueError, IndexError):
            continue

        ports.append(ListeningPort(
            protocol="tcp",
            local_address=addr,
            local_port=port_num,
            pid=pid,
            is_public=_is_public_address(addr),
        ))

    # Enrich with process names
    for port in ports:
        if port.pid:
            rc, out, _ = run_command(
                ["powershell", "-Command",
                 f"(Get-Process -Id {port.pid}).ProcessName"],
                timeout=5,
            )
            if rc == 0:
                port.process_name = out.strip()

    return ports
