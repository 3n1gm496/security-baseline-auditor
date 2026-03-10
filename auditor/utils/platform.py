"""Platform detection and command execution utilities."""

from __future__ import annotations

import logging
import os
import platform
import subprocess
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


def get_os_family() -> str:
    """Return normalized OS family: 'linux', 'windows', or 'darwin'."""
    system = platform.system().lower()
    if system == "linux":
        return "linux"
    elif system == "darwin":
        return "darwin"
    elif system == "windows":
        return "windows"
    return system


def is_root() -> bool:
    """Check if running as root/admin."""
    if get_os_family() == "windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0


def run_command(
    cmd: List[str],
    timeout: int = 30,
    check: bool = False,
    capture_stderr: bool = True,
) -> Tuple[int, str, str]:
    """Run a shell command safely and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, check=check,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        logger.warning("Command timed out: %s", " ".join(cmd))
        return -1, "", "Command timed out"
    except FileNotFoundError:
        logger.debug("Command not found: %s", cmd[0])
        return -1, "", f"Command not found: {cmd[0]}"
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout or "", e.stderr or ""
    except Exception as e:
        logger.warning("Command failed: %s — %s", " ".join(cmd), e)
        return -1, "", str(e)


def file_exists(path: str) -> bool:
    return os.path.isfile(path)


def read_file(path: str, max_size: int = 10 * 1024 * 1024) -> Optional[str]:
    """Read a file's content safely (max 10 MB by default)."""
    try:
        if os.path.getsize(path) > max_size:
            logger.debug("File too large, skipping: %s", path)
            return None
        with open(path, "r", errors="replace") as f:
            return f.read()
    except (OSError, PermissionError) as e:
        logger.debug("Cannot read file %s: %s", path, e)
        return None


def mask_secret(value: str, visible_chars: int = 4) -> str:
    """Mask a secret value, showing only first few characters."""
    if len(value) <= visible_chars:
        return "*" * len(value)
    return value[:visible_chars] + "*" * min(8, len(value) - visible_chars) + "..."
