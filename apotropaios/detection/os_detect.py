# ==============================================================================
# File:         apotropaios/detection/os_detect.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Secure operating system detection and identification
# Description:  Detects the running operating system by parsing /etc/os-release
#               and other system identification files. Validates against the
#               supported OS list. Determines package manager and OS family.
#               Uses multiple fallback detection methods for robustness:
#                 1. /etc/os-release (preferred — standard across modern Linux)
#                 2. /etc/lsb-release (Ubuntu/Debian fallback)
#                 3. /etc/redhat-release (RHEL family fallback)
#                 4. platform.uname() (minimal fallback)
#
#               Results are stored in an OSDetectionResult dataclass for clean
#               data passing (replaces bash's global variables pattern).
#
# Notes:        - Requires apotropaios.core.constants (SUPPORTED_OS, OS_FAMILY_MAP)
#               - Detection is non-destructive (read-only operations)
#               - All file reads validate content size before use (security)
#               - Supports: Ubuntu, Kali, Debian 12, Rocky 9, AlmaLinux 9, Arch
#               - Thread-safe: no shared mutable state
#               - Parity target: bash v1.1.10 lib/detection/os_detect.sh
# Version:      1.2.1
# ==============================================================================

from __future__ import annotations

import os
import platform
import re
import shutil
from dataclasses import dataclass
from typing import Final

from apotropaios.core.constants import (
    SUPPORTED_OS_IDS,
    Color,
)

# Maximum file size for /etc/os-release (security — reject abnormally large files)
_MAX_RELEASE_FILE_SIZE: Final[int] = 4096


# ==============================================================================
# Detection Result
# ==============================================================================

@dataclass
class OSDetectionResult:
    """Result of operating system detection.

    Attributes:
        os_id:       Canonical lowercase identifier (e.g., 'ubuntu', 'rocky').
        name:        Human-readable OS name (e.g., 'Ubuntu 22.04 LTS').
        version:     Full version string (e.g., '22.04.3 LTS').
        version_id:  Short version ID (e.g., '22.04', '9').
        family:      OS family ('debian', 'rhel', 'arch', 'unknown').
        pkg_manager: Package manager command ('apt', 'dnf', 'pacman', 'unknown').
        supported:   Whether the OS is in the supported list.
        id_like:     ID_LIKE field from os-release (for derivative detection).
        method:      Detection method used ('os-release', 'lsb-release', etc.).
    """

    os_id: str = ""
    name: str = ""
    version: str = "unknown"
    version_id: str = "unknown"
    family: str = "unknown"
    pkg_manager: str = "unknown"
    supported: bool = False
    id_like: str = ""
    method: str = ""


# ==============================================================================
# Main Detection Function
# ==============================================================================

def detect_os(
    log_fn: object | None = None,
) -> OSDetectionResult:
    """Perform operating system detection using multiple methods.

    Tries detection methods in order of reliability:
    1. /etc/os-release (modern standard)
    2. /etc/lsb-release (Ubuntu/Debian)
    3. /etc/redhat-release (RHEL family)
    4. platform.uname() (minimal fallback)

    After detection, determines OS family and package manager, and
    checks against the supported OS list.

    Args:
        log_fn: Optional logger object with .info(), .debug(), .warning()
                methods matching FrameworkLogger interface.

    Returns:
        OSDetectionResult with all fields populated.
    """
    def _log(level: str, msg: str, extra: str = "") -> None:
        if log_fn is not None:
            method = getattr(log_fn, level, None)
            if method is not None:
                method("os_detect", msg, extra)

    _log("info", "Beginning operating system detection")

    result = OSDetectionResult()

    # Try detection methods in priority order
    if _detect_os_release(result):
        result.method = "os-release"
        _log("info", f"OS detected via /etc/os-release: {result.name} ({result.os_id})")
    elif _detect_lsb_release(result):
        result.method = "lsb-release"
        _log("info", f"OS detected via /etc/lsb-release: {result.name} ({result.os_id})")
    elif _detect_redhat_release(result):
        result.method = "redhat-release"
        _log("info", f"OS detected via /etc/redhat-release: {result.name} ({result.os_id})")
    elif _detect_uname(result):
        result.method = "uname"
        _log("info", f"OS detected via uname: {result.name} ({result.os_id})")
    else:
        _log("error", "Unable to detect operating system")
        result.os_id = "unknown"
        result.name = "Unknown"
        result.method = "none"

    # Determine family and package manager
    _determine_family(result)

    # Check supported status
    result.supported = result.os_id in SUPPORTED_OS_IDS

    _log(
        "info",
        "Detection complete",
        f"id={result.os_id} version={result.version} "
        f"family={result.family} pkg={result.pkg_manager} "
        f"supported={result.supported}",
    )

    if not result.supported:
        _log("warning", f"Operating system '{result.name}' is not in the supported list")

    return result


# ==============================================================================
# Detection Method 1: /etc/os-release
# ==============================================================================

def _detect_os_release(result: OSDetectionResult) -> bool:
    """Parse /etc/os-release for OS identification.

    This is the preferred detection method (standard across modern Linux).
    Parses KEY=VALUE format without eval for security.

    Args:
        result: OSDetectionResult to populate.

    Returns:
        True if successfully parsed, False if file missing/unreadable.
    """
    release_file = "/etc/os-release"

    if not os.path.isfile(release_file) or not os.access(release_file, os.R_OK):
        return False

    # Validate file size (security — reject abnormally large files)
    try:
        file_size = os.path.getsize(release_file)
        if file_size > _MAX_RELEASE_FILE_SIZE:
            return False
    except OSError:
        return False

    # Parse KEY=VALUE fields safely (no eval of arbitrary content)
    fields: dict[str, str] = {}
    try:
        with open(release_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, _, value = line.partition("=")
                # Remove surrounding quotes (double or single)
                value = value.strip()
                if len(value) >= 2:
                    if (value[0] == '"' and value[-1] == '"') or \
                       (value[0] == "'" and value[-1] == "'"):
                        value = value[1:-1]
                fields[key.strip()] = value
    except OSError:
        return False

    os_id = fields.get("ID", "").lower()
    if not os_id:
        return False

    # Normalize known OS IDs
    id_like = fields.get("ID_LIKE", "").lower()
    result.id_like = id_like

    if os_id in ("arch", "archlinux"):
        result.os_id = "arch"
    elif os_id in SUPPORTED_OS_IDS:
        result.os_id = os_id
    else:
        # Check ID_LIKE for derivative distributions
        result.os_id = os_id
        if "debian" in id_like or "ubuntu" in id_like:
            result.family = "debian"
        elif "rhel" in id_like or "centos" in id_like or "fedora" in id_like:
            result.family = "rhel"

    result.name = fields.get("NAME", os_id)
    result.version = fields.get("VERSION", "unknown")
    result.version_id = fields.get("VERSION_ID", "unknown")

    return True


# ==============================================================================
# Detection Method 2: /etc/lsb-release
# ==============================================================================

def _detect_lsb_release(result: OSDetectionResult) -> bool:
    """Parse /etc/lsb-release for OS identification (Ubuntu/Debian fallback).

    Args:
        result: OSDetectionResult to populate.

    Returns:
        True if successfully parsed, False if not available.
    """
    release_file = "/etc/lsb-release"

    if not os.path.isfile(release_file) or not os.access(release_file, os.R_OK):
        return False

    fields: dict[str, str] = {}
    try:
        with open(release_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                value = value.strip().strip('"').strip("'")
                fields[key.strip()] = value
    except OSError:
        return False

    distrib_id = fields.get("DISTRIB_ID", "").lower()
    if not distrib_id:
        return False

    result.os_id = distrib_id
    result.name = fields.get("DISTRIB_DESCRIPTION", distrib_id)
    result.version = fields.get("DISTRIB_RELEASE", "unknown")
    result.version_id = result.version

    return True


# ==============================================================================
# Detection Method 3: /etc/redhat-release
# ==============================================================================

def _detect_redhat_release(result: OSDetectionResult) -> bool:
    """Parse /etc/redhat-release for OS identification (RHEL family).

    Args:
        result: OSDetectionResult to populate.

    Returns:
        True if successfully parsed, False if not available.
    """
    release_file = "/etc/redhat-release"

    if not os.path.isfile(release_file) or not os.access(release_file, os.R_OK):
        return False

    try:
        with open(release_file, "r", encoding="utf-8", errors="replace") as f:
            content = f.readline().strip()
    except OSError:
        return False

    if not content:
        return False

    lower = content.lower()

    if "rocky" in lower:
        result.os_id = "rocky"
    elif "alma" in lower:
        result.os_id = "almalinux"
    elif "centos" in lower:
        result.os_id = "centos"
    elif "red hat" in lower:
        result.os_id = "rhel"
    else:
        result.os_id = "rhel_unknown"

    result.name = content

    # Extract version number
    version_match = re.search(r'[0-9]+\.[0-9]+', content)
    if version_match:
        result.version = version_match.group()
        result.version_id = result.version.split(".")[0]
    else:
        result.version = "unknown"
        result.version_id = "unknown"

    return True


# ==============================================================================
# Detection Method 4: platform.uname() fallback
# ==============================================================================

def _detect_uname(result: OSDetectionResult) -> bool:
    """Fallback detection using Python's platform module.

    Args:
        result: OSDetectionResult to populate.

    Returns:
        True if basic detection succeeds.
    """
    uname = platform.uname()

    if uname.system != "Linux":
        result.os_id = "unknown"
        result.name = uname.system
        result.version = uname.release
        result.version_id = "unknown"
        return True

    result.os_id = "linux_unknown"
    result.name = "Linux (unknown distribution)"
    result.version = uname.release
    result.version_id = "unknown"

    return True


# ==============================================================================
# Family and Package Manager Determination
# ==============================================================================

def _determine_family(result: OSDetectionResult) -> None:
    """Determine OS family and package manager from detected OS ID.

    Uses a local ID-to-(family, package manager) map for known IDs, then
    the ID_LIKE-derived family, then falls back to probing for available
    package manager binaries on the system.

    Args:
        result: OSDetectionResult to update (family and pkg_manager fields).
    """
    # Skip if family already set by detection (e.g., derivative via ID_LIKE)
    if result.family != "unknown" and result.pkg_manager != "unknown":
        return

    # Map known IDs to families
    os_id = result.os_id
    family_map: dict[str, tuple[str, str]] = {
        "ubuntu":       ("debian", "apt"),
        "kali":         ("debian", "apt"),
        "debian":       ("debian", "apt"),
        "rocky":        ("rhel",   "dnf"),
        "almalinux":    ("rhel",   "dnf"),
        "centos":       ("rhel",   "dnf"),
        "rhel":         ("rhel",   "dnf"),
        "rhel_unknown": ("rhel",   "dnf"),
        "arch":         ("arch",   "pacman"),
        "archlinux":    ("arch",   "pacman"),
    }

    if os_id in family_map:
        result.family, result.pkg_manager = family_map[os_id]
        return

    # Fallback: check for ID_LIKE-based family (already set by os-release parser)
    if result.family != "unknown":
        pkg_map = {"debian": "apt", "rhel": "dnf", "arch": "pacman"}
        result.pkg_manager = pkg_map.get(result.family, "unknown")
        return

    # Last resort: detect by available package manager binaries
    if shutil.which("apt-get"):
        result.family = "debian"
        result.pkg_manager = "apt"
    elif shutil.which("dnf"):
        result.family = "rhel"
        result.pkg_manager = "dnf"
    elif shutil.which("pacman"):
        result.family = "arch"
        result.pkg_manager = "pacman"
    else:
        result.family = "unknown"
        result.pkg_manager = "unknown"


# ==============================================================================
# Display Functions
# ==============================================================================

def print_os_info(result: OSDetectionResult) -> None:
    """Print detected OS information to stderr.

    Args:
        result: Detection result to display.
    """
    from apotropaios.core.utils import print_kv
    print_kv("OS ID", result.os_id)
    print_kv("OS Name", result.name)
    print_kv("OS Version", result.version)
    print_kv("OS Family", result.family)
    print_kv("Package Manager", result.pkg_manager)

    supported_str = f"{Color.GREEN}Yes{Color.RESET}" if result.supported \
        else f"{Color.RED}No{Color.RESET}"
    print_kv("Supported", supported_str)
