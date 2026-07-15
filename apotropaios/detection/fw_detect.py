# ==============================================================================
# File:         apotropaios/detection/fw_detect.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Firewall application detection, version discovery, and status
# Description:  Detects installed firewall applications (firewalld, ipset,
#               iptables, nftables, ufw), retrieves their versions, and checks
#               their running/enabled status. Results are stored in a structured
#               FWDetectionResult dataclass containing per-backend detail.
#
#               Detection is non-destructive — only read-only operations are
#               performed (command existence, version queries, status checks).
#               All subprocess calls use list-form arguments (never shell=True),
#               capture stderr, and enforce timeouts.
#
# Notes:        - Requires apotropaios.core.constants (SUPPORTED_FIREWALLS, FW_INFO_BY_ID)
#               - All subprocess calls use list form with timeout (Lesson #2, #3)
#               - Version parsing handles varied output formats across distros
#               - ipset is always considered "running" if installed (kernel tool)
#               - Thread-safe: no shared mutable state
#               - Parity target: bash v1.1.10 lib/detection/fw_detect.sh
# Version:      1.2.1
# ==============================================================================

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Final

from apotropaios.core.constants import (
    FW_INFO_BY_ID,
    SUPPORTED_FIREWALLS,
    Color,
    FirewallInfo,
)

# Type alias for the internal logging callback
from typing import Protocol


class _LogCallback(Protocol):
    """Protocol for internal logging callbacks."""
    def __call__(self, level: str, msg: str, extra: str = "") -> None: ...


# Subprocess timeout for version/status queries
_CMD_TIMEOUT: Final[int] = 5


# ==============================================================================
# Per-Backend Detection Detail
# ==============================================================================

@dataclass
class FWBackendStatus:
    """Detection result for a single firewall backend.

    Attributes:
        fw_id:      Canonical backend name (e.g., 'iptables').
        installed:  Whether the binary was found on PATH.
        binary:     Full path to the binary, or empty if not found.
        version:    Detected version string, or 'unknown'.
        running:    Whether the backend is currently active/running.
        enabled:    Whether the backend is enabled at boot (systemd).
    """

    fw_id: str = ""
    installed: bool = False
    binary: str = ""
    version: str = "unknown"
    running: bool = False
    enabled: bool = False


# ==============================================================================
# Aggregate Detection Result
# ==============================================================================

@dataclass
class FWDetectionResult:
    """Aggregate result of firewall detection across all backends.

    Attributes:
        backends:  Dict mapping fw_id → FWBackendStatus for all probed backends.
        count:     Number of installed backends.
    """

    backends: dict[str, FWBackendStatus] = field(default_factory=dict)
    count: int = 0

    def get_installed(self) -> list[str]:
        """Return list of installed firewall IDs.

        Returns:
            List of fw_id strings for backends that are installed.
        """
        return [
            fw_id for fw_id, status in self.backends.items()
            if status.installed
        ]

    def get_running(self) -> list[str]:
        """Return list of running firewall IDs.

        Returns:
            List of fw_id strings for backends that are running.
        """
        return [
            fw_id for fw_id, status in self.backends.items()
            if status.running
        ]

    def is_installed(self, fw_id: str) -> bool:
        """Check if a specific firewall is installed.

        Args:
            fw_id: Firewall backend identifier.

        Returns:
            True if installed, False otherwise.
        """
        status = self.backends.get(fw_id)
        return status.installed if status is not None else False

    def is_running(self, fw_id: str) -> bool:
        """Check if a specific firewall is currently running.

        Args:
            fw_id: Firewall backend identifier.

        Returns:
            True if running, False otherwise.
        """
        status = self.backends.get(fw_id)
        return status.running if status is not None else False


# ==============================================================================
# Main Detection Function
# ==============================================================================

def detect_firewalls(
    log_fn: object | None = None,
) -> FWDetectionResult:
    """Detect all supported firewall applications.

    Scans for each of the 5 supported backends: checks binary existence,
    retrieves version, checks running state, and checks boot-enabled state.

    Args:
        log_fn: Optional logger object with .info(), .debug(), .warning()
                methods matching FrameworkLogger interface.

    Returns:
        FWDetectionResult with per-backend details.
    """
    def _log(level: str, msg: str, extra: str = "") -> None:
        if log_fn is not None:
            method = getattr(log_fn, level, None)
            if method is not None:
                method("fw_detect", msg, extra)

    _log("info", "Beginning firewall detection scan")

    result = FWDetectionResult()

    for fw_info in SUPPORTED_FIREWALLS:
        status = _detect_single(fw_info, _log)
        result.backends[fw_info.fw_id] = status
        if status.installed:
            result.count += 1

    _log("info", f"Firewall detection complete: {result.count} firewall(s) found")
    return result


def detect_single(
    fw_id: str,
    log_fn: object | None = None,
) -> FWBackendStatus:
    """Detect a specific firewall backend by ID.

    Args:
        fw_id:  Firewall identifier (e.g., 'iptables').
        log_fn: Optional logger object.

    Returns:
        FWBackendStatus for the requested backend.

    Raises:
        ValueError: If fw_id is not in SUPPORTED_FIREWALLS.
    """
    fw_info = FW_INFO_BY_ID.get(fw_id)
    if fw_info is None:
        raise ValueError(f"Unknown firewall: {fw_id}")

    def _log(level: str, msg: str, extra: str = "") -> None:
        if log_fn is not None:
            method = getattr(log_fn, level, None)
            if method is not None:
                method("fw_detect", msg, extra)

    return _detect_single(fw_info, _log)


# ==============================================================================
# Internal Detection Logic
# ==============================================================================

def _detect_single(
    fw_info: FirewallInfo,
    log: _LogCallback,
) -> FWBackendStatus:
    """Detect a single firewall application.

    Checks binary existence, version, running state, and boot-enabled state.

    Args:
        fw_info: FirewallInfo metadata for the backend.
        log:     Callable(level, msg, extra) for logging.

    Returns:
        FWBackendStatus with all fields populated.
    """
    status = FWBackendStatus(fw_id=fw_info.fw_id)

    log("debug", f"Checking for {fw_info.fw_id} (binary: {fw_info.binary})")

    # Check if binary exists on PATH
    binary_path = shutil.which(fw_info.binary)
    if binary_path is None:
        log("debug", f"{fw_info.fw_id}: not installed")
        return status

    status.installed = True
    status.binary = binary_path

    # Get version
    status.version = _get_version(fw_info.fw_id, binary_path)

    # Check running status (uses the resolved binary path, not a second
    # PATH lookup, so the status check exercises the same binary that was
    # detected)
    status.running = _check_running(fw_info.fw_id, status.installed, binary_path)

    # Check enabled at boot
    status.enabled = _check_enabled(fw_info.service)

    log(
        "info",
        f"{fw_info.fw_id}: installed (v{status.version}) "
        f"running={status.running} enabled={status.enabled} "
        f"path={binary_path}",
    )

    return status


# ==============================================================================
# Version Detection
# ==============================================================================

def _get_version(fw_id: str, binary_path: str) -> str:
    """Extract version string from a firewall binary's output.

    Each backend has a different version output format, so this function
    uses per-backend parsing logic.

    Args:
        fw_id:       Firewall identifier.
        binary_path: Absolute path to the binary.

    Returns:
        Version string, or 'unknown' if extraction fails.
    """
    version = "unknown"

    try:
        if fw_id == "firewalld":
            # firewall-cmd --version → "X.Y.Z"
            raw = _run_cmd([binary_path, "--version"])
            match = re.search(r'[0-9]+\.[0-9]+(\.[0-9]+)?', raw)
            if match:
                version = match.group()

        elif fw_id == "ipset":
            # ipset --version → "ipset vX.Y.Z, protocol version: N"
            raw = _run_cmd([binary_path, "--version"])
            match = re.search(r'v([0-9]+\.[0-9]+(\.[0-9]+)?)', raw)
            if match:
                version = match.group(1)

        elif fw_id == "iptables":
            # iptables --version → "iptables vX.Y.Z (..."
            raw = _run_cmd([binary_path, "--version"])
            match = re.search(r'v([0-9]+\.[0-9]+(\.[0-9]+)?)', raw)
            if match:
                version = match.group(1)

        elif fw_id == "nftables":
            # nft --version → "nftables vX.Y.Z (..."
            raw = _run_cmd([binary_path, "--version"])
            match = re.search(r'v([0-9]+\.[0-9]+(\.[0-9]+)?)', raw)
            if match:
                version = match.group(1)

        elif fw_id == "ufw":
            # ufw version → "ufw X.Y.Z" or ufw --version
            raw = _run_cmd([binary_path, "version"])
            if not raw:
                raw = _run_cmd([binary_path, "--version"])
            match = re.search(r'[0-9]+\.[0-9]+(\.[0-9]+)?', raw)
            if match:
                version = match.group()

    except Exception:
        pass  # Version extraction failure is non-fatal

    return version


# ==============================================================================
# Running Status Detection
# ==============================================================================

def _check_running(fw_id: str, installed: bool, binary_path: str = "") -> bool:
    """Check if a firewall service is currently running.

    Uses systemctl for systemd-managed services, with backend-specific
    fallback checks executed via the already-resolved binary path.

    Args:
        fw_id:       Firewall identifier.
        installed:   Whether the binary was found (for ipset logic).
        binary_path: Resolved absolute path to the backend binary.

    Returns:
        True if the backend is running/active.
    """
    has_systemctl = shutil.which("systemctl") is not None
    binary = binary_path or fw_id

    if fw_id == "firewalld":
        if has_systemctl:
            return _systemctl_is_active("firewalld")
        # Fallback: firewall-cmd --state
        raw = _run_cmd([binary, "--state"])
        return "running" in raw.lower()

    elif fw_id == "ipset":
        # ipset is a kernel-level tool — "running" whenever installed
        return installed

    elif fw_id == "iptables":
        # Kernel-level: check for /proc/net/ip_tables_names
        if os.path.exists("/proc/net/ip_tables_names"):
            return True
        # Fallback: try listing rules
        raw = _run_cmd([binary, "-L", "-n"])
        return "Chain" in raw

    elif fw_id == "nftables":
        if has_systemctl:
            return _systemctl_is_active("nftables")
        # Fallback: nft list ruleset
        raw = _run_cmd([binary, "list", "ruleset"])
        return len(raw) > 0

    elif fw_id == "ufw":
        raw = _run_cmd([binary, "status"])
        return "status: active" in raw.lower()

    return False


# ==============================================================================
# Boot-Enabled Detection
# ==============================================================================

def _check_enabled(service_name: str) -> bool:
    """Check if a firewall service is enabled at boot.

    Uses systemctl is-enabled for systemd-managed services.

    Args:
        service_name: Systemd service name (empty string if N/A).

    Returns:
        True if the service is enabled at boot.
    """
    if not service_name:
        return False

    if shutil.which("systemctl") is None:
        return False

    return _systemctl_is_enabled(service_name)


# ==============================================================================
# Subprocess Helpers
# ==============================================================================

def _run_cmd(args: list[str]) -> str:
    """Run a command and return its stdout.

    Uses list-form arguments (never shell=True), captures both stdout
    and stderr, and enforces a timeout.

    Args:
        args: Command and arguments as list.

    Returns:
        stdout output as string, or empty string on failure.
    """
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=_CMD_TIMEOUT,
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def _systemctl_is_active(service: str) -> bool:
    """Check if a systemd service is active.

    Args:
        service: Service name (e.g., 'firewalld').

    Returns:
        True if the service is active.
    """
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "--quiet", service],
            capture_output=True,
            timeout=_CMD_TIMEOUT,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _systemctl_is_enabled(service: str) -> bool:
    """Check if a systemd service is enabled at boot.

    Args:
        service: Service name (e.g., 'firewalld').

    Returns:
        True if the service is enabled.
    """
    try:
        result = subprocess.run(
            ["systemctl", "is-enabled", "--quiet", service],
            capture_output=True,
            timeout=_CMD_TIMEOUT,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


# ==============================================================================
# Display Function
# ==============================================================================

def print_fw_info(result: FWDetectionResult) -> None:
    """Print detected firewall information to stderr.

    Shows all 5 backends: installed ones with version/status, and
    not-installed ones with a dim indicator (per BUG-002 lesson:
    show ALL items for complete situational awareness).

    Args:
        result: Detection result to display.
    """
    from apotropaios.core.utils import print_separator

    sys.stderr.write(f"\n  {Color.BOLD}Detected Firewalls:{Color.RESET}\n")
    print_separator("─", 60)

    for fw_info in SUPPORTED_FIREWALLS:
        status = result.backends.get(fw_info.fw_id)
        if status is None:
            continue

        if status.installed:
            # Running status with color
            if status.running:
                status_color = Color.GREEN
                status_text = "running"
            else:
                status_color = Color.YELLOW
                status_text = "stopped"

            enabled_text = "(enabled)" if status.enabled else "(disabled)"

            sys.stderr.write(
                f"  {Color.BOLD}{fw_info.fw_id:<12s}{Color.RESET} "
                f"v{status.version:<10s} "
                f"[{status_color}{status_text:<7s}{Color.RESET}] "
                f"{enabled_text}\n"
            )
        else:
            sys.stderr.write(
                f"  {Color.DIM}{fw_info.fw_id:<12s}{Color.RESET} "
                f"{'':12s} "
                f"[{Color.DIM}{'not installed':<13s}{Color.RESET}]\n"
            )
