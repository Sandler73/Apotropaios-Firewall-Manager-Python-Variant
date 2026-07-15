# ==============================================================================
# File:         apotropaios/install/installer.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Firewall package installation and update management
# Description:  Handles installation and update of firewall packages across
#               supported Linux distributions using the detected package manager
#               (apt, dnf, pacman). Creates restore points before operations
#               and validates installation success after completion.
#
# Notes:        - Requires root privileges for all operations
#               - Creates restore point before install/update
#               - Validates installation by re-detecting the firewall
#               - Supports apt (Debian family), dnf (RHEL family), pacman (Arch)
#               - --allowerasing for dnf (Lesson: RHEL container package conflicts)
#               - Parity target: bash v1.1.10 lib/install/installer.sh
# Version:      1.2.1
# ==============================================================================

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Final

from apotropaios.core.constants import (
    FW_INFO_BY_ID,
    SUPPORTED_FW_IDS,
    Performance,
)
from apotropaios.core.errors import (
    FirewallInstallError,
    FirewallNotFoundError,
    PermissionError_,
)
from apotropaios.core.security import is_root

_log_fn: object | None = None

# Package operations (download + install) routinely exceed the default
# 30-second subprocess timeout; they use the long operation budget instead.
_CMD_T: Final[int] = Performance.OPERATION_TIMEOUT_SECONDS


def _log(level: str, msg: str) -> None:
    if _log_fn is not None:
        method = getattr(_log_fn, level, None)
        if method is not None:
            method("installer", msg)


def set_logger(logger: object) -> None:
    """Set the logger for the installer."""
    global _log_fn
    _log_fn = logger


def install_firewall(
    fw_name: str,
    pkg_manager: str = "",
    os_id: str = "",
) -> None:
    """Install a firewall package.

    Args:
        fw_name:     Firewall name from SUPPORTED_FW_IDS.
        pkg_manager: Package manager to use (auto-detected if empty).
        os_id:       OS identifier (for package name resolution).

    Raises:
        FirewallInstallError: If installation fails.
        FirewallNotFoundError: If fw_name is not supported.
        PermissionError_: If not running as root.
    """
    if fw_name not in SUPPORTED_FW_IDS:
        raise FirewallNotFoundError(f"Unsupported firewall: {fw_name}")

    if not is_root():
        raise PermissionError_("Root privileges required for installation")

    fw_info = FW_INFO_BY_ID[fw_name]

    # Check if already installed
    if shutil.which(fw_info.binary):
        _log("info", f"{fw_name} is already installed")
        return

    # Create restore point
    try:
        from apotropaios.backup.backup import create_restore_point
        create_restore_point(f"pre_install_{fw_name}")
    except Exception:
        pass

    # Determine package name
    pkg_name = fw_info.packages.get(pkg_manager, "")
    if not pkg_name:
        # Try all known managers
        for mgr in ("apt", "dnf", "pacman"):
            if shutil.which(mgr if mgr != "apt" else "apt-get"):
                pkg_name = fw_info.packages.get(mgr, "")
                pkg_manager = mgr
                break

    if not pkg_name:
        raise FirewallInstallError(
            f"Cannot determine package name for {fw_name}",
            backend=fw_name,
        )

    _log("info", f"Installing {fw_name} (package: {pkg_name}) via {pkg_manager}")

    # Install
    try:
        if pkg_manager == "apt":
            _apt_install(pkg_name)
        elif pkg_manager == "dnf":
            _dnf_install(pkg_name)
        elif pkg_manager == "pacman":
            _pacman_install(pkg_name)
        else:
            raise FirewallInstallError(f"Unsupported package manager: {pkg_manager}")
    except subprocess.CalledProcessError as exc:
        raise FirewallInstallError(f"Failed to install {fw_name}: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise FirewallInstallError(
            f"Installation of {fw_name} timed out after {_CMD_T}s",
        ) from exc

    # Verify installation
    if not shutil.which(fw_info.binary):
        raise FirewallInstallError(
            f"Installation verification failed: {fw_name} not detected after install",
            backend=fw_name,
        )

    _log("info", f"{fw_name} installed successfully")


def update_firewall(
    fw_name: str,
    pkg_manager: str = "",
) -> None:
    """Update a firewall package to latest version.

    Args:
        fw_name:     Firewall name from SUPPORTED_FW_IDS.
        pkg_manager: Package manager to use.

    Raises:
        FirewallInstallError: If update fails.
        FirewallNotFoundError: If fw_name is not installed.
        PermissionError_: If not running as root.
    """
    if fw_name not in SUPPORTED_FW_IDS:
        raise FirewallNotFoundError(f"Unsupported firewall: {fw_name}")

    if not is_root():
        raise PermissionError_("Root privileges required for update")

    fw_info = FW_INFO_BY_ID[fw_name]

    if not shutil.which(fw_info.binary):
        raise FirewallNotFoundError(f"{fw_name} is not installed")

    # Create restore point
    try:
        from apotropaios.backup.backup import create_restore_point
        create_restore_point(f"pre_update_{fw_name}")
    except Exception:
        pass

    pkg_name = fw_info.packages.get(pkg_manager, "")
    if not pkg_name:
        for mgr in ("apt", "dnf", "pacman"):
            if shutil.which(mgr if mgr != "apt" else "apt-get"):
                pkg_name = fw_info.packages.get(mgr, "")
                pkg_manager = mgr
                break

    if not pkg_name:
        raise FirewallInstallError(f"Cannot determine package for {fw_name}")

    _log("info", f"Updating {fw_name} (package: {pkg_name})")

    try:
        if pkg_manager == "apt":
            _apt_update(pkg_name)
        elif pkg_manager == "dnf":
            _dnf_update(pkg_name)
        elif pkg_manager == "pacman":
            _pacman_update(pkg_name)
        else:
            raise FirewallInstallError(f"Unsupported package manager: {pkg_manager}")
    except subprocess.CalledProcessError as exc:
        raise FirewallInstallError(f"Failed to update {fw_name}: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise FirewallInstallError(
            f"Update of {fw_name} timed out after {_CMD_T}s",
        ) from exc

    _log("info", f"{fw_name} updated successfully")


# --- Package manager operations ---

def _apt_install(pkg: str) -> None:
    """Install a package via apt."""
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    subprocess.run(
        ["apt-get", "update", "-qq"],
        capture_output=True, timeout=_CMD_T, env=env,
    )
    subprocess.run(
        ["apt-get", "install", "-y", "-qq", pkg],
        capture_output=True, timeout=_CMD_T, env=env, check=True,
    )


def _dnf_install(pkg: str) -> None:
    """Install a package via dnf (with --allowerasing for RHEL compat)."""
    subprocess.run(
        ["dnf", "install", "-y", "--allowerasing", pkg],
        capture_output=True, timeout=_CMD_T, check=True,
    )


def _pacman_install(pkg: str) -> None:
    """Install a package via pacman."""
    subprocess.run(
        ["pacman", "-Sy", "--noconfirm", pkg],
        capture_output=True, timeout=_CMD_T, check=True,
    )


def _apt_update(pkg: str) -> None:
    """Update a package via apt."""
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    subprocess.run(
        ["apt-get", "update", "-qq"],
        capture_output=True, timeout=_CMD_T, env=env,
    )
    subprocess.run(
        ["apt-get", "upgrade", "-y", "-qq", pkg],
        capture_output=True, timeout=_CMD_T, env=env, check=True,
    )


def _dnf_update(pkg: str) -> None:
    """Update a package via dnf."""
    subprocess.run(
        ["dnf", "update", "-y", pkg],
        capture_output=True, timeout=_CMD_T, check=True,
    )


def _pacman_update(pkg: str) -> None:
    """Update a package via pacman."""
    subprocess.run(
        ["pacman", "-Syu", "--noconfirm", pkg],
        capture_output=True, timeout=_CMD_T, check=True,
    )
