# ==============================================================================
# File:         apotropaios/backup/backup.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Firewall configuration backup and restore point management
# Description:  Creates timestamped compressed tar.gz archives of firewall
#               configurations, rule index, rule state, and a JSON manifest.
#               Supports per-backend and full system backups with SHA-256
#               checksums and configurable retention management.
#
# Notes:        - Backups stored as .tar.gz with .sha256 sidecar
#               - Pre-change restore points enable safe rollback
#               - Staging dir pattern avoids partial archive writes
#               - Retention enforced after each backup creation
#               - Parity target: bash v1.1.10 lib/backup/backup.sh
# Version:      1.2.1
# ==============================================================================

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

from apotropaios.core.constants import (
    VERSION,
    Backup,
    Color,
    Performance,
    Security,
    SUPPORTED_FIREWALLS,
)
from apotropaios.core.errors import BackupError
from apotropaios.core.security import file_checksum, secure_dir
from apotropaios.core.utils import (
    human_bytes,
    timestamp,
    timestamp_filename,
)

_log_fn: object | None = None
_backup_dir: str = ""
_rules_dir: str = ""
_last_backup_file: str = ""


def _log(level: str, msg: str) -> None:
    if _log_fn is not None:
        method = getattr(_log_fn, level, None)
        if method is not None:
            method("backup", msg)


def init_backup(
    backup_dir: str,
    logger: object | None = None,
    rules_dir: str = "",
) -> None:
    """Initialize the backup subsystem.

    Args:
        backup_dir: Path to the backup directory.
        logger:     Optional FrameworkLogger instance.
        rules_dir:  Default rules directory. Backup and restore operations
                    that do not receive an explicit rules_dir fall back to
                    this value, so every entry path (CLI, menu, restore
                    points) includes the rule index and state files.
    """
    global _log_fn, _backup_dir, _rules_dir
    _log_fn = logger
    secure_dir(backup_dir)
    _backup_dir = backup_dir
    _rules_dir = rules_dir
    _log("info", f"Backup subsystem initialized: {backup_dir}")


def get_default_rules_dir() -> str:
    """Return the default rules directory recorded at initialization.

    Returns:
        Rules directory path, or empty string if not configured.
    """
    return _rules_dir


def create_backup(
    label: str = "manual",
    backend: str = "all",
    rules_dir: str = "",
) -> str:
    """Create a backup of current firewall configuration.

    Args:
        label:     Backup label/description.
        backend:   Specific backend or "all" for all installed.
        rules_dir: Path to the rules directory (for index/state files).

    Returns:
        Path to the created backup archive.

    Raises:
        BackupError: If backup creation fails.
    """
    global _last_backup_file

    if not _backup_dir:
        raise BackupError("Backup subsystem not initialized")

    # Fall back to the initialization-time rules directory so callers that
    # omit rules_dir (menu paths, restore points) still capture the index
    # and state files
    if not rules_dir:
        rules_dir = _rules_dir

    ts = timestamp_filename()
    safe_label = "".join(c for c in label if c.isalnum() or c in "-_")
    backup_name = f"{Backup.PREFIX}_{safe_label}_{ts}"
    staging_dir = os.path.join(_backup_dir, f".staging_{backup_name}")
    backup_file = os.path.join(_backup_dir, f"{backup_name}{Backup.EXTENSION}")

    # Create staging directory
    try:
        os.makedirs(staging_dir, mode=Security.DIR_PERMS, exist_ok=True)
    except OSError as exc:
        raise BackupError(f"Failed to create staging directory: {exc}") from exc

    _log("info", f"Creating backup: {backup_name} (backend={backend})")

    # Export firewall configurations
    if backend == "all":
        _export_all(staging_dir)
    else:
        _export_single(staging_dir, backend)

    # Copy rule index and state files
    if rules_dir:
        for fname in ("rule_index.dat", "rule_state.dat"):
            src = os.path.join(rules_dir, fname)
            if os.path.isfile(src):
                try:
                    shutil.copy2(src, os.path.join(staging_dir, fname))
                except OSError:
                    pass

    # Write JSON manifest
    manifest = {
        "name": backup_name,
        "timestamp": timestamp(),
        "label": label,
        "backend": backend,
        "version": VERSION,
    }
    manifest_path = os.path.join(staging_dir, Backup.MANIFEST_FILE)
    try:
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
    except OSError:
        pass

    # Create compressed archive
    try:
        with tarfile.open(backup_file, "w:gz") as tar:
            tar.add(staging_dir, arcname=f".staging_{backup_name}")
    except (OSError, tarfile.TarError) as exc:
        shutil.rmtree(staging_dir, ignore_errors=True)
        raise BackupError(f"Failed to create archive: {exc}") from exc

    # Generate checksum sidecar
    try:
        checksum = file_checksum(backup_file)
        with open(f"{backup_file}.sha256", "w", encoding="utf-8") as f:
            f.write(f"{checksum}  {os.path.basename(backup_file)}\n")
    except Exception:
        pass

    # Cleanup staging
    shutil.rmtree(staging_dir, ignore_errors=True)

    # Set permissions
    try:
        os.chmod(backup_file, Security.FILE_PERMS)
    except OSError:
        pass

    # Enforce retention
    _enforce_retention()

    _last_backup_file = backup_file
    _log("info", f"Backup created: {backup_file}")
    return backup_file


def create_restore_point(description: str = "pre-change") -> str:
    """Create a restore point before making changes.

    Args:
        description: Description of the pending change.

    Returns:
        Path to the restore point backup.
    """
    safe_desc = "".join(c for c in description if c.isalnum() or c in "-_")
    return create_backup(f"restore_{safe_desc}")


def list_backups() -> str:
    """List available backups.

    Returns:
        Formatted string listing all backups.
    """
    if not _backup_dir:
        return "  Backup subsystem not initialized"

    backups = sorted(
        Path(_backup_dir).glob(f"{Backup.PREFIX}_*{Backup.EXTENSION}"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    if not backups:
        return f"  {Color.YELLOW}No backups found{Color.RESET}"

    lines: list[str] = []
    lines.append(f"\n  {Color.BOLD}Available Backups ({len(backups)}):{Color.RESET}")
    lines.append(f"  {'─' * 80}")

    for i, bpath in enumerate(backups, 1):
        try:
            size = bpath.stat().st_size
        except OSError:
            size = 0
        lines.append(
            f"  {Color.BOLD}{i:2d}.{Color.RESET} {bpath.name:<55s} {human_bytes(size)}"
        )

    return "\n".join(lines)


def get_last_backup() -> str:
    """Return path to the most recently created backup."""
    return _last_backup_file


# --- Internal helpers ---

def _export_all(staging: str) -> None:
    """Export all detected firewall configurations."""
    for fw_info in SUPPORTED_FIREWALLS:
        if shutil.which(fw_info.binary):
            _export_single(staging, fw_info.fw_id)


def _export_single(staging: str, fw_name: str) -> None:
    """Export a single firewall's configuration."""
    output = os.path.join(staging, f"{fw_name}.conf")
    _CMD_T = Performance.SUBPROCESS_TIMEOUT
    try:
        if fw_name == "iptables" and shutil.which("iptables-save"):
            result = subprocess.run(["iptables-save"], capture_output=True, text=True, timeout=_CMD_T)
            if result.stdout:
                with open(output, "w", encoding="utf-8") as f:
                    f.write(result.stdout)
        elif fw_name == "nftables" and shutil.which("nft"):
            result = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True, timeout=_CMD_T)
            if result.stdout:
                with open(output, "w", encoding="utf-8") as f:
                    f.write(result.stdout)
        elif fw_name == "firewalld" and shutil.which("firewall-cmd"):
            # Save human-readable text dump for reference
            result = subprocess.run(["firewall-cmd", "--list-all-zones"], capture_output=True, text=True, timeout=_CMD_T)
            if result.stdout:
                with open(output, "w", encoding="utf-8") as f:
                    f.write(result.stdout)
            # Ensure runtime config is saved to permanent XML files
            subprocess.run(
                ["firewall-cmd", "--runtime-to-permanent"],
                capture_output=True, text=True, timeout=_CMD_T,
            )
            # Copy zone XML files for machine-restorable backup
            firewalld_zones_src = "/etc/firewalld/zones"
            if os.path.isdir(firewalld_zones_src):
                firewalld_zones_dst = os.path.join(staging, "firewalld_zones")
                try:
                    shutil.copytree(firewalld_zones_src, firewalld_zones_dst)
                    _log("debug", f"Backed up firewalld zones from {firewalld_zones_src}")
                except OSError as exc:
                    _log("warning", f"Failed to copy firewalld zone files: {exc}")
        elif fw_name == "ufw" and shutil.which("ufw"):
            # Human-readable status dump for reference
            result = subprocess.run(["ufw", "status", "numbered", "verbose"], capture_output=True, text=True, timeout=_CMD_T)
            if result.stdout:
                with open(output, "w", encoding="utf-8") as f:
                    f.write(result.stdout)
            # Machine-restorable configuration: copy /etc/ufw into the
            # archive as ufw_etc. The status text alone is not restorable —
            # restore looks for ufw_etc (save→load round-trip contract).
            ufw_etc_src = "/etc/ufw"
            if os.path.isdir(ufw_etc_src):
                ufw_etc_dst = os.path.join(staging, "ufw_etc")
                try:
                    shutil.copytree(ufw_etc_src, ufw_etc_dst)
                    _log("debug", f"Backed up ufw configuration from {ufw_etc_src}")
                except OSError as exc:
                    _log("warning", f"Failed to copy ufw configuration: {exc}")
        elif fw_name == "ipset" and shutil.which("ipset"):
            result = subprocess.run(["ipset", "save"], capture_output=True, text=True, timeout=_CMD_T)
            if result.stdout:
                with open(output, "w", encoding="utf-8") as f:
                    f.write(result.stdout)
    except (subprocess.TimeoutExpired, OSError):
        pass

    if os.path.isfile(output):
        try:
            os.chmod(output, Security.FILE_PERMS)
        except OSError:
            pass


def _enforce_retention() -> None:
    """Remove old backups beyond the retention limit."""
    if not _backup_dir:
        return

    backups = sorted(
        Path(_backup_dir).glob(f"{Backup.PREFIX}_*{Backup.EXTENSION}"),
        key=lambda p: p.stat().st_mtime,
    )

    if len(backups) > Backup.MAX_RETAINED:
        excess = len(backups) - Backup.MAX_RETAINED
        _log("debug", f"Removing {excess} old backup(s) (retention: {Backup.MAX_RETAINED})")
        for old in backups[:excess]:
            try:
                old.unlink()
                sha = Path(f"{old}.sha256")
                if sha.exists():
                    sha.unlink()
            except OSError:
                pass
