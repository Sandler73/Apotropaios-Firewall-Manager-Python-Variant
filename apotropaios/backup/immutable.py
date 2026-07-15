# ==============================================================================
# File:         apotropaios/backup/immutable.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Immutable snapshot management for system recovery
# Description:  Creates and manages immutable snapshots of firewall state that
#               cannot be modified after creation. Uses filesystem immutable
#               attribute (chattr +i) where available, with SHA-256 checksum-based
#               integrity verification as fallback/complement.
#
#               Verify returns 3 codes:
#               - 0: all snapshots pass integrity check
#               - 1: at least one integrity failure
#               - 2: no snapshots exist (Lesson #15: explicit empty state)
#
# Notes:        - chattr +i requires root and ext2/3/4/btrfs filesystem
#               - Falls back to checksum verification on unsupported FS
#               - Snapshots include all firewall configs + rule index
#               - "No immutable snapshots exist" when count is 0 (Lesson #15)
#               - Parity target: bash v1.1.10 lib/backup/immutable.sh
# Version:      1.2.1
# ==============================================================================

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from apotropaios.core.constants import (
    Backup,
    Color,
    Performance,
    Security,
)
from apotropaios.core.errors import BackupError
from apotropaios.core.security import file_checksum, secure_dir, verify_checksum
from apotropaios.core.utils import human_bytes

_log_fn: object | None = None


def _log(level: str, msg: str) -> None:
    if _log_fn is not None:
        method = getattr(_log_fn, level, None)
        if method is not None:
            method("immutable", msg)


def _get_immutable_dir(backup_dir: str) -> str:
    """Return the immutable snapshots subdirectory path."""
    return os.path.join(backup_dir, "immutable")


def create_snapshot(
    backup_dir: str,
    label: str = "snapshot",
    rules_dir: str = "",
) -> str:
    """Create an immutable snapshot of current firewall state.

    Creates a backup, copies it to the immutable directory, generates
    an integrity checksum file, and attempts to set the chattr +i
    immutable attribute.

    Args:
        backup_dir: Path to the backup directory.
        label:      Snapshot label.
        rules_dir:  Path to rules directory (for index/state files).

    Returns:
        Path to the immutable snapshot file.

    Raises:
        BackupError: If snapshot creation fails.
    """
    if not backup_dir:
        raise BackupError("Backup subsystem not initialized")

    immutable_dir = _get_immutable_dir(backup_dir)
    secure_dir(immutable_dir)

    # Create a backup first
    from apotropaios.backup.backup import create_backup, get_last_backup
    create_backup(f"immutable_{label}", rules_dir=rules_dir)
    backup_file = get_last_backup()

    if not backup_file or not os.path.isfile(backup_file):
        raise BackupError("No backup file available for immutable snapshot")

    # Copy to immutable directory
    snapshot_name = os.path.basename(backup_file)
    immutable_file = os.path.join(immutable_dir, snapshot_name)

    try:
        shutil.copy2(backup_file, immutable_file)
        # Copy checksum sidecar if exists
        sha_src = f"{backup_file}.sha256"
        if os.path.isfile(sha_src):
            shutil.copy2(sha_src, f"{immutable_file}.sha256")
    except OSError as exc:
        raise BackupError(f"Failed to copy to immutable directory: {exc}") from exc

    # Generate integrity checksum file
    try:
        checksum = file_checksum(immutable_file)
        integrity_path = f"{immutable_file}.integrity"
        with open(integrity_path, "w", encoding="utf-8") as f:
            f.write(f"{checksum}  {snapshot_name}\n")
    except Exception:
        pass

    # Try to set immutable attribute (chattr +i)
    if shutil.which("chattr"):
        for fpath in (immutable_file, f"{immutable_file}.sha256", f"{immutable_file}.integrity"):
            if os.path.isfile(fpath):
                result = subprocess.run(
                    ["chattr", "+i", fpath],
                    capture_output=True, timeout=Performance.SUBPROCESS_TIMEOUT,
                )
                if result.returncode == 0:
                    _log("info", f"Immutable attribute set on {os.path.basename(fpath)}")
                else:
                    _log("warning", "Cannot set immutable attribute (filesystem may not support it)")

    try:
        os.chmod(immutable_file, Security.FILE_PERMS)
    except OSError:
        pass

    _log("info", f"Immutable snapshot created: {immutable_file}")
    return immutable_file


def verify_snapshots(backup_dir: str) -> int:
    """Verify integrity of all immutable snapshots.

    Returns:
        0 if all pass, 1 if any fail, 2 if no snapshots exist (Lesson #15).
    """
    immutable_dir = _get_immutable_dir(backup_dir)

    if not os.path.isdir(immutable_dir):
        return 2

    # Find all integrity files
    integrity_files = list(Path(immutable_dir).glob("*.integrity"))

    if not integrity_files:
        return 2

    failed = 0
    checked = 0

    for integrity_file in integrity_files:
        snapshot_file = str(integrity_file).removesuffix(".integrity")
        try:
            with open(integrity_file, "r", encoding="utf-8") as f:
                expected = f.read().strip().split()[0]
        except (OSError, IndexError):
            continue

        if not expected:
            continue

        if not os.path.isfile(snapshot_file):
            _log("error", f"Snapshot missing: {snapshot_file}")
            failed += 1
            continue

        checked += 1
        try:
            verify_checksum(snapshot_file, expected)
            _log("debug", f"Verified: {os.path.basename(snapshot_file)}")
        except Exception:
            _log("error", f"INTEGRITY FAILURE: {os.path.basename(snapshot_file)}")
            failed += 1

    _log("info", f"Verified {checked} snapshot(s): {failed} failure(s)")
    return 1 if failed > 0 else 0


def list_snapshots(backup_dir: str) -> str:
    """List immutable snapshots.

    Returns:
        Formatted string listing all snapshots, or explicit
        "No immutable snapshots exist" message (Lesson #15).
    """
    immutable_dir = _get_immutable_dir(backup_dir)

    if not os.path.isdir(immutable_dir):
        return f"  {Color.YELLOW}No immutable snapshots exist.{Color.RESET}"

    snapshots = sorted(
        Path(immutable_dir).glob(f"{Backup.PREFIX}_*{Backup.EXTENSION}"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    if not snapshots:
        return f"  {Color.YELLOW}No immutable snapshots exist.{Color.RESET}"

    lines: list[str] = []
    lines.append(f"\n  {Color.BOLD}Immutable Snapshots ({len(snapshots)}):{Color.RESET}")
    lines.append(f"  {'─' * 70}")

    for snap in snapshots:
        try:
            size = snap.stat().st_size
        except OSError:
            size = 0
        lines.append(f"  {snap.name:<55s} {human_bytes(size)}")

    return "\n".join(lines)
