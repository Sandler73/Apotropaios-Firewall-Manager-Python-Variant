# ==============================================================================
# File:         apotropaios/backup/restore.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Firewall configuration restoration from backups
# Description:  Restores firewall configurations from previously created backup
#               archives. Validates archive integrity via SHA-256 checksum before
#               restoration. Creates a pre-restore safety backup automatically.
#               Supports selective per-backend restoration.
#
# Notes:        - Creates pre-restore backup automatically for safety
#               - Validates archive integrity before extracting
#               - Per-backend restore uses native tools (iptables-restore, nft -f, etc.)
#               - Rule index and state files restored if present in archive
#               - Parity target: bash v1.1.10 lib/backup/restore.sh
# Version:      1.2.1
# ==============================================================================

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tarfile

from apotropaios.core.constants import (
    Backup,
    Performance,
    Security,
    SUPPORTED_FIREWALLS,
)
from apotropaios.core.errors import (
    BackupNotFoundError,
    IntegrityError,
    RestoreError,
)
from apotropaios.core.security import create_temp_dir, verify_checksum

_log_fn: object | None = None


def _log(level: str, msg: str) -> None:
    if _log_fn is not None:
        method = getattr(_log_fn, level, None)
        if method is not None:
            method("restore", msg)


def restore_backup(
    backup_file: str,
    target_backend: str = "all",
    rules_dir: str = "",
) -> None:
    """Restore firewall configuration from a backup archive.

    Args:
        backup_file:    Path to the backup .tar.gz archive.
        target_backend: Specific backend to restore, or "all".
        rules_dir:      Path to rules directory (for index/state restore).

    Raises:
        BackupNotFoundError: If the backup file doesn't exist.
        IntegrityError: If checksum verification fails.
        RestoreError: If extraction or restoration fails.
    """
    if not os.path.isfile(backup_file):
        raise BackupNotFoundError(f"Backup file not found: {backup_file}")

    # Fall back to the backup subsystem's default rules directory so
    # menu-driven restores also recover the rule index and state files
    if not rules_dir:
        from apotropaios.backup.backup import get_default_rules_dir
        rules_dir = get_default_rules_dir()

    # Verify integrity if checksum sidecar exists
    checksum_file = f"{backup_file}.sha256"
    if os.path.isfile(checksum_file):
        try:
            with open(checksum_file, "r", encoding="utf-8") as f:
                expected = f.read().strip().split()[0]
            if expected:
                verify_checksum(backup_file, expected)
                _log("info", "Backup integrity verified")
        except IntegrityError:
            _log("error", "Backup integrity check failed — aborting restore")
            raise
        except Exception as exc:
            _log("warning", f"Could not verify checksum: {exc}")

    # Create pre-restore safety backup
    _log("info", "Creating pre-restore safety backup")
    try:
        from apotropaios.backup.backup import create_backup
        create_backup("pre_restore", target_backend, rules_dir)
    except Exception as exc:
        _log("warning", f"Failed to create pre-restore backup: {exc} — proceeding with caution")

    # Extract to temporary directory
    try:
        extract_dir = create_temp_dir("restore")
    except Exception as exc:
        raise RestoreError(f"Failed to create temp directory: {exc}") from exc

    try:
        with tarfile.open(backup_file, "r:gz") as tar:
            # Security: check for path traversal and unsafe members
            for member in tar.getmembers():
                # Reject absolute paths and directory traversal (CWE-22)
                if member.name.startswith("/") or ".." in member.name:
                    raise RestoreError(f"Unsafe path in archive: {member.name}")
                # Reject symlinks and device nodes (CWE-59: symlink following)
                if member.issym() or member.islnk():
                    raise RestoreError(f"Symbolic/hard link in archive: {member.name}")
                if member.isdev() or member.ischr() or member.isblk():
                    raise RestoreError(f"Device node in archive: {member.name}")
            # Python 3.12+ filter='data' as defense-in-depth: strips
            # symlinks, device nodes, absolute paths, ownership
            tar.extractall(path=extract_dir, filter="data")
    except (tarfile.TarError, OSError) as exc:
        shutil.rmtree(extract_dir, ignore_errors=True)
        raise RestoreError(f"Failed to extract archive: {exc}") from exc

    # Find staging directory inside extract
    staging_dir = extract_dir
    for entry in os.listdir(extract_dir):
        candidate = os.path.join(extract_dir, entry)
        if os.path.isdir(candidate) and entry.startswith(".staging_"):
            staging_dir = candidate
            break

    # Read manifest if present
    manifest_path = os.path.join(staging_dir, Backup.MANIFEST_FILE)
    if os.path.isfile(manifest_path):
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
            _log("info", f"Backup manifest: {json.dumps(manifest, indent=2)}")
        except Exception:
            pass

    # Restore configurations
    _CMD_T = Performance.SUBPROCESS_TIMEOUT
    restore_errors = 0

    if target_backend == "all":
        for fw_info in SUPPORTED_FIREWALLS:
            config = os.path.join(staging_dir, f"{fw_info.fw_id}.conf")
            if os.path.isfile(config) and shutil.which(fw_info.binary):
                if not _restore_single(staging_dir, fw_info.fw_id, _CMD_T):
                    restore_errors += 1
    else:
        config = os.path.join(staging_dir, f"{target_backend}.conf")
        if os.path.isfile(config):
            if not _restore_single(staging_dir, target_backend, _CMD_T):
                restore_errors += 1
        else:
            _log("warning", f"No backup config found for {target_backend}")

    # Restore rule index and state files
    if rules_dir:
        for fname in ("rule_index.dat", "rule_state.dat"):
            src = os.path.join(staging_dir, fname)
            dst = os.path.join(rules_dir, fname)
            if os.path.isfile(src):
                try:
                    shutil.copy2(src, dst)
                    os.chmod(dst, Security.FILE_PERMS)
                    _log("info", f"{fname} restored")
                except OSError as exc:
                    _log("warning", f"Failed to restore {fname}: {exc}")

    # Cleanup
    shutil.rmtree(extract_dir, ignore_errors=True)

    if restore_errors:
        raise RestoreError("Restore completed with errors")

    _log("info", f"Restore completed successfully from: {backup_file}")


def _restore_single(staging: str, fw_name: str, timeout: int) -> bool:
    """Restore a single backend's configuration.

    Returns:
        True on success, False on failure.
    """
    config = os.path.join(staging, f"{fw_name}.conf")
    if not os.path.isfile(config):
        return False

    _log("info", f"Restoring {fw_name} configuration")

    try:
        if fw_name == "iptables" and shutil.which("iptables-restore"):
            with open(config, "r", encoding="utf-8") as f:
                result = subprocess.run(
                    ["iptables-restore"], input=f.read(),
                    capture_output=True, text=True, timeout=timeout,
                )
                if result.returncode != 0:
                    _log("error", f"iptables restore failed: {result.stderr.strip()}")
                    return False

        elif fw_name == "nftables" and shutil.which("nft"):
            result = subprocess.run(
                ["nft", "-f", config],
                capture_output=True, text=True, timeout=timeout,
            )
            if result.returncode != 0:
                _log("error", f"nftables restore failed: {result.stderr.strip()}")
                return False

        elif fw_name == "firewalld" and shutil.which("firewall-cmd"):
            # Restore zone XML files if backed up
            firewalld_zones_src = os.path.join(staging, "firewalld_zones")
            firewalld_zones_dst = "/etc/firewalld/zones"
            if os.path.isdir(firewalld_zones_src) and os.path.isdir(firewalld_zones_dst):
                for item in os.listdir(firewalld_zones_src):
                    src = os.path.join(firewalld_zones_src, item)
                    dst = os.path.join(firewalld_zones_dst, item)
                    try:
                        if os.path.isfile(src):
                            shutil.copy2(src, dst)
                            os.chmod(dst, Security.FILE_PERMS)
                    except OSError as exc:
                        _log("warning", f"Failed to restore zone file {item}: {exc}")
                _log("info", "Firewalld zone files restored")
            # Reload to apply restored configuration
            result = subprocess.run(
                ["firewall-cmd", "--reload"],
                capture_output=True, text=True, timeout=timeout,
            )
            if result.returncode != 0:
                _log("error", f"firewalld reload failed: {result.stderr.strip()}")
                return False

        elif fw_name == "ufw":
            ufw_etc = os.path.join(staging, "ufw_etc")
            if not os.path.isdir(ufw_etc):
                # Archive predates machine-restorable ufw backups (status
                # dump only) — nothing can be restored. Report honestly
                # instead of claiming success.
                _log(
                    "error",
                    "Archive contains no restorable ufw configuration "
                    "(ufw_etc missing — status dump is reference-only)",
                )
                return False
            if not os.path.isdir("/etc/ufw"):
                _log("error", "/etc/ufw does not exist — cannot restore ufw")
                return False
            for item in os.listdir(ufw_etc):
                src = os.path.join(ufw_etc, item)
                dst = os.path.join("/etc/ufw", item)
                try:
                    if os.path.isdir(src):
                        shutil.copytree(src, dst, dirs_exist_ok=True)
                    else:
                        shutil.copy2(src, dst)
                except OSError as exc:
                    _log("warning", f"Failed to restore ufw item {item}: {exc}")
            if shutil.which("ufw"):
                subprocess.run(
                    ["ufw", "reload"],
                    capture_output=True, text=True, timeout=timeout,
                )

        elif fw_name == "ipset" and shutil.which("ipset"):
            with open(config, "r", encoding="utf-8") as f:
                result = subprocess.run(
                    ["ipset", "restore"], input=f.read(),
                    capture_output=True, text=True, timeout=timeout,
                )
                if result.returncode != 0:
                    _log("error", f"ipset restore failed: {result.stderr.strip()}")
                    return False

        _log("info", f"{fw_name} configuration restored")
        return True

    except (subprocess.TimeoutExpired, OSError) as exc:
        _log("error", f"Restore failed for {fw_name}: {exc}")
        return False
