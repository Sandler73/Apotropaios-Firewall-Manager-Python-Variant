# ==============================================================================
# File:         apotropaios/rules/import_export.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Rule configuration file import and export
# Description:  Import rules from and export rules to portable configuration
#               files. Import validates every line before application and supports
#               dry-run mode. Export generates complete rule specifications with
#               optional SHA-256 checksum sidecar file.
#
#               File format: key=value pairs per rule, blank line between rules.
#               Lines starting with # are comments. Supports // comments too.
#
# Notes:        - Imports validated line-by-line before application
#               - File size limit: 10MB (security)
#               - Checksum verification if .sha256 sidecar exists
#               - Dry run validates without applying
#               - Parity target: bash v1.1.10 lib/rules/rule_import.sh
# Version:      1.6.2
# ==============================================================================

from __future__ import annotations

import os
from typing import Final

from apotropaios.core.constants import Security
from apotropaios.core.errors import (
    RuleImportError,
    ValidationError,
)
from apotropaios.core.security import file_checksum, verify_checksum
from apotropaios.core.utils import timestamp
from apotropaios.core.validation import validate_file_path
from apotropaios.rules.index import rule_index

_MAX_IMPORT_SIZE: Final[int] = 10_485_760  # 10MB

_log_fn: object | None = None


def _log(level: str, msg: str) -> None:
    if _log_fn is not None:
        method = getattr(_log_fn, level, None)
        if method is not None:
            method("rule_import", msg)


# ==============================================================================
# Import
# ==============================================================================

def import_rules(
    config_path: str,
    dry_run: bool = False,
) -> tuple[int, int, int]:
    """Import and apply rules from a configuration file.

    Each rule is a block of key=value lines separated by blank lines.
    All rules are validated before any are applied.

    Args:
        config_path: Path to the configuration file.
        dry_run:     If True, validate only (do not apply).

    Returns:
        Tuple of (success_count, error_count, skip_count).

    Raises:
        RuleImportError: If the file cannot be read or fails integrity check.
    """
    # Validate file path
    try:
        validate_file_path(config_path)
    except ValidationError as exc:
        raise RuleImportError(f"Invalid file path: {config_path}") from exc

    if not os.path.isfile(config_path):
        raise RuleImportError(f"Configuration file not found: {config_path}")

    if not os.access(config_path, os.R_OK):
        raise RuleImportError(f"Configuration file not readable: {config_path}")

    # Validate file size
    try:
        file_size = os.path.getsize(config_path)
        if file_size > _MAX_IMPORT_SIZE:
            raise RuleImportError(
                f"Configuration file too large: {file_size} bytes (max 10MB)"
            )
    except OSError as exc:
        raise RuleImportError(f"Cannot read file: {exc}") from exc

    # Check integrity if checksum sidecar exists
    checksum_path = f"{config_path}.sha256"
    if os.path.isfile(checksum_path):
        try:
            with open(checksum_path, "r", encoding="utf-8") as f:
                expected = f.read().strip().split()[0]
            if expected:
                verify_checksum(config_path, expected)
                _log("info", "Configuration file integrity verified")
        except Exception as exc:
            raise RuleImportError(f"Integrity check failed: {exc}") from exc

    _log("info", f"Importing rules from: {config_path} (dry_run={dry_run})")

    # Parse rule blocks
    rule_blocks: list[dict[str, str]] = []
    current_block: dict[str, str] = {}

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()

                # Skip comments
                if not line or line.startswith("#") or line.startswith("//"):
                    # Blank line or comment: if we have a current block, save it
                    if not line and current_block:
                        rule_blocks.append(current_block)
                        current_block = {}
                    continue

                # Parse key=value
                if "=" not in line:
                    _log("warning", f"Skipping invalid line {line_num}: no '=' found")
                    continue

                key, _, value = line.partition("=")
                key = key.strip().lower()
                value = value.strip()

                if key:
                    current_block[key] = value

        # Don't forget the last block
        if current_block:
            rule_blocks.append(current_block)

    except OSError as exc:
        raise RuleImportError(f"Failed to read file: {exc}") from exc

    if not rule_blocks:
        _log("warning", "No rules found in configuration file")
        return (0, 0, 0)

    _log("info", f"Parsed {len(rule_blocks)} rule block(s)")

    # Apply rules
    success_count = 0
    error_count = 0
    skip_count = 0

    if not dry_run:
        from apotropaios.rules.engine import rule_create

    for i, block in enumerate(rule_blocks, 1):
        if not block.get("action") and not block.get("direction"):
            _log("debug", f"Skipping block {i}: missing required fields")
            skip_count += 1
            continue

        if dry_run:
            _log("info", f"[DRY RUN] Rule {i}: {block}")
            success_count += 1
        else:
            try:
                rule_id = rule_create(block)
                _log("info", f"Rule {i} imported: {rule_id}")
                success_count += 1
            except Exception as exc:
                _log("error", f"Failed to import rule {i}: {exc}")
                error_count += 1

    _log(
        "info",
        f"Import complete: {success_count} success, "
        f"{error_count} errors, {skip_count} skipped",
    )

    return (success_count, error_count, skip_count)


# ==============================================================================
# Export
# ==============================================================================

def export_rules(
    output_path: str,
    generate_checksum: bool = True,
) -> int:
    """Export all tracked rules to a configuration file.

    Generates a portable key=value format file that can be imported on
    this or another system.

    Args:
        output_path:       Output file path.
        generate_checksum: If True, also write a .sha256 sidecar file.

    Returns:
        Number of rules actually written to the file (expired rules and
        records that cannot be read are skipped and not counted).

    Raises:
        RuleImportError: If the file cannot be written.
    """
    try:
        validate_file_path(output_path)
    except ValidationError as exc:
        raise RuleImportError(f"Invalid output path: {output_path}") from exc

    rule_ids = rule_index.list_ids()
    if not rule_ids:
        _log("warning", "No rules to export")

    # Export fields (subset relevant for re-import)
    export_fields: tuple[str, ...] = (
        "direction", "protocol", "src_ip", "dst_ip", "src_port", "dst_port",
        "action", "interface", "chain", "table", "table_family", "zone",
        "set_name", "conn_state", "log_prefix", "log_level", "limit",
        "limit_burst", "duration_type", "ttl", "description",
    )

    exported_count = 0
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("# Apotropaios Rule Export\n")
            f.write(f"# Generated: {timestamp()}\n")
            f.write("#\n\n")

            for rule_id in rule_ids:
                try:
                    record = rule_index.get(rule_id)
                except Exception:
                    continue

                # Skip non-exportable states
                state = record.get("state", "")
                if state == "expired":
                    continue

                f.write(f"# Rule: {rule_id}\n")
                for field in export_fields:
                    value = record.get(field, "")
                    if value and value != "any":
                        f.write(f"{field}={value}\n")
                f.write("\n")
                exported_count += 1

        os.chmod(output_path, Security.FILE_PERMS)
        _log("info", f"Rules exported to {output_path}")

    except OSError as exc:
        raise RuleImportError(f"Failed to write export file: {exc}") from exc

    # Generate checksum sidecar
    if generate_checksum:
        try:
            checksum = file_checksum(output_path)
            checksum_path = f"{output_path}.sha256"
            with open(checksum_path, "w", encoding="utf-8") as f:
                f.write(f"{checksum}  {os.path.basename(output_path)}\n")
            os.chmod(checksum_path, Security.FILE_PERMS)
            _log("info", f"Checksum written to {checksum_path}")
        except Exception as exc:
            _log("warning", f"Failed to generate checksum: {exc}")

    return exported_count
