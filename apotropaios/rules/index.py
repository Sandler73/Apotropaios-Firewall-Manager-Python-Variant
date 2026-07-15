# ==============================================================================
# File:         apotropaios/rules/index.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Persistent rule index with unique ID tracking
# Description:  Maintains a persistent index of all rules created by the
#               framework. Each rule is tracked by UUID with full parameter
#               details. Index is stored as a pipe-delimited flat file and
#               loaded into memory (dict) for O(1) lookups.
#
#               File format: one rule per line, pipe-delimited fields.
#               Atomic writes via temp file + rename pattern.
#               Validated on load to detect and skip corrupt entries.
#
# Notes:        - Thread-safe via threading.Lock on all mutations
#               - File size limit: 10MB (security)
#               - Atomic save: write temp → rename (no partial writes)
#               - Parity target: bash v1.1.10 lib/rules/rule_index.sh
# Version:      1.2.1
# ==============================================================================

from __future__ import annotations

import os
import threading
from typing import Final

from apotropaios.core.constants import (
    Color,
    FileName,
    Security,
)
from apotropaios.core.errors import (
    RuleExistsError,
    RuleNotFoundError,
)
from apotropaios.core.validation import validate_rule_id

# Field order for serialization — must match bash variant exactly
RULE_INDEX_FIELDS: Final[tuple[str, ...]] = (
    "rule_id", "backend", "direction", "action", "protocol",
    "src_ip", "dst_ip", "src_port", "dst_port", "interface",
    "chain", "table", "table_family", "zone", "set_name",
    "conn_state", "log_prefix", "log_level", "limit", "limit_burst",
    "duration_type", "ttl", "description", "state",
    "created_at", "activated_at", "expires_at",
)

_MAX_INDEX_SIZE: Final[int] = 10_485_760  # 10MB

_log_fn: object | None = None


def _log(level: str, msg: str) -> None:
    if _log_fn is not None:
        method = getattr(_log_fn, level, None)
        if method is not None:
            method("rule_index", msg)


class RuleIndex:
    """Persistent rule index with in-memory cache.

    Stores rule records as dictionaries keyed by UUID. Persists to a
    pipe-delimited flat file with atomic write semantics.

    Usage:
        index = RuleIndex()
        index.init("/path/to/rules/dir")
        index.add({"rule_id": "uuid-...", "backend": "iptables", ...})
        record = index.get("uuid-...")
        index.update_field("uuid-...", "state", "inactive")
        index.remove("uuid-...")
    """

    def __init__(self) -> None:
        self._lock: threading.Lock = threading.Lock()
        self._rules: dict[str, dict[str, str]] = {}
        self._order: list[str] = []  # Preserve insertion order
        self._file_path: str = ""
        self._initialized: bool = False

    def init(self, rules_dir: str) -> None:
        """Initialize the rule index.

        Creates the rules directory if needed and loads any existing
        index file from disk.

        Args:
            rules_dir: Path to the rules data directory.
        """
        from apotropaios.core.security import secure_dir
        secure_dir(rules_dir)

        self._file_path = os.path.join(rules_dir, FileName.RULE_INDEX)

        if os.path.isfile(self._file_path):
            try:
                self.load()
            except Exception:
                _log("warning", "Failed to load existing index — starting fresh")
                with self._lock:
                    self._rules.clear()
                    self._order.clear()

        self._initialized = True
        _log("info", f"Rule index initialized: {len(self._order)} rule(s) loaded")

    def load(self) -> None:
        """Load rule index from disk file into memory.

        Validates each line and skips corrupt entries.
        """
        if not self._file_path or not os.path.isfile(self._file_path):
            return

        # Validate file size
        try:
            file_size = os.path.getsize(self._file_path)
            if file_size > _MAX_INDEX_SIZE:
                _log("error", f"Index file exceeds size limit: {file_size} bytes")
                return
        except OSError:
            return

        with self._lock:
            self._rules.clear()
            self._order.clear()

            valid_count = 0
            corrupt_count = 0

            with open(self._file_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    fields = line.split("|")
                    if len(fields) != len(RULE_INDEX_FIELDS):
                        _log(
                            "warning",
                            f"Corrupt entry at line {line_num}: "
                            f"field count {len(fields)} != {len(RULE_INDEX_FIELDS)}",
                        )
                        corrupt_count += 1
                        continue

                    rule_id = fields[0]
                    try:
                        validate_rule_id(rule_id)
                    except Exception:
                        _log("warning", f"Corrupt entry at line {line_num}: invalid rule ID")
                        corrupt_count += 1
                        continue

                    # Build record dict
                    record: dict[str, str] = {}
                    for i, field_name in enumerate(RULE_INDEX_FIELDS):
                        record[field_name] = fields[i]

                    self._rules[rule_id] = record
                    self._order.append(rule_id)
                    valid_count += 1

            if corrupt_count:
                _log("warning", f"Loaded {valid_count} rules, skipped {corrupt_count} corrupt entries")
            else:
                _log("debug", f"Loaded {valid_count} rules from index")

    def save(self) -> bool:
        """Save the in-memory rule index to disk.

        Uses atomic write: temp file → rename.

        Returns:
            True on success, False on failure.
        """
        if not self._file_path:
            _log("error", "Index file path not set")
            return False

        tmp_path = f"{self._file_path}.tmp.{os.getpid()}"

        with self._lock:
            try:
                with open(tmp_path, "w", encoding="utf-8") as f:
                    from apotropaios.core.utils import timestamp
                    f.write("# Apotropaios Rule Index\n")
                    f.write(f"# Generated: {timestamp()}\n")
                    f.write(f"# Fields: {'|'.join(RULE_INDEX_FIELDS)}\n")
                    f.write("#\n")

                    for rule_id in self._order:
                        record = self._rules.get(rule_id)
                        if record is None:
                            continue
                        values = [record.get(field, "") for field in RULE_INDEX_FIELDS]
                        f.write("|".join(values) + "\n")

                # Atomic rename
                os.replace(tmp_path, self._file_path)
                os.chmod(self._file_path, Security.FILE_PERMS)
                _log("debug", f"Index saved: {len(self._order)} rules")
                return True
            except OSError as exc:
                _log("error", f"Failed to save index: {exc}")
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                return False

    def add(self, record: dict[str, str]) -> None:
        """Add a rule record to the index.

        Args:
            record: Rule field dictionary (must contain 'rule_id').

        Raises:
            RuleExistsError: If a rule with this ID already exists.
            ValueError: If rule_id is missing.
        """
        rule_id = record.get("rule_id", "")
        if not rule_id:
            raise ValueError("Cannot add rule: missing rule_id")

        with self._lock:
            if rule_id in self._rules:
                raise RuleExistsError(f"Duplicate rule ID: {rule_id}", rule_id=rule_id)

            self._rules[rule_id] = dict(record)
            self._order.append(rule_id)

        self.save()
        _log("debug", f"Rule added to index: {rule_id}")

    def remove(self, rule_id: str) -> None:
        """Remove a rule from the index.

        Args:
            rule_id: UUID of the rule to remove.

        Raises:
            RuleNotFoundError: If the rule is not in the index.
        """
        with self._lock:
            if rule_id not in self._rules:
                raise RuleNotFoundError(f"Rule not found: {rule_id}", rule_id=rule_id)

            del self._rules[rule_id]
            self._order = [rid for rid in self._order if rid != rule_id]

        self.save()
        _log("debug", f"Rule removed from index: {rule_id}")

    def get(self, rule_id: str) -> dict[str, str]:
        """Retrieve a rule's data by ID.

        Args:
            rule_id: UUID of the rule.

        Returns:
            Copy of the rule record dictionary.

        Raises:
            RuleNotFoundError: If not found.
        """
        with self._lock:
            record = self._rules.get(rule_id)
            if record is None:
                raise RuleNotFoundError(f"Rule not found: {rule_id}", rule_id=rule_id)
            return dict(record)

    def update_field(self, rule_id: str, field: str, value: str) -> None:
        """Update a single field of a rule in the index.

        Args:
            rule_id: UUID of the rule.
            field:   Field name to update.
            value:   New value.

        Raises:
            RuleNotFoundError: If the rule is not in the index.
        """
        with self._lock:
            if rule_id not in self._rules:
                raise RuleNotFoundError(f"Rule not found: {rule_id}", rule_id=rule_id)
            self._rules[rule_id][field] = value

        self.save()

    def list_ids(self) -> list[str]:
        """Return all rule IDs in insertion order.

        Returns:
            List of UUID strings.
        """
        with self._lock:
            return list(self._order)

    def count(self) -> int:
        """Return the number of rules in the index."""
        with self._lock:
            return len(self._order)

    def list_formatted(self) -> str:
        """Format all rules as a display table.

        Returns:
            Formatted string for terminal output.
        """
        with self._lock:
            count = len(self._order)

        if count == 0:
            return f"  {Color.YELLOW}No rules in index{Color.RESET}"

        lines: list[str] = []
        lines.append(f"\n  {Color.BOLD}Rule Index ({count} rules):{Color.RESET}")
        lines.append(f"  {'─' * 100}")
        lines.append(
            f"  {'RULE ID':<38s} {'BACKEND':<10s} {'DIRECTION':<9s} "
            f"{'ACTION':<8s} {'PROTO':<6s} {'D.PORT':<7s} {'STATE':<10s} DESCRIPTION"
        )
        lines.append(f"  {'─' * 100}")

        with self._lock:
            for rule_id in self._order:
                record = self._rules.get(rule_id)
                if record is None:
                    continue

                state = record.get("state", "unknown")
                state_colors = {
                    "active": Color.GREEN,
                    "inactive": Color.YELLOW,
                    "expired": Color.RED,
                }
                sc = state_colors.get(state, "")
                sr = Color.RESET if sc else ""

                lines.append(
                    f"  {rule_id:<38s} {record.get('backend', ''):<10s} "
                    f"{record.get('direction', ''):<9s} {record.get('action', ''):<8s} "
                    f"{record.get('protocol', 'any'):<6s} {record.get('dst_port', 'any'):<7s} "
                    f"{sc}{state:<10s}{sr} {record.get('description', '')}"
                )

        return "\n".join(lines)

    @property
    def initialized(self) -> bool:
        """Whether the index has been initialized."""
        return self._initialized


# Module-level singleton
rule_index: Final[RuleIndex] = RuleIndex()
