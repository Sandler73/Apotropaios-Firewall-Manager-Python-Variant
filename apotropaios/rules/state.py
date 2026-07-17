# ==============================================================================
# File:         apotropaios/rules/state.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Rule activation state and TTL (time-to-live) tracking
# Description:  Tracks the activation state of firewall rules including
#               permanent/temporary designation, time-based expiry for
#               temporary rules, and state persistence across sessions.
#               State file is pipe-delimited, alongside the rule index.
#
# Notes:        - Thread-safe via threading.Lock
#               - State file: rule_id|state|duration_type|ttl|created|expires
#               - Atomic writes via temp + rename
#               - Parity target: bash v1.1.10 lib/rules/rule_state.sh
# Version:      1.6.2
# ==============================================================================

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import Final

from apotropaios.core.constants import (
    FileName,
    Security,
)

_log_fn: object | None = None


def _log(level: str, msg: str) -> None:
    if _log_fn is not None:
        method = getattr(_log_fn, level, None)
        if method is not None:
            method("rule_state", msg)


@dataclass
class StateEntry:
    """In-memory state for a single rule."""
    state: str = "active"         # active, inactive, expired, pending
    duration_type: str = "permanent"  # permanent, temporary
    ttl: int = 0                  # TTL in seconds (0 for permanent)
    created_epoch: int = 0        # Epoch when state was set
    expires_epoch: int = 0        # Epoch when rule expires (0 for permanent)


class RuleState:
    """Rule state tracker with TTL expiry support.

    Manages per-rule state (active/inactive/expired/pending), duration
    type (permanent/temporary), and TTL-based expiry timestamps.

    Usage:
        state = RuleState()
        state.init("/path/to/rules/dir")
        state.set("uuid-...", "active", "temporary", ttl=7200)
        if state.is_expired("uuid-..."):
            # handle expiry
        remaining = state.time_remaining("uuid-...")
    """

    def __init__(self) -> None:
        self._lock: threading.Lock = threading.Lock()
        self._entries: dict[str, StateEntry] = {}
        self._file_path: str = ""
        self._initialized: bool = False

    def init(self, rules_dir: str) -> None:
        """Initialize rule state tracking.

        Args:
            rules_dir: Path to the rules data directory.
        """
        self._file_path = os.path.join(rules_dir, FileName.RULE_STATE)

        if os.path.isfile(self._file_path):
            try:
                self._load()
            except Exception:
                _log("warning", "Failed to load state file")

        self._initialized = True
        _log("info", "Rule state tracking initialized")

    def set(
        self,
        rule_id: str,
        state: str = "active",
        duration_type: str = "permanent",
        ttl: int = 0,
    ) -> None:
        """Set or update the state of a rule.

        Args:
            rule_id:       Rule UUID.
            state:         Rule state (active/inactive/expired/pending).
            duration_type: permanent or temporary.
            ttl:           TTL in seconds for temporary rules.
        """
        now = int(time.time())
        expires = (now + ttl) if (duration_type == "temporary" and ttl > 0) else 0

        with self._lock:
            self._entries[rule_id] = StateEntry(
                state=state,
                duration_type=duration_type,
                ttl=ttl,
                created_epoch=now,
                expires_epoch=expires,
            )

        self._save()
        _log("debug", f"State set: {rule_id} state={state} type={duration_type} ttl={ttl}")

    def get(self, rule_id: str) -> str:
        """Get the current state of a rule.

        Args:
            rule_id: Rule UUID.

        Returns:
            State string, or empty string if not tracked.
        """
        with self._lock:
            entry = self._entries.get(rule_id)
            return entry.state if entry else ""

    def remove(self, rule_id: str) -> None:
        """Remove state tracking for a rule.

        Args:
            rule_id: Rule UUID.
        """
        with self._lock:
            self._entries.pop(rule_id, None)
        self._save()

    def is_expired(self, rule_id: str) -> bool:
        """Check if a temporary rule has expired.

        Args:
            rule_id: Rule UUID.

        Returns:
            True if the rule is temporary and has passed its expiry time.
        """
        with self._lock:
            entry = self._entries.get(rule_id)
            if entry is None or entry.duration_type != "temporary":
                return False
            if entry.expires_epoch == 0:
                return False
            return int(time.time()) >= entry.expires_epoch

    def time_remaining(self, rule_id: str) -> int:
        """Get remaining time for a temporary rule in seconds.

        Args:
            rule_id: Rule UUID.

        Returns:
            Seconds remaining (0 if expired or permanent).
        """
        with self._lock:
            entry = self._entries.get(rule_id)
            if entry is None or entry.expires_epoch == 0:
                return 0
            remaining = entry.expires_epoch - int(time.time())
            return max(0, remaining)

    def get_entry(self, rule_id: str) -> StateEntry | None:
        """Get the full state entry for a rule.

        Args:
            rule_id: Rule UUID.

        Returns:
            Copy of StateEntry, or None if not tracked.
        """
        with self._lock:
            entry = self._entries.get(rule_id)
            if entry is None:
                return None
            # Return a copy
            return StateEntry(
                state=entry.state,
                duration_type=entry.duration_type,
                ttl=entry.ttl,
                created_epoch=entry.created_epoch,
                expires_epoch=entry.expires_epoch,
            )

    def get_expiring_soon(self, within_seconds: int = 600) -> list[tuple[str, int]]:
        """Get rules expiring within a time window.

        Args:
            within_seconds: Window in seconds (default: 10 minutes).

        Returns:
            List of (rule_id, seconds_remaining) tuples.
        """
        now = int(time.time())
        result: list[tuple[str, int]] = []

        with self._lock:
            for rule_id, entry in self._entries.items():
                if entry.duration_type != "temporary" or entry.expires_epoch == 0:
                    continue
                if entry.state != "active":
                    continue
                remaining = entry.expires_epoch - now
                if 0 < remaining <= within_seconds:
                    result.append((rule_id, remaining))

        return sorted(result, key=lambda x: x[1])

    def _load(self) -> None:
        """Load state from disk file."""
        if not os.path.isfile(self._file_path):
            return

        with self._lock:
            self._entries.clear()
            with open(self._file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("|")
                    if len(parts) != 6:
                        continue
                    rule_id, state, dtype, ttl_s, created_s, expires_s = parts
                    try:
                        self._entries[rule_id] = StateEntry(
                            state=state,
                            duration_type=dtype,
                            ttl=int(ttl_s) if ttl_s.isdigit() else 0,
                            created_epoch=int(created_s) if created_s.isdigit() else 0,
                            expires_epoch=int(expires_s) if expires_s.isdigit() else 0,
                        )
                    except (ValueError, TypeError):
                        continue

    def _save(self) -> None:
        """Save state to disk file with atomic write."""
        if not self._file_path:
            return

        tmp_path = f"{self._file_path}.tmp.{os.getpid()}"
        with self._lock:
            try:
                with open(tmp_path, "w", encoding="utf-8") as f:
                    f.write("# Apotropaios Rule State\n")
                    f.write("# Format: rule_id|state|duration_type|ttl|created_epoch|expires_epoch\n")
                    for rule_id, entry in self._entries.items():
                        f.write(
                            f"{rule_id}|{entry.state}|{entry.duration_type}|"
                            f"{entry.ttl}|{entry.created_epoch}|{entry.expires_epoch}\n"
                        )
                os.replace(tmp_path, self._file_path)
                os.chmod(self._file_path, Security.FILE_PERMS)
            except OSError:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    @property
    def initialized(self) -> bool:
        """Whether the rule state subsystem has been initialized."""
        return self._initialized


# Module-level singleton
rule_state: Final[RuleState] = RuleState()
