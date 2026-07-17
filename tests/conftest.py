# ==============================================================================
# File:         tests/conftest.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     pytest fixtures and shared test infrastructure
# Description:  Provides reusable fixtures for all test tiers (unit, integration,
#               security). Includes temporary directory management, mock backends,
#               pre-populated rule indexes, and logger configuration.
#
# Notes:        - Fixtures use tmp_path (pytest built-in) for isolation
#               - Each test gets a fresh environment (no state leakage)
#               - Mock backend avoids needing root/real firewall for unit tests
#               - Parity target: bash v1.1.10 tests/helpers/test_helper.bash
# Version:      1.2.1
# ==============================================================================

from __future__ import annotations

import os
import sys
from typing import Any, Generator

import pytest

# Ensure project root is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from apotropaios.core.constants import SUPPORTED_FW_IDS
from apotropaios.firewall.base import FirewallBackend
from apotropaios.firewall.common import register_backend, _registry
from apotropaios.rules.index import RuleIndex, RULE_INDEX_FIELDS


# ==============================================================================
# Mock Firewall Backend (for unit tests without root/real firewall)
# ==============================================================================

class MockBackend(FirewallBackend):
    """Mock firewall backend that records operations without system calls.

    All operations succeed by default. Tracks calls for assertion in tests.
    """

    def __init__(self, name: str = "iptables") -> None:
        self._name = name
        self.calls: list[tuple[str, Any]] = []
        self.fail_next: str | None = None  # Set to method name to force failure

    @property
    def name(self) -> str:
        return self._name

    def _record(self, method: str, *args: Any) -> bool:
        self.calls.append((method, args))
        if self.fail_next == method:
            self.fail_next = None
            return False
        return True

    def add_rule(self, rule: dict[str, str]) -> bool:
        return self._record("add_rule", rule)

    def remove_rule(self, rule: dict[str, str]) -> bool:
        return self._record("remove_rule", rule)

    def list_rules(self, **kwargs: str) -> str:
        self._record("list_rules", kwargs)
        return "Mock rules listing"

    def enable(self) -> bool:
        return self._record("enable")

    def disable(self) -> bool:
        return self._record("disable")

    def status(self) -> str:
        self._record("status")
        return "Mock status: active"

    def block_all(self) -> bool:
        return self._record("block_all")

    def allow_all(self) -> bool:
        return self._record("allow_all")

    def reset(self) -> bool:
        return self._record("reset")

    def save(self, path: str = "") -> bool:
        return self._record("save", path)

    def load(self, path: str) -> bool:
        return self._record("load", path)


# ==============================================================================
# Fixtures
# ==============================================================================

@pytest.fixture
def rules_dir(tmp_path: Any) -> str:
    """Create a temporary rules directory."""
    d = str(tmp_path / "rules")
    os.makedirs(d, exist_ok=True)
    return d


@pytest.fixture
def backup_dir(tmp_path: Any) -> str:
    """Create a temporary backup directory."""
    d = str(tmp_path / "backups")
    os.makedirs(d, exist_ok=True)
    return d


@pytest.fixture
def logs_dir(tmp_path: Any) -> str:
    """Create a temporary logs directory."""
    d = str(tmp_path / "logs")
    os.makedirs(d, exist_ok=True)
    return d


@pytest.fixture
def fresh_index(rules_dir: str) -> RuleIndex:
    """Create a fresh, empty rule index backed by a temp directory."""
    idx = RuleIndex()
    idx.init(rules_dir)
    return idx


@pytest.fixture
def populated_index(rules_dir: str) -> RuleIndex:
    """Create a rule index pre-populated with 3 test rules."""
    idx = RuleIndex()
    idx.init(rules_dir)

    for i, (action, state, duration) in enumerate([
        ("accept", "active", "permanent"),
        ("drop", "inactive", "permanent"),
        ("accept", "active", "temporary"),
    ]):
        record = {f: "" for f in RULE_INDEX_FIELDS}
        record.update({
            "rule_id": f"aaaaaaaa-bbbb-cccc-dddd-{i:012d}",
            "backend": "iptables",
            "direction": "inbound",
            "action": action,
            "protocol": "tcp",
            "dst_port": str(443 + i),
            "state": state,
            "duration_type": duration,
            "ttl": "7200" if duration == "temporary" else "0",
            "description": f"Test rule {i}",
            "created_at": "2026-03-29T00:00:00Z",
            "activated_at": "2026-03-29T00:00:00Z",
            "expires_at": "2026-03-30T00:00:00Z" if duration == "temporary" else "",
        })
        idx.add(record)

    return idx


@pytest.fixture
def mock_backend() -> MockBackend:
    """Create a fresh mock backend instance."""
    return MockBackend("iptables")


@pytest.fixture
def registered_mock(mock_backend: MockBackend) -> Generator[MockBackend, None, None]:
    """Register a mock backend and set it as active, restore after test."""
    from apotropaios.firewall.common import set_backend, _registry

    # Save original state
    original = dict(_registry)

    # Register mock
    _registry["iptables"] = mock_backend
    set_backend("iptables")

    yield mock_backend

    # Restore
    _registry.clear()
    _registry.update(original)


@pytest.fixture
def sample_rule_params() -> dict[str, str]:
    """Standard rule parameters for testing."""
    return {
        "direction": "inbound",
        "protocol": "tcp",
        "dst_port": "443",
        "action": "accept",
        "duration_type": "permanent",
        "ttl": "0",
        "description": "Test HTTPS rule",
    }


@pytest.fixture
def sample_import_file(tmp_path: Any) -> str:
    """Create a sample rule import configuration file."""
    path = str(tmp_path / "import_rules.conf")
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Test import file\n\n")
        f.write("direction=inbound\n")
        f.write("protocol=tcp\n")
        f.write("dst_port=80\n")
        f.write("action=accept\n")
        f.write("description=HTTP import test\n\n")
        f.write("direction=inbound\n")
        f.write("protocol=tcp\n")
        f.write("dst_port=443\n")
        f.write("action=accept\n")
        f.write("description=HTTPS import test\n\n")
    return path
