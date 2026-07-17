# ==============================================================================
# File:         tests/integration/test_lifecycle.py
# Synopsis:     Integration tests for full rule lifecycle with mock backend
# Version:      1.2.1
# ==============================================================================

import os
import tempfile
import pytest
from tests.conftest import MockBackend
from apotropaios.firewall.common import _registry, set_backend
from apotropaios.rules.index import RuleIndex
from apotropaios.rules.state import RuleState


@pytest.fixture
def lifecycle_env(tmp_path: object) -> tuple[RuleIndex, RuleState, MockBackend]:
    """Set up complete rule engine environment with mock backend."""
    rules_dir = os.path.join(str(tmp_path), "rules")
    os.makedirs(rules_dir, exist_ok=True)

    idx = RuleIndex()
    idx.init(rules_dir)

    st = RuleState()
    st.init(rules_dir)

    mock = MockBackend("iptables")
    original = dict(_registry)
    _registry["iptables"] = mock
    set_backend("iptables")

    # Patch singletons used by engine — both the module attr and engine's import
    import apotropaios.rules.index as idx_mod
    import apotropaios.rules.state as st_mod
    import apotropaios.rules.engine as eng_mod
    old_idx = idx_mod.rule_index
    old_st = st_mod.rule_state
    old_eng_idx = getattr(eng_mod, "rule_index", None)
    old_eng_st = getattr(eng_mod, "rule_state", None)

    object.__setattr__(idx_mod, "rule_index", idx)
    object.__setattr__(st_mod, "rule_state", st)
    eng_mod.rule_index = idx  # type: ignore[attr-defined]
    eng_mod.rule_state = st  # type: ignore[attr-defined]

    yield idx, st, mock

    # Restore
    _registry.clear()
    _registry.update(original)
    object.__setattr__(idx_mod, "rule_index", old_idx)
    object.__setattr__(st_mod, "rule_state", old_st)
    if old_eng_idx is not None:
        eng_mod.rule_index = old_eng_idx  # type: ignore[attr-defined]
    if old_eng_st is not None:
        eng_mod.rule_state = old_eng_st  # type: ignore[attr-defined]


class TestFullRuleLifecycle:
    def test_create_list_deactivate_activate_remove(
        self, lifecycle_env: tuple[RuleIndex, RuleState, MockBackend]
    ) -> None:
        idx, st, mock = lifecycle_env
        from apotropaios.rules.engine import (
            rule_create, rule_deactivate, rule_activate, rule_remove,
        )

        # 1. Create
        rule_id = rule_create({
            "direction": "inbound", "protocol": "tcp",
            "dst_port": "443", "action": "accept",
            "description": "Lifecycle test",
        })
        assert len(rule_id) == 36
        assert idx.count() == 1
        assert idx.get(rule_id)["state"] == "active"
        assert any(c[0] == "add_rule" for c in mock.calls)

        # 2. List
        ids = idx.list_ids()
        assert rule_id in ids

        # 3. Deactivate
        mock.calls.clear()
        rule_deactivate(rule_id)
        assert idx.get(rule_id)["state"] == "inactive"
        assert any(c[0] == "remove_rule" for c in mock.calls)

        # 4. Re-activate
        mock.calls.clear()
        rule_activate(rule_id)
        assert idx.get(rule_id)["state"] == "active"
        assert any(c[0] == "add_rule" for c in mock.calls)

        # 5. Remove
        mock.calls.clear()
        rule_remove(rule_id)
        assert idx.count() == 0

    def test_block_all_creates_tracked_rule(
        self, lifecycle_env: tuple[RuleIndex, RuleState, MockBackend]
    ) -> None:
        idx, st, mock = lifecycle_env
        from apotropaios.rules.engine import rule_block_all

        rid = rule_block_all()
        assert idx.count() == 1
        record = idx.get(rid)
        assert record["action"] == "drop"
        assert record["description"] == "BLOCK ALL TRAFFIC"
        assert any(c[0] == "block_all" for c in mock.calls)

    def test_allow_all_creates_tracked_rule(
        self, lifecycle_env: tuple[RuleIndex, RuleState, MockBackend]
    ) -> None:
        idx, st, mock = lifecycle_env
        from apotropaios.rules.engine import rule_allow_all

        rid = rule_allow_all()
        record = idx.get(rid)
        assert record["action"] == "accept"
        assert record["description"] == "ALLOW ALL TRAFFIC"

    def test_invalid_params_rejected(
        self, lifecycle_env: tuple[RuleIndex, RuleState, MockBackend]
    ) -> None:
        idx, st, mock = lifecycle_env
        from apotropaios.rules.engine import rule_create
        from apotropaios.core.errors import RuleInvalidError

        with pytest.raises(RuleInvalidError, match="direction"):
            rule_create({"direction": "sideways", "action": "accept"})

        with pytest.raises(RuleInvalidError, match="action"):
            rule_create({"direction": "inbound", "action": "nuke"})

        assert idx.count() == 0  # Nothing committed
