# ==============================================================================
# File:         tests/unit/test_rule_engine.py
# Synopsis:     Unit tests for rule index, state, engine, and import/export
# Version:      1.2.1
# ==============================================================================

import os
import time
import tempfile
import pytest
from apotropaios.core.errors import (
    RuleExistsError, RuleInvalidError, RuleNotFoundError,
)
from apotropaios.rules.index import RuleIndex, RULE_INDEX_FIELDS
from apotropaios.rules.state import RuleState, StateEntry


# ==============================================================================
# Rule Index Tests
# ==============================================================================

class TestRuleIndex:
    def test_init_creates_dir(self, tmp_path: object) -> None:
        idx = RuleIndex()
        path = os.path.join(str(tmp_path), "sub", "rules")
        idx.init(path)
        assert idx.initialized
        assert idx.count() == 0

    def test_add_and_get(self, fresh_index: RuleIndex) -> None:
        record = {f: "" for f in RULE_INDEX_FIELDS}
        record.update({"rule_id": "aaaaaaaa-bbbb-cccc-dddd-000000000001",
                        "backend": "iptables", "state": "active"})
        fresh_index.add(record)
        got = fresh_index.get("aaaaaaaa-bbbb-cccc-dddd-000000000001")
        assert got["backend"] == "iptables"

    def test_add_duplicate_raises(self, fresh_index: RuleIndex) -> None:
        record = {f: "" for f in RULE_INDEX_FIELDS}
        record["rule_id"] = "aaaaaaaa-bbbb-cccc-dddd-000000000002"
        fresh_index.add(record)
        with pytest.raises(RuleExistsError):
            fresh_index.add(record)

    def test_get_missing_raises(self, fresh_index: RuleIndex) -> None:
        with pytest.raises(RuleNotFoundError):
            fresh_index.get("aaaaaaaa-bbbb-cccc-dddd-999999999999")

    def test_remove(self, populated_index: RuleIndex) -> None:
        assert populated_index.count() == 3
        populated_index.remove("aaaaaaaa-bbbb-cccc-dddd-000000000000")
        assert populated_index.count() == 2

    def test_remove_missing_raises(self, fresh_index: RuleIndex) -> None:
        with pytest.raises(RuleNotFoundError):
            fresh_index.remove("aaaaaaaa-bbbb-cccc-dddd-999999999999")

    def test_update_field(self, populated_index: RuleIndex) -> None:
        populated_index.update_field(
            "aaaaaaaa-bbbb-cccc-dddd-000000000000", "state", "expired"
        )
        got = populated_index.get("aaaaaaaa-bbbb-cccc-dddd-000000000000")
        assert got["state"] == "expired"

    def test_list_ids(self, populated_index: RuleIndex) -> None:
        ids = populated_index.list_ids()
        assert len(ids) == 3
        assert ids[0] == "aaaaaaaa-bbbb-cccc-dddd-000000000000"

    def test_persistence(self, rules_dir: str) -> None:
        idx1 = RuleIndex()
        idx1.init(rules_dir)
        record = {f: "" for f in RULE_INDEX_FIELDS}
        record.update({"rule_id": "aaaaaaaa-bbbb-cccc-dddd-000000000099",
                        "backend": "nftables"})
        idx1.add(record)

        idx2 = RuleIndex()
        idx2.init(rules_dir)
        assert idx2.count() == 1
        got = idx2.get("aaaaaaaa-bbbb-cccc-dddd-000000000099")
        assert got["backend"] == "nftables"

    def test_formatted_output(self, populated_index: RuleIndex) -> None:
        output = populated_index.list_formatted()
        assert "Rule Index (3 rules)" in output
        assert "Test rule 0" in output

    def test_corrupt_entries_skipped(self, rules_dir: str) -> None:
        idx = RuleIndex()
        idx.init(rules_dir)
        record = {f: "" for f in RULE_INDEX_FIELDS}
        record.update({"rule_id": "aaaaaaaa-bbbb-cccc-dddd-000000000001"})
        idx.add(record)

        # Corrupt the file by adding a bad line
        file_path = os.path.join(rules_dir, "rule_index.dat")
        with open(file_path, "a", encoding="utf-8") as f:
            f.write("corrupt|line|only|three|fields\n")

        idx2 = RuleIndex()
        idx2.init(rules_dir)
        assert idx2.count() == 1  # Good line loaded, corrupt skipped


# ==============================================================================
# Rule State Tests
# ==============================================================================

class TestRuleState:
    def test_permanent_not_expired(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            st = RuleState()
            st.init(d)
            st.set("rule-perm", "active", "permanent", 0)
            assert st.get("rule-perm") == "active"
            assert not st.is_expired("rule-perm")
            assert st.time_remaining("rule-perm") == 0

    def test_temporary_expiry(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            st = RuleState()
            st.init(d)
            st.set("rule-temp", "active", "temporary", 1)
            assert not st.is_expired("rule-temp")
            time.sleep(1.2)
            assert st.is_expired("rule-temp")

    def test_time_remaining(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            st = RuleState()
            st.init(d)
            st.set("rule-tr", "active", "temporary", 300)
            rem = st.time_remaining("rule-tr")
            assert 298 <= rem <= 300

    def test_get_expiring_soon(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            st = RuleState()
            st.init(d)
            st.set("soon1", "active", "temporary", 120)
            st.set("soon2", "active", "temporary", 500)
            st.set("far", "active", "temporary", 7200)
            expiring = st.get_expiring_soon(600)
            ids = [e[0] for e in expiring]
            assert "soon1" in ids
            assert "soon2" in ids
            assert "far" not in ids

    def test_remove(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            st = RuleState()
            st.init(d)
            st.set("rm-me", "active")
            st.remove("rm-me")
            assert st.get("rm-me") == ""

    def test_get_entry(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            st = RuleState()
            st.init(d)
            st.set("entry-test", "active", "temporary", 600)
            entry = st.get_entry("entry-test")
            assert entry is not None
            assert entry.duration_type == "temporary"
            assert entry.ttl == 600

    def test_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            st1 = RuleState()
            st1.init(d)
            st1.set("persist", "active", "permanent")

            st2 = RuleState()
            st2.init(d)
            assert st2.get("persist") == "active"


# ==============================================================================
# Import/Export Tests
# ==============================================================================

class TestImportExport:
    def test_dry_run(self, sample_import_file: str) -> None:
        from apotropaios.rules.import_export import import_rules
        ok, err, skip = import_rules(sample_import_file, dry_run=True)
        assert ok == 2
        assert err == 0

    def test_import_missing_file(self) -> None:
        from apotropaios.rules.import_export import import_rules
        from apotropaios.core.errors import RuleImportError
        with pytest.raises(RuleImportError, match="not found"):
            import_rules("/nonexistent/file.conf")

    def test_export_creates_file(self, rules_dir: str, tmp_path: object) -> None:
        from apotropaios.rules.import_export import export_rules
        from apotropaios.rules.index import RuleIndex
        idx = RuleIndex()
        idx.init(rules_dir)
        # Export even with no rules
        export_path = os.path.join(str(tmp_path), "export.conf")
        count = export_rules(export_path)
        assert os.path.isfile(export_path)
        assert os.path.isfile(f"{export_path}.sha256")

    def test_export_checksum_sidecar(self, tmp_path: object) -> None:
        from apotropaios.rules.import_export import export_rules
        path = os.path.join(str(tmp_path), "out.conf")
        export_rules(path, generate_checksum=True)
        sha_path = f"{path}.sha256"
        assert os.path.isfile(sha_path)
        with open(sha_path, encoding="utf-8") as f:
            content = f.read()
        assert len(content.split()[0]) == 64  # SHA-256 hex
