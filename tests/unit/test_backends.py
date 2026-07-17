# ==============================================================================
# File:         tests/unit/test_backends.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Unit tests for firewall backend ABC, registry, and dispatch
# Description:  Verifies backend registration, selection, unified dispatch, and
#               failure propagation using the mock backend.
# Version:      1.6.2
# ==============================================================================

import pytest
from apotropaios.core.errors import FirewallNotFoundError
from apotropaios.firewall.base import FirewallBackend
from apotropaios.firewall.common import (
    fw_add_rule, fw_block_all, fw_list_rules,
    fw_remove_rule, fw_status, get_backend, get_backend_name,
    get_registered_backends, register_backend, require_backend,
    set_backend,
)

# Import conftest MockBackend via fixture
from tests.conftest import MockBackend


class TestABCEnforcement:
    def test_cannot_instantiate_abc(self) -> None:
        with pytest.raises(TypeError, match="abstract"):
            FirewallBackend()  # type: ignore[abstract]

    def test_all_abstract_methods_present(self) -> None:
        methods = {
            "name", "add_rule", "remove_rule", "list_rules",
            "enable", "disable", "status", "block_all", "allow_all",
            "reset", "save", "load",
        }
        for m in methods:
            assert hasattr(FirewallBackend, m)


class TestBackendRegistry:
    def test_all_five_registered_on_import(self) -> None:
        # Side-effect imports: each backend module registers itself on import
        import importlib
        for _mod in ("iptables", "nftables", "firewalld", "ufw", "ipset"):
            importlib.import_module(f"apotropaios.firewall.{_mod}")

        backends = get_registered_backends()
        assert set(backends) == {"iptables", "nftables", "firewalld", "ufw", "ipset"}

    def test_register_unknown_name_raises(self) -> None:
        mock = MockBackend("totally_fake")
        with pytest.raises(ValueError, match="Unknown backend"):
            register_backend(mock)


class TestBackendSelection:
    def test_set_and_get(self, registered_mock: MockBackend) -> None:
        assert get_backend_name() == "iptables"
        assert get_backend() is registered_mock

    def test_require_backend(self, registered_mock: MockBackend) -> None:
        be = require_backend()
        assert be.name == "iptables"

    def test_set_unknown_raises(self) -> None:
        with pytest.raises(FirewallNotFoundError):
            set_backend("nonexistent_fw")

    def test_require_when_none_raises(self) -> None:
        from apotropaios.firewall import common
        saved = common._active_backend
        saved_name = common._active_backend_name
        try:
            common._active_backend = None
            common._active_backend_name = ""
            with pytest.raises(FirewallNotFoundError, match="No firewall backend"):
                require_backend()
        finally:
            common._active_backend = saved
            common._active_backend_name = saved_name


class TestDispatch:
    def test_add_rule_dispatches(self, registered_mock: MockBackend) -> None:
        rule = {"direction": "inbound", "action": "accept"}
        fw_add_rule(rule)
        assert any(c[0] == "add_rule" for c in registered_mock.calls)

    def test_remove_rule_dispatches(self, registered_mock: MockBackend) -> None:
        rule = {"direction": "inbound", "action": "accept"}
        fw_remove_rule(rule)
        assert any(c[0] == "remove_rule" for c in registered_mock.calls)

    def test_list_rules_dispatches(self, registered_mock: MockBackend) -> None:
        result = fw_list_rules()
        assert result == "Mock rules listing"

    def test_status_dispatches(self, registered_mock: MockBackend) -> None:
        result = fw_status()
        assert result == "Mock status: active"

    def test_block_all_dispatches(self, registered_mock: MockBackend) -> None:
        fw_block_all()
        assert any(c[0] == "block_all" for c in registered_mock.calls)


class TestIptablesHelpers:
    def test_parse_compound_action(self) -> None:
        from apotropaios.firewall.iptables import _parse_compound_action
        nt, t = _parse_compound_action("log,drop")
        assert nt == ["log"]
        assert t == "drop"

    def test_parse_single_action(self) -> None:
        from apotropaios.firewall.iptables import _parse_compound_action
        nt, t = _parse_compound_action("accept")
        assert nt == []
        assert t == "accept"

    def test_build_match_args_basic(self) -> None:
        from apotropaios.firewall.iptables import _build_match_args
        rule = {"direction": "inbound", "protocol": "tcp", "dst_port": "443",
                "table": "filter"}
        args, table, chain = _build_match_args(rule)
        assert table == "filter"
        assert chain == "INPUT"
        assert "-p" in args and "tcp" in args
        assert "--dport" in args and "443" in args

    def test_direction_to_chain_mapping(self) -> None:
        from apotropaios.firewall.iptables import _direction_to_chain
        assert _direction_to_chain("inbound") == "INPUT"
        assert _direction_to_chain("outbound") == "OUTPUT"
        assert _direction_to_chain("forward") == "FORWARD"
        assert _direction_to_chain("unknown") == "INPUT"  # default


class TestNftablesHelpers:
    def test_direction_to_chain(self) -> None:
        from apotropaios.firewall.nftables import _direction_to_chain
        assert _direction_to_chain("inbound") == "input"
        assert _direction_to_chain("outbound") == "output"


class TestUfwHelpers:
    def test_map_action_simple(self) -> None:
        from apotropaios.firewall.ufw import _map_action
        verb, log = _map_action("accept")
        assert verb == "allow"
        assert not log

    def test_map_action_compound(self) -> None:
        from apotropaios.firewall.ufw import _map_action
        verb, log = _map_action("log,drop")
        assert verb == "deny"
        assert log


class TestFirewalldRichRule:
    def test_basic_port_rule(self) -> None:
        from apotropaios.firewall.firewalld import _build_rich_rule
        rule = {"protocol": "tcp", "dst_port": "443", "action": "accept"}
        rich = _build_rich_rule(rule)
        assert 'family="ipv4"' in rich
        assert 'port="443"' in rich
        assert "accept" in rich

    def test_compound_action(self) -> None:
        from apotropaios.firewall.firewalld import _build_rich_rule
        rule = {"protocol": "tcp", "dst_port": "80", "action": "log,drop",
                "log_prefix": "APO:"}
        rich = _build_rich_rule(rule)
        assert "log" in rich
        assert "drop" in rich
        assert 'prefix="APO:"' in rich

    def test_protocol_only(self) -> None:
        from apotropaios.firewall.firewalld import _build_rich_rule
        rule = {"protocol": "tcp", "action": "accept"}
        rich = _build_rich_rule(rule)
        assert 'protocol value="tcp"' in rich
