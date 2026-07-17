# ==============================================================================
# File:         tests/unit/test_backend_validation.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Backend defense-in-depth and fail-closed behavior tests
# Description:  Exercises the pure builder/mapper/validator functions that the
#               v1.0.1-v1.0.3 audit remediations hardened: nftables and
#               firewalld command-string composition re-validation, ufw
#               fail-closed action mapping, and ipset per-set-type entry
#               validation. These paths passed the original suite because it
#               used a mock backend; this module tests the composition sites
#               directly so injection vectors and fail-open regressions are
#               caught.
# Notes:        - No root or real firewall required; pure functions only
#               - Covers audit findings 1.0.1 (re-validation), 1.0.3 (ufw
#                 fail-closed), and 1.1.5 (IPv6/ICMP construction)
# Version:      1.6.2
# ==============================================================================
"""Unit tests for backend defense-in-depth re-validation and fail-closed logic."""

from __future__ import annotations

import pytest

from apotropaios.core.errors import RuleApplyError, ValidationError
from apotropaios.firewall.firewalld import _build_rich_rule
from apotropaios.firewall.ipset import _validate_entry
from apotropaios.firewall.ufw import _map_action


# ==============================================================================
# ufw fail-closed action mapping (finding 1.0.3)
# ==============================================================================

class TestUfwActionMapping:
    """ufw action translation must fail closed on unsupported actions."""

    @pytest.mark.parametrize(
        "action,expected_verb",
        [
            ("accept", "allow"),
            ("allow", "allow"),
            ("drop", "deny"),
            ("deny", "deny"),
            ("reject", "reject"),
            ("limit", "limit"),
        ],
    )
    def test_supported_actions_map(self, action: str, expected_verb: str) -> None:
        verb, _ = _map_action(action)
        assert verb == expected_verb

    def test_log_only_maps_to_allow_with_log_flag(self) -> None:
        verb, has_log = _map_action("log")
        assert verb == "allow"
        assert has_log is True

    def test_compound_log_and_terminal(self) -> None:
        verb, has_log = _map_action("log,drop")
        assert verb == "deny"
        assert has_log is True

    @pytest.mark.parametrize(
        "action",
        ["masquerade", "snat", "dnat", "return", "bogus", "log,masquerade"],
    )
    def test_unsupported_actions_raise_not_default_allow(self, action: str) -> None:
        # Regression guard: these previously mapped silently to "allow"
        with pytest.raises(RuleApplyError):
            _map_action(action)


# ==============================================================================
# ipset per-set-type entry validation (finding 1.0.1)
# ==============================================================================

class TestIpsetEntryValidation:
    """ipset entries must be validated per set type, not merely comma-checked."""

    def test_hash_ip_accepts_valid_ip(self) -> None:
        assert _validate_entry("192.0.2.10", "hash:ip") is True

    def test_hash_ip_rejects_cidr(self) -> None:
        with pytest.raises(ValidationError):
            _validate_entry("192.0.2.0/24", "hash:ip")

    def test_hash_net_accepts_cidr_and_ip(self) -> None:
        assert _validate_entry("192.0.2.0/24", "hash:net") is True
        assert _validate_entry("192.0.2.10", "hash:net") is True

    def test_hash_ip_port_validates_components(self) -> None:
        assert _validate_entry("192.0.2.10,tcp:443", "hash:ip,port") is True
        assert _validate_entry("192.0.2.10,443", "hash:ip,port") is True

    def test_hash_ip_port_rejects_bad_port(self) -> None:
        with pytest.raises(ValidationError):
            _validate_entry("192.0.2.10,tcp:99999", "hash:ip,port")

    def test_hash_ip_port_rejects_bad_protocol(self) -> None:
        with pytest.raises(ValidationError):
            _validate_entry("192.0.2.10,bogus:443", "hash:ip,port")

    def test_hash_net_iface_validates_both(self) -> None:
        assert _validate_entry("192.0.2.0/24,eth0", "hash:net,iface") is True

    def test_hash_net_iface_rejects_bad_interface(self) -> None:
        with pytest.raises(ValidationError):
            _validate_entry("192.0.2.0/24,eth0;rm -rf", "hash:net,iface")

    def test_list_set_validates_set_name(self) -> None:
        assert _validate_entry("other_set", "list:set") is True

    def test_list_set_rejects_injection_name(self) -> None:
        with pytest.raises(ValidationError):
            _validate_entry("bad;name", "list:set")

    def test_missing_comma_rejected_for_paired_types(self) -> None:
        with pytest.raises(RuleApplyError):
            _validate_entry("192.0.2.10", "hash:ip,port")


# ==============================================================================
# firewalld rich-rule re-validation and IPv6 family (findings 1.0.1, 1.1.5)
# ==============================================================================

class TestFirewalldRichRule:
    """Rich-rule composition must re-validate interpolated values and derive family."""

    def test_ipv4_source_produces_ipv4_family(self) -> None:
        rich = _build_rich_rule(
            {"src_ip": "192.0.2.0/24", "action": "drop"}
        )
        assert 'rule family="ipv4"' in rich

    def test_ipv6_source_produces_ipv6_family(self) -> None:
        rich = _build_rich_rule(
            {"src_ip": "2001:db8::/32", "action": "drop"}
        )
        assert 'rule family="ipv6"' in rich

    def test_mixed_family_rejected(self) -> None:
        with pytest.raises(RuleApplyError):
            _build_rich_rule(
                {"src_ip": "192.0.2.1", "dst_ip": "2001:db8::1", "action": "drop"}
            )

    def test_log_prefix_with_quote_rejected(self) -> None:
        # Quote breakout attempt in an interpolated field must be rejected
        with pytest.raises(ValidationError):
            _build_rich_rule(
                {
                    "src_ip": "192.0.2.1",
                    "action": "accept,log",
                    "log_prefix": 'evil" drop; rule ',
                }
            )

    def test_invalid_syslog_level_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _build_rich_rule(
                {
                    "src_ip": "192.0.2.1",
                    "action": "accept,log",
                    "log_prefix": "ok",
                    "log_level": "notalevel",
                }
            )
