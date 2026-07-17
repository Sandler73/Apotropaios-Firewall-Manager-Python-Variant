# ==============================================================================
# File:         tests/unit/test_constants.py
# Synopsis:     Verify constants module integrity and completeness
# Version:      1.2.1
# ==============================================================================

from apotropaios.core.constants import (
    ALL_ACTIONS, CLI_COMMANDS, CANCEL_KEYWORDS, Color,
    ConnState, DurationType, ErrorCode, IPTABLES_TABLES,
    IPSET_TYPES, LogLevel, NFTABLES_TABLE_FAMILIES,
    NON_TERMINAL_ACTIONS, Pattern, RuleAction, RuleDirection,
    RuleState, Security, SUPPORTED_FIREWALLS, SUPPORTED_FW_IDS,
    SUPPORTED_OS, SUPPORTED_OS_IDS, SyslogLevel, TERMINAL_ACTIONS,
    TTLLimits, VERSION,
)


class TestErrorCodes:
    def test_count(self) -> None:
        assert len(ErrorCode) == 27

    def test_success_is_zero(self) -> None:
        assert ErrorCode.SUCCESS == 0

    def test_ranges(self) -> None:
        assert ErrorCode.OS_UNSUPPORTED == 10
        assert ErrorCode.RULE_INVALID == 20
        assert ErrorCode.BACKUP_FAIL == 30
        assert ErrorCode.VALIDATION_FAIL == 40
        assert ErrorCode.LOG_FAIL == 50
        assert ErrorCode.LOCK_FAIL == 60
        assert ErrorCode.INTEGRITY_FAIL == 70
        assert ErrorCode.SIGNAL_RECEIVED == 80


class TestLogLevel:
    def test_ordering(self) -> None:
        assert LogLevel.TRACE < LogLevel.DEBUG < LogLevel.INFO
        assert LogLevel.INFO < LogLevel.WARNING < LogLevel.ERROR
        assert LogLevel.ERROR < LogLevel.CRITICAL < LogLevel.NONE

    def test_from_string(self) -> None:
        assert LogLevel.from_string("debug") == LogLevel.DEBUG
        assert LogLevel.from_string("INFO") == LogLevel.INFO

    def test_to_stdlib(self) -> None:
        assert LogLevel.DEBUG.to_stdlib_level() == 10
        assert LogLevel.INFO.to_stdlib_level() == 20


class TestSupportedOS:
    def test_count(self) -> None:
        assert len(SUPPORTED_OS) == 6

    def test_ids_match(self) -> None:
        assert SUPPORTED_OS_IDS == frozenset(
            {"ubuntu", "kali", "debian", "rocky", "almalinux", "arch"}
        )


class TestSupportedFirewalls:
    def test_count(self) -> None:
        assert len(SUPPORTED_FIREWALLS) == 5

    def test_ids(self) -> None:
        assert SUPPORTED_FW_IDS == frozenset(
            {"firewalld", "ipset", "iptables", "nftables", "ufw"}
        )


class TestRuleActions:
    def test_terminal_count(self) -> None:
        assert len(TERMINAL_ACTIONS) == 7

    def test_non_terminal(self) -> None:
        assert NON_TERMINAL_ACTIONS == frozenset({"log"})

    def test_all_actions(self) -> None:
        assert ALL_ACTIONS == TERMINAL_ACTIONS | NON_TERMINAL_ACTIONS


class TestPatterns:
    def test_ipv4_matches(self) -> None:
        assert Pattern.IPV4.fullmatch("192.168.1.1")
        assert not Pattern.IPV4.fullmatch("not_an_ip")

    def test_port_matches(self) -> None:
        assert Pattern.PORT.fullmatch("8080")
        assert not Pattern.PORT.fullmatch("abc")

    def test_rule_id_matches(self) -> None:
        assert Pattern.RULE_ID.fullmatch("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
        assert not Pattern.RULE_ID.fullmatch("not-a-uuid")


class TestCLICommands:
    def test_count(self) -> None:
        assert len(CLI_COMMANDS) == 21

    def test_contains_key_commands(self) -> None:
        for cmd in ("detect", "status", "add-rule", "backup", "menu", "help"):
            assert cmd in CLI_COMMANDS
