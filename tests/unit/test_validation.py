# ==============================================================================
# File:         tests/unit/test_validation.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Unit tests for the validation module (27 validators + sanitizer)
# Description:  Verifies all input validators and the sanitizer with valid and
#               invalid inputs, covering the whitelist boundaries.
# Version:      1.6.2
# ==============================================================================

import pytest

from apotropaios.core.errors import SanitizationError, ValidationError
from apotropaios.core.validation import (
    is_cancel_keyword,
    sanitize_input,
    validate_chain,
    validate_cidr,
    validate_conn_state,
    validate_description,
    validate_duration_type,
    validate_file_path,
    validate_hostname,
    validate_interface,
    validate_ip,
    validate_ipset_name,
    validate_ipv4,
    validate_ipv6,
    validate_log_level,
    validate_log_prefix,
    validate_numeric,
    validate_port,
    validate_port_range,
    validate_protocol,
    validate_rate_limit,
    validate_rule_action,
    validate_rule_direction,
    validate_rule_id,
    validate_syslog_level,
    validate_table,
    validate_table_family,
    validate_ttl,
    validate_zone,
)


# ==============================================================================
# Port Validation
# ==============================================================================

class TestValidatePort:
    def test_valid_ports(self) -> None:
        assert validate_port("1") == 1
        assert validate_port("80") == 80
        assert validate_port("443") == 443
        assert validate_port("8080") == 8080
        assert validate_port("65535") == 65535

    def test_invalid_ports(self) -> None:
        with pytest.raises(ValidationError):
            validate_port("")
        with pytest.raises(ValidationError):
            validate_port("0")
        with pytest.raises(ValidationError):
            validate_port("65536")
        with pytest.raises(ValidationError):
            validate_port("abc")
        with pytest.raises(ValidationError):
            validate_port("-1")
        with pytest.raises(ValidationError):
            validate_port("999999")


class TestValidatePortRange:
    def test_valid_ranges(self) -> None:
        assert validate_port_range("80-90") == (80, 90)
        assert validate_port_range("8080:8090") == (8080, 8090)
        assert validate_port_range("1-65535") == (1, 65535)

    def test_invalid_ranges(self) -> None:
        with pytest.raises(ValidationError):
            validate_port_range("")
        with pytest.raises(ValidationError):
            validate_port_range("90-80")  # reversed
        with pytest.raises(ValidationError):
            validate_port_range("abc")


# ==============================================================================
# IP Validation
# ==============================================================================

class TestValidateIPv4:
    def test_valid(self) -> None:
        assert validate_ipv4("192.168.1.1") == "192.168.1.1"
        assert validate_ipv4("0.0.0.0") == "0.0.0.0"
        assert validate_ipv4("255.255.255.255") == "255.255.255.255"
        assert validate_ipv4("10.0.0.1") == "10.0.0.1"

    def test_invalid(self) -> None:
        with pytest.raises(ValidationError):
            validate_ipv4("")
        with pytest.raises(ValidationError):
            validate_ipv4("256.1.1.1")
        with pytest.raises(ValidationError):
            validate_ipv4("192.168.01.1")  # leading zeros
        with pytest.raises(ValidationError):
            validate_ipv4("not.an.ip.addr")
        with pytest.raises(ValidationError):
            validate_ipv4("1.2.3")


class TestValidateIPv6:
    def test_valid(self) -> None:
        assert validate_ipv6("::1") == "::1"
        assert validate_ipv6("fe80::1") == "fe80::1"

    def test_invalid(self) -> None:
        with pytest.raises(ValidationError):
            validate_ipv6("")


class TestValidateIP:
    def test_valid_v4(self) -> None:
        assert validate_ip("10.0.0.1") == "10.0.0.1"

    def test_valid_v6(self) -> None:
        assert validate_ip("::1") == "::1"

    def test_invalid(self) -> None:
        with pytest.raises(ValidationError):
            validate_ip("garbage")


class TestValidateCIDR:
    def test_valid(self) -> None:
        assert validate_cidr("192.168.0.0/24") == "192.168.0.0/24"
        assert validate_cidr("10.0.0.0/8") == "10.0.0.0/8"
        assert validate_cidr("fd00::/64") == "fd00::/64"

    def test_invalid(self) -> None:
        with pytest.raises(ValidationError):
            validate_cidr("")
        with pytest.raises(ValidationError):
            validate_cidr("10.0.0.0/33")  # IPv4 prefix too large
        with pytest.raises(ValidationError):
            validate_cidr("10.0.0.0")  # no prefix


# ==============================================================================
# Protocol and Network Names
# ==============================================================================

class TestValidateProtocol:
    def test_valid(self) -> None:
        assert validate_protocol("tcp") == "tcp"
        assert validate_protocol("UDP") == "udp"
        assert validate_protocol("icmp") == "icmp"
        assert validate_protocol("all") == "all"

    def test_invalid(self) -> None:
        with pytest.raises(ValidationError):
            validate_protocol("invalid")
        with pytest.raises(ValidationError):
            validate_protocol("")


class TestValidateHostname:
    def test_valid(self) -> None:
        assert validate_hostname("example.com") == "example.com"
        assert validate_hostname("localhost") == "localhost"
        assert validate_hostname("sub.domain.example.com")

    def test_invalid(self) -> None:
        with pytest.raises(ValidationError):
            validate_hostname("")
        with pytest.raises(ValidationError):
            validate_hostname("evil;host")  # metachar


class TestValidateInterface:
    def test_valid(self) -> None:
        assert validate_interface("eth0") == "eth0"
        assert validate_interface("wlan0") == "wlan0"
        assert validate_interface("ens33") == "ens33"

    def test_invalid(self) -> None:
        with pytest.raises(ValidationError):
            validate_interface("")
        with pytest.raises(ValidationError):
            validate_interface("0eth")  # starts with digit


# ==============================================================================
# Path Validation
# ==============================================================================

class TestValidateFilePath:
    def test_valid(self) -> None:
        assert validate_file_path("/etc/config") == "/etc/config"
        assert validate_file_path("/home/user/file.txt")

    def test_traversal_rejected(self) -> None:
        with pytest.raises(ValidationError, match="traversal"):
            validate_file_path("/etc/../passwd")

    def test_metachar_rejected(self) -> None:
        with pytest.raises(ValidationError, match="metacharacters"):
            validate_file_path("/etc/;rm")

    def test_null_byte_rejected(self) -> None:
        with pytest.raises(ValidationError, match="null byte"):
            validate_file_path("/etc/config\x00evil")


# ==============================================================================
# Firewall Names
# ==============================================================================

class TestValidateZone:
    def test_valid(self) -> None:
        assert validate_zone("public") == "public"
        assert validate_zone("my-zone") == "my-zone"

    def test_invalid(self) -> None:
        with pytest.raises(ValidationError):
            validate_zone("")


class TestValidateChain:
    def test_valid(self) -> None:
        assert validate_chain("INPUT") == "INPUT"
        assert validate_chain("my-chain") == "my-chain"

    def test_invalid(self) -> None:
        with pytest.raises(ValidationError):
            validate_chain("")


class TestValidateTable:
    def test_valid(self) -> None:
        assert validate_table("filter") == "filter"

    def test_invalid(self) -> None:
        with pytest.raises(ValidationError):
            validate_table("")


class TestValidateTableFamily:
    def test_valid(self) -> None:
        assert validate_table_family("inet") == "inet"
        assert validate_table_family("IP") == "ip"
        assert validate_table_family("ip6") == "ip6"

    def test_invalid(self) -> None:
        with pytest.raises(ValidationError):
            validate_table_family("invalid")


class TestValidateIpsetName:
    def test_valid(self) -> None:
        assert validate_ipset_name("blocklist") == "blocklist"

    def test_invalid(self) -> None:
        with pytest.raises(ValidationError):
            validate_ipset_name("")


# ==============================================================================
# Rule Parameter Validation
# ==============================================================================

class TestValidateRuleId:
    def test_valid(self) -> None:
        assert validate_rule_id("a1b2c3d4-e5f6-7890-abcd-ef1234567890")

    def test_invalid(self) -> None:
        with pytest.raises(ValidationError):
            validate_rule_id("abc")
        with pytest.raises(ValidationError):
            validate_rule_id("")


class TestValidateRuleAction:
    def test_single_actions(self) -> None:
        assert validate_rule_action("accept") == "accept"
        assert validate_rule_action("DROP") == "drop"

    def test_compound_actions(self) -> None:
        assert validate_rule_action("log,drop") == "log,drop"
        assert validate_rule_action("LOG,ACCEPT") == "log,accept"

    def test_invalid_double_terminal(self) -> None:
        with pytest.raises(ValidationError, match="terminal"):
            validate_rule_action("accept,drop")

    def test_invalid_unknown(self) -> None:
        with pytest.raises(ValidationError):
            validate_rule_action("nuke")


class TestValidateRuleDirection:
    def test_valid(self) -> None:
        assert validate_rule_direction("inbound") == "inbound"
        assert validate_rule_direction("OUTBOUND") == "outbound"
        assert validate_rule_direction("forward") == "forward"

    def test_invalid(self) -> None:
        with pytest.raises(ValidationError):
            validate_rule_direction("sideways")


class TestValidateDurationType:
    def test_valid(self) -> None:
        assert validate_duration_type("permanent") == "permanent"
        assert validate_duration_type("TEMPORARY") == "temporary"

    def test_invalid(self) -> None:
        with pytest.raises(ValidationError):
            validate_duration_type("forever")


class TestValidateTTL:
    def test_valid(self) -> None:
        assert validate_ttl("60") == 60
        assert validate_ttl("2592000") == 2592000

    def test_invalid(self) -> None:
        with pytest.raises(ValidationError):
            validate_ttl("59")  # below min
        with pytest.raises(ValidationError):
            validate_ttl("2592001")  # above max
        with pytest.raises(ValidationError):
            validate_ttl("abc")


class TestValidateConnState:
    def test_valid(self) -> None:
        assert validate_conn_state("new") == "new"
        assert validate_conn_state("new,established") == "new,established"
        assert validate_conn_state("NEW,RELATED") == "new,related"

    def test_invalid(self) -> None:
        with pytest.raises(ValidationError):
            validate_conn_state("connected")


class TestValidateLogPrefix:
    def test_valid(self) -> None:
        assert validate_log_prefix("APO:BLOCK") == "APO:BLOCK"

    def test_too_long(self) -> None:
        with pytest.raises(ValidationError):
            validate_log_prefix("x" * 30)


class TestValidateRateLimit:
    def test_valid(self) -> None:
        assert validate_rate_limit("5/minute") == "5/minute"
        assert validate_rate_limit("100/day") == "100/day"

    def test_invalid(self) -> None:
        with pytest.raises(ValidationError):
            validate_rate_limit("fast")


class TestValidateLogLevel:
    def test_valid_name(self) -> None:
        assert validate_log_level("debug") == "DEBUG"
        assert validate_log_level("INFO") == "INFO"

    def test_valid_numeric(self) -> None:
        assert validate_log_level("2") == "INFO"

    def test_invalid(self) -> None:
        with pytest.raises(ValidationError):
            validate_log_level("verbose")


class TestValidateSyslogLevel:
    def test_valid(self) -> None:
        assert validate_syslog_level("emerg") == "emerg"
        assert validate_syslog_level("WARNING") == "warning"

    def test_invalid(self) -> None:
        with pytest.raises(ValidationError):
            validate_syslog_level("fatal")


class TestValidateNumeric:
    def test_valid(self) -> None:
        assert validate_numeric("42") == 42
        assert validate_numeric("5", min_value=1, max_value=10) == 5

    def test_out_of_range(self) -> None:
        with pytest.raises(ValidationError):
            validate_numeric("0", min_value=1)
        with pytest.raises(ValidationError):
            validate_numeric("11", max_value=10)


class TestValidateDescription:
    def test_valid(self) -> None:
        assert validate_description("Block SSH traffic") == "Block SSH traffic"
        assert validate_description("") == ""  # empty allowed

    def test_metachar_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_description("bad;desc")

    def test_too_long(self) -> None:
        with pytest.raises(ValidationError):
            validate_description("x" * 257)


# ==============================================================================
# Sanitizer
# ==============================================================================

class TestSanitizeInput:
    def test_strips_html(self) -> None:
        result = sanitize_input("Hello <script>World</script>")
        assert "<" not in result and ">" not in result

    def test_strips_metacharacters(self) -> None:
        result = sanitize_input("test;rm -rf")
        assert ";" not in result

    def test_trims_whitespace(self) -> None:
        assert sanitize_input("  spaces  ") == "spaces"

    def test_rejects_none(self) -> None:
        with pytest.raises(SanitizationError):
            sanitize_input(None)  # type: ignore[arg-type]

    def test_truncates_long_input(self) -> None:
        long_input = "a" * 5000
        result = sanitize_input(long_input)
        assert len(result) <= 4096


# ==============================================================================
# Cancel Keywords
# ==============================================================================

class TestIsCancelKeyword:
    def test_cancel_words(self) -> None:
        assert is_cancel_keyword("q")
        assert is_cancel_keyword("QUIT")
        assert is_cancel_keyword(" Cancel ")
        assert is_cancel_keyword("back")
        assert is_cancel_keyword("b")

    def test_non_cancel(self) -> None:
        assert not is_cancel_keyword("yes")
        assert not is_cancel_keyword("443")
        assert not is_cancel_keyword("")
