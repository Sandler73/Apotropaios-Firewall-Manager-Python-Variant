# ==============================================================================
# File:         tests/unit/test_audit_regressions.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Regression tests for principal-audit remediations
# Description:  Locks in the behavior corrected by the v1.0.x-v1.1.x audit
#               remediations so the defects cannot silently return: the
#               configuration-file trust gate (1.1.3), the RHEL-family
#               package-manager mapping (1.0.6), strict IPv6/CIDR validation
#               (1.0.9), the retry guard and ErrorContext traceback capture
#               (1.1.8), and log extra_context sanitization (1.0.4).
# Notes:        - Pure functions and filesystem fixtures only; no root needed
#               - Each test names the audit finding it guards
# Version:      1.6.2
# ==============================================================================
"""Regression tests guarding principal-audit remediations."""

from __future__ import annotations

import os

import pytest

from apotropaios.core.errors import ErrorContext, ValidationError, retry
from apotropaios.core.validation import validate_cidr, validate_ipv6
from apotropaios.detection.os_detect import OSDetectionResult, _determine_family


# ==============================================================================
# Configuration trust gate (finding 1.1.3)
# ==============================================================================

class TestConfigTrustGate:
    """The config loader must reject group/world-writable or foreign-owned files."""

    def test_trusted_file_is_loaded(self, tmp_path: object) -> None:
        from apotropaios.cli import _load_config

        base = str(tmp_path)
        conf_dir = os.path.join(base, "conf")
        os.makedirs(conf_dir)
        conf = os.path.join(conf_dir, "apotropaios.conf")
        with open(conf, "w", encoding="utf-8") as f:
            f.write("[firewall]\ndefault_backend = nftables\n")
        os.chmod(conf, 0o600)

        config = _load_config(base)
        assert config.get("firewall.default_backend") == "nftables"

    def test_world_writable_file_is_skipped(self, tmp_path: object) -> None:
        from apotropaios.cli import _load_config

        base = str(tmp_path)
        conf_dir = os.path.join(base, "conf")
        os.makedirs(conf_dir)
        conf = os.path.join(conf_dir, "apotropaios.conf")
        with open(conf, "w", encoding="utf-8") as f:
            f.write("[firewall]\ndefault_backend = nftables\n")
        with open(conf, "w", encoding="utf-8") as f2:
            f2.write("[firewall]\ndefault_backend = ufw\n")
        os.chmod(conf, 0o666)  # world-writable -- must be rejected

        config = _load_config(base)
        # The untrusted file's value must never be applied. If a trusted
        # shipped default follows in the search order it may supply its own
        # value, but never "ufw" from the rejected project-local file.
        assert config.get("firewall.default_backend") != "ufw"


# ==============================================================================
# RHEL-family package-manager mapping (finding 1.0.6)
# ==============================================================================

class TestDetermineFamily:
    """ID_LIKE-derived RHEL family must map to dnf, not the invalid 'rhel'."""

    def test_rhel_family_maps_to_dnf(self) -> None:
        result = OSDetectionResult()
        result.os_id = "some-derivative"
        result.family = "rhel"  # set by ID_LIKE parser, pkg_manager unknown
        result.pkg_manager = "unknown"
        _determine_family(result)
        assert result.pkg_manager == "dnf"

    def test_known_rhel_id_maps_to_dnf(self) -> None:
        result = OSDetectionResult()
        result.os_id = "rocky"
        _determine_family(result)
        assert result.family == "rhel"
        assert result.pkg_manager == "dnf"

    def test_debian_family_maps_to_apt(self) -> None:
        result = OSDetectionResult()
        result.os_id = "ubuntu"
        _determine_family(result)
        assert result.pkg_manager == "apt"


# ==============================================================================
# Strict IPv6 / CIDR validation (finding 1.0.9)
# ==============================================================================

class TestStrictIpValidation:
    """Malformed IPv6 forms and out-of-range prefixes must be rejected exactly."""

    @pytest.mark.parametrize("value", ["2001:db8::1", "::1", "fe80::"])
    def test_valid_ipv6_accepted(self, value: str) -> None:
        assert validate_ipv6(value) == value

    @pytest.mark.parametrize("value", [":::", "1::2::3", "2001:db8:::1"])
    def test_malformed_ipv6_rejected(self, value: str) -> None:
        with pytest.raises(ValidationError):
            validate_ipv6(value)

    def test_ipv4_cidr_prefix_range(self) -> None:
        assert validate_cidr("192.0.2.0/24") == "192.0.2.0/24"
        with pytest.raises(ValidationError):
            validate_cidr("192.0.2.0/33")

    def test_ipv6_cidr_prefix_range(self) -> None:
        assert validate_cidr("2001:db8::/32") == "2001:db8::/32"
        with pytest.raises(ValidationError):
            validate_cidr("2001:db8::/129")


# ==============================================================================
# retry guard and ErrorContext traceback capture (finding 1.1.8)
# ==============================================================================

class TestRetryGuard:
    """retry() must reject invalid counts and surface the real exception."""

    def test_zero_retries_rejected(self) -> None:
        with pytest.raises(ValueError):
            retry(lambda: None, max_retries=0)

    def test_successful_call_returns_value(self) -> None:
        assert retry(lambda: 42, max_retries=3) == 42

    def test_exhausted_retries_raise_original(self) -> None:
        attempts = {"n": 0}

        def always_fails() -> None:
            attempts["n"] += 1
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            retry(always_fails, max_retries=2, initial_delay=0.0)
        assert attempts["n"] == 2


class TestErrorContextTraceback:
    """ErrorContext.record must capture a real traceback from any call site."""

    def test_traceback_captured_outside_except(self) -> None:
        ctx = ErrorContext()
        exc = ValueError("captured out of band")
        ctx.record(exc)
        rendered = ctx.get_formatted()
        assert "ValueError" in rendered
        # The real traceback must be captured even outside an except block
        assert "NoneType: None" not in rendered


# ==============================================================================
# Log extra_context sanitization (finding 1.0.4)
# ==============================================================================

class TestLogSanitization:
    """The sanitizing filter must mask the structured extra_context field."""

    def test_extra_context_secret_is_masked(self) -> None:
        import logging as _logging

        from apotropaios.core.logging import _SanitizingFilter, _sanitizer

        filt = _SanitizingFilter(_sanitizer)
        record = _logging.LogRecord(
            name="test", level=_logging.INFO, pathname=__file__, lineno=1,
            msg="operation complete", args=None, exc_info=None,
        )
        record.extra_context = "api_key=SUPERSECRETVALUE"  # type: ignore[attr-defined]
        filt.filter(record)
        assert "SUPERSECRETVALUE" not in record.extra_context  # type: ignore[attr-defined]

    def test_extra_context_control_chars_removed(self) -> None:
        import logging as _logging

        from apotropaios.core.logging import _SanitizingFilter, _sanitizer

        filt = _SanitizingFilter(_sanitizer)
        record = _logging.LogRecord(
            name="test", level=_logging.INFO, pathname=__file__, lineno=1,
            msg="msg", args=None, exc_info=None,
        )
        record.extra_context = "line1\ninjected fake log line"  # type: ignore[attr-defined]
        filt.filter(record)
        assert "\n" not in record.extra_context  # type: ignore[attr-defined]
