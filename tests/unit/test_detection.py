# ==============================================================================
# File:         tests/unit/test_detection.py
# Synopsis:     Unit tests for OS and firewall detection modules
# Version:      1.2.1
# ==============================================================================

import os
import pytest
from apotropaios.detection.os_detect import (
    OSDetectionResult, detect_os, _detect_os_release,
    _detect_lsb_release, _detect_uname, print_os_info,
)
from apotropaios.detection.fw_detect import (
    FWBackendStatus, FWDetectionResult, detect_firewalls, detect_single,
    print_fw_info,
)


class TestOSDetectionResult:
    def test_dataclass_defaults(self) -> None:
        r = OSDetectionResult()
        assert r.os_id == ""
        assert r.name == ""
        assert r.version == "unknown"
        assert r.supported is False
        assert r.pkg_manager == "unknown"

    def test_fields_exist(self) -> None:
        r = OSDetectionResult()
        for attr in ("os_id", "name", "version", "family", "pkg_manager", "supported", "method"):
            assert hasattr(r, attr)


class TestDetectOS:
    def test_returns_result(self) -> None:
        result = detect_os()
        assert isinstance(result, OSDetectionResult)
        assert result.os_id in ("ubuntu", "debian", "unknown", "")

    def test_has_name(self) -> None:
        result = detect_os()
        if result.os_id:
            assert result.name != ""

    def test_has_method(self) -> None:
        result = detect_os()
        if result.os_id:
            assert result.method != ""


class TestDetectFromOsRelease:
    def test_with_real_file(self) -> None:
        if os.path.exists("/etc/os-release"):
            result = OSDetectionResult()
            success = _detect_os_release(result)
            assert success
            assert result.name != ""

    def test_returns_bool(self) -> None:
        result = OSDetectionResult()
        ret = _detect_os_release(result)
        assert isinstance(ret, bool)


class TestDetectFromUname:
    def test_returns_bool(self) -> None:
        result = OSDetectionResult()
        ret = _detect_uname(result)
        assert isinstance(ret, bool)


class TestPrintOsInfo:
    def test_no_crash(self) -> None:
        result = detect_os()
        print_os_info(result)


class TestFWBackendStatus:
    def test_dataclass_defaults(self) -> None:
        r = FWBackendStatus()
        assert r.fw_id == ""
        assert r.installed is False
        assert r.version == "unknown"
        assert r.running is False
        assert r.enabled is False


class TestFWDetectionResult:
    def test_dataclass_defaults(self) -> None:
        r = FWDetectionResult()
        assert isinstance(r.backends, dict)
        assert r.count == 0

    def test_get_installed(self) -> None:
        r = FWDetectionResult()
        assert r.get_installed() == []


class TestDetectFirewall:
    def test_returns_result(self) -> None:
        result = detect_firewalls()
        assert isinstance(result, FWDetectionResult)

    def test_count_matches(self) -> None:
        result = detect_firewalls()
        installed = result.get_installed()
        assert result.count == len(installed)


class TestDetectSingleFirewall:
    def test_iptables(self) -> None:
        result = detect_single("iptables")
        assert isinstance(result, FWBackendStatus)
        assert result.fw_id == "iptables"

    def test_unknown_fw_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown firewall"):
            detect_single("nonexistent_fw")


class TestPrintFwInfo:
    def test_no_crash(self) -> None:
        result = detect_firewalls()
        print_fw_info(result)
