# ==============================================================================
# File:         tests/unit/test_logging.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Unit tests for logging module
# Description:  Verifies logger initialization, sanitization, rotation settings,
#               and correlation identifiers.
# Version:      1.6.2
# ==============================================================================

import os
import tempfile
from apotropaios.core.constants import LogLevel
from apotropaios.core.logging import FrameworkLogger, LogSanitizer


class TestLogSanitizer:
    def setup_method(self) -> None:
        self.san = LogSanitizer()

    def test_kv_masking(self) -> None:
        result = self.san.sanitize("user=admin password=s3cret token=abc")
        assert "s3cret" not in result
        assert "abc" not in result
        assert "user=admin" in result

    def test_quoted_masking(self) -> None:
        result = self.san.sanitize('password="my secret"')
        assert "my secret" not in result

    def test_json_masking(self) -> None:
        result = self.san.sanitize('{"password": "s3cret", "name": "admin"}')
        assert "s3cret" not in result
        assert "admin" in result

    def test_auth_header_masking(self) -> None:
        result = self.san.sanitize("Authorization: Bearer eyJtoken123")
        assert "eyJtoken123" not in result

    def test_control_chars_stripped(self) -> None:
        result = self.san.sanitize("hello\x00world\x0btest")
        assert "\x00" not in result


class TestFrameworkLogger:
    def test_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log = FrameworkLogger()
            log.init(tmpdir, LogLevel.DEBUG)
            assert log.initialized
            assert log.correlation_id
            assert os.path.exists(log.log_file)
            log.info("test", "Test message")
            assert log.entry_count >= 1
            log.shutdown()
            assert not log.initialized

    def test_file_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log = FrameworkLogger()
            log.init(tmpdir, LogLevel.INFO)
            perms = oct(os.stat(log.log_file).st_mode & 0o777)
            assert perms == "0o600"
            log.shutdown()

    def test_sanitization_in_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log = FrameworkLogger()
            log.init(tmpdir, LogLevel.DEBUG)
            log.info("auth", "Login password=supersecret")
            log.shutdown()
            with open(log.log_file, encoding="utf-8") as f:
                contents = f.read()
            assert "supersecret" not in contents
            assert "MASKED" in contents

    def test_traversal_rejected(self) -> None:
        log = FrameworkLogger()
        log.init("/tmp/../../../etc/evil", LogLevel.INFO)
        assert not log.initialized

    def test_correlation_id_unique(self) -> None:
        ids = {FrameworkLogger.generate_correlation_id() for _ in range(100)}
        assert len(ids) == 100

    def test_level_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log = FrameworkLogger()
            log.init(tmpdir, LogLevel.INFO)
            log.set_level(LogLevel.WARNING)
            assert log.level == LogLevel.WARNING
            log.shutdown()
