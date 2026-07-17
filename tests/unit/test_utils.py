# ==============================================================================
# File:         tests/unit/test_utils.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Unit tests for utilities module
# Description:  Verifies formatting, timing, parallel execution, and filesystem
#               helper functions.
# Version:      1.6.2
# ==============================================================================

import os
import tempfile
from apotropaios.core.utils import (
    file_age_seconds, human_bytes, human_duration, is_command_available,
    parse_iso_timestamp, read_kv_file, timestamp, timestamp_epoch,
    timestamp_filename, write_kv_file,
)


class TestTimestamps:
    def test_iso_format(self) -> None:
        ts = timestamp()
        assert "T" in ts and ts.endswith("Z")

    def test_epoch(self) -> None:
        assert timestamp_epoch() > 1700000000

    def test_filename_safe(self) -> None:
        ts = timestamp_filename()
        assert ":" not in ts and "T" in ts

    def test_parse_roundtrip(self) -> None:
        ts = timestamp()
        parsed = parse_iso_timestamp(ts)
        assert parsed is not None

    def test_parse_invalid(self) -> None:
        assert parse_iso_timestamp("invalid") is None


class TestHumanDuration:
    def test_seconds_only(self) -> None:
        assert human_duration(30) == "30s"

    def test_minutes(self) -> None:
        assert human_duration(90) == "1m 30s"

    def test_hours(self) -> None:
        assert human_duration(3661) == "1h 1m 1s"

    def test_days(self) -> None:
        assert human_duration(86400 + 3600 + 60 + 1) == "1d 1h 1m 1s"

    def test_zero(self) -> None:
        assert human_duration(0) == "0s"


class TestHumanBytes:
    def test_bytes(self) -> None:
        assert human_bytes(512) == "512 B"

    def test_kilobytes(self) -> None:
        assert human_bytes(1024) == "1.0 KB"

    def test_megabytes(self) -> None:
        assert human_bytes(1048576) == "1.0 MB"

    def test_gigabytes(self) -> None:
        assert human_bytes(1073741824) == "1.0 GB"


class TestKVFile:
    def test_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.kv")
            data = {"key1": "val1", "key2": "val2"}
            write_kv_file(path, data, header="Test")
            loaded = read_kv_file(path)
            assert loaded == data

    def test_file_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.kv")
            write_kv_file(path, {"k": "v"})
            assert oct(os.stat(path).st_mode & 0o777) == "0o600"


class TestCommandAvailability:
    def test_python_exists(self) -> None:
        assert is_command_available("python3")

    def test_nonexistent(self) -> None:
        assert not is_command_available("nonexistent_binary_xyz")


class TestFileAge:
    def test_fresh_file(self) -> None:
        with tempfile.NamedTemporaryFile() as f:
            age = file_age_seconds(f.name)
            assert 0 <= age <= 2

    def test_nonexistent(self) -> None:
        assert file_age_seconds("/nonexistent") == -1
