# ==============================================================================
# File:         tests/unit/test_security.py
# Synopsis:     Unit tests for security module
# Version:      1.2.1
# ==============================================================================

import os
import tempfile
import pytest
from apotropaios.core.errors import IntegrityError
from apotropaios.core.security import (
    FileLock, create_temp_dir, create_temp_file,
    file_checksum, generate_uuid, secure_dir, secure_file,
    verify_checksum,
)


class TestTempFiles:
    def test_temp_file_permissions(self) -> None:
        path = create_temp_file("test")
        assert os.path.exists(path)
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"
        os.unlink(path)

    def test_temp_dir_permissions(self) -> None:
        path = create_temp_dir("test")
        assert os.path.isdir(path)
        assert oct(os.stat(path).st_mode & 0o777) == "0o700"
        os.rmdir(path)


class TestChecksum:
    def test_generate_and_verify(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("Hello Apotropaios")
            path = f.name
        try:
            cs = file_checksum(path)
            assert len(cs) == 64
            assert verify_checksum(path, cs)
        finally:
            os.unlink(path)

    def test_mismatch_raises(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("test")
            path = f.name
        try:
            with pytest.raises(IntegrityError):
                verify_checksum(path, "0" * 64)
        finally:
            os.unlink(path)


class TestFileLock:
    def test_acquire_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            lock_path = os.path.join(tmpdir, "test.lock")
            lock = FileLock(lock_path)
            lock.acquire(timeout=2)
            assert lock.acquired
            lock.release()
            assert not lock.acquired

    def test_context_manager(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            lock_path = os.path.join(tmpdir, "test.lock")
            with FileLock(lock_path) as lock:
                assert lock.acquired
            assert not lock.acquired

    def test_double_release_safe(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            lock_path = os.path.join(tmpdir, "test.lock")
            lock = FileLock(lock_path)
            lock.acquire(timeout=2)
            lock.release()
            lock.release()  # Should not raise


class TestUUID:
    def test_format(self) -> None:
        uid = generate_uuid()
        assert len(uid) == 36
        assert uid.count("-") == 4

    def test_uniqueness(self) -> None:
        ids = {generate_uuid() for _ in range(100)}
        assert len(ids) == 100


class TestSecureDir:
    def test_creates_with_perms(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "secure_test")
            secure_dir(path)
            assert os.path.isdir(path)
            assert oct(os.stat(path).st_mode & 0o777) == "0o700"
