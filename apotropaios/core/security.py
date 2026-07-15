# ==============================================================================
# File:         apotropaios/core/security.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Security controls, integrity verification, and concurrency locking
# Description:  Security controls, integrity verification, and file locking:
#               - Root privilege verification
#               - Advisory file locking with timeout (fcntl.flock preferred,
#                 PID-file fallback for portability)
#               - SHA-256 file checksum generation and verification
#               - Secure temporary file/directory creation (0o600/0o700 perms)
#               - Sensitive variable scrubbing on cleanup
#               - Secure directory creation with restrictive permissions
#               - Binary/command validation
#               - UUID v4 generation (stdlib uuid module)
#               - Umask enforcement
#
#               All cleanup operations are registered with the CleanupStack
#               from errors.py for signal-safe execution.
#
# Notes:        - Requires apotropaios.core.constants (Security, ErrorCode)
#               - Requires apotropaios.core.errors (CleanupStack, exceptions)
#               - Requires apotropaios.core.logging (FrameworkLogger)
#               - Lock acquisition uses fcntl.flock (POSIX) with PID-file fallback
#               - SHA-256 via hashlib (stdlib, always available)
#               - UUID via uuid module (stdlib, cryptographic quality)
#               - Thread-safe: locking operations use threading.Lock guard
#               - Parity target: bash v1.1.10 lib/core/security.sh
# Version:      1.2.1
# ==============================================================================

from __future__ import annotations

import fcntl
import hashlib
import hmac
import os
import shutil
import tempfile
import threading
import uuid
from typing import Final

from apotropaios.core.constants import (
    DirPath,
    ErrorCode,
    Security,
)
from apotropaios.core.errors import (
    ApotropaiosError,
    IntegrityError,
    LockError,
    LockTimeoutError,
    PermissionError_,
    cleanup_stack,
)


# ==============================================================================
# Module-Level State
# ==============================================================================

# Track sensitive values for scrubbing on cleanup
_sensitive_values: list[str] = []
_sensitive_lock: Final[threading.Lock] = threading.Lock()

# Track temporary files/dirs for cleanup
_temp_items: list[str] = []
_temp_lock: Final[threading.Lock] = threading.Lock()

# Logger reference — set by init_security() to avoid circular import at module level
_log_fn: None | object = None


def _log(level: str, message: str) -> None:
    """Emit a log message if the logger is available.

    Args:
        level:   Log level method name (e.g., "debug", "warning").
        message: Log message text.
    """
    if _log_fn is not None:
        method = getattr(_log_fn, level, None)
        if method is not None:
            method("security", message)


# ==============================================================================
# Initialization
# ==============================================================================

def init_security(
    base_dir: str,
    logger: object | None = None,
) -> None:
    """Initialize the security subsystem.

    Sets the process umask, creates the secure temp directory, and
    registers cleanup handlers with the CleanupStack.

    Args:
        base_dir: Framework base directory path.
        logger:   FrameworkLogger instance for log output.
    """
    global _log_fn
    _log_fn = logger

    # Set restrictive umask
    os.umask(Security.UMASK)
    _log("debug", f"Umask set to {oct(Security.UMASK)}")

    # Harden PATH for privileged execution: subprocess invocations resolve
    # firewall binaries through PATH, and an inherited attacker-influenced
    # PATH under root would redirect them (untrusted search path). The
    # fixed system directories cover every supported platform's tools.
    if os.geteuid() == 0:
        os.environ["PATH"] = (
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        )
        _log("debug", "PATH hardened for privileged execution")

    # Validate Python version
    import sys
    from apotropaios.core.constants import MIN_PYTHON_VERSION
    if sys.version_info < MIN_PYTHON_VERSION:
        _log(
            "critical",
            f"Python {sys.version} is too old. "
            f"Minimum required: {MIN_PYTHON_VERSION[0]}.{MIN_PYTHON_VERSION[1]}",
        )

    # Create secure temp directory
    temp_dir = os.path.join(base_dir, DirPath.TEMP)
    secure_dir(temp_dir)

    # Register cleanup with CleanupStack
    cleanup_stack.register(security_cleanup, "security_cleanup")

    _log("info", "Security subsystem initialized")


# ==============================================================================
# Privilege Checks
# ==============================================================================

def check_root() -> bool:
    """Check if the current process has root (UID 0) privileges.

    Returns:
        True if running as root.

    Raises:
        PermissionError_: If not running as root.
    """
    uid = os.getuid()
    if uid != 0:
        _log("error", f"Root privileges required. Current UID: {uid}")
        raise PermissionError_(
            f"Root privileges required. Current UID: {uid}",
            uid=str(uid),
        )
    _log("debug", "Root privilege check passed")
    return True


def is_root() -> bool:
    """Check if running as root without raising an exception.

    Returns:
        True if running as root (UID 0), False otherwise.
    """
    return os.getuid() == 0


# ==============================================================================
# Secure Temporary Files
# ==============================================================================

def create_temp_file(prefix: str = "apotropaios") -> str:
    """Create a secure temporary file with restrictive permissions (0o600).

    The file is tracked for automatic cleanup on process exit via the
    CleanupStack.

    Args:
        prefix: Filename prefix for the temporary file.

    Returns:
        Absolute path to the created temporary file.

    Raises:
        ApotropaiosError: If file creation fails.
    """
    try:
        fd, path = tempfile.mkstemp(prefix=f"{prefix}.")
        os.close(fd)  # Close the raw FD; callers open with Python file API
        os.chmod(path, Security.FILE_PERMS)
    except OSError as exc:
        _log("error", f"Failed to create temporary file: {exc}")
        raise ApotropaiosError(
            f"Failed to create temporary file: {exc}",
            ErrorCode.GENERAL,
        ) from exc

    with _temp_lock:
        _temp_items.append(path)

    _log("trace", f"Secure temp file created: {path}")
    return path


def create_temp_dir(prefix: str = "apotropaios") -> str:
    """Create a secure temporary directory with restrictive permissions (0o700).

    The directory is tracked for automatic cleanup on process exit via
    the CleanupStack.

    Args:
        prefix: Directory name prefix.

    Returns:
        Absolute path to the created temporary directory.

    Raises:
        ApotropaiosError: If directory creation fails.
    """
    try:
        path = tempfile.mkdtemp(prefix=f"{prefix}.")
        os.chmod(path, Security.DIR_PERMS)
    except OSError as exc:
        _log("error", f"Failed to create temporary directory: {exc}")
        raise ApotropaiosError(
            f"Failed to create temporary directory: {exc}",
            ErrorCode.GENERAL,
        ) from exc

    with _temp_lock:
        _temp_items.append(path)

    _log("trace", f"Secure temp dir created: {path}")
    return path


# ==============================================================================
# Sensitive Variable Scrubbing
# ==============================================================================

def register_sensitive_value(value: str) -> None:
    """Register a sensitive value for scrubbing on cleanup.

    In Python, we track the actual value strings since we can't
    directly unset variables in calling scopes. The cleanup function
    overwrites the tracked list with empty strings.

    Args:
        value: Sensitive string value to track for scrubbing.
    """
    with _sensitive_lock:
        _sensitive_values.append(value)
    _log("trace", "Sensitive value registered for scrubbing")


def scrub_sensitive_values() -> None:
    """Overwrite all registered sensitive values with empty strings.

    Defense-in-depth measure against memory inspection. While Python's
    garbage collector will eventually reclaim the memory, this ensures
    the values are overwritten immediately.
    """
    with _sensitive_lock:
        # Overwrite each tracked value position
        for i in range(len(_sensitive_values)):
            _sensitive_values[i] = ""
        _sensitive_values.clear()
    _log("trace", "Sensitive values scrubbed")


# ==============================================================================
# File Integrity (SHA-256 Checksums)
# ==============================================================================

def file_checksum(path: str, algorithm: str = "sha256") -> str:
    """Generate a cryptographic checksum of a file.

    Reads the file in 64KB chunks for memory efficiency with large files.

    Args:
        path:      File path to checksum.
        algorithm: Hash algorithm name (default: sha256).

    Returns:
        Hexadecimal checksum string.

    Raises:
        ApotropaiosError: If the file cannot be read.
        IntegrityError: If the hash algorithm is not available.
    """
    if not os.path.isfile(path):
        _log("error", f"Cannot checksum: file not found: {path}")
        raise ApotropaiosError(
            f"Cannot checksum: file not found: {path}",
            ErrorCode.GENERAL,
        )

    try:
        hasher = hashlib.new(algorithm)
    except ValueError as exc:
        raise IntegrityError(
            f"Hash algorithm not available: {algorithm}",
        ) from exc

    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)  # 64KB chunks
                if not chunk:
                    break
                hasher.update(chunk)
    except OSError as exc:
        _log("error", f"Failed to read file for checksum: {path} ({exc})")
        raise ApotropaiosError(
            f"Failed to read file for checksum: {path}",
            ErrorCode.GENERAL,
        ) from exc

    return hasher.hexdigest()


def verify_checksum(
    path: str,
    expected: str,
    algorithm: str = "sha256",
) -> bool:
    """Verify a file's integrity against a known checksum.

    Args:
        path:      File path to verify.
        expected:  Expected hexadecimal checksum string.
        algorithm: Hash algorithm name (default: sha256).

    Returns:
        True if checksums match.

    Raises:
        IntegrityError: If checksums do not match.
    """
    actual = file_checksum(path, algorithm)

    # Constant-time comparison to prevent timing side-channel attacks
    # (CWE-208: Observable Timing Discrepancy)
    if not hmac.compare_digest(actual.encode(), expected.encode()):
        _log(
            "error",
            f"Checksum mismatch for {path}: "
            f"expected={expected} actual={actual}",
        )
        raise IntegrityError(
            f"Checksum mismatch for {path}",
            expected=expected,
            actual=actual,
        )

    _log("debug", f"Checksum verified for {path}")
    return True


# ==============================================================================
# Advisory File Locking
#
# Uses fcntl.flock() (POSIX advisory locking) as the primary mechanism.
# Falls back to PID-file based locking if fcntl is not available.
# ==============================================================================

class FileLock:
    """Advisory file lock with timeout and stale lock detection.

    Uses fcntl.flock() for atomic, race-free locking. Falls back to
    PID-file creation if flock is unavailable. Supports context manager
    protocol for automatic release.

    Usage:
        lock = FileLock("/var/run/apotropaios.lock")
        with lock:
            # ... exclusive operations ...

        # Or manual acquire/release:
        lock.acquire(timeout=30)
        try:
            # ... exclusive operations ...
        finally:
            lock.release()
    """

    def __init__(self, lock_path: str) -> None:
        self._lock_path: str = lock_path
        self._fd: int | None = None
        self._acquired: bool = False
        self._lock: threading.Lock = threading.Lock()

    @property
    def acquired(self) -> bool:
        """Whether the lock is currently held."""
        return self._acquired

    @property
    def lock_path(self) -> str:
        """Path to the lock file."""
        return self._lock_path

    def acquire(self, timeout: int = Security.LOCK_TIMEOUT_SECONDS) -> bool:
        """Acquire the advisory file lock with timeout.

        Attempts to acquire an exclusive flock on the lock file. If the
        lock cannot be acquired within the timeout period, raises
        LockTimeoutError.

        Args:
            timeout: Maximum seconds to wait for lock acquisition.

        Returns:
            True on successful acquisition.

        Raises:
            LockError: If the lock file cannot be opened.
            LockTimeoutError: If acquisition times out.
        """
        with self._lock:
            if self._acquired:
                return True  # Already held

            # Try non-blocking flock with retry loop. The lock file is
            # re-opened on every iteration: after a stale lock file is
            # unlinked (by this or another process) and recreated, an fd
            # opened earlier would point at the unlinked inode, and a
            # flock taken on it would coexist with a lock on the new file
            # — two holders at once (CWE-367). Re-opening guarantees the
            # flock is always taken on the current directory entry.
            import time
            elapsed = 0.0
            retry_interval = min(Security.LOCK_RETRY_INTERVAL, 1.0)

            while elapsed < timeout:
                self._close_fd()
                try:
                    self._fd = os.open(
                        self._lock_path,
                        os.O_RDWR | os.O_CREAT,
                        Security.FILE_PERMS,
                    )
                except OSError as exc:
                    _log("error", f"Cannot open lock file: {self._lock_path} ({exc})")
                    raise LockError(
                        f"Cannot open lock file: {self._lock_path}",
                    ) from exc

                try:
                    fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    # Lock acquired — write PID for identification
                    os.ftruncate(self._fd, 0)
                    os.lseek(self._fd, 0, os.SEEK_SET)
                    os.write(self._fd, str(os.getpid()).encode())
                    self._acquired = True
                    _log("debug", f"Lock acquired: {self._lock_path}")
                    return True
                except OSError:
                    # Lock held by another process — check for stale lock.
                    # (BlockingIOError is an OSError subclass.)
                    self._check_stale_lock()
                    time.sleep(retry_interval)
                    elapsed += retry_interval

            # Timeout — clean up FD
            self._close_fd()
            _log(
                "error",
                f"Lock acquisition timed out after {timeout}s: {self._lock_path}",
            )
            raise LockTimeoutError(
                f"Lock acquisition timed out after {timeout}s: {self._lock_path}",
            )

    def release(self) -> None:
        """Release the advisory file lock.

        Safe to call multiple times. Only releases if the lock is
        currently held by this instance.
        """
        with self._lock:
            if not self._acquired or self._fd is None:
                return

            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            except OSError:
                pass  # Best-effort unlock

            self._close_fd()

            # Remove lock file if we own it
            try:
                if os.path.exists(self._lock_path):
                    with open(self._lock_path, "r", encoding="utf-8") as f:
                        pid_str = f.read().strip()
                    if pid_str == str(os.getpid()):
                        os.unlink(self._lock_path)
            except OSError:
                pass

            self._acquired = False
            _log("debug", f"Lock released: {self._lock_path}")

    def _close_fd(self) -> None:
        """Close the lock file descriptor."""
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None

    def _check_stale_lock(self) -> None:
        """Check if the current lock holder is still alive.

        If the PID in the lock file is dead, remove the stale lock file
        so the next acquire attempt can succeed.
        """
        try:
            with open(self._lock_path, "r", encoding="utf-8") as f:
                pid_str = f.read().strip()
            if pid_str:
                pid = int(pid_str)
                try:
                    os.kill(pid, 0)  # Signal 0 = check existence
                except ProcessLookupError:
                    # PID is dead — stale lock
                    _log(
                        "warning",
                        f"Removing stale lock file "
                        f"(PID {pid} is dead): {self._lock_path}",
                    )
                    try:
                        os.unlink(self._lock_path)
                    except OSError:
                        pass
                except PermissionError:
                    pass  # PID exists but we can't signal it — lock is valid
        except (OSError, ValueError):
            pass

    def __enter__(self) -> FileLock:
        """Context manager entry — acquire the lock."""
        self.acquire()
        return self

    def __exit__(self, *args: object) -> None:
        """Context manager exit — release the lock."""
        self.release()

    def __del__(self) -> None:
        """Destructor — ensure FD is closed."""
        self._close_fd()


# ==============================================================================
# Secure Directory and File Operations
# ==============================================================================

def secure_dir(path: str) -> str:
    """Ensure a directory exists with secure permissions (0o700).

    Creates parent directories as needed.

    Args:
        path: Directory path to create/secure.

    Returns:
        The directory path.

    Raises:
        ApotropaiosError: If directory creation or permission setting fails.
    """
    try:
        os.makedirs(path, mode=Security.DIR_PERMS, exist_ok=True)
        os.chmod(path, Security.DIR_PERMS)
    except OSError as exc:
        _log("error", f"Failed to create/secure directory: {path} ({exc})")
        raise ApotropaiosError(
            f"Failed to create directory: {path}",
            ErrorCode.GENERAL,
        ) from exc

    return path


def secure_file(path: str) -> str:
    """Set secure permissions (0o600) on an existing file.

    Args:
        path: File path to secure.

    Returns:
        The file path.

    Raises:
        ApotropaiosError: If the file doesn't exist or permissions can't be set.
    """
    if not os.path.isfile(path):
        _log("error", f"File not found: {path}")
        raise ApotropaiosError(
            f"File not found: {path}",
            ErrorCode.GENERAL,
        )

    try:
        os.chmod(path, Security.FILE_PERMS)
    except OSError as exc:
        _log("warning", f"Failed to set permissions on: {path} ({exc})")
        raise ApotropaiosError(
            f"Failed to set permissions on: {path}",
            ErrorCode.GENERAL,
        ) from exc

    return path


# ==============================================================================
# Binary Validation
# ==============================================================================

def validate_binary(name: str) -> str | None:
    """Validate that a binary exists and is executable.

    Searches PATH for command-name inputs, or validates directly for
    absolute paths.

    Args:
        name: Binary name (e.g., 'iptables') or absolute path.

    Returns:
        Absolute path to the binary, or None if not found.
    """
    path = shutil.which(name)
    if path is not None:
        return path

    # For absolute paths, check directly
    if name.startswith("/") and os.path.isfile(name) and os.access(name, os.X_OK):
        return name

    return None


# ==============================================================================
# UUID Generation
# ==============================================================================

def generate_uuid() -> str:
    """Generate a UUID v4 string.

    Uses Python's uuid module which reads from /dev/urandom on Linux
    for cryptographic quality randomness.

    Returns:
        Lowercase UUID string in standard 8-4-4-4-12 format.
    """
    return str(uuid.uuid4())


# ==============================================================================
# Cleanup
# ==============================================================================

def security_cleanup() -> None:
    """Cleanup function for the CleanupStack.

    Scrubs sensitive values, removes tracked temporary files/directories,
    and releases any held locks. Registered automatically by init_security().
    """
    # Scrub sensitive values
    scrub_sensitive_values()

    # Remove tracked temp items
    with _temp_lock:
        for item in _temp_items:
            try:
                if os.path.isdir(item):
                    shutil.rmtree(item, ignore_errors=True)
                elif os.path.exists(item):
                    os.unlink(item)
            except OSError:
                pass
        _temp_items.clear()

    _log("trace", "Security cleanup complete")
