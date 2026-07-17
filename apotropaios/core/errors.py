# ==============================================================================
# File:         apotropaios/core/errors.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Error handling framework with exception hierarchy and cleanup stack
# Description:  Error handling infrastructure for the Apotropaios framework:
#               - Exception class hierarchy mapped to ErrorCode categories
#               - LIFO cleanup stack with idempotent execution
#               - Signal handler registration (SIGTERM, SIGINT, SIGHUP)
#               - Retry with exponential backoff and configurable cap
#               - Fallback execution (primary → fallback)
#               - Error context tracking for debugging
#               - Thread-safe cleanup operations via threading.Lock
#
#               Architecture notes:
#               - Every exception carries an ErrorCode for structured exit codes
#               - CleanupStack is a singleton -- one per process lifetime
#               - Signal handlers trigger cleanup then re-raise via sys.exit()
#               - atexit integration ensures cleanup runs on normal exit too
#               - Cleanup functions must be idempotent (safe to call multiple times)
#
# Notes:        - Requires apotropaios.core.constants (ErrorCode, Color)
#               - Logging is deferred: errors.py accepts an optional logger to
#                 avoid circular imports (errors.py loads before logging.py)
#               - All cleanup operations are guarded against recursion
#               - Parity target: bash v1.1.10 lib/core/errors.sh
# Version:      1.6.2
# ==============================================================================

from __future__ import annotations

import atexit
import signal
import sys
import threading
import time
import traceback
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any, Final, NoReturn, TypeVar

from apotropaios.core.constants import Color, ErrorCode


# ==============================================================================
# Type Variables
# ==============================================================================

T = TypeVar("T")


# ==============================================================================
# Exception Hierarchy
#
# Base exception carries an ErrorCode for structured exit code propagation.
# Subclasses map to error code categories from constants.py.
#
# Hierarchy:
#   ApotropaiosError (base)
#   ├── UsageError            (USAGE)
#   ├── PermissionError_      (PERMISSION) -- trailing underscore avoids builtin clash
#   ├── OSDetectionError      (OS_UNSUPPORTED)
#   ├── FirewallError         (FW_*)
#   │   ├── FirewallNotFoundError    (FW_NOT_FOUND)
#   │   ├── FirewallNotRunningError  (FW_NOT_RUNNING)
#   │   └── FirewallInstallError     (FW_INSTALL_FAIL)
#   ├── RuleError             (RULE_*)
#   │   ├── RuleInvalidError         (RULE_INVALID)
#   │   ├── RuleExistsError          (RULE_EXISTS)
#   │   ├── RuleNotFoundError        (RULE_NOT_FOUND)
#   │   ├── RuleApplyError           (RULE_APPLY_FAIL)
#   │   ├── RuleRemoveError          (RULE_REMOVE_FAIL)
#   │   └── RuleImportError          (RULE_IMPORT_FAIL)
#   ├── BackupError           (BACKUP_FAIL)
#   ├── RestoreError          (RESTORE_FAIL)
#   ├── BackupNotFoundError   (BACKUP_NOT_FOUND)
#   ├── ValidationError       (VALIDATION_FAIL)
#   ├── SanitizationError     (INPUT_SANITIZE_FAIL)
#   ├── LoggingError          (LOG_*)
#   ├── LockError             (LOCK_*)
#   │   └── LockTimeoutError         (LOCK_TIMEOUT)
#   ├── IntegrityError        (INTEGRITY_FAIL)
#   └── SignalReceivedError   (SIGNAL_RECEIVED)
# ==============================================================================


class ApotropaiosError(Exception):
    """Base exception for all Apotropaios framework errors.

    Every exception carries an ErrorCode that can be used as a process
    exit code via sys.exit(error.code).

    Attributes:
        code:    ErrorCode enum member for structured error identification.
        message: Human-readable error description.
        context: Optional dictionary of additional context key-value pairs.
    """

    def __init__(
        self,
        message: str,
        code: ErrorCode = ErrorCode.GENERAL,
        context: dict[str, Any] | None = None,
    ) -> None:
        self.code: Final[ErrorCode] = code
        self.message: Final[str] = message
        self.context: Final[dict[str, Any]] = context or {}
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        """Format the full error message including code and context.

        Returns:
            Formatted string with error code name, message, and any context.
        """
        parts: list[str] = [f"[{self.code.name}] {self.message}"]
        if self.context:
            ctx_str = " ".join(f"{k}={v}" for k, v in self.context.items())
            parts.append(f"({ctx_str})")
        return " ".join(parts)


# --- General errors ---

class UsageError(ApotropaiosError):
    """Invalid command-line usage or argument errors."""

    def __init__(self, message: str, **ctx: Any) -> None:
        super().__init__(message, ErrorCode.USAGE, ctx or None)


class PermissionError_(ApotropaiosError):
    """Insufficient privileges (e.g., not running as root).

    Note: Trailing underscore avoids shadowing Python's builtin PermissionError.
    """

    def __init__(self, message: str, **ctx: Any) -> None:
        super().__init__(message, ErrorCode.PERMISSION, ctx or None)


# --- OS / Firewall detection errors ---

class OSDetectionError(ApotropaiosError):
    """Operating system not supported or detection failure."""

    def __init__(self, message: str, **ctx: Any) -> None:
        super().__init__(message, ErrorCode.OS_UNSUPPORTED, ctx or None)


class FirewallError(ApotropaiosError):
    """Base class for firewall backend errors."""

    def __init__(
        self,
        message: str,
        code: ErrorCode = ErrorCode.FW_NOT_FOUND,
        **ctx: Any,
    ) -> None:
        super().__init__(message, code, ctx or None)


class FirewallNotFoundError(FirewallError):
    """Requested firewall backend is not installed."""

    def __init__(self, message: str, **ctx: Any) -> None:
        super().__init__(message, ErrorCode.FW_NOT_FOUND, **ctx)


class FirewallNotRunningError(FirewallError):
    """Firewall backend is installed but not running."""

    def __init__(self, message: str, **ctx: Any) -> None:
        super().__init__(message, ErrorCode.FW_NOT_RUNNING, **ctx)


class FirewallInstallError(FirewallError):
    """Firewall package installation or update failure."""

    def __init__(self, message: str, **ctx: Any) -> None:
        super().__init__(message, ErrorCode.FW_INSTALL_FAIL, **ctx)


# --- Rule errors ---

class RuleError(ApotropaiosError):
    """Base class for rule engine errors."""

    def __init__(
        self,
        message: str,
        code: ErrorCode = ErrorCode.RULE_INVALID,
        **ctx: Any,
    ) -> None:
        super().__init__(message, code, ctx or None)


class RuleInvalidError(RuleError):
    """Rule parameters fail validation."""

    def __init__(self, message: str, **ctx: Any) -> None:
        super().__init__(message, ErrorCode.RULE_INVALID, **ctx)


class RuleExistsError(RuleError):
    """Duplicate rule already exists in the index."""

    def __init__(self, message: str, **ctx: Any) -> None:
        super().__init__(message, ErrorCode.RULE_EXISTS, **ctx)


class RuleNotFoundError(RuleError):
    """Rule ID not found in the index."""

    def __init__(self, message: str, **ctx: Any) -> None:
        super().__init__(message, ErrorCode.RULE_NOT_FOUND, **ctx)


class RuleApplyError(RuleError):
    """Failed to apply rule to the firewall backend."""

    def __init__(self, message: str, **ctx: Any) -> None:
        super().__init__(message, ErrorCode.RULE_APPLY_FAIL, **ctx)


class RuleRemoveError(RuleError):
    """Failed to remove rule from the firewall backend."""

    def __init__(self, message: str, **ctx: Any) -> None:
        super().__init__(message, ErrorCode.RULE_REMOVE_FAIL, **ctx)


class RuleImportError(RuleError):
    """Rule import from configuration file failed."""

    def __init__(self, message: str, **ctx: Any) -> None:
        super().__init__(message, ErrorCode.RULE_IMPORT_FAIL, **ctx)


# --- Backup / Restore errors ---

class BackupError(ApotropaiosError):
    """Backup creation failure."""

    def __init__(self, message: str, **ctx: Any) -> None:
        super().__init__(message, ErrorCode.BACKUP_FAIL, ctx or None)


class RestoreError(ApotropaiosError):
    """Backup restore failure."""

    def __init__(self, message: str, **ctx: Any) -> None:
        super().__init__(message, ErrorCode.RESTORE_FAIL, ctx or None)


class BackupNotFoundError(ApotropaiosError):
    """Requested backup archive not found."""

    def __init__(self, message: str, **ctx: Any) -> None:
        super().__init__(message, ErrorCode.BACKUP_NOT_FOUND, ctx or None)


# --- Validation errors ---

class ValidationError(ApotropaiosError):
    """Input validation failure.

    Raised when user-supplied input does not match whitelist patterns
    or fails range/format checks.
    """

    def __init__(self, message: str, **ctx: Any) -> None:
        super().__init__(message, ErrorCode.VALIDATION_FAIL, ctx or None)


class SanitizationError(ApotropaiosError):
    """Input sanitization failure (dangerous characters detected)."""

    def __init__(self, message: str, **ctx: Any) -> None:
        super().__init__(message, ErrorCode.INPUT_SANITIZE_FAIL, ctx or None)


# --- Infrastructure errors ---

class LoggingError(ApotropaiosError):
    """Logging subsystem failure."""

    def __init__(
        self,
        message: str,
        code: ErrorCode = ErrorCode.LOG_FAIL,
        **ctx: Any,
    ) -> None:
        super().__init__(message, code, ctx or None)


class LockError(ApotropaiosError):
    """File locking failure."""

    def __init__(self, message: str, **ctx: Any) -> None:
        super().__init__(message, ErrorCode.LOCK_FAIL, ctx or None)


class LockTimeoutError(LockError):
    """File lock acquisition timed out."""

    def __init__(self, message: str, **ctx: Any) -> None:
        # Skip LockError.__init__ to set correct code directly
        ApotropaiosError.__init__(
            self, message, ErrorCode.LOCK_TIMEOUT, ctx or None
        )


class IntegrityError(ApotropaiosError):
    """Data integrity verification failure (checksum mismatch, etc.)."""

    def __init__(self, message: str, **ctx: Any) -> None:
        super().__init__(message, ErrorCode.INTEGRITY_FAIL, ctx or None)


class SignalReceivedError(ApotropaiosError):
    """Process received a termination signal."""

    def __init__(self, signal_name: str, **ctx: Any) -> None:
        super().__init__(
            f"Signal received: {signal_name}",
            ErrorCode.SIGNAL_RECEIVED,
            {"signal": signal_name, **ctx},
        )


# ==============================================================================
# Error Context Tracker
#
# Records the most recent error location for debugging.
# Thread-safe via threading.Lock.
# ==============================================================================

class ErrorContext:
    """Tracks the most recent error context for debugging.

    Records function name, line number, and exception details from the
    last error. Thread-safe for use with the expiry monitor daemon thread.

    Usage:
        error_context = ErrorContext()
        try:
            risky_operation()
        except Exception as exc:
            error_context.record(exc)
            # ... handle error ...
        print(error_context.get_formatted())
    """

    def __init__(self) -> None:
        self._lock: threading.Lock = threading.Lock()
        self._function: str = ""
        self._line: int = 0
        self._exception: str = ""
        self._traceback: str = ""

    def record(
        self,
        exc: BaseException | None = None,
        function: str = "",
        line: int = 0,
    ) -> None:
        """Record an error context snapshot.

        Args:
            exc:      The exception that occurred (optional).
            function: Function name where the error occurred.
            line:     Line number where the error occurred.
        """
        with self._lock:
            self._function = function
            self._line = line
            if exc is not None:
                self._exception = f"{type(exc).__name__}: {exc}"
                # format_exception(exc) works from any call site;
                # format_exc() only captures inside an except block and
                # yields "NoneType: None" elsewhere
                self._traceback = "".join(traceback.format_exception(exc))
            else:
                self._exception = ""
                self._traceback = ""

    def get_formatted(self) -> str:
        """Return the last error context as a formatted string.

        Includes function name, line number, exception summary, and
        truncated traceback when available.

        Returns:
            Formatted context string, or empty string if no error recorded.
        """
        with self._lock:
            parts: list[str] = []
            if self._function:
                parts.append(f"function={self._function}")
            if self._line:
                parts.append(f"line={self._line}")
            if self._exception:
                parts.append(f"exception={self._exception}")
            if self._traceback:
                # Include last 3 traceback lines for debugging context
                tb_lines = self._traceback.strip().splitlines()
                tail = tb_lines[-3:] if len(tb_lines) > 3 else tb_lines
                parts.append(f"traceback=[{'; '.join(l.strip() for l in tail)}]")
            return " ".join(parts)

    def get_traceback(self) -> str:
        """Return the full traceback from the last recorded error.

        Returns:
            Full traceback string, or empty string if none recorded.
        """
        with self._lock:
            return self._traceback

    def clear(self) -> None:
        """Reset the error context to empty state."""
        with self._lock:
            self._function = ""
            self._line = 0
            self._exception = ""
            self._traceback = ""


# Module-level singleton error context
error_context: Final[ErrorContext] = ErrorContext()


# ==============================================================================
# Cleanup Stack
#
# LIFO stack of cleanup functions executed on exit or signal.
# Thread-safe, idempotent, recursion-guarded.
# Replaces bash's _CLEANUP_STACK array + trap EXIT handler.
# ==============================================================================

class CleanupStack:
    """LIFO stack of cleanup functions executed on process exit or signal.

    Cleanup functions are called in reverse registration order (last-in,
    first-out). Each function must be idempotent -- it may be called more
    than once if signals race with normal exit.

    The stack registers itself with atexit on first use and sets up
    signal handlers via the SignalHandler class.

    Thread-safe: all operations are guarded by a threading.Lock.

    Usage:
        cleanup = CleanupStack()
        cleanup.register(lambda: print("cleaning up temp files"))
        cleanup.register(release_lock, "advisory lock release")
        # On exit, release_lock runs first, then temp file cleanup
    """

    def __init__(self) -> None:
        self._stack: list[tuple[Callable[[], Any], str]] = []
        # RLock (not Lock): the signal handler runs execute_all() in the
        # main thread between bytecodes. If the signal interrupts a frame
        # that already holds this lock (e.g., inside register()), a
        # non-reentrant lock would deadlock the process (CWE-833).
        self._lock: threading.RLock = threading.RLock()
        self._in_progress: bool = False
        self._atexit_registered: bool = False
        # Logger reference -- set after logging module initializes to avoid
        # circular import. Uses a simple callable that accepts (level, msg).
        self._log_fn: Callable[[str, str], None] | None = None

    def set_logger(self, log_fn: Callable[[str, str], None]) -> None:
        """Set the logging function after the logging module initializes.

        Args:
            log_fn: Callable accepting (level: str, message: str).
                    Typically a bound method from the framework logger.
        """
        self._log_fn = log_fn

    def _log(self, level: str, message: str) -> None:
        """Emit a log message if a logger is available.

        Args:
            level:   Log level name (e.g., "debug", "warning").
            message: Log message text.
        """
        if self._log_fn is not None:
            try:
                self._log_fn(level, message)
            except Exception:
                # Logging must never prevent cleanup execution
                pass

    def register(
        self,
        func: Callable[[], Any],
        description: str = "",
    ) -> None:
        """Register a cleanup function to be called on exit.

        Functions are executed in LIFO order. The function must accept
        no arguments and must be idempotent.

        Args:
            func:        Callable to invoke during cleanup.
            description: Human-readable label for logging/debugging.
        """
        with self._lock:
            label = description or getattr(func, "__name__", repr(func))
            self._stack.append((func, label))
            self._log(
                "trace",
                f"Cleanup registered: {label} (stack depth: {len(self._stack)})",
            )

            # Register atexit handler on first use
            if not self._atexit_registered:
                atexit.register(self.execute_all)
                self._atexit_registered = True

    def unregister(self, func: Callable[[], Any]) -> bool:
        """Remove the first occurrence of a cleanup function.

        Args:
            func: The callable to remove from the stack.

        Returns:
            True if the function was found and removed, False otherwise.
        """
        with self._lock:
            for i, (registered_func, label) in enumerate(self._stack):
                if registered_func is func:
                    self._stack.pop(i)
                    self._log("trace", f"Cleanup unregistered: {label}")
                    return True
            return False

    def execute_all(self) -> None:
        """Execute all registered cleanup functions in LIFO order.

        Idempotent: prevents recursive execution if called during cleanup.
        Each function's failure is logged but does not prevent subsequent
        functions from running.
        """
        with self._lock:
            # Guard against recursive cleanup
            if self._in_progress:
                return
            self._in_progress = True
            # Take a snapshot and clear the stack under the lock
            stack_snapshot = list(self._stack)
            self._stack.clear()

        # Execute outside the lock to avoid deadlocks in cleanup functions
        if stack_snapshot:
            self._log(
                "debug",
                f"Executing {len(stack_snapshot)} cleanup handlers",
            )

        # LIFO order -- reverse the list
        for func, label in reversed(stack_snapshot):
            self._log("trace", f"Executing cleanup: {label}")
            try:
                func()
            except Exception as exc:
                self._log("warning", f"Cleanup function failed: {label} -- {exc}")

        with self._lock:
            self._in_progress = False

    @property
    def depth(self) -> int:
        """Current number of registered cleanup functions.

        Returns:
            Stack depth as integer.
        """
        with self._lock:
            return len(self._stack)


# Module-level singleton cleanup stack
cleanup_stack: Final[CleanupStack] = CleanupStack()


# ==============================================================================
# Signal Handler
#
# Registers OS signal handlers that trigger cleanup then exit.
# Maps SIGTERM → 143, SIGINT → 130, SIGHUP → 129 (128 + signal number).
# ==============================================================================

class SignalHandler:
    """OS signal handler that triggers cleanup stack execution on termination.

    Handles SIGTERM, SIGINT, and SIGHUP. On signal receipt:
    1. Logs the signal (if logger available)
    2. Prints user feedback for SIGINT (Ctrl+C)
    3. Executes the cleanup stack
    4. Exits with the standard signal exit code (128 + signal number)

    Must be initialized after CleanupStack is created.

    Usage:
        signal_handler = SignalHandler(cleanup_stack)
        signal_handler.install()
    """

    # Standard exit codes: 128 + signal number (Unix convention)
    _SIGNAL_EXIT_CODES: Final[dict[int, int]] = {
        signal.SIGTERM: 143,   # 128 + 15
        signal.SIGINT: 130,    # 128 + 2
        **({signal.SIGHUP: 129} if hasattr(signal, "SIGHUP") else {}),  # 128 + 1
    }

    def __init__(self, stack: CleanupStack) -> None:
        self._stack: CleanupStack = stack
        self._original_handlers: dict[int, Any] = {}
        self._installed: bool = False
        self._log_fn: Callable[[str, str], None] | None = None
        # Depth counter for interruptible scopes. While positive, SIGINT
        # raises KeyboardInterrupt into the running frame (interrupting the
        # current operation, which the interactive layer catches to recover)
        # instead of executing cleanup and terminating the process. The
        # counter is only touched from the main thread; signal handlers also
        # run in the main thread, so no lock is required.
        self._interruptible_depth: int = 0

    def set_logger(self, log_fn: Callable[[str, str], None]) -> None:
        """Set the logging function for signal events.

        Args:
            log_fn: Callable accepting (level: str, message: str).
        """
        self._log_fn = log_fn

    def _log(self, level: str, message: str) -> None:
        """Emit a log message if a logger is available."""
        if self._log_fn is not None:
            try:
                self._log_fn(level, message)
            except Exception:
                pass

    def install(self) -> None:
        """Install signal handlers for SIGTERM, SIGINT, and SIGHUP.

        Saves the original handlers for potential restoration. Safe to
        call multiple times -- subsequent calls are no-ops.

        Note: SIGHUP is only available on POSIX systems. On Windows,
        it is silently skipped.
        """
        if self._installed:
            return

        # Signals to handle -- SIGHUP may not exist on all platforms
        signals_to_handle: list[int] = [signal.SIGTERM, signal.SIGINT]
        if hasattr(signal, "SIGHUP"):
            signals_to_handle.append(signal.SIGHUP)

        for sig in signals_to_handle:
            try:
                self._original_handlers[sig] = signal.signal(
                    sig, self._handler
                )
            except (OSError, ValueError):
                # Cannot set handler (e.g., not main thread, or signal
                # not supported on this platform)
                pass

        self._installed = True
        self._log("debug", "Signal handlers installed (SIGTERM, SIGINT, SIGHUP)")

    @contextmanager
    def interruptible(self) -> Iterator[None]:
        """Scope in which SIGINT aborts the operation, not the process.

        Intended for interactive contexts: while the scope is active,
        Ctrl+C raises KeyboardInterrupt into the running frame so the
        caller can catch it and recover (for example, returning to the
        menu after aborting a package operation). Scopes nest; process
        termination semantics resume when the outermost scope exits.
        Non-interactive executions never enter a scope, so headless CLI
        behavior (cleanup then exit 130) is unchanged.
        """
        self._interruptible_depth += 1
        try:
            yield
        finally:
            self._interruptible_depth -= 1

    def uninstall(self) -> None:
        """Restore original signal handlers.

        Used during testing to prevent interference between test cases.
        """
        for sig, handler in self._original_handlers.items():
            try:
                signal.signal(sig, handler)
            except (OSError, ValueError):
                pass
        self._original_handlers.clear()
        self._installed = False

    def _handler(self, signum: int, frame: Any) -> None:
        """Signal handler callback.

        Executes cleanup stack then exits with the appropriate code.

        Args:
            signum: Signal number received.
            frame:  Current stack frame (unused).
        """
        sig_name = signal.Signals(signum).name
        self._log("warning", f"Signal received: {sig_name} (pid={_getpid()})")

        # Inside an interruptible scope (interactive menu), SIGINT aborts
        # the current operation rather than the process: raising here
        # propagates KeyboardInterrupt into the interrupted frame, where the
        # interactive layer catches it and returns control to the menu.
        # SIGTERM and SIGHUP always terminate regardless of scope.
        if signum == signal.SIGINT and self._interruptible_depth > 0:
            self._log("info", "SIGINT in interruptible scope: aborting operation")
            raise KeyboardInterrupt

        # User feedback for Ctrl+C
        if signum == signal.SIGINT:
            sys.stderr.write(
                f"\n{Color.YELLOW}Interrupt received. Cleaning up...{Color.RESET}\n"
            )

        # Execute cleanup
        self._stack.execute_all()

        # Exit with signal-specific code
        exit_code = self._SIGNAL_EXIT_CODES.get(signum, ErrorCode.SIGNAL_RECEIVED)
        sys.exit(exit_code)


def _getpid() -> int:
    """Get current process ID (extracted for testability).

    Returns:
        Current process ID.
    """
    import os
    return os.getpid()


# Module-level singleton signal handler
signal_handler: Final[SignalHandler] = SignalHandler(cleanup_stack)


# ==============================================================================
# Retry with Exponential Backoff
# ==============================================================================

def retry(
    func: Callable[..., T],
    *args: Any,
    max_retries: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 60.0,
    backoff_factor: float = 2.0,
    exceptions: tuple[type[BaseException], ...] = (Exception,),
    log_fn: Callable[[str, str], None] | None = None,
    context: str = "",
    **kwargs: Any,
) -> T:
    """Execute a function with retry logic and exponential backoff.

    Retries on specified exception types up to max_retries times. Delay
    between retries doubles each attempt (exponential backoff) up to
    max_delay.

    Args:
        func:            Callable to execute.
        *args:           Positional arguments passed to func.
        max_retries:     Maximum number of retry attempts.
        initial_delay:   Initial delay in seconds before first retry.
        max_delay:       Maximum delay cap in seconds.
        backoff_factor:  Multiplier for delay between retries.
        exceptions:      Tuple of exception types that trigger retries.
        log_fn:          Optional logging callable(level, message).
        context:         Description string for log messages.
        **kwargs:        Keyword arguments passed to func.

    Returns:
        Return value of func on successful execution.

    Raises:
        ValueError: If max_retries is less than 1.
        The last exception raised by func if all retries are exhausted.
    """
    if max_retries < 1:
        raise ValueError(f"max_retries must be >= 1 (got {max_retries})")

    delay = initial_delay
    last_exception: BaseException | None = None
    label = context or getattr(func, "__name__", repr(func))

    for attempt in range(1, max_retries + 1):
        if log_fn:
            log_fn("debug", f"Retry attempt {attempt}/{max_retries}: {label}")
        try:
            result: T = func(*args, **kwargs)
            if log_fn and attempt > 1:
                log_fn("debug", f"Retry succeeded on attempt {attempt}: {label}")
            return result
        except exceptions as exc:
            last_exception = exc
            if attempt < max_retries:
                if log_fn:
                    log_fn(
                        "warning",
                        f"Attempt {attempt} failed ({exc}), "
                        f"retrying in {delay:.1f}s: {label}",
                    )
                time.sleep(delay)
                # Exponential backoff with cap
                delay = min(delay * backoff_factor, max_delay)
            else:
                if log_fn:
                    log_fn(
                        "error",
                        f"All {max_retries} retry attempts failed: {label}",
                    )

    # All retries exhausted -- re-raise the last exception. Explicit check
    # rather than assert: asserts are stripped under -O, and raising None
    # would surface as an unrelated TypeError.
    if last_exception is None:
        raise RuntimeError("retry() exhausted without capturing an exception")
    raise last_exception


# ==============================================================================
# Fallback Execution
# ==============================================================================

def with_fallback(
    primary: Callable[[], T],
    fallback: Callable[[], T],
    context: str = "operation",
    log_fn: Callable[[str, str], None] | None = None,
) -> T:
    """Execute a primary function; on failure, execute a fallback.

    Args:
        primary:  Primary callable to attempt first.
        fallback: Fallback callable if primary raises an exception.
        context:  Description for log messages.
        log_fn:   Optional logging callable(level, message).

    Returns:
        Return value of whichever callable succeeds.

    Raises:
        The fallback's exception if both primary and fallback fail.
    """
    if log_fn:
        log_fn("debug", f"Executing primary: {context}")

    try:
        return primary()
    except Exception as primary_exc:
        if log_fn:
            log_fn(
                "warning",
                f"Primary failed ({primary_exc}), executing fallback: {context}",
            )

        try:
            result = fallback()
            if log_fn:
                log_fn("info", f"Fallback succeeded: {context}")
            return result
        except Exception as fallback_exc:
            if log_fn:
                log_fn(
                    "error",
                    f"Both primary and fallback failed: {context} "
                    f"(primary={primary_exc}, fallback={fallback_exc})",
                )
            raise


# ==============================================================================
# Fatal Error Helper
# ==============================================================================

def die(
    message: str,
    code: ErrorCode = ErrorCode.GENERAL,
    log_fn: Callable[[str, str], None] | None = None,
) -> NoReturn:
    """Log a critical error and exit the process immediately.

    Triggers cleanup stack execution via sys.exit() → atexit handlers.

    Args:
        message: Error message to log/display.
        code:    ErrorCode for the exit status.
        log_fn:  Optional logging callable(level, message).

    Raises:
        SystemExit: Always raised (never returns).
    """
    if log_fn:
        log_fn("critical", f"{message} (exit_code={code.value})")
    else:
        sys.stderr.write(
            f"{Color.RED}FATAL: {message} (exit_code={code.value}){Color.RESET}\n"
        )
    sys.exit(code.value)


# ==============================================================================
# Initialization Helper
# ==============================================================================

def init_error_handling(
    log_fn: Callable[[str, str], None] | None = None,
) -> None:
    """Initialize the error handling subsystem.

    Sets up the cleanup stack, signal handlers, and error context.
    Should be called once during framework startup, after the logging
    module is initialized.

    Args:
        log_fn: Optional logging callable(level, message) for the
                cleanup stack and signal handler to use.
    """
    if log_fn:
        cleanup_stack.set_logger(log_fn)
        signal_handler.set_logger(log_fn)

    signal_handler.install()

    if log_fn:
        log_fn("debug", "Error handling initialized with signal traps")
