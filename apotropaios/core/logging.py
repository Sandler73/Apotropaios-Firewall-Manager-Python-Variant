# ==============================================================================
# File:         apotropaios/core/logging.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Structured logging framework with file and console output
# Description:  Structured logging framework with dual output (file + console),
#               7 log levels (TRACE through NONE), dual output (console + file),
#               per-execution log files, log file rotation (size-based with
#               configurable retention), file handle tracking with recovery,
#               4-family sensitive data sanitization, and per-session correlation
#               IDs. Implements NIST SP 800-92 and OWASP logging best practices.
#
#               Key design decisions:
#               - Custom Logger class wraps stdlib logging for TRACE level support
#               - LogSanitizer is a dedicated class for the 4 masking families:
#                 key=value, quoted values, JSON, HTTP Authorization headers
#               - Per-execution log files (timestamped) with rotation by size
#               - Console output to stderr with ANSI color coding
#               - Thread-safe via stdlib logging's internal locks
#               - No external dependencies — stdlib only
#
# Notes:        - Requires apotropaios.core.constants (LogLevel, Security, Color)
#               - TRACE level (5) registered as custom stdlib logging level
#               - Log files written with 0o600 permissions
#               - All sensitive data masked before writing to any output
#               - Parity target: bash v1.1.10 lib/core/logging.sh
# Version:      1.2.1
# ==============================================================================

from __future__ import annotations

import logging
import os
import re
import secrets
import sys
import threading
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Final

from apotropaios.core.constants import (
    Color,
    LogLevel,
    Security,
)


# ==============================================================================
# Custom TRACE Level Registration
#
# Python's stdlib logging does not include a TRACE level. We register it
# once at module import to enable log.trace() calls throughout the framework.
# ==============================================================================

TRACE_LEVEL_NUM: Final[int] = 5  # Below DEBUG (10)

# Register TRACE level with stdlib logging (idempotent — safe to call multiple times)
if not hasattr(logging, "TRACE"):
    logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")
    logging.TRACE = TRACE_LEVEL_NUM  # type: ignore[attr-defined]


# ==============================================================================
# Log Sanitizer
#
# Masks sensitive data in 4 pattern families before log output.
# All patterns are compiled at class load time for performance.
# Thread-safe: compiled regex objects are immutable after compilation.
# ==============================================================================

class LogSanitizer:
    """Masks sensitive data patterns in log messages.

    Covers 4 families of sensitive data patterns:
    1. key=value:  password=xxx, token=xxx, secret=xxx, etc.
    2. Quoted:     password="xxx", token='xxx'
    3. JSON:       "password": "xxx", "token": "value"
    4. HTTP Auth:  Authorization: Bearer xxx, Basic xxx

    Also strips ASCII control characters (except newline and tab).

    Usage:
        sanitizer = LogSanitizer()
        clean_msg = sanitizer.sanitize("user=admin password=s3cret")
        # Result: "user=admin password=***MASKED***"
    """

    # Sensitive key names to mask (case-insensitive in patterns)
    _SENSITIVE_KEYS: Final[str] = (
        r"password|passwd|secret|token|key|apikey|api_key|"
        r"api_secret|access_key|private_key|credential"
    )

    _MASK: Final[str] = "***MASKED***"

    def __init__(self) -> None:
        # Family 1: key=value (unquoted, space-delimited)
        self._pattern_kv: re.Pattern[str] = re.compile(
            rf"({self._SENSITIVE_KEYS})=(\S+)",
            re.IGNORECASE,
        )

        # Family 2: key="quoted value" or key='quoted value'
        self._pattern_quoted_dbl: re.Pattern[str] = re.compile(
            rf'({self._SENSITIVE_KEYS})="[^"]*"',
            re.IGNORECASE,
        )
        self._pattern_quoted_sgl: re.Pattern[str] = re.compile(
            rf"({self._SENSITIVE_KEYS})='[^']*'",
            re.IGNORECASE,
        )

        # Family 3: JSON — "key": "value" (with optional whitespace)
        self._pattern_json: re.Pattern[str] = re.compile(
            rf'"({self._SENSITIVE_KEYS})"\s*:\s*"[^"]*"',
            re.IGNORECASE,
        )

        # Family 4: HTTP Authorization headers
        self._pattern_auth: re.Pattern[str] = re.compile(
            r"(Authorization)\s*:\s*(Bearer|Basic|Digest|Token)\s+\S+",
            re.IGNORECASE,
        )

        # Control character stripping (keep only tab \x09, strip everything
        # else in 0x00-0x1f including newline and CR to prevent log injection
        # attacks per CWE-117: Improper Output Neutralization for Logs)
        self._pattern_control: re.Pattern[str] = re.compile(
            r"[\x00-\x08\x0a-\x1f]"
        )

    def sanitize(self, message: str) -> str:
        """Sanitize a log message by masking sensitive data patterns.

        Processing order:
        1. Strip ASCII control characters (except newline, tab)
        2. Mask key=value patterns
        3. Mask key="quoted" patterns (double and single quotes)
        4. Mask JSON "key": "value" patterns
        5. Mask HTTP Authorization headers

        Args:
            message: Raw log message string.

        Returns:
            Sanitized message with sensitive values replaced by ***MASKED***.
        """
        # 1. Remove control characters
        msg = self._pattern_control.sub("", message)

        # 2. Mask key=value (do quoted first to avoid partial matches)
        # Family 2: quoted values
        msg = self._pattern_quoted_dbl.sub(
            rf'\1="{self._MASK}"', msg
        )
        msg = self._pattern_quoted_sgl.sub(
            rf"\1='{self._MASK}'", msg
        )

        # Family 3: JSON
        msg = self._pattern_json.sub(
            rf'"\1": "{self._MASK}"', msg
        )

        # Family 1: unquoted key=value (after quoted to avoid double-masking)
        msg = self._pattern_kv.sub(
            rf"\1={self._MASK}", msg
        )

        # Family 4: HTTP Authorization
        msg = self._pattern_auth.sub(
            rf"\1: \2 {self._MASK}", msg
        )

        return msg


# Module-level sanitizer singleton
_sanitizer: Final[LogSanitizer] = LogSanitizer()


# ==============================================================================
# Colored Console Formatter
#
# Formats log records with ANSI color codes for stderr output.
# Colors are disabled automatically when stderr is not a TTY.
# ==============================================================================

class _ColoredConsoleFormatter(logging.Formatter):
    """Logging formatter that adds ANSI color codes to console output.

    Color mapping:
        TRACE    → dim
        DEBUG    → cyan
        INFO     → green
        WARNING  → yellow
        ERROR    → red
        CRITICAL → bold red
    """

    # Level → color escape sequence
    _LEVEL_COLORS: dict[int, str] = {
        TRACE_LEVEL_NUM: Color.DIM,
        logging.DEBUG: Color.CYAN,
        logging.INFO: Color.GREEN,
        logging.WARNING: Color.YELLOW,
        logging.ERROR: Color.RED,
        logging.CRITICAL: f"{Color.BOLD}{Color.RED}",
    }

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record with color codes.

        Format: [LEVEL   ] [context] message

        Args:
            record: The log record to format.

        Returns:
            Formatted and colorized log string.
        """
        color = self._LEVEL_COLORS.get(record.levelno, "")
        reset = Color.RESET if color else ""

        # Extract context from record (stored as extra field)
        context = getattr(record, "context", "general")

        return (
            f"{color}[{record.levelname:<8s}] [{context}] "
            f"{record.getMessage()}{reset}"
        )


# ==============================================================================
# Structured File Formatter
#
# Formats log records in the structured format matching the bash variant:
# [timestamp] [LEVEL] [context] [cid:correlation_id] message | extra
# ==============================================================================

class _StructuredFileFormatter(logging.Formatter):
    """Logging formatter for structured file output.

    Format: [ISO8601_UTC] [LEVEL] [context] [cid:correlation_id] message | extra

    Matching the bash variant's log line format exactly.
    """

    def __init__(self, correlation_id: str) -> None:
        super().__init__()
        self._correlation_id: str = correlation_id

    @property
    def correlation_id(self) -> str:
        """Current session correlation ID."""
        return self._correlation_id

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record in structured format.

        Args:
            record: The log record to format.

        Returns:
            Structured log line string.
        """
        # ISO 8601 UTC timestamp with milliseconds
        timestamp = datetime.fromtimestamp(
            record.created, tz=timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        context = getattr(record, "context", "general")
        extra_ctx = getattr(record, "extra_context", "")

        line = (
            f"[{timestamp}] [{record.levelname}] [{context}] "
            f"[cid:{self._correlation_id}] {record.getMessage()}"
        )

        if extra_ctx:
            line += f" | {extra_ctx}"

        return line


# ==============================================================================
# Sanitizing Filter
#
# Logging filter that sanitizes record messages before they reach handlers.
# Applied at the logger level so all handlers get sanitized messages.
# ==============================================================================

class _SanitizingFilter(logging.Filter):
    """Logging filter that masks sensitive data in log messages.

    Applies the LogSanitizer to every log record's message arguments
    before formatting, ensuring sensitive data never reaches any handler.
    """

    def __init__(self, sanitizer: LogSanitizer) -> None:
        super().__init__()
        self._sanitizer: LogSanitizer = sanitizer

    def filter(self, record: logging.LogRecord) -> bool:
        """Sanitize the log record message and extra context.

        Both the message and the structured extra_context field are
        sanitized: extra_context reaches the file formatter verbatim,
        so leaving it unmasked would permit log-line forging via control
        characters (CWE-117) and secret leakage through structured fields.

        Args:
            record: Log record to sanitize.

        Returns:
            Always True (record is never dropped, only sanitized).
        """
        # Sanitize the message (handling both string and lazy format args)
        if record.args:
            # Format first, then sanitize
            record.msg = self._sanitizer.sanitize(record.getMessage())
            record.args = None
        else:
            record.msg = self._sanitizer.sanitize(str(record.msg))

        # Sanitize the structured extra_context field if present
        extra_ctx = getattr(record, "extra_context", "")
        if extra_ctx:
            record.extra_context = self._sanitizer.sanitize(str(extra_ctx))
        return True


# ==============================================================================
# Secure Rotating File Handler
#
# Extends RotatingFileHandler to set secure file permissions on creation
# and rotation. New files are created with 0o600 permissions.
# ==============================================================================

class _SecureRotatingHandler(RotatingFileHandler):
    """RotatingFileHandler that enforces secure file permissions.

    On file creation and rotation, sets permissions to 0o600 (owner read/write
    only). This prevents other users from reading log files that may contain
    sensitive operational data.
    """

    def _open(self) -> Any:
        """Open the log file with secure permissions.

        Returns:
            File stream for the log file (io.TextIOWrapper).
        """
        stream = super()._open()
        try:
            os.chmod(self.baseFilename, Security.FILE_PERMS)
        except OSError:
            pass  # Best-effort: don't fail if permissions can't be set
        return stream

    def doRollover(self) -> None:
        """Perform log rotation with secure permissions on new file.

        Calls parent rotation logic, then secures the new file.
        """
        super().doRollover()
        try:
            os.chmod(self.baseFilename, Security.FILE_PERMS)
        except OSError:
            pass


# ==============================================================================
# Framework Logger
#
# Main logging interface for the Apotropaios framework. Wraps stdlib logging
# with TRACE level support, dual output, correlation IDs, and sanitization.
# ==============================================================================

class FrameworkLogger:
    """Structured logging with dual output, sanitization, and correlation IDs.

    Provides the primary logging interface for all Apotropaios modules.
    Creates per-execution log files with rotation support and outputs
    colorized messages to stderr for interactive use.

    Usage:
        logger = FrameworkLogger()
        logger.init("/path/to/logs", LogLevel.DEBUG)
        logger.info("main", "Framework initialized", "version=1.0")
        logger.warning("firewall", "Backend not running", "backend=iptables")
        logger.shutdown()

    Thread-safety: Guaranteed by stdlib logging's internal lock mechanisms.
    """

    def __init__(self) -> None:
        self._count_lock: threading.Lock = threading.Lock()
        self._logger: logging.Logger | None = None
        self._file_handler: _SecureRotatingHandler | None = None
        self._console_handler: logging.StreamHandler | None = None  # type: ignore[type-arg]
        self._file_formatter: _StructuredFileFormatter | None = None
        self._log_file: str = ""
        self._initialized: bool = False
        self._shut_down: bool = False  # Distinguishes "not yet init" from "already shut down"
        self._entry_count: int = 0
        self._correlation_id: str = ""
        self._level: LogLevel = LogLevel.INFO
        self._sanitizer: LogSanitizer = _sanitizer

    @staticmethod
    def generate_correlation_id() -> str:
        """Generate a unique correlation ID for the current execution.

        Uses secrets module (cryptographically secure) for 8 random hex bytes.
        Falls back to PID + timestamp if secrets is unavailable.

        Returns:
            16-character hexadecimal correlation ID string.
        """
        try:
            return secrets.token_hex(8)
        except Exception:
            # Fallback: PID + timestamp
            return f"{os.getpid():05d}{int(time.time()):010d}"

    def init(
        self,
        log_dir: str,
        level: LogLevel = LogLevel.INFO,
    ) -> None:
        """Initialize the logging subsystem.

        Creates the log directory (with secure permissions), generates a
        timestamped log file, configures file and console handlers, and
        writes an initialization marker.

        Args:
            log_dir: Base log directory path.
            level:   Initial log level threshold.

        Raises:
            OSError: If log directory or file cannot be created.
        """
        # Re-initialization: shut down the previous session first. Without
        # this, the prior stdlib logger stays registered in the logging
        # manager with its rotating file handler attached — a file
        # descriptor leak per re-initialization.
        if self._initialized:
            self.shutdown()

        # Validate log directory path
        if ".." in log_dir:
            sys.stderr.write(
                f"[CRITICAL] [logging] Invalid log directory: "
                f"directory traversal detected ({log_dir})\n"
            )
            return

        # Create log directory with secure permissions
        log_path = Path(log_dir)
        try:
            log_path.mkdir(parents=True, exist_ok=True)
            os.chmod(log_dir, Security.DIR_PERMS)
        except OSError as exc:
            sys.stderr.write(
                f"[CRITICAL] [logging] Failed to create log directory: "
                f"{log_dir} ({exc})\n"
            )
            return

        # Generate timestamped log filename
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
        log_file = str(log_path / f"apotropaios-{timestamp}.log")

        # Generate correlation ID for this session
        self._correlation_id = self.generate_correlation_id()

        # Configure the stdlib logger
        self._logger = logging.getLogger(f"apotropaios.{self._correlation_id}")
        self._logger.setLevel(TRACE_LEVEL_NUM)  # Accept all levels; handlers filter
        self._logger.propagate = False  # Don't propagate to root logger

        # Remove any existing handlers (prevent duplication on re-init)
        for handler in self._logger.handlers[:]:
            self._logger.removeHandler(handler)

        # Add sanitizing filter
        self._logger.addFilter(_SanitizingFilter(self._sanitizer))

        # File handler: structured format, rotation by size
        try:
            self._file_handler = _SecureRotatingHandler(
                filename=log_file,
                maxBytes=Security.MAX_LOG_FILE_SIZE_BYTES,
                backupCount=Security.MAX_LOG_FILES_RETAINED,
                encoding="utf-8",
            )
            self._file_formatter = _StructuredFileFormatter(self._correlation_id)
            self._file_handler.setFormatter(self._file_formatter)
            self._file_handler.setLevel(TRACE_LEVEL_NUM)
            self._logger.addHandler(self._file_handler)
        except OSError as exc:
            sys.stderr.write(
                f"[CRITICAL] [logging] Failed to create log file: "
                f"{log_file} ({exc})\n"
            )
            return

        # Console handler: colorized format to stderr
        self._console_handler = logging.StreamHandler(sys.stderr)
        self._console_handler.setFormatter(_ColoredConsoleFormatter())
        self._console_handler.setLevel(level.to_stdlib_level())
        self._logger.addHandler(self._console_handler)

        # Set state
        self._log_file = log_file
        self._level = level
        self._initialized = True
        self._shut_down = False  # Reset in case of re-initialization
        self._entry_count = 0

        # Write initialization marker
        self.info(
            "logging",
            f"Logging initialized: file={log_file} "
            f"level={level.name} correlation_id={self._correlation_id}",
        )

    def shutdown(self) -> None:
        """Shut down the logging subsystem.

        Removes the console handler first (no more terminal output), writes
        a shutdown marker to the file handler only, then closes everything.
        Safe to call multiple times.
        """
        if not self._initialized:
            return

        # Remove console handler FIRST to prevent terminal noise
        if self._logger and self._console_handler:
            try:
                self._console_handler.flush()
                self._console_handler.close()
            except Exception:
                pass
            self._logger.removeHandler(self._console_handler)
            self._console_handler = None

        # Write shutdown marker to file only
        if self._logger and self._file_handler:
            self._logger.log(
                logging.INFO,
                f"Logging shutdown: entries_written={self._entry_count}",
                extra={"context": "logging", "extra_context": ""},
            )

        # Close remaining handlers (file handler)
        if self._logger:
            for handler in self._logger.handlers[:]:
                try:
                    handler.flush()
                    handler.close()
                except Exception:
                    pass
                self._logger.removeHandler(handler)

        self._file_handler = None
        self._initialized = False
        self._shut_down = True  # Suppress post-shutdown fallback output

    def set_level(self, level: LogLevel) -> None:
        """Change the runtime log level.

        Adjusts the console handler threshold. The file handler always
        records everything (file logs are for post-mortem analysis).

        Args:
            level: New log level threshold.
        """
        old_level = self._level
        self._level = level

        if self._console_handler:
            self._console_handler.setLevel(level.to_stdlib_level())

        self.info(
            "logging",
            f"Log level changed: {old_level.name} -> {level.name}",
        )

    # ------------------------------------------------------------------
    # Primary logging methods
    # Each wraps _write with the appropriate level.
    # Parameters:
    #   context:       Module/subsystem name (e.g., "firewall", "rules")
    #   message:       Log message text
    #   extra_context: Optional structured context string (e.g., "pid=123")
    # ------------------------------------------------------------------

    def trace(
        self, context: str, message: str, extra_context: str = "",
    ) -> None:
        """Log at TRACE level (ultra-verbose debugging)."""
        self._write(TRACE_LEVEL_NUM, context, message, extra_context)

    def debug(
        self, context: str, message: str, extra_context: str = "",
    ) -> None:
        """Log at DEBUG level."""
        self._write(logging.DEBUG, context, message, extra_context)

    def info(
        self, context: str, message: str, extra_context: str = "",
    ) -> None:
        """Log at INFO level."""
        self._write(logging.INFO, context, message, extra_context)

    def warning(
        self, context: str, message: str, extra_context: str = "",
    ) -> None:
        """Log at WARNING level."""
        self._write(logging.WARNING, context, message, extra_context)

    def error(
        self, context: str, message: str, extra_context: str = "",
    ) -> None:
        """Log at ERROR level."""
        self._write(logging.ERROR, context, message, extra_context)

    def critical(
        self, context: str, message: str, extra_context: str = "",
    ) -> None:
        """Log at CRITICAL level."""
        self._write(logging.CRITICAL, context, message, extra_context)

    # ------------------------------------------------------------------
    # Dual-level log function for errors.py deferred logging
    # ------------------------------------------------------------------

    def log_by_name(self, level_name: str, message: str) -> None:
        """Log a message using a level name string.

        Used by the errors module (CleanupStack, SignalHandler) which
        receives log level as a string to avoid circular imports.

        Args:
            level_name: Level name (e.g., "debug", "warning", "error").
            message:    Log message text.
        """
        level_map: dict[str, int] = {
            "trace": TRACE_LEVEL_NUM,
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
            "critical": logging.CRITICAL,
        }
        stdlib_level = level_map.get(level_name.lower(), logging.INFO)
        self._write(stdlib_level, "errors", message)

    # ------------------------------------------------------------------
    # Internal write implementation
    # ------------------------------------------------------------------

    def _write(
        self,
        level: int,
        context: str,
        message: str,
        extra_context: str = "",
    ) -> None:
        """Core log writing function.

        Creates a LogRecord with extra fields (context, extra_context)
        and dispatches to all configured handlers. Falls back to stderr
        if the logger is not initialized.

        Args:
            level:         stdlib logging level integer.
            context:       Module/subsystem name.
            message:       Log message text.
            extra_context: Optional structured context string.
        """
        if not self._initialized or self._logger is None:
            # After explicit shutdown, silently discard (cleanup stack noise)
            if self._shut_down:
                return
            # Before init: write to stderr (only at INFO+ to avoid noise)
            if level < logging.INFO:
                return
            level_name = logging.getLevelName(level)
            sys.stderr.write(
                f"[{level_name:<8s}] [{context}] {message}\n"
            )
            return

        # Create log record with extra context fields
        # Using logger.log() with extra dict to pass context through
        self._logger.log(
            level,
            message,
            extra={"context": context, "extra_context": extra_context},
        )

        # Guarded increment: the expiry monitor daemon thread logs
        # concurrently with the main thread, and += on a shared int is a
        # non-atomic read-modify-write.
        with self._count_lock:
            self._entry_count += 1

    # ------------------------------------------------------------------
    # Property accessors
    # ------------------------------------------------------------------

    @property
    def log_file(self) -> str:
        """Current log file path, or empty string if not initialized."""
        return self._log_file

    @property
    def level(self) -> LogLevel:
        """Current log level."""
        return self._level

    @property
    def entry_count(self) -> int:
        """Number of log entries written in this session."""
        return self._entry_count

    @property
    def correlation_id(self) -> str:
        """Current session correlation ID."""
        return self._correlation_id

    @property
    def initialized(self) -> bool:
        """Whether the logging subsystem is initialized."""
        return self._initialized


# ==============================================================================
# Module-Level Logger Singleton
#
# All framework modules import and use this single instance.
# Initialized during framework startup by cli.py / __main__.py.
# ==============================================================================

log: Final[FrameworkLogger] = FrameworkLogger()
"""Module-level logger singleton. Use: from apotropaios.core.logging import log"""
