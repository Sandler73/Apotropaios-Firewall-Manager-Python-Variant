# ==============================================================================
# File:         apotropaios/core/utils.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Common utility functions and formatting helpers
# Description:  Shared utility functions used across the Apotropaios framework
#               including timestamp generation (ISO 8601 UTC), human-readable
#               duration and byte formatting, key-value file I/O, text
#               formatting (banner, separator, key-value display), command
#               availability checking, user confirmation prompts, file age
#               calculation, and parallel execution support.
#
#               All functions are pure where possible (no shared mutable state).
#               Formatting functions use Color constants for terminal output
#               with automatic TTY detection.
#
# Notes:        - Requires apotropaios.core.constants (VERSION, Color, Security)
#               - No external dependencies -- stdlib only
#               - Thread-safe: all functions are stateless/pure
#               - Parity target: bash v1.1.10 lib/core/utils.sh
# Version:      1.6.2
# ==============================================================================

from __future__ import annotations

import os
import shutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

from apotropaios.core.constants import (
    VERSION,
    Color,
    Performance,
    Security,
)


# ==============================================================================
# Timestamp Functions
# ==============================================================================

def timestamp() -> str:
    """Generate an ISO 8601 UTC timestamp.

    Format: YYYY-MM-DDTHH:MM:SSZ

    Returns:
        UTC timestamp string.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def timestamp_epoch() -> int:
    """Return current time as Unix epoch seconds.

    Returns:
        Epoch seconds as integer.
    """
    return int(time.time())


def timestamp_filename() -> str:
    """Generate a filename-safe UTC timestamp (no colons).

    Format: YYYY-MM-DDTHH-MM-SS

    Returns:
        Filename-safe timestamp string.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")


def timestamp_iso_utc_ms() -> str:
    """Generate an ISO 8601 UTC timestamp with milliseconds.

    Format: YYYY-MM-DDTHH:MM:SS.mmmZ

    Returns:
        UTC timestamp string with millisecond precision.
    """
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def parse_iso_timestamp(ts: str) -> datetime | None:
    """Parse an ISO 8601 UTC timestamp string to a datetime object.

    Accepts both with and without milliseconds, and with 'Z' or '+00:00'
    timezone suffixes.

    Args:
        ts: ISO 8601 timestamp string.

    Returns:
        Timezone-aware datetime object, or None if parsing fails.
    """
    # Normalize Z to +00:00 for fromisoformat compatibility
    normalized = ts.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except (ValueError, TypeError):
        return None


# ==============================================================================
# String Utilities
# ==============================================================================

def to_lower(value: str) -> str:
    """Convert string to lowercase.

    Args:
        value: Input string.

    Returns:
        Lowercase string.
    """
    return value.lower()


def to_upper(value: str) -> str:
    """Convert string to uppercase.

    Args:
        value: Input string.

    Returns:
        Uppercase string.
    """
    return value.upper()


def trim(value: str) -> str:
    """Trim leading and trailing whitespace.

    Args:
        value: Input string.

    Returns:
        Trimmed string.
    """
    return value.strip()


# ==============================================================================
# Command Availability
# ==============================================================================

def is_command_available(cmd: str) -> bool:
    """Check if a command exists on the system PATH.

    Uses shutil.which() which searches PATH entries and checks executability.

    Args:
        cmd: Command name to search for.

    Returns:
        True if the command is found and executable.
    """
    return shutil.which(cmd) is not None


def require_command(cmd: str, context: str = "") -> str:
    """Assert that a command is available on the system.

    Args:
        cmd:     Command name to check.
        context: Optional description of why the command is needed.

    Returns:
        Absolute path to the command.

    Raises:
        FileNotFoundError: If the command is not found.
    """
    path = shutil.which(cmd)
    if path is None:
        msg = f"Required command not found: {cmd}"
        if context:
            msg += f" (needed for: {context})"
        raise FileNotFoundError(msg)
    return path


# ==============================================================================
# File Utilities
# ==============================================================================

def file_age_seconds(path: str) -> int:
    """Calculate the age of a file in seconds.

    Args:
        path: File path to check.

    Returns:
        Age in seconds, or -1 if the file does not exist.
    """
    try:
        mtime = os.path.getmtime(path)
        return int(time.time() - mtime)
    except OSError:
        return -1


# ==============================================================================
# Key-Value File I/O
# ==============================================================================

def read_kv_file(path: str) -> dict[str, str]:
    """Read a key=value file into a dictionary.

    Skips comments (lines starting with #) and empty lines.
    Keys and values are stripped of leading/trailing whitespace.
    Lines without '=' are silently skipped.

    Args:
        path: File path to read.

    Returns:
        Dictionary of key-value pairs.

    Raises:
        FileNotFoundError: If the file does not exist.
        OSError: If the file cannot be read.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"KV file not found: {path}")

    result: dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue
            # Extract key=value
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if key:
                result[key] = value

    return result


def write_kv_file(
    path: str,
    data: dict[str, str],
    header: str = "",
) -> None:
    """Write a dictionary to a key=value file.

    Creates the file with secure permissions (0o600). Includes a
    generation timestamp comment.

    Args:
        path:   File path to write.
        data:   Dictionary of key-value pairs.
        header: Optional header comment (without # prefix).

    Raises:
        OSError: If the file cannot be written.
    """
    with open(path, "w", encoding="utf-8") as f:
        if header:
            f.write(f"# {header}\n")
        f.write(f"# Generated: {timestamp()}\n\n")
        for key, value in sorted(data.items()):
            f.write(f"{key}={value}\n")

    try:
        os.chmod(path, Security.FILE_PERMS)
    except OSError:
        pass  # Best-effort permission setting


# ==============================================================================
# Human-Readable Formatting
# ==============================================================================

def human_duration(seconds: int) -> str:
    """Convert seconds to human-readable duration string.

    Args:
        seconds: Duration in seconds (non-negative).

    Returns:
        Formatted string (e.g., '2d 5h 15m 30s', '45m 10s', '30s').
    """
    if seconds < 0:
        seconds = 0

    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)

    parts: list[str] = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")

    return " ".join(parts)


def human_bytes(size: int) -> str:
    """Convert bytes to human-readable size string.

    Uses binary units (1024-based): B, KB, MB, GB, TB.

    Args:
        size: Size in bytes (non-negative).

    Returns:
        Formatted string (e.g., '1.5 MB', '512 B', '2.3 GB').
    """
    if size < 0:
        size = 0

    if size >= 1_099_511_627_776:  # 1 TB
        return f"{size / 1_099_511_627_776:.1f} TB"
    elif size >= 1_073_741_824:  # 1 GB
        return f"{size / 1_073_741_824:.1f} GB"
    elif size >= 1_048_576:  # 1 MB
        return f"{size / 1_048_576:.1f} MB"
    elif size >= 1024:  # 1 KB
        return f"{size / 1024:.1f} KB"
    else:
        return f"{size} B"


# ==============================================================================
# User Interaction
# ==============================================================================

def confirm(
    message: str,
    default: bool = False,
) -> bool:
    """Prompt user for yes/no confirmation.

    Reads from the terminal directly (not piped stdin). Writes prompt
    to stderr to avoid interfering with stdout data.

    Args:
        message: Prompt message to display.
        default: Default answer when user presses Enter without input.
                 True = default yes, False = default no.

    Returns:
        True if user confirmed (yes), False if denied (no).
    """
    if default:
        prompt = f"{message} [Y/n]: "
    else:
        prompt = f"{message} [y/N]: "

    sys.stderr.write(f"{Color.YELLOW}{prompt}{Color.RESET}")
    sys.stderr.flush()

    try:
        # Read from terminal directly
        with open("/dev/tty", "r") as tty:
            reply = tty.readline().strip().lower()
    except (OSError, EOFError):
        reply = ""

    if reply in ("y", "yes"):
        return True
    elif reply in ("n", "no"):
        return False
    else:
        # Empty or unrecognized → use default
        return default


# ==============================================================================
# Terminal Formatting
# ==============================================================================

# ASCII art banner -- verified character by character per BUG-001 lesson
_BANNER: str = r"""    _                _                         _
   / \   _ __   ___ | |_ _ __ ___  _ __   __ _(_) ___  ___
  / _ \ | '_ \ / _ \| __| '__/ _ \| '_ \ / _` | |/ _ \/ __|
 / ___ \| |_) | (_) | |_| | | (_) | |_) | (_| | | (_) \__ \
/_/   \_\ .__/ \___/ \__|_|  \___/| .__/ \__,_|_|\___/|___/
        |_|                       |_|"""


def print_banner() -> None:
    """Print the Apotropaios ASCII art banner with version.

    Banner text is cyan, version is bold. Output goes to stderr
    to avoid polluting stdout for piped/scripted usage.
    """
    sys.stderr.write(f"{Color.CYAN}{_BANNER}\n")
    sys.stderr.write(
        f"{Color.BOLD}        Firewall Manager v{VERSION}{Color.RESET}\n\n"
    )
    sys.stderr.flush()


def print_separator(char: str = "─", width: int = 72) -> None:
    """Print a visual separator line.

    Args:
        char:  Character to repeat (default: horizontal line ─).
        width: Number of characters wide (default: 72).
    """
    sys.stderr.write(f"{Color.DIM}{char * width}{Color.RESET}\n")
    sys.stderr.flush()


def print_kv(key: str, value: str, key_width: int = 20) -> None:
    """Print a key-value pair with aligned formatting.

    Args:
        key:       Label text (left-aligned, bold).
        value:     Value text.
        key_width: Column width for the key (default: 20).
    """
    sys.stderr.write(
        f"  {Color.BOLD}{key:<{key_width}}{Color.RESET} : {value}\n"
    )
    sys.stderr.flush()


def print_colored(
    message: str,
    color: str = "",
    end: str = "\n",
    file: Any = None,
) -> None:
    """Print a message with optional ANSI color.

    Args:
        message: Text to print.
        color:   ANSI color escape sequence (from Color constants).
        end:     String appended after the message (default: newline).
        file:    Output stream (default: stderr).
    """
    output = file if file is not None else sys.stderr
    if color:
        output.write(f"{color}{message}{Color.RESET}{end}")
    else:
        output.write(f"{message}{end}")
    output.flush()


# ==============================================================================
# Parallel Execution
# ==============================================================================

def parallel_exec(
    tasks: list[tuple[Any, ...]],
    func: Any,
    max_workers: int = Performance.MAX_CONCURRENT_OPERATIONS,
) -> list[tuple[bool, Any]]:
    """Execute multiple tasks in parallel with a concurrency limit.

    Uses ThreadPoolExecutor for I/O-bound operations (subprocess calls
    to firewall backends). Each task is a tuple of arguments passed
    to the callable.

    Args:
        tasks:       List of argument tuples for the callable.
        func:        Callable to execute for each task.
        max_workers: Maximum concurrent threads (default: 4).

    Returns:
        List of (success: bool, result_or_exception) tuples in
        submission order.
    """
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks, preserving order via dict keyed by future
        future_to_index = {
            executor.submit(func, *task): i
            for i, task in enumerate(tasks)
        }

        # Pre-allocate result slots
        results: list[tuple[bool, Any]] = [(False, None)] * len(tasks)

        # Collect results as they complete
        for future in as_completed(future_to_index):
            idx = future_to_index[future]
            try:
                result = future.result()
                results[idx] = (True, result)
            except Exception as exc:
                results[idx] = (False, exc)

    return results
