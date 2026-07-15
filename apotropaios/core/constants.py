# ==============================================================================
# File:         apotropaios/core/constants.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Immutable constants, version information, and configuration defaults
# Description:  Defines all immutable constants used throughout the Apotropaios
#               framework including version strings, supported operating systems,
#               supported firewall backends, directory paths, exit/error codes,
#               log levels, validation patterns, security limits, rule parameters,
#               backup settings, performance tuning, and terminal color codes.
#
#               Python design choices:
#               - IntEnum for exit codes (usable as sys.exit() arguments)
#               - IntEnum for log levels (numeric comparison support)
#               - StrEnum for string-valued enumerations (actions, directions, etc.)
#               - NamedTuple for structured OS/firewall metadata
#               - Compiled re.Pattern objects for validation (precompiled at import)
#               - Module-level frozenset/tuple for immutable collections
#               - sys.stdout.isatty() for terminal color detection
#
# Notes:        - Must be imported before any other apotropaios module
#               - All public constants use UPPER_SNAKE_CASE naming convention
#               - All collections are immutable (tuple, frozenset, NamedTuple)
#               - Compiled regex patterns are thread-safe (re module guarantee)
#               - No external dependencies — stdlib only
#               - Parity target: bash v1.1.10 constants.sh
# Version:      1.2.1
# ==============================================================================

from __future__ import annotations

import re
import sys
from enum import IntEnum, StrEnum, unique
from typing import Final, NamedTuple


# ==============================================================================
# Version & Identity
# ==============================================================================

VERSION: Final[str] = "1.2.1"
"""Semantic version string for the Python variant."""

PROJECT_NAME: Final[str] = "Apotropaios"
"""Short project name."""

FULL_NAME: Final[str] = "Apotropaios - Firewall Manager"
"""Full display name including subtitle."""

MIN_PYTHON_VERSION: Final[tuple[int, int]] = (3, 12)
"""Minimum required Python version as (major, minor) tuple."""


# ==============================================================================
# Directory Paths (relative to base directory, resolved at runtime)
# ==============================================================================

class DirPath:
    """Relative directory paths from the framework base directory.

    These are joined with the runtime-determined base directory by the
    initialization code. All paths use forward slashes (POSIX).
    """

    CONF: Final[str] = "conf"
    DATA: Final[str] = "data"
    LOGS: Final[str] = "data/logs"
    RULES: Final[str] = "data/rules"
    BACKUPS: Final[str] = "data/backups"
    TEMP: Final[str] = "data/.tmp"


# ==============================================================================
# File Names
# ==============================================================================

class FileName:
    """Standard file names used by the framework.

    These are basenames only — directory paths are resolved at runtime
    by combining with the appropriate DirPath constant.
    """

    CONF: Final[str] = "apotropaios.conf"
    RULE_INDEX: Final[str] = "rule_index.dat"
    RULE_STATE: Final[str] = "rule_state.dat"
    LOCK: Final[str] = "apotropaios.lock"
    PID: Final[str] = "apotropaios.pid"


# ==============================================================================
# Supported Operating Systems
# ==============================================================================

class OSInfo(NamedTuple):
    """Metadata for a supported operating system.

    Attributes:
        os_id:          Canonical lowercase identifier matching /etc/os-release ID field.
        display_name:   Human-readable OS name for UI display.
        pkg_manager:    Package manager command (apt, dnf, pacman).
        family:         OS family for grouping (debian, rhel, arch).
    """

    os_id: str
    display_name: str
    pkg_manager: str
    family: str


# Supported OS definitions — order matches bash variant's parallel arrays.
# Each entry carries all metadata in a single NamedTuple (no parallel arrays).
SUPPORTED_OS: Final[tuple[OSInfo, ...]] = (
    OSInfo(os_id="ubuntu",    display_name="Ubuntu",         pkg_manager="apt",    family="debian"),
    OSInfo(os_id="kali",      display_name="Kali Linux",     pkg_manager="apt",    family="debian"),
    OSInfo(os_id="debian",    display_name="Debian 12",      pkg_manager="apt",    family="debian"),
    OSInfo(os_id="rocky",     display_name="Rocky Linux 9",  pkg_manager="dnf",    family="rhel"),
    OSInfo(os_id="almalinux", display_name="AlmaLinux 9",    pkg_manager="dnf",    family="rhel"),
    OSInfo(os_id="arch",      display_name="Arch Linux",     pkg_manager="pacman", family="arch"),
)

# Quick-lookup set for ID validation (O(1) membership test)
SUPPORTED_OS_IDS: Final[frozenset[str]] = frozenset(os.os_id for os in SUPPORTED_OS)

# Family mapping: os_id_like values → canonical family identifiers
# Used by os_detect to resolve derivative distributions (e.g., fedora → rhel)
OS_FAMILY_MAP: Final[dict[str, str]] = {
    "ubuntu": "debian",
    "debian": "debian",
    "kali": "debian",
    "rhel": "rhel",
    "centos": "rhel",
    "fedora": "rhel",
    "rocky": "rhel",
    "almalinux": "rhel",
    "opensuse": "suse",
    "arch": "arch",
}


# ==============================================================================
# Supported Firewall Backends
# ==============================================================================

class FirewallInfo(NamedTuple):
    """Metadata for a supported firewall backend.

    Attributes:
        fw_id:          Canonical lowercase identifier for the backend.
        binary:         Command-line binary name to check availability.
        service:        Systemd service name (empty string if none).
        packages:       Per-package-manager package names as {manager: name}.
    """

    fw_id: str
    binary: str
    service: str
    packages: dict[str, str]


# Supported firewall backend definitions — replaces bash's parallel arrays.
SUPPORTED_FIREWALLS: Final[tuple[FirewallInfo, ...]] = (
    FirewallInfo(
        fw_id="firewalld",
        binary="firewall-cmd",
        service="firewalld",
        packages={"apt": "firewalld", "dnf": "firewalld", "pacman": "firewalld"},
    ),
    FirewallInfo(
        fw_id="ipset",
        binary="ipset",
        service="",
        packages={"apt": "ipset", "dnf": "ipset", "pacman": "ipset"},
    ),
    FirewallInfo(
        fw_id="iptables",
        binary="iptables",
        service="iptables",
        packages={"apt": "iptables", "dnf": "iptables", "pacman": "iptables"},
    ),
    FirewallInfo(
        fw_id="nftables",
        binary="nft",
        service="nftables",
        packages={"apt": "nftables", "dnf": "nftables", "pacman": "nftables"},
    ),
    FirewallInfo(
        fw_id="ufw",
        binary="ufw",
        service="ufw",
        packages={"apt": "ufw", "dnf": "ufw", "pacman": "ufw"},
    ),
)

# Quick-lookup set for firewall ID validation
SUPPORTED_FW_IDS: Final[frozenset[str]] = frozenset(fw.fw_id for fw in SUPPORTED_FIREWALLS)

# Quick-lookup dict: fw_id → FirewallInfo
FW_INFO_BY_ID: Final[dict[str, FirewallInfo]] = {fw.fw_id: fw for fw in SUPPORTED_FIREWALLS}


# ==============================================================================
# Exit / Error Codes
#
# Organized by category with numeric ranges matching the bash variant exactly.
# IntEnum allows direct use as sys.exit() arguments and numeric comparison.
# ==============================================================================

@unique
class ErrorCode(IntEnum):
    """Structured error codes for all framework operations.

    Ranges:
        0-9:    General / process-level
        10-19:  OS / firewall detection
        20-29:  Rule operations
        30-39:  Backup / restore
        40-49:  Validation
        50-59:  Logging
        60-69:  Locking
        70-79:  Integrity / memory
        80-89:  Signal handling
    """

    # General (0-9)
    SUCCESS             = 0
    GENERAL             = 1
    USAGE               = 2
    PERMISSION          = 3

    # OS / Firewall (10-19)
    OS_UNSUPPORTED      = 10
    FW_NOT_FOUND        = 11
    FW_NOT_RUNNING      = 12
    FW_INSTALL_FAIL     = 13

    # Rule operations (20-29)
    RULE_INVALID        = 20
    RULE_EXISTS         = 21
    RULE_NOT_FOUND      = 22
    RULE_APPLY_FAIL     = 23
    RULE_REMOVE_FAIL    = 24
    RULE_IMPORT_FAIL    = 25

    # Backup / Restore (30-39)
    BACKUP_FAIL         = 30
    RESTORE_FAIL        = 31
    BACKUP_NOT_FOUND    = 32

    # Validation (40-49)
    VALIDATION_FAIL     = 40
    INPUT_SANITIZE_FAIL = 41

    # Logging (50-59)
    LOG_FAIL            = 50
    LOG_HANDLE_LOST     = 51

    # Locking (60-69)
    LOCK_FAIL           = 60
    LOCK_TIMEOUT        = 61

    # Integrity / Memory (70-79)
    INTEGRITY_FAIL      = 70
    MEMORY_FAIL         = 71

    # Signal handling (80-89)
    SIGNAL_RECEIVED     = 80
    CLEANUP_FAIL        = 81


# ==============================================================================
# Log Levels
#
# Custom IntEnum that adds a TRACE level (below DEBUG) and NONE (suppresses all).
# Numeric values allow direct comparison: if level >= current_level: emit().
# Maps to Python stdlib logging levels where applicable.
# ==============================================================================

@unique
class LogLevel(IntEnum):
    """Logging severity levels.

    TRACE (0) is below DEBUG for ultra-verbose output.
    NONE (99) suppresses all logging.
    Values 1-5 map to stdlib logging DEBUG/INFO/WARNING/ERROR/CRITICAL.
    """

    TRACE    = 0
    DEBUG    = 1
    INFO     = 2
    WARNING  = 3
    ERROR    = 4
    CRITICAL = 5
    NONE     = 99

    @classmethod
    def from_string(cls, name: str) -> LogLevel:
        """Parse a log level name (case-insensitive) to its enum member.

        Args:
            name: Log level name (e.g., 'debug', 'INFO', 'Warning').

        Returns:
            Corresponding LogLevel enum member.

        Raises:
            ValueError: If the name does not match any known level.
        """
        upper = name.upper().strip()
        try:
            return cls[upper]
        except KeyError:
            valid = ", ".join(member.name.lower() for member in cls)
            raise ValueError(
                f"Invalid log level: {name!r}. Valid levels: {valid}"
            ) from None

    def to_stdlib_level(self) -> int:
        """Convert to Python stdlib logging numeric level.

        Returns:
            stdlib logging level integer. TRACE maps to 5 (custom),
            NONE maps to 100 (above CRITICAL).
        """
        return _LOGLEVEL_TO_STDLIB.get(self.value, 20)


# Module-level mapping: LogLevel value → stdlib logging level
# Defined outside the IntEnum to avoid enum member interpretation.
# stdlib levels: DEBUG=10, INFO=20, WARNING=30, ERROR=40, CRITICAL=50
_LOGLEVEL_TO_STDLIB: Final[dict[int, int]] = {
    0: 5,      # TRACE → custom level 5
    1: 10,     # DEBUG → logging.DEBUG
    2: 20,     # INFO → logging.INFO
    3: 30,     # WARNING → logging.WARNING
    4: 40,     # ERROR → logging.ERROR
    5: 50,     # CRITICAL → logging.CRITICAL
    99: 100,   # NONE → above CRITICAL (suppresses all)
}


# Default log level for new sessions
DEFAULT_LOG_LEVEL: Final[LogLevel] = LogLevel.WARNING


# ==============================================================================
# Validation Patterns (Compiled Regular Expressions)
#
# Security: Whitelist patterns — reject everything that doesn't fullmatch().
# All patterns are compiled at module import time for performance.
# Thread-safe by Python re module guarantee.
# ==============================================================================

class Pattern:
    """Precompiled regex patterns for input validation.

    All patterns are whitelist-based: input must fullmatch() the pattern
    to be considered valid. This enforces the "reject by default" principle.

    Naming convention: ENTITY_TYPE (e.g., IPV4, PORT_RANGE, HOSTNAME).
    """

    # --- Network addresses ---

    # IPv4 address: 0-255.0-255.0-255.0-255 (octet range checked in validator)
    IPV4: Final[re.Pattern[str]] = re.compile(
        r'^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    )

    # IPv6 address: simplified pattern allowing compressed notation (::)
    IPV6: Final[re.Pattern[str]] = re.compile(
        r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
    )

    # CIDR notation: IPv4/prefix (prefix range checked in validator)
    CIDR_V4: Final[re.Pattern[str]] = re.compile(
        r'^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'
    )

    # CIDR notation: IPv6/prefix (prefix range checked in validator)
    CIDR_V6: Final[re.Pattern[str]] = re.compile(
        r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}/[0-9]{1,3}$'
    )

    # --- Ports ---

    # Single port number: 1-65535 (range checked in validator)
    PORT: Final[re.Pattern[str]] = re.compile(
        r'^[0-9]{1,5}$'
    )

    # Port range: port-port or port:port (both delimiters accepted)
    PORT_RANGE: Final[re.Pattern[str]] = re.compile(
        r'^[0-9]{1,5}[-:][0-9]{1,5}$'
    )

    # --- Protocol ---

    # Allowed protocols: tcp, udp, icmp, icmpv6, sctp, all
    PROTOCOL: Final[re.Pattern[str]] = re.compile(
        r'^(tcp|udp|icmp|icmpv6|sctp|all)$'
    )

    # --- Names and identifiers ---

    # Hostname: RFC 1123 compliant (labels up to 63 chars, alphanumeric + hyphens)
    HOSTNAME: Final[re.Pattern[str]] = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    )

    # Network interface name: starts with letter, up to 15 chars total
    INTERFACE: Final[re.Pattern[str]] = re.compile(
        r'^[a-zA-Z][a-zA-Z0-9._-]{0,14}$'
    )

    # Firewalld zone name: starts with letter, up to 32 chars
    ZONE: Final[re.Pattern[str]] = re.compile(
        r'^[a-zA-Z][a-zA-Z0-9_-]{0,31}$'
    )

    # Firewall chain name: starts with letter, up to 64 chars
    CHAIN: Final[re.Pattern[str]] = re.compile(
        r'^[a-zA-Z][a-zA-Z0-9_-]{0,63}$'
    )

    # Firewall table name: starts with letter, up to 32 chars
    TABLE: Final[re.Pattern[str]] = re.compile(
        r'^[a-zA-Z][a-zA-Z0-9_]{0,31}$'
    )

    # IPSet set name: starts with letter, up to 31 chars
    IPSET_NAME: Final[re.Pattern[str]] = re.compile(
        r'^[a-zA-Z][a-zA-Z0-9_-]{0,30}$'
    )

    # Rule UUID: lowercase hex with hyphens (8-4-4-4-12 format)
    RULE_ID: Final[re.Pattern[str]] = re.compile(
        r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
    )

    # --- Paths ---

    # Safe file path: restricted whitelist of characters, no traversal sequences
    # Allows: alphanumeric, forward slash, underscore, dot, space, tilde, colon,
    #         plus, hyphen. Path traversal (..) must be checked separately.
    SAFE_PATH: Final[re.Pattern[str]] = re.compile(
        r'^[a-zA-Z0-9/_. ~:+\-]+$'
    )

    # Safe directory path: identical to SAFE_PATH (explicit alias for clarity)
    SAFE_DIR: Final[re.Pattern[str]] = re.compile(
        r'^[a-zA-Z0-9/_. ~:+\-]+$'
    )

    # --- Generic ---

    # Numeric only (unsigned integers)
    NUMERIC: Final[re.Pattern[str]] = re.compile(
        r'^[0-9]+$'
    )

    # Alphanumeric with hyphens and underscores (safe identifier)
    ALNUM_SAFE: Final[re.Pattern[str]] = re.compile(
        r'^[a-zA-Z0-9_-]+$'
    )


# Shell metacharacters to reject during input sanitization.
# In Python, this is a single frozenset — no need for bash's per-character patterns.
# Used by sanitize_input() to detect dangerous characters.
SHELL_METACHARACTERS: Final[frozenset[str]] = frozenset(
    ';|&`$(){}\\<>!#'
)


# ==============================================================================
# Security Constants
# ==============================================================================

class Security:
    """Security-related limits and permission masks.

    All numeric values match the bash variant exactly for behavioral parity.
    """

    # File permission masks (octal)
    UMASK: Final[int] = 0o077
    DIR_PERMS: Final[int] = 0o700
    FILE_PERMS: Final[int] = 0o600
    EXEC_PERMS: Final[int] = 0o700

    # Input length limits
    MAX_INPUT_LENGTH: Final[int] = 4096
    MAX_PATH_LENGTH: Final[int] = 4096
    MAX_RULE_DESCRIPTION_LENGTH: Final[int] = 256

    # Log rotation
    MAX_LOG_FILE_SIZE_BYTES: Final[int] = 104_857_600  # 100 MB
    MAX_LOG_FILES_RETAINED: Final[int] = 10

    # File locking
    LOCK_TIMEOUT_SECONDS: Final[int] = 30
    LOCK_RETRY_INTERVAL: Final[int] = 1


# ==============================================================================
# Firewall Rule Constants
# ==============================================================================

@unique
class RuleAction(StrEnum):
    """Firewall rule actions.

    Terminal actions (ACCEPT, DROP, REJECT, etc.) stop packet processing.
    Non-terminal actions (LOG) allow processing to continue.
    Compound actions (e.g., "log,drop") are represented as comma-separated
    strings and parsed at the validation layer.
    """

    ACCEPT     = "accept"
    DROP       = "drop"
    REJECT     = "reject"
    LOG        = "log"
    MASQUERADE = "masquerade"
    SNAT       = "snat"
    DNAT       = "dnat"
    RETURN     = "return"


# Sets for quick classification of terminal vs non-terminal actions
TERMINAL_ACTIONS: Final[frozenset[str]] = frozenset({
    RuleAction.ACCEPT,
    RuleAction.DROP,
    RuleAction.REJECT,
    RuleAction.MASQUERADE,
    RuleAction.SNAT,
    RuleAction.DNAT,
    RuleAction.RETURN,
})

NON_TERMINAL_ACTIONS: Final[frozenset[str]] = frozenset({
    RuleAction.LOG,
})

# All valid single action values
ALL_ACTIONS: Final[frozenset[str]] = TERMINAL_ACTIONS | NON_TERMINAL_ACTIONS


@unique
class RuleDirection(StrEnum):
    """Packet direction for firewall rules."""

    INBOUND  = "inbound"
    OUTBOUND = "outbound"
    FORWARD  = "forward"


@unique
class RuleState(StrEnum):
    """Rule lifecycle states in the index."""

    ACTIVE   = "active"
    INACTIVE = "inactive"
    PENDING  = "pending"
    EXPIRED  = "expired"


@unique
class DurationType(StrEnum):
    """Rule duration classification."""

    PERMANENT = "permanent"
    TEMPORARY = "temporary"


@unique
class ConnState(StrEnum):
    """Connection tracking states (netfilter conntrack/state module)."""

    NEW         = "new"
    ESTABLISHED = "established"
    RELATED     = "related"
    INVALID     = "invalid"
    UNTRACKED   = "untracked"


@unique
class SyslogLevel(StrEnum):
    """Syslog severity levels for firewall log actions.

    These are the log levels accepted by firewall backends (iptables --log-level,
    firewalld rich rule log level, etc.). Distinct from framework LogLevel.
    """

    EMERG   = "emerg"
    ALERT   = "alert"
    CRIT    = "crit"
    ERR     = "err"
    WARNING = "warning"
    NOTICE  = "notice"
    INFO    = "info"
    DEBUG   = "debug"


# nftables table family values
NFTABLES_TABLE_FAMILIES: Final[frozenset[str]] = frozenset({
    "inet", "ip", "ip6", "arp", "bridge", "netdev",
})

# iptables table names
IPTABLES_TABLES: Final[frozenset[str]] = frozenset({
    "filter", "nat", "mangle", "raw", "security",
})

# iptables built-in chain names
IPTABLES_BUILTIN_CHAINS: Final[frozenset[str]] = frozenset({
    "INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING",
})

# ipset supported set types
IPSET_TYPES: Final[frozenset[str]] = frozenset({
    "hash:ip",
    "hash:net",
    "hash:ip,port",
    "hash:net,port",
    "hash:net,iface",
    "list:set",
})


# TTL limits for temporary rules (in seconds)
class TTLLimits:
    """Minimum and maximum TTL values for temporary rules."""

    MIN_SECONDS: Final[int] = 60          # 1 minute
    MAX_SECONDS: Final[int] = 2_592_000   # 30 days


# ==============================================================================
# Backup Constants
# ==============================================================================

class Backup:
    """Backup and restore configuration constants."""

    PREFIX: Final[str] = "apotropaios_backup"
    EXTENSION: Final[str] = ".tar.gz"
    MANIFEST_FILE: Final[str] = "manifest.json"
    MAX_RETAINED: Final[int] = 20
    INTEGRITY_ALGORITHM: Final[str] = "sha256"


# ==============================================================================
# Performance Constants
# ==============================================================================

class Performance:
    """Performance tuning constants."""

    MAX_CONCURRENT_OPERATIONS: Final[int] = 4
    OPERATION_TIMEOUT_SECONDS: Final[int] = 300   # 5 minutes
    BATCH_SIZE: Final[int] = 50                    # Rules per batch operation
    EXPIRY_CHECK_INTERVAL: Final[int] = 30         # Seconds between expiry checks
    SUBPROCESS_TIMEOUT: Final[int] = 30            # Default subprocess timeout


# ==============================================================================
# Terminal Colors
#
# ANSI escape sequences for terminal output. Automatically detects whether
# stdout is a TTY and disables colors for non-interactive/piped output.
# ==============================================================================

class _Color:
    """ANSI terminal color codes with automatic TTY detection.

    Colors are empty strings when stdout is not a terminal, preventing
    escape sequences from appearing in redirected/piped output.

    Usage:
        from apotropaios.core.constants import Color
        print(f"{Color.GREEN}Success{Color.RESET}")
    """

    def __init__(self) -> None:
        # Detect TTY once at initialization
        # Check stderr because all user-facing output goes to stderr
        # (stdout is reserved for machine-readable data)
        is_tty: bool = hasattr(sys.stderr, "isatty") and sys.stderr.isatty()

        # Core colors
        self.RESET: str = "\033[0m" if is_tty else ""
        self.RED: str = "\033[0;31m" if is_tty else ""
        self.GREEN: str = "\033[0;32m" if is_tty else ""
        self.YELLOW: str = "\033[0;33m" if is_tty else ""
        self.BLUE: str = "\033[0;34m" if is_tty else ""
        self.MAGENTA: str = "\033[0;35m" if is_tty else ""
        self.CYAN: str = "\033[0;36m" if is_tty else ""
        self.WHITE: str = "\033[0;37m" if is_tty else ""

        # Text effects
        self.BOLD: str = "\033[1m" if is_tty else ""
        self.DIM: str = "\033[2m" if is_tty else ""


# Module-level singleton — evaluated once at import time
Color: Final[_Color] = _Color()


# ==============================================================================
# Cancel Keywords (for interactive wizard prompts)
# ==============================================================================

CANCEL_KEYWORDS: Final[frozenset[str]] = frozenset({
    "q", "quit", "cancel", "back", "b",
})


# ==============================================================================
# CLI Command Names (for dispatch and help routing)
# ==============================================================================

CLI_COMMANDS: Final[tuple[str, ...]] = (
    "menu",
    "help",
    "detect",
    "status",
    "add-rule",
    "remove-rule",
    "activate-rule",
    "deactivate-rule",
    "list-rules",
    "system-rules",
    "enable",
    "disable",
    "reset",
    "block-all",
    "allow-all",
    "import",
    "export",
    "backup",
    "restore",
    "install",
    "update",
)
