# ==============================================================================
# File:         apotropaios/core/validation.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Input validation and sanitization framework
# Description:  Whitelist-based input validation for all user-supplied
#               data including IP addresses, ports, protocols, hostnames, file
#               paths, chain/table names, and rule parameters. Implements
#               defense-in-depth per OWASP CRG and CWE-20 guidelines.
#
#               All validation uses whitelist (positive) matching -- everything
#               not explicitly permitted is rejected. Functions raise
#               ValidationError on invalid input rather than returning boolean,
#               enabling clean error propagation in Python.
#
#               Validators (27):
#                 port, port_range, ipv4, ipv6, ip, cidr, protocol, hostname,
#                 interface, file_path, zone, chain, table, table_family,
#                 ipset_name, rule_id, rule_action, rule_direction,
#                 duration_type, ttl, log_level, conn_state, log_prefix,
#                 rate_limit, numeric, description, syslog_level
#
#               Sanitizer (1):
#                 sanitize_input -- whitelist-based character filtering
#
#               Internal helper:
#                 _contains_shell_meta -- shell metacharacter detection
#
# Notes:        - Requires apotropaios.core.constants (Pattern, Security, etc.)
#               - Requires apotropaios.core.errors (ValidationError, SanitizationError)
#               - All validators accept str input and raise ValidationError on failure
#               - Validate at every trust boundary before any use of input
#               - Never interpolate raw input into commands or paths
#               - Thread-safe: all functions are pure (no shared mutable state)
#               - Parity target: bash v1.1.10 lib/core/validation.sh
# Version:      1.6.2
# ==============================================================================

from __future__ import annotations

import ipaddress
import re
from typing import Final

from apotropaios.core.constants import (
    ALL_ACTIONS,
    CANCEL_KEYWORDS,
    NFTABLES_TABLE_FAMILIES,
    SHELL_METACHARACTERS,
    TERMINAL_ACTIONS,
    ConnState,
    DurationType,
    LogLevel,
    Pattern,
    RuleDirection,
    Security,
    SyslogLevel,
    TTLLimits,
)
from apotropaios.core.errors import SanitizationError, ValidationError


# ==============================================================================
# Internal Helpers
# ==============================================================================

def _contains_shell_meta(value: str) -> bool:
    """Check if a string contains shell metacharacters.

    Uses the SHELL_METACHARACTERS frozenset from constants for O(1) per-char
    lookup. This is the Python equivalent of the bash _contains_shell_meta()
    function which tested each metachar individually.

    Args:
        value: String to check for dangerous characters.

    Returns:
        True if any shell metacharacter is found (DANGEROUS), False if clean.
    """
    return bool(SHELL_METACHARACTERS & set(value))


# Precompiled pattern for sanitize_input whitelist
# Allowed: alphanumeric, space, dot, comma, underscore, colon, slash,
#          plus, equals, at sign, tilde, percent, hyphen
_SANITIZE_WHITELIST: Final[re.Pattern[str]] = re.compile(
    r'[^a-zA-Z0-9 .,_:/+=@~%\-]'
)

# Precompiled pattern for log prefix validation
_LOG_PREFIX_PATTERN: Final[re.Pattern[str]] = re.compile(
    r'^[a-zA-Z0-9 _.:/-]+$'
)

# Precompiled pattern for rate limit validation
_RATE_LIMIT_PATTERN: Final[re.Pattern[str]] = re.compile(
    r'^[0-9]+/(second|minute|hour|day)$'
)


# ==============================================================================
# Network Address Validators
# ==============================================================================

def validate_port(value: str) -> int:
    """Validate a TCP/UDP port number (1-65535).

    Args:
        value: Port number as string.

    Returns:
        Validated port number as integer.

    Raises:
        ValidationError: If input is empty, non-numeric, or out of range.
    """
    if not value:
        raise ValidationError("Port validation failed: empty input", field="port")

    if len(value) > 5:
        raise ValidationError(
            "Port validation failed: exceeds max length",
            field="port", value=value,
        )

    if not Pattern.PORT.fullmatch(value):
        raise ValidationError(
            "Port validation failed: non-numeric characters",
            field="port", value=value,
        )

    port = int(value)
    if port < 1 or port > 65535:
        raise ValidationError(
            f"Port validation failed: out of range ({port})",
            field="port", value=value,
        )

    return port


def validate_port_range(value: str) -> tuple[int, int]:
    """Validate a port range (e.g., '8080-8090' or '8080:8090').

    Args:
        value: Port range string with '-' or ':' separator.

    Returns:
        Tuple of (start_port, end_port) as integers.

    Raises:
        ValidationError: If format is invalid, ports are out of range,
                         or start > end.
    """
    if not value:
        raise ValidationError(
            "Port range validation failed: empty input", field="port_range",
        )

    if not Pattern.PORT_RANGE.fullmatch(value):
        raise ValidationError(
            "Port range validation failed: invalid format",
            field="port_range", value=value,
        )

    # Extract start and end ports (handle both separators)
    if "-" in value:
        parts = value.split("-", 1)
    else:
        parts = value.split(":", 1)

    start = validate_port(parts[0])
    end = validate_port(parts[1])

    if start > end:
        raise ValidationError(
            f"Port range validation failed: start > end ({start} > {end})",
            field="port_range", value=value,
        )

    return (start, end)


def validate_ipv4(value: str) -> str:
    """Validate an IPv4 address with full octet range checking.

    Rejects leading zeros in octets (except '0' itself) per security
    best practice (prevents octal interpretation ambiguity).

    Args:
        value: IPv4 address string (e.g., '192.168.1.1').

    Returns:
        Validated IPv4 address string.

    Raises:
        ValidationError: If format is invalid or octets out of range.
    """
    if not value:
        raise ValidationError("IPv4 validation failed: empty input", field="ipv4")

    if len(value) > 15:
        raise ValidationError(
            "IPv4 validation failed: exceeds max length",
            field="ipv4", value=value,
        )

    if not Pattern.IPV4.fullmatch(value):
        raise ValidationError(
            "IPv4 validation failed: pattern mismatch",
            field="ipv4", value=value,
        )

    # Validate each octet
    octets = value.split(".")
    if len(octets) != 4:
        raise ValidationError(
            "IPv4 validation failed: wrong number of octets",
            field="ipv4", value=value,
        )

    for octet_str in octets:
        # Reject leading zeros (except "0" itself)
        if len(octet_str) > 1 and octet_str.startswith("0"):
            raise ValidationError(
                "IPv4 validation failed: leading zeros in octet",
                field="ipv4", value=value,
            )
        octet_val = int(octet_str)
        if octet_val > 255:
            raise ValidationError(
                f"IPv4 validation failed: octet out of range ({octet_val})",
                field="ipv4", value=value,
            )

    return value


def validate_ipv6(value: str) -> str:
    """Validate an IPv6 address (simplified validation).

    Accepts compressed notation (::) and standard hex group format.

    Args:
        value: IPv6 address string.

    Returns:
        Validated IPv6 address string.

    Raises:
        ValidationError: If format is invalid.
    """
    if not value:
        raise ValidationError("IPv6 validation failed: empty input", field="ipv6")

    # Max IPv6 representation is 39 chars (8 groups × 4 hex + 7 colons)
    if len(value) > 39:
        raise ValidationError(
            "IPv6 validation failed: exceeds max length",
            field="ipv6", value=value,
        )

    if not Pattern.IPV6.fullmatch(value):
        raise ValidationError(
            "IPv6 validation failed: pattern mismatch",
            field="ipv6", value=value,
        )

    # Exact semantic validation: the character-class pattern above cannot
    # reject malformed forms such as ":::" or "1::2::3" (multiple
    # compressions) -- the stdlib parser enforces the full RFC 4291 grammar.
    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        raise ValidationError(
            "IPv6 validation failed: not a valid IPv6 address",
            field="ipv6", value=value,
        ) from None

    return value


def validate_ip(value: str) -> str:
    """Validate an IP address (auto-detect IPv4 or IPv6).

    Attempts IPv4 validation first, then falls back to IPv6.

    Args:
        value: IP address string (either version).

    Returns:
        Validated IP address string.

    Raises:
        ValidationError: If input is neither valid IPv4 nor IPv6.
    """
    if not value:
        raise ValidationError("IP validation failed: empty input", field="ip")

    # Try IPv4 first
    try:
        return validate_ipv4(value)
    except ValidationError:
        pass

    # Then IPv6
    try:
        return validate_ipv6(value)
    except ValidationError:
        pass

    raise ValidationError(
        "IP validation failed: neither valid IPv4 nor IPv6",
        field="ip", value=value,
    )


def validate_cidr(value: str) -> str:
    """Validate CIDR notation (IP/prefix).

    Accepts both IPv4 (e.g., '192.168.1.0/24') and IPv6 (e.g., 'fd00::/64').
    Validates prefix length: 0-32 for IPv4, 0-128 for IPv6.

    Args:
        value: CIDR string.

    Returns:
        Validated CIDR string.

    Raises:
        ValidationError: If format, IP, or prefix length is invalid.
    """
    if not value:
        raise ValidationError("CIDR validation failed: empty input", field="cidr")

    if "/" not in value:
        raise ValidationError(
            "CIDR validation failed: no prefix separator",
            field="cidr", value=value,
        )

    ip_part, prefix_part = value.rsplit("/", 1)

    # Validate prefix is numeric
    if not Pattern.NUMERIC.fullmatch(prefix_part):
        raise ValidationError(
            "CIDR validation failed: prefix is not numeric",
            field="cidr", value=value,
        )

    prefix = int(prefix_part)

    # Determine IP version first, then range-check the prefix OUTSIDE the
    # detection try-blocks. Raising the range error inside its own
    # try/except ValidationError would swallow the specific error and
    # misreport an out-of-range prefix as an invalid IP portion.
    is_v4 = False
    is_v6 = False
    try:
        validate_ipv4(ip_part)
        is_v4 = True
    except ValidationError:
        try:
            validate_ipv6(ip_part)
            is_v6 = True
        except ValidationError:
            pass

    if is_v4:
        if prefix > 32:
            raise ValidationError(
                f"CIDR validation failed: IPv4 prefix out of range ({prefix})",
                field="cidr", value=value,
            )
        return value

    if is_v6:
        if prefix > 128:
            raise ValidationError(
                f"CIDR validation failed: IPv6 prefix out of range ({prefix})",
                field="cidr", value=value,
            )
        return value

    raise ValidationError(
        "CIDR validation failed: invalid IP portion",
        field="cidr", value=value,
    )


def validate_protocol(value: str) -> str:
    """Validate and normalize a network protocol name.

    Accepted values: tcp, udp, icmp, icmpv6, sctp, all.

    Args:
        value: Protocol name (case-insensitive).

    Returns:
        Normalized lowercase protocol string.

    Raises:
        ValidationError: If protocol is not in the allowed set.
    """
    if not value:
        raise ValidationError(
            "Protocol validation failed: empty input", field="protocol",
        )

    normalized = value.lower().strip()

    if not Pattern.PROTOCOL.fullmatch(normalized):
        raise ValidationError(
            f"Protocol validation failed: {value!r}",
            field="protocol", value=value,
        )

    return normalized


def validate_hostname(value: str) -> str:
    """Validate a hostname per RFC 1123.

    Rejects hostnames longer than 253 characters, those containing shell
    metacharacters, and those not matching the RFC 1123 pattern.

    Args:
        value: Hostname string.

    Returns:
        Validated hostname string.

    Raises:
        ValidationError: If hostname is invalid or contains dangerous characters.
    """
    if not value:
        raise ValidationError(
            "Hostname validation failed: empty input", field="hostname",
        )

    if len(value) > 253:
        raise ValidationError(
            "Hostname validation failed: exceeds max length (253)",
            field="hostname", value=value,
        )

    if _contains_shell_meta(value):
        raise ValidationError(
            "Hostname validation failed: contains shell metacharacters",
            field="hostname", value=value,
        )

    if not Pattern.HOSTNAME.fullmatch(value):
        raise ValidationError(
            "Hostname validation failed: RFC 1123 pattern mismatch",
            field="hostname", value=value,
        )

    return value


def validate_interface(value: str) -> str:
    """Validate a network interface name.

    Must start with a letter and be at most 15 characters.

    Args:
        value: Interface name string.

    Returns:
        Validated interface name.

    Raises:
        ValidationError: If name is invalid.
    """
    if not value:
        raise ValidationError(
            "Interface validation failed: empty input", field="interface",
        )

    if len(value) > 15:
        raise ValidationError(
            "Interface validation failed: exceeds max length (15)",
            field="interface", value=value,
        )

    if not Pattern.INTERFACE.fullmatch(value):
        raise ValidationError(
            "Interface validation failed: pattern mismatch",
            field="interface", value=value,
        )

    return value


# ==============================================================================
# Path Validator
# ==============================================================================

def validate_file_path(value: str) -> str:
    """Validate a file path for safety.

    Rejects: empty input, overlength, directory traversal (..),
    shell metacharacters, null bytes, and unsafe characters.

    Args:
        value: File path string.

    Returns:
        Validated file path string.

    Raises:
        ValidationError: If path is unsafe.
    """
    if not value:
        raise ValidationError(
            "Path validation failed: empty input", field="file_path",
        )

    if len(value) > Security.MAX_PATH_LENGTH:
        raise ValidationError(
            "Path validation failed: exceeds max length",
            field="file_path", value=value,
        )

    # Reject directory traversal
    if ".." in value:
        raise ValidationError(
            "Path validation failed: directory traversal detected",
            field="file_path", value=value,
        )

    # Reject shell metacharacters (CWE-78)
    if _contains_shell_meta(value):
        raise ValidationError(
            "Path validation failed: shell metacharacters detected",
            field="file_path", value=value,
        )

    # Reject null bytes (CWE-158)
    if "\x00" in value:
        raise ValidationError(
            "Path validation failed: null byte detected",
            field="file_path", value=value,
        )

    # Must match safe path whitelist pattern
    if not Pattern.SAFE_PATH.fullmatch(value):
        raise ValidationError(
            "Path validation failed: unsafe characters",
            field="file_path", value=value,
        )

    return value


# ==============================================================================
# Firewall Name Validators
# ==============================================================================

def validate_zone(value: str) -> str:
    """Validate a firewalld zone name.

    Must start with a letter and be at most 32 characters.

    Args:
        value: Zone name string.

    Returns:
        Validated zone name.

    Raises:
        ValidationError: If zone name is invalid.
    """
    if not value:
        raise ValidationError(
            "Zone validation failed: empty input", field="zone",
        )

    if len(value) > 32:
        raise ValidationError(
            "Zone validation failed: exceeds max length (32)",
            field="zone", value=value,
        )

    if not Pattern.ZONE.fullmatch(value):
        raise ValidationError(
            "Zone validation failed: pattern mismatch",
            field="zone", value=value,
        )

    return value


def validate_chain(value: str) -> str:
    """Validate an iptables/nftables chain name.

    Must start with a letter and be at most 64 characters.

    Args:
        value: Chain name string.

    Returns:
        Validated chain name.

    Raises:
        ValidationError: If chain name is invalid.
    """
    if not value:
        raise ValidationError(
            "Chain validation failed: empty input", field="chain",
        )

    if len(value) > 64:
        raise ValidationError(
            "Chain validation failed: exceeds max length (64)",
            field="chain", value=value,
        )

    if not Pattern.CHAIN.fullmatch(value):
        raise ValidationError(
            "Chain validation failed: pattern mismatch",
            field="chain", value=value,
        )

    return value


def validate_table(value: str) -> str:
    """Validate an iptables/nftables table name.

    Must start with a letter and be at most 32 characters.

    Args:
        value: Table name string.

    Returns:
        Validated table name.

    Raises:
        ValidationError: If table name is invalid.
    """
    if not value:
        raise ValidationError(
            "Table validation failed: empty input", field="table",
        )

    if len(value) > 32:
        raise ValidationError(
            "Table validation failed: exceeds max length (32)",
            field="table", value=value,
        )

    if not Pattern.TABLE.fullmatch(value):
        raise ValidationError(
            "Table validation failed: pattern mismatch",
            field="table", value=value,
        )

    return value


def validate_table_family(value: str) -> str:
    """Validate an nftables table family.

    Accepted values: inet, ip, ip6, arp, bridge, netdev.

    Args:
        value: Table family string (case-insensitive).

    Returns:
        Normalized lowercase table family string.

    Raises:
        ValidationError: If family is not in the allowed set.
    """
    if not value:
        raise ValidationError(
            "Table family validation failed: empty input",
            field="table_family",
        )

    normalized = value.lower().strip()

    if normalized not in NFTABLES_TABLE_FAMILIES:
        raise ValidationError(
            f"Table family validation failed: {value!r}",
            field="table_family", value=value,
        )

    return normalized


def validate_ipset_name(value: str) -> str:
    """Validate an ipset set name.

    Must start with a letter and be at most 31 characters.

    Args:
        value: IPSet name string.

    Returns:
        Validated ipset name.

    Raises:
        ValidationError: If name is invalid.
    """
    if not value:
        raise ValidationError(
            "IPSet name validation failed: empty input", field="ipset_name",
        )

    if len(value) > 31:
        raise ValidationError(
            "IPSet name validation failed: exceeds max length (31)",
            field="ipset_name", value=value,
        )

    if not Pattern.IPSET_NAME.fullmatch(value):
        raise ValidationError(
            "IPSet name validation failed: pattern mismatch",
            field="ipset_name", value=value,
        )

    return value


# ==============================================================================
# Rule Parameter Validators
# ==============================================================================

def validate_rule_id(value: str) -> str:
    """Validate a rule UUID.

    Must be exactly 36 characters in lowercase hex UUID format
    (8-4-4-4-12).

    Args:
        value: Rule ID string.

    Returns:
        Validated rule ID string.

    Raises:
        ValidationError: If UUID format is invalid.
    """
    if not value:
        raise ValidationError(
            "Rule ID validation failed: empty input", field="rule_id",
        )

    if len(value) != 36:
        raise ValidationError(
            "Rule ID validation failed: wrong length (expected 36)",
            field="rule_id", value=value,
        )

    if not Pattern.RULE_ID.fullmatch(value):
        raise ValidationError(
            "Rule ID validation failed: UUID pattern mismatch",
            field="rule_id", value=value,
        )

    return value


def validate_rule_action(value: str) -> str:
    """Validate a firewall rule action (single or compound).

    Supports compound actions (comma-separated) like 'log,drop'.
    Compound actions must contain at most one terminal action
    (accept/drop/reject/masquerade/snat/dnat/return) and may include
    non-terminal actions (log).

    Args:
        value: Action string (case-insensitive, comma-separated for compound).

    Returns:
        Normalized lowercase action string.

    Raises:
        ValidationError: If action is unknown or compound has too many
                         terminal actions.
    """
    if not value:
        raise ValidationError(
            "Rule action validation failed: empty input", field="action",
        )

    # Normalize: lowercase, strip spaces
    normalized = value.lower().replace(" ", "")

    # Split on comma for compound actions
    parts = normalized.split(",")
    terminal_count = 0
    seen: set[str] = set()

    for part in parts:
        if not part:
            raise ValidationError(
                "Rule action validation failed: empty component",
                field="action", value=value,
            )

        if part not in ALL_ACTIONS:
            raise ValidationError(
                f"Unknown action component: {part!r}",
                field="action", value=value,
            )

        # Reject duplicate components (e.g., "log,log")
        if part in seen:
            raise ValidationError(
                f"Duplicate action component: {part!r}",
                field="action", value=value,
            )
        seen.add(part)

        if part in TERMINAL_ACTIONS:
            terminal_count += 1

    # At most one terminal action in a compound
    if terminal_count > 1:
        raise ValidationError(
            f"Compound action has {terminal_count} terminal actions (max 1)",
            field="action", value=value,
        )

    return normalized


def validate_rule_direction(value: str) -> str:
    """Validate a firewall rule direction.

    Accepted values: inbound, outbound, forward.

    Args:
        value: Direction string (case-insensitive).

    Returns:
        Normalized lowercase direction string.

    Raises:
        ValidationError: If direction is not in the allowed set.
    """
    if not value:
        raise ValidationError(
            "Rule direction validation failed: empty input",
            field="direction",
        )

    normalized = value.lower().strip()

    try:
        RuleDirection(normalized)
    except ValueError:
        valid = ", ".join(d.value for d in RuleDirection)
        raise ValidationError(
            f"Rule direction validation failed: {value!r}. "
            f"Valid directions: {valid}",
            field="direction", value=value,
        ) from None

    return normalized


def validate_duration_type(value: str) -> str:
    """Validate a rule duration type.

    Accepted values: permanent, temporary.

    Args:
        value: Duration type string (case-insensitive).

    Returns:
        Normalized lowercase duration type string.

    Raises:
        ValidationError: If duration type is not in the allowed set.
    """
    if not value:
        raise ValidationError(
            "Duration type validation failed: empty input",
            field="duration_type",
        )

    normalized = value.lower().strip()

    try:
        DurationType(normalized)
    except ValueError:
        valid = ", ".join(d.value for d in DurationType)
        raise ValidationError(
            f"Duration type validation failed: {value!r}. "
            f"Valid types: {valid}",
            field="duration_type", value=value,
        ) from None

    return normalized


def validate_ttl(value: str) -> int:
    """Validate a temporary rule TTL (time-to-live) in seconds.

    Must be between TTLLimits.MIN_SECONDS (60) and
    TTLLimits.MAX_SECONDS (2,592,000 = 30 days).

    Args:
        value: TTL in seconds as string.

    Returns:
        Validated TTL as integer.

    Raises:
        ValidationError: If non-numeric or out of range.
    """
    if not value:
        raise ValidationError(
            "TTL validation failed: empty input", field="ttl",
        )

    if not Pattern.NUMERIC.fullmatch(value):
        raise ValidationError(
            "TTL validation failed: non-numeric",
            field="ttl", value=value,
        )

    ttl = int(value)
    if ttl < TTLLimits.MIN_SECONDS or ttl > TTLLimits.MAX_SECONDS:
        raise ValidationError(
            f"TTL validation failed: out of range ({ttl}s, "
            f"min={TTLLimits.MIN_SECONDS}, max={TTLLimits.MAX_SECONDS})",
            field="ttl", value=value,
        )

    return ttl


def validate_log_level(value: str) -> str:
    """Validate a framework log level name or number.

    Accepts both names (e.g., 'debug', 'INFO') and numeric values.

    Args:
        value: Log level string.

    Returns:
        Normalized uppercase log level name.

    Raises:
        ValidationError: If level is not recognized.
    """
    if not value:
        raise ValidationError(
            "Log level validation failed: empty input", field="log_level",
        )

    # Try as name first (case-insensitive)
    try:
        level = LogLevel.from_string(value)
        return level.name
    except ValueError:
        pass

    # Try as numeric
    if Pattern.NUMERIC.fullmatch(value):
        try:
            level = LogLevel(int(value))
            return level.name
        except ValueError:
            pass

    raise ValidationError(
        f"Log level validation failed: {value!r}",
        field="log_level", value=value,
    )


def validate_syslog_level(value: str) -> str:
    """Validate a syslog severity level for firewall log actions.

    Accepted values: emerg, alert, crit, err, warning, notice, info, debug.

    Args:
        value: Syslog level string (case-insensitive).

    Returns:
        Normalized lowercase syslog level string.

    Raises:
        ValidationError: If level is not in the allowed set.
    """
    if not value:
        raise ValidationError(
            "Syslog level validation failed: empty input",
            field="syslog_level",
        )

    normalized = value.lower().strip()

    try:
        SyslogLevel(normalized)
    except ValueError:
        valid = ", ".join(s.value for s in SyslogLevel)
        raise ValidationError(
            f"Syslog level validation failed: {value!r}. "
            f"Valid levels: {valid}",
            field="syslog_level", value=value,
        ) from None

    return normalized


def validate_conn_state(value: str) -> str:
    """Validate connection tracking state(s).

    Accepts comma-separated states: new, established, related, invalid,
    untracked.

    Args:
        value: State string (single or comma-separated, case-insensitive).

    Returns:
        Normalized lowercase comma-separated state string.

    Raises:
        ValidationError: If any state component is invalid.
    """
    if not value:
        raise ValidationError(
            "Connection state validation failed: empty input",
            field="conn_state",
        )

    # Normalize: lowercase, strip spaces
    normalized = value.lower().replace(" ", "")

    # Validate each component
    valid_states = {s.value for s in ConnState}
    parts = normalized.split(",")

    for part in parts:
        if not part:
            raise ValidationError(
                "Connection state validation failed: empty component",
                field="conn_state", value=value,
            )
        if part not in valid_states:
            raise ValidationError(
                f"Invalid connection state: {part!r}",
                field="conn_state", value=value,
            )

    return normalized


def validate_log_prefix(value: str) -> str:
    """Validate a log prefix string.

    Must be 1-29 characters, alphanumeric plus basic punctuation
    (spaces, underscores, dots, colons, slashes, hyphens).

    Args:
        value: Log prefix string.

    Returns:
        Validated log prefix string.

    Raises:
        ValidationError: If prefix is empty, too long, or contains
                         invalid characters.
    """
    if not value:
        raise ValidationError(
            "Log prefix validation failed: empty input", field="log_prefix",
        )

    if len(value) > 29:
        raise ValidationError(
            "Log prefix validation failed: exceeds max length (29)",
            field="log_prefix", value=value,
        )

    if not _LOG_PREFIX_PATTERN.fullmatch(value):
        raise ValidationError(
            "Log prefix validation failed: invalid characters",
            field="log_prefix", value=value,
        )

    return value


def validate_rate_limit(value: str) -> str:
    """Validate a rate limit string.

    Accepted format: '<number>/<unit>' where unit is one of:
    second, minute, hour, day.

    Args:
        value: Rate limit string (e.g., '5/minute', '10/second').

    Returns:
        Validated rate limit string.

    Raises:
        ValidationError: If format is invalid.
    """
    if not value:
        raise ValidationError(
            "Rate limit validation failed: empty input", field="rate_limit",
        )

    if not _RATE_LIMIT_PATTERN.fullmatch(value):
        raise ValidationError(
            "Rate limit validation failed: invalid format. "
            "Expected: <number>/(second|minute|hour|day)",
            field="rate_limit", value=value,
        )

    return value


# ==============================================================================
# Generic Validators
# ==============================================================================

def validate_numeric(
    value: str,
    min_value: int | None = None,
    max_value: int | None = None,
) -> int:
    """Validate that input is a positive integer with optional range.

    Args:
        value:     Input string.
        min_value: Minimum allowed value (inclusive, optional).
        max_value: Maximum allowed value (inclusive, optional).

    Returns:
        Validated integer.

    Raises:
        ValidationError: If non-numeric or out of range.
    """
    if not value:
        raise ValidationError(
            "Numeric validation failed: empty input", field="numeric",
        )

    if not Pattern.NUMERIC.fullmatch(value):
        raise ValidationError(
            "Numeric validation failed: non-numeric characters",
            field="numeric", value=value,
        )

    num = int(value)

    if min_value is not None and num < min_value:
        raise ValidationError(
            f"Numeric validation failed: {num} < {min_value}",
            field="numeric", value=value, min=str(min_value),
        )

    if max_value is not None and num > max_value:
        raise ValidationError(
            f"Numeric validation failed: {num} > {max_value}",
            field="numeric", value=value, max=str(max_value),
        )

    return num


def validate_description(value: str) -> str:
    """Validate a rule description string.

    Allows empty descriptions. Rejects descriptions exceeding the
    maximum length or containing shell metacharacters.

    Args:
        value: Description string (may be empty).

    Returns:
        Validated description string.

    Raises:
        ValidationError: If too long or contains dangerous characters.
    """
    # Empty descriptions are valid
    if not value:
        return ""

    if len(value) > Security.MAX_RULE_DESCRIPTION_LENGTH:
        raise ValidationError(
            f"Description validation failed: exceeds max length "
            f"({len(value)} > {Security.MAX_RULE_DESCRIPTION_LENGTH})",
            field="description", value=value,
        )

    if _contains_shell_meta(value):
        raise ValidationError(
            "Description validation failed: shell metacharacters detected",
            field="description", value=value,
        )

    return value


# ==============================================================================
# Input Sanitizer
# ==============================================================================

def sanitize_input(value: str) -> str:
    """Sanitize a general input string using a WHITELIST approach.

    Keeps only known-safe characters -- everything else is stripped.
    This is a defense-in-depth measure applied after validation.

    Allowed characters: alphanumeric, space, dot, comma, underscore,
    colon, slash, plus, equals, at sign, tilde, percent, hyphen.

    Processing steps:
    1. Truncate to MAX_INPUT_LENGTH
    2. Remove null bytes
    3. Strip non-whitelisted characters (the whitelist contains only
       printable characters, so control characters are removed here too)
    4. Trim leading/trailing whitespace

    Args:
        value: Raw input string to sanitize.

    Returns:
        Sanitized string with only whitelisted characters.

    Raises:
        SanitizationError: If input is None (not a string).
    """
    if value is None:
        raise SanitizationError("Cannot sanitize None input")

    # 1. Enforce maximum length
    if len(value) > Security.MAX_INPUT_LENGTH:
        value = value[:Security.MAX_INPUT_LENGTH]

    # 2. Remove null bytes
    value = value.replace("\x00", "")

    # 3. Strip non-whitelisted characters via regex substitution.
    #    The whitelist admits only printable characters, so this step also
    #    removes every control character.
    value = _SANITIZE_WHITELIST.sub("", value)

    # 4. Trim leading/trailing whitespace
    value = value.strip()

    return value


# ==============================================================================
# Convenience: Check if a value is a cancel keyword
# ==============================================================================

def is_cancel_keyword(value: str) -> bool:
    """Check if user input is a cancel/quit keyword.

    Used by the interactive wizard to detect abort requests at any prompt.

    Args:
        value: Raw user input string.

    Returns:
        True if the input matches a cancel keyword (case-insensitive).
    """
    return value.strip().lower() in CANCEL_KEYWORDS
