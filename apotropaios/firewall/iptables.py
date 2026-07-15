# ==============================================================================
# File:         apotropaios/firewall/iptables.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     iptables firewall backend implementation
# Description:  Implements the FirewallBackend ABC for iptables. Provides full
#               rule management including compound actions (log,drop creates
#               separate LOG + terminal rules), connection tracking, rate
#               limiting, table/chain selection, and configuration persistence
#               via iptables-save/iptables-restore.
#
#               Key design decisions:
#               - All commands use subprocess.run() with list-form args (never
#                 shell=True) per Lesson #2
#               - stderr is always captured per Lesson #3
#               - Compound actions create MULTIPLE rules; removal mirrors add
#                 logic exactly per Lesson #9
#               - All user-supplied parameters are re-validated before building
#                 commands, even when loaded from the rule index
#               - Direction maps to chain: inbound→INPUT, outbound→OUTPUT,
#                 forward→FORWARD (overridable via explicit --chain)
#
# Notes:        - Requires root privileges for all operations
#               - Supports tables: filter, nat, mangle, raw, security
#               - Supports built-in chains: INPUT, OUTPUT, FORWARD,
#                 PREROUTING, POSTROUTING, plus custom chains
#               - iptables-save/iptables-restore for persistence
#               - Thread-safe: no shared mutable state
#               - Parity target: bash v1.1.10 lib/firewall/iptables.sh
# Version:      1.2.1
# ==============================================================================

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Final

from apotropaios.core.constants import (
    IPTABLES_TABLES,
    NON_TERMINAL_ACTIONS,
    TERMINAL_ACTIONS,
    Color,
    Performance,
    Security,
)
from apotropaios.core.errors import (
    RuleApplyError,
    RuleRemoveError,
)
from apotropaios.core.validation import (
    sanitize_input,
    validate_chain,
    validate_cidr,
    validate_conn_state,
    validate_interface,
    validate_ip,
    validate_log_prefix,
    validate_numeric,
    validate_port,
    validate_port_range,
    validate_protocol,
    validate_rate_limit,
    validate_syslog_level,
    validate_table,
)
from apotropaios.firewall.base import FirewallBackend

# Subprocess timeout for iptables commands
_CMD_TIMEOUT: Final[int] = Performance.SUBPROCESS_TIMEOUT

# Logger reference (set via set_logger)
_log_fn: object | None = None


def _set_logger(logger: object) -> None:
    """Set the logger for the iptables backend."""
    global _log_fn
    _log_fn = logger


def _log(level: str, msg: str) -> None:
    """Emit a log message if logger is available."""
    if _log_fn is not None:
        method = getattr(_log_fn, level, None)
        if method is not None:
            method("iptables", msg)


def _run(args: list[str], check: bool = False) -> subprocess.CompletedProcess[str]:
    """Execute an iptables command with security constraints.

    Always uses list-form arguments (never shell=True), captures both
    stdout and stderr, and enforces a timeout.

    Args:
        args: Command and arguments as list (e.g., ['iptables', '-L']).
        check: If True, raise CalledProcessError on non-zero exit code.

    Returns:
        CompletedProcess with stdout, stderr, and returncode.
    """
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=_CMD_TIMEOUT,
        check=check,
    )


def _direction_to_chain(direction: str) -> str:
    """Map a rule direction to the default iptables chain.

    Args:
        direction: 'inbound', 'outbound', or 'forward'.

    Returns:
        Chain name: 'INPUT', 'OUTPUT', or 'FORWARD'.
    """
    mapping: dict[str, str] = {
        "inbound": "INPUT",
        "outbound": "OUTPUT",
        "forward": "FORWARD",
    }
    return mapping.get(direction, "INPUT")


def _action_to_target(action: str) -> str:
    """Map a rule action to an iptables target name.

    Args:
        action: Lowercase action string (e.g., 'accept', 'drop').

    Returns:
        Uppercase iptables target (e.g., 'ACCEPT', 'DROP').
    """
    return action.upper()


# ==============================================================================
# Build Match Arguments
#
# Shared logic for constructing the common match portion of iptables commands.
# Used by both add_rule and remove_rule to ensure exact mirroring (Lesson #9).
# ==============================================================================

def _build_match_args(rule: dict[str, str]) -> tuple[list[str], str, str]:
    """Build the common match arguments for an iptables command.

    Validates all parameters and constructs the argument list that is
    shared between -A (append) and -D (delete) commands.

    Args:
        rule: Rule parameters dictionary.

    Returns:
        Tuple of (match_args, table, chain) where:
        - match_args: List of iptables arguments for matching
        - table: Validated table name
        - chain: Resolved chain name

    Raises:
        RuleApplyError: If any parameter fails validation.
    """
    direction = rule.get("direction", "inbound")
    protocol = rule.get("protocol", "")
    src_ip = rule.get("src_ip", "")
    dst_ip = rule.get("dst_ip", "")
    src_port = rule.get("src_port", "")
    dst_port = rule.get("dst_port", "")
    chain = rule.get("chain", "")
    table = rule.get("table", "filter")
    interface = rule.get("interface", "")
    comment = rule.get("comment", "")
    conn_state = rule.get("conn_state", "")
    limit = rule.get("limit", "")
    limit_burst = rule.get("limit_burst", "")

    match_args: list[str] = []

    # Validate and set table
    if table:
        validate_table(table)
        # iptables-specific: only the 5 standard tables are valid
        if table not in IPTABLES_TABLES:
            raise RuleApplyError(
                f"Invalid iptables table: {table!r}. "
                f"Valid tables: {', '.join(sorted(IPTABLES_TABLES))}",
                backend="iptables",
            )

    # Resolve chain from direction if not explicit
    if not chain:
        chain = _direction_to_chain(direction)
    validate_chain(chain)

    # Protocol
    if protocol:
        protocol = validate_protocol(protocol)
        if protocol != "all":
            match_args.extend(["-p", protocol])

    # Source IP (accepts IP or CIDR)
    if src_ip:
        try:
            validate_ip(src_ip)
        except Exception:
            validate_cidr(src_ip)
        match_args.extend(["-s", src_ip])

    # Destination IP
    if dst_ip:
        try:
            validate_ip(dst_ip)
        except Exception:
            validate_cidr(dst_ip)
        match_args.extend(["-d", dst_ip])

    # Interface: inbound uses -i, outbound uses -o
    if interface:
        validate_interface(interface)
        if direction == "inbound" or chain == "INPUT":
            match_args.extend(["-i", interface])
        else:
            match_args.extend(["-o", interface])

    # Source port (requires protocol)
    if src_port:
        try:
            validate_port(src_port)
        except Exception:
            validate_port_range(src_port)
        match_args.extend(["--sport", src_port])

    # Destination port
    if dst_port:
        try:
            validate_port(dst_port)
        except Exception:
            validate_port_range(dst_port)
        match_args.extend(["--dport", dst_port])

    # Connection tracking state (re-validated per the module contract:
    # all user-supplied parameters are re-validated before command build)
    if conn_state:
        conn_state = validate_conn_state(conn_state)
        ct_upper = conn_state.upper()
        match_args.extend(["-m", "conntrack", "--ctstate", ct_upper])

    # Rate limiting (re-validated)
    if limit:
        validate_rate_limit(limit)
        match_args.extend(["-m", "limit", "--limit", limit])
        if limit_burst:
            validate_numeric(limit_burst, min_value=1)
            match_args.extend(["--limit-burst", limit_burst])

    # Comment for rule tracking
    if comment:
        safe_comment = sanitize_input(comment)
        match_args.extend(["-m", "comment", "--comment", safe_comment])

    return (match_args, table, chain)


def _parse_compound_action(action: str) -> tuple[list[str], str]:
    """Parse a compound action string into non-terminal and terminal parts.

    Args:
        action: Action string (e.g., 'log,drop', 'accept', 'log').

    Returns:
        Tuple of (non_terminal_list, terminal_action) where terminal_action
        may be empty string if no terminal action present.
    """
    parts = action.lower().replace(" ", "").split(",")
    non_terminal: list[str] = []
    terminal = ""

    for part in parts:
        if part in NON_TERMINAL_ACTIONS:
            non_terminal.append(part)
        elif part in TERMINAL_ACTIONS:
            terminal = part
        # Unknown parts are silently skipped (validated upstream)

    return (non_terminal, terminal)


# ==============================================================================
# IptablesBackend Class
# ==============================================================================

class IptablesBackend(FirewallBackend):
    """iptables firewall backend implementation.

    Supports all 5 tables (filter, nat, mangle, raw, security), built-in
    and custom chains, compound actions (LOG + terminal), connection
    tracking, rate limiting, and configuration persistence.
    """

    @property
    def name(self) -> str:
        """Return the canonical backend name."""
        return "iptables"

    def add_rule(self, rule: dict[str, str]) -> bool:
        """Add iptables rule(s).

        For compound actions (e.g., 'log,drop'), creates separate rules:
        1. LOG rule with prefix/level (non-terminating in iptables)
        2. Terminal rule (DROP, ACCEPT, etc.)

        Args:
            rule: Rule parameters dictionary.

        Returns:
            True on success.

        Raises:
            RuleApplyError: If any rule cannot be applied.
        """
        action = rule.get("action", "accept")
        log_prefix = rule.get("log_prefix", "")
        log_level = rule.get("log_level", "")
        comment = rule.get("comment", "")

        # Re-validate log options before use in command construction
        if log_prefix:
            validate_log_prefix(log_prefix)
        if log_level:
            log_level = validate_syslog_level(log_level)

        # Build shared match arguments
        match_args, table, chain = _build_match_args(rule)

        # Parse compound action
        non_terminal, terminal = _parse_compound_action(action)

        # Apply non-terminal actions first (LOG rules)
        for nt_action in non_terminal:
            log_cmd: list[str] = ["iptables"]
            if table:
                log_cmd.extend(["-t", table])
            log_cmd.extend(["-A", chain])
            log_cmd.extend(match_args)
            log_cmd.extend(["-j", "LOG"])

            # Log options
            if log_prefix:
                log_cmd.extend(["--log-prefix", log_prefix])
            elif comment:
                # Auto-generate prefix from comment
                log_cmd.extend(["--log-prefix", f"[{sanitize_input(comment)}] "])
            if log_level:
                log_cmd.extend(["--log-level", log_level])

            _log("info", f"Adding LOG rule: {' '.join(log_cmd)}")
            result = _run(log_cmd)
            if result.returncode != 0:
                stderr = result.stderr.strip()
                _log("error", f"Failed to add LOG rule: {stderr}")
                raise RuleApplyError(
                    f"Failed to add LOG rule: {stderr}",
                    backend="iptables",
                )

        # Apply terminal action
        if terminal:
            target = _action_to_target(terminal)
            term_cmd: list[str] = ["iptables"]
            if table:
                term_cmd.extend(["-t", table])
            term_cmd.extend(["-A", chain])
            term_cmd.extend(match_args)
            term_cmd.extend(["-j", target])

            _log("info", f"Adding rule: {' '.join(term_cmd)}")
            result = _run(term_cmd)
            if result.returncode != 0:
                stderr = result.stderr.strip()
                _log("error", f"Failed to add rule: {stderr}")
                raise RuleApplyError(
                    f"Failed to add rule: {stderr}",
                    backend="iptables",
                )

        # Validate at least one rule was created
        if not terminal and not non_terminal:
            raise RuleApplyError(
                "No valid action to apply",
                backend="iptables", action=action,
            )

        _log("info", "Rule(s) added successfully")
        return True

    def remove_rule(self, rule: dict[str, str]) -> bool:
        """Remove iptables rule(s).

        For compound actions, removes both the terminal and LOG rules,
        mirroring the add logic exactly (Lesson #9). Terminal rule is
        removed first to prevent LOG rules from matching traffic with
        no terminal to follow.

        Args:
            rule: Rule parameters dictionary.

        Returns:
            True on success.

        Raises:
            RuleRemoveError: If removal fails critically.
        """
        action = rule.get("action", "accept")
        log_prefix = rule.get("log_prefix", "")
        log_level = rule.get("log_level", "")
        comment = rule.get("comment", "")

        # Re-validate log options before use in command construction
        if log_prefix:
            validate_log_prefix(log_prefix)
        if log_level:
            log_level = validate_syslog_level(log_level)

        # Re-validate parameters from index (Lesson #9 / H4 fix)
        match_args, table, chain = _build_match_args(rule)

        # Parse compound action
        non_terminal, terminal = _parse_compound_action(action)

        partial_failure = False

        # Remove terminal rule FIRST (so LOG doesn't match orphaned traffic)
        if terminal:
            target = _action_to_target(terminal)
            del_cmd: list[str] = ["iptables"]
            if table:
                del_cmd.extend(["-t", table])
            del_cmd.extend(["-D", chain])
            del_cmd.extend(match_args)
            del_cmd.extend(["-j", target])

            _log("info", f"Removing terminal rule: {' '.join(del_cmd)}")
            result = _run(del_cmd)
            if result.returncode != 0:
                _log("warning", "Failed to remove terminal rule (may have been manually removed)")
                partial_failure = True

        # Remove non-terminal (LOG) rules
        for nt_action in non_terminal:
            log_del: list[str] = ["iptables"]
            if table:
                log_del.extend(["-t", table])
            log_del.extend(["-D", chain])
            log_del.extend(match_args)
            log_del.extend(["-j", "LOG"])

            if log_prefix:
                log_del.extend(["--log-prefix", log_prefix])
            elif comment:
                log_del.extend(["--log-prefix", f"[{sanitize_input(comment)}] "])
            if log_level:
                log_del.extend(["--log-level", log_level])

            _log("info", f"Removing LOG rule: {' '.join(log_del)}")
            result = _run(log_del)
            if result.returncode != 0:
                _log("warning", "Failed to remove LOG rule (may have been manually removed)")
                partial_failure = True

        # Handle single non-compound action (neither compound terminal nor non-terminal parsed)
        if not terminal and not non_terminal:
            simple_del: list[str] = ["iptables"]
            if table:
                simple_del.extend(["-t", table])
            simple_del.extend(["-D", chain])
            simple_del.extend(match_args)
            simple_del.extend(["-j", _action_to_target(action)])

            _log("info", f"Removing rule: {' '.join(simple_del)}")
            result = _run(simple_del)
            if result.returncode != 0:
                stderr = result.stderr.strip()
                _log("error", f"Failed to remove rule: {stderr}")
                raise RuleRemoveError(
                    f"Failed to remove rule: {stderr}",
                    backend="iptables",
                )

        if partial_failure:
            _log("warning", "Rule removal partially completed (some rules may have been manually removed)")
        else:
            _log("info", "Rule(s) removed successfully")

        return True

    def list_rules(self, **kwargs: str) -> str:
        """List current iptables rules.

        Args:
            table: iptables table (default: 'filter').
            chain: Specific chain to list (default: all chains).

        Returns:
            Formatted rule listing string.
        """
        table = kwargs.get("table", "filter")
        chain = kwargs.get("chain", "")

        cmd: list[str] = ["iptables", "-t", table, "-L", "-n", "-v", "--line-numbers"]
        if chain:
            cmd.append(chain)

        try:
            result = _run(cmd)
        except subprocess.TimeoutExpired:
            return "Error: iptables command timed out"

        output = result.stdout.strip()
        stderr = result.stderr.strip()

        # Check for permission errors
        for err_msg in ("Permission denied", "you must be root", "Operation not permitted"):
            if err_msg in output or err_msg in stderr:
                return f"{Color.RED}Root privileges required to list iptables rules{Color.RESET}"

        return output if output else "No iptables rules currently configured"

    def enable(self) -> bool:
        """Start and enable the firewall service.

        Returns:
            True on success.
        """
        ok = True
        if shutil.which("systemctl"):
            result = subprocess.run(
                ["systemctl", "start", "iptables"],
                capture_output=True, timeout=_CMD_TIMEOUT,
            )
            if result.returncode != 0:
                stderr = result.stderr.decode() if isinstance(result.stderr, bytes) else result.stderr
                _log("warning", f"Failed to start iptables service: {stderr}")
                ok = False
            result = subprocess.run(
                ["systemctl", "enable", "iptables"],
                capture_output=True, timeout=_CMD_TIMEOUT,
            )
            if result.returncode != 0:
                stderr = result.stderr.decode() if isinstance(result.stderr, bytes) else result.stderr
                _log("warning", f"Failed to enable iptables service: {stderr}")
                ok = False
        if ok:
            _log("info", "iptables enabled")
        return ok

    def disable(self) -> bool:
        """Stop the firewall service.

        Returns:
            True on success.
        """
        ok = True
        if shutil.which("systemctl"):
            result = subprocess.run(
                ["systemctl", "stop", "iptables"],
                capture_output=True, timeout=_CMD_TIMEOUT,
            )
            if result.returncode != 0:
                stderr = result.stderr.decode() if isinstance(result.stderr, bytes) else result.stderr
                _log("warning", f"Failed to stop iptables service: {stderr}")
                ok = False
        if ok:
            _log("info", "iptables disabled")
        return ok

    def status(self) -> str:
        """Get iptables status with rule listing."""
        header = f"{Color.BOLD}iptables Status:{Color.RESET}\n"

        try:
            result = _run(["iptables", "-L", "-n", "--line-numbers"])
        except subprocess.TimeoutExpired:
            return header + "  Error: iptables command timed out\n"

        output = result.stdout.strip()
        stderr = result.stderr.strip()

        for err_msg in ("Permission denied", "you must be root", "Operation not permitted"):
            if err_msg in output or err_msg in stderr:
                return (
                    header +
                    f"  {Color.RED}Root privileges required to view iptables status{Color.RESET}\n"
                    f"  Run with: sudo python3 -m apotropaios\n"
                )

        if not output:
            return header + "  No iptables rules currently configured\n"

        return header + output + "\n"

    def block_all(self) -> bool:
        """Block all inbound and outbound traffic.

        Sets default policies to DROP and preserves loopback.
        """
        _log("warning", "Blocking ALL traffic (inbound + outbound)")

        # Set default policies to DROP — each result is checked: a failed
        # policy change would leave the emergency control claiming success
        # while traffic still passes (fail-open)
        ok = True
        for chain, target in (("INPUT", "DROP"), ("OUTPUT", "DROP"), ("FORWARD", "DROP")):
            result = _run(["iptables", "-P", chain, target])
            if result.returncode != 0:
                _log("error", f"Failed to set {chain} policy to {target}: {result.stderr.strip()}")
                ok = False

        # Preserve loopback (best-effort: failure narrows, not widens, access)
        for args in (
            ["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
            ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
        ):
            result = _run(args)
            if result.returncode != 0:
                _log("warning", f"Failed to add loopback rule: {result.stderr.strip()}")

        if not ok:
            _log("error", "block-all did NOT fully apply — traffic may still pass")
            return False
        _log("info", "All traffic blocked (loopback preserved)")
        return True

    def allow_all(self) -> bool:
        """Allow all traffic by flushing rules and setting ACCEPT policies.

        Flushes all chains in the filter table first to remove any existing
        DROP/REJECT rules, then sets default policies to ACCEPT.

        Returns:
            True on success.
        """
        _log("warning", "Allowing ALL traffic (inbound + outbound)")

        ok = True
        # Flush filter table rules first to remove any blocking rules
        result = _run(["iptables", "-t", "filter", "-F"])
        if result.returncode != 0:
            _log("error", f"Failed to flush filter table: {result.stderr.strip()}")
            ok = False

        for chain in ("INPUT", "OUTPUT", "FORWARD"):
            result = _run(["iptables", "-P", chain, "ACCEPT"])
            if result.returncode != 0:
                _log("error", f"Failed to set {chain} policy to ACCEPT: {result.stderr.strip()}")
                ok = False

        if ok:
            _log("info", "All traffic allowed (filter rules flushed, policies set to ACCEPT)")
        return ok

    def reset(self) -> bool:
        """Flush all rules and reset to defaults.

        Flushes (-F), deletes custom chains (-X), and zeroes counters (-Z)
        across all 5 iptables tables, then resets default policies to ACCEPT.
        """
        _log("warning", "Resetting iptables to defaults (flushing all rules)")

        ok = True
        # Flush all chains in all tables
        for tbl in ("filter", "nat", "mangle", "raw", "security"):
            for flag in ("-F", "-X", "-Z"):
                result = _run(["iptables", "-t", tbl, flag])
                if result.returncode != 0:
                    _log("warning", f"iptables -t {tbl} {flag} failed: {result.stderr.strip()}")
                    ok = False

        # Reset default policies
        for chain in ("INPUT", "OUTPUT", "FORWARD"):
            result = _run(["iptables", "-P", chain, "ACCEPT"])
            if result.returncode != 0:
                _log("error", f"Failed to reset {chain} policy: {result.stderr.strip()}")
                ok = False

        if ok:
            _log("info", "iptables reset complete")
        return ok

    def save(self, path: str = "") -> bool:
        """Save current iptables rules to file via iptables-save.

        Args:
            path: Output file path (default: /etc/iptables/rules.v4).

        Returns:
            True on success.
        """
        if not path:
            path = "/etc/iptables/rules.v4"

        # Ensure parent directory exists
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        iptables_save = shutil.which("iptables-save")
        if not iptables_save:
            _log("error", "iptables-save command not available")
            return False

        try:
            result = _run([iptables_save])
            if result.returncode != 0:
                _log("error", f"iptables-save failed: {result.stderr.strip()}")
                return False

            with open(path, "w", encoding="utf-8") as f:
                f.write(result.stdout)

            os.chmod(path, Security.FILE_PERMS)
            _log("info", f"Rules saved to {path}")
            return True
        except OSError as exc:
            _log("error", f"Failed to save rules to {path}: {exc}")
            return False

    def load(self, path: str) -> bool:
        """Load iptables rules from file via iptables-restore.

        Args:
            path: Input file path.

        Returns:
            True on success.
        """
        if not os.path.isfile(path):
            _log("error", f"Rules file not found: {path}")
            return False

        iptables_restore = shutil.which("iptables-restore")
        if not iptables_restore:
            _log("error", "iptables-restore command not available")
            return False

        try:
            with open(path, "r", encoding="utf-8") as f:
                rules_content = f.read()

            result = subprocess.run(
                [iptables_restore],
                input=rules_content,
                capture_output=True,
                text=True,
                timeout=_CMD_TIMEOUT,
            )

            if result.returncode != 0:
                _log("error", f"iptables-restore failed: {result.stderr.strip()}")
                return False

            _log("info", f"Rules reloaded from {path}")
            return True
        except OSError as exc:
            _log("error", f"Failed to load rules from {path}: {exc}")
            return False


# ==============================================================================
# Module-Level Registration
#
# Create a singleton instance and register with the backend registry.
# This runs at import time so the backend is available for selection.
# ==============================================================================

_instance: IptablesBackend = IptablesBackend()

# Register with the backend registry (imported lazily to avoid circular deps)
from apotropaios.firewall.common import register_backend  # noqa: E402

register_backend(_instance)
