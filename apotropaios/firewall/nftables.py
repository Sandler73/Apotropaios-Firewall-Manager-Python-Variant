# ==============================================================================
# File:         apotropaios/firewall/nftables.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     nftables firewall backend implementation
# Description:  Implements the FirewallBackend ABC for nftables. Provides rule
#               management using the nft command-line tool with table family
#               support (inet/ip/ip6/arp/bridge/netdev), auto-creation of tables
#               and chains, and compound actions as single nft expressions (e.g.,
#               "log prefix ... drop" in one rule — unlike iptables which needs
#               separate rules).
#
#               Security: All commands use subprocess.run() with list-form args.
#               nft -f file mode is NOT used (removed in bash variant as injection
#               vector via semicolons — C4 security fix). The nft command string
#               is built from individually validated components and passed via
#               subprocess stdin or individual nft invocations.
#
# Notes:        - Requires root privileges for all operations
#               - Table families: inet, ip, ip6, arp, bridge, netdev
#               - Default table: "apotropaios" (inet family)
#               - Chains auto-created with appropriate hook/priority
#               - Rule removal by handle number (found via comment match)
#               - Parity target: bash v1.1.10 lib/firewall/nftables.sh
# Version:      1.2.1
# ==============================================================================

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Final

from apotropaios.core.constants import (
    Color,
    Performance,
    Security,
)
from apotropaios.core.errors import (
    RuleApplyError,
    RuleNotFoundError,
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
    validate_table_family,
)
from apotropaios.firewall.base import FirewallBackend

_CMD_TIMEOUT: Final[int] = Performance.SUBPROCESS_TIMEOUT
_log_fn: object | None = None


def _log(level: str, msg: str) -> None:
    if _log_fn is not None:
        method = getattr(_log_fn, level, None)
        if method is not None:
            method("nftables", msg)


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    """Execute a subprocess command with timeout and capture."""
    return subprocess.run(
        args, capture_output=True, text=True, timeout=_CMD_TIMEOUT,
    )


def _nft_cmd(nft_expr: str) -> subprocess.CompletedProcess[str]:
    """Execute an nft command expression.

    The expression is passed as a single argument to nft, not via -f file
    mode (security: -f interprets semicolons as command separators).

    Args:
        nft_expr: nft command string (e.g., "add rule inet apotropaios input tcp dport 443 accept").

    Returns:
        CompletedProcess result.
    """
    return subprocess.run(
        ["nft", nft_expr],
        capture_output=True, text=True, timeout=_CMD_TIMEOUT,
    )


def _ensure_table(family: str, table: str) -> bool:
    """Ensure an nftables table exists, creating it if needed."""
    result = _run(["nft", "list", "table", family, table])
    if result.returncode != 0:
        _log("debug", f"Creating table: {family} {table}")
        result = _nft_cmd(f"add table {family} {table}")
        if result.returncode != 0:
            _log("error", f"Failed to create table: {family} {table}: {result.stderr.strip()}")
            return False
    return True


def _ensure_chain(family: str, table: str, chain: str, direction: str) -> bool:
    """Ensure an nftables chain exists, creating it if needed."""
    result = _run(["nft", "list", "chain", family, table, chain])
    if result.returncode != 0:
        hook_map = {"inbound": "input", "outbound": "output", "forward": "forward"}
        hook = hook_map.get(direction, "input")
        chain_def = (
            f"add chain {family} {table} {chain} "
            f"{{ type filter hook {hook} priority 0; policy accept; }}"
        )
        _log("debug", f"Creating chain: {family} {table} {chain} (hook={hook})")
        result = _nft_cmd(chain_def)
        if result.returncode != 0:
            _log("error", f"Failed to create chain: {result.stderr.strip()}")
            return False
    return True


def _direction_to_chain(direction: str) -> str:
    return {"inbound": "input", "outbound": "output", "forward": "forward"}.get(direction, "input")


class NftablesBackend(FirewallBackend):
    """nftables firewall backend implementation."""

    @property
    def name(self) -> str:
        """Backend identifier string."""
        return "nftables"

    def add_rule(self, rule: dict[str, str]) -> bool:
        """Add a firewall rule via backend-specific commands.

        Args:
            rule: Dictionary of rule parameters.

        Returns:
            True on success.

        Raises:
            RuleApplyError: If the backend rejects the rule.
        """
        direction = rule.get("direction", "inbound")
        protocol = rule.get("protocol", "")
        src_ip = rule.get("src_ip", "")
        dst_ip = rule.get("dst_ip", "")
        src_port = rule.get("src_port", "")
        dst_port = rule.get("dst_port", "")
        action = rule.get("action", "accept")
        chain = rule.get("chain", "")
        table = rule.get("table", "apotropaios")
        table_family = rule.get("table_family", "inet")
        interface = rule.get("interface", "")
        comment = rule.get("comment", "")
        conn_state = rule.get("conn_state", "")
        limit = rule.get("limit", "")
        limit_burst = rule.get("limit_burst", "")
        log_prefix = rule.get("log_prefix", "")
        log_level = rule.get("log_level", "")

        # Validate
        validate_table(table)
        validate_table_family(table_family)
        if not chain:
            chain = _direction_to_chain(direction)
        validate_chain(chain)

        # Ensure table and chain exist
        if not _ensure_table(table_family, table):
            raise RuleApplyError("Failed to ensure nftables table", backend="nftables")
        if not _ensure_chain(table_family, table, chain, direction):
            raise RuleApplyError("Failed to ensure nftables chain", backend="nftables")

        # Build nft rule expression
        expr_parts: list[str] = []

        # Protocol
        if protocol:
            protocol = validate_protocol(protocol)
            if protocol != "all":
                expr_parts.append(protocol)

        # Source/Dest IP. nft distinguishes protocol families in the match
        # keyword itself: IPv4 operands use "ip", IPv6 operands need "ip6" —
        # emitting "ip saddr" for an IPv6 address is a syntax error.
        if src_ip:
            try:
                validate_ip(src_ip)
            except Exception:
                validate_cidr(src_ip)
            addr_family = "ip6" if ":" in src_ip else "ip"
            expr_parts.append(f"{addr_family} saddr {src_ip}")
        if dst_ip:
            try:
                validate_ip(dst_ip)
            except Exception:
                validate_cidr(dst_ip)
            addr_family = "ip6" if ":" in dst_ip else "ip"
            expr_parts.append(f"{addr_family} daddr {dst_ip}")

        # Interface
        if interface:
            validate_interface(interface)
            if direction == "inbound":
                expr_parts.append(f'iifname "{interface}"')
            else:
                expr_parts.append(f'oifname "{interface}"')

        # Ports (require protocol context)
        if src_port and protocol:
            try:
                validate_port(src_port)
            except Exception:
                validate_port_range(src_port)
            nft_port = src_port.replace(":", "-")
            expr_parts.append(f"{protocol} sport {nft_port}")
        if dst_port and protocol:
            try:
                validate_port(dst_port)
            except Exception:
                validate_port_range(dst_port)
            nft_port = dst_port.replace(":", "-")
            expr_parts.append(f"{protocol} dport {nft_port}")

        # Connection tracking
        if conn_state:
            validate_conn_state(conn_state)  # Defense-in-depth validation
            expr_parts.append(f"ct state {conn_state.lower()}")

        # Rate limiting (re-validated: values are interpolated into the
        # nft command string, so the whitelist formats below are the only
        # accepted shapes — defense-in-depth against statement injection)
        if limit:
            validate_rate_limit(limit)
            expr_parts.append(f"limit rate {limit}")
            if limit_burst:
                validate_numeric(limit_burst, min_value=1)
                expr_parts.append(f"burst {limit_burst} packets")

        # Comment
        if comment:
            safe_comment = sanitize_input(comment)
            expr_parts.append(f'comment "{safe_comment}"')

        # Verdict — nftables supports compound in single expression: "log prefix ... drop"
        action_lower = action.lower().replace(" ", "")
        for apart in action_lower.split(","):
            if apart == "log":
                verdict = "log"
                if log_prefix:
                    # Re-validated: whitelist excludes quotes/semicolons,
                    # preventing breakout from the nft string literal
                    validate_log_prefix(log_prefix)
                    verdict += f' prefix "{log_prefix}"'
                if log_level:
                    log_level = validate_syslog_level(log_level)
                    verdict += f" level {log_level}"
                expr_parts.append(verdict)
            elif apart in ("accept", "drop", "reject", "masquerade", "return"):
                expr_parts.append(apart)
            else:
                raise RuleApplyError(f"Unsupported nftables action: {apart}", backend="nftables")

        rule_expr = " ".join(expr_parts)
        nft_full = f"add rule {table_family} {table} {chain} {rule_expr}"

        _log("info", f"Adding rule: nft {nft_full}")
        result = _nft_cmd(nft_full)
        if result.returncode != 0:
            stderr = result.stderr.strip()
            _log("error", f"Failed to add rule: {stderr}")
            raise RuleApplyError(f"Failed to add nftables rule: {stderr}", backend="nftables")

        _log("info", "Rule added successfully")
        return True

    def remove_rule(self, rule: dict[str, str]) -> bool:
        """Remove a firewall rule via backend-specific commands.

        Args:
            rule: Dictionary identifying the rule to remove.

        Returns:
            True on success.

        Raises:
            RuleRemoveError: If removal fails.
        """
        table = rule.get("table", "apotropaios")
        table_family = rule.get("table_family", "inet")
        chain = rule.get("chain", "")
        direction = rule.get("direction", "inbound")
        handle = rule.get("handle", "")
        comment = rule.get("comment", "")

        if not chain:
            chain = _direction_to_chain(direction)

        # Re-validate identifiers interpolated into nft command strings
        validate_table(table)
        validate_table_family(table_family)
        validate_chain(chain)

        # If handle provided, delete directly
        if handle:
            # Re-validate: handle is interpolated into the nft command string
            validate_numeric(handle)
            nft_del = f"delete rule {table_family} {table} {chain} handle {handle}"
            _log("info", f"Removing rule by handle: {handle}")
            result = _nft_cmd(nft_del)
            if result.returncode != 0:
                raise RuleRemoveError(f"Failed to remove rule handle {handle}", backend="nftables")
            return True

        # Otherwise find by comment
        if comment:
            safe_comment = sanitize_input(comment)
            result = _run(["nft", "-a", "list", "chain", table_family, table, chain])
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if f'comment "{safe_comment}"' in line and "handle" in line:
                        # Extract handle number
                        parts = line.strip().split()
                        for i, p in enumerate(parts):
                            if p == "handle" and i + 1 < len(parts):
                                rule_handle = parts[i + 1]
                                nft_del = f"delete rule {table_family} {table} {chain} handle {rule_handle}"
                                del_result = _nft_cmd(nft_del)
                                if del_result.returncode != 0:
                                    raise RuleRemoveError("Failed to remove rule by comment match", backend="nftables")
                                _log("info", f"Rule removed (handle {rule_handle})")
                                return True

        _log("warning", "Could not identify rule to remove")
        raise RuleNotFoundError("Could not identify nftables rule to remove", backend="nftables")

    def list_rules(self, **kwargs: str) -> str:
        """List current firewall rules from the backend.

        Returns:
            Formatted string of current rules.
        """
        family = kwargs.get("family", "")
        table = kwargs.get("table", "")
        if family and table:
            result = _run(["nft", "list", "table", family, table])
        elif family:
            result = _run(["nft", "list", "tables", family])
        else:
            result = _run(["nft", "list", "ruleset"])
        output = result.stdout.strip()
        stderr = result.stderr.strip()
        for err in ("Permission denied", "Operation not permitted"):
            if err in output or err in stderr:
                return f"{Color.RED}Root privileges required to list nftables rules{Color.RESET}"
        return output if output else "No nftables rules currently configured"

    def enable(self) -> bool:
        """Start and enable the firewall service.

        Returns:
            True on success.
        """
        ok = True
        if shutil.which("systemctl"):
            for verb in ("start", "enable"):
                result = _run(["systemctl", verb, "nftables"])
                if result.returncode != 0:
                    _log("warning", f"systemctl {verb} nftables failed: {result.stderr.strip()}")
                    ok = False
        if ok:
            _log("info", "nftables enabled")
        return ok

    def disable(self) -> bool:
        """Stop the firewall service.

        Returns:
            True on success.
        """
        ok = True
        if shutil.which("systemctl"):
            result = _run(["systemctl", "stop", "nftables"])
            if result.returncode != 0:
                _log("warning", f"systemctl stop nftables failed: {result.stderr.strip()}")
                ok = False
        if ok:
            _log("info", "nftables disabled")
        return ok

    def status(self) -> str:
        """Get backend service status and configuration summary.

        Returns:
            Formatted status string.
        """
        header = f"{Color.BOLD}Nftables Status:{Color.RESET}\n"
        result = _run(["nft", "list", "ruleset"])
        output = result.stdout.strip()
        stderr = result.stderr.strip()
        for err in ("Permission denied", "Operation not permitted"):
            if err in output or err in stderr:
                return header + f"  {Color.RED}Root privileges required{Color.RESET}\n"
        return header + (output if output else "  No nftables rules currently configured") + "\n"

    def block_all(self) -> bool:
        """Block all inbound and outbound traffic.

        Returns:
            True on success.
        """
        _log("warning", "Blocking ALL traffic")
        _ensure_table("inet", "apotropaios")
        _nft_cmd("flush table inet apotropaios")
        _nft_cmd("add chain inet apotropaios input { type filter hook input priority 0; policy drop; }")
        _nft_cmd("add chain inet apotropaios output { type filter hook output priority 0; policy drop; }")
        _nft_cmd("add chain inet apotropaios forward { type filter hook forward priority 0; policy drop; }")
        _nft_cmd("add rule inet apotropaios input iifname lo accept")
        _nft_cmd("add rule inet apotropaios output oifname lo accept")
        _log("info", "All traffic blocked (loopback preserved)")
        return True

    def allow_all(self) -> bool:
        """Allow all traffic (remove all restrictions).

        Returns:
            True on success.
        """
        _log("warning", "Allowing ALL traffic")
        result = _run(["nft", "list", "table", "inet", "apotropaios"])
        if result.returncode == 0:
            _nft_cmd("flush table inet apotropaios")
            _nft_cmd("delete table inet apotropaios")
        _log("info", "All traffic allowed (apotropaios table removed)")
        return True

    def reset(self) -> bool:
        """Reset backend to default configuration.

        Returns:
            True on success.
        """
        _log("warning", "Resetting nftables (flushing all rules)")
        result = _nft_cmd("flush ruleset")
        if result.returncode != 0:
            _log("error", f"Failed to flush ruleset: {result.stderr.strip()}")
            return False
        _log("info", "nftables reset complete")
        return True

    def save(self, path: str = "") -> bool:
        """Save current configuration to persistent storage.

        Args:
            path: Output file path (optional, uses default if empty).

        Returns:
            True on success.
        """
        if not path:
            path = "/etc/nftables.conf"
        result = _run(["nft", "list", "ruleset"])
        if result.returncode != 0:
            _log("error", f"Failed to export ruleset: {result.stderr.strip()}")
            return False
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(result.stdout)
            os.chmod(path, Security.FILE_PERMS)
            _log("info", f"Ruleset saved to {path}")
            return True
        except OSError as exc:
            _log("error", f"Failed to save: {exc}")
            return False

    def load(self, path: str) -> bool:
        """Load configuration from file.

        Args:
            path: Input file path.

        Returns:
            True on success.
        """
        if not os.path.isfile(path):
            _log("error", f"Config not found: {path}")
            return False
        result = _run(["nft", "-f", path])
        if result.returncode != 0:
            _log("error", f"Failed to reload: {result.stderr.strip()}")
            return False
        _log("info", f"Ruleset reloaded from {path}")
        return True


_instance = NftablesBackend()
from apotropaios.firewall.common import register_backend  # noqa: E402
register_backend(_instance)
