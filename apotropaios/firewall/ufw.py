# ==============================================================================
# File:         apotropaios/firewall/ufw.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     UFW (Uncomplicated Firewall) backend implementation
# Description:  Implements the FirewallBackend ABC for ufw. Handles both simple
#               and extended rule formats. Simple syntax (ufw allow PORT/PROTO)
#               is used only when a destination port is the sole parameter.
#               Extended syntax is forced when: no port, source IP, dest IP,
#               source port, or outbound direction (Lesson #8).
#
#               Compound actions: UFW doesn't support compound natively.
#               Terminal action is extracted for the ufw verb; logging is
#               enabled separately via "ufw logging on".
#
# Notes:        - Requires root privileges for all operations
#               - ufw is a frontend to iptables/nftables
#               - Supports allow/deny/reject/limit actions
#               - stderr captured on all ufw calls (Lesson #3)
#               - Parity target: bash v1.1.10 lib/firewall/ufw.sh
# Version:      1.6.2
# ==============================================================================

from __future__ import annotations

import os
import subprocess
from typing import Final

from apotropaios.core.constants import (
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
    validate_cidr,
    validate_interface,
    validate_ip,
    validate_numeric,
    validate_port,
    validate_port_range,
    validate_protocol,
)
from apotropaios.firewall.base import FirewallBackend

_CMD_TIMEOUT: Final[int] = Performance.SUBPROCESS_TIMEOUT
_log_fn: object | None = None


def _log(level: str, msg: str) -> None:
    if _log_fn is not None:
        method = getattr(_log_fn, level, None)
        if method is not None:
            method("ufw", msg)


def _run(args: list[str], stdin_data: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args, capture_output=True, text=True, timeout=_CMD_TIMEOUT,
        input=stdin_data if stdin_data else None,
    )


def _map_action(action: str) -> tuple[str, bool]:
    """Map a rule action to a ufw verb, handling compounds.

    Unsupported actions (masquerade, snat, dnat, return, or anything
    unrecognized) raise rather than silently mapping to a permissive
    verb: defaulting to "allow" would be a fail-open translation of a
    rule the operator intended to restrict traffic with.

    Returns:
        Tuple of (ufw_verb, has_log).

    Raises:
        RuleApplyError: If the action is not supported by ufw.
    """
    action_lower = action.lower().replace(" ", "")
    has_log = False

    mapping: dict[str, str] = {
        "accept": "allow", "allow": "allow",
        "drop": "deny", "deny": "deny",
        "reject": "reject", "limit": "limit",
    }

    if "," in action_lower:
        parts = action_lower.split(",")
        terminal = ""
        for p in parts:
            if p == "log":
                has_log = True
            elif p in mapping:
                terminal = mapping[p]
            else:
                raise RuleApplyError(
                    f"Action not supported by ufw: {p!r}", backend="ufw",
                )
        if not terminal:
            # log-only compound: ufw has no standalone log rule; logging is
            # enabled globally and the rule itself permits the traffic
            terminal = "allow"
        return (terminal, has_log)

    if action_lower == "log":
        return ("allow", True)

    ufw_verb = mapping.get(action_lower, "")
    if not ufw_verb:
        raise RuleApplyError(
            f"Action not supported by ufw: {action_lower!r}", backend="ufw",
        )
    return (ufw_verb, has_log)


class UfwBackend(FirewallBackend):
    """UFW firewall backend implementation."""

    @property
    def name(self) -> str:
        """Backend identifier string."""
        return "ufw"

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
        action = rule.get("action", "allow")
        interface = rule.get("interface", "")
        comment = rule.get("comment", "")

        ufw_verb, has_log = _map_action(action)

        # Enable logging if compound action includes log
        if has_log:
            _log("info", "Enabling logging (ufw logging on)")
            _run(["ufw", "logging", "on"])

        # Determine simple vs extended (Lesson #8: simple requires port)
        use_extended = (
            not dst_port or src_ip or dst_ip or
            src_port or direction == "outbound"
        )

        cmd_args: list[str] = ["ufw"]

        if use_extended:
            cmd_args.append(ufw_verb)

            # Direction
            if direction == "inbound":
                cmd_args.append("in")
            elif direction == "outbound":
                cmd_args.append("out")

            # Interface
            if interface:
                validate_interface(interface)
                cmd_args.extend(["on", interface])

            # Protocol
            if protocol and protocol != "all":
                protocol = validate_protocol(protocol)
                cmd_args.extend(["proto", protocol])

            # Source
            if src_ip:
                try:
                    validate_ip(src_ip)
                except Exception:
                    validate_cidr(src_ip)
                cmd_args.extend(["from", src_ip])
            else:
                cmd_args.extend(["from", "any"])

            # Source port
            if src_port:
                try:
                    validate_port(src_port)
                except Exception:
                    validate_port_range(src_port)
                ufw_port = src_port.replace("-", ":")
                cmd_args.extend(["port", ufw_port])

            # Destination
            if dst_ip:
                try:
                    validate_ip(dst_ip)
                except Exception:
                    validate_cidr(dst_ip)
                cmd_args.extend(["to", dst_ip])
            else:
                cmd_args.extend(["to", "any"])

            # Destination port
            if dst_port:
                try:
                    validate_port(dst_port)
                except Exception:
                    validate_port_range(dst_port)
                ufw_port = dst_port.replace("-", ":")
                cmd_args.extend(["port", ufw_port])

            # Comment
            if comment:
                safe_comment = sanitize_input(comment)
                cmd_args.extend(["comment", safe_comment])
        else:
            # Simple syntax: ufw allow PORT[/PROTO]
            cmd_args.append(ufw_verb)
            if dst_port:
                try:
                    validate_port(dst_port)
                except Exception:
                    validate_port_range(dst_port)
                port_spec = dst_port
                if protocol and protocol != "all":
                    protocol = validate_protocol(protocol)
                    port_spec = f"{port_spec}/{protocol}"
                cmd_args.append(port_spec)

            if comment:
                safe_comment = sanitize_input(comment)
                cmd_args.extend(["comment", safe_comment])

        _log("info", f"Adding rule: {' '.join(cmd_args)}")
        result = _run(cmd_args)
        if result.returncode != 0:
            stderr = result.stderr.strip()
            _log("error", f"Failed to add rule: {stderr or 'no output'}")
            raise RuleApplyError(f"Failed to add ufw rule: {stderr}", backend="ufw")

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
        rule_number = rule.get("rule_number", "")
        dst_port = rule.get("dst_port", "")
        protocol = rule.get("protocol", "")
        action = rule.get("action", "allow")

        # Prefer removal by number
        if rule_number:
            # Re-validate: rule number must be a positive integer
            validate_numeric(rule_number, min_value=1)
            _log("info", f"Removing rule #{rule_number}")
            result = _run(["ufw", "--force", "delete", rule_number])
            if result.returncode != 0:
                stderr = result.stderr.strip()
                raise RuleRemoveError(f"Failed to remove rule #{rule_number}: {stderr}", backend="ufw")
            return True

        # Remove by spec
        if dst_port:
            # Re-validate stored parameters before command construction
            try:
                validate_port(dst_port)
            except Exception:
                validate_port_range(dst_port)
            ufw_verb, _ = _map_action(action)
            port_spec = dst_port
            if protocol:
                protocol = validate_protocol(protocol)
                port_spec = f"{port_spec}/{protocol}"

            _log("info", f"Removing rule: ufw delete {ufw_verb} {port_spec}")
            result = _run(["ufw", "--force", "delete", ufw_verb, port_spec])
            if result.returncode != 0:
                stderr = result.stderr.strip()
                raise RuleRemoveError(f"Failed to remove rule: {stderr}", backend="ufw")
            return True

        raise RuleRemoveError("Cannot determine ufw rule to remove", backend="ufw")

    def list_rules(self, **kwargs: str) -> str:
        """List current firewall rules from the backend.

        Returns:
            Formatted string of current rules.
        """
        result = _run(["ufw", "status", "verbose"])
        output = result.stdout.strip()
        stderr = result.stderr.strip()
        for err in ("Permission denied", "you must be root"):
            if err in output or err in stderr:
                return f"{Color.RED}Root privileges required to list ufw rules{Color.RESET}"
        return output if output else "UFW is not active or has no rules configured"

    def enable(self) -> bool:
        """Start and enable the firewall service.

        Returns:
            True on success.
        """
        result = _run(["ufw", "--force", "enable"])
        if result.returncode != 0:
            _log("error", f"Failed to enable ufw: {result.stderr.strip()}")
            return False
        _log("info", "ufw enabled")
        return True

    def disable(self) -> bool:
        """Stop the firewall service.

        Returns:
            True on success.
        """
        result = _run(["ufw", "disable"])
        if result.returncode != 0:
            _log("error", f"Failed to disable ufw: {result.stderr.strip()}")
            return False
        _log("info", "ufw disabled")
        return True

    def status(self) -> str:
        """Get backend service status and configuration summary.

        Returns:
            Formatted status string.
        """
        header = f"{Color.BOLD}UFW Status:{Color.RESET}\n"
        result = _run(["ufw", "status", "verbose"])
        output = result.stdout.strip()
        return header + (output if output else "  UFW is not active") + "\n"

    def block_all(self) -> bool:
        """Block all inbound and outbound traffic.

        Returns:
            True on success.
        """
        _log("warning", "Blocking ALL traffic")
        ok = True
        for args in (
            ["ufw", "--force", "reset"],
            ["ufw", "default", "deny", "incoming"],
            ["ufw", "default", "deny", "outgoing"],
            ["ufw", "--force", "enable"],
        ):
            result = _run(args)
            if result.returncode != 0:
                _log("error", f"{' '.join(args)} failed: {result.stderr.strip()}")
                ok = False
        if not ok:
            _log("error", "block-all did NOT fully apply -- traffic may still pass")
            return False
        _log("info", "All traffic blocked")
        return True

    def allow_all(self) -> bool:
        """Allow all traffic (remove all restrictions).

        Returns:
            True on success.
        """
        _log("warning", "Allowing ALL traffic")
        ok = True
        for args in (
            ["ufw", "default", "allow", "incoming"],
            ["ufw", "default", "allow", "outgoing"],
        ):
            result = _run(args)
            if result.returncode != 0:
                _log("error", f"{' '.join(args)} failed: {result.stderr.strip()}")
                ok = False
        if ok:
            _log("info", "All traffic allowed")
        return ok

    def reset(self) -> bool:
        """Reset backend to default configuration.

        Returns:
            True on success.
        """
        _log("warning", "Resetting ufw to defaults")
        result = _run(["ufw", "--force", "reset"])
        if result.returncode != 0:
            _log("error", f"ufw reset failed: {result.stderr.strip()}")
            return False
        _log("info", "ufw reset complete")
        return True

    def save(self, path: str = "") -> bool:
        """Save current configuration to persistent storage.

        Args:
            path: Output file path (optional, uses default if empty).

        Returns:
            True on success.
        """
        result = _run(["ufw", "status", "verbose"])
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(result.stdout)
                os.chmod(path, Security.FILE_PERMS)
                _log("info", f"UFW status exported to {path}")
            except OSError as exc:
                _log("error", f"Failed to save: {exc}")
                return False
        return True

    def load(self, path: str) -> bool:
        """Load configuration from file.

        Args:
            path: Input file path.

        Returns:
            True on success.
        """
        _log("warning", "ufw load not directly supported; use ufw --force reset + re-add rules")
        return False


_instance = UfwBackend()
from apotropaios.firewall.common import register_backend  # noqa: E402
register_backend(_instance)
