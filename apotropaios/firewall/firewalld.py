# ==============================================================================
# File:         apotropaios/firewall/firewalld.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     firewalld firewall backend implementation
# Description:  Implements the FirewallBackend ABC for firewalld. Provides
#               zone-based rule management using firewall-cmd with rich rule
#               support, compound actions, protocol-only rules, and full zone
#               awareness (reset iterates ALL zones per Lesson #10, status
#               shows ALL zones per Lesson #11).
#
#               Rich rules are used when any of: no port, source IP, dest IP,
#               outbound direction, non-accept action, compound action,
#               connection state, log prefix, or rate limit is specified.
#               Simple --add-port path used only for basic port accept rules.
#
#               firewalld rich rules require at least one filtering element
#               between family declaration and action. Protocol-only rules
#               get "protocol value='tcp'" explicitly (Lesson #6).
#
# Notes:        - Requires root privileges for all operations
#               - Default zone: public (overridable via --zone)
#               - Permanent rules with --reload after modification
#               - stderr captured on all firewall-cmd calls (Lesson #3)
#               - Parity target: bash v1.1.10 lib/firewall/firewalld.sh
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
    RuleRemoveError,
)
from apotropaios.core.validation import (
    validate_cidr,
    validate_ip,
    validate_log_prefix,
    validate_port,
    validate_port_range,
    validate_protocol,
    validate_rate_limit,
    validate_syslog_level,
    validate_zone,
)
from apotropaios.firewall.base import FirewallBackend

_CMD_TIMEOUT: Final[int] = Performance.SUBPROCESS_TIMEOUT
_log_fn: object | None = None


def _log(level: str, msg: str) -> None:
    if _log_fn is not None:
        method = getattr(_log_fn, level, None)
        if method is not None:
            method("firewalld", msg)


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=_CMD_TIMEOUT)


def _build_rich_rule(rule: dict[str, str]) -> str:
    """Construct a firewalld rich rule string from parameters.

    Supports compound actions (log+terminal), log prefix/level, rate
    limiting, and protocol-only rules. Firewalld rich rules natively
    support log combined with a terminal action in one rule.

    Args:
        rule: Rule parameters dictionary.

    Returns:
        Rich rule string (e.g., 'rule family="ipv4" port port="443" protocol="tcp" accept').
    """
    protocol = rule.get("protocol", "tcp")
    src_ip = rule.get("src_ip", "")
    dst_ip = rule.get("dst_ip", "")
    dst_port = rule.get("dst_port", "")
    action = rule.get("action", "accept")
    log_prefix = rule.get("log_prefix", "")
    log_level = rule.get("log_level", "")
    limit = rule.get("limit", "")

    # Rich rule family follows the address operands: IPv6 addresses in an
    # ipv4-family rule are rejected by firewalld. Mixed families in one
    # rule cannot be expressed and are refused.
    src_is_v6 = ":" in src_ip if src_ip else False
    dst_is_v6 = ":" in dst_ip if dst_ip else False
    if src_ip and dst_ip and src_is_v6 != dst_is_v6:
        raise RuleApplyError(
            "Cannot mix IPv4 and IPv6 addresses in one firewalld rich rule",
            backend="firewalld",
        )
    family = "ipv6" if (src_is_v6 or dst_is_v6) else "ipv4"
    parts: list[str] = [f'rule family="{family}"']

    # Source address
    if src_ip:
        try:
            validate_ip(src_ip)
        except Exception:
            validate_cidr(src_ip)
        parts.append(f'source address="{src_ip}"')

    # Destination address
    if dst_ip:
        try:
            validate_ip(dst_ip)
        except Exception:
            validate_cidr(dst_ip)
        parts.append(f'destination address="{dst_ip}"')

    # Port / Protocol filtering element
    if dst_port:
        try:
            validate_port(dst_port)
        except Exception:
            validate_port_range(dst_port)
        port_fmt = dst_port.replace(":", "-")
        parts.append(f'port port="{port_fmt}" protocol="{protocol or "tcp"}"')
    elif protocol and protocol != "all":
        # Protocol-only rule — Lesson #6: a rich rule must carry at least
        # one filtering element. "protocol value=..." is the correct
        # element for every protocol including ICMP; icmp-block-inversion
        # is a zone option, not a rich-rule element, and firewalld rejects
        # it inside a rule.
        parts.append(f'protocol value="{protocol}"')

    # Parse compound action
    action_lower = action.lower().replace(" ", "")
    action_parts = action_lower.split(",")
    has_log = "log" in action_parts
    terminal = ""
    for ap in action_parts:
        if ap in ("accept", "drop", "reject"):
            terminal = ap

    # Log clause (before terminal in rich rules).
    # All three values are interpolated into the rich rule string, so each
    # is re-validated here — defense-in-depth against quote breakout.
    if has_log:
        log_part = "log"
        if log_prefix:
            validate_log_prefix(log_prefix)
            log_part += f' prefix="{log_prefix}"'
        if log_level:
            log_level = validate_syslog_level(log_level)
            log_part += f' level="{log_level}"'
        if limit:
            validate_rate_limit(limit)
            log_part += f' limit value="{limit}"'
        parts.append(log_part)

    # Terminal action
    if terminal:
        parts.append(terminal)
    elif not has_log:
        parts.append("accept")

    return " ".join(parts)


class FirewalldBackend(FirewallBackend):
    """firewalld firewall backend implementation with zone awareness."""

    @property
    def name(self) -> str:
        """Backend identifier string."""
        return "firewalld"

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
        protocol = rule.get("protocol", "tcp")
        dst_port = rule.get("dst_port", "")
        action = rule.get("action", "accept")
        zone = rule.get("zone", "public")
        permanent = rule.get("permanent", "1")
        src_ip = rule.get("src_ip", "")
        dst_ip = rule.get("dst_ip", "")

        validate_zone(zone)
        if protocol:
            protocol = validate_protocol(protocol)

        # Determine if rich rule needed (Lesson #7: simple path requires port)
        use_rich = (
            not dst_port or src_ip or dst_ip or
            direction == "outbound" or
            action != "accept" or "," in action or
            rule.get("conn_state", "") or
            rule.get("log_prefix", "") or
            rule.get("limit", "")
        )

        cmd_args: list[str] = ["firewall-cmd", f"--zone={zone}"]
        if permanent == "1":
            cmd_args.append("--permanent")

        if use_rich:
            rich_rule = _build_rich_rule(rule)
            cmd_args.append(f"--add-rich-rule={rich_rule}")
            _log("info", f"Adding rich rule to zone {zone}: {rich_rule}")
        else:
            # Simple port addition
            if dst_port:
                try:
                    validate_port(dst_port)
                except Exception:
                    validate_port_range(dst_port)
                port_fmt = dst_port.replace(":", "-")
                cmd_args.append(f"--add-port={port_fmt}/{protocol}")
                _log("info", f"Adding port {dst_port}/{protocol} to zone {zone}")

        result = _run(cmd_args)
        if result.returncode != 0:
            stderr = result.stderr.strip()
            _log("error", f"Failed to add rule: {stderr or 'no output'}")
            raise RuleApplyError(f"Failed to add firewalld rule: {stderr}", backend="firewalld")

        # Reload if permanent
        if permanent == "1":
            _run(["firewall-cmd", "--reload"])

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
        zone = rule.get("zone", "public")
        permanent = rule.get("permanent", "1")
        dst_port = rule.get("dst_port", "")
        protocol = rule.get("protocol", "tcp")
        rich_rule = rule.get("rich_rule", "")

        cmd_args: list[str] = ["firewall-cmd", f"--zone={zone}"]
        if permanent == "1":
            cmd_args.append("--permanent")

        if rich_rule:
            cmd_args.append(f"--remove-rich-rule={rich_rule}")
        elif dst_port:
            # Re-validate stored parameters before command construction
            try:
                validate_port(dst_port)
            except Exception:
                validate_port_range(dst_port)
            try:
                protocol = validate_protocol(protocol)
            except Exception:
                protocol = "tcp"
            port_fmt = dst_port.replace(":", "-")
            cmd_args.append(f"--remove-port={port_fmt}/{protocol}")
        else:
            raise RuleRemoveError(
                "Cannot determine rule to remove (no port or rich rule)", backend="firewalld",
            )

        _log("info", f"Removing rule from zone {zone}")
        result = _run(cmd_args)
        if result.returncode != 0:
            stderr = result.stderr.strip()
            _log("error", f"Failed to remove rule: {stderr or 'no output'}")
            raise RuleRemoveError(f"Failed to remove firewalld rule: {stderr}", backend="firewalld")

        if permanent == "1":
            _run(["firewall-cmd", "--reload"])

        _log("info", "Rule removed successfully")
        return True

    def list_rules(self, **kwargs: str) -> str:
        """List current firewall rules from the backend.

        Returns:
            Formatted string of current rules.
        """
        zone = kwargs.get("zone", "")
        if zone:
            result = _run(["firewall-cmd", f"--zone={zone}", "--list-all"])
            return f"{Color.BOLD}Zone: {zone}{Color.RESET}\n{result.stdout}"
        result = _run(["firewall-cmd", "--list-all-zones"])
        return result.stdout if result.stdout else "No firewalld configuration available"

    def enable(self) -> bool:
        """Start and enable the firewall service.

        Returns:
            True on success.
        """
        ok = True
        if shutil.which("systemctl"):
            for verb in ("start", "enable"):
                result = _run(["systemctl", verb, "firewalld"])
                if result.returncode != 0:
                    _log("warning", f"systemctl {verb} firewalld failed: {result.stderr.strip()}")
                    ok = False
        if ok:
            _log("info", "firewalld enabled")
        return ok

    def disable(self) -> bool:
        """Stop the firewall service.

        Returns:
            True on success.
        """
        ok = True
        if shutil.which("systemctl"):
            result = _run(["systemctl", "stop", "firewalld"])
            if result.returncode != 0:
                _log("warning", f"systemctl stop firewalld failed: {result.stderr.strip()}")
                ok = False
        if ok:
            _log("info", "firewalld disabled")
        return ok

    def status(self) -> str:
        """Get backend service status and configuration summary.

        Returns:
            Formatted status string.
        """
        header = f"{Color.BOLD}Firewalld Status:{Color.RESET}\n"
        state = _run(["firewall-cmd", "--state"])
        state_txt = state.stdout.strip() or "firewalld is not running"
        zones = _run(["firewall-cmd", "--get-active-zones"])
        all_config = _run(["firewall-cmd", "--list-all-zones"])
        parts = [header, f"  State: {state_txt}\n"]
        if zones.stdout.strip():
            parts.append(f"\n{Color.BOLD}Active Zones:{Color.RESET}\n{zones.stdout}\n")
        if all_config.stdout.strip():
            parts.append(all_config.stdout)
        return "".join(parts)

    def block_all(self) -> bool:
        """Block all inbound and outbound traffic.

        Returns:
            True on success.
        """
        _log("warning", "Blocking ALL traffic via panic mode")
        result = _run(["firewall-cmd", "--panic-on"])
        if result.returncode != 0:
            _log("warning", "Panic mode unavailable — falling back to drop zone")
            result = _run(["firewall-cmd", "--set-default-zone=drop"])
            if result.returncode != 0:
                _log("error", f"block-all failed: {result.stderr.strip()}")
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
        result = _run(["firewall-cmd", "--panic-off"])
        if result.returncode != 0:
            # Panic may simply not be on; log and continue to zone reset
            _log("debug", f"panic-off returned non-zero: {result.stderr.strip()}")
        result = _run(["firewall-cmd", "--set-default-zone=public"])
        if result.returncode != 0:
            _log("error", f"Failed to set default zone: {result.stderr.strip()}")
            ok = False
        if ok:
            _log("info", "All traffic allowed")
        return ok

    def reset(self) -> bool:
        """Reset firewalld — iterates ALL zones (Lesson #10)."""
        _log("warning", "Resetting firewalld to defaults")
        zones_result = _run(["firewall-cmd", "--get-zones"])
        all_zones = zones_result.stdout.strip().split() if zones_result.stdout.strip() else ["public"]

        for zone in all_zones:
            # Remove ports
            ports_result = _run(["firewall-cmd", f"--zone={zone}", "--list-ports"])
            for port in (ports_result.stdout.strip().split() if ports_result.stdout.strip() else []):
                _run(["firewall-cmd", f"--zone={zone}", "--permanent", f"--remove-port={port}"])

            # Remove rich rules
            rules_result = _run(["firewall-cmd", f"--zone={zone}", "--list-rich-rules"])
            for rule_line in (rules_result.stdout.strip().splitlines() if rules_result.stdout.strip() else []):
                if rule_line.strip():
                    _run(["firewall-cmd", f"--zone={zone}", "--permanent", f"--remove-rich-rule={rule_line.strip()}"])

        _run(["firewall-cmd", "--reload"])
        _log("info", f"firewalld reset complete (cleaned {len(all_zones)} zones)")
        return True

    def save(self, path: str = "") -> bool:
        """Save current configuration to persistent storage.

        Args:
            path: Output file path (optional, uses default if empty).

        Returns:
            True on success.
        """
        if path:
            result = _run(["firewall-cmd", "--list-all-zones"])
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(result.stdout)
                os.chmod(path, Security.FILE_PERMS)
                _log("info", f"Configuration exported to {path}")
            except OSError as exc:
                _log("error", f"Failed to save: {exc}")
                return False
        result = _run(["firewall-cmd", "--runtime-to-permanent"])
        if result.returncode != 0:
            _log("error", f"runtime-to-permanent failed: {result.stderr.strip()}")
            return False
        _log("info", "Runtime configuration saved to permanent")
        return True

    def load(self, path: str) -> bool:
        """Reload firewalld configuration from permanent zone files.

        If path points to a directory of zone XML files, copies them to
        /etc/firewalld/zones/ and reloads. Otherwise performs a standard
        reload from existing permanent configuration.

        Args:
            path: Path to zone directory or config file.

        Returns:
            True on success.
        """
        if os.path.isdir(path):
            # Restore zone XML files from the provided directory
            dst = "/etc/firewalld/zones"
            if os.path.isdir(dst):
                for item in os.listdir(path):
                    if item.endswith(".xml"):
                        src_file = os.path.join(path, item)
                        dst_file = os.path.join(dst, item)
                        try:
                            shutil.copy2(src_file, dst_file)
                            os.chmod(dst_file, Security.FILE_PERMS)
                        except OSError as exc:
                            _log("warning", f"Failed to copy zone file {item}: {exc}")
                _log("info", f"Zone files restored from {path}")

        result = _run(["firewall-cmd", "--reload"])
        if result.returncode != 0:
            _log("error", "Failed to reload firewalld")
            return False
        _log("info", "firewalld reloaded")
        return True


_instance = FirewalldBackend()
from apotropaios.firewall.common import register_backend  # noqa: E402
register_backend(_instance)
