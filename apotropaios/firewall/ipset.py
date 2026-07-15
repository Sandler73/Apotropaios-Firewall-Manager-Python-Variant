# ==============================================================================
# File:         apotropaios/firewall/ipset.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     ipset firewall backend implementation
# Description:  Implements the FirewallBackend ABC for ipset. Manages IP sets
#               for efficient bulk IP/network matching. ipset works alongside
#               iptables/nftables — it manages named sets of IPs/networks/ports
#               that can be referenced in firewall rules for O(1) matching.
#
#               Supported set types: hash:ip, hash:net, hash:ip,port,
#               hash:net,port, hash:net,iface, list:set
#
#               The add_rule operation creates/populates a set and optionally
#               creates an iptables match rule referencing it. The remove_rule
#               operation removes entries or destroys sets, cleaning up any
#               iptables references first.
#
# Notes:        - Requires root privileges for all operations
#               - Sets persist across reboots via ipset save/restore
#               - Timeout support for temporary entries
#               - Removes iptables references before destroying sets during reset
#               - Parity target: bash v1.1.10 lib/firewall/ipset.sh
# Version:      1.2.1
# ==============================================================================

from __future__ import annotations

import os
import subprocess
from typing import Final

from apotropaios.core.constants import (
    Color,
    IPSET_TYPES,
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
    validate_ipset_name,
    validate_port,
    validate_protocol,
)
from apotropaios.firewall.base import FirewallBackend

_CMD_TIMEOUT: Final[int] = Performance.SUBPROCESS_TIMEOUT
_log_fn: object | None = None


def _log(level: str, msg: str) -> None:
    if _log_fn is not None:
        method = getattr(_log_fn, level, None)
        if method is not None:
            method("ipset", msg)


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args, capture_output=True, text=True, timeout=_CMD_TIMEOUT,
    )


def _validate_entry(entry: str, set_type: str) -> bool:
    """Validate an ipset entry against the set type.

    Args:
        entry: Entry value (IP, network, port combo, etc.).
        set_type: ipset type (hash:ip, hash:net, etc.).

    Returns:
        True if valid for the given type.

    Raises:
        RuleApplyError: If validation fails.
    """
    def _validate_addr(value: str, allow_net: bool) -> None:
        try:
            validate_ip(value)
        except Exception:
            if allow_net:
                validate_cidr(value)
            else:
                raise

    if set_type == "hash:ip":
        _validate_addr(entry, allow_net=False)
    elif set_type == "hash:net":
        _validate_addr(entry, allow_net=True)  # hash:net also accepts plain IPs
    elif set_type in ("hash:ip,port", "hash:net,port"):
        # Format: addr,[proto:]port — validate both components
        if "," not in entry:
            raise RuleApplyError(
                f"Invalid entry format for {set_type}: {entry}",
                backend="ipset",
            )
        addr_part, _, port_part = entry.partition(",")
        _validate_addr(addr_part, allow_net=set_type == "hash:net,port")
        if ":" in port_part:
            proto_part, _, port_part = port_part.partition(":")
            validate_protocol(proto_part)
        validate_port(port_part)
    elif set_type == "hash:net,iface":
        # Format: net,iface — validate both components
        if "," not in entry:
            raise RuleApplyError(
                f"Invalid entry format for {set_type}: {entry}",
                backend="ipset",
            )
        net_part, _, iface_part = entry.partition(",")
        _validate_addr(net_part, allow_net=True)
        validate_interface(iface_part)
    elif set_type == "list:set":
        # Entries in a list:set are names of other sets
        validate_ipset_name(entry)
    return True


class IpsetBackend(FirewallBackend):
    """ipset firewall backend implementation."""

    @property
    def name(self) -> str:
        """Backend identifier string."""
        return "ipset"

    def add_rule(self, rule: dict[str, str]) -> bool:
        """Add entry to an ipset, creating the set if needed.

        Optionally creates an iptables rule referencing the set.

        Args:
            rule: Parameters including: set_name, set_type, entry,
                  timeout, create_fw_rule, direction, action, comment.

        Returns:
            True on success.
        """
        set_name = rule.get("set_name", "")
        set_type = rule.get("set_type", "hash:net")
        entry = rule.get("entry", "")
        timeout = rule.get("timeout", "0")
        direction = rule.get("direction", "inbound")
        action = rule.get("action", "drop")
        chain = rule.get("chain", "")
        comment = rule.get("comment", "")
        create_fw_rule = rule.get("create_fw_rule", "0")

        if not set_name:
            raise RuleApplyError("Set name is required", backend="ipset")
        validate_ipset_name(set_name)

        if set_type not in IPSET_TYPES:
            raise RuleApplyError(f"Unsupported set type: {set_type}", backend="ipset")

        # Create set if it doesn't exist
        check = _run(["ipset", "list", set_name])
        if check.returncode != 0:
            create_args: list[str] = ["ipset", "create", set_name, set_type]

            # Timeout support
            timeout_val = int(timeout) if timeout.isdigit() else 0
            if timeout_val > 0:
                create_args.extend(["timeout", str(timeout_val)])

            # Comment support
            create_args.append("comment")

            _log("info", f"Creating set: {set_name} (type: {set_type})")
            result = _run(create_args)
            if result.returncode != 0:
                stderr = result.stderr.strip()
                _log("error", f"Failed to create set: {stderr}")
                raise RuleApplyError(f"Failed to create ipset: {stderr}", backend="ipset")

        # Add entry to set
        if entry:
            _validate_entry(entry, set_type)
            add_args: list[str] = ["ipset", "add", set_name, entry]

            if timeout and timeout.isdigit() and int(timeout) > 0:
                add_args.extend(["timeout", timeout])

            if comment:
                safe_comment = sanitize_input(comment)
                add_args.extend(["comment", safe_comment])

            _log("info", f"Adding entry to {set_name}: {entry}")
            result = _run(add_args)
            if result.returncode != 0:
                stderr = result.stderr.strip()
                # "already added" is not an error
                if "already added" not in stderr:
                    _log("error", f"Failed to add entry: {stderr}")
                    raise RuleApplyError(f"Failed to add ipset entry: {stderr}", backend="ipset")

        # Optionally create iptables match rule
        if create_fw_rule == "1":
            if not chain:
                chain = "INPUT" if direction == "inbound" else "OUTPUT"

            match_flag = "src" if direction == "inbound" else "dst"
            target = action.upper().split(",")[-1]  # Terminal action
            if target == "LOG":
                target = "DROP"  # Default terminal for ipset

            ipt_args: list[str] = [
                "iptables", "-A", chain,
                "-m", "set", "--match-set", set_name, match_flag,
                "-j", target,
            ]

            if comment:
                safe_comment = sanitize_input(comment)
                ipt_args.extend(["-m", "comment", "--comment", safe_comment])

            _log("info", f"Creating iptables rule for set: {' '.join(ipt_args)}")
            result = _run(ipt_args)
            if result.returncode != 0:
                _log("warning", f"Failed to create iptables match rule: {result.stderr.strip()}")

        _log("info", "ipset operation completed successfully")
        return True

    def remove_rule(self, rule: dict[str, str]) -> bool:
        """Remove entry from ipset or destroy the set.

        If entry is provided, removes that entry. If only set_name is
        provided, destroys the entire set (after cleaning iptables refs).

        Args:
            rule: Parameters including: set_name, entry, destroy_set.

        Returns:
            True on success.
        """
        set_name = rule.get("set_name", "")
        entry = rule.get("entry", "")
        destroy_set = rule.get("destroy_set", "0")

        if not set_name:
            raise RuleRemoveError("Set name is required", backend="ipset")
        validate_ipset_name(set_name)

        if entry:
            # Remove specific entry
            _log("info", f"Removing entry from {set_name}: {entry}")
            result = _run(["ipset", "del", set_name, entry])
            if result.returncode != 0:
                stderr = result.stderr.strip()
                raise RuleRemoveError(f"Failed to remove entry: {stderr}", backend="ipset")
            return True

        if destroy_set == "1":
            # Remove iptables references first
            _remove_iptables_refs(set_name)

            # Flush then destroy
            _run(["ipset", "flush", set_name])
            _log("info", f"Destroying set: {set_name}")
            result = _run(["ipset", "destroy", set_name])
            if result.returncode != 0:
                stderr = result.stderr.strip()
                raise RuleRemoveError(f"Failed to destroy set: {stderr}", backend="ipset")
            return True

        raise RuleRemoveError(
            "Specify entry to remove or destroy_set=1 to destroy the set",
            backend="ipset",
        )

    def list_rules(self, **kwargs: str) -> str:
        """List current firewall rules from the backend.

        Returns:
            Formatted string of current rules.
        """
        set_name = kwargs.get("set_name", "")
        if set_name:
            result = _run(["ipset", "list", set_name])
        else:
            result = _run(["ipset", "list"])
        output = result.stdout.strip()
        stderr = result.stderr.strip()
        for err in ("Permission denied", "you must be root"):
            if err in output or err in stderr:
                return f"{Color.RED}Root privileges required to list ipsets{Color.RESET}"
        return output if output else "No ipsets configured"

    def enable(self) -> bool:
        """Start and enable the firewall service.

        Returns:
            True on success.
        """
        _log("info", "ipset is always available when installed (kernel module)")
        return True

    def disable(self) -> bool:
        """Stop the firewall service.

        Returns:
            True on success.
        """
        _log("info", "ipset cannot be disabled (kernel module)")
        return True

    def status(self) -> str:
        """Get backend service status and configuration summary.

        Returns:
            Formatted status string.
        """
        header = f"{Color.BOLD}ipset Status:{Color.RESET}\n"
        result = _run(["ipset", "list"])
        output = result.stdout.strip()
        if not output:
            return header + "  No ipsets configured\n"
        # Count sets
        set_count = output.count("Name:")
        return header + f"  Sets configured: {set_count}\n\n{output}\n"

    def block_all(self) -> bool:
        """Block all inbound and outbound traffic.

        Returns:
            True on success.
        """
        _log("warning", "ipset block-all: creating blocklist set with iptables DROP rule")

        # Create the catch-all set. "already exists" is acceptable on re-run.
        result = _run(["ipset", "create", "apotropaios_block", "hash:net", "comment"])
        if result.returncode != 0 and "already exists" not in result.stderr:
            _log("error", f"Failed to create block set: {result.stderr.strip()}")
            return False

        # hash:net rejects a /0 prefix, so full coverage requires the two
        # complementary /1 networks. Every add is checked — a silent failure
        # here would leave the emergency control claiming success while
        # blocking nothing (fail-open).
        failed = False
        for net in ("0.0.0.0/1", "128.0.0.0/1"):
            result = _run([
                "ipset", "add", "apotropaios_block", net,
                "comment", "block-all",
            ])
            if result.returncode != 0 and "already added" not in result.stderr:
                _log("error", f"Failed to add {net} to block set: {result.stderr.strip()}")
                failed = True

        for chain, flag in (("INPUT", "src"), ("OUTPUT", "dst")):
            result = _run([
                "iptables", "-I", chain,
                "-m", "set", "--match-set", "apotropaios_block", flag,
                "-j", "DROP",
            ])
            if result.returncode != 0:
                _log("error", f"Failed to add {chain} DROP rule: {result.stderr.strip()}")
                failed = True

        if failed:
            _log("error", "block-all did NOT fully apply — traffic may still pass")
            return False

        _log("info", "All traffic blocked via ipset + iptables")
        return True

    def allow_all(self) -> bool:
        """Allow all traffic (remove all restrictions).

        Returns:
            True on success.
        """
        _log("warning", "ipset allow-all: removing block sets")
        _remove_iptables_refs("apotropaios_block")

        # Missing set means nothing to remove — treat as success. Any other
        # failure is reported so the caller does not assume open traffic.
        check = _run(["ipset", "list", "-n"])
        if "apotropaios_block" in check.stdout.split():
            _run(["ipset", "flush", "apotropaios_block"])
            result = _run(["ipset", "destroy", "apotropaios_block"])
            if result.returncode != 0:
                _log("error", f"Failed to destroy block set: {result.stderr.strip()}")
                return False

        _log("info", "Block sets removed")
        return True

    def reset(self) -> bool:
        """Reset ipset — flush all sets and remove iptables references."""
        _log("warning", "Resetting ipset (flushing all sets)")

        # List all sets
        result = _run(["ipset", "list", "-n"])
        set_names = result.stdout.strip().splitlines() if result.stdout.strip() else []

        # Remove iptables references for each set, then flush/destroy
        for sn in set_names:
            sn = sn.strip()
            if sn:
                _remove_iptables_refs(sn)
                _run(["ipset", "flush", sn])
                _run(["ipset", "destroy", sn])

        _log("info", f"ipset reset complete ({len(set_names)} sets removed)")
        return True

    def save(self, path: str = "") -> bool:
        """Save current configuration to persistent storage.

        Args:
            path: Output file path (optional, uses default if empty).

        Returns:
            True on success.
        """
        if not path:
            path = "/etc/ipset.conf"
        result = _run(["ipset", "save"])
        if result.returncode != 0:
            _log("error", f"Failed to save ipsets: {result.stderr.strip()}")
            return False
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(result.stdout)
            os.chmod(path, Security.FILE_PERMS)
            _log("info", f"ipsets saved to {path}")
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
            _log("error", f"ipset config not found: {path}")
            return False
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            result = subprocess.run(
                ["ipset", "restore"],
                input=content, capture_output=True, text=True,
                timeout=_CMD_TIMEOUT,
            )
            if result.returncode != 0:
                _log("error", f"Failed to restore: {result.stderr.strip()}")
                return False
            _log("info", f"ipsets restored from {path}")
            return True
        except OSError as exc:
            _log("error", f"Failed to load: {exc}")
            return False


def _remove_iptables_refs(set_name: str) -> None:
    """Remove iptables rules that reference an ipset.

    Scans iptables -L output for match-set references and removes them.
    Must be called before destroying a set to prevent kernel errors.

    Args:
        set_name: ipset name to clean references for.
    """
    for chain in ("INPUT", "OUTPUT", "FORWARD"):
        while True:
            result = _run(["iptables", "-L", chain, "-n", "--line-numbers"])
            found = False
            for line in reversed(result.stdout.splitlines()):
                if set_name in line and "match-set" in line:
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        rule_num = parts[0]
                        _run(["iptables", "-D", chain, rule_num])
                        found = True
                        break
            if not found:
                break


_instance = IpsetBackend()
from apotropaios.firewall.common import register_backend  # noqa: E402
register_backend(_instance)
