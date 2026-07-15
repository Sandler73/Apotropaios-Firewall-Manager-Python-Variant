# ==============================================================================
# File:         apotropaios/menu/help_system.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Progressive layered help system
# Description:  Per-command help system with synopsis, options, and examples.
#               Implements a 3-tier help architecture:
#                 Tier 1: Global help (--help) — handled by cli.py
#                 Tier 2: Command help (COMMAND --help) — this module
#                 Tier 3: Interactive menu help — in-app guidance (Sprint 3.3)
#
#               Each per-command help page includes: synopsis, description,
#               options/arguments, examples, related commands, and notes.
#               Help display does NOT require framework initialization.
#
# Notes:        - Requires only apotropaios.core.constants (no engine deps)
#               - All help functions follow _help_cmd_COMMAND() naming convention
#               - dispatch uses dynamic lookup via function name convention
#               - No external dependencies
#               - Parity target: bash v1.1.10 lib/menu/help_system.sh
# Version:      1.2.1
# ==============================================================================

from __future__ import annotations

import sys

from typing import Callable

from apotropaios.core.constants import (
    FULL_NAME,
    VERSION,
    Color,
    ErrorCode,
)


# ==============================================================================
# Internal Formatting Helpers
# ==============================================================================

def _header(command: str, synopsis: str) -> None:
    """Print standardized help header for a command."""
    sys.stderr.write(
        f"\n{Color.BOLD}{command} — {synopsis}{Color.RESET}\n"
    )
    sys.stderr.write(
        f"{Color.DIM}{FULL_NAME} v{VERSION}{Color.RESET}\n"
    )
    sys.stderr.write(f"{Color.DIM}{'─' * 70}{Color.RESET}\n")


def _section(title: str) -> None:
    """Print a section heading."""
    sys.stderr.write(f"\n{Color.BOLD}{title}{Color.RESET}\n")


def _opt(flag: str, desc: str) -> None:
    """Print a formatted option line."""
    sys.stderr.write(f"  {flag:<22s} {desc}\n")


def _tip(text: str) -> None:
    """Print a tip callout."""
    sys.stderr.write(f"  {Color.CYAN}Tip:{Color.RESET} {text}\n")


def _related(*commands: str) -> None:
    """Print related commands section."""
    sys.stderr.write(f"\n{Color.BOLD}Related Commands:{Color.RESET}\n")
    for cmd in commands:
        sys.stderr.write(f"  {cmd}\n")


# ==============================================================================
# Help Dispatch
# ==============================================================================

# Map of command names → help functions (populated at module level)
_HELP_FUNCTIONS: dict[str, Callable[[], None]] = {}


def help_dispatch(command: str) -> int:
    """Route to the correct per-command help function.

    Uses the _HELP_FUNCTIONS registry populated by @_register decorator.
    Falls back to a generic message if no help is available.

    Args:
        command: Command name (e.g., 'add-rule', 'backup').

    Returns:
        0 if help displayed, 1 if no help for that command.
    """
    func = _HELP_FUNCTIONS.get(command)
    if func is not None:
        func()
        return ErrorCode.SUCCESS

    sys.stderr.write(f"No detailed help available for: {command}\n")
    sys.stderr.write("Run: apotropaios --help  for general usage\n")
    return ErrorCode.USAGE


def _register(command: str) -> Callable[[Callable[[], None]], Callable[[], None]]:
    """Decorator to register a help function for a command."""
    def decorator(func: Callable[[], None]) -> Callable[[], None]:
        _HELP_FUNCTIONS[command] = func
        return func
    return decorator


# ==============================================================================
# Per-Command Help Functions (Tier 2)
#
# Each function provides detailed help for one CLI command. These are
# registered via @_register and looked up by help_dispatch().
# Full help for all 17 commands is built iteratively as commands are
# implemented. Priority commands are included first.
# ==============================================================================

ME: str = "apotropaios"


@_register("menu")
def _help_cmd_menu() -> None:
    """Help for the menu / --interactive command."""
    _header("menu / --interactive", "Launch the interactive menu interface")

    _section("Synopsis")
    sys.stderr.write(f"  {ME} --interactive             "
                     f"{Color.DIM}(preferred — explicit interactive mode){Color.RESET}\n")
    sys.stderr.write(f"  {ME} [OPTIONS] menu            "
                     f"{Color.DIM}(backward compatible subcommand){Color.RESET}\n")
    sys.stderr.write(f"  {ME} [OPTIONS]                 "
                     f"{Color.DIM}(backward compatible — no args = menu){Color.RESET}\n")

    _section("Description")
    sys.stderr.write(
        "  Launches the interactive menu-driven interface. The --interactive\n"
        "  flag provides explicit separation between interactive menu mode\n"
        "  and direct CLI command execution.\n\n"
        "  The menu provides guided access to all framework features\n"
        "  organized into seven functional categories with input validation,\n"
        "  cancel support, and per-backend configuration submenus.\n"
    )

    _section("Menu Structure")
    sys.stderr.write(
        "  1. Firewall Management   — Select backend, start/stop, status\n"
        "  2. Rule Management       — Create, list, remove, activate/deactivate\n"
        "  3. Quick Actions         — One-click block-all or allow-all\n"
        "  4. Backup & Recovery     — Create backups, restore, immutable snapshots\n"
        "  5. System Information    — OS details, firewall status, framework info\n"
        "  6. Install & Update      — Install or update firewall packages\n"
        "  7. Help & Documentation  — In-app help reference\n"
        "  8. Exit                  — Clean shutdown\n"
    )
    sys.stderr.write("\n")


@_register("detect")
def _help_cmd_detect() -> None:
    """Help for the detect command."""
    _header("detect", "Detect operating system and installed firewalls")

    _section("Synopsis")
    sys.stderr.write(f"  sudo {ME} detect\n")

    _section("Description")
    sys.stderr.write(
        "  Scans the system to identify the operating system (from\n"
        "  /etc/os-release) and all 5 supported firewall backends.\n"
        "  Reports installed vs running vs not-found for each backend.\n"
    )

    _related(
        f"{ME} status          — Show active backend status",
        f"{ME} --interactive   — Launch interactive menu",
    )
    sys.stderr.write("\n")


@_register("status")
def _help_cmd_status() -> None:
    """Help for the status command."""
    _header("status", "Show active firewall backend status")

    _section("Synopsis")
    sys.stderr.write(f"  sudo {ME} [--backend NAME] status\n")

    _section("Description")
    sys.stderr.write(
        "  Displays the current status of the active firewall backend\n"
        "  including enabled state, active rules, and configuration.\n"
    )

    _related(
        f"{ME} detect          — Scan for all available backends",
    )
    sys.stderr.write("\n")


@_register("add-rule")
def _help_cmd_add_rule() -> None:
    """Help for the add-rule command."""
    _header("add-rule", "Create and apply a firewall rule")

    _section("Synopsis")
    sys.stderr.write(f"  {ME} [OPTIONS] add-rule [RULE-OPTIONS]\n")

    _section("Description")
    sys.stderr.write(
        "  Creates a new firewall rule, validates all parameters, generates a\n"
        "  unique UUID for tracking, applies the rule via the active backend,\n"
        "  and records it in the persistent rule index.\n\n"
        "  The rule is tagged with a comment (apotropaios:<UUID>) in the backend\n"
        "  for targeted management without affecting other rules.\n"
    )

    _section("Rule Options")
    _opt("--direction DIR", "Traffic direction: inbound, outbound, forward [inbound]")
    _opt("--protocol PROTO", "Protocol: tcp, udp, icmp, icmpv6, sctp, all [tcp]")
    _opt("--src-ip IP", "Source IP address or CIDR notation")
    _opt("--dst-ip IP", "Destination IP address or CIDR notation")
    _opt("--src-port PORT", "Source port number or range (e.g., 1024-65535)")
    _opt("--dst-port PORT", "Destination port number or range (e.g., 80 or 8080-8090)")
    _opt("--action ACTION", "Rule action: accept, drop, reject, log, masquerade, return")
    _opt("", "Compound: log,drop  log,accept  log,reject")
    _opt("--interface IFACE", "Network interface (e.g., eth0, ens33)")
    _opt("--duration TYPE", "Rule duration: permanent, temporary [permanent]")
    _opt("--ttl SECONDS", "Time-to-live for temporary rules (60-2592000)")
    _opt("--description TEXT", "Human-readable description for the rule")

    _section("Connection Tracking")
    _opt("--conn-state STATES", "Conntrack states: new, established, related, invalid")
    _opt("", "Comma-separated for multiple: new,established,related")

    _section("Logging Options (when action includes log)")
    _opt("--log-prefix TEXT", "Log message prefix (max 29 chars)")
    _opt("--log-level LEVEL", "Syslog level: emerg/alert/crit/err/warning/notice/info/debug")

    _section("Rate Limiting")
    _opt("--limit RATE", "Rate limit: N/second, N/minute, N/hour, N/day")
    _opt("--limit-burst N", "Max burst before limit applies [5]")

    _section("Backend-Specific Options")
    _opt("--zone ZONE", "Firewalld zone name [public]")
    _opt("--chain CHAIN", "iptables/nftables chain (auto-set from direction if omitted)")
    _opt("--table TABLE", "iptables table (filter/nat/mangle/raw) or nftables table name")

    _section("Examples")
    sys.stderr.write(
        f"  # Allow HTTPS inbound\n"
        f"  sudo {ME} add-rule --protocol tcp --dst-port 443 --action accept\n\n"
        f"  # Block a specific IP\n"
        f"  sudo {ME} add-rule --src-ip 203.0.113.50 --action drop \\\n"
        f"      --description \"Block suspicious host\"\n\n"
        f"  # Temporary DNS rule (2 hours)\n"
        f"  sudo {ME} add-rule --protocol udp --dst-port 53 --action accept \\\n"
        f"      --duration temporary --ttl 7200 --description \"DNS 2h\"\n\n"
        f"  # Log and drop with connection tracking\n"
        f"  sudo {ME} add-rule --action log,drop --conn-state invalid \\\n"
        f"      --log-prefix \"APO:INVALID: \" --description \"Log invalid pkts\"\n"
    )

    _tip("Temporary rules auto-expire. Monitor via: menu > Rule Management > Rule expiry watcher")
    _tip("Rules are tracked by UUID. Use list-rules to see all tracked rules.")

    _related(
        f"{ME} list-rules         — Show all Apotropaios-tracked rules",
        f"{ME} remove-rule ID     — Remove a rule by its UUID",
        f"{ME} activate-rule ID   — Re-activate a deactivated rule",
        f"{ME} deactivate-rule ID — Deactivate without deleting",
        f"{ME} import FILE        — Bulk-import rules from a file",
    )
    sys.stderr.write("\n")


@_register("remove-rule")
def _help_cmd_remove_rule() -> None:
    """Help for the remove-rule command."""
    _header("remove-rule", "Remove a rule by its UUID")
    _section("Synopsis")
    sys.stderr.write(f"  sudo {ME} remove-rule RULE_ID\n")
    _section("Description")
    sys.stderr.write(
        "  Permanently removes a rule from both the firewall backend and the\n"
        "  persistent rule index. The rule UUID is required.\n"
    )
    _related(
        f"{ME} list-rules         — Find rule UUIDs",
        f"{ME} deactivate-rule ID — Deactivate without deleting",
    )
    sys.stderr.write("\n")


@_register("activate-rule")
def _help_cmd_activate_rule() -> None:
    """Help for the activate-rule command."""
    _header("activate-rule", "Re-activate a deactivated rule")
    _section("Synopsis")
    sys.stderr.write(f"  sudo {ME} activate-rule RULE_ID\n")
    _section("Description")
    sys.stderr.write(
        "  Re-applies a previously deactivated rule to the firewall backend\n"
        "  and updates its state to active in the rule index.\n"
    )
    sys.stderr.write("\n")


@_register("deactivate-rule")
def _help_cmd_deactivate_rule() -> None:
    """Help for the deactivate-rule command."""
    _header("deactivate-rule", "Deactivate a rule (keep in index)")
    _section("Synopsis")
    sys.stderr.write(f"  sudo {ME} deactivate-rule RULE_ID\n")
    _section("Description")
    sys.stderr.write(
        "  Removes the rule from the firewall backend but keeps it in the\n"
        "  rule index for potential re-activation later.\n"
    )
    sys.stderr.write("\n")


@_register("list-rules")
def _help_cmd_list_rules() -> None:
    """Help for the list-rules command."""
    _header("list-rules", "List all Apotropaios-tracked rules")
    _section("Synopsis")
    sys.stderr.write(f"  {ME} list-rules\n")
    _section("Description")
    sys.stderr.write(
        "  Displays all rules tracked by Apotropaios with their UUID, backend,\n"
        "  direction, action, state, and TTL information. Does not require root.\n"
    )
    sys.stderr.write("\n")


@_register("system-rules")
def _help_cmd_system_rules() -> None:
    """Help for the system-rules command."""
    _header("system-rules", "Audit all native system firewall rules")
    _section("Synopsis")
    sys.stderr.write(f"  sudo {ME} system-rules\n")
    _section("Description")
    sys.stderr.write(
        "  Displays all rules currently active in the firewall backend,\n"
        "  including rules not managed by Apotropaios.\n"
    )
    sys.stderr.write("\n")


@_register("block-all")
def _help_cmd_block_all() -> None:
    """Help for the block-all command."""
    _header("block-all", "Block ALL inbound and outbound traffic")
    _section("Synopsis")
    sys.stderr.write(f"  sudo {ME} block-all\n")
    _section("Description")
    sys.stderr.write(
        "  Drops all inbound and outbound traffic. Creates an automatic\n"
        "  restore point before execution so the change can be reverted.\n"
    )
    _tip("A restore point is created automatically before block-all executes.")
    sys.stderr.write("\n")


@_register("allow-all")
def _help_cmd_allow_all() -> None:
    """Help for the allow-all command."""
    _header("allow-all", "Allow ALL traffic (remove restrictions)")
    _section("Synopsis")
    sys.stderr.write(f"  sudo {ME} allow-all\n")
    _section("Description")
    sys.stderr.write(
        "  Removes all firewall restrictions, allowing all traffic through.\n"
        "  Use with caution — this effectively disables the firewall.\n"
    )
    sys.stderr.write("\n")


@_register("enable")
def _help_cmd_enable() -> None:
    """Help for the enable command."""
    _header("enable", "Start and enable the firewall backend")
    _section("Synopsis")
    sys.stderr.write(f"  sudo {ME} enable\n")
    _section("Description")
    sys.stderr.write(
        "  Starts the active firewall backend service and enables it at boot.\n"
        "  Uses systemctl for systemd-managed services.\n"
    )
    _related(
        f"{ME} disable         — Stop the firewall backend",
        f"{ME} status          — Check current backend state",
    )
    sys.stderr.write("\n")


@_register("disable")
def _help_cmd_disable() -> None:
    """Help for the disable command."""
    _header("disable", "Stop the firewall backend")
    _section("Synopsis")
    sys.stderr.write(f"  sudo {ME} disable\n")
    _section("Description")
    sys.stderr.write(
        "  Stops the active firewall backend service. Existing rules remain\n"
        "  in the kernel until reboot but no new connections are filtered.\n"
    )
    _related(
        f"{ME} enable          — Start the firewall backend",
        f"{ME} status          — Check current backend state",
    )
    sys.stderr.write("\n")


@_register("reset")
def _help_cmd_reset() -> None:
    """Help for the reset command."""
    _header("reset", "Reset the firewall backend to defaults")
    _section("Synopsis")
    sys.stderr.write(f"  sudo {ME} reset\n")
    _section("Description")
    sys.stderr.write(
        "  Flushes all rules and resets the active backend to its default\n"
        "  configuration. Requires interactive confirmation (type 'yes').\n"
        "  For iptables: flushes all 5 tables, deletes custom chains,\n"
        "  zeroes counters, sets policies to ACCEPT.\n"
    )
    _related(
        f"{ME} status          — Check current backend state",
        f"{ME} backup          — Create backup before resetting",
    )
    sys.stderr.write("\n")


@_register("import")
def _help_cmd_import() -> None:
    """Help for the import command."""
    _header("import", "Import rules from configuration file")
    _section("Synopsis")
    sys.stderr.write(f"  sudo {ME} import FILE\n")
    _section("Description")
    sys.stderr.write(
        "  Reads rules from a configuration file and applies them via the\n"
        "  active backend. Supports dry-run preview and validation.\n"
    )
    _related(
        f"{ME} export FILE    — Export current rules to a file",
    )
    sys.stderr.write("\n")


@_register("export")
def _help_cmd_export() -> None:
    """Help for the export command."""
    _header("export", "Export rules to configuration file")
    _section("Synopsis")
    sys.stderr.write(f"  {ME} export FILE\n")
    _section("Description")
    sys.stderr.write(
        "  Exports all Apotropaios-tracked rules to a configuration file\n"
        "  that can be imported on this or another system.\n"
    )
    sys.stderr.write("\n")


@_register("backup")
def _help_cmd_backup() -> None:
    """Help for the backup command."""
    _header("backup", "Create a configuration backup")
    _section("Synopsis")
    sys.stderr.write(f"  sudo {ME} backup [LABEL]\n")
    _section("Description")
    sys.stderr.write(
        "  Creates a timestamped tar.gz archive of all firewall configs,\n"
        "  rule index, state files, and a JSON manifest. LABEL is optional\n"
        "  (default: 'manual').\n"
    )
    _related(
        f"{ME} restore FILE   — Restore from a backup archive",
    )
    sys.stderr.write("\n")


@_register("restore")
def _help_cmd_restore() -> None:
    """Help for the restore command."""
    _header("restore", "Restore from backup archive")
    _section("Synopsis")
    sys.stderr.write(f"  sudo {ME} restore FILE\n")
    _section("Description")
    sys.stderr.write(
        "  Restores firewall configuration and rules from a backup archive.\n"
        "  Validates the archive integrity before restoring.\n"
    )
    sys.stderr.write("\n")


@_register("install")
def _help_cmd_install() -> None:
    """Help for the install command."""
    _header("install", "Install a firewall package")
    _section("Synopsis")
    sys.stderr.write(f"  sudo {ME} install FW_NAME\n")
    _section("Description")
    sys.stderr.write(
        "  Installs the specified firewall package using the system's\n"
        "  package manager (apt, dnf, or pacman).\n"
    )
    sys.stderr.write("\n")


@_register("update")
def _help_cmd_update() -> None:
    """Help for the update command."""
    _header("update", "Update a firewall package")
    _section("Synopsis")
    sys.stderr.write(f"  sudo {ME} update FW_NAME\n")
    _section("Description")
    sys.stderr.write(
        "  Updates the specified firewall package to the latest available\n"
        "  version using the system's package manager.\n"
    )
    sys.stderr.write("\n")
