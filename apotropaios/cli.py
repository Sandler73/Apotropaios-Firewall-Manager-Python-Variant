# ==============================================================================
# File:         apotropaios/cli.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     CLI argument parsing, initialization, and command dispatch
# Description:  Implements the full command-line interface with progressive help,
#               21 subcommands, global options, and two-phase execution:
#
#               Phase 1 (Pre-init): Parse arguments and detect help requests.
#                 - Global help (--help before command) exits immediately.
#                 - Per-command help (COMMAND --help) dispatches to help_system
#                   and exits without initializing the framework.
#                 - --version prints version and exits.
#
#               Phase 2 (Post-init): Initialize framework subsystems, then
#                 dispatch to the appropriate command handler.
#
#               Global Options:
#                 -h, --help            Show global help or per-command help
#                 -v, --version         Show version and exit
#                 --interactive         Launch interactive menu mode
#                 --non-interactive     Disable interactive prompts (scripting)
#                 --log-level LEVEL     Set log verbosity
#                 --backend NAME        Select firewall backend
#
#               Commands (21):
#                 menu, help, detect, status, add-rule, remove-rule,
#                 activate-rule, deactivate-rule, list-rules, system-rules,
#                 enable, disable, reset, block-all, allow-all, import,
#                 export, backup, restore, install, update
#
# Notes:        - Uses argparse with add_help=False for progressive help control
#               - Per-command help bypasses _initialize() (Bash Lesson #23)
#               - --interactive and --non-interactive are mutually exclusive
#               - --interactive cannot be combined with a command
#               - Default behavior (no args) launches interactive menu
#               - Parity target: bash v1.1.10 apotropaios.sh (_parse_args,
#                 _initialize, _execute_command, _cli_add_rule)
# Version:      1.2.1
# ==============================================================================

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import NoReturn

from apotropaios.core.constants import (
    CLI_COMMANDS,
    FULL_NAME,
    MIN_PYTHON_VERSION,
    VERSION,
    Color,
    DirPath,
    ErrorCode,
    LogLevel,
    SUPPORTED_FW_IDS,
)

# Runtime state dict for sharing detection results between _initialize and handlers
_state: dict[str, object] = {}


# ==============================================================================
# Argument Parser Construction
#
# Uses add_help=False on all parsers to implement progressive help manually.
# This lets us intercept --help at the right level and bypass initialization
# for per-command help (matching bash variant behavior).
# ==============================================================================

def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all commands and options.

    Returns a parser with add_help=False (help handled manually),
    global options, and subparsers for all 21 commands.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="apotropaios",
        description=f"{FULL_NAME} v{VERSION}",
        add_help=False,  # Manual help handling for progressive help
    )

    # --- Global options ---
    parser.add_argument(
        "-h", "--help",
        action="store_true",
        default=False,
        dest="help",
        help="Show help (global or per-command)",
    )
    parser.add_argument(
        "-v", "--version",
        action="store_true",
        default=False,
        dest="version",
        help="Show version and exit",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        default=False,
        help="Launch interactive menu mode",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        default=False,
        dest="non_interactive",
        help="Disable interactive prompts (scripting/automation)",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default=None,
        dest="log_level",
        metavar="LEVEL",
        help="Set log verbosity: trace|debug|info|warning|error|critical",
    )
    parser.add_argument(
        "--backend",
        type=str,
        default=None,
        metavar="NAME",
        help="Set firewall backend: firewalld|ipset|iptables|nftables|ufw",
    )

    # --- Subcommands ---
    subparsers = parser.add_subparsers(
        dest="command",
        metavar="COMMAND",
    )

    # menu (also default when no command given)
    subparsers.add_parser("menu", add_help=False,
                          help="Launch interactive menu (default)")

    # help (maps to --help)
    subparsers.add_parser("help", add_help=False,
                          help="Show help (same as --help)")

    # detect
    subparsers.add_parser("detect", add_help=False,
                          help="Detect OS and installed firewalls")

    # status
    subparsers.add_parser("status", add_help=False,
                          help="Show active firewall backend status")

    # add-rule (most complex — many options)
    add_rule = subparsers.add_parser("add-rule", add_help=False,
                                     help="Create and apply a firewall rule")
    _add_rule_options(add_rule)

    # remove-rule
    rm = subparsers.add_parser("remove-rule", add_help=False,
                               help="Remove a rule by its UUID")
    rm.add_argument("rule_id", nargs="?", default=None,
                    help="Rule UUID to remove")

    # activate-rule
    act = subparsers.add_parser("activate-rule", add_help=False,
                                help="Re-activate a deactivated rule")
    act.add_argument("rule_id", nargs="?", default=None,
                     help="Rule UUID to activate")

    # deactivate-rule
    deact = subparsers.add_parser("deactivate-rule", add_help=False,
                                  help="Deactivate a rule (keep in index)")
    deact.add_argument("rule_id", nargs="?", default=None,
                       help="Rule UUID to deactivate")

    # list-rules
    subparsers.add_parser("list-rules", add_help=False,
                          help="List all Apotropaios-tracked rules")

    # system-rules
    subparsers.add_parser("system-rules", add_help=False,
                          help="Audit all native system firewall rules")

    # block-all
    subparsers.add_parser("block-all", add_help=False,
                          help="Block ALL inbound and outbound traffic")

    # allow-all
    subparsers.add_parser("allow-all", add_help=False,
                          help="Allow ALL traffic (remove restrictions)")

    # enable
    subparsers.add_parser("enable", add_help=False,
                          help="Start and enable the active firewall backend")

    # disable
    subparsers.add_parser("disable", add_help=False,
                          help="Stop the active firewall backend")

    # reset
    subparsers.add_parser("reset", add_help=False,
                          help="Reset the active firewall backend to defaults")

    # import
    imp = subparsers.add_parser("import", add_help=False,
                                help="Import rules from configuration file")
    imp.add_argument("file_path", nargs="?", default=None,
                     help="Path to the rule configuration file")
    imp.add_argument("--dry-run", action="store_true", default=False,
                     dest="dry_run",
                     help="Validate only, do not apply rules")

    # export
    exp = subparsers.add_parser("export", add_help=False,
                                help="Export rules to configuration file")
    exp.add_argument("file_path", nargs="?", default=None,
                     help="Output file path for exported rules")

    # backup
    bkp = subparsers.add_parser("backup", add_help=False,
                                help="Create a configuration backup")
    bkp.add_argument("label", nargs="?", default="manual",
                     help="Backup label (default: manual)")

    # restore
    rst = subparsers.add_parser("restore", add_help=False,
                                help="Restore from backup archive")
    rst.add_argument("file_path", nargs="?", default=None,
                     help="Path to backup archive file")

    # install
    inst = subparsers.add_parser("install", add_help=False,
                                 help="Install a firewall package")
    inst.add_argument("fw_name", nargs="?", default=None,
                      help="Firewall name to install")

    # update
    upd = subparsers.add_parser("update", add_help=False,
                                help="Update a firewall package")
    upd.add_argument("fw_name", nargs="?", default=None,
                     help="Firewall name to update")

    return parser


def _add_rule_options(parser: argparse.ArgumentParser) -> None:
    """Add all add-rule subcommand options to a parser.

    These mirror the bash variant's _cli_add_rule() option set exactly.

    Args:
        parser: The add-rule subcommand parser.
    """
    # --help flag for per-command help (handled manually)
    parser.add_argument("-h", "--help", action="store_true",
                        default=False, dest="help")

    # Core rule parameters
    parser.add_argument("--direction", default="inbound",
                        help="Traffic direction: inbound|outbound|forward [inbound]")
    parser.add_argument("--protocol", default="tcp",
                        help="Protocol: tcp|udp|icmp|icmpv6|sctp|all [tcp]")
    parser.add_argument("--src-ip", default=None, dest="src_ip",
                        help="Source IP address or CIDR notation")
    parser.add_argument("--dst-ip", default=None, dest="dst_ip",
                        help="Destination IP address or CIDR notation")
    parser.add_argument("--src-port", default=None, dest="src_port",
                        help="Source port number or range")
    parser.add_argument("--dst-port", default=None, dest="dst_port",
                        help="Destination port number or range")
    parser.add_argument("--action", default="accept",
                        help="Rule action: accept|drop|reject|log|masquerade [accept]")
    parser.add_argument("--interface", default=None,
                        help="Network interface (e.g., eth0)")

    # Duration and TTL
    parser.add_argument("--duration", default="permanent", dest="duration_type",
                        help="Duration: permanent|temporary [permanent]")
    parser.add_argument("--ttl", default="0",
                        help="TTL in seconds for temporary rules (60-2592000)")
    parser.add_argument("--description", default="",
                        help="Human-readable rule description")

    # Connection tracking
    parser.add_argument("--conn-state", "--state", default=None, dest="conn_state",
                        help="Conntrack states: new,established,related,invalid")

    # Logging options (for log actions)
    parser.add_argument("--log-prefix", default=None, dest="log_prefix",
                        help="Log message prefix (max 29 chars)")
    parser.add_argument("--log-level", default=None, dest="rule_log_level",
                        help="Syslog level: emerg|alert|crit|err|warning|notice|info|debug")

    # Rate limiting
    parser.add_argument("--limit", default=None,
                        help="Rate limit: N/second|N/minute|N/hour|N/day")
    parser.add_argument("--limit-burst", default=None, dest="limit_burst",
                        help="Max burst before rate limit applies")

    # Backend-specific
    parser.add_argument("--zone", default=None,
                        help="Firewalld zone name [public]")
    parser.add_argument("--chain", default=None,
                        help="iptables/nftables chain name")
    parser.add_argument("--table", default=None,
                        help="iptables table or nftables table name")


# ==============================================================================
# Global Help Display (Tier 1)
# ==============================================================================

def _show_global_help() -> None:
    """Display top-level usage information (Tier 1 help).

    Points users to per-command help (Tier 2) for detailed options.
    Output matches the bash variant's _show_usage() function.
    """
    from apotropaios.core.utils import print_banner
    print_banner()

    me = "apotropaios"
    out = sys.stderr.write

    out(f"Usage: {me} [OPTIONS] [COMMAND] [ARGS...]\n")
    out(f"       {me} COMMAND --help     "
        f"{Color.DIM}(detailed command help){Color.RESET}\n\n")

    out(f"{Color.BOLD}Global Options:{Color.RESET}\n")

    def _opt(flag: str, desc: str) -> None:
        out(f"  {flag:<26s} {desc}\n")

    _opt("-h, --help", "Show this help (or COMMAND --help for details)")
    _opt("-v, --version", "Show version and exit")
    _opt("--interactive", "Launch the interactive menu-driven interface")
    _opt("--log-level LEVEL", "Set verbosity: trace|debug|info|warning|error|critical")
    _opt("--backend NAME", "Set firewall: firewalld|ipset|iptables|nftables|ufw")
    _opt("--non-interactive", "Disable interactive prompts (for scripting/automation)")

    out(f"\n{Color.BOLD}Commands:{Color.RESET}\n")

    def _cmd(name: str, desc: str) -> None:
        out(f"  {Color.CYAN}{name:<22s}{Color.RESET} {desc}\n")
    _cmd("menu", "Launch interactive menu (default if no command given)")
    _cmd("detect", "Detect OS and installed firewalls")
    _cmd("status", "Show active firewall backend status")
    out("\n")
    _cmd("add-rule [OPTS]", "Create and apply a firewall rule")
    _cmd("remove-rule ID", "Remove a rule by its UUID")
    _cmd("activate-rule ID", "Re-activate a deactivated rule")
    _cmd("deactivate-rule ID", "Deactivate a rule (keep in index)")
    _cmd("list-rules", "List all Apotropaios-tracked rules")
    _cmd("system-rules", "Audit all native system firewall rules")
    out("\n")
    _cmd("block-all", "Block ALL inbound and outbound traffic")
    _cmd("allow-all", "Allow ALL traffic (remove restrictions)")
    out("\n")
    _cmd("enable", "Start and enable the active firewall backend")
    _cmd("disable", "Stop the active firewall backend")
    _cmd("reset", "Reset the active backend to defaults")
    out("\n")
    _cmd("import FILE", "Import rules from configuration file")
    _cmd("export FILE", "Export rules to configuration file")
    _cmd("backup [LABEL]", "Create a configuration backup")
    _cmd("restore FILE", "Restore from backup archive")
    _cmd("install FW_NAME", "Install a firewall package")
    _cmd("update FW_NAME", "Update a firewall package")

    out(f"\n{Color.BOLD}Operation Modes:{Color.RESET}\n")
    out("  The framework operates in two distinct modes:\n")
    out(f"    {Color.CYAN}Interactive:{Color.RESET}  sudo {me} --interactive"
        f"        {Color.DIM}(guided menu interface){Color.RESET}\n")
    out(f"    {Color.CYAN}CLI:{Color.RESET}          sudo {me} COMMAND [OPTIONS]"
        f"    {Color.DIM}(direct command execution){Color.RESET}\n")

    out(f"\n{Color.BOLD}Quick Examples:{Color.RESET}\n")
    out(f"  sudo {me} --interactive                          "
        f"# Launch interactive menu\n")
    out(f"  sudo {me} detect                                 "
        f"# Scan system (CLI mode)\n")
    out(f"  sudo {me} add-rule --help                        "
        f"# Full add-rule help\n")
    out(f"  sudo {me} add-rule --dst-port 443 --action accept\n")
    out(f"  sudo {me} backup pre-deploy\n")

    out(f"\n{Color.BOLD}Detailed Help:{Color.RESET}\n")
    out("  Every command supports --help for detailed usage, options, and examples:\n")
    out(f"    {me} add-rule --help      Full rule option reference\n")
    out(f"    {me} backup --help        Backup contents and retention info\n")
    out(f"    {me} import --help        Configuration file format reference\n\n")


# ==============================================================================
# Pre-scan for progressive help detection
#
# Scans argv to determine if --help was passed and whether it's global or
# per-command. This is needed because argparse's built-in help action
# immediately prints and exits, preventing us from bypassing initialization
# for per-command help.
# ==============================================================================

def _detect_help_request(argv: list[str]) -> tuple[bool, bool, str]:
    """Pre-scan arguments to detect help requests.

    Determines whether --help was passed before or after a command,
    enabling the progressive help architecture where per-command help
    bypasses framework initialization.

    Args:
        argv: Command-line arguments (sys.argv[1:]).

    Returns:
        Tuple of (is_global_help, is_command_help, command_name).
        At most one of is_global_help / is_command_help is True.
    """
    # Known commands for detection
    command_set = set(CLI_COMMANDS)

    help_found = False
    command_found = ""
    help_before_command = False
    help_after_command = False

    for arg in argv:
        if arg in ("-h", "--help"):
            help_found = True
            if command_found:
                # --help after a command → per-command help
                help_after_command = True
            else:
                # --help before any command → global help
                help_before_command = True
        elif arg in command_set and not command_found:
            command_found = arg
            if help_found:
                # Already saw --help → it was before the command
                pass

    if help_before_command and not command_found:
        return (True, False, "")
    if help_after_command and command_found:
        return (False, True, command_found)
    if help_before_command and command_found:
        # --help appeared, then a command was found later
        # This is ambiguous, but we follow bash behavior: global help
        return (True, False, "")

    return (False, False, command_found)


# ==============================================================================
# Framework Initialization
# ==============================================================================

def _resolve_base_dir() -> str:
    """Determine the framework base directory.

    Resolves to the directory containing the apotropaios package. This
    is used for finding conf/, data/, and other relative paths.

    Returns:
        Absolute path to the framework base directory.
    """
    # The base dir is the parent of the apotropaios package directory
    package_dir = Path(__file__).resolve().parent
    return str(package_dir.parent)


def _load_config(base_dir: str) -> dict[str, str]:
    """Load the framework configuration file if present.

    Search order (first match wins):
    1. /etc/apotropaios/apotropaios.conf   (system-wide)
    2. <base_dir>/conf/apotropaios.conf    (project-local)
    3. <package>/conf/apotropaios.conf     (shipped defaults)

    The file uses INI format (configparser). Values are flattened to a
    single-level dict keyed as "section.option". Precedence at apply time
    is: command line > configuration file > built-in defaults.

    Args:
        base_dir: Framework base directory path.

    Returns:
        Flat dict of configuration values ("section.option" → value).
        Empty dict when no file exists or parsing fails.
    """
    import configparser

    candidates = (
        "/etc/apotropaios/apotropaios.conf",
        os.path.join(base_dir, "conf", "apotropaios.conf"),
        str(Path(__file__).resolve().parent / "conf" / "apotropaios.conf"),
    )

    for candidate in candidates:
        if not os.path.isfile(candidate):
            continue
        # Trust gate: a configuration file that influences privileged
        # firewall behavior must be owned by root or the current effective
        # user and must not be group- or world-writable. Untrusted files
        # are skipped, never partially applied.
        try:
            st = os.stat(candidate)
        except OSError:
            continue
        if st.st_uid not in (0, os.geteuid()) or (st.st_mode & 0o022):
            sys.stderr.write(
                f"Warning: ignoring untrusted configuration file "
                f"(ownership/permissions): {candidate}\n"
            )
            continue
        parser = configparser.ConfigParser()
        try:
            parser.read(candidate, encoding="utf-8")
        except (configparser.Error, OSError):
            sys.stderr.write(
                f"Warning: could not parse configuration file: {candidate}\n"
            )
            return {}
        flat: dict[str, str] = {}
        for section in parser.sections():
            for option, value in parser.items(section):
                flat[f"{section}.{option}"] = value.strip()
        flat["_source"] = candidate
        return flat

    return {}


def _initialize(
    base_dir: str,
    log_level: LogLevel,
    backend_name: str | None = None,
    cli_log_level_given: bool = False,
) -> None:
    """Initialize all framework subsystems.

    Called after argument parsing, before command dispatch. Loads the
    configuration file, then sets up logging, error handling, security,
    OS detection, firewall detection, backend registration and selection,
    rule subsystem, and backup subsystem. Precedence for shared settings:
    command line > configuration file > built-in defaults.

    Args:
        base_dir:            Framework base directory path.
        log_level:           Configured log level (from CLI or default).
        backend_name:        Explicitly requested backend (None = config/auto).
        cli_log_level_given: True when --log-level was passed on the CLI
                             (config must not override an explicit flag).
    """
    from apotropaios.core.logging import log
    from apotropaios.core.errors import init_error_handling
    from apotropaios.core.security import init_security

    # Load configuration file (may adjust defaults below)
    config = _load_config(base_dir)
    _state["config"] = config

    # Config-supplied log level applies only when the CLI didn't set one
    if not cli_log_level_given and config.get("logging.log_level"):
        try:
            log_level = LogLevel.from_string(config["logging.log_level"])
        except ValueError:
            sys.stderr.write(
                f"Warning: invalid log_level in configuration: "
                f"{config['logging.log_level']}\n"
            )

    # Initialize logging
    log_dir = os.path.join(base_dir, DirPath.LOGS)
    log.init(log_dir, log_level)

    if config.get("_source"):
        log.debug("main", f"Configuration loaded from: {config['_source']}")

    # Initialize error handling with logger integration
    init_error_handling(log.log_by_name)

    # Initialize security subsystem
    init_security(base_dir, log)

    # Check root privileges — warn early if not running as root.
    # Most firewall operations require root; detection and status may
    # work partially without root but rule operations will fail.
    from apotropaios.core.security import is_root
    if not is_root():
        log.warning(
            "main",
            "Not running as root — firewall operations will require elevated privileges",
        )

    # Log startup
    log.info(
        "main",
        f"Apotropaios v{VERSION} initializing",
        f"base_dir={base_dir}",
    )

    # OS detection
    from apotropaios.detection.os_detect import detect_os
    os_result = detect_os(log)
    _state["os_result"] = os_result

    # Firewall detection
    from apotropaios.detection.fw_detect import detect_firewalls
    fw_result = detect_firewalls(log)
    _state["fw_result"] = fw_result

    # Register all backends (imports trigger auto-registration)
    import apotropaios.firewall.iptables   # noqa: F401
    import apotropaios.firewall.nftables   # noqa: F401
    import apotropaios.firewall.firewalld  # noqa: F401
    import apotropaios.firewall.ufw        # noqa: F401
    import apotropaios.firewall.ipset      # noqa: F401

    # Backend selection: explicit --backend or auto-detect first installed
    from apotropaios.firewall.common import set_backend, get_backend_name, set_logger as fw_set_logger
    fw_set_logger(log)

    # Configuration-file default backend applies when no --backend flag
    if not backend_name:
        cfg_backend = config.get("firewall.default_backend", "")
        if cfg_backend and cfg_backend in SUPPORTED_FW_IDS:
            backend_name = cfg_backend
            log.info("main", f"Backend set via configuration file: {cfg_backend}")
        elif cfg_backend:
            log.warning("main", f"Invalid default_backend in configuration: {cfg_backend}")

    if backend_name:
        try:
            set_backend(backend_name)
            log.info("main", f"Backend selected: {backend_name}")
        except Exception as exc:
            log.warning("main", f"Failed to set backend {backend_name}: {exc}")
    else:
        # Auto-select first installed backend (preference order)
        for fw_id in ("iptables", "nftables", "firewalld", "ufw"):
            if fw_id in fw_result.get_installed():
                try:
                    set_backend(fw_id)
                    log.info("main", f"Backend auto-selected: {fw_id}")
                    break
                except Exception:
                    continue

    _state["backend"] = get_backend_name()

    # Initialize rule subsystem
    rules_dir = os.path.join(base_dir, DirPath.DATA, "rules")
    from apotropaios.rules.index import rule_index
    from apotropaios.rules.state import rule_state
    try:
        rule_index.init(rules_dir)
        rule_state.init(rules_dir)
        _state["rules_dir"] = rules_dir
        log.info("main", f"Rule subsystem initialized: {rule_index.count()} rule(s)")
    except Exception as exc:
        log.warning("main", f"Rule subsystem init failed: {exc}")
        _state["rules_dir"] = rules_dir

    # Initialize backup subsystem
    backup_dir = os.path.join(base_dir, DirPath.DATA, "backups")
    from apotropaios.backup.backup import init_backup
    try:
        init_backup(backup_dir, log, rules_dir=rules_dir)
        _state["backup_dir"] = backup_dir
    except Exception as exc:
        log.warning("main", f"Backup subsystem init failed: {exc}")

    log.info(
        "main",
        f"Apotropaios v{VERSION} initialized",
        f"os={os_result.os_id} fw_count={fw_result.count} backend={get_backend_name() or 'none'}",
    )


# ==============================================================================
# Destructive Operation Confirmation
# ==============================================================================

def _confirm_destructive(warning: str) -> bool:
    """Prompt for explicit confirmation before a destructive operation.

    Honors the --non-interactive contract: when interactive prompts are
    disabled, the operation proceeds without prompting (the operator has
    explicitly opted into unattended execution). Otherwise the operator
    must type 'yes'. Reads from the controlling terminal when available
    so piped stdin cannot accidentally satisfy the confirmation.

    Args:
        warning: Warning text describing the destructive operation.

    Returns:
        True if the operation is confirmed (or non-interactive mode is on).
    """
    if _state.get("non_interactive"):
        return True

    sys.stderr.write(f"{Color.RED}WARNING: {warning}{Color.RESET}\n")
    sys.stderr.write("Type 'yes' to confirm: ")
    sys.stderr.flush()
    try:
        with open("/dev/tty", "r") as tty:
            reply = tty.readline().strip().lower()
    except OSError:
        try:
            reply = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            reply = ""
    except (EOFError, KeyboardInterrupt):
        reply = ""
    return reply == "yes"


# ==============================================================================
# Command Dispatch
# ==============================================================================

def _dispatch(args: argparse.Namespace) -> int:
    """Execute the parsed command.

    Routes to the appropriate command handler based on the parsed
    subcommand. Every handler delegates to the actual engine implementation.

    Args:
        args: Parsed argument namespace from argparse.

    Returns:
        Exit code (0 for success, non-zero for errors).
    """
    command = args.command or "menu"

    if command in ("", "menu"):
        return _cmd_menu(args)
    elif command == "help":
        _show_global_help()
        return ErrorCode.SUCCESS
    elif command == "detect":
        return _cmd_detect(args)
    elif command == "status":
        return _cmd_status(args)
    elif command == "add-rule":
        return _cmd_add_rule(args)
    elif command == "remove-rule":
        return _cmd_remove_rule(args)
    elif command == "activate-rule":
        return _cmd_activate_rule(args)
    elif command == "deactivate-rule":
        return _cmd_deactivate_rule(args)
    elif command == "list-rules":
        return _cmd_list_rules(args)
    elif command == "system-rules":
        return _cmd_system_rules(args)
    elif command == "block-all":
        return _cmd_block_all(args)
    elif command == "allow-all":
        return _cmd_allow_all(args)
    elif command == "enable":
        return _cmd_enable(args)
    elif command == "disable":
        return _cmd_disable(args)
    elif command == "reset":
        return _cmd_reset(args)
    elif command == "import":
        return _cmd_import(args)
    elif command == "export":
        return _cmd_export(args)
    elif command == "backup":
        return _cmd_backup(args)
    elif command == "restore":
        return _cmd_restore(args)
    elif command == "install":
        return _cmd_install(args)
    elif command == "update":
        return _cmd_update(args)
    else:
        sys.stderr.write(f"Error: Unknown command: {command}\n")
        sys.stderr.write("Run with --help for usage information\n")
        return ErrorCode.USAGE


# ==============================================================================
# Command Handlers — Fully Wired to Engine Implementations
# ==============================================================================

def _cmd_menu(args: argparse.Namespace) -> int:
    """Launch the interactive menu."""
    from apotropaios.menu.main import menu_main
    from apotropaios.core.logging import log
    menu_main(logger=log)
    return ErrorCode.SUCCESS


def _cmd_detect(args: argparse.Namespace) -> int:
    """Detect OS and installed firewalls."""
    from apotropaios.core.utils import print_banner
    from apotropaios.detection.os_detect import print_os_info, OSDetectionResult
    from apotropaios.detection.fw_detect import print_fw_info, FWDetectionResult

    print_banner()
    sys.stderr.write(f"  {Color.BOLD}OS Detection:{Color.RESET}\n")

    os_result = _state.get("os_result")
    if isinstance(os_result, OSDetectionResult):
        print_os_info(os_result)
    else:
        sys.stderr.write("    OS detection data not available.\n")

    fw_result = _state.get("fw_result")
    if isinstance(fw_result, FWDetectionResult):
        print_fw_info(fw_result)
    else:
        sys.stderr.write("    Firewall detection data not available.\n")

    # Show active backend
    backend = _state.get("backend", "")
    if backend:
        sys.stderr.write(f"\n  {Color.BOLD}Active Backend:{Color.RESET} {Color.GREEN}{backend}{Color.RESET}\n")

    sys.stderr.write("\n")
    return ErrorCode.SUCCESS


def _cmd_status(args: argparse.Namespace) -> int:
    """Show firewall backend service state and summary.

    Displays: active backend, running/enabled status, rule count,
    and Apotropaios-tracked rule count. Does NOT dump raw rules
    (use system-rules or list-rules for that).
    """
    from apotropaios.firewall.common import get_backend_name
    from apotropaios.detection.fw_detect import FWDetectionResult, FWBackendStatus
    from apotropaios.rules.index import rule_index

    backend_name = get_backend_name()
    if not backend_name:
        sys.stderr.write(f"{Color.YELLOW}No backend selected. Use --backend NAME.{Color.RESET}\n")
        return ErrorCode.FW_NOT_FOUND

    sys.stderr.write(f"\n  {Color.BOLD}Firewall Status{Color.RESET}\n")
    sys.stderr.write(f"  {'─' * 50}\n")
    sys.stderr.write(f"  Active Backend:  {Color.GREEN}{backend_name}{Color.RESET}\n")

    # Show detection details for the active backend
    fw_result = _state.get("fw_result")
    if isinstance(fw_result, FWDetectionResult):
        status_obj = fw_result.backends.get(backend_name)
        if isinstance(status_obj, FWBackendStatus):
            # Running status
            if status_obj.running:
                sys.stderr.write(f"  Service State:   {Color.GREEN}running{Color.RESET}\n")
            else:
                sys.stderr.write(f"  Service State:   {Color.RED}stopped{Color.RESET}\n")

            # Enabled at boot
            if status_obj.enabled:
                sys.stderr.write(f"  Boot Enabled:    {Color.GREEN}yes{Color.RESET}\n")
            else:
                sys.stderr.write(f"  Boot Enabled:    {Color.YELLOW}no{Color.RESET}\n")

            sys.stderr.write(f"  Version:         {status_obj.version}\n")
            sys.stderr.write(f"  Binary:          {status_obj.binary}\n")

    # Show all detected firewalls summary
    if isinstance(fw_result, FWDetectionResult):
        sys.stderr.write(f"\n  {Color.BOLD}All Detected Firewalls:{Color.RESET}\n")
        for fw_id in sorted(fw_result.backends.keys()):
            bs = fw_result.backends[fw_id]
            if bs.installed:
                state_icon = f"{Color.GREEN}●{Color.RESET}" if bs.running else f"{Color.RED}○{Color.RESET}"
                active_tag = f" {Color.CYAN}← active{Color.RESET}" if fw_id == backend_name else ""
                sys.stderr.write(
                    f"    {state_icon} {fw_id:<12s} v{bs.version:<10s} "
                    f"{'running' if bs.running else 'stopped':<8s} "
                    f"{'enabled' if bs.enabled else 'disabled'}{active_tag}\n"
                )
            else:
                sys.stderr.write(f"    {Color.DIM}○ {fw_id:<12s} not installed{Color.RESET}\n")

    # Apotropaios tracked rules count
    tracked = rule_index.count() if rule_index.initialized else 0
    sys.stderr.write(f"\n  Tracked Rules:   {tracked}\n")
    sys.stderr.write("\n")

    return ErrorCode.SUCCESS


def _cmd_add_rule(args: argparse.Namespace) -> int:
    """Create and apply a firewall rule via CLI options."""
    from apotropaios.rules.engine import rule_create

    # Build rule params dict from parsed args
    rule_params: dict[str, str] = {}
    param_map = {
        "direction": args.direction,
        "protocol": args.protocol,
        "src_ip": getattr(args, "src_ip", None),
        "dst_ip": getattr(args, "dst_ip", None),
        "src_port": getattr(args, "src_port", None),
        "dst_port": getattr(args, "dst_port", None),
        "action": args.action,
        "interface": getattr(args, "interface", None),
        "duration_type": getattr(args, "duration_type", "permanent"),
        "ttl": getattr(args, "ttl", "0"),
        "description": getattr(args, "description", ""),
        "conn_state": getattr(args, "conn_state", None),
        "log_prefix": getattr(args, "log_prefix", None),
        "log_level": getattr(args, "rule_log_level", None),
        "limit": getattr(args, "limit", None),
        "limit_burst": getattr(args, "limit_burst", None),
        "zone": getattr(args, "zone", None),
        "chain": getattr(args, "chain", None),
        "table": getattr(args, "table", None),
    }

    # Filter out None values
    for k, v in param_map.items():
        if v is not None:
            rule_params[k] = str(v)

    try:
        rule_id = rule_create(rule_params)
        sys.stderr.write(f"{Color.GREEN}Rule created: {rule_id}{Color.RESET}\n")
        return ErrorCode.SUCCESS
    except Exception as exc:
        sys.stderr.write(f"{Color.RED}Error: {exc}{Color.RESET}\n")
        return ErrorCode.RULE_APPLY_FAIL


def _cmd_remove_rule(args: argparse.Namespace) -> int:
    """Remove a rule by its UUID."""
    from apotropaios.rules.engine import rule_remove
    if not args.rule_id:
        sys.stderr.write("Error: remove-rule requires a rule ID\n")
        return ErrorCode.USAGE
    try:
        rule_remove(args.rule_id)
        sys.stderr.write(f"{Color.GREEN}Rule removed: {args.rule_id}{Color.RESET}\n")
        return ErrorCode.SUCCESS
    except Exception as exc:
        sys.stderr.write(f"{Color.RED}Error: {exc}{Color.RESET}\n")
        return ErrorCode.RULE_REMOVE_FAIL


def _cmd_activate_rule(args: argparse.Namespace) -> int:
    """Re-activate a deactivated rule."""
    from apotropaios.rules.engine import rule_activate
    if not args.rule_id:
        sys.stderr.write("Error: activate-rule requires a rule ID\n")
        return ErrorCode.USAGE
    try:
        rule_activate(args.rule_id)
        sys.stderr.write(f"{Color.GREEN}Rule activated: {args.rule_id}{Color.RESET}\n")
        return ErrorCode.SUCCESS
    except Exception as exc:
        sys.stderr.write(f"{Color.RED}Error: {exc}{Color.RESET}\n")
        return ErrorCode.RULE_APPLY_FAIL


def _cmd_deactivate_rule(args: argparse.Namespace) -> int:
    """Deactivate a rule (keep in index)."""
    from apotropaios.rules.engine import rule_deactivate
    if not args.rule_id:
        sys.stderr.write("Error: deactivate-rule requires a rule ID\n")
        return ErrorCode.USAGE
    try:
        rule_deactivate(args.rule_id)
        sys.stderr.write(f"{Color.GREEN}Rule deactivated: {args.rule_id}{Color.RESET}\n")
        return ErrorCode.SUCCESS
    except Exception as exc:
        sys.stderr.write(f"{Color.RED}Error: {exc}{Color.RESET}\n")
        return ErrorCode.GENERAL


def _cmd_list_rules(args: argparse.Namespace) -> int:
    """List all Apotropaios-tracked rules."""
    from apotropaios.rules.index import rule_index
    output = rule_index.list_formatted()
    sys.stderr.write(output + "\n")
    return ErrorCode.SUCCESS


def _cmd_system_rules(args: argparse.Namespace) -> int:
    """Audit all native system firewall rules."""
    from apotropaios.firewall.common import fw_list_rules, get_backend_name
    try:
        backend = get_backend_name()
        if not backend:
            sys.stderr.write(f"{Color.YELLOW}No backend selected. Use --backend NAME.{Color.RESET}\n")
            return ErrorCode.FW_NOT_FOUND
        output = fw_list_rules()
        sys.stderr.write(f"\n  {Color.BOLD}System Rules ({backend}):{Color.RESET}\n")
        sys.stderr.write(f"{output}\n")
        return ErrorCode.SUCCESS
    except Exception as exc:
        sys.stderr.write(f"{Color.RED}Error: {exc}{Color.RESET}\n")
        return ErrorCode.GENERAL


def _cmd_block_all(args: argparse.Namespace) -> int:
    """Block ALL inbound and outbound traffic."""
    from apotropaios.rules.engine import rule_block_all
    try:
        rule_id = rule_block_all()
        sys.stderr.write(f"{Color.GREEN}All traffic blocked (rule: {rule_id}){Color.RESET}\n")
        return ErrorCode.SUCCESS
    except Exception as exc:
        sys.stderr.write(f"{Color.RED}Error: {exc}{Color.RESET}\n")
        return ErrorCode.RULE_APPLY_FAIL


def _cmd_allow_all(args: argparse.Namespace) -> int:
    """Allow ALL traffic (remove restrictions)."""
    from apotropaios.rules.engine import rule_allow_all
    try:
        rule_id = rule_allow_all()
        sys.stderr.write(f"{Color.GREEN}All traffic allowed (rule: {rule_id}){Color.RESET}\n")
        return ErrorCode.SUCCESS
    except Exception as exc:
        sys.stderr.write(f"{Color.RED}Error: {exc}{Color.RESET}\n")
        return ErrorCode.RULE_APPLY_FAIL


def _cmd_enable(args: argparse.Namespace) -> int:
    """Start and enable the active firewall backend."""
    from apotropaios.firewall.common import fw_enable, get_backend_name
    backend = get_backend_name()
    if not backend:
        sys.stderr.write(f"{Color.YELLOW}No backend selected. Use --backend NAME.{Color.RESET}\n")
        return ErrorCode.FW_NOT_FOUND
    try:
        fw_enable()
        sys.stderr.write(f"{Color.GREEN}{backend} enabled and started{Color.RESET}\n")
        return ErrorCode.SUCCESS
    except Exception as exc:
        sys.stderr.write(f"{Color.RED}Error: {exc}{Color.RESET}\n")
        return ErrorCode.GENERAL


def _cmd_disable(args: argparse.Namespace) -> int:
    """Stop the active firewall backend."""
    from apotropaios.firewall.common import fw_disable, get_backend_name
    backend = get_backend_name()
    if not backend:
        sys.stderr.write(f"{Color.YELLOW}No backend selected. Use --backend NAME.{Color.RESET}\n")
        return ErrorCode.FW_NOT_FOUND
    try:
        fw_disable()
        sys.stderr.write(f"{Color.GREEN}{backend} stopped{Color.RESET}\n")
        return ErrorCode.SUCCESS
    except Exception as exc:
        sys.stderr.write(f"{Color.RED}Error: {exc}{Color.RESET}\n")
        return ErrorCode.GENERAL


def _cmd_reset(args: argparse.Namespace) -> int:
    """Reset the active firewall backend to defaults."""
    from apotropaios.firewall.common import fw_reset, get_backend_name
    backend = get_backend_name()
    if not backend:
        sys.stderr.write(f"{Color.YELLOW}No backend selected. Use --backend NAME.{Color.RESET}\n")
        return ErrorCode.FW_NOT_FOUND
    # Safety confirmation — reset is destructive (skipped in
    # --non-interactive mode per the flag's contract)
    if not _confirm_destructive(
        f"This will reset {backend} to defaults, removing all rules."
    ):
        sys.stderr.write("Reset cancelled.\n")
        return ErrorCode.SUCCESS
    try:
        fw_reset()
        sys.stderr.write(f"{Color.GREEN}{backend} reset to defaults{Color.RESET}\n")
        return ErrorCode.SUCCESS
    except Exception as exc:
        sys.stderr.write(f"{Color.RED}Error: {exc}{Color.RESET}\n")
        return ErrorCode.GENERAL


def _cmd_import(args: argparse.Namespace) -> int:
    """Import rules from configuration file."""
    from apotropaios.rules.import_export import import_rules
    if not args.file_path:
        sys.stderr.write("Error: import requires a file path\n")
        return ErrorCode.USAGE
    dry_run = getattr(args, "dry_run", False)
    try:
        ok, err, skip = import_rules(args.file_path, dry_run=dry_run)
        prefix = "[DRY RUN] " if dry_run else ""
        sys.stderr.write(f"{prefix}Import complete: {ok} success, {err} errors, {skip} skipped\n")
        return ErrorCode.SUCCESS if err == 0 else ErrorCode.RULE_IMPORT_FAIL
    except Exception as exc:
        sys.stderr.write(f"{Color.RED}Error: {exc}{Color.RESET}\n")
        return ErrorCode.RULE_IMPORT_FAIL


def _cmd_export(args: argparse.Namespace) -> int:
    """Export rules to configuration file."""
    from apotropaios.rules.import_export import export_rules
    if not args.file_path:
        sys.stderr.write("Error: export requires a file path\n")
        return ErrorCode.USAGE
    try:
        count = export_rules(args.file_path)
        sys.stderr.write(f"Exported {count} rules to {args.file_path}\n")
        return ErrorCode.SUCCESS
    except Exception as exc:
        sys.stderr.write(f"{Color.RED}Error: {exc}{Color.RESET}\n")
        return ErrorCode.GENERAL


def _cmd_backup(args: argparse.Namespace) -> int:
    """Create a configuration backup."""
    from apotropaios.backup.backup import create_backup
    label = getattr(args, "label", "manual") or "manual"
    rules_dir = str(_state.get("rules_dir", ""))
    try:
        backup_file = create_backup(label, rules_dir=rules_dir)
        sys.stderr.write(f"{Color.GREEN}Backup created: {backup_file}{Color.RESET}\n")
        return ErrorCode.SUCCESS
    except Exception as exc:
        sys.stderr.write(f"{Color.RED}Error: {exc}{Color.RESET}\n")
        return ErrorCode.BACKUP_FAIL


def _cmd_restore(args: argparse.Namespace) -> int:
    """Restore from backup archive."""
    from apotropaios.backup.restore import restore_backup
    if not args.file_path:
        sys.stderr.write("Error: restore requires a backup file path\n")
        return ErrorCode.USAGE
    rules_dir = str(_state.get("rules_dir", ""))
    try:
        restore_backup(args.file_path, rules_dir=rules_dir)
        sys.stderr.write(f"{Color.GREEN}Restore complete{Color.RESET}\n")
        return ErrorCode.SUCCESS
    except Exception as exc:
        sys.stderr.write(f"{Color.RED}Error: {exc}{Color.RESET}\n")
        return ErrorCode.RESTORE_FAIL


def _cmd_install(args: argparse.Namespace) -> int:
    """Install a firewall package."""
    from apotropaios.install.installer import install_firewall
    if not args.fw_name:
        sys.stderr.write("Error: install requires a firewall name\n")
        return ErrorCode.USAGE
    try:
        install_firewall(args.fw_name)
        sys.stderr.write(f"{Color.GREEN}{args.fw_name} installed successfully{Color.RESET}\n")
        return ErrorCode.SUCCESS
    except Exception as exc:
        sys.stderr.write(f"{Color.RED}Error: {exc}{Color.RESET}\n")
        return ErrorCode.FW_INSTALL_FAIL


def _cmd_update(args: argparse.Namespace) -> int:
    """Update a firewall package."""
    from apotropaios.install.installer import update_firewall
    if not args.fw_name:
        sys.stderr.write("Error: update requires a firewall name\n")
        return ErrorCode.USAGE
    try:
        update_firewall(args.fw_name)
        sys.stderr.write(f"{Color.GREEN}{args.fw_name} updated successfully{Color.RESET}\n")
        return ErrorCode.SUCCESS
    except Exception as exc:
        sys.stderr.write(f"{Color.RED}Error: {exc}{Color.RESET}\n")
        return ErrorCode.FW_INSTALL_FAIL


# ==============================================================================
# Main Entry Point
# ==============================================================================

def main(argv: list[str] | None = None) -> NoReturn:
    """Main entry point for the CLI.

    Implements the full lifecycle: parse → validate → (help or init+dispatch).

    Args:
        argv: Command-line arguments. Defaults to sys.argv[1:].

    Raises:
        SystemExit: Always exits with an appropriate error code.
    """
    if argv is None:
        argv = sys.argv[1:]

    # --- Phase 0a: Python interpreter gate ---
    # The framework depends on 3.12+ language and stdlib behavior; running
    # on an older interpreter must fail fast rather than partially work.
    if sys.version_info < MIN_PYTHON_VERSION:
        sys.stderr.write(
            f"Error: Python {MIN_PYTHON_VERSION[0]}.{MIN_PYTHON_VERSION[1]}+ "
            f"is required (running "
            f"{sys.version_info.major}.{sys.version_info.minor})\n"
        )
        sys.exit(ErrorCode.GENERAL)

    # --- Phase 0: Version check (fast exit) ---
    if "--version" in argv or "-v" in argv:
        sys.stdout.write(f"{FULL_NAME} v{VERSION}\n")
        sys.exit(ErrorCode.SUCCESS)

    # --- Phase 1: Progressive help detection ---
    is_global_help, is_command_help, help_command = _detect_help_request(argv)

    if is_global_help:
        _show_global_help()
        sys.exit(ErrorCode.SUCCESS)

    if is_command_help:
        # Per-command help bypasses initialization (Bash Lesson #23)
        from apotropaios.menu.help_system import help_dispatch
        exit_code = help_dispatch(help_command)
        sys.exit(exit_code)

    # --- Phase 2: Full argument parsing ---
    parser = _build_parser()

    # Pre-extract global options that may appear before OR after the command.
    # argparse subparsers don't pass through parent options when the
    # subcommand appears first, so we extract them manually.
    filtered_argv: list[str] = []
    pre_log_level: str | None = None
    pre_backend: str | None = None
    pre_interactive = False
    pre_non_interactive = False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            i += 1
            continue  # Already handled above
        elif a == "--log-level" and i + 1 < len(argv):
            pre_log_level = argv[i + 1]
            i += 2
            continue
        elif a.startswith("--log-level="):
            pre_log_level = a.split("=", 1)[1]
            i += 1
            continue
        elif a == "--backend" and i + 1 < len(argv):
            pre_backend = argv[i + 1]
            i += 2
            continue
        elif a.startswith("--backend="):
            pre_backend = a.split("=", 1)[1]
            i += 1
            continue
        elif a == "--interactive":
            pre_interactive = True
            i += 1
            continue
        elif a == "--non-interactive":
            pre_non_interactive = True
            i += 1
            continue
        filtered_argv.append(a)
        i += 1

    args = parser.parse_args(filtered_argv)

    # Merge pre-extracted globals into args namespace
    if pre_log_level is not None:
        args.log_level = pre_log_level
    if pre_backend is not None:
        args.backend = pre_backend
    if pre_interactive:
        args.interactive = True
    if pre_non_interactive:
        args.non_interactive = True

    # Handle "help" command same as --help (bypass init)
    if args.command == "help":
        _show_global_help()
        sys.exit(ErrorCode.SUCCESS)

    # --- Phase 3: Validate mutually exclusive flags ---
    if args.interactive and args.non_interactive:
        sys.stderr.write(
            "Error: --interactive and --non-interactive are mutually exclusive\n"
        )
        sys.exit(ErrorCode.USAGE)

    if args.interactive and args.command:
        sys.stderr.write(
            f"Error: --interactive cannot be combined with a command "
            f"({args.command})\n"
            f"Use --interactive for menu mode, or specify a command for "
            f"CLI mode\n"
        )
        sys.exit(ErrorCode.USAGE)

    # --interactive forces menu mode
    if args.interactive:
        args.command = "menu"

    # Default: no command → menu
    if not args.command:
        args.command = "menu"

    # --- Phase 4: Resolve log level ---
    log_level = LogLevel.WARNING  # Default: clean console (file always captures all)
    if args.log_level:
        try:
            log_level = LogLevel.from_string(args.log_level)
        except ValueError:
            sys.stderr.write(
                f"Error: Invalid log level: {args.log_level}\n"
                f"Valid levels: trace, debug, info, warning, error, critical\n"
            )
            sys.exit(ErrorCode.USAGE)

    # --- Phase 5: Validate backend name if specified ---
    if args.backend and args.backend.lower() not in SUPPORTED_FW_IDS:
        sys.stderr.write(
            f"Error: Unknown backend: {args.backend}\n"
            f"Valid backends: {', '.join(sorted(SUPPORTED_FW_IDS))}\n"
        )
        sys.exit(ErrorCode.USAGE)

    # Record prompt mode for command handlers (destructive confirmations)
    _state["non_interactive"] = bool(args.non_interactive)

    # --- Phase 6: Initialize framework ---
    base_dir = _resolve_base_dir()
    _initialize(base_dir, log_level, args.backend,
                cli_log_level_given=args.log_level is not None)

    # --- Phase 7: Dispatch command ---
    exit_code = _dispatch(args)

    # --- Phase 8: Shutdown ---
    from apotropaios.core.logging import log
    log.shutdown()

    sys.exit(exit_code)
