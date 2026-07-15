# ==============================================================================
# File:         apotropaios/menu/main.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Interactive menu system with expiry monitoring
# Description:  Implements the interactive menu-driven interface with:
#               - 8-option main menu (Firewall, Rules, Quick Actions, Backup,
#                 System Info, Install/Update, Help, Exit)
#               - Background expiry monitor daemon thread (30s interval)
#               - Cancel-aware input helper at every prompt (Lesson #14)
#               - Color-coded expiry warnings on menu render (Lesson #16)
#               - Clean lifecycle: monitor starts on entry, stops on exit,
#                 registered with cleanup stack for signal-safe termination
#
# Notes:        - All prompts use same output channel (stderr) per Lesson #12
#               - Cancel keywords: q, quit, cancel, back, b
#               - Don't read input in daemon thread (Lesson #13)
#               - Background monitor uses threading.Event for clean shutdown
#               - Parity target: bash v1.1.10 lib/menu/menu_main.sh
# Version:      1.2.1
# ==============================================================================

from __future__ import annotations

import sys
import threading
from typing import Final

from apotropaios.core.constants import (
    VERSION,
    Color,
    Performance,
)
from apotropaios.core.errors import cleanup_stack
from apotropaios.core.utils import print_banner, print_separator
from apotropaios.core.validation import is_cancel_keyword

_log_fn: object | None = None


def _log(level: str, msg: str) -> None:
    if _log_fn is not None:
        method = getattr(_log_fn, level, None)
        if method is not None:
            method("menu", msg)


# ==============================================================================
# Expiry Monitor — Background daemon thread
# ==============================================================================

class ExpiryMonitor:
    """Background daemon thread that checks for expired temporary rules.

    Runs every 30 seconds (configurable) while the interactive menu is
    active. Auto-deactivates expired rules and prints terminal alerts
    for rules within 10 minutes of expiring.

    The daemon thread auto-terminates when the main process exits
    (daemon=True). Clean shutdown via stop() or cleanup stack.

    Usage:
        monitor = ExpiryMonitor()
        monitor.start()
        # ... interactive menu loop ...
        monitor.stop()
    """

    def __init__(
        self,
        check_interval: int = Performance.EXPIRY_CHECK_INTERVAL,
    ) -> None:
        self._stop_event: threading.Event = threading.Event()
        self._thread: threading.Thread | None = None
        self._interval: int = check_interval

    def start(self) -> None:
        """Start the expiry monitor daemon thread.

        Double-start guard: subsequent calls are no-ops if already running.
        """
        if self._thread is not None and self._thread.is_alive():
            return  # Already running

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop,
            daemon=True,
            name="expiry-monitor",
        )
        self._thread.start()
        _log("debug", "Expiry monitor started")

    def stop(self) -> None:
        """Stop the expiry monitor daemon thread.

        Signals the thread to stop and waits up to 5 seconds for it
        to finish. Safe to call multiple times.
        """
        self._stop_event.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=5)
        self._thread = None
        _log("debug", "Expiry monitor stopped")

    def _loop(self) -> None:
        """Main monitor loop — runs until stop_event is set."""
        while not self._stop_event.wait(self._interval):
            self._check()

    def _check(self) -> None:
        """Check for expired rules and print near-expiry alerts."""
        try:
            from apotropaios.rules.engine import rule_check_expired
            expired = rule_check_expired()
            if expired > 0:
                sys.stderr.write(
                    f"\n{Color.RED}  ⚠ {expired} rule(s) expired and auto-deactivated"
                    f"{Color.RESET}\n"
                )
        except Exception:
            pass

        # Print near-expiry alerts
        try:
            from apotropaios.rules.state import rule_state
            expiring = rule_state.get_expiring_soon(600)  # 10 minutes
            for rule_id, remaining in expiring:
                if remaining > 1800:
                    color = Color.GREEN
                elif remaining > 600:
                    color = Color.YELLOW
                else:
                    color = Color.RED
                mins = remaining // 60
                secs = remaining % 60
                sys.stderr.write(
                    f"  {color}⏱ Rule {rule_id[:8]}... expires in "
                    f"{mins}m {secs}s{Color.RESET}\n"
                )
        except Exception:
            pass


# Module-level singleton
_monitor: Final[ExpiryMonitor] = ExpiryMonitor()


# ==============================================================================
# Cancel-Aware Input Helper
# ==============================================================================

def _read_input(prompt: str) -> str | None:
    """Read user input with cancel keyword detection.

    All prompts go to stderr (Lesson #12). Cancel keywords (q, quit,
    cancel, back, b) return None to signal abort.

    Args:
        prompt: Prompt text to display.

    Returns:
        User input string, or None if cancelled.
    """
    sys.stderr.write(f"{Color.CYAN}{prompt}{Color.RESET}")
    sys.stderr.flush()
    try:
        value = input().strip()
    except (EOFError, KeyboardInterrupt):
        return None

    if is_cancel_keyword(value):
        return None

    return value


def _read_choice(prompt: str, max_choice: int) -> int | None:
    """Read a numeric menu choice.

    Args:
        prompt:     Prompt text.
        max_choice: Maximum valid choice number.

    Returns:
        Choice as integer (1-based), or None if cancelled/invalid.
    """
    value = _read_input(prompt)
    if value is None:
        return None
    try:
        choice = int(value)
        if 1 <= choice <= max_choice:
            return choice
    except ValueError:
        pass
    return None


# ==============================================================================
# Main Menu
# ==============================================================================

def menu_main(logger: object | None = None) -> None:
    """Launch the interactive menu-driven interface.

    Starts the expiry monitor, renders the main menu in a loop,
    dispatches to category handlers, and performs clean shutdown on exit.

    Args:
        logger: Optional FrameworkLogger instance.
    """
    global _log_fn
    _log_fn = logger

    _log("info", "Launching interactive menu")

    # Start expiry monitor and register with cleanup stack
    _monitor.start()
    cleanup_stack.register(_monitor.stop, "expiry_monitor_stop")

    try:
        while True:
            _render_main_menu()

            choice = _read_choice("\n  Select option [1-8]: ", 8)

            if choice is None:
                continue
            elif choice == 1:
                _menu_firewall_management()
            elif choice == 2:
                _menu_rule_management()
            elif choice == 3:
                _menu_quick_actions()
            elif choice == 4:
                _menu_backup_recovery()
            elif choice == 5:
                _menu_system_info()
            elif choice == 6:
                _menu_install_update()
            elif choice == 7:
                _menu_help()
            elif choice == 8:
                _log("info", "User selected exit")
                break
    except KeyboardInterrupt:
        sys.stderr.write(f"\n{Color.YELLOW}Interrupt received.{Color.RESET}\n")
    finally:
        _monitor.stop()
        cleanup_stack.unregister(_monitor.stop)
        _log("info", "Interactive menu exited")


def _render_main_menu() -> None:
    """Render the main menu display."""
    print_banner()

    # Check for near-expiry rules and display inline alerts
    try:
        from apotropaios.rules.state import rule_state
        expiring = rule_state.get_expiring_soon(600)
        if expiring:
            sys.stderr.write(
                f"  {Color.YELLOW}⚠ {len(expiring)} rule(s) expiring within "
                f"10 minutes{Color.RESET}\n\n"
            )
    except Exception:
        pass

    sys.stderr.write(f"  {Color.BOLD}Main Menu{Color.RESET}\n")
    print_separator("─", 50)
    sys.stderr.write(
        f"  {Color.CYAN}1.{Color.RESET} Firewall Management\n"
        f"  {Color.CYAN}2.{Color.RESET} Rule Management\n"
        f"  {Color.CYAN}3.{Color.RESET} Quick Actions\n"
        f"  {Color.CYAN}4.{Color.RESET} Backup & Recovery\n"
        f"  {Color.CYAN}5.{Color.RESET} System Information\n"
        f"  {Color.CYAN}6.{Color.RESET} Install & Update\n"
        f"  {Color.CYAN}7.{Color.RESET} Help & Documentation\n"
        f"  {Color.CYAN}8.{Color.RESET} Exit\n"
    )


# ==============================================================================
# Category Menu Handlers
# ==============================================================================

def _menu_firewall_management() -> None:
    """Firewall Management submenu."""
    from apotropaios.firewall.common import (
        get_backend_name, get_registered_backends,
        set_backend, fw_enable, fw_disable,
        fw_list_rules,
    )
    from apotropaios.detection.fw_detect import detect_firewalls, FWBackendStatus

    while True:
        backend = get_backend_name() or "none"
        sys.stderr.write(f"\n  {Color.BOLD}Firewall Management{Color.RESET}\n")
        print_separator("─", 50)
        sys.stderr.write(
            f"  Current backend: {Color.GREEN}{backend}{Color.RESET}\n\n"
            f"  {Color.CYAN}1.{Color.RESET} Select backend\n"
            f"  {Color.CYAN}2.{Color.RESET} Show service status\n"
            f"  {Color.CYAN}3.{Color.RESET} Enable/start service\n"
            f"  {Color.CYAN}4.{Color.RESET} Disable/stop service\n"
            f"  {Color.CYAN}5.{Color.RESET} List system rules ({backend})\n"
            f"  {Color.CYAN}6.{Color.RESET} Reset firewall to defaults\n"
            f"  {Color.CYAN}7.{Color.RESET} Back to main menu\n"
        )

        choice = _read_choice("\n  Select [1-7]: ", 7)
        if choice is None or choice == 7:
            return

        if choice == 1:
            backends = get_registered_backends()
            sys.stderr.write(f"\n  Available backends: {', '.join(backends)}\n")
            name = _read_input("  Enter backend name: ")
            if name:
                try:
                    set_backend(name)
                    sys.stderr.write(f"  {Color.GREEN}Backend set to: {name}{Color.RESET}\n")
                except Exception as exc:
                    sys.stderr.write(f"  {Color.RED}{exc}{Color.RESET}\n")

        elif choice == 2:
            # Service STATUS (running/enabled/version), NOT raw rules
            try:
                fw_result = detect_firewalls()
                current = get_backend_name()
                sys.stderr.write(f"\n  {Color.BOLD}Service Status — {current}{Color.RESET}\n")
                print_separator("─", 50)
                bs = fw_result.backends.get(current)
                if isinstance(bs, FWBackendStatus) and bs.installed:
                    state_str = f"{Color.GREEN}running{Color.RESET}" if bs.running else f"{Color.RED}stopped{Color.RESET}"
                    enabled_str = f"{Color.GREEN}enabled{Color.RESET}" if bs.enabled else f"{Color.YELLOW}disabled{Color.RESET}"
                    sys.stderr.write(f"    Service State:  {state_str}\n")
                    sys.stderr.write(f"    Boot Enabled:   {enabled_str}\n")
                    sys.stderr.write(f"    Version:        {bs.version}\n")
                    sys.stderr.write(f"    Binary:         {bs.binary}\n")
                else:
                    sys.stderr.write(f"    {Color.YELLOW}Backend not installed or not detected{Color.RESET}\n")
            except Exception as exc:
                sys.stderr.write(f"  {Color.RED}{exc}{Color.RESET}\n")

        elif choice == 3:
            try:
                fw_enable()
                sys.stderr.write(f"  {Color.GREEN}Firewall enabled/started{Color.RESET}\n")
            except Exception as exc:
                sys.stderr.write(f"  {Color.RED}{exc}{Color.RESET}\n")

        elif choice == 4:
            try:
                fw_disable()
                sys.stderr.write(f"  {Color.GREEN}Firewall disabled/stopped{Color.RESET}\n")
            except Exception as exc:
                sys.stderr.write(f"  {Color.RED}{exc}{Color.RESET}\n")

        elif choice == 5:
            try:
                output = fw_list_rules()
                sys.stderr.write(f"\n  {Color.BOLD}System Rules ({backend}):{Color.RESET}\n")
                sys.stderr.write(f"{output}\n")
            except Exception as exc:
                sys.stderr.write(f"  {Color.RED}{exc}{Color.RESET}\n")

        elif choice == 6:
            confirm = _read_input(
                f"  {Color.RED}⚠ This will reset {backend} to defaults. Continue? [y/N]: {Color.RESET}"
            )
            if confirm and confirm.lower() in ("y", "yes"):
                try:
                    from apotropaios.firewall.common import fw_reset
                    fw_reset()
                    sys.stderr.write(f"  {Color.GREEN}Firewall reset complete{Color.RESET}\n")
                except Exception as exc:
                    sys.stderr.write(f"  {Color.RED}{exc}{Color.RESET}\n")


def _menu_rule_management() -> None:
    """Rule Management submenu."""
    from apotropaios.rules.index import rule_index
    from apotropaios.rules.engine import (
        rule_create, rule_remove, rule_activate, rule_deactivate,
    )
    from apotropaios.core.validation import validate_rule_id
    from apotropaios.firewall.common import get_backend_name, fw_list_rules

    while True:
        backend = get_backend_name() or "none"
        sys.stderr.write(f"\n  {Color.BOLD}Rule Management{Color.RESET}\n")
        print_separator("─", 50)
        sys.stderr.write(
            f"  {Color.CYAN}1.{Color.RESET} Create new rule (wizard)\n"
            f"  {Color.CYAN}2.{Color.RESET} List Apotropaios rules\n"
            f"  {Color.CYAN}3.{Color.RESET} List system rules — {backend}\n"
            f"  {Color.CYAN}4.{Color.RESET} Remove rule\n"
            f"  {Color.CYAN}5.{Color.RESET} Activate rule\n"
            f"  {Color.CYAN}6.{Color.RESET} Deactivate rule\n"
            f"  {Color.CYAN}7.{Color.RESET} Import rules\n"
            f"  {Color.CYAN}8.{Color.RESET} Export rules\n"
            f"  {Color.CYAN}9.{Color.RESET} Back to main menu\n"
        )

        choice = _read_choice("\n  Select [1-9]: ", 9)
        if choice is None or choice == 9:
            return

        if choice == 1:
            # Rule creation wizard
            params: dict[str, str] = {}
            for field, prompt_text, default in [
                ("direction", "Direction (inbound/outbound/forward)", "inbound"),
                ("protocol", "Protocol (tcp/udp/icmp/all)", "tcp"),
                ("dst_port", "Destination port (or empty)", ""),
                ("src_ip", "Source IP (or empty)", ""),
                ("action", "Action (accept/drop/reject/log,drop)", "accept"),
                ("duration_type", "Duration (permanent/temporary)", "permanent"),
                ("description", "Description", ""),
            ]:
                val = _read_input(f"  {prompt_text} [{default}]: ")
                if val is None:
                    sys.stderr.write(f"  {Color.YELLOW}Cancelled{Color.RESET}\n")
                    break
                params[field] = val if val else default
            else:
                # TTL prompt for temporary rules
                if params.get("duration_type") == "temporary":
                    ttl = _read_input("  TTL in seconds (60-2592000) [3600]: ")
                    if ttl is None:
                        sys.stderr.write(f"  {Color.YELLOW}Cancelled{Color.RESET}\n")
                        continue
                    params["ttl"] = ttl if ttl else "3600"
                try:
                    rule_id = rule_create(params)
                    sys.stderr.write(
                        f"  {Color.GREEN}Rule created: {rule_id}{Color.RESET}\n"
                    )
                except Exception as exc:
                    sys.stderr.write(f"  {Color.RED}Failed: {exc}{Color.RESET}\n")

        elif choice == 2:
            # List Apotropaios-tracked rules
            sys.stderr.write(rule_index.list_formatted() + "\n")

        elif choice == 3:
            # List native system rules for current backend
            try:
                output = fw_list_rules()
                sys.stderr.write(f"\n  {Color.BOLD}System Rules — {backend}:{Color.RESET}\n")
                sys.stderr.write(f"{output}\n")
            except Exception as exc:
                sys.stderr.write(f"  {Color.RED}{exc}{Color.RESET}\n")

        elif choice in (4, 5, 6):
            action_name = {4: "remove", 5: "activate", 6: "deactivate"}[choice]
            rid = _read_input(f"  Enter rule UUID to {action_name}: ")
            if rid is None:
                continue
            try:
                validate_rule_id(rid)
                if choice == 4:
                    rule_remove(rid)
                elif choice == 5:
                    rule_activate(rid)
                else:
                    rule_deactivate(rid)
                sys.stderr.write(f"  {Color.GREEN}Rule {action_name}d: {rid}{Color.RESET}\n")
            except Exception as exc:
                sys.stderr.write(f"  {Color.RED}{exc}{Color.RESET}\n")

        elif choice == 7:
            path = _read_input("  Import file path: ")
            if path:
                dry = _read_input("  Dry run? (y/n) [n]: ")
                dry_run = dry is not None and dry.lower() in ("y", "yes")
                try:
                    from apotropaios.rules.import_export import import_rules
                    ok, err, skip = import_rules(path, dry_run=dry_run)
                    prefix = "[DRY RUN] " if dry_run else ""
                    sys.stderr.write(
                        f"  {prefix}Import: {ok} success, {err} errors, {skip} skipped\n"
                    )
                except Exception as exc:
                    sys.stderr.write(f"  {Color.RED}{exc}{Color.RESET}\n")

        elif choice == 8:
            path = _read_input("  Export file path: ")
            if path:
                try:
                    from apotropaios.rules.import_export import export_rules
                    count = export_rules(path)
                    sys.stderr.write(f"  Exported {count} rules to {path}\n")
                except Exception as exc:
                    sys.stderr.write(f"  {Color.RED}{exc}{Color.RESET}\n")


def _menu_quick_actions() -> None:
    """Quick Actions submenu."""
    from apotropaios.rules.engine import rule_block_all, rule_allow_all
    from apotropaios.firewall.common import get_backend_name, fw_reset

    backend = get_backend_name() or "none"
    sys.stderr.write(f"\n  {Color.BOLD}Quick Actions{Color.RESET}  (backend: {backend})\n")
    print_separator("─", 50)
    sys.stderr.write(
        f"  {Color.CYAN}1.{Color.RESET} Block ALL traffic\n"
        f"  {Color.CYAN}2.{Color.RESET} Allow ALL traffic\n"
        f"  {Color.CYAN}3.{Color.RESET} Reset firewall to defaults\n"
        f"  {Color.CYAN}4.{Color.RESET} Back to main menu\n"
    )

    choice = _read_choice("\n  Select [1-4]: ", 4)
    if choice == 1:
        confirm = _read_input(
            f"  {Color.RED}⚠ BLOCK ALL traffic on {backend}. "
            f"This may disconnect SSH. Continue? [y/N]: {Color.RESET}"
        )
        if confirm and confirm.lower() in ("y", "yes"):
            try:
                rid = rule_block_all()
                sys.stderr.write(
                    f"  {Color.GREEN}All traffic blocked via {backend} "
                    f"(rule: {rid}){Color.RESET}\n"
                )
            except Exception as exc:
                sys.stderr.write(f"  {Color.RED}Failed: {exc}{Color.RESET}\n")
    elif choice == 2:
        confirm = _read_input(
            f"  {Color.YELLOW}⚠ ALLOW ALL traffic on {backend}. Continue? [y/N]: {Color.RESET}"
        )
        if confirm and confirm.lower() in ("y", "yes"):
            try:
                rid = rule_allow_all()
                sys.stderr.write(
                    f"  {Color.GREEN}All traffic allowed via {backend} "
                    f"(rule: {rid}){Color.RESET}\n"
                )
            except Exception as exc:
                sys.stderr.write(f"  {Color.RED}Failed: {exc}{Color.RESET}\n")
    elif choice == 3:
        confirm = _read_input(
            f"  {Color.RED}⚠ RESET {backend} to defaults. All rules will be flushed. "
            f"Continue? [y/N]: {Color.RESET}"
        )
        if confirm and confirm.lower() in ("y", "yes"):
            try:
                fw_reset()
                sys.stderr.write(
                    f"  {Color.GREEN}{backend} reset to defaults{Color.RESET}\n"
                )
            except Exception as exc:
                sys.stderr.write(f"  {Color.RED}Failed: {exc}{Color.RESET}\n")


def _menu_backup_recovery() -> None:
    """Backup & Recovery submenu."""
    from apotropaios.backup.backup import create_backup, list_backups
    from apotropaios.backup.restore import restore_backup
    from apotropaios.backup.immutable import (
        create_snapshot, verify_snapshots, list_snapshots,
    )

    while True:
        sys.stderr.write(f"\n  {Color.BOLD}Backup & Recovery{Color.RESET}\n")
        print_separator("─", 50)
        sys.stderr.write(
            f"  {Color.CYAN}1.{Color.RESET} Create backup\n"
            f"  {Color.CYAN}2.{Color.RESET} List backups\n"
            f"  {Color.CYAN}3.{Color.RESET} Restore from backup\n"
            f"  {Color.CYAN}4.{Color.RESET} Create immutable snapshot\n"
            f"  {Color.CYAN}5.{Color.RESET} Verify immutable snapshots\n"
            f"  {Color.CYAN}6.{Color.RESET} List immutable snapshots\n"
            f"  {Color.CYAN}7.{Color.RESET} Back to main menu\n"
        )

        choice = _read_choice("\n  Select [1-7]: ", 7)
        if choice is None or choice == 7:
            return

        if choice == 1:
            label = _read_input("  Backup label [manual]: ")
            try:
                bf = create_backup(label or "manual")
                sys.stderr.write(f"  {Color.GREEN}Backup created: {bf}{Color.RESET}\n")
            except Exception as exc:
                sys.stderr.write(f"  {Color.RED}{exc}{Color.RESET}\n")
        elif choice == 2:
            sys.stderr.write(list_backups() + "\n")
        elif choice == 3:
            path = _read_input("  Backup file path: ")
            if path:
                try:
                    restore_backup(path)
                    sys.stderr.write(f"  {Color.GREEN}Restore complete{Color.RESET}\n")
                except Exception as exc:
                    sys.stderr.write(f"  {Color.RED}{exc}{Color.RESET}\n")
        elif choice == 4:
            label = _read_input("  Snapshot label [snapshot]: ")
            try:
                from apotropaios.backup.backup import _backup_dir
                sf = create_snapshot(_backup_dir, label or "snapshot")
                sys.stderr.write(f"  {Color.GREEN}Snapshot created: {sf}{Color.RESET}\n")
            except Exception as exc:
                sys.stderr.write(f"  {Color.RED}{exc}{Color.RESET}\n")
        elif choice == 5:
            try:
                from apotropaios.backup.backup import _backup_dir
                rc = verify_snapshots(_backup_dir)
                if rc == 0:
                    sys.stderr.write(f"  {Color.GREEN}All snapshots verified{Color.RESET}\n")
                elif rc == 2:
                    sys.stderr.write(f"  {Color.YELLOW}No immutable snapshots exist{Color.RESET}\n")
                else:
                    sys.stderr.write(f"  {Color.RED}Integrity failure detected{Color.RESET}\n")
            except Exception as exc:
                sys.stderr.write(f"  {Color.RED}{exc}{Color.RESET}\n")
        elif choice == 6:
            try:
                from apotropaios.backup.backup import _backup_dir
                sys.stderr.write(list_snapshots(_backup_dir) + "\n")
            except Exception as exc:
                sys.stderr.write(f"  {Color.RED}{exc}{Color.RESET}\n")


def _menu_system_info() -> None:
    """System Information submenu — full OS and firewall detection details."""
    from apotropaios.detection.os_detect import detect_os
    from apotropaios.detection.fw_detect import detect_firewalls
    from apotropaios.firewall.common import get_backend_name
    from apotropaios.rules.index import rule_index

    sys.stderr.write(f"\n  {Color.BOLD}System Information{Color.RESET}\n")
    print_separator("─", 60)
    sys.stderr.write(f"  Framework: Apotropaios v{VERSION}\n\n")

    # OS Detection
    sys.stderr.write(f"  {Color.BOLD}Operating System:{Color.RESET}\n")
    try:
        os_result = detect_os()
        sys.stderr.write(f"    Name:          {os_result.name or 'unknown'}\n")
        sys.stderr.write(f"    ID:            {os_result.os_id or 'unknown'}\n")
        sys.stderr.write(f"    Version:       {os_result.version}\n")
        sys.stderr.write(f"    Family:        {os_result.family}\n")
        sys.stderr.write(f"    Pkg Manager:   {os_result.pkg_manager}\n")
        sys.stderr.write(f"    Supported:     {'yes' if os_result.supported else 'no'}\n")
        sys.stderr.write(f"    Method:        {os_result.method}\n")
    except Exception as exc:
        sys.stderr.write(f"    {Color.RED}Detection failed: {exc}{Color.RESET}\n")

    # Firewall Detection
    sys.stderr.write(f"\n  {Color.BOLD}Firewall Backends:{Color.RESET}\n")
    try:
        fw_result = detect_firewalls()
        for fw_id in sorted(fw_result.backends.keys()):
            bs = fw_result.backends[fw_id]
            if bs.installed:
                state = f"{Color.GREEN}running{Color.RESET}" if bs.running else f"{Color.RED}stopped{Color.RESET}"
                enabled = f"{Color.GREEN}enabled{Color.RESET}" if bs.enabled else f"{Color.YELLOW}disabled{Color.RESET}"
                sys.stderr.write(
                    f"    {fw_id:<12s} v{bs.version:<10s} {state}  {enabled}  {bs.binary}\n"
                )
            else:
                sys.stderr.write(f"    {fw_id:<12s} {Color.DIM}not installed{Color.RESET}\n")
        sys.stderr.write(f"\n    Total installed: {fw_result.count}\n")
    except Exception as exc:
        sys.stderr.write(f"    {Color.RED}Detection failed: {exc}{Color.RESET}\n")

    # Active backend
    backend = get_backend_name()
    sys.stderr.write(f"\n  {Color.BOLD}Active Backend:{Color.RESET} {Color.GREEN}{backend or 'none'}{Color.RESET}\n")

    # Rule summary
    tracked = rule_index.count() if rule_index.initialized else 0
    sys.stderr.write(f"  {Color.BOLD}Tracked Rules:{Color.RESET}  {tracked}\n\n")

    _read_input("  Press Enter to return...")


def _menu_install_update() -> None:
    """Install & Update submenu."""
    from apotropaios.install.installer import install_firewall, update_firewall

    while True:
        sys.stderr.write(f"\n  {Color.BOLD}Install & Update{Color.RESET}\n")
        print_separator("─", 50)
        sys.stderr.write(
            f"  {Color.CYAN}1.{Color.RESET} Install firewall\n"
            f"  {Color.CYAN}2.{Color.RESET} Update firewall\n"
            f"  {Color.CYAN}3.{Color.RESET} Back to main menu\n"
        )

        choice = _read_choice("\n  Select [1-3]: ", 3)
        if choice is None or choice == 3:
            return

        fw = _read_input("  Firewall name (iptables/nftables/firewalld/ufw/ipset): ")
        if not fw:
            continue

        try:
            if choice == 1:
                install_firewall(fw)
                sys.stderr.write(f"  {Color.GREEN}{fw} installed{Color.RESET}\n")
            else:
                update_firewall(fw)
                sys.stderr.write(f"  {Color.GREEN}{fw} updated{Color.RESET}\n")
        except Exception as exc:
            sys.stderr.write(f"  {Color.RED}{exc}{Color.RESET}\n")


def _menu_help() -> None:
    """Help & Documentation submenu with per-command help access."""
    from apotropaios.menu.help_system import help_dispatch

    while True:
        sys.stderr.write(f"\n  {Color.BOLD}Help & Documentation{Color.RESET}\n")
        print_separator("─", 50)
        sys.stderr.write(
            f"  {Color.CYAN}1.{Color.RESET}  General usage overview\n"
            f"  {Color.CYAN}2.{Color.RESET}  Rule management help (add-rule, remove-rule, etc.)\n"
            f"  {Color.CYAN}3.{Color.RESET}  Backup & recovery help\n"
            f"  {Color.CYAN}4.{Color.RESET}  Import / export help\n"
            f"  {Color.CYAN}5.{Color.RESET}  Firewall detection help\n"
            f"  {Color.CYAN}6.{Color.RESET}  Install & update help\n"
            f"  {Color.CYAN}7.{Color.RESET}  All commands reference\n"
            f"  {Color.CYAN}8.{Color.RESET}  Back to main menu\n"
        )

        choice = _read_choice("\n  Select [1-8]: ", 8)
        if choice is None or choice == 8:
            return

        if choice == 1:
            sys.stderr.write(f"\n  {Color.BOLD}General Usage{Color.RESET}\n")
            print_separator("─", 60)
            sys.stderr.write(
                f"\n  Apotropaios operates in two modes:\n\n"
                f"    {Color.CYAN}Interactive:{Color.RESET}  sudo python3 apotropaios.py --interactive\n"
                f"    {Color.CYAN}CLI:{Color.RESET}          sudo python3 apotropaios.py COMMAND [OPTIONS]\n\n"
                f"  All firewall operations require root (sudo).\n"
                f"  Every command supports --help for detailed options:\n"
                f"    python3 apotropaios.py add-rule --help\n\n"
                f"  Cancel any interactive prompt with: q, quit, cancel, back, b\n\n"
                f"  Rule lifecycle: create → active → deactivate → re-activate → remove\n"
                f"  Temporary rules auto-expire after the configured TTL.\n\n"
            )

        elif choice == 2:
            sys.stderr.write(f"\n  {Color.BOLD}Rule Management Commands:{Color.RESET}\n")
            for cmd in ("add-rule", "remove-rule", "activate-rule", "deactivate-rule",
                        "list-rules", "system-rules"):
                sys.stderr.write(f"\n  {'─' * 60}\n")
                help_dispatch(cmd)

        elif choice == 3:
            sys.stderr.write(f"\n  {Color.BOLD}Backup & Recovery Commands:{Color.RESET}\n")
            for cmd in ("backup", "restore"):
                sys.stderr.write(f"\n  {'─' * 60}\n")
                help_dispatch(cmd)

        elif choice == 4:
            sys.stderr.write(f"\n  {Color.BOLD}Import / Export Commands:{Color.RESET}\n")
            for cmd in ("import", "export"):
                sys.stderr.write(f"\n  {'─' * 60}\n")
                help_dispatch(cmd)

        elif choice == 5:
            sys.stderr.write(f"\n  {Color.BOLD}Detection Commands:{Color.RESET}\n")
            for cmd in ("detect", "status"):
                sys.stderr.write(f"\n  {'─' * 60}\n")
                help_dispatch(cmd)

        elif choice == 6:
            sys.stderr.write(f"\n  {Color.BOLD}Install & Update Commands:{Color.RESET}\n")
            for cmd in ("install", "update"):
                sys.stderr.write(f"\n  {'─' * 60}\n")
                help_dispatch(cmd)

        elif choice == 7:
            sys.stderr.write(f"\n  {Color.BOLD}All Commands Reference:{Color.RESET}\n")
            for cmd in ("detect", "status", "add-rule", "remove-rule", "activate-rule",
                        "deactivate-rule", "list-rules", "system-rules", "block-all",
                        "allow-all", "import", "export", "backup", "restore",
                        "install", "update"):
                sys.stderr.write(f"\n  {'─' * 60}\n")
                help_dispatch(cmd)
