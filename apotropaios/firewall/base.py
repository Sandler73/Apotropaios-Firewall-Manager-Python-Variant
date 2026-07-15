# ==============================================================================
# File:         apotropaios/firewall/base.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Abstract firewall backend interface
# Description:  Defines the abstract base class (ABC) that all firewall backends
#               must implement. Provides a uniform API for rule management,
#               firewall control, and configuration persistence across all 5
#               supported backends: iptables, nftables, firewalld, ufw, ipset.
#
#               Every backend implements these operations:
#               - add_rule / remove_rule: Rule lifecycle
#               - list_rules: Display current rules
#               - enable / disable: Start/stop the firewall service
#               - status: Show current firewall state
#               - block_all / allow_all: Emergency traffic control
#               - reset: Restore default configuration
#               - save / load: Configuration persistence
#
# Notes:        - Uses Python's abc module for strict interface enforcement
#               - Rule parameters passed as dict[str, str] for flexibility
#               - All methods that interact with the system require root
#               - Backends must capture stderr on subprocess calls (Lesson #3)
#               - Parity target: bash v1.1.10 backend function signatures
# Version:      1.2.1
# ==============================================================================

from __future__ import annotations

from abc import ABC, abstractmethod


class FirewallBackend(ABC):
    """Abstract base class for firewall backend implementations.

    Each backend (iptables, nftables, firewalld, ufw, ipset) must
    subclass this and implement all abstract methods. The common.py
    dispatch layer calls these methods via the unified interface.

    Rule parameters are passed as a dictionary with string keys and
    values. Common keys include: direction, protocol, src_ip, dst_ip,
    src_port, dst_port, action, chain, table, interface, comment,
    conn_state, log_prefix, log_level, limit, limit_burst, zone.

    All methods that modify firewall state require root privileges.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the canonical backend name (e.g., 'iptables').

        Returns:
            Backend identifier string matching constants.SUPPORTED_FW_IDS.
        """
        ...

    @abstractmethod
    def add_rule(self, rule: dict[str, str]) -> bool:
        """Add a firewall rule.

        Supports compound actions (e.g., 'log,drop') by creating
        separate rules for non-terminal and terminal actions where
        required by the backend.

        Args:
            rule: Dictionary of rule parameters. Keys vary by backend
                  but typically include: direction, protocol, src_ip,
                  dst_ip, src_port, dst_port, action, comment.

        Returns:
            True if the rule was successfully applied.

        Raises:
            RuleApplyError: If the rule cannot be applied.
        """
        ...

    @abstractmethod
    def remove_rule(self, rule: dict[str, str]) -> bool:
        """Remove a firewall rule.

        For compound actions, must remove all component rules (e.g.,
        both the LOG rule and the terminal rule for iptables).
        Re-validates stored parameters before constructing removal commands.

        Args:
            rule: Dictionary of rule parameters (same format as add_rule).

        Returns:
            True if the rule was successfully removed.

        Raises:
            RuleRemoveError: If the rule cannot be removed.
        """
        ...

    @abstractmethod
    def list_rules(self, **kwargs: str) -> str:
        """List current firewall rules.

        Args:
            **kwargs: Backend-specific options (e.g., table='filter',
                      chain='INPUT' for iptables).

        Returns:
            Formatted string of current rules.
        """
        ...

    @abstractmethod
    def enable(self) -> bool:
        """Enable/start the firewall service.

        Returns:
            True if successfully enabled.
        """
        ...

    @abstractmethod
    def disable(self) -> bool:
        """Disable/stop the firewall service.

        Returns:
            True if successfully disabled.
        """
        ...

    @abstractmethod
    def status(self) -> str:
        """Get current firewall status.

        Returns:
            Formatted status string for display.
        """
        ...

    @abstractmethod
    def block_all(self) -> bool:
        """Block all inbound and outbound traffic.

        Should preserve loopback interface access.

        Returns:
            True if traffic was successfully blocked.
        """
        ...

    @abstractmethod
    def allow_all(self) -> bool:
        """Allow all traffic (remove all restrictions).

        Returns:
            True if restrictions were successfully removed.
        """
        ...

    @abstractmethod
    def reset(self) -> bool:
        """Reset firewall to default configuration.

        Flushes all rules and restores default policies.

        Returns:
            True if reset was successful.
        """
        ...

    @abstractmethod
    def save(self, path: str = "") -> bool:
        """Save current firewall configuration to file.

        Args:
            path: Output file path. Backend uses default if empty.

        Returns:
            True if configuration was saved successfully.
        """
        ...

    @abstractmethod
    def load(self, path: str) -> bool:
        """Load firewall configuration from file.

        Args:
            path: Input file path containing saved configuration.

        Returns:
            True if configuration was loaded successfully.
        """
        ...
