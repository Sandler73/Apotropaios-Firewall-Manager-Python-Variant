# ==============================================================================
# File:         apotropaios/firewall/common.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Backend registry and unified dispatch layer
# Description:  Registry and dispatch layer for firewall backend
#               implementations, providing a unified dispatch interface. All
#               firewall operations go through this module, which routes each
#               call to the currently active backend.
#
#               The registry pattern replaces bash's function-name-based dispatch
#               (fw_${backend}_${operation}) with a proper object registry:
#               backends register themselves, and dispatch calls the active
#               backend's ABC method directly.
#
# Notes:        - Backends register via register_backend() at import time
#               - Only one backend is active at a time (set via set_backend)
#               - All operations validate backend availability before dispatch
#               - Parity target: bash v1.1.10 lib/firewall/common.sh
# Version:      1.2.1
# ==============================================================================

from __future__ import annotations

from apotropaios.core.constants import (
    SUPPORTED_FW_IDS,
)
from apotropaios.core.errors import (
    FirewallNotFoundError,
)
from apotropaios.firewall.base import FirewallBackend


# ==============================================================================
# Backend Registry
# ==============================================================================

# Registry of backend instances, keyed by fw_id
_registry: dict[str, FirewallBackend] = {}

# Currently active backend
_active_backend: FirewallBackend | None = None
_active_backend_name: str = ""

# Logger reference
_log_fn: object | None = None


def set_logger(logger: object) -> None:
    """Set the logger for the dispatch layer.

    Args:
        logger: FrameworkLogger instance.
    """
    global _log_fn
    _log_fn = logger


def _log(level: str, msg: str) -> None:
    """Emit a log message if logger is available."""
    if _log_fn is not None:
        method = getattr(_log_fn, level, None)
        if method is not None:
            method("fw_common", msg)


# ==============================================================================
# Registration
# ==============================================================================

def register_backend(backend: FirewallBackend) -> None:
    """Register a firewall backend implementation.

    Called at import time by each backend module. The backend's name
    property must match a value in SUPPORTED_FW_IDS.

    Args:
        backend: FirewallBackend subclass instance.

    Raises:
        ValueError: If the backend name is not in SUPPORTED_FW_IDS.
    """
    name = backend.name
    if name not in SUPPORTED_FW_IDS:
        raise ValueError(
            f"Unknown backend name: {name!r}. "
            f"Must be one of: {', '.join(sorted(SUPPORTED_FW_IDS))}"
        )
    _registry[name] = backend
    _log("debug", f"Backend registered: {name}")


def get_registered_backends() -> list[str]:
    """Return list of registered backend names.

    Returns:
        Sorted list of fw_id strings for registered backends.
    """
    return sorted(_registry.keys())


# ==============================================================================
# Backend Selection
# ==============================================================================

def set_backend(name: str) -> None:
    """Set the active firewall backend for operations.

    The backend must be registered (imported) before it can be activated.

    Args:
        name: Backend identifier (e.g., 'iptables', 'firewalld').

    Raises:
        FirewallNotFoundError: If the backend is not registered.
    """
    global _active_backend, _active_backend_name

    if name not in SUPPORTED_FW_IDS:
        raise FirewallNotFoundError(
            f"Unknown firewall backend: {name}",
            backend=name,
        )

    backend = _registry.get(name)
    if backend is None:
        raise FirewallNotFoundError(
            f"Firewall backend not registered: {name}. "
            f"Registered backends: {', '.join(get_registered_backends()) or 'none'}",
            backend=name,
        )

    _active_backend = backend
    _active_backend_name = name
    _log("info", f"Active firewall backend set to: {name}")


def get_backend() -> FirewallBackend | None:
    """Return the currently active backend instance.

    Returns:
        Active FirewallBackend, or None if no backend is set.
    """
    return _active_backend


def get_backend_name() -> str:
    """Return the name of the currently active backend.

    Returns:
        Backend identifier string, or empty string if none set.
    """
    return _active_backend_name


def require_backend() -> FirewallBackend:
    """Assert that a backend is selected and return it.

    Returns:
        The active FirewallBackend instance.

    Raises:
        FirewallNotFoundError: If no backend is set.
    """
    if _active_backend is None:
        raise FirewallNotFoundError(
            "No firewall backend selected. "
            "Use --backend NAME or let auto-detection select one."
        )
    return _active_backend


# ==============================================================================
# Unified Dispatch Functions
#
# These provide a clean API for the rest of the framework. Each function
# delegates to the active backend's corresponding method.
# ==============================================================================

def fw_add_rule(rule: dict[str, str]) -> bool:
    """Add a firewall rule via the active backend.

    Args:
        rule: Rule parameters dictionary.

    Returns:
        True on success.

    Raises:
        FirewallNotFoundError: If no backend is set.
        RuleApplyError: If the rule cannot be applied.
    """
    backend = require_backend()
    _log("debug", f"Dispatching add_rule to {backend.name}")
    return backend.add_rule(rule)


def fw_remove_rule(rule: dict[str, str]) -> bool:
    """Remove a firewall rule via the active backend.

    Args:
        rule: Rule parameters dictionary.

    Returns:
        True on success.

    Raises:
        FirewallNotFoundError: If no backend is set.
        RuleRemoveError: If the rule cannot be removed.
    """
    backend = require_backend()
    _log("debug", f"Dispatching remove_rule to {backend.name}")
    return backend.remove_rule(rule)


def fw_list_rules(**kwargs: str) -> str:
    """List current firewall rules via the active backend.

    Args:
        **kwargs: Backend-specific options.

    Returns:
        Formatted rules string.
    """
    backend = require_backend()
    return backend.list_rules(**kwargs)


def fw_enable() -> bool:
    """Enable the firewall via the active backend."""
    backend = require_backend()
    return backend.enable()


def fw_disable() -> bool:
    """Disable the firewall via the active backend."""
    backend = require_backend()
    return backend.disable()


def fw_status() -> str:
    """Get firewall status via the active backend."""
    backend = require_backend()
    return backend.status()


def fw_block_all() -> bool:
    """Block all traffic via the active backend."""
    backend = require_backend()
    _log("warning", f"Dispatching block_all to {backend.name}")
    return backend.block_all()


def fw_allow_all() -> bool:
    """Allow all traffic via the active backend."""
    backend = require_backend()
    _log("warning", f"Dispatching allow_all to {backend.name}")
    return backend.allow_all()


def fw_reset() -> bool:
    """Reset firewall to defaults via the active backend."""
    backend = require_backend()
    _log("warning", f"Dispatching reset to {backend.name}")
    return backend.reset()


def fw_save(path: str = "") -> bool:
    """Save firewall configuration via the active backend."""
    backend = require_backend()
    return backend.save(path)


def fw_load(path: str) -> bool:
    """Load firewall configuration via the active backend."""
    backend = require_backend()
    return backend.load(path)
