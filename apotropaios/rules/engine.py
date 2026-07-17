# ==============================================================================
# File:         apotropaios/rules/engine.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Rule creation, application, removal, and lifecycle management
# Description:  Orchestrates the complete firewall rule lifecycle:
#               1. Validates all parameters at the engine layer
#               2. Generates unique UUID for tracking
#               3. Dispatches to the appropriate backend for application
#               4. Records in the rule index and state tracker
#               5. Supports deactivation (keep in index) and re-activation
#               6. Handles block-all/allow-all as tracked special rules
#               7. Checks and processes expired temporary rules
#
# Notes:        - Validates at UI boundary before engine (Lesson #4)
#               - UUID tracking via apotropaios:<uuid> comment field
#               - Backend-agnostic: delegates all FW operations to common.py
#               - Thread-safe: index and state singletons handle locking
#               - Parity target: bash v1.1.10 lib/rules/rule_engine.sh
# Version:      1.6.2
# ==============================================================================

from __future__ import annotations

import time
from datetime import datetime, timezone
from apotropaios.core.errors import (
    RuleApplyError,
    RuleInvalidError,
)
from apotropaios.core.security import generate_uuid
from apotropaios.core.utils import timestamp
from apotropaios.core.validation import (
    validate_cidr,
    validate_conn_state,
    validate_description,
    validate_duration_type,
    validate_ip,
    validate_log_prefix,
    validate_numeric,
    validate_port,
    validate_port_range,
    validate_protocol,
    validate_rate_limit,
    validate_rule_action,
    validate_rule_direction,
    validate_rule_id,
    validate_syslog_level,
    validate_ttl,
)
from apotropaios.firewall.common import (
    fw_add_rule,
    fw_allow_all,
    fw_block_all,
    fw_remove_rule,
    get_backend_name,
    require_backend,
    set_backend,
)
from apotropaios.rules.index import rule_index
from apotropaios.rules.state import rule_state

_log_fn: object | None = None


def set_logger(logger: object) -> None:
    """Set the logger for the rule engine."""
    global _log_fn
    _log_fn = logger


def _log(level: str, msg: str, extra: str = "") -> None:
    if _log_fn is not None:
        method = getattr(_log_fn, level, None)
        if method is not None:
            method("rule_engine", msg, extra)


# ==============================================================================
# Rule Creation
# ==============================================================================

def rule_create(params: dict[str, str]) -> str:
    """Create and apply a firewall rule.

    Validates all parameters, generates a UUID, applies via the active
    backend, and records in the rule index and state tracker.

    Args:
        params: Rule parameters dictionary. Common keys:
                direction, protocol, src_ip, dst_ip, src_port, dst_port,
                action, duration_type, ttl, description, zone, chain,
                table, table_family, interface, conn_state, log_prefix,
                log_level, limit, limit_burst, set_name, set_type, entry.

    Returns:
        The UUID of the newly created rule.

    Raises:
        RuleInvalidError: If parameter validation fails.
        RuleApplyError: If the backend fails to apply the rule.
    """
    _log("info", "Creating new firewall rule")

    # Extract and normalize core params
    direction = params.get("direction", "inbound")
    action = params.get("action", "accept").lower().replace(" ", "")
    params["action"] = action
    backend = params.get("backend", get_backend_name())
    duration_type = params.get("duration_type", "permanent")
    ttl = params.get("ttl", "0")
    description = params.get("description", "")

    # --- Validate core parameters ---
    try:
        validate_rule_direction(direction)
    except Exception as exc:
        raise RuleInvalidError(f"Invalid direction: {direction}") from exc

    try:
        validate_rule_action(action)
    except Exception as exc:
        raise RuleInvalidError(f"Invalid action: {action}") from exc

    try:
        validate_duration_type(duration_type)
    except Exception as exc:
        raise RuleInvalidError(f"Invalid duration type: {duration_type}") from exc

    if duration_type == "temporary":
        try:
            validate_ttl(ttl)
        except Exception as exc:
            raise RuleInvalidError(f"Invalid TTL: {ttl}") from exc

    # --- Validate optional parameters ---
    protocol = params.get("protocol", "")
    if protocol:
        try:
            validate_protocol(protocol)
        except Exception as exc:
            raise RuleInvalidError(f"Invalid protocol: {protocol}") from exc

    for ip_field in ("src_ip", "dst_ip"):
        ip_val = params.get(ip_field, "")
        if ip_val:
            try:
                validate_ip(ip_val)
            except Exception:
                try:
                    validate_cidr(ip_val)
                except Exception as exc:
                    raise RuleInvalidError(f"Invalid {ip_field}: {ip_val}") from exc

    for port_field in ("src_port", "dst_port"):
        port_val = params.get(port_field, "")
        if port_val:
            try:
                validate_port(port_val)
            except Exception:
                try:
                    validate_port_range(port_val)
                except Exception as exc:
                    raise RuleInvalidError(f"Invalid {port_field}: {port_val}") from exc

    if params.get("conn_state", ""):
        try:
            validate_conn_state(params["conn_state"])
        except Exception as exc:
            raise RuleInvalidError(f"Invalid conn_state: {params['conn_state']}") from exc

    if params.get("log_prefix", ""):
        try:
            validate_log_prefix(params["log_prefix"])
        except Exception as exc:
            raise RuleInvalidError(f"Invalid log_prefix: {params['log_prefix']}") from exc

    if params.get("limit", ""):
        try:
            validate_rate_limit(params["limit"])
        except Exception as exc:
            raise RuleInvalidError(f"Invalid rate limit: {params['limit']}") from exc

    if params.get("limit_burst", ""):
        try:
            validate_numeric(params["limit_burst"])
        except Exception as exc:
            raise RuleInvalidError(f"Invalid limit_burst (must be numeric): {params['limit_burst']}") from exc

    if params.get("log_level", ""):
        try:
            validate_syslog_level(params["log_level"])
        except Exception as exc:
            raise RuleInvalidError(f"Invalid syslog log_level: {params['log_level']}") from exc

    if description:
        validate_description(description)

    # --- Generate UUID and tracking comment ---
    rule_id = generate_uuid()
    _log("debug", f"Generated rule ID: {rule_id}")

    params["comment"] = f"apotropaios:{rule_id}"

    # --- Switch backend if specified (restored after application, matching
    # the removal/deactivation/activation session semantics) ---
    original_backend = get_backend_name()
    switched = False
    if backend and backend != original_backend:
        set_backend(backend)
        switched = True

    # --- Apply via backend ---
    _log("info", f"Applying rule {rule_id} via {get_backend_name()}", f"action={action} direction={direction}")
    try:
        fw_add_rule(params)
    except Exception as exc:
        _log("error", f"Failed to apply rule {rule_id}: {exc}")
        if switched and original_backend:
            try:
                set_backend(original_backend)
            except Exception:
                pass
        raise RuleApplyError(f"Failed to apply rule: {exc}") from exc

    # --- Record in index ---
    ts = timestamp()
    ttl_int = int(ttl) if ttl.isascii() and ttl.isdigit() else 0

    record: dict[str, str] = {
        "rule_id": rule_id,
        "backend": get_backend_name(),
        "direction": direction,
        "action": action,
        "protocol": params.get("protocol", ""),
        "src_ip": params.get("src_ip", ""),
        "dst_ip": params.get("dst_ip", ""),
        "src_port": params.get("src_port", ""),
        "dst_port": params.get("dst_port", ""),
        "interface": params.get("interface", ""),
        "chain": params.get("chain", ""),
        "table": params.get("table", ""),
        "table_family": params.get("table_family", ""),
        "zone": params.get("zone", ""),
        "set_name": params.get("set_name", ""),
        "conn_state": params.get("conn_state", ""),
        "log_prefix": params.get("log_prefix", ""),
        "log_level": params.get("log_level", ""),
        "limit": params.get("limit", ""),
        "limit_burst": params.get("limit_burst", ""),
        "duration_type": duration_type,
        "ttl": ttl,
        "description": description,
        "state": "active",
        "created_at": ts,
        "activated_at": ts,
        "expires_at": "",
    }

    # Calculate expiry for temporary rules
    if duration_type == "temporary" and ttl_int > 0:
        expire_epoch = int(time.time()) + ttl_int
        expire_dt = datetime.fromtimestamp(expire_epoch, tz=timezone.utc)
        record["expires_at"] = expire_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        rule_index.add(record)
    except Exception as exc:
        _log("error", f"Failed to index rule {rule_id} -- rule was applied but not tracked: {exc}")

    # --- Update state tracking ---
    rule_state.set(rule_id, "active", duration_type, ttl_int)

    _log(
        "info",
        f"Rule created and applied: {rule_id}",
        f"backend={get_backend_name()} direction={direction} action={action}",
    )

    # Restore the session's original backend after a per-rule switch
    if switched and original_backend:
        try:
            set_backend(original_backend)
        except Exception:
            pass

    return rule_id


# ==============================================================================
# Rule Removal
# ==============================================================================

def rule_remove(rule_id: str, remove_from_backend: bool = True) -> None:
    """Remove a firewall rule by its UUID.

    Removes from both the backend and the rule index by default.

    Args:
        rule_id:             Rule UUID.
        remove_from_backend: If True, also remove from the firewall backend.

    Raises:
        RuleNotFoundError: If the rule is not in the index.
    """
    validate_rule_id(rule_id)

    record = rule_index.get(rule_id)

    if remove_from_backend and record.get("state") == "active":
        # Prepare removal params
        remove_params = dict(record)
        remove_params["comment"] = f"apotropaios:{rule_id}"

        backend = record.get("backend", get_backend_name())
        original = get_backend_name()
        switched = False
        if backend and backend != original:
            try:
                set_backend(backend)
                switched = True
            except Exception as exc:
                _log("warning", f"Cannot switch to backend {backend} for removal: {exc}")

        try:
            fw_remove_rule(remove_params)
        except Exception as exc:
            _log("warning", f"Backend removal may have partially failed: {exc}")

        if switched:
            try:
                set_backend(original)
            except Exception:
                pass

    # Remove from index and state
    rule_index.remove(rule_id)
    rule_state.remove(rule_id)

    _log("info", f"Rule removed: {rule_id}")


# ==============================================================================
# Rule Deactivation
# ==============================================================================

def rule_deactivate(rule_id: str) -> None:
    """Deactivate a rule: remove from backend but keep in index.

    Args:
        rule_id: Rule UUID.

    Raises:
        RuleNotFoundError: If the rule is not in the index.
    """
    validate_rule_id(rule_id)

    record = rule_index.get(rule_id)

    if record.get("state") == "inactive":
        _log("warning", f"Rule already inactive: {rule_id}")
        return

    # Remove from backend
    remove_params = dict(record)
    remove_params["comment"] = f"apotropaios:{rule_id}"

    backend = record.get("backend", get_backend_name())
    original = get_backend_name()
    switched = False
    if backend and backend != original:
        try:
            set_backend(backend)
            switched = True
        except Exception as exc:
            _log("warning", f"Cannot switch to backend {backend} for deactivation: {exc}")

    try:
        fw_remove_rule(remove_params)
    except Exception as exc:
        _log("warning", f"Backend deactivation may have partially failed: {exc}")

    if switched:
        try:
            set_backend(original)
        except Exception:
            pass

    # Update index and state -- preserve the rule's duration designation
    # and TTL so a temporary rule does not silently become permanent in
    # the state tracker when deactivated.
    rule_index.update_field(rule_id, "state", "inactive")
    duration_type = record.get("duration_type", "permanent")
    ttl_str = record.get("ttl", "0")
    ttl = int(ttl_str) if ttl_str.isascii() and ttl_str.isdigit() else 0
    rule_state.set(rule_id, "inactive", duration_type, ttl)

    _log("info", f"Rule deactivated: {rule_id}")


# ==============================================================================
# Rule Activation
# ==============================================================================

def rule_activate(rule_id: str) -> None:
    """Re-activate a previously deactivated rule.

    Args:
        rule_id: Rule UUID.

    Raises:
        RuleNotFoundError: If the rule is not in the index.
        RuleApplyError: If re-application fails.
    """
    validate_rule_id(rule_id)

    record = rule_index.get(rule_id)

    if record.get("state") == "active":
        _log("warning", f"Rule already active: {rule_id}")
        return

    # Re-apply via backend
    apply_params = dict(record)
    apply_params["comment"] = f"apotropaios:{rule_id}"

    backend = record.get("backend", get_backend_name())
    original = get_backend_name()
    switched = False
    if backend and backend != original:
        try:
            set_backend(backend)
            switched = True
        except Exception as exc:
            _log("warning", f"Cannot switch to backend {backend} for activation: {exc}")

    try:
        fw_add_rule(apply_params)
    except Exception as exc:
        if switched:
            try:
                set_backend(original)
            except Exception:
                pass
        raise RuleApplyError(f"Failed to re-activate rule {rule_id}: {exc}") from exc

    if switched:
        try:
            set_backend(original)
        except Exception:
            pass

    # Update index and state
    ts = timestamp()
    rule_index.update_field(rule_id, "state", "active")
    rule_index.update_field(rule_id, "activated_at", ts)

    duration_type = record.get("duration_type", "permanent")
    ttl_str = record.get("ttl", "0"); ttl = int(ttl_str) if ttl_str.isascii() and ttl_str.isdigit() else 0
    rule_state.set(rule_id, "active", duration_type, ttl)

    _log("info", f"Rule re-activated: {rule_id}")


# ==============================================================================
# Block / Allow All Traffic
# ==============================================================================

def rule_block_all() -> str:
    """Block all inbound and outbound traffic.

    Creates a tracked special rule in the index.

    Returns:
        UUID of the block-all rule.
    """
    require_backend()
    _log("warning", f"Blocking ALL traffic via {get_backend_name()}")

    fw_block_all()

    # Record as tracked rule
    rule_id = generate_uuid()
    ts = timestamp()
    record: dict[str, str] = {
        "rule_id": rule_id, "backend": get_backend_name(),
        "direction": "all", "action": "drop", "protocol": "all",
        "src_ip": "any", "dst_ip": "any", "src_port": "any", "dst_port": "any",
        "interface": "", "chain": "", "table": "", "table_family": "",
        "zone": "", "set_name": "", "conn_state": "", "log_prefix": "",
        "log_level": "", "limit": "", "limit_burst": "",
        "duration_type": "permanent", "ttl": "0",
        "description": "BLOCK ALL TRAFFIC", "state": "active",
        "created_at": ts, "activated_at": ts, "expires_at": "",
    }
    try:
        rule_index.add(record)
    except Exception as exc:
        _log("error", f"Failed to index block-all rule {rule_id} -- applied but not tracked: {exc}")

    _log("info", f"All traffic blocked (rule_id={rule_id})")
    return rule_id


def rule_allow_all() -> str:
    """Allow all inbound and outbound traffic.

    Returns:
        UUID of the allow-all rule.
    """
    require_backend()
    _log("warning", f"Allowing ALL traffic via {get_backend_name()}")

    fw_allow_all()

    rule_id = generate_uuid()
    ts = timestamp()
    record: dict[str, str] = {
        "rule_id": rule_id, "backend": get_backend_name(),
        "direction": "all", "action": "accept", "protocol": "all",
        "src_ip": "any", "dst_ip": "any", "src_port": "any", "dst_port": "any",
        "interface": "", "chain": "", "table": "", "table_family": "",
        "zone": "", "set_name": "", "conn_state": "", "log_prefix": "",
        "log_level": "", "limit": "", "limit_burst": "",
        "duration_type": "permanent", "ttl": "0",
        "description": "ALLOW ALL TRAFFIC", "state": "active",
        "created_at": ts, "activated_at": ts, "expires_at": "",
    }
    try:
        rule_index.add(record)
    except Exception as exc:
        _log("error", f"Failed to index allow-all rule {rule_id} -- applied but not tracked: {exc}")

    _log("info", f"All traffic allowed (rule_id={rule_id})")
    return rule_id


# ==============================================================================
# Expired Rule Processing
# ==============================================================================

def rule_check_expired() -> int:
    """Check for and auto-deactivate expired temporary rules.

    Returns:
        Number of expired rules processed.
    """
    from apotropaios.core.utils import parse_iso_timestamp

    expired_count = 0
    now = int(time.time())

    _log("debug", "Checking for expired temporary rules")

    for rule_id in rule_index.list_ids():
        try:
            record = rule_index.get(rule_id)
        except Exception:
            continue

        if record.get("duration_type") != "temporary":
            continue
        if record.get("state") != "active":
            continue

        expires_at = record.get("expires_at", "")
        if not expires_at:
            continue

        # Parse expiry timestamp
        try:
            expire_dt = parse_iso_timestamp(expires_at)
            if expire_dt is None:
                # Try as epoch
                expire_epoch = int(expires_at)
            else:
                expire_epoch = int(expire_dt.timestamp())
        except (ValueError, TypeError):
            continue

        if now >= expire_epoch:
            _log("info", f"Rule expired: {rule_id} (expired at {expires_at})")
            try:
                rule_deactivate(rule_id)
                rule_index.update_field(rule_id, "state", "expired")
                rule_state.set(rule_id, "expired", "temporary",
                               int(record.get("ttl", "0"))
                               if record.get("ttl", "0").isdigit() else 0)
                expired_count += 1
            except Exception as exc:
                _log("warning", f"Failed to process expired rule {rule_id}: {exc}")

    if expired_count > 0:
        _log("info", f"Processed {expired_count} expired rule(s)")

    return expired_count
