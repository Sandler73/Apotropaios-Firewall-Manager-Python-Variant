# Developer Guide — Exhaustive Code Component Catalog

Authoritative reference for every source file, class, function, and method in Apotropaios. Generated from AST analysis of actual source — all signatures and line counts verified.

**Codebase:** 35 Python files (27 production + 8 __init__.py) · 14,409 lines · mypy --strict: 0 errors · 230 tests

```
Layer 5 (UI):        cli.py (1,201), __main__.py (57), menu/main.py (790), menu/help_system.py (526)
Layer 4 (Engine):    rules/{engine(555),index(359),state(278),import_export(267)}, backup/{backup(309),restore(255),immutable(216)}, install/installer.py (252)
Layer 3 (Backends):  firewall/{base(190),common(279),iptables(695),nftables(476),firewalld(440),ufw(400),ipset(432)}
Layer 2 (Detection): detection/{os_detect(433),fw_detect(519)}
Layer 1 (Core):      core/{constants(737),errors(881),validation(1256),logging(727),security(678),utils(503)}
```


## Layer 1 — Core Infrastructure

### `apotropaios/core/constants.py` (746 lines)

Immutable constants, 27 ErrorCodes (IntEnum), 7 LogLevels, 8 RuleActions, 18 compiled regex patterns, frozensets, NamedTuples, Security/Performance/Backup config classes

#### class `DirPath`

Relative directory paths from the framework base directory.

#### class `FileName`

Standard file names used by the framework.

#### class `OSInfo`(NamedTuple)

Metadata for a supported operating system.

#### class `FirewallInfo`(NamedTuple)

Metadata for a supported firewall backend.

#### class `ErrorCode`(IntEnum)

Structured error codes for all framework operations.

#### class `LogLevel`(IntEnum)

Logging severity levels.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `from_string` | name | `LogLevel` | Parse a log level name (case-insensitive) to its enum member. |
| `to_stdlib_level` |  | `int` | Convert to Python stdlib logging numeric level. |

#### class `Pattern`

Precompiled regex patterns for input validation.

#### class `Security`

Security-related limits and permission masks.

#### class `RuleAction`(StrEnum)

Firewall rule actions.

#### class `RuleDirection`(StrEnum)

Packet direction for firewall rules.

#### class `RuleState`(StrEnum)

Rule lifecycle states in the index.

#### class `DurationType`(StrEnum)

Rule duration classification.

#### class `ConnState`(StrEnum)

Connection tracking states (netfilter conntrack/state module).

#### class `SyslogLevel`(StrEnum)

Syslog severity levels for firewall log actions.

#### class `TTLLimits`

Minimum and maximum TTL values for temporary rules.

#### class `Backup`

Backup and restore configuration constants.

#### class `Performance`

Performance tuning constants.

#### class `_Color`

ANSI terminal color codes with automatic TTY detection.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` |  | `None` |  |

---

### `apotropaios/core/errors.py` (911 lines)

25 exception classes (ApotropaiosError base), CleanupStack (LIFO, recursion guard, thread-safe), SignalHandler (SIGTERM→143, SIGINT→130, SIGHUP→129), retry with exponential backoff, ErrorContext

#### class `ApotropaiosError`(Exception)

Base exception for all Apotropaios framework errors.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | message, code, context | `None` |  |
| `_format_message` |  | `str` | Format the full error message including code and context. |

#### class `UsageError`(ApotropaiosError)

Invalid command-line usage or argument errors.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | message | `None` |  |

#### class `PermissionError_`(ApotropaiosError)

Insufficient privileges (e.g., not running as root).

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | message | `None` |  |

#### class `OSDetectionError`(ApotropaiosError)

Operating system not supported or detection failure.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | message | `None` |  |

#### class `FirewallError`(ApotropaiosError)

Base class for firewall backend errors.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | message, code | `None` |  |

#### class `FirewallNotFoundError`(FirewallError)

Requested firewall backend is not installed.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | message | `None` |  |

#### class `FirewallNotRunningError`(FirewallError)

Firewall backend is installed but not running.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | message | `None` |  |

#### class `FirewallInstallError`(FirewallError)

Firewall package installation or update failure.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | message | `None` |  |

#### class `RuleError`(ApotropaiosError)

Base class for rule engine errors.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | message, code | `None` |  |

#### class `RuleInvalidError`(RuleError)

Rule parameters fail validation.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | message | `None` |  |

#### class `RuleExistsError`(RuleError)

Duplicate rule already exists in the index.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | message | `None` |  |

#### class `RuleNotFoundError`(RuleError)

Rule ID not found in the index.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | message | `None` |  |

#### class `RuleApplyError`(RuleError)

Failed to apply rule to the firewall backend.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | message | `None` |  |

#### class `RuleRemoveError`(RuleError)

Failed to remove rule from the firewall backend.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | message | `None` |  |

#### class `RuleImportError`(RuleError)

Rule import from configuration file failed.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | message | `None` |  |

#### class `BackupError`(ApotropaiosError)

Backup creation failure.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | message | `None` |  |

#### class `RestoreError`(ApotropaiosError)

Backup restore failure.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | message | `None` |  |

#### class `BackupNotFoundError`(ApotropaiosError)

Requested backup archive not found.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | message | `None` |  |

#### class `ValidationError`(ApotropaiosError)

Input validation failure.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | message | `None` |  |

#### class `SanitizationError`(ApotropaiosError)

Input sanitization failure (dangerous characters detected).

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | message | `None` |  |

#### class `LoggingError`(ApotropaiosError)

Logging subsystem failure.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | message, code | `None` |  |

#### class `LockError`(ApotropaiosError)

File locking failure.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | message | `None` |  |

#### class `LockTimeoutError`(LockError)

File lock acquisition timed out.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | message | `None` |  |

#### class `IntegrityError`(ApotropaiosError)

Data integrity verification failure (checksum mismatch, etc.).

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | message | `None` |  |

#### class `SignalReceivedError`(ApotropaiosError)

Process received a termination signal.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | signal_name | `None` |  |

#### class `ErrorContext`

Tracks the most recent error context for debugging.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` |  | `None` |  |
| `record` | exc, function, line | `None` | Record an error context snapshot. |
| `get_formatted` |  | `str` | Return the last error context as a formatted string. |
| `clear` |  | `None` | Reset the error context to empty state. |

#### class `CleanupStack`

LIFO stack of cleanup functions executed on process exit or signal.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` |  | `None` |  |
| `set_logger` | log_fn | `None` | Set the logging function after the logging module initializes. |
| `_log` | level, message | `None` | Emit a log message if a logger is available. |
| `register` | func, description | `None` | Register a cleanup function to be called on exit. |
| `unregister` | func | `bool` | Remove the first occurrence of a cleanup function. |
| `execute_all` |  | `None` | Execute all registered cleanup functions in LIFO order. |
| `depth` |  | `int` | Current number of registered cleanup functions. |

#### class `SignalHandler`

OS signal handler that triggers cleanup stack execution on termination.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | stack | `None` |  |
| `set_logger` | log_fn | `None` | Set the logging function for signal events. |
| `_log` | level, message | `None` | Emit a log message if a logger is available. |
| `install` |  | `None` | Install signal handlers for SIGTERM, SIGINT, and SIGHUP. |
| `uninstall` |  | `None` | Restore original signal handlers. |
| `_handler` | signum, frame | `None` | Signal handler callback. |

| Function | Parameters | Returns | Description |
|:---------|:-----------|:--------|:------------|
| `_getpid` |  | `int` | Get current process ID (extracted for testability). |
| `retry` | func | `T` | Execute a function with retry logic and exponential backoff. |
| `with_fallback` | primary, fallback, context, log_fn | `T` | Execute a primary function; on failure, execute a fallback. |
| `die` | message, code, log_fn | `None` | Log a critical error and exit the process immediately. |
| `init_error_handling` | log_fn | `None` | Initialize the error handling subsystem. |

---

### `apotropaios/core/validation.py` (1272 lines)

27 whitelist validators, sanitize_input (whitelist regex), _contains_shell_meta (14-char frozenset), duplicate compound action detection

| Function | Parameters | Returns | Description |
|:---------|:-----------|:--------|:------------|
| `_contains_shell_meta` | value | `bool` | Check if a string contains shell metacharacters. |
| `validate_port` | value | `int` | Validate a TCP/UDP port number (1-65535). |
| `validate_port_range` | value | `tuple[int, int]` | Validate a port range (e.g., '8080-8090' or '8080:8090'). |
| `validate_ipv4` | value | `str` | Validate an IPv4 address with full octet range checking. |
| `validate_ipv6` | value | `str` | Validate an IPv6 address (simplified validation). |
| `validate_ip` | value | `str` | Validate an IP address (auto-detect IPv4 or IPv6). |
| `validate_cidr` | value | `str` | Validate CIDR notation (IP/prefix). |
| `validate_protocol` | value | `str` | Validate and normalize a network protocol name. |
| `validate_hostname` | value | `str` | Validate a hostname per RFC 1123. |
| `validate_interface` | value | `str` | Validate a network interface name. |
| `validate_file_path` | value | `str` | Validate a file path for safety. |
| `validate_zone` | value | `str` | Validate a firewalld zone name. |
| `validate_chain` | value | `str` | Validate an iptables/nftables chain name. |
| `validate_table` | value | `str` | Validate an iptables/nftables table name. |
| `validate_table_family` | value | `str` | Validate an nftables table family. |
| `validate_ipset_name` | value | `str` | Validate an ipset set name. |
| `validate_rule_id` | value | `str` | Validate a rule UUID. |
| `validate_rule_action` | value | `str` | Validate a firewall rule action (single or compound). |
| `validate_rule_direction` | value | `str` | Validate a firewall rule direction. |
| `validate_duration_type` | value | `str` | Validate a rule duration type. |
| `validate_ttl` | value | `int` | Validate a temporary rule TTL (time-to-live) in seconds. |
| `validate_log_level` | value | `str` | Validate a framework log level name or number. |
| `validate_syslog_level` | value | `str` | Validate a syslog severity level for firewall log actions. |
| `validate_conn_state` | value | `str` | Validate connection tracking state(s). |
| `validate_log_prefix` | value | `str` | Validate a log prefix string. |
| `validate_rate_limit` | value | `str` | Validate a rate limit string. |
| `validate_numeric` | value, min_value, max_value | `int` | Validate that input is a positive integer with optional range. |
| `validate_description` | value | `str` | Validate a rule description string. |
| `sanitize_input` | value | `str` | Sanitize a general input string using a WHITELIST approach. |
| `is_cancel_keyword` | value | `bool` | Check if user input is a cancel/quit keyword. |

---

### `apotropaios/core/logging.py` (752 lines)

LogSanitizer (6 compiled patterns: kv, quoted_dbl, quoted_sgl, json, auth, control; 11 sensitive keywords), FrameworkLogger (dual output, correlation IDs, TRACE level, secure rotation)

#### class `LogSanitizer`

Masks sensitive data patterns in log messages.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` |  | `None` |  |
| `sanitize` | message | `str` | Sanitize a log message by masking sensitive data patterns. |

#### class `_ColoredConsoleFormatter`(logging.Formatter)

Logging formatter that adds ANSI color codes to console output.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `format` | record | `str` | Format a log record with color codes. |

#### class `_StructuredFileFormatter`(logging.Formatter)

Logging formatter for structured file output.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | correlation_id | `None` |  |
| `correlation_id` |  | `str` | Current session correlation ID. |
| `format` | record | `str` | Format a log record in structured format. |

#### class `_SanitizingFilter`(logging.Filter)

Logging filter that masks sensitive data in log messages.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | sanitizer | `None` |  |
| `filter` | record | `bool` | Sanitize the log record message. |

#### class `_SecureRotatingHandler`(RotatingFileHandler)

RotatingFileHandler that enforces secure file permissions.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `_open` |  | `Any` | Open the log file with secure permissions. |
| `doRollover` |  | `None` | Perform log rotation with secure permissions on new file. |

#### class `FrameworkLogger`

Structured logging with dual output, sanitization, and correlation IDs.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` |  | `None` |  |
| `generate_correlation_id` |  | `str` | Generate a unique correlation ID for the current execution. |
| `init` | log_dir, level | `None` | Initialize the logging subsystem. |
| `shutdown` |  | `None` | Shut down the logging subsystem. |
| `set_level` | level | `None` | Change the runtime log level. |
| `trace` | context, message, extra_context | `None` | Log at TRACE level (ultra-verbose debugging). |
| `debug` | context, message, extra_context | `None` | Log at DEBUG level. |
| `info` | context, message, extra_context | `None` | Log at INFO level. |
| `warning` | context, message, extra_context | `None` | Log at WARNING level. |
| `error` | context, message, extra_context | `None` | Log at ERROR level. |
| `critical` | context, message, extra_context | `None` | Log at CRITICAL level. |
| `log_by_name` | level_name, message | `None` | Log a message using a level name string. |
| `_write` | level, context, message, extra_context | `None` | Core log writing function. |
| `log_file` |  | `str` | Current log file path, or empty string if not initialized. |
| `level` |  | `LogLevel` | Current log level. |
| `entry_count` |  | `int` | Number of log entries written in this session. |
| `correlation_id` |  | `str` | Current session correlation ID. |
| `initialized` |  | `bool` | Whether the logging subsystem is initialized. |

---

### `apotropaios/core/security.py` (693 lines)

FileLock (fcntl.flock with stale PID detection), SHA-256 checksums with hmac.compare_digest (constant-time), UUID v4, sensitive value scrubbing, secure_dir/file, init_security

#### class `FileLock`

Advisory file lock with timeout and stale lock detection.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | lock_path | `None` |  |
| `acquired` |  | `bool` | Whether the lock is currently held. |
| `lock_path` |  | `str` | Path to the lock file. |
| `acquire` | timeout | `bool` | Acquire the advisory file lock with timeout. |
| `release` |  | `None` | Release the advisory file lock. |
| `_close_fd` |  | `None` | Close the lock file descriptor. |
| `_check_stale_lock` |  | `None` | Check if the current lock holder is still alive. |
| `__enter__` |  | `FileLock` | Context manager entry — acquire the lock. |
| `__exit__` |  | `None` | Context manager exit — release the lock. |
| `__del__` |  | `None` | Destructor — ensure FD is closed. |

| Function | Parameters | Returns | Description |
|:---------|:-----------|:--------|:------------|
| `_log` | level, message | `None` | Emit a log message if the logger is available. |
| `init_security` | base_dir, logger | `None` | Initialize the security subsystem. |
| `check_root` |  | `bool` | Check if the current process has root (UID 0) privileges. |
| `is_root` |  | `bool` | Check if running as root without raising an exception. |
| `create_temp_file` | prefix | `str` | Create a secure temporary file with restrictive permissions (0o600). |
| `create_temp_dir` | prefix | `str` | Create a secure temporary directory with restrictive permissions (0o700). |
| `register_sensitive_value` | value | `None` | Register a sensitive value for scrubbing on cleanup. |
| `scrub_sensitive_values` |  | `None` | Overwrite all registered sensitive values with empty strings. |
| `file_checksum` | path, algorithm | `str` | Generate a cryptographic checksum of a file. |
| `verify_checksum` | path, expected, algorithm | `bool` | Verify a file's integrity against a known checksum. |
| `secure_dir` | path | `str` | Ensure a directory exists with secure permissions (0o700). |
| `secure_file` | path | `str` | Set secure permissions (0o600) on an existing file. |
| `validate_binary` | name | `str | None` | Validate that a binary exists and is executable. |
| `generate_uuid` |  | `str` | Generate a UUID v4 string. |
| `security_cleanup` |  | `None` | Cleanup function for the CleanupStack. |

---

### `apotropaios/core/utils.py` (501 lines)

UTC timestamps (ISO 8601, epoch, filename-safe), atomic KV file I/O, parallel_exec (ThreadPoolExecutor), human_duration/human_bytes, is_command_available

| Function | Parameters | Returns | Description |
|:---------|:-----------|:--------|:------------|
| `timestamp` |  | `str` | Generate an ISO 8601 UTC timestamp. |
| `timestamp_epoch` |  | `int` | Return current time as Unix epoch seconds. |
| `timestamp_filename` |  | `str` | Generate a filename-safe UTC timestamp (no colons). |
| `timestamp_iso_utc_ms` |  | `str` | Generate an ISO 8601 UTC timestamp with milliseconds. |
| `parse_iso_timestamp` | ts | `datetime | None` | Parse an ISO 8601 UTC timestamp string to a datetime object. |
| `to_lower` | value | `str` | Convert string to lowercase. |
| `to_upper` | value | `str` | Convert string to uppercase. |
| `trim` | value | `str` | Trim leading and trailing whitespace. |
| `is_command_available` | cmd | `bool` | Check if a command exists on the system PATH. |
| `require_command` | cmd, context | `str` | Assert that a command is available on the system. |
| `file_age_seconds` | path | `int` | Calculate the age of a file in seconds. |
| `read_kv_file` | path | `dict[str, str]` | Read a key=value file into a dictionary. |
| `write_kv_file` | path, data, header | `None` | Write a dictionary to a key=value file. |
| `human_duration` | seconds | `str` | Convert seconds to human-readable duration string. |
| `human_bytes` | size | `str` | Convert bytes to human-readable size string. |
| `confirm` | message, default | `bool` | Prompt user for yes/no confirmation. |
| `print_banner` |  | `None` | Print the Apotropaios ASCII art banner with version. |
| `print_separator` | char, width | `None` | Print a visual separator line. |
| `print_kv` | key, value, key_width | `None` | Print a key-value pair with aligned formatting. |
| `print_colored` | message, color, end, file | `None` | Print a message with optional ANSI color. |
| `parallel_exec` | tasks, func, max_workers | `list[tuple[bool, Any]]` | Execute multiple tasks in parallel with a concurrency limit. |

---


## Layer 2 — Detection

### `apotropaios/detection/os_detect.py` (430 lines)

4-fallback OS detection: /etc/os-release → lsb-release → redhat-release → platform.uname(). 4KB file size cap. Family resolution via OS_FAMILY_MAP

#### class `OSDetectionResult`

Result of operating system detection.

| Function | Parameters | Returns | Description |
|:---------|:-----------|:--------|:------------|
| `detect_os` | log_fn | `OSDetectionResult` | Perform operating system detection using multiple methods. |
| `_detect_os_release` | result | `bool` | Parse /etc/os-release for OS identification. |
| `_detect_lsb_release` | result | `bool` | Parse /etc/lsb-release for OS identification (Ubuntu/Debian fallback). |
| `_detect_redhat_release` | result | `bool` | Parse /etc/redhat-release for OS identification (RHEL family). |
| `_detect_uname` | result | `bool` | Fallback detection using Python's platform module. |
| `_determine_family` | result | `None` | Determine OS family and package manager from detected OS ID. |
| `print_os_info` | result | `None` | Print detected OS information to stderr. |

---

### `apotropaios/detection/fw_detect.py` (518 lines)

5-backend probing: shutil.which(binary) → version regex → systemctl is-active → is-enabled. 5-second per-probe timeout

#### class `_LogCallback`(Protocol)

Protocol for internal logging callbacks.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__call__` | level, msg, extra | `None` |  |

#### class `FWBackendStatus`

Detection result for a single firewall backend.

#### class `FWDetectionResult`

Aggregate result of firewall detection across all backends.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `get_installed` |  | `list[str]` | Return list of installed firewall IDs. |
| `get_running` |  | `list[str]` | Return list of running firewall IDs. |
| `is_installed` | fw_id | `bool` | Check if a specific firewall is installed. |
| `is_running` | fw_id | `bool` | Check if a specific firewall is currently running. |

| Function | Parameters | Returns | Description |
|:---------|:-----------|:--------|:------------|
| `detect_firewalls` | log_fn | `FWDetectionResult` | Detect all supported firewall applications. |
| `detect_single` | fw_id, log_fn | `FWBackendStatus` | Detect a specific firewall backend by ID. |
| `_detect_single` | fw_info, log | `FWBackendStatus` | Detect a single firewall application. |
| `_get_version` | fw_id, binary_path | `str` | Extract version string from a firewall binary's output. |
| `_check_running` | fw_id, installed | `bool` | Check if a firewall service is currently running. |
| `_check_enabled` | service_name | `bool` | Check if a firewall service is enabled at boot. |
| `_run_cmd` | args | `str` | Run a command and return its stdout. |
| `_systemctl_is_active` | service | `bool` | Check if a systemd service is active. |
| `_systemctl_is_enabled` | service | `bool` | Check if a systemd service is enabled at boot. |
| `print_fw_info` | result | `None` | Print detected firewall information to stderr. |

---


## Layer 3 — Firewall Backends

### `apotropaios/firewall/base.py` (190 lines)

FirewallBackend ABC with 12 abstract methods: name, add_rule, remove_rule, list_rules, enable, disable, status, block_all, allow_all, reset, save, load

#### class `FirewallBackend`(ABC)

Abstract base class for firewall backend implementations.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `name` |  | `str` | Return the canonical backend name (e.g., 'iptables'). |
| `add_rule` | rule | `bool` | Add a firewall rule. |
| `remove_rule` | rule | `bool` | Remove a firewall rule. |
| `list_rules` |  | `str` | List current firewall rules. |
| `enable` |  | `bool` | Enable/start the firewall service. |
| `disable` |  | `bool` | Disable/stop the firewall service. |
| `status` |  | `str` | Get current firewall status. |
| `block_all` |  | `bool` | Block all inbound and outbound traffic. |
| `allow_all` |  | `bool` | Allow all traffic (remove all restrictions). |
| `reset` |  | `bool` | Reset firewall to default configuration. |
| `save` | path | `bool` | Save current firewall configuration to file. |
| `load` | path | `bool` | Load firewall configuration from file. |

---

### `apotropaios/firewall/common.py` (276 lines)

Backend registry with auto-registration at import. set_backend/get_backend/require_backend. 12 dispatch functions

| Function | Parameters | Returns | Description |
|:---------|:-----------|:--------|:------------|
| `set_logger` | logger | `None` | Set the logger for the dispatch layer. |
| `_log` | level, msg | `None` | Emit a log message if logger is available. |
| `register_backend` | backend | `None` | Register a firewall backend implementation. |
| `get_registered_backends` |  | `list[str]` | Return list of registered backend names. |
| `set_backend` | name | `None` | Set the active firewall backend for operations. |
| `get_backend` |  | `FirewallBackend | None` | Return the currently active backend instance. |
| `get_backend_name` |  | `str` | Return the name of the currently active backend. |
| `require_backend` |  | `FirewallBackend` | Assert that a backend is selected and return it. |
| `fw_add_rule` | rule | `bool` | Add a firewall rule via the active backend. |
| `fw_remove_rule` | rule | `bool` | Remove a firewall rule via the active backend. |
| `fw_list_rules` |  | `str` | List current firewall rules via the active backend. |
| `fw_enable` |  | `bool` | Enable the firewall via the active backend. |
| `fw_disable` |  | `bool` | Disable the firewall via the active backend. |
| `fw_status` |  | `str` | Get firewall status via the active backend. |
| `fw_block_all` |  | `bool` | Block all traffic via the active backend. |
| `fw_allow_all` |  | `bool` | Allow all traffic via the active backend. |
| `fw_reset` |  | `bool` | Reset firewall to defaults via the active backend. |
| `fw_save` | path | `bool` | Save firewall configuration via the active backend. |
| `fw_load` | path | `bool` | Load firewall configuration via the active backend. |

---

### `apotropaios/firewall/iptables.py` (783 lines)

iptables: compound actions (separate LOG + terminal), _build_match_args, 5-table reset, iptables-save/restore

#### class `IptablesBackend`(FirewallBackend)

iptables firewall backend implementation.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `name` |  | `str` | Return the canonical backend name. |
| `add_rule` | rule | `bool` | Add iptables rule(s). |
| `remove_rule` | rule | `bool` | Remove iptables rule(s). |
| `list_rules` |  | `str` | List current iptables rules. |
| `enable` |  | `bool` | Start/enable iptables service via systemctl. |
| `disable` |  | `bool` | Stop/disable iptables service via systemctl. |
| `status` |  | `str` | Get iptables status with rule listing. |
| `block_all` |  | `bool` | Block all inbound and outbound traffic. |
| `allow_all` |  | `bool` | Allow all inbound and outbound traffic. |
| `reset` |  | `bool` | Flush all rules and reset to defaults. |
| `save` | path | `bool` | Save current iptables rules to file via iptables-save. |
| `load` | path | `bool` | Load iptables rules from file via iptables-restore. |

| Function | Parameters | Returns | Description |
|:---------|:-----------|:--------|:------------|
| `_set_logger` | logger | `None` | Set the logger for the iptables backend. |
| `_log` | level, msg | `None` | Emit a log message if logger is available. |
| `_run` | args, check | `subprocess.CompletedProcess[str]` | Execute an iptables command with security constraints. |
| `_direction_to_chain` | direction | `str` | Map a rule direction to the default iptables chain. |
| `_action_to_target` | action | `str` | Map a rule action to an iptables target name. |
| `_build_match_args` | rule | `tuple[list[str], str, str]` | Build the common match arguments for an iptables command. |
| `_parse_compound_action` | action | `tuple[list[str], str]` | Parse a compound action string into non-terminal and terminal parts. |

---

### `apotropaios/firewall/nftables.py` (508 lines)

nftables: single-expression compounds, auto table/chain creation, 6 families (inet default), nft -f for load

#### class `NftablesBackend`(FirewallBackend)

nftables firewall backend implementation.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `name` |  | `str` | Backend identifier string. |
| `add_rule` | rule | `bool` | Add a firewall rule via backend-specific commands. |
| `remove_rule` | rule | `bool` | Remove a firewall rule via backend-specific commands. |
| `list_rules` |  | `str` | List current firewall rules from the backend. |
| `enable` |  | `bool` | Start and enable the firewall service. |
| `disable` |  | `bool` | Stop the firewall service. |
| `status` |  | `str` | Get backend service status and configuration summary. |
| `block_all` |  | `bool` | Block all inbound and outbound traffic. |
| `allow_all` |  | `bool` | Allow all traffic (remove all restrictions). |
| `reset` |  | `bool` | Reset backend to default configuration. |
| `save` | path | `bool` | Save current configuration to persistent storage. |
| `load` | path | `bool` | Load configuration from file. |

| Function | Parameters | Returns | Description |
|:---------|:-----------|:--------|:------------|
| `_log` | level, msg | `None` |  |
| `_run` | args | `subprocess.CompletedProcess[str]` | Execute a subprocess command with timeout and capture. |
| `_nft_cmd` | nft_expr | `subprocess.CompletedProcess[str]` | Execute an nft command expression. |
| `_ensure_table` | family, table | `bool` | Ensure an nftables table exists, creating it if needed. |
| `_ensure_chain` | family, table, chain, direction | `bool` | Ensure an nftables chain exists, creating it if needed. |
| `_direction_to_chain` | direction | `str` |  |

---

### `apotropaios/firewall/firewalld.py` (489 lines)

firewalld: zone-aware rich rules, --permanent + --reload, all-zone reset, zone XML backup/restore, panic-on for block_all

#### class `FirewalldBackend`(FirewallBackend)

firewalld firewall backend implementation with zone awareness.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `name` |  | `str` | Backend identifier string. |
| `add_rule` | rule | `bool` | Add a firewall rule via backend-specific commands. |
| `remove_rule` | rule | `bool` | Remove a firewall rule via backend-specific commands. |
| `list_rules` |  | `str` | List current firewall rules from the backend. |
| `enable` |  | `bool` | Start and enable the firewall service. |
| `disable` |  | `bool` | Stop the firewall service. |
| `status` |  | `str` | Get backend service status and configuration summary. |
| `block_all` |  | `bool` | Block all inbound and outbound traffic. |
| `allow_all` |  | `bool` | Allow all traffic (remove all restrictions). |
| `reset` |  | `bool` | Reset firewalld — iterates ALL zones (Lesson #10). |
| `save` | path | `bool` | Save current configuration to persistent storage. |
| `load` | path | `bool` | Reload firewalld configuration from permanent zone files. |

| Function | Parameters | Returns | Description |
|:---------|:-----------|:--------|:------------|
| `_log` | level, msg | `None` |  |
| `_run` | args | `subprocess.CompletedProcess[str]` |  |
| `_build_rich_rule` | rule | `str` | Construct a firewalld rich rule string from parameters. |

---

### `apotropaios/firewall/ufw.py` (449 lines)

UFW: --force on all commands, _map_action for compound handling, direction-aware syntax

#### class `UfwBackend`(FirewallBackend)

UFW firewall backend implementation.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `name` |  | `str` | Backend identifier string. |
| `add_rule` | rule | `bool` | Add a firewall rule via backend-specific commands. |
| `remove_rule` | rule | `bool` | Remove a firewall rule via backend-specific commands. |
| `list_rules` |  | `str` | List current firewall rules from the backend. |
| `enable` |  | `bool` | Start and enable the firewall service. |
| `disable` |  | `bool` | Stop the firewall service. |
| `status` |  | `str` | Get backend service status and configuration summary. |
| `block_all` |  | `bool` | Block all inbound and outbound traffic. |
| `allow_all` |  | `bool` | Allow all traffic (remove all restrictions). |
| `reset` |  | `bool` | Reset backend to default configuration. |
| `save` | path | `bool` | Save current configuration to persistent storage. |
| `load` | path | `bool` | Load configuration from file. |

| Function | Parameters | Returns | Description |
|:---------|:-----------|:--------|:------------|
| `_log` | level, msg | `None` |  |
| `_run` | args, stdin_data | `subprocess.CompletedProcess[str]` |  |
| `_map_action` | action | `tuple[str, bool]` | Map a rule action to a ufw verb, handling compounds. |

---

### `apotropaios/firewall/ipset.py` (497 lines)

ipset: 6 set types, iptables cross-references, _remove_iptables_refs, entry validation per set type

#### class `IpsetBackend`(FirewallBackend)

ipset firewall backend implementation.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `name` |  | `str` | Backend identifier string. |
| `add_rule` | rule | `bool` | Add entry to an ipset, creating the set if needed. |
| `remove_rule` | rule | `bool` | Remove entry from ipset or destroy the set. |
| `list_rules` |  | `str` | List current firewall rules from the backend. |
| `enable` |  | `bool` | Start and enable the firewall service. |
| `disable` |  | `bool` | Stop the firewall service. |
| `status` |  | `str` | Get backend service status and configuration summary. |
| `block_all` |  | `bool` | Block all inbound and outbound traffic. |
| `allow_all` |  | `bool` | Allow all traffic (remove all restrictions). |
| `reset` |  | `bool` | Reset ipset — flush all sets and remove iptables references. |
| `save` | path | `bool` | Save current configuration to persistent storage. |
| `load` | path | `bool` | Load configuration from file. |

| Function | Parameters | Returns | Description |
|:---------|:-----------|:--------|:------------|
| `_log` | level, msg | `None` |  |
| `_run` | args | `subprocess.CompletedProcess[str]` |  |
| `_validate_entry` | entry, set_type | `bool` | Validate an ipset entry against the set type. |
| `_remove_iptables_refs` | set_name | `None` | Remove iptables rules that reference an ipset. |

---


## Layer 4 — Engine

### `apotropaios/rules/engine.py` (595 lines)

Rule lifecycle: rule_create (validate→UUID→backend→index→state), rule_remove, rule_deactivate, rule_activate, rule_block_all, rule_allow_all, rule_check_expired

| Function | Parameters | Returns | Description |
|:---------|:-----------|:--------|:------------|
| `set_logger` | logger | `None` | Set the logger for the rule engine. |
| `_log` | level, msg, extra | `None` |  |
| `rule_create` | params | `str` | Create and apply a firewall rule. |
| `rule_remove` | rule_id, remove_from_backend | `None` | Remove a firewall rule by its UUID. |
| `rule_deactivate` | rule_id | `None` | Deactivate a rule: remove from backend but keep in index. |
| `rule_activate` | rule_id | `None` | Re-activate a previously deactivated rule. |
| `rule_block_all` |  | `str` | Block all inbound and outbound traffic. |
| `rule_allow_all` |  | `str` | Allow all inbound and outbound traffic. |
| `rule_check_expired` |  | `int` | Check for and auto-deactivate expired temporary rules. |

---

### `apotropaios/rules/index.py` (358 lines)

Persistent pipe-delimited index (27 fields), RuleIndex singleton, thread-safe, atomic save, corrupt entry recovery, 10MB size limit

#### class `RuleIndex`

Persistent rule index with in-memory cache.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` |  | `None` |  |
| `init` | rules_dir | `None` | Initialize the rule index. |
| `load` |  | `None` | Load rule index from disk file into memory. |
| `save` |  | `bool` | Save the in-memory rule index to disk. |
| `add` | record | `None` | Add a rule record to the index. |
| `remove` | rule_id | `None` | Remove a rule from the index. |
| `get` | rule_id | `dict[str, str]` | Retrieve a rule's data by ID. |
| `update_field` | rule_id, field, value | `None` | Update a single field of a rule in the index. |
| `list_ids` |  | `list[str]` | Return all rule IDs in insertion order. |
| `count` |  | `int` | Return the number of rules in the index. |
| `list_formatted` |  | `str` | Format all rules as a display table. |
| `initialized` |  | `bool` | Whether the index has been initialized. |

| Function | Parameters | Returns | Description |
|:---------|:-----------|:--------|:------------|
| `_log` | level, msg | `None` |  |

---

### `apotropaios/rules/state.py` (278 lines)

TTL tracking: StateEntry dataclass, RuleState singleton, is_expired, time_remaining, get_expiring_soon(600s default)

#### class `StateEntry`

In-memory state for a single rule.

#### class `RuleState`

Rule state tracker with TTL expiry support.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` |  | `None` |  |
| `init` | rules_dir | `None` | Initialize rule state tracking. |
| `set` | rule_id, state, duration_type, ttl | `None` | Set or update the state of a rule. |
| `get` | rule_id | `str` | Get the current state of a rule. |
| `remove` | rule_id | `None` | Remove state tracking for a rule. |
| `is_expired` | rule_id | `bool` | Check if a temporary rule has expired. |
| `time_remaining` | rule_id | `int` | Get remaining time for a temporary rule in seconds. |
| `get_entry` | rule_id | `StateEntry | None` | Get the full state entry for a rule. |
| `get_expiring_soon` | within_seconds | `list[tuple[str, int]]` | Get rules expiring within a time window. |
| `_load` |  | `None` | Load state from disk file. |
| `_save` |  | `None` | Save state to disk file with atomic write. |
| `initialized` |  | `bool` | Whether the rule state subsystem has been initialized. |

| Function | Parameters | Returns | Description |
|:---------|:-----------|:--------|:------------|
| `_log` | level, msg | `None` |  |

---

### `apotropaios/rules/import_export.py` (269 lines)

import_rules: KV block parsing, dry-run, SHA-256 sidecar verification, 10MB size limit. export_rules: KV output with checksum sidecar

| Function | Parameters | Returns | Description |
|:---------|:-----------|:--------|:------------|
| `_log` | level, msg | `None` |  |
| `import_rules` | config_path, dry_run | `tuple[int, int, int]` | Import and apply rules from a configuration file. |
| `export_rules` | output_path, generate_checksum | `int` | Export all tracked rules to a configuration file. |

---

### `apotropaios/backup/backup.py` (343 lines)

create_backup: per-backend export (iptables-save, nft list, firewalld zone XMLs, ufw status, ipset save), tar.gz, JSON manifest, SHA-256 sidecar, retention (max 20)

| Function | Parameters | Returns | Description |
|:---------|:-----------|:--------|:------------|
| `_log` | level, msg | `None` |  |
| `init_backup` | backup_dir, logger, rules_dir | `None` | Initialize the backup subsystem and record the default rules directory. |
| `get_default_rules_dir` |  | `str` | Return the default rules directory recorded at initialization. |
| `create_backup` | label, backend, rules_dir | `str` | Create a backup of current firewall configuration. |
| `create_restore_point` | description | `str` | Create a restore point before making changes. |
| `list_backups` |  | `str` | List available backups. |
| `get_last_backup` |  | `str` | Return path to the most recently created backup. |
| `_export_all` | staging | `None` | Export all detected firewall configurations. |
| `_export_single` | staging, fw_name | `None` | Export a single firewall's configuration. |
| `_enforce_retention` |  | `None` | Remove old backups beyond the retention limit. |

---

### `apotropaios/backup/restore.py` (283 lines)

restore_backup: checksum verify, pre-restore safety backup, path traversal check, per-backend restore with zone XML copy for firewalld

| Function | Parameters | Returns | Description |
|:---------|:-----------|:--------|:------------|
| `_log` | level, msg | `None` |  |
| `restore_backup` | backup_file, target_backend, rules_dir | `None` | Restore firewall configuration from a backup archive. |
| `_restore_single` | staging, fw_name, timeout | `bool` | Restore a single backend's configuration. |

---

### `apotropaios/backup/immutable.py` (215 lines)

create_snapshot: chattr +i, SHA-256 integrity files. verify_snapshots: integrity scan

| Function | Parameters | Returns | Description |
|:---------|:-----------|:--------|:------------|
| `_log` | level, msg | `None` |  |
| `_get_immutable_dir` | backup_dir | `str` | Return the immutable snapshots subdirectory path. |
| `create_snapshot` | backup_dir, label, rules_dir | `str` | Create an immutable snapshot of current firewall state. |
| `verify_snapshots` | backup_dir | `int` | Verify integrity of all immutable snapshots. |
| `list_snapshots` | backup_dir | `str` | List immutable snapshots. |

---

### `apotropaios/install/installer.py` (262 lines)

install_firewall/update_firewall: apt (DEBIAN_FRONTEND=noninteractive), dnf (--allowerasing), pacman (--noconfirm)

| Function | Parameters | Returns | Description |
|:---------|:-----------|:--------|:------------|
| `_log` | level, msg | `None` |  |
| `set_logger` | logger | `None` | Set the logger for the installer. |
| `install_firewall` | fw_name, pkg_manager, os_id | `None` | Install a firewall package. |
| `update_firewall` | fw_name, pkg_manager | `None` | Update a firewall package to latest version. |
| `_apt_install` | pkg | `None` | Install a package via apt. |
| `_dnf_install` | pkg | `None` | Install a package via dnf (with --allowerasing for RHEL compat). |
| `_pacman_install` | pkg | `None` | Install a package via pacman. |
| `_apt_update` | pkg | `None` | Update a package via apt. |
| `_dnf_update` | pkg | `None` | Update a package via dnf. |
| `_pacman_update` | pkg | `None` | Update a package via pacman. |

---


## Layer 5 — User Interface

### `apotropaios/cli.py` (1341 lines)

21 CLI commands (17 _cmd_* handlers + help inline). Progressive help. Position-independent globals. Full init: logging→errors→security→detection→backends→rules→backup

| Function | Parameters | Returns | Description |
|:---------|:-----------|:--------|:------------|
| `_build_parser` |  | `argparse.ArgumentParser` | Build the argument parser with all commands and options. |
| `_add_rule_options` | parser | `None` | Add all add-rule subcommand options to a parser. |
| `_show_global_help` |  | `None` | Display top-level usage information (Tier 1 help). |
| `_detect_help_request` | argv | `tuple[bool, bool, str]` | Pre-scan arguments to detect help requests. |
| `_resolve_base_dir` |  | `str` | Determine the framework base directory. |
| `_load_config` | base_dir | `dict[str, str]` | Load the framework configuration file if present (trusted files only; first match wins). |
| `_confirm_destructive` | warning | `bool` | Prompt for explicit confirmation before a destructive operation; honors non-interactive mode and reads from the controlling terminal. |
| `_initialize` | base_dir, log_level, backend_name, cli_log_level_given | `None` | Initialize all framework subsystems with configuration-file precedence handling. |
| `_dispatch` | args | `int` | Execute the parsed command. |
| `_cmd_menu` | args | `int` | Launch the interactive menu. |
| `_cmd_detect` | args | `int` | Detect OS and installed firewalls. |
| `_cmd_status` | args | `int` | Show firewall backend service state and summary. |
| `_cmd_add_rule` | args | `int` | Create and apply a firewall rule via CLI options. |
| `_cmd_remove_rule` | args | `int` | Remove a rule by its UUID. |
| `_cmd_activate_rule` | args | `int` | Re-activate a deactivated rule. |
| `_cmd_deactivate_rule` | args | `int` | Deactivate a rule (keep in index). |
| `_cmd_list_rules` | args | `int` | List all Apotropaios-tracked rules. |
| `_cmd_system_rules` | args | `int` | Audit all native system firewall rules. |
| `_cmd_block_all` | args | `int` | Block ALL inbound and outbound traffic. |
| `_cmd_allow_all` | args | `int` | Allow ALL traffic (remove restrictions). |
| `_cmd_import` | args | `int` | Import rules from configuration file. |
| `_cmd_export` | args | `int` | Export rules to configuration file. |
| `_cmd_backup` | args | `int` | Create a configuration backup. |
| `_cmd_restore` | args | `int` | Restore from backup archive. |
| `_cmd_install` | args | `int` | Install a firewall package. |
| `_cmd_update` | args | `int` | Update a firewall package. |
| `main` | argv | `NoReturn` | Main entry point for the CLI. |

---

### `apotropaios/__main__.py` (57 lines)

Package entry point for python3 -m apotropaios. Python version check

| Function | Parameters | Returns | Description |
|:---------|:-----------|:--------|:------------|
| `main` |  | `None` | Top-level entry point for the Apotropaios framework. |

---

### `apotropaios/menu/main.py` (789 lines)

8-option interactive menu. ExpiryMonitor daemon (30s interval, 600s/10min alerts). Cancel-aware input. Rule wizard

#### class `ExpiryMonitor`

Background daemon thread that checks for expired temporary rules.

| Method | Parameters | Returns | Description |
|:-------|:-----------|:--------|:------------|
| `__init__` | check_interval | `None` |  |
| `start` |  | `None` | Start the expiry monitor daemon thread. |
| `stop` |  | `None` | Stop the expiry monitor daemon thread. |
| `_loop` |  | `None` | Main monitor loop — runs until stop_event is set. |
| `_check` |  | `None` | Check for expired rules and print near-expiry alerts. |

| Function | Parameters | Returns | Description |
|:---------|:-----------|:--------|:------------|
| `_log` | level, msg | `None` |  |
| `_read_input` | prompt | `str | None` | Read user input with cancel keyword detection. |
| `_read_choice` | prompt, max_choice | `int | None` | Read a numeric menu choice. |
| `menu_main` | logger | `None` | Launch the interactive menu-driven interface. |
| `_render_main_menu` |  | `None` | Render the main menu display. |
| `_menu_firewall_management` |  | `None` | Firewall Management submenu. |
| `_menu_rule_management` |  | `None` | Rule Management submenu. |
| `_menu_quick_actions` |  | `None` | Quick Actions submenu. |
| `_menu_backup_recovery` |  | `None` | Backup & Recovery submenu. |
| `_menu_system_info` |  | `None` | System Information submenu — full OS and firewall detection details. |
| `_menu_install_update` |  | `None` | Install & Update submenu. |
| `_menu_help` |  | `None` | Help & Documentation submenu with per-command help access. |

---

### `apotropaios/menu/help_system.py` (526 lines)

17 @_register-decorated per-command help functions. Synopsis, options, examples, related commands

| Function | Parameters | Returns | Description |
|:---------|:-----------|:--------|:------------|
| `_header` | command, synopsis | `None` | Print standardized help header for a command. |
| `_section` | title | `None` | Print a section heading. |
| `_opt` | flag, desc | `None` | Print a formatted option line. |
| `_tip` | text | `None` | Print a tip callout. |
| `_related` |  | `None` | Print related commands section. |
| `help_dispatch` | command | `int` | Route to the correct per-command help function. |
| `_register` | command | `Callable[[Callable[[], None]], Callable[[], None]]` | Decorator to register a help function for a command. |
| `_help_cmd_menu` |  | `None` | Help for the menu / --interactive command. |
| `_help_cmd_detect` |  | `None` | Help for the detect command. |
| `_help_cmd_status` |  | `None` | Help for the status command. |
| `_help_cmd_add_rule` |  | `None` | Help for the add-rule command. |
| `_help_cmd_remove_rule` |  | `None` | Help for the remove-rule command. |
| `_help_cmd_activate_rule` |  | `None` | Help for the activate-rule command. |
| `_help_cmd_deactivate_rule` |  | `None` | Help for the deactivate-rule command. |
| `_help_cmd_list_rules` |  | `None` | Help for the list-rules command. |
| `_help_cmd_system_rules` |  | `None` | Help for the system-rules command. |
| `_help_cmd_block_all` |  | `None` | Help for the block-all command. |
| `_help_cmd_allow_all` |  | `None` | Help for the allow-all command. |
| `_help_cmd_import` |  | `None` | Help for the import command. |
| `_help_cmd_export` |  | `None` | Help for the export command. |
| `_help_cmd_backup` |  | `None` | Help for the backup command. |
| `_help_cmd_restore` |  | `None` | Help for the restore command. |
| `_help_cmd_install` |  | `None` | Help for the install command. |
| `_help_cmd_update` |  | `None` | Help for the update command. |

---

