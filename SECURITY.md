# Security Policy -- Apotropaios Firewall Manager (Python Variant)

## Table of Contents

- [Reporting Vulnerabilities](#reporting-vulnerabilities)
- [Coordinated Disclosure](#coordinated-disclosure)
- [Security Design Philosophy](#security-design-philosophy)
- [Input Validation Architecture](#input-validation-architecture)
- [Subprocess Security](#subprocess-security)
- [Log Sanitization](#log-sanitization)
- [File System Security](#file-system-security)
- [Cryptographic Operations](#cryptographic-operations)
- [Process Security](#process-security)
- [Compound Action Security](#compound-action-security)
- [CWE Coverage](#cwe-coverage)
- [Threat Model](#threat-model)
- [Security Testing](#security-testing)
- [Supported Versions](#supported-versions)
- [Known Limitations](#known-limitations)

---

## Reporting Vulnerabilities

**DO NOT** report security vulnerabilities through public GitHub issues.

To report a vulnerability, please email the maintainers directly or use GitHub's private vulnerability reporting feature. Include:

1. Description of the vulnerability
2. Steps to reproduce
3. Affected version(s)
4. Potential impact assessment
5. Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide an initial assessment within 7 days.

## Coordinated Disclosure

We follow a coordinated disclosure process:

1. Reporter notifies maintainers privately
2. Maintainers assess severity and develop a fix
3. Fix is released with a security advisory
4. Public disclosure after patch availability (minimum 14-day embargo)

Contributors who discover vulnerabilities are expected to follow this process. Public disclosure before a fix is available may constitute a violation of the project License.

---

## Security Design Philosophy

Apotropaios operates at the most sensitive layer of system infrastructure -- the network firewall. The framework runs as root, modifies kernel-level packet filtering rules, and manages configuration that determines what traffic enters and exits the system. Every design decision prioritizes security:

1. **Defense-in-depth**: Multiple independent security controls at every layer. Input is validated, then sanitized, then passed as list-form arguments. Even if one layer fails, the next catches the problem.
2. **Whitelist over blacklist**: All 27 validators define what IS allowed, not what isn't. A new attack vector doesn't bypass whitelist validation.
3. **Fail-closed**: Invalid input is rejected. Unknown backends are rejected. Unrecognized commands are rejected. The default is denial.
4. **Least privilege in design**: Files are 0o600, directories 0o700, umask 0o077. Even though the framework runs as root, it minimizes the accessibility of its own data.
5. **Zero external dependencies**: The runtime uses only the Python 3.12+ standard library. No pip packages, no supply chain risk.

---

## Input Validation Architecture

### 27 Whitelist Validators

Every parameter entering the framework passes through at least one validator in `core/validation.py` (1,256 lines). Validators are pure functions that raise `ValidationError` on invalid input -- they never return boolean.

| Validator | Input Type | Validation Logic |
|:----------|:-----------|:-----------------|
| `validate_port` | Port number | Parse to int, verify 1 ≤ port ≤ 65535 |
| `validate_port_range` | Port range | Split on `-` or `:`, validate each end, verify start < end |
| `validate_ipv4` | IPv4 address | Regex format check + per-octet 0-255 range check |
| `validate_ipv6` | IPv6 address | Regex format check supporting `::` compressed notation |
| `validate_ip` | IP address | Auto-detect v4/v6, delegate to specific validator |
| `validate_cidr` | CIDR notation | Validate IP portion + prefix range (0-32 for v4, 0-128 for v6) |
| `validate_protocol` | Protocol name | Lowercase, verify in `{tcp, udp, icmp, icmpv6, sctp, all}` |
| `validate_hostname` | Hostname | RFC 1123 compliance: labels ≤63 chars, alphanumeric + hyphens, no shell metachars |
| `validate_interface` | Network interface | Regex: starts with letter, ≤15 chars, alphanumeric + dot/hyphen/underscore |
| `validate_file_path` | File path | Three checks: null byte rejection → path traversal (`..`) rejection → shell metachar rejection |
| `validate_zone` | Firewalld zone | Regex: starts with letter, ≤32 chars, alphanumeric + underscore/hyphen |
| `validate_chain` | Chain name | Regex: starts with letter, ≤64 chars |
| `validate_table` | Table name | Lowercase, verify in `{filter, nat, mangle, raw, security}` for iptables |
| `validate_table_family` | nftables family | Verify in `{inet, ip, ip6, arp, bridge, netdev}` |
| `validate_ipset_name` | ipset name | Regex: starts with letter, ≤31 chars, no shell metachars |
| `validate_rule_id` | UUID | UUID v4 format regex: 8-4-4-4-12 lowercase hex |
| `validate_rule_action` | Rule action | Single or compound; compound: split on comma, verify each in ALL_ACTIONS, reject double-terminal |
| `validate_rule_direction` | Direction | Verify in `{inbound, outbound, forward}` |
| `validate_duration_type` | Duration | Verify in `{permanent, temporary}` |
| `validate_ttl` | TTL seconds | Parse to int, verify 60 ≤ ttl ≤ 2,592,000 |
| `validate_log_level` | Framework level | Verify in LogLevel enum names or numeric 0-5 |
| `validate_syslog_level` | Syslog level | Verify in SyslogLevel enum: emerg through debug |
| `validate_conn_state` | Conntrack states | Split on comma, verify each in ConnState enum |
| `validate_log_prefix` | Log prefix | Safe chars only, ≤29 chars (iptables kernel limit) |
| `validate_rate_limit` | Rate limit | Regex: `N/(second|minute|hour|day)` |
| `validate_numeric` | Integer | Parse to int, verify min ≤ value ≤ max |
| `validate_description` | Description | Shell metachar rejection, length ≤256 |

### Input Sanitization

`sanitize_input()` applies defense-in-depth to all user input:

1. Rejects None/non-string input (raises `SanitizationError`)
2. Strips whitespace with `str.strip()`
3. Removes HTML tags with regex: `<[^>]*>` → empty string (prevents stored XSS)
4. Applies whitelist regex `[^a-zA-Z0-9 .,_:/+=@~%-]` -- removes any character not in this set
5. Truncates to `Security.MAX_INPUT_LENGTH` (4096 chars)
6. Returns the cleaned string

### Shell Metacharacter Detection

`_contains_shell_meta(value)` tests input against `SHELL_METACHARACTERS` frozenset containing: `;|&`$(){}\\<>!#`. Uses frozenset intersection for O(1) per-character lookup.

---

## Subprocess Security

**All subprocess calls use list-form arguments -- never `shell=True`.** This is the single most important security control in the framework.

```python
# CORRECT -- list-form, no shell interpretation
subprocess.run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", port, "-j", "ACCEPT"],
               capture_output=True, text=True, timeout=30)

# FORBIDDEN -- shell=True enables injection
subprocess.run(f"iptables -A INPUT -p tcp --dport {port} -j ACCEPT", shell=True)
```

Every subprocess call also:
- Captures stderr with `capture_output=True` for error diagnosis
- Sets `timeout=30` seconds to prevent hanging (configurable via `Performance.SUBPROCESS_TIMEOUT`)
- Uses `text=True` for string (not bytes) output

The `make security-scan` target verifies no `shell=True`, `eval()`, `exec()`, or `pickle` usage exists in the codebase on every build.

---

## Log Sanitization

### 4-Family Credential Masking

`LogSanitizer` in `core/logging.py` intercepts all log messages before they reach any handler. Four compiled regex patterns mask different credential formats:

| Family | Pattern Example | Masked Output |
|:-------|:----------------|:-------------|
| Key-value | `password=secret123` | `password=***MASKED***` |
| Quoted values | `password="secret123"` | `password="***MASKED***"` |
| JSON values | `{"password": "secret123"}` | `{"password": "***MASKED***"}` |
| Auth headers | `Bearer eyJhbGci...` | `Bearer ***MASKED***` |

**Sensitive field names** (11): password, passwd, secret, token, key, api_key, apikey, access_token, auth, authorization, credential, private_key, api_secret, client_secret.

**Control character stripping**: Bytes 0x00-0x08 and 0x0E-0x1F are removed from all log messages to prevent log injection attacks where binary control sequences could manipulate terminal display or corrupt log parsing (CWE-117).

---

## File System Security

| Control | Implementation |
|:--------|:---------------|
| Directory permissions | Created with `os.chmod(path, 0o700)` -- owner-only access |
| File permissions | Created with `os.chmod(path, 0o600)` -- owner read/write only |
| umask | Set to `0o077` during `init_security()` -- blocks group/world on new files |
| Atomic writes | All persistent data: write to `filename.tmp.<PID>` → `os.replace()` → `os.chmod(0o600)` |
| Path traversal | `validate_file_path()` rejects `..` components anywhere in the path |
| Null byte injection | `validate_file_path()` rejects `\x00` characters (C-string truncation attack) |
| Temp files | Created via `tempfile.mkstemp()` with 0o600 permissions |
| Temp directories | Created via `tempfile.mkdtemp()` with 0o700 permissions |
| Backup archives | Archive extraction validates all paths -- rejects entries containing `..` or absolute paths |

---

## Cryptographic Operations

| Operation | Algorithm | Implementation |
|:----------|:----------|:---------------|
| File checksums | SHA-256 | `hashlib.sha256()` with 64KB chunked reading |
| Checksum verification | SHA-256 | `hmac.compare_digest()` for constant-time comparison (prevents timing attacks) |
| UUID generation | UUID v4 | `uuid.uuid4()` -- cryptographic quality via OS random source |
| Backup integrity | SHA-256 | `.sha256` sidecar files generated and verified automatically |
| Immutable snapshots | SHA-256 + chattr | `.integrity` file + `chattr +i` filesystem attribute |

---

## Process Security

| Control | Implementation |
|:--------|:---------------|
| Root check | `os.geteuid() == 0` verified before firewall operations |
| umask enforcement | `os.umask(0o077)` set during security initialization |
| Signal handling | SIGTERM, SIGINT, SIGHUP trapped with CleanupStack integration. SIGINT is context-aware: inside the interactive menu it aborts the current operation and recovers to the menu; in headless execution it runs cleanup and exits 130. SIGTERM and SIGHUP always terminate. |
| File locking | `fcntl.flock()` with stale lock detection (PID validation via `os.kill(pid, 0)`) |
| Lock timeout | 30 seconds with 1-second retry interval; `LockTimeoutError` on failure |
| Memory scrubbing | `scrub_sensitive_values()` overwrites registered sensitive strings (best-effort in Python) |
| Cleanup stack | LIFO execution on signal or exit, with recursion guard and continue-on-failure |

---

## Compound Action Security

Compound actions (e.g., `log,drop`) are parsed by `validate_rule_action()`:

1. Action string is split on commas only
2. Each component validated against `ALL_ACTIONS` frozenset
3. Terminal/non-terminal classification applied
4. Double-terminal detection rejects invalid combinations (`accept,drop`)
5. Backend-specific translation: iptables creates separate rules, nftables uses single expression

**Why this matters**: If compound action parsing were insecure, an attacker could craft an action string that creates unintended rules or bypasses the intended terminal action.

---

## CWE Coverage

The security test suite (`tests/security/test_injection.py`, 15 tests) covers:

| CWE | Vulnerability | Test Coverage |
|:----|:-------------|:-------------|
| CWE-78 | OS Command Injection | Shell metachar injection via all 9 input types (IP, port, chain, table, zone, interface, ipset, description, hostname) |
| CWE-22 | Path Traversal | `../` sequences in file paths, null byte injection (`\x00`) |
| CWE-79 | Cross-Site Scripting | HTML tag injection in `sanitize_input()` |
| CWE-117 | Log Injection | Control character stripping in LogSanitizer |
| CWE-20 | Improper Input Validation | All 27 validators tested with both valid and invalid inputs (42 unit tests) |

The `make security-scan` target also performs 6 static pattern checks:
1. No `shell=True` in subprocess calls
2. No `eval()` usage
3. No `exec()` usage
4. No `pickle`/`marshal` usage (deserialization attacks)
5. No hardcoded credentials
6. No TODO/FIXME markers (incomplete code)

---

## Threat Model

### Assets Protected

1. **Firewall rules** -- Kernel-level packet filtering determining network access
2. **Rule index** -- Persistent tracking of all managed rules
3. **Backup archives** -- Historical firewall configurations
4. **Log files** -- Audit trail of all operations

### Threat Actors

1. **Untrusted input** -- Malicious parameters passed via CLI or import files
2. **Compromised import files** -- Tampered rule configurations
3. **Local privilege escalation** -- Non-root user attempting to modify firewall rules
4. **Log manipulation** -- Injection of misleading log entries

### Mitigations

| Threat | Mitigation |
|:-------|:-----------|
| Command injection via parameters | 27 whitelist validators + list-form subprocess (never shell=True) |
| Path traversal in file operations | `validate_file_path()` rejects `..` and null bytes |
| Import file tampering | SHA-256 sidecar verification before processing |
| Unauthorized access | Root check + 0o600/0o700 permissions + umask 0o077 |
| Log injection | Control character stripping + 4-family credential masking |
| Stale lock DoS | PID validation and automatic stale lock recovery |
| Partial write corruption | Atomic temp-then-replace for all persistent data |
| Timing side channels | `hmac.compare_digest()` for checksum verification |

---

## Security Testing

```bash
# Run security test suite (15 CWE-mapped tests)
make test-security

# Run static security scan (6 pattern checks)
make security-scan

# Run individual security tests
make test-injection

# Run all quality gates (includes security)
make test-all
```

---

## Supported Versions

| Version | Supported |
|:--------|:----------|
| Current release (see [CHANGELOG.md](CHANGELOG.md)) | Supported |
| Earlier releases | Upgrade to the current release |

---

## Known Limitations

1. **Python GC and sensitive memory**: Python's garbage collector does not guarantee timely scrubbing of sensitive memory. `scrub_sensitive_values()` is best-effort -- the GC may have already copied string objects.

2. **Log rotation**: Built-in rotation triggers at 100MB per file with 10 retained. High-traffic environments should use external log rotation (logrotate).

3. **Container environments**: Kernel modules (`ip_tables`, `nf_tables`) are required for firewall operations. Containers may lack these. Use `--cap-add=NET_ADMIN` with Docker.

4. **Cross-process locking**: Rule index uses thread-safe `threading.Lock` but does not implement cross-process file locking for the index file itself. Concurrent processes modifying rules may race.

5. **TTL precision**: The ExpiryMonitor checks every 30 seconds. A temporary rule may remain active up to 30 seconds past its nominal TTL.

6. **IPv6 validation**: IPv6 validation uses a simplified regex pattern. Exotic edge cases (embedded IPv4, zone IDs) may not be fully validated.

7. **No TLS/encryption**: Log files and data files are protected by filesystem permissions only. No at-rest encryption is provided.
