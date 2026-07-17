# Frequently Asked Questions (FAQ) -- Apotropaios Firewall Manager

## Table of Contents

- [General](#general)
- [Installation and Setup](#installation-and-setup)
- [Usage and Operation](#usage-and-operation)
- [Rules and Actions](#rules-and-actions)
- [Backends and Compatibility](#backends-and-compatibility)
- [Security](#security)
- [Backup and Recovery](#backup-and-recovery)
- [Logging and Debugging](#logging-and-debugging)
- [Development and Contributing](#development-and-contributing)

---

## General

### What does "Apotropaios" mean?

From Greek ἀποτρόπαιος (*apotropaios*) -- "averting evil." In ancient Greek culture, apotropaic objects and rituals were used to ward off evil spirits and harmful influences. The name reflects the framework's purpose: defending systems against malicious network traffic.

### What firewalls does Apotropaios support?

Five Linux firewall backends: **iptables**, **nftables**, **firewalld**, **UFW** (Uncomplicated Firewall), and **ipset**. Each backend has a full implementation with all 12 required operations (add/remove rule, list rules, enable/disable, status, block/allow all, reset, save/load).

### What Linux distributions are supported?

Ubuntu (22.04, 24.04), Debian (11, 12), Kali Linux (2024+), Rocky Linux (8, 9), AlmaLinux (8, 9), and Arch Linux (rolling). Compatible derivatives are supported via the `ID_LIKE` field in `/etc/os-release`.

### Does Apotropaios require external Python packages?

No. The runtime is **stdlib-only** -- zero external dependencies. Dev dependencies (pytest, mypy) are optional and only needed for development/testing. No pip packages are required at runtime.

### Does Apotropaios replace my existing firewall?

No. Apotropaios is a management layer that sits on top of your existing firewall backend. It creates, tracks, and manages rules through the native firewall tools (iptables, nft, firewall-cmd, ufw, ipset). It does not replace or bypass any kernel-level firewall functionality.

### What is the difference between the bash and Python variants?

The bash variant (`Sandler73/Apotropaios-Firewall-Manager`) is the reference implementation at v1.1.10. The Python variant targets 100% feature parity with the bash reference, using Python 3.12+ with strict typing, a 5-layer architecture, and 322 automated tests. Both share the same feature set, rule format, backup format, and CLI commands.

### How large is the codebase?

35 production source files, 14,545 lines of Python. 12 test files, 322 automated tests. 27 documentation files, 5,000+ lines. Zero external runtime dependencies.

---

## Installation and Setup

### Do I need to install Apotropaios to use it?

No. You can run directly from the project directory with no installation:
```bash
sudo python3 apotropaios.py detect
```
The `apotropaios.py` script adds the project root to `sys.path` automatically.

### Should I use pip3 or pip?

Always use `pip3` to ensure Python 3.x. The `pip` command may resolve to Python 2 on some systems. This was Lesson PY-005.

### Can I run Apotropaios in a Docker container?

Yes, but you need the `NET_ADMIN` capability and the appropriate kernel modules (ip_tables, nf_tables). Docker containers often lack these by default:
```bash
docker run --cap-add=NET_ADMIN --privileged -it python:3.12 bash
```

### Why does Apotropaios require Python 3.12+?

The codebase uses modern Python features that require 3.12+: `X | None` union syntax (PEP 604), `dict[str, str]` generic subscripts (PEP 585), `from __future__ import annotations` for postponed evaluation, and `StrEnum` (PEP 435 extension).

### How do I set up a development environment?

```bash
git clone https://github.com/Sandler73/Apotropaios-Firewall-Manager-Python.git
cd Apotropaios-Firewall-Manager-Python
make dev-setup
source .venv/bin/activate
make check    # Must pass: mypy --strict + 322 tests
```

---

## Usage and Operation

### How do I see verbose output?

Use the `--log-level` flag. The default console level is WARNING (only warnings and errors). Increase verbosity:
```bash
sudo python3 apotropaios.py detect --log-level info     # Informational
sudo python3 apotropaios.py detect --log-level debug    # Diagnostic
sudo python3 apotropaios.py detect --log-level trace    # Maximum detail
```

The log file (in `data/logs/`) always captures all levels regardless of the console setting.

### Where are log files stored?

In `data/logs/` relative to the project root. Each execution creates a timestamped log file (e.g., `apotropaios-2026-03-30T00-30-02.log`). Files are created with 0o600 permissions and require root access to read when run with sudo.

### How do I switch between firewall backends?

Use the `--backend` flag (works before or after the command):
```bash
sudo python3 apotropaios.py status --backend firewalld
sudo python3 apotropaios.py --backend nftables add-rule --dst-port 80 --action accept
```
Or in interactive mode: Firewall Management → Select backend.

### What is the difference between "status", "system-rules", and "list-rules"?

| Command | Shows | Scope |
|:--------|:------|:------|
| `status` | Service state -- running/stopped, enabled/disabled, version, binary path | Active backend + all backends summary |
| `system-rules` | Native firewall rules dump (iptables -L, nft list ruleset, etc.) | ALL rules in the backend, not just Apotropaios-tracked |
| `list-rules` | Apotropaios-tracked rules table with UUIDs, states, parameters | Only rules created through this framework |

### Can I use --log-level and --backend after the command name?

Yes. Global options are position-independent. Both of these work:
```bash
sudo python3 apotropaios.py --log-level info detect
sudo python3 apotropaios.py detect --log-level info
```

---

## Rules and Actions

### What are compound actions?

Actions like `log,drop` that combine a non-terminal action (LOG) with a terminal action (DROP). Apotropaios handles these per-backend: iptables creates two separate rules (LOG is non-terminating), nftables combines in one expression (`log drop`), firewalld uses rich rule syntax.

### Can I combine two terminal actions like `accept,drop`?

No. A packet can only have one terminal fate. The validator rejects double-terminal combinations. Valid: `log,drop`, `log,accept`, `log,reject`. Invalid: `accept,drop`, `drop,reject`.

### What are temporary rules?

Rules with a TTL (time-to-live) that auto-expire after the specified duration. Create with `--duration temporary --ttl 7200` (2 hours). Valid TTL range: 60 seconds (1 minute) to 2,592,000 seconds (30 days).

The ExpiryMonitor daemon (30-second interval, interactive mode only) auto-deactivates expired rules and prints near-expiry alerts.

### How are rules tracked across reboots?

Each rule is assigned a UUID and stored in the persistent pipe-delimited index file (`data/rules/rule_index.dat`). The index survives reboots. However, the actual firewall rules depend on the backend's native persistence mechanism (e.g., iptables-save/restore, firewalld --permanent).

### Can I import rules from a file?

Yes. Create a key=value format file (see [USAGE_GUIDE.md](USAGE_GUIDE.md)) and import:
```bash
sudo python3 apotropaios.py import rules.conf --dry-run    # Validate first
sudo python3 apotropaios.py import rules.conf               # Apply
```

### What connection tracking states are supported?

Five states: `new` (first packet of new connection), `established` (existing connection), `related` (related to existing connection, e.g., FTP data), `invalid` (no known connection), `untracked` (excluded from tracking). Comma-separated: `--conn-state new,established,related`.

### How does rate limiting work?

Per-rule rate limiting controls packet frequency: `--limit 5/minute --limit-burst 10`. Translated to: `-m limit` (iptables), `limit rate` (nftables), `limit value=` (firewalld rich rules).

---

## Backends and Compatibility

### Which backend should I use?

- **iptables**: Most widely available, best documented, works everywhere. Choose for maximum compatibility.
- **nftables**: Modern replacement for iptables. Cleaner syntax, better performance for complex rulesets. Choose if your distribution defaults to nftables.
- **firewalld**: Zone-based management. Choose if you need zone awareness or use RHEL/Fedora.
- **ufw**: Simplest syntax. Choose if you want minimal complexity.
- **ipset**: For managing IP address sets. Choose for blocklist/allowlist management.

### Can I use multiple backends simultaneously?

Rules are tagged with the backend used to create them. You can switch backends between rule creation operations. When deactivating or removing rules, Apotropaios automatically routes to the correct backend regardless of the currently active one.

### Does Apotropaios work with firewalld zones?

Yes. The firewalld backend is zone-aware. Specify a zone with `--zone public` (or any valid zone name). The default zone is `public`. Zone-specific operations are available in the interactive menu.

---

## Security

### Is Apotropaios safe to use in production?

The framework passes 322 automated tests and mypy --strict with zero errors, and has completed multiple internal security audit passes. It has not undergone independent third-party security audit. See [SECURITY.md](SECURITY.md) and the LICENSE for full disclaimers.

### How does Apotropaios prevent command injection?

Three independent layers: (1) 27 whitelist validators reject shell metacharacters at input; (2) `sanitize_input()` whitelist-filters all input as defense-in-depth; (3) all subprocess calls use list-form arguments (never `shell=True`). Even if layers 1 and 2 both fail, list-form subprocess prevents shell interpretation of the input.

### Are passwords logged?

No. The 4-family `LogSanitizer` masks passwords, tokens, API keys, secrets, and authorization headers in key-value, quoted, JSON, and HTTP header formats before they reach any log handler. 11 sensitive field name keywords are recognized.

### What CWE vulnerabilities are tested?

CWE-78 (OS Command Injection), CWE-22 (Path Traversal), CWE-79 (Cross-Site Scripting), CWE-117 (Log Injection), CWE-20 (Improper Input Validation). See [SECURITY.md](SECURITY.md) for the full CWE coverage table.

---

## Backup and Recovery

### What does a backup contain?

A compressed tar.gz archive with: per-backend configuration exports (iptables-save output, nft ruleset, firewalld zone config, etc.), rule index file, rule state file, and a JSON manifest with metadata (timestamp, version, backend, label, file checksums). A SHA-256 checksum sidecar is generated alongside.

### What are immutable snapshots?

Backups protected with `chattr +i` (Linux immutable attribute) that cannot be modified or deleted without first removing the immutable flag (`chattr -i`). SHA-256 integrity verification detects any tampering. Requires ext2/3/4/btrfs filesystem. Created via the interactive menu: Backup & Recovery → Create immutable snapshot.

### How many backups are retained?

20 by default (configurable via `Backup.MAX_RETAINED` in `core/constants.py`). After each new backup, the oldest archives beyond the retention limit are automatically deleted.

### Is a safety backup created before restore?

Yes. `restore_backup()` always creates a pre-restore backup before applying the restoration. This allows rollback if the restore goes wrong.

---

## Logging and Debugging

### Why is the console output so quiet by default?

The default console level is WARNING to provide clean, user-friendly output. Most users don't want to see framework initialization noise. Use `--log-level info` for verbose output. The log file always captures everything (TRACE level and above).

### What is a correlation ID?

An 8-byte hex string (e.g., `c4015d9f`) generated for each execution. It appears in every log entry, enabling log correlation when multiple processes write to the same log directory. Generated via `secrets.token_hex(8)`.

### How do I find errors that occurred during a command?

Check the most recent log file:
```bash
sudo cat $(ls -t data/logs/*.log | head -1) | grep -E '\[ERROR\]|\[CRITICAL\]|\[WARNING\]'
```

### Why do log files require sudo to read?

Log files are created with 0o600 permissions (owner read/write only) when run as root via sudo. This is intentional security behavior -- log files may contain operational details that should not be world-readable.

---

## Development and Contributing

### How do I run the tests?

```bash
make check         # Full CI: mypy --strict + 322 tests
make test-quick    # Unit tests only (fast feedback)
make test-report   # Per-file breakdown
make security-scan # Static pattern analysis
```

### What is mypy --strict?

mypy is a static type checker for Python. `--strict` mode enforces the most rigorous type checking: no `Any` types, no untyped function signatures, no missing return types. The framework passes with zero errors across all 35 source files.

### How do I add a new firewall backend?

1. Create `apotropaios/firewall/newbackend.py`
2. Subclass `FirewallBackend` from `base.py` and implement all 12 abstract methods
3. Register at module level: `register_backend(_instance)`
4. Add to `SUPPORTED_FIREWALLS` in `constants.py`
5. Add detection logic in `fw_detect.py`
6. Import in `cli.py` `_initialize()` function
7. Add tests and update documentation
8. `make check` must pass

See [DEVELOPMENT_GUIDE.md](DEVELOPMENT_GUIDE.md) for full details.


**Q: What does Ctrl+C do?**

Inside the interactive menu, Ctrl+C aborts the operation or prompt in progress and returns to the menu (the Install & Update submenu recovers in place); it does not terminate the application. In headless CLI use, Ctrl+C runs the cleanup stack and exits with status 130. Package install and update operations cannot block on hidden prompts and are bounded by a 300-second timeout.
