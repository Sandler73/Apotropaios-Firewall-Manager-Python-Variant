# Troubleshooting Guide — Apotropaios Firewall Manager (Python Variant)

Guide to diagnosing and resolving issues across installation, runtime, backends, rules, backup, logging, and the interactive menu.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Runtime Errors](#runtime-errors)
- [Firewall Backend Issues](#firewall-backend-issues)
- [Rule Management Issues](#rule-management-issues)
- [Backup and Recovery Issues](#backup-and-recovery-issues)
- [Logging Issues](#logging-issues)
- [Interactive Menu Issues](#interactive-menu-issues)
- [Performance Issues](#performance-issues)
- [Diagnostic Commands](#diagnostic-commands)

---

## Installation Issues

### pip3 install fails with "Multiple top-level packages discovered"

**Symptom**: `pip3 install .` fails with setuptools package discovery error.

**Root Cause**: setuptools auto-discovers `data/`, `tests/`, `docs/` as Python packages alongside `apotropaios/` in flat-layout.

**Fix**: Ensure `pyproject.toml` has explicit package discovery:
```toml
[tool.setuptools.packages.find]
include = ["apotropaios*"]
exclude = ["tests*", "data*", "docs*", "tasks*", "conf*"]
```

**Lesson**: PY-009 — Always configure explicit package discovery in `pyproject.toml` for projects with non-package top-level directories.

### pip3 install fails with license deprecation warning

**Symptom**: Warning about `project.license` as TOML table being deprecated.

**Root Cause**: Older pyproject.toml format used `license = {text = "MIT"}`.

**Fix**: Use SPDX format: `license = "MIT"` (simple string). Remove deprecated `License :: OSI Approved :: MIT License` classifier.

### Python version too old

**Symptom**: `SyntaxError` on type hints like `dict[str, str]` or `X | None`.

**Root Cause**: Apotropaios requires Python 3.12+ for PEP 604 union syntax and PEP 585 generic subscripts.

**Fix**: Check version with `python3 --version`. Upgrade via package manager, pyenv, or deadsnakes PPA.

### venv creation fails

**Symptom**: `python3 -m venv .venv` fails with "No module named venv".

**Root Cause**: The `venv` module is packaged separately on some distributions.

**Fix**:
```bash
sudo apt install python3-venv         # Debian/Ubuntu/Kali
sudo dnf install python3-venv         # RHEL family
```

### "ModuleNotFoundError: No module named 'apotropaios'"

**Symptom**: `python3 -m apotropaios` fails with import error.

**Root Cause**: Not running from the project root, or package not installed.

**Fix**: Use `python3 apotropaios.py` (which adds the project root to `sys.path`), or install via `pip3 install .`.

---

## Runtime Errors

### "No firewall backend selected"

**Symptom**: Commands fail with "No backend selected. Use --backend NAME."

**Root Cause**: Auto-detection found no installed firewalls matching the supported list (iptables, nftables, firewalld, ufw).

**Fix**: Either install a firewall (`sudo python3 apotropaios.py install iptables`) or specify explicitly (`sudo python3 apotropaios.py status --backend iptables`).

### "Permission denied" on any firewall operation

**Symptom**: Commands fail with permission errors from subprocess.

**Root Cause**: Firewall operations (iptables, nft, firewall-cmd, etc.) require root privileges because they modify kernel-level packet filtering rules.

**Fix**: Always use `sudo`:
```bash
sudo python3 apotropaios.py detect
```

### "Protocol not supported" on iptables operations

**Symptom**: `iptables: Failed to initialize nft: Protocol not supported`

**Root Cause**: Running in a container or VM without the netfilter kernel module loaded. Modern iptables uses the nf_tables backend by default.

**Fix**: Load the kernel modules on the host:
```bash
sudo modprobe ip_tables
sudo modprobe iptable_filter
sudo modprobe nf_tables
```

For Docker containers, use `--cap-add=NET_ADMIN` or `--privileged`.

### Command output appears empty

**Symptom**: Running a command produces no visible output (or only warnings).

**Root Cause**: Default console log level is WARNING. Framework initialization messages (INFO level) are suppressed for clean output.

**Fix**: Use `--log-level info` or `--log-level debug` for verbose output:
```bash
sudo python3 apotropaios.py detect --log-level info
```

The log file (in `data/logs/`) always captures all levels regardless of the console setting.

### "--log-level" or "--backend" not recognized

**Symptom**: argparse reports "unrecognized arguments" for global options.

**Root Cause**: This was fixed in the current version. Global options are pre-extracted before argparse parsing and work in any position.

**Fix**: Ensure you're running the latest version. Global options work before or after the command:
```bash
sudo python3 apotropaios.py detect --log-level info    # Works
sudo python3 apotropaios.py --log-level info detect    # Also works
```

---

## Firewall Backend Issues

### firewalld: "FirewallD is not running"

**Symptom**: firewalld commands fail because the service is not active.

**Fix**:
```bash
sudo systemctl start firewalld
sudo systemctl enable firewalld
```

### nftables: "nft: command not found"

**Symptom**: nftables backend selected but `nft` binary not installed.

**Fix**: `sudo apt install nftables` (Debian/Ubuntu), `sudo dnf install nftables` (RHEL), `sudo pacman -S nftables` (Arch).

### ufw: "ERROR: You need to be root to run this script"

**Symptom**: UFW operations fail even with sudo.

**Root Cause**: In some containers, ufw requires additional capabilities or full root.

**Fix**: Ensure running with full root: `sudo -E python3 apotropaios.py status`.

### ipset: "Set cannot be destroyed: it is in use by a kernel component"

**Symptom**: ipset destroy fails because iptables rules reference the set.

**Root Cause**: iptables rules referencing the set must be removed first.

**Fix**: Apotropaios automatically removes iptables references before destroying sets via `_remove_iptables_refs()`. If manual cleanup is needed:
```bash
sudo iptables -L -n --line-numbers | grep match-set
sudo iptables -D INPUT <line_number>
```

### Backend auto-selection picks wrong firewall

**Symptom**: Framework auto-selects iptables when you want firewalld.

**Root Cause**: Auto-selection preference order is: iptables → nftables → firewalld → ufw (first installed wins).

**Fix**: Use `--backend` to override:
```bash
sudo python3 apotropaios.py status --backend firewalld
```

Or select via interactive menu: Firewall Management → Select backend.

### firewalld reset doesn't clear all rules

**Symptom**: After reset, some firewalld rules remain.

**Root Cause**: Earlier versions only reset the default zone. The fix (Lesson #10) iterates ALL zones.

**Fix**: Ensure you're running the latest version. The `reset()` method now calls `firewall-cmd --zone=<z> --remove-rich-rule=...` for every zone.

---

## Rule Management Issues

### Rule created but not visible in system-rules

**Symptom**: `list-rules` shows the rule but `system-rules` does not.

**Root Cause**: Rule application to the backend failed (subprocess error) but the rule was still indexed. Check the log file for the actual backend error.

**Fix**: Remove the orphaned rule from the index:
```bash
sudo python3 apotropaios.py remove-rule <UUID>
```

### "Rule not found" when removing by UUID

**Symptom**: `remove-rule` fails with `RuleNotFoundError`.

**Root Cause**: The UUID is not in the rule index. The rule may have been manually removed from the backend, or the index file was corrupted.

**Fix**: List rules to verify available UUIDs:
```bash
sudo python3 apotropaios.py list-rules
```

### Temporary rule not expiring

**Symptom**: Temporary rule remains active past its TTL.

**Root Cause**: The ExpiryMonitor daemon thread only runs during interactive menu mode (30-second check interval). CLI commands execute and exit — no background monitoring.

**Fix**: Use the interactive menu for sessions with temporary rules, or periodically check with:
```bash
sudo python3 apotropaios.py list-rules   # Check rule states manually
```

### Import file validation fails

**Symptom**: Import rejects rules that appear valid.

**Root Cause**: Import validates every field against the framework's 27 validators. Common issues: missing required fields, shell metacharacters in description, port out of range, invalid protocol.

**Fix**: Use `--dry-run` to identify which rules fail and why:
```bash
sudo python3 apotropaios.py import rules.conf --dry-run
```

### Compound action "drop,accept" rejected

**Symptom**: `ValidationError: Cannot combine multiple terminal actions`

**Root Cause**: Correct behavior. A packet can have only one terminal fate. `drop` and `accept` are both terminal actions.

**Fix**: Use `log,drop` or `log,accept` — combine one non-terminal (log) with one terminal.

### Rule deactivated but still blocking traffic

**Symptom**: After deactivating a rule, traffic is still being blocked.

**Root Cause**: The backend removal may have partially failed (e.g., the rule was modified manually). Or another rule with the same match criteria exists.

**Fix**: Check native rules to see what's actually in the kernel:
```bash
sudo python3 apotropaios.py system-rules
```

---

## Backup and Recovery Issues

### Backup file checksum verification fails

**Symptom**: Restore refuses to proceed due to checksum mismatch.

**Root Cause**: The `.sha256` sidecar file does not match the archive. The backup may have been modified, corrupted during transfer, or the sidecar regenerated incorrectly.

**Fix**: Regenerate the checksum: `sha256sum backup.tar.gz > backup.tar.gz.sha256`

### Immutable snapshot cannot be modified or deleted

**Symptom**: `rm: cannot remove 'file': Operation not permitted` even as root.

**Root Cause**: `chattr +i` (immutable attribute) was set on the file. This attribute prevents all modification, even by root.

**Fix**: Remove the immutable attribute first: `sudo chattr -i <file>`

### Restore fails with "unsafe path in archive"

**Symptom**: Restore rejects the archive with a path traversal warning.

**Root Cause**: The archive contains entries with `..` components or absolute paths. This is a security check — malicious archives could overwrite system files.

**Fix**: Recreate the backup from a trusted state. Do not use archives from untrusted sources.

### Restore fails with "pre-restore backup failed"

**Symptom**: Restore creates a safety backup before applying, but that backup creation fails.

**Root Cause**: Usually a permissions or disk space issue in the backup directory.

**Fix**: Ensure `data/backups/` exists with 0o700 permissions and sufficient disk space.

---

## Logging Issues

### Log file not created

**Symptom**: No log file appears in `data/logs/`.

**Root Cause**: The log directory could not be created (permissions) or path traversal was detected in the directory path.

**Fix**: Ensure the data directory is writable:
```bash
sudo mkdir -p data/logs && sudo chmod 700 data/logs
```

### Log file locked (requires elevated privileges to read)

**Symptom**: Cannot read log files without sudo.

**Root Cause**: Log files are created with 0o600 permissions owned by root (when run with sudo). This is intentional security behavior — log files may contain operational details that should not be world-readable.

**Fix**: Read with sudo:
```bash
sudo cat data/logs/apotropaios-*.log
sudo tail -50 $(ls -t data/logs/*.log | head -1)
```

### Sensitive data appearing in logs

**Symptom**: Concern about passwords or tokens appearing in log files.

**Root Cause**: The 4-family LogSanitizer should mask these automatically using 11 sensitive field name keywords.

**Fix**: If a field name is not being masked, it may not be in the sanitizer's keyword list. The current list is: password, passwd, secret, token, key, api_key, apikey, access_token, auth, authorization, credential, private_key, api_secret, client_secret. Additional keywords can be added to the `_SENSITIVE_KEYS` set in `core/logging.py`.

### Console output too verbose / too quiet

**Symptom**: Too much framework noise on console, or no output at all.

**Root Cause**: Default console level is WARNING. INFO and below are suppressed.

**Fix**: Adjust with `--log-level`:
```bash
# Maximum detail
sudo python3 apotropaios.py detect --log-level trace

# Informational (recommended for debugging)
sudo python3 apotropaios.py detect --log-level info

# Errors only
sudo python3 apotropaios.py detect --log-level error

# Suppress all console output
sudo python3 apotropaios.py detect --log-level none
```

The log FILE always captures all levels regardless of console setting.

---

## Interactive Menu Issues

### Menu launches but input not working

**Symptom**: Menu displays but keypresses are not registered.

**Root Cause**: stdin may be redirected (piping input) or the terminal is not interactive.

**Fix**: Run interactively without piping: `sudo python3 apotropaios.py --interactive`

### Cancel keywords not working

**Symptom**: Typing "q" at a prompt does not cancel.

**Root Cause**: Cancel detection is case-insensitive and trims whitespace. Recognized keywords: `q`, `quit`, `cancel`, `back`, `b`.

**Fix**: Ensure you are typing one of the exact keywords. Ctrl+C also works as a cancel (caught by the signal handler, triggers clean shutdown).

### ExpiryMonitor alerts not appearing

**Symptom**: Temporary rules expire silently without console alerts.

**Root Cause**: The ExpiryMonitor daemon thread runs only during interactive menu mode with a 30-second check interval. CLI commands exit immediately.

**Fix**: Use the interactive menu for sessions with temporary rules. The monitor alerts for rules expiring within 10 minutes.

### Menu "System Information" shows incomplete data

**Symptom**: OS or firewall information missing.

**Root Cause**: Detection may have partially failed (e.g., a binary exists but is not functional).

**Fix**: Run detection directly for full diagnostic output:
```bash
sudo python3 apotropaios.py detect --log-level debug
```

---

## Performance Issues

### Slow startup

**Symptom**: Framework takes several seconds to start.

**Root Cause**: During initialization, all 5 firewall backends are probed via subprocess calls (checking binary existence, version, systemd status). Each call has a 5-second timeout.

**Fix**: This is expected behavior. Use `--log-level info` to see which step is slow. If a backend is timing out, it may have a hung service. Specify `--backend` to skip auto-detection.

### Large rule index loading slowly

**Symptom**: Framework startup is slow with hundreds of tracked rules.

**Root Cause**: The pipe-delimited index file is parsed line-by-line. Each rule ID is validated.

**Fix**: The 10MB index file size limit prevents unbounded growth. For very large rule sets (500+ rules), consider periodic cleanup of deactivated/expired rules.

---

## Diagnostic Commands

```bash
# System scan with maximum diagnostic detail
sudo python3 apotropaios.py detect --log-level trace

# Check Python version
python3 --version

# Check installed firewalls (quick)
which iptables nft firewall-cmd ufw ipset 2>/dev/null

# Check all dependencies (full check)
make check-deps

# View last log file
sudo cat $(ls -t data/logs/*.log 2>/dev/null | head -1)

# View recent log entries
sudo tail -100 $(ls -t data/logs/*.log 2>/dev/null | head -1)

# Check kernel version (for module compatibility)
uname -r

# Check available kernel modules
lsmod | grep -E 'ip_tables|nf_tables|iptable_filter'

# Full quality check (tests + type check)
make check

# Project statistics
make metrics
```
