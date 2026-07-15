# Apotropaios — Usage Guide

Complete reference for all CLI commands, interactive menu operations, rule creation, and advanced features.

## Table of Contents

1. [Running Apotropaios](#running-apotropaios)
2. [Interactive Menu Mode](#interactive-menu-mode)
3. [CLI Mode](#cli-mode)
4. [Per-Command Help](#per-command-help)
5. [Managing Firewall Backends](#managing-firewall-backends)
6. [Creating Firewall Rules](#creating-firewall-rules)
7. [Compound Actions](#compound-actions)
8. [Connection Tracking](#connection-tracking)
9. [Rate Limiting](#rate-limiting)
10. [Rule Lifecycle](#rule-lifecycle)
11. [Temporary Rules with TTL](#temporary-rules-with-ttl)
12. [Importing and Exporting Rules](#importing-and-exporting-rules)
13. [Backup and Recovery](#backup-and-recovery)
14. [Quick Actions](#quick-actions)
15. [Logging and Troubleshooting](#logging-and-troubleshooting)

---

## Running Apotropaios

Apotropaios requires root privileges for firewall operations.

**Direct execution (no install):**
```bash
sudo python3 apotropaios.py [OPTIONS] COMMAND [ARGS]
```

**Module execution (after pip install):**
```bash
sudo python3 -m apotropaios [OPTIONS] COMMAND [ARGS]
```

**Interactive mode:**
```bash
sudo python3 apotropaios.py --interactive
```

**Global options (position-independent — work before or after the command):**

| Option | Description |
|:-------|:------------|
| `--help`, `-h` | Show global help (or per-command help if after a command) |
| `--version`, `-v` | Show version and exit |
| `--backend BACKEND` | Override auto-detected backend (iptables, nftables, firewalld, ufw, ipset) |
| `--log-level LEVEL` | Set console verbosity: trace, debug, info, warning (default), error, critical |
| `--interactive` | Launch the interactive menu (mutually exclusive with commands) |
| `--non-interactive` | Disable interactive prompts. Destructive commands such as `reset` skip their confirmation prompt and proceed, so unattended automation never blocks on terminal input. |

**Examples:**
```bash
sudo python3 apotropaios.py detect --log-level trace      # Maximum verbosity
sudo python3 apotropaios.py --log-level error status       # Errors only
sudo python3 apotropaios.py --backend nftables add-rule --dst-port 80 --action accept
```

---

## Interactive Menu Mode

Launch the interactive menu using the `--interactive` flag:

```bash
sudo python3 apotropaios.py --interactive                        # Preferred
sudo python3 apotropaios.py --interactive --backend iptables     # Pre-select backend
sudo python3 apotropaios.py --interactive --log-level trace      # Debug mode
```

**Backward compatibility:** `sudo python3 apotropaios.py menu` and `sudo python3 apotropaios.py` (no arguments) also launch the interactive menu.

**Mutual exclusivity:** The `--interactive` flag cannot be combined with CLI commands (e.g., `--interactive add-rule` is an error) or `--non-interactive`.

The main menu presents numbered options. Enter the number and press Enter.

**Main Menu Options:**

1. **Firewall Management** — Select and configure firewall backends. Show service status (running/enabled/version). Start, stop, reset firewalls. View current system rules.
2. **Rule Management** — Create rules through a guided wizard with cancel support (type `q`, `quit`, `cancel`, or `back` at any prompt). List Apotropaios-tracked rules. List native system rules for the active backend. Remove, activate, deactivate rules by UUID. Import/export with dry-run support.
3. **Quick Actions** — Block-all or allow-all traffic with confirmation prompts showing the active backend name. Reset firewall to defaults.
4. **Backup & Recovery** — Create timestamped backups with labels. List available backups. Restore from archive. Create immutable snapshots. Verify snapshot integrity. List snapshots.
5. **System Information** — Full OS detection display (name, ID, version, family, package manager, supported status). All 5 firewall backends with version, running/stopped, enabled/disabled status. Active backend indicator. Tracked rule count.
6. **Install & Update** — Install or update firewall packages via apt/dnf/pacman.
7. **Help & Documentation** — 8-option submenu: general usage, rule management help, backup/recovery help, import/export help, detection help, install/update help, all-commands reference.
8. **Exit** — Clean shutdown with resource cleanup.

### Rule Creation Wizard

The interactive wizard guides you through the rule creation process:

**Step 1: Rule Parameters** — Direction (inbound/outbound/forward), protocol (tcp/udp/icmp/all), destination port, source IP, action (including compound like `log,drop`).

**Step 2: Duration** — Permanent or temporary. If temporary, enter TTL in seconds (60-2592000).

**Step 3: Description** — Human-readable description (max 256 chars).

At each step, type `q`, `quit`, `cancel`, `back`, or `b` to abort without applying.

### ExpiryMonitor

While the interactive menu is active, a **background daemon thread** runs every 30 seconds:
- Checks all temporary rules for TTL expiry
- Auto-deactivates expired rules
- Prints console alerts for rules expiring within 10 minutes
- Shows rule ID, description, and time remaining

---

## CLI Mode

Every operation available in the menu is also accessible via CLI commands.

### Detection and Status

```bash
sudo python3 apotropaios.py detect              # OS and firewall detection
sudo python3 apotropaios.py status              # Service state (running/enabled/version)
sudo python3 apotropaios.py system-rules        # Native firewall rules dump
```

**Important distinction:**
- `status` — Shows service state: running/stopped, enabled/disabled, version, binary path, all backends summary
- `system-rules` — Dumps actual native rules (iptables -L, nft list ruleset, etc.) — ALL rules, not just ours
- `list-rules` — Shows only Apotropaios-tracked rules from the rule index

### Rule Operations

```bash
sudo python3 apotropaios.py list-rules                           # List tracked rules
sudo python3 apotropaios.py add-rule [OPTIONS]                   # Create a new rule
sudo python3 apotropaios.py remove-rule <UUID>                   # Remove by UUID
sudo python3 apotropaios.py activate-rule <UUID>                 # Re-apply a deactivated rule
sudo python3 apotropaios.py deactivate-rule <UUID>               # Remove from firewall, keep in index
```

### Import/Export

```bash
sudo python3 apotropaios.py import /path/to/rules.conf           # Import rules
sudo python3 apotropaios.py import /path/to/rules.conf --dry-run # Validate only
sudo python3 apotropaios.py export /path/to/output.conf          # Export tracked rules
```

### Backup and Recovery

```bash
sudo python3 apotropaios.py backup <label>                       # Create labeled backup
sudo python3 apotropaios.py restore /path/to/backup.tar.gz       # Restore from archive
```

### Quick Actions

```bash
sudo python3 apotropaios.py block-all                            # Drop all traffic
sudo python3 apotropaios.py allow-all                            # Remove all restrictions
```

### Firewall Installation

```bash
sudo python3 apotropaios.py install nftables                     # Install a backend
sudo python3 apotropaios.py update iptables                      # Update a backend
```

---

## Per-Command Help

Every command has detailed help with synopsis, options, examples, tips, and related commands:

```bash
python3 apotropaios.py help                    # Global help (no root needed)
python3 apotropaios.py --help                  # Same as help
python3 apotropaios.py add-rule --help         # Full add-rule option reference
python3 apotropaios.py backup --help           # Backup contents and retention
python3 apotropaios.py import --help           # Config file format reference
```

Per-command help **bypasses framework initialization** for instant response — no root required, no firewall detection delay.

All 18 commands have dedicated help: `menu`, `help`, `detect`, `status`, `add-rule`, `remove-rule`, `activate-rule`, `deactivate-rule`, `list-rules`, `system-rules`, `import`, `export`, `backup`, `restore`, `block-all`, `allow-all`, `install`, `update`.

---

## Managing Firewall Backends

Apotropaios auto-detects installed firewalls and selects the first available as the active backend (preference order: iptables → nftables → firewalld → ufw). Override with `--backend`:

```bash
sudo python3 apotropaios.py --backend nftables add-rule --dst-port 80 --action accept
sudo python3 apotropaios.py status --backend firewalld
```

In interactive mode, use **Firewall Management > Select backend** to switch.

Rules are tagged with the backend used to create them. When removing or deactivating rules, Apotropaios automatically routes to the correct backend regardless of the currently active one.

---

## Creating Firewall Rules

### add-rule Options

| Option | Description | Default |
|:-------|:------------|:--------|
| `--direction DIR` | Traffic direction: inbound, outbound, forward | inbound |
| `--protocol PROTO` | Protocol: tcp, udp, icmp, icmpv6, sctp, all | tcp |
| `--src-ip IP` | Source IP address or CIDR notation | any |
| `--dst-ip IP` | Destination IP address or CIDR notation | any |
| `--src-port PORT` | Source port or range (e.g., 1024-65535) | any |
| `--dst-port PORT` | Destination port or range (e.g., 443, 8080-8090) | any |
| `--action ACTION` | Single or compound: accept, drop, reject, log, log,drop | accept |
| `--interface IFACE` | Network interface (e.g., eth0, ens33) | any |
| `--conn-state STATES` | Connection tracking: new,established,related,invalid | — |
| `--log-prefix TEXT` | Log message prefix (max 29 chars, when action includes log) | auto |
| `--log-level LEVEL` | Syslog level: emerg/alert/crit/err/warning/notice/info/debug | — |
| `--limit RATE` | Rate limit: N/second, N/minute, N/hour, N/day | — |
| `--limit-burst N` | Burst packets before rate limit applies | — |
| `--duration TYPE` | permanent or temporary | permanent |
| `--ttl SECONDS` | TTL for temporary rules (60-2592000) | — |
| `--description TEXT` | Human-readable description (max 256 chars) | — |
| `--zone ZONE` | Firewalld zone name | public |
| `--chain CHAIN` | iptables/nftables chain (auto-set from direction) | auto |
| `--table TABLE` | iptables table (filter/nat/mangle/raw) or nftables table | filter |

### Basic Examples

```bash
# Allow HTTPS inbound
sudo python3 apotropaios.py add-rule --protocol tcp --dst-port 443 --action accept

# Block a specific IP
sudo python3 apotropaios.py add-rule --src-ip 10.0.0.50 --action drop --description "Block attacker"

# Allow DNS (temporary, 1 hour)
sudo python3 apotropaios.py add-rule --protocol udp --dst-port 53 --action accept \
    --duration temporary --ttl 3600

# Allow a port range
sudo python3 apotropaios.py add-rule --protocol tcp --dst-port 8080-8090 --action accept

# Outbound rule on specific interface
sudo python3 apotropaios.py add-rule --direction outbound --protocol tcp --dst-port 25 \
    --action reject --interface eth0 --description "Block SMTP outbound"
```

---

## Compound Actions

Rules can combine non-terminal actions (like `log`) with a terminal action (like `drop`, `accept`, `reject`). Use comma-separated syntax:

```bash
# Log and drop — the most common compound action
sudo python3 apotropaios.py add-rule --src-ip 10.0.0.0/8 --action log,drop \
    --log-prefix "BLOCKED: " --log-level warning

# Log and accept
sudo python3 apotropaios.py add-rule --protocol tcp --dst-port 22 --action log,accept \
    --log-prefix "SSH: "

# Log and reject
sudo python3 apotropaios.py add-rule --protocol tcp --dst-port 23 --action log,reject
```

### How Backends Handle Compound Actions

Each backend translates compound actions into its native equivalent:

| Backend | Compound Action Translation |
|:--------|:----------------------------|
| **iptables** | Creates two separate rules: LOG rule first, then terminal rule. This is correct because iptables LOG is non-terminating. |
| **nftables** | Combines in a single expression: `log prefix "..." drop`. nft handles this natively. |
| **firewalld** | Rich rule with log clause: `rule ... log prefix="..." level="..." drop`. |
| **ufw** | Extracts the terminal action for the ufw verb; enables logging separately via `ufw logging on`. |

### Validation Rules

- At most **one terminal action** per compound: `log,drop` is valid; `drop,accept` is invalid.
- Terminal actions: accept, drop, reject, masquerade, snat, dnat, return.
- Non-terminal actions: log.
- Log options (`--log-prefix`, `--log-level`) only apply when the action includes `log`.

---

## Connection Tracking

Connection tracking allows rules to match traffic based on the connection's state in the kernel's conntrack table:

```bash
# Allow established and related connections (stateful firewall baseline)
sudo python3 apotropaios.py add-rule --conn-state established,related --action accept

# Only match new connections on port 443
sudo python3 apotropaios.py add-rule --protocol tcp --dst-port 443 \
    --conn-state new --action accept

# Drop invalid packets
sudo python3 apotropaios.py add-rule --conn-state invalid --action drop
```

### Available States

| State | Description |
|:------|:------------|
| `new` | First packet of a new connection |
| `established` | Packet belongs to an existing, tracked connection |
| `related` | Packet starting a new connection related to an existing one (e.g., FTP data) |
| `invalid` | Packet that does not match any known connection |
| `untracked` | Packet explicitly excluded from connection tracking |

Multiple states can be comma-separated: `--conn-state new,established,related`.

### Backend Translation

| Backend | Implementation |
|:--------|:---------------|
| iptables | `-m conntrack --ctstate NEW,ESTABLISHED,RELATED` |
| nftables | `ct state new,established,related` |
| firewalld | Rich rule with connection state matching |
| ufw | Uses underlying iptables conntrack |

---

## Rate Limiting

Rate limiting controls how many packets matching a rule are processed per time unit. Useful for mitigating brute force, DDoS, and scan attacks:

```bash
# Limit SSH connections to 5 per minute
sudo python3 apotropaios.py add-rule --protocol tcp --dst-port 22 --action accept \
    --limit 5/minute --limit-burst 10

# Log excessive ICMP (ping flood mitigation)
sudo python3 apotropaios.py add-rule --protocol icmp --action log,accept \
    --limit 1/second --limit-burst 5 --log-prefix "ICMP-FLOOD: "

# Rate limit HTTP connections
sudo python3 apotropaios.py add-rule --protocol tcp --dst-port 80 --action accept \
    --limit 100/minute
```

### Rate Format

`N/unit` where unit is: `second`, `minute`, `hour`, or `day`.

`--limit-burst N` specifies how many packets are allowed before the rate limit takes effect.

### Backend Translation

| Backend | Implementation |
|:--------|:---------------|
| iptables | `-m limit --limit 5/minute --limit-burst 10` |
| nftables | `limit rate 5/minute burst 10 packets` |
| firewalld | Rich rule: `limit value="5/m"` |

---

## Rule Lifecycle

Every rule created through Apotropaios follows this lifecycle:

1. **Created** — Parameters validated (27 validators), UUID assigned, tracking comment generated (`apotropaios:<uuid>`)
2. **Applied** — Rule dispatched to the firewall backend (with compound action translation)
3. **Indexed** — Rule recorded in the persistent pipe-delimited index with 27 fields
4. **Active** — Rule is enforced by the firewall

From the active state, a rule can be:

- **Deactivated** — Removed from the firewall but retained in the index. Can be re-activated later with all original parameters.
- **Removed** — Deleted from both the firewall and the index permanently.
- **Expired** — Temporary rules automatically transition to inactive when their TTL expires.

### Rule Index Fields

Each indexed rule stores 27 fields: rule_id, backend, direction, action, protocol, src_ip, dst_ip, src_port, dst_port, interface, chain, table, table_family, zone, set_name, conn_state, log_prefix, log_level, limit, limit_burst, duration_type, ttl, description, state, created_at, activated_at, expires_at.

Use `list-rules` to see all tracked rules with their current state in a formatted table.

---

## Temporary Rules with TTL

Temporary rules are automatically deactivated after their TTL (time-to-live) expires.

```bash
# Block an IP for 30 minutes (1800 seconds)
sudo python3 apotropaios.py add-rule --src-ip 192.168.1.100 --action drop \
    --duration temporary --ttl 1800 --description "Temporary block"

# Allow testing port for 2 hours
sudo python3 apotropaios.py add-rule --protocol tcp --dst-port 8080 --action accept \
    --duration temporary --ttl 7200 --description "Testing window"
```

TTL range: 60 seconds (1 minute) to 2,592,000 seconds (30 days).

### Automatic Expiry Monitoring

In interactive mode, a **background expiry monitor** runs every 30 seconds and automatically deactivates rules when their TTL expires — no manual intervention required. The monitor also prints terminal alerts when a rule is within 10 minutes of expiring, showing the rule ID, description, and time remaining.

In CLI mode, expired rules are checked once at each command execution. For ongoing monitoring, use the interactive menu.

---

## Importing and Exporting Rules

### Export

```bash
# Export to specific path
sudo python3 apotropaios.py export /tmp/my-rules.conf
```

Export creates a key-value format file and a SHA-256 checksum sidecar (`.sha256`).

### Import

```bash
# Import from file
sudo python3 apotropaios.py import /tmp/my-rules.conf

# Dry-run — validate without applying
sudo python3 apotropaios.py import /tmp/my-rules.conf --dry-run
```

### Configuration File Format

```
# Lines starting with # are comments
# Blank lines separate rule blocks

direction=inbound
protocol=tcp
dst_port=443
action=accept
description=Allow HTTPS

direction=inbound
action=log,drop
src_ip=10.0.0.0/8
description=Log and block RFC1918

direction=inbound
action=accept
conn_state=established,related
description=Stateful baseline

direction=outbound
protocol=udp
dst_port=53
action=accept
duration_type=temporary
ttl=7200
description=Allow DNS 2h
```

### Supported Import Fields

`direction`, `action`, `protocol`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `duration_type`, `ttl`, `description`, `conn_state`, `log_prefix`, `log_level`, `limit`, `limit_burst`, `zone`, `table`, `chain`, `interface`

### SHA-256 Verification

If a `.sha256` sidecar file exists alongside the import file (e.g., `rules.conf.sha256`), the checksum is verified before processing. If verification fails, the import is aborted.

---

## Backup and Recovery

### Creating Backups

```bash
# CLI with descriptive label
sudo python3 apotropaios.py backup pre-deployment
```

The backup includes:
- All detected firewall configurations (iptables-save, nft list ruleset, etc.)
- Rule index and state files
- JSON manifest with metadata (timestamp, version, label, file checksums)
- Compressed with gzip, verified with SHA-256

### Restoring from Backup

```bash
sudo python3 apotropaios.py restore data/backups/apotropaios_backup_pre-deployment_2026-03-30.tar.gz
```

A pre-restore safety backup is automatically created before applying the restoration. All archive paths are validated for traversal attacks before extraction.

### Immutable Snapshots

Via the interactive menu (Backup & Recovery), immutable snapshots use `chattr +i` to prevent modification:

- Cannot be deleted, modified, or overwritten without removing the immutable attribute
- SHA-256 integrity file generated alongside
- Useful for production baselines and compliance auditing

### Backup Contents

| Component | What's Backed Up |
|:----------|:-----------------|
| iptables | `iptables-save` output |
| nftables | `nft list ruleset` output |
| firewalld | `firewall-cmd --list-all-zones` output |
| ufw | `ufw status verbose` output |
| ipset | `ipset save` output |
| Rule index | Pipe-delimited rule tracking data (27 fields per rule) |
| State data | TTL tracking, activation state |
| Manifest | JSON with timestamp, version, backend list, file checksums |

---

## Quick Actions

### Block All Traffic

```bash
sudo python3 apotropaios.py block-all
```

Sets all default policies to DROP (iptables) or creates deny-all rules (firewalld/ufw). The operation is tracked in the rule index with a UUID.

**Warning:** This will block ALL network traffic including SSH. Ensure you have out-of-band access (console, IPMI) before using on remote systems.

### Allow All Traffic

```bash
sudo python3 apotropaios.py allow-all
```

Removes all restrictions by flushing rules and setting default policies to ACCEPT. The operation is tracked in the rule index.

Both quick actions are available from the interactive menu under **Quick Actions**, with confirmation prompts showing the active backend name.

---

## Logging and Troubleshooting

### Log Location

Logs are written to `data/logs/` with ISO 8601 timestamps:

```
data/logs/apotropaios-2026-03-30T00-30-02.log
```

### Log Format

```
[2026-03-30T00:30:02.743Z] [INFO] [rule_engine] [cid:c4015d9f] Rule created: abc-def-123 | backend=iptables direction=inbound
```

Each entry includes: ISO 8601 UTC timestamp, severity level, component name, correlation ID, message, and optional structured context.

### Log Levels

From most to least verbose: `TRACE`, `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`

The default **console** level is `WARNING` — only warnings and errors appear. The **log file** always captures all levels (TRACE and above), regardless of console setting.

```bash
# Maximum diagnostic detail
sudo python3 apotropaios.py detect --log-level trace

# Informational messages
sudo python3 apotropaios.py detect --log-level info

# Production — warnings and above only (default)
sudo python3 apotropaios.py add-rule --dst-port 443 --action accept
```

### Log Rotation

Rotation occurs automatically when a log file exceeds 100MB. Up to 10 rotated files are retained. Oldest files are removed first.

### Security

- Sensitive data (passwords, tokens, API keys) is automatically masked in log output across 4 formats
- Control characters are stripped to prevent log injection
- Log files are created with 0o600 permissions (owner read/write only)
- Console handler removed before shutdown marker — no post-shutdown noise

### Diagnostic Commands

```bash
# System scan with maximum detail
sudo python3 apotropaios.py detect --log-level trace

# Check last log file
sudo ls -la data/logs/ | tail -3

# View recent log entries
sudo tail -50 $(ls -t data/logs/*.log | head -1)

# Check Python version
python3 --version

# Check installed firewalls
which iptables nft firewall-cmd ufw ipset 2>/dev/null

# Check all dependencies
make check-deps
```
