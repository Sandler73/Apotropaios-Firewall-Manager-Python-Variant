# Apotropaios -- Setup & Installation Guide

Installation and setup guide for, configuring, and verifying Apotropaios across all supported platforms.

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Quick Start (No Install)](#quick-start-no-install)
3. [Installation Methods](#installation-methods)
4. [Distribution-Specific Notes](#distribution-specific-notes)
5. [Configuration](#configuration)
6. [Post-Installation Setup](#post-installation-setup)
7. [Verifying Installation](#verifying-installation)
8. [Installing Firewall Backends](#installing-firewall-backends)
9. [Data Directory Structure](#data-directory-structure)
10. [Permissions and Security Hardening](#permissions-and-security-hardening)
11. [Container and Virtual Machine Notes](#container-and-virtual-machine-notes)
12. [Development Environment Setup](#development-environment-setup)
13. [Upgrading](#upgrading)
14. [Uninstallation](#uninstallation)
15. [Troubleshooting Installation Issues](#troubleshooting-installation-issues)

---

## System Requirements

### Minimum Requirements

- Python 3.12 or newer (for modern type annotation syntax)
- Linux operating system (see supported distributions below)
- Root access (for firewall operations)
- At least one supported firewall backend installed

### Supported Distributions

| Distribution | Version | Package Manager | Tested |
|:------------|:--------|:----------------|:-------|
| Ubuntu | 22.04 LTS, 24.04 LTS | apt | Yes |
| Kali Linux | Rolling (2024+) | apt | Yes |
| Debian | 11, 12 (Bookworm) | apt | Yes |
| Rocky Linux | 8, 9 | dnf | Yes |
| AlmaLinux | 8, 9 | dnf | Yes |
| Arch Linux | Rolling | pacman | Yes |

### Optional Dependencies

| Tool | Purpose | Required For |
|:-----|:--------|:-------------|
| pytest 8.0+ | Automated testing framework | Running tests (`make test`) |
| mypy 1.10+ | Static type checking | Type checking (`make typecheck`) |
| Git | Version control | Cloning, updates, development |
| `chattr` (e2fsprogs) | Filesystem attributes | Immutable backup snapshots |

**No external runtime dependencies** -- Apotropaios uses only the Python 3.12+ standard library. No pip packages are required at runtime. pytest and mypy are only needed for development and testing.

### Checking Python Version

```bash
python3 --version
# Output must show 3.12 or newer
# Python 3.12.3
```

If your Python is older than 3.12, upgrade it through your package manager or use pyenv/deadsnakes PPA before proceeding.

---

## Quick Start (No Install)

The fastest way to use Apotropaios. No pip install, no venv, no configuration needed:

```bash
# Clone the repository
git clone https://github.com/Sandler73/Apotropaios-Firewall-Manager-Python-Variant.git
cd Apotropaios-Firewall-Manager-Python

# Run directly -- no install required
sudo python3 apotropaios.py detect
sudo python3 apotropaios.py status
sudo python3 apotropaios.py --interactive
```

This works because `apotropaios.py` adds the project root to `sys.path` and delegates to the package entry point. All data directories are created automatically on first run.

---

## Installation Methods

Apotropaios supports three installation methods. Choose the one that fits your workflow.

### Method 1: Direct Execution (Recommended for Quick Use)

No installation at all. Run directly from the project root:

```bash
git clone https://github.com/Sandler73/Apotropaios-Firewall-Manager-Python-Variant.git
cd Apotropaios-Firewall-Manager-Python

# Run any command
sudo python3 apotropaios.py detect
sudo python3 apotropaios.py add-rule --dst-port 443 --action accept
sudo python3 apotropaios.py --interactive
sudo python3 apotropaios.py help
```

**Makefile shortcuts:**
```bash
make run CMD="detect"
make run CMD="status --backend iptables"
make run-interactive
make run-detect
make run-help
```

### Method 2: Virtual Environment (Recommended for Development)

Isolates dependencies in a project-local `.venv` directory. Does not touch system Python packages.

```bash
git clone https://github.com/Sandler73/Apotropaios-Firewall-Manager-Python-Variant.git
cd Apotropaios-Firewall-Manager-Python

# Create venv (one-time setup)
python3 -m venv .venv

# Activate venv
source .venv/bin/activate

# Install in editable mode with dev dependencies
pip3 install -e ".[dev]"

# Verify
python3 -m apotropaios --version
python3 -m apotropaios detect
python3 -m pytest tests/ -v --tb=short
python3 -m mypy apotropaios/ --strict --python-version 3.12

# Deactivate when done
deactivate
```

**Makefile shortcuts (venv auto-created if needed):**
```bash
make venv              # Create venv + install deps
make venv-test         # Run tests inside venv
make venv-typecheck    # Run mypy inside venv
make venv-check        # Full CI check inside venv
make venv-run CMD="detect"   # Run command inside venv
```

**Important notes about venv:**
- The venv only needs to be created once
- Makefile venv targets auto-activate -- no manual activation needed
- Firewall operations still require `sudo` even inside a venv
- When using `sudo` inside a venv, use the full venv Python path:
  ```bash
  sudo .venv/bin/python3 -m apotropaios detect
  ```

### Method 3: System Install (pip3)

Installs the package system-wide:

```bash
git clone https://github.com/Sandler73/Apotropaios-Firewall-Manager-Python-Variant.git
cd Apotropaios-Firewall-Manager-Python

# Minimal install (runtime only, no dev tools)
sudo pip3 install . --break-system-packages

# Full install with dev dependencies (pytest, mypy)
sudo pip3 install ".[dev]" --break-system-packages

# Development install (editable -- changes take effect immediately)
sudo pip3 install -e ".[dev]" --break-system-packages

# Now available system-wide
sudo python3 -m apotropaios detect
sudo python3 -m apotropaios --interactive
```

**Makefile shortcuts:**
```bash
make install           # Minimal install (runtime only)
make install-full      # Runtime + dev dependencies
make install-dev       # Editable mode + dev deps
```

### From Release Tarball

Three release packages are available for each version:

| Package | Contents | Use Case |
|:--------|:---------|:---------|
| `apotropaios-X.Y.Z.tar.gz` | Runtime: source, docs, Makefile | Production deployment |
| `apotropaios-X.Y.Z-full.tar.gz` | Runtime + tests, CI, tasks | Development, contributing |
| `apotropaios-X.Y.Z-venv.tar.gz` | Runtime + activate.sh, bin/ wrapper | Portable without system install |

**Standard install from tarball:**

```bash
# Download the release
wget https://github.com/.../apotropaios-<version>.tar.gz

# Verify checksum
wget https://github.com/.../SHA256SUMS.txt
sha256sum -c SHA256SUMS.txt

# Extract and run
tar -xzf apotropaios-<version>.tar.gz
cd apotropaios-<version>
sudo python3 apotropaios.py detect
```

**Venv package (portable, activate/deactivate):**

```bash
tar -xzf apotropaios-<version>-venv.tar.gz
cd apotropaios-<version>-venv

# Activate the environment
source activate.sh

# Now available as: sudo python3 apotropaios.py detect
# Or via wrapper:   sudo apotropaios detect

# Deactivate
apotropaios_deactivate
```

After activation, `APOTROPAIOS_HOME` is set, the shell prompt is prefixed with `(apotropaios)`, and the `bin/` directory is on PATH.

---

## Distribution-Specific Notes

### Ubuntu / Debian / Kali Linux

These distributions use `apt`. Python 3.12+ is available on Ubuntu 24.04+ and Kali 2024+. For Ubuntu 22.04, use the deadsnakes PPA:

```bash
# Ubuntu 22.04 -- install Python 3.12 via deadsnakes
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install python3.12 python3.12-venv

# All Debian-family -- install venv module if needed
sudo apt install python3-venv
```

**Kali Linux note:** Kali's rolling release model means Python versions change frequently. Verify with `python3 --version`.

### Rocky Linux 9 / AlmaLinux 9

RHEL-family distributions use `dnf`. Python 3.12 is available in AppStream:

```bash
# Standard installation
sudo dnf install python3.12

# In containers (minimal images):
sudo dnf install -y --allowerasing python3.12
```

### Arch Linux

```bash
sudo pacman -Sy python
# Arch rolling release always ships current Python
```

---

## Configuration

### Runtime Configuration

Apotropaios reads built-in defaults from `core/constants.py` at import time and additionally loads an optional INI-format configuration file at startup. Every candidate file passes a trust gate before use -- it must be owned by root or the current effective user and must not be group- or world-writable -- so a tamperable file is skipped entirely rather than partially applied. Search order: `/etc/apotropaios/apotropaios.conf`, then `conf/apotropaios.conf` under the framework base directory, then the copy shipped inside the package. Setting precedence is command line > configuration file > built-in defaults. The file currently drives the console log level and the default firewall backend; other sections are parsed and reserved. The `APOTROPAIOS_BASE_DIR` environment variable overrides the framework base directory when it names an existing directory, relocating the `data/` tree (logs, rules, backups) and the project-local configuration lookup without touching the installation; an invalid override emits a warning and falls back to the default.

Override configuration at runtime via CLI flags:

```bash
# Set log level for a single run
sudo python3 apotropaios.py detect --log-level trace

# Select a specific backend
sudo python3 apotropaios.py status --backend firewalld
```

### Key Configuration Constants

| Setting | Default | Location | Override |
|:--------|:--------|:---------|:---------|
| Console log level | WARNING | `cli.py` | `--log-level LEVEL` |
| File log level | TRACE (all) | `logging.py` | Not overridable |
| Log rotation | 100MB × 10 files | `Security` class | Code constant |
| Subprocess timeout | 30 seconds | `Performance` class | Code constant |
| Expiry check interval | 30 seconds | `Performance` class | Code constant |
| Backup retention | 20 archives | `Backup` class | Code constant |
| TTL range | 60–2,592,000 sec | `TTLLimits` class | Code constant |
| Max input length | 4096 chars | `Security` class | Code constant |
| File permissions | 0o600 | `Security` class | Code constant |
| Directory permissions | 0o700 | `Security` class | Code constant |

---

## Post-Installation Setup

### First Run

On first run, Apotropaios will automatically:

1. Detect your operating system (distribution, version, family, package manager)
2. Scan for all installed firewall applications across all 5 supported backends
3. Create the data directory structure with secure permissions (0o700)
4. Initialize the logging subsystem with timestamped log files (0o600)
5. Initialize the rule index and state tracking files
6. Initialize the backup subsystem
7. Auto-select the first available firewall backend

```bash
# Recommended first command -- full system scan
sudo python3 apotropaios.py detect

# Create initial backup before making any changes
sudo python3 apotropaios.py backup initial-baseline
```

### Verifying Backend Selection

```bash
# Show which backend was auto-selected
sudo python3 apotropaios.py status

# Override if desired
sudo python3 apotropaios.py status --backend firewalld
```

---

## Verifying Installation

```bash
# Check version
python3 apotropaios.py --version

# Run detection
sudo python3 apotropaios.py detect

# Check dependencies
make check-deps

# Run full test suite
make check    # mypy --strict + 322 tests

# Verify installation (if pip-installed)
make verify
```

**Expected `make verify` output:**

```
==> Verifying installation...
  [1/4] Checking Python version...
    ✓ Python 3.12.3 (...)
  [2/4] Checking package import...
    ✓ Package importable
  [3/4] Checking mypy...
    ✓ mypy available
  [4/4] Checking pytest...
    ✓ pytest available
==> Verification complete
```

---

## Installing Firewall Backends

Apotropaios can install firewalls for you:

```bash
sudo python3 apotropaios.py install iptables
sudo python3 apotropaios.py install nftables
sudo python3 apotropaios.py install firewalld
sudo python3 apotropaios.py install ufw
sudo python3 apotropaios.py install ipset
```

### Manual Installation by Platform

**Ubuntu / Debian / Kali:**
```bash
sudo apt install iptables            # iptables
sudo apt install nftables            # nftables
sudo apt install firewalld           # firewalld
sudo apt install ufw                 # UFW (usually pre-installed)
sudo apt install ipset               # ipset
```

**Rocky Linux / AlmaLinux:**
```bash
sudo dnf install iptables-services   # iptables
sudo dnf install nftables            # nftables
sudo dnf install firewalld           # firewalld (usually pre-installed)
sudo dnf install ipset               # ipset
```

**Arch Linux:**
```bash
sudo pacman -S iptables              # iptables
sudo pacman -S nftables              # nftables
sudo pacman -S firewalld             # firewalld
sudo pacman -S ufw                   # UFW
sudo pacman -S ipset                 # ipset
```

After installing, re-run detection:
```bash
sudo python3 apotropaios.py detect
```

---

## Data Directory Structure

```
data/                        # Runtime data (gitignored, created automatically)
├── logs/                    # Timestamped log files (0o600 permissions)
│   ├── apotropaios-2026-03-30T00-30-02.log
│   └── .gitkeep
├── rules/                   # Rule index and state (0o600)
│   ├── rule_index.dat       # Persistent pipe-delimited rule index (27 fields)
│   ├── rule_state.dat       # TTL tracking and lifecycle state
│   └── .gitkeep
└── backups/                 # Compressed backup archives (0o600)
    ├── apotropaios_backup_pre-deploy_2026-03-30T00-30-02.tar.gz
    ├── apotropaios_backup_pre-deploy_2026-03-30T00-30-02.tar.gz.sha256
    ├── immutable/           # Immutable snapshots (chattr +i)
    └── .gitkeep
```

All data directories are created with 0o700 permissions (owner-only access). All data files are created with 0o600 permissions (owner read/write only). The umask is set to 0o077 during framework initialization.

---

## Permissions and Security Hardening

### Default Permissions

| Resource | Permissions | Description |
|:---------|:-----------|:------------|
| `data/` directories | 0o700 | Owner-only access |
| Log files | 0o600 | Owner read/write |
| Rule index | 0o600 | Owner read/write |
| Backup archives | 0o600 | Owner read/write |
| Temporary files | 0o600 | Created via `tempfile.mkstemp()` |
| Lock files | 0o600 | Advisory locks via `fcntl.flock()` |

### Additional Hardening

For production deployments:

```bash
# 1. Restrict data directory access
sudo chmod 700 data/
sudo chown root:root data/

# 2. Enable immutable snapshots for critical baselines
# (via interactive menu: Backup & Recovery > Create immutable snapshot)

# 3. Use minimal console output
sudo python3 apotropaios.py --log-level warning detect

# 4. Verify backup integrity periodically
# (via interactive menu: Backup & Recovery > Verify snapshots)
```

### umask

Apotropaios sets `umask(0o077)` during `init_security()`, ensuring all files and directories created during execution are accessible only by the owner.

---

## Container and Virtual Machine Notes

### Docker

Apotropaios runs in Docker containers but requires appropriate capabilities for firewall operations:

```bash
# Run with NET_ADMIN capability
docker run --cap-add=NET_ADMIN -it python:3.12 bash

# Or run with full privileges (testing only)
docker run --privileged -it python:3.12 bash
```

**Important:** Some containers may lack the netfilter kernel modules. Load them on the host:
```bash
sudo modprobe ip_tables
sudo modprobe iptable_filter
sudo modprobe nf_tables
```

Container-based firewall management affects the container's network namespace, not the host.

### WSL (Windows Subsystem for Linux)

Apotropaios detection and rule management work in WSL 2:
- WSL 2 has its own network namespace with iptables/nftables support
- Firewall rules in WSL do not affect the Windows host firewall
- Some backends may not be available in WSL 1

### Virtual Machines

Apotropaios works identically in VMs (VMware, VirtualBox, KVM, Hyper-V) as on bare metal. No special configuration required.

---

## Development Environment Setup

For contributors and testers:

```bash
# Clone
git clone https://github.com/Sandler73/Apotropaios-Firewall-Manager-Python-Variant.git
cd Apotropaios-Firewall-Manager-Python

# Automated setup (creates venv + installs deps)
make dev-setup

# Or manual setup:
python3 -m venv .venv
source .venv/bin/activate
pip3 install -e ".[dev]"

# Verify everything works
make check              # mypy --strict + 322 tests
make test-report        # Detailed per-file breakdown
make check-deps         # Show all tool availability
make metrics            # Project statistics
make security-scan      # Static pattern analysis (6 checks)
```

See [DEVELOPMENT_GUIDE.md](DEVELOPMENT_GUIDE.md) for coding standards and [CONTRIBUTING.md](CONTRIBUTING.md) for contribution workflow.

---

## Upgrading

### From Git

```bash
cd Apotropaios-Firewall-Manager-Python
git pull origin main

# If using venv
source .venv/bin/activate
pip3 install -e ".[dev]"

# Verify
make check
python3 apotropaios.py --version
```

### From Release Tarball

```bash
# Backup current data
cp -r data/ /tmp/apotropaios-data-backup

# Download and extract new version
tar -xzf apotropaios-X.Y.Z.tar.gz
cd apotropaios-X.Y.Z

# Restore data
cp -r /tmp/apotropaios-data-backup/* data/

# Verify
sudo python3 apotropaios.py --version
sudo python3 apotropaios.py detect
```

**Data preservation:** Logs, rules, and backups in `data/` are never overwritten by updates. The data directory structure is recreated automatically if missing.

---

## Uninstallation

### If Using Direct Execution

Simply delete the project directory:

```bash
rm -rf Apotropaios-Firewall-Manager-Python
```

### If pip-Installed

```bash
pip3 uninstall apotropaios
# Or via Makefile:
make uninstall
```

### Cleanup

```bash
# Remove runtime data (logs, tracked rules, backups)
# CAUTION: This deletes all rule tracking and backup history
sudo rm -rf data/
```

**Important:** Uninstallation does not modify or remove any firewall rules that were applied through Apotropaios. Active rules remain in their respective firewall backends. To remove applied rules before uninstalling, use the interactive menu or CLI to deactivate/remove tracked rules.

---

## Troubleshooting Installation Issues

### pip3 install fails with "Multiple top-level packages discovered"

**Cause:** setuptools auto-discovers `data/`, `tests/`, `docs/` as packages.

**Fix:** The `pyproject.toml` includes `[tool.setuptools.packages.find]` with explicit include/exclude. Ensure your copy has this section.

### pip3 install fails with license deprecation warning

**Cause:** Older pyproject.toml format used `license = {text = "MIT"}`.

**Fix:** Use SPDX format: `license = "MIT"` (simple string).

### "ModuleNotFoundError: No module named 'apotropaios'"

**Cause:** Not running from the project root or package not installed.

**Fix:** Either run from the project root using `python3 apotropaios.py` (which adds the path), or install via `pip3 install .`.

### venv creation fails

```bash
sudo apt install python3-venv         # Debian/Ubuntu/Kali
sudo dnf install python3-venv         # RHEL family
```

### "Permission denied" during firewall operations

Firewall management requires root. Always run with `sudo`:

```bash
sudo python3 apotropaios.py detect
```

### "No firewall backends detected"

Install at least one supported firewall:

```bash
sudo apt install iptables             # Ubuntu/Debian/Kali
sudo dnf install firewalld            # Rocky/Alma
sudo pacman -S nftables               # Arch
```

### Diagnostic Commands

```bash
# Maximum diagnostic detail
sudo python3 apotropaios.py detect --log-level trace

# Check Python version
python3 --version

# Check installed firewalls
which iptables nft firewall-cmd ufw ipset 2>/dev/null

# Check all dependencies
make check-deps

# View last log file
sudo cat $(ls -t data/logs/*.log 2>/dev/null | head -1)
```

For additional help, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
