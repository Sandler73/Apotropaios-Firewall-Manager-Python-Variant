# Changelog — Apotropaios Firewall Manager (Python Variant)

All notable changes documented per [Keep a Changelog](https://keepachangelog.com/). Versioning follows [Semantic Versioning](https://semver.org/).

---

## [1.2.1] — 2026-07-14

### Documentation
- Removed version identifiers from all documentation outside the changelogs (README badge and version-history table, SECURITY supported-versions table, SETUP_GUIDE download examples, DEVELOPER_GUIDE/DEVELOPMENT_GUIDE/FAQ, wiki sidebar, footer, and guides); documentation is now fact-of.
- Corrected the Configuration-Reference and SETUP_GUIDE statements that no external configuration file exists; documented the configuration file search order, trust gate, and precedence.
- Documented `--non-interactive` destructive-command semantics, expanded backup-contents description, and regenerated all per-file and total line counts from source.

## [1.2.0] — 2026-07-14

### Changed
- CI and release workflows pin `actions/checkout@v6` per the project workflow standard.

## [1.1.9] — 2026-07-14

### Fixed
- cli.py header now states 21 subcommands and lists all of them (previously claimed 20 and listed 17); parser docstring corrected from 17 to 21.
- menu/main.py header describes the 8-option main menu (previously "7-category").
- os_detect `_determine_family` docstring no longer claims `OS_FAMILY_MAP` usage; it documents the local map, ID_LIKE fallback, and binary probing actually implemented.
- `export_rules` returns the number of rules actually written to the export file; expired and unreadable records are no longer counted.

## [1.1.8] — 2026-07-14

### Fixed
- Removed 45 unused imports across 18 modules and one unused local variable; removed f-string prefixes from placeholder-less literals.
- Normalized over-indented docstring bodies across the nftables, firewalld, ufw, and ipset backends.
- `retry()` rejects `max_retries < 1` with an explicit ValueError and replaces the exhaustion assert with an explicit raise (asserts are stripped under `-O`).
- `ErrorContext.record` captures tracebacks with `traceback.format_exception(exc)` so recording outside an except block no longer stores "NoneType: None".
- `die()` is typed `-> NoReturn`; removed the dead control-character pass in `sanitize_input` (the whitelist already excludes them); removed the duplicate result-list initialization in `parallel_exec`; repaired the broken sentence in the common.py header.

## [1.1.7] — 2026-07-14

### Security
- Privileged executions now run with a hardened fixed `PATH` set during security initialization, closing the untrusted-search-path window for subprocess resolution of firewall binaries under root.

### Changed
- Detection running-state checks execute through the already-resolved binary path instead of performing a second PATH lookup; removed the dead ipset kernel-module fallback branch.

## [1.1.6] — 2026-07-14

### Fixed
- Backend service operations no longer report success unconditionally: iptables, nftables, firewalld, and ufw `enable`/`disable` now check systemctl/ufw results; iptables and ufw `block_all`, `allow_all`, and `reset` verify every policy and flush command; firewalld `block_all` verifies panic mode and its drop-zone fallback, `allow_all` verifies the zone reset, and `save` verifies `--runtime-to-permanent`; the firewalld restore path verifies `--reload`. Failed emergency controls now return failure instead of claiming success.

## [1.1.5] — 2026-07-14

### Fixed
- nftables rules with IPv6 operands now emit `ip6 saddr`/`ip6 daddr` (previously `ip saddr`, a syntax error for IPv6 addresses).
- firewalld rich rules derive the address family from the operands (`ipv6` when IPv6 addresses are present) instead of hardcoding `ipv4`; mixed-family rules are rejected explicitly.
- firewalld protocol-only ICMP rules use `protocol value="icmp|icmpv6"`; the invalid `icmp-block-inversion` rich-rule element (a zone option) is no longer emitted.

## [1.1.4] — 2026-07-14

### Fixed
- Menu-driven backups and restores now include the rule index and state files: the backup subsystem records the rules directory at initialization and both `create_backup` and `restore_backup` fall back to it when no explicit directory is passed, unifying the CLI and menu paths.

## [1.1.3] — 2026-07-14

### Added
- The shipped configuration file is now loaded at startup (previously parsed by nothing). Search order: `/etc/apotropaios/apotropaios.conf`, `<base>/conf/apotropaios.conf`, packaged default. Every candidate passes a trust gate — owned by root or the effective user, not group/world-writable — before use. Precedence: command line > configuration file > built-in defaults. The file drives the console log level and default backend selection.

## [1.1.2] — 2026-07-14

### Fixed
- `--non-interactive` is now honored: destructive confirmations (reset) proceed without prompting in non-interactive mode instead of blocking on stdin.
- The reset confirmation reads from the controlling terminal when available, so piped stdin cannot accidentally satisfy it; falls back to stdin only when no terminal exists.
- The minimum Python version is enforced at CLI entry with a clear error and non-zero exit (previously logged as critical and execution continued).

## [1.1.1] — 2026-07-14

### Fixed
- `FrameworkLogger.init()` shuts down any previous session before re-initializing, eliminating a file-descriptor leak where the prior stdlib logger stayed registered with its rotating file handler attached.
- The log entry counter is guarded by a lock; the expiry monitor daemon thread and the main thread previously raced a non-atomic increment.

## [1.1.0] — 2026-07-14

### Fixed
- Deactivating a rule preserves its duration type and TTL in the state tracker; temporary rules no longer silently become permanent on deactivation, and expired rules are recorded as `expired` in both the index and the state tracker.
- `rule_create` restores the session's original backend after a per-rule backend switch, matching removal, deactivation, and activation semantics; a failed application also restores the original backend.

## [1.0.9] — 2026-07-14

### Fixed
- `validate_cidr` no longer swallows its own prefix-out-of-range error inside the version-detection try block; out-of-range prefixes are reported specifically instead of as an invalid IP portion.
- IPv6 validation performs exact semantic validation via the stdlib `ipaddress` module after the pattern check; malformed forms such as `:::` and `1::2::3` are now rejected.

## [1.0.8] — 2026-07-14

### Fixed
- ufw backup/restore round-trip: backups now capture the complete `/etc/ufw` configuration directory (`ufw_etc` in the archive) alongside the human-readable status dump; restore reports failure honestly when an archive contains no restorable ufw configuration instead of logging success while restoring nothing.

## [1.0.7] — 2026-07-14

### Fixed
- Package install and update operations use the long operation timeout (300 s) instead of the 30-second subprocess default, which real package operations routinely exceed; `subprocess.TimeoutExpired` is caught and reported as an installation error instead of escaping as a raw exception.

## [1.0.6] — 2026-07-14

### Fixed
- `os_detect` ID_LIKE family fallback maps the `rhel` family to package manager `dnf` (previously the invalid value `rhel`), restoring install/update support on RHEL-derivative distributions.

## [1.0.5] — 2026-07-14

### Security
- `CleanupStack` uses a reentrant lock: the signal handler executes the cleanup stack in the main thread, and a non-reentrant lock deadlocked the process when a signal interrupted a frame already holding the lock (CWE-833).
- `FileLock.acquire` re-opens the lock file on every retry iteration; after stale-lock removal and recreation, flock was previously taken on the unlinked inode, allowing two simultaneous holders (CWE-367). Removed the redundant `BlockingIOError` from the except clause.

## [1.0.4] — 2026-07-14

### Security
- The log sanitizing filter now masks the structured `extra_context` field in addition to the message. Previously extra_context reached the file formatter verbatim, permitting log-line forging via control characters (CWE-117) and secret leakage through structured fields.

## [1.0.3] — 2026-07-14

### Security
- ufw action mapping fails closed: unknown or unsupported actions (masquerade, snat, dnat, return, or unrecognized values) raise `RuleApplyError` instead of silently translating to `allow`; compound actions without a supported terminal no longer default to a permissive verb except for explicit log-only rules.

## [1.0.2] — 2026-07-14

### Security
- ipset `block_all` fails closed: coverage is achieved with the two complementary `/1` networks (`hash:net` rejects a `/0` prefix, so the previous `0.0.0.0/0` add always failed), and every set and iptables operation is verified — the emergency control returns failure when blocking did not fully apply instead of claiming success while blocking nothing. `allow_all` verifies block-set removal.

## [1.0.1] — 2026-07-14

### Security
- Completed defense-in-depth re-validation across all five backends: nftables re-validates `log_prefix`, `log_level`, `limit`, `limit_burst`, `handle`, `table`, `table_family`, and `chain` before interpolation into nft command strings (closing quote-breakout/statement-injection paths); firewalld re-validates rich-rule `log_prefix`/`log_level`/`limit` and removal-path ports; iptables re-validates `conn_state`, `limit`, `limit_burst`, `log_prefix`, and `log_level`; ufw re-validates removal-path rule numbers, ports, and protocols; ipset validates entries for every set type including `hash:*,port`, `hash:net,iface`, and `list:set`.

## [1.0.0] — 2026-04-12

### Production Release

First production release of the Apotropaios Firewall Manager Python variant.
Designates feature-complete, fully audited, stable codebase after 12 development
iterations spanning 6 distinct audit passes.

**Codebase:** 35 Python files, 13,877 lines, 430 callable entities, stdlib-only.
**Quality:** mypy --strict zero errors, 230 automated tests, zero known bugs.
**Security:** 6 CWE-mapped vulnerabilities found and fixed across 3 audit passes.
**Coverage:** 21 CLI commands, 20 help pages, 5 firewall backends, 6 Linux platforms.

**Audit history:**
- v0.1.5: Line-by-line security audit — 6 bugs fixed (SIGHUP, firewalld backup,
  timing side-channel, duplicate actions, ExpiryMonitor, hierarchy comment)
- v0.1.6: Code quality audit — 44 docstrings added, 3 unused imports removed
- v0.1.7: Technical quality audit — 16 findings (allow_all flush, backend switch
  failure, dead parameter, unchecked return codes, Color TTY, conn_state validation)
- v0.1.8: CLI expansion — enable/disable/reset commands, root privilege check,
  IPTABLES_TABLES validation, ErrorContext traceback, empty field standardization
- v0.1.9: Secure code audit — tarfile extraction hardening (CWE-22/59),
  log injection prevention (CWE-117), standalone exception wrapping (CWE-209)
- v0.1.10: SAST analysis — limit_burst/log_level taint gaps closed (CWE-20),
  swallowed index.add exceptions replaced with error logging
- v0.1.11: Documentation audit — 26 discrepancies corrected, version history
  restructured with per-category version entries

---

## [0.1.11] — 2026-04-12

### Technical Code Documentation Audit

**Discrepancies fixed (26):**
- Total line count updated (13,853 → 13,877) across 6 files
- `logging.py` line count updated (727 → 729) across 4 files
- `engine.py` line count updated (562 → 576) across 4 files
- `restore.py` line count updated (255 → 263) across 4 files
- CLI command count updated (18 → 21) across 6 files
- Version badge updated from 0.1.8-dev to current in README
- Architecture layer subtotals recalculated (L1: 4,809, L4: 2,520)

**Version history restructured:**
- Split bundled v0.1.9-dev into v0.1.9 (security audit) + v0.1.10 (SAST)
- Each audit category now has its own version entry

---

## [0.1.10-dev] — 2026-04-11

### SAST & Static Code Analysis — 3 Findings Fixed

- **SAST-001**: `limit_burst` parameter passed from CLI through engine to
  iptables/nftables subprocess with zero validation at any layer. Added
  `validate_numeric()` call in engine validation chain. (CWE-20)
- **SAST-002**: `log_level` (syslog level for LOG action) passed to backends
  unvalidated despite `validate_syslog_level()` existing. Added validation
  call in engine. (CWE-20)
- **SAST-003**: `rule_block_all()` and `rule_allow_all()` silently swallowed
  `rule_index.add()` failures via `except Exception: pass`. Rules applied to
  firewall but not tracked in index — data integrity gap. Added error logging.

---

## [0.1.9-dev] — 2026-04-11

### Secure Code Audit — 3 Security Findings Fixed

Line-by-line secure code audit of all 35 source files focused on CWE Top 25,
OWASP CRG, and NIST SSDF security requirements.

- **S001**: `restore.py` tarfile extraction vulnerable to symlink, hard link,
  and device node attacks. Added explicit checks for `issym()`, `islnk()`,
  `isdev()`, `ischr()`, `isblk()` members, plus Python 3.12+ `filter="data"`
  parameter for defense-in-depth. (CWE-22, CWE-59)

- **S004**: `LogSanitizer` control character pattern allowed newline (`\x0a`)
  and carriage return (`\x0d`) through, enabling log injection attacks where
  attacker-controlled data could forge fake log entries. Fixed pattern to
  strip all control chars except tab. (CWE-117)

- **S005**: `apotropaios.py` standalone execution lacked the exception
  handling wrapper present in `__main__.py`. Unhandled exceptions exposed
  full Python tracebacks. Added KeyboardInterrupt handler and catch-all.

---

## [0.1.8-dev] — 2026-04-11

### New CLI Commands + Deferred Fixes

**New CLI commands (3):**
- `enable` — Start and enable the active firewall backend via systemctl.
- `disable` — Stop the active firewall backend.
- `reset` — Reset the active backend to defaults with interactive confirmation.

**Root privilege detection:**
- Added root privilege check to `_initialize()`. Logs warning when not running
  as root so users see early feedback before firewall operations fail.

**Deferred audit findings fixed (5):**
- **Q006**: `ErrorContext.get_formatted()` now includes traceback tail. Added
  `get_traceback()` method for full traceback access.
- **Q011**: iptables backend validates `--table` against `IPTABLES_TABLES`.
- **Q013**: Empty rule fields stored as empty strings (not "any") in index.
- **Q014**: `ttl.isdigit()` replaced with ASCII-only check.
- `CLI_COMMANDS` expanded from 18 → 21, help system 17 → 20 registrations,
  dispatch 17 → 20 handlers.

---

## [0.1.7-dev] — 2026-04-03

### Code Quality Audit — 16 Findings Fixed

Line-by-line technical code quality audit of all 35 source files identified and
fixed 16 quality issues across 2 critical, 5 high, and 9 medium severity findings.

**Critical fixes:**
- **Q010**: `iptables.allow_all()` set ACCEPT policies without flushing existing
  DROP/REJECT rules — traffic remained blocked despite "allow all" success.
  Fixed: flush filter table before setting policies.
- **Q015**: `rule_remove()`, `rule_deactivate()`, and `rule_activate()` silently
  swallowed backend switch failures (except: pass), causing operations to execute
  against the wrong firewall backend. Fixed: track switch state explicitly, log
  failures instead of silently ignoring.

**High fixes:**
- **Q001**: constants.py comment referenced nonexistent `validate_sanitize_input()`.
- **Q004**: Duplicate comment line in errors.py signal handler section.
- **Q007**: `iptables._run()` accepted `check` parameter but never passed it to
  `subprocess.run()`. Wired through.
- **Q008**: `iptables.enable()`/`disable()` ignored systemctl return codes.
  Added returncode checking with warning log on failure.
- **Q012**: `nftables.py` used `conn_state` directly in nft expressions without
  calling `validate_conn_state()`. Added defense-in-depth validation.

**Medium fixes:**
- **Q002**: `LogLevel.to_stdlib_level()` created mapping dict on every call.
  Moved to module-level constant `_LOGLEVEL_TO_STDLIB`.
- **Q003**: `_Color` checked `sys.stdout.isatty()` but all output goes to stderr.
  Changed to check `sys.stderr.isatty()`.
- **Q009**: Status message showed `python` instead of `python3` (PY-005 regression).
- **Q016**: `parse_iso_timestamp` imported inside loop body in `rule_check_expired()`.
  Moved to function top.

**Documented (deferred to next sprint):**
- Q005: Inconsistent exception context passing pattern (works correctly, cosmetic).
- Q006: `ErrorContext._traceback` stored but not exposed in `get_formatted()`.
- Q011: `validate_table()` too permissive for iptables (accepts any alphanumeric).
- Q013: Empty fields stored as "any" in rule index (inconsistent with input).
- Q014: `ttl.isdigit()` accepts Unicode digits (upstream regex prevents issue).

**Missing CLI commands identified (future sprint):**
- `enable`, `disable`, `reset` — available in interactive menu but not CLI mode.
- `save`, `load` — backend dispatch functions exist but unwired.

---

## [0.1.6-dev] — 2026-03-31

### Technical Code Quality Audit

Complete line-by-line technical code quality audit of all 35 source files. Focused on annotations, docstrings, unused imports, resource management, thread safety, return type consistency, and code organization.

**Docstring completeness (44 additions):**
- Added docstrings to all 12 public methods on `NftablesBackend` (nftables.py)
- Added docstrings to all 10 public methods on `FirewalldBackend` (firewalld.py)
- Added docstrings to all 12 public methods on `UfwBackend` (ufw.py)
- Added docstrings to 9 public methods on `IpsetBackend` (ipset.py)
- Added docstring to `RuleState.initialized` property (state.py)

**Unused import removal (3 removals):**
- Removed `import shutil` from `ipset.py` (unused after prior refactor)
- Removed `import shutil` from `ufw.py` (unused after prior refactor)
- Removed `import sys` from `index.py` (unused)

**Quality verification (13 automated checks, all passing):**
1. Type annotations: complete on all public functions and methods
2. Docstrings: present on all public classes, functions, and methods
3. No bare `except` clauses anywhere in codebase
4. No TODO/FIXME/HACK markers in production code
5. All module header versions consistent (0.1.8-dev)
6. All `open()` calls use context managers (`with` statement)
7. No O(n²) string concatenation in hot paths
8. Thread-safe lock usage in all singleton mutating methods
9. All backend methods have return type annotations
10. All `__init__.py` package comments accurate
11. Help system registrations match CLI_COMMANDS exactly (17/17)
12. All resource handles properly managed
13. Lesson references in code comments are consistent

---

## [0.1.5-dev] — 2026-03-31

### Bug Fixes from Line-by-Line Security Audit

Complete line-by-line secure code audit identified and fixed 6 bugs:

- **BUG-001**: SIGHUP exit code was 80 instead of Unix standard 129 (128+1). Added `signal.SIGHUP: 129` to `_SIGNAL_EXIT_CODES`.
- **BUG-002**: Exception hierarchy comment showed wrong inheritance for RestoreError/BackupNotFoundError. Fixed to match actual `ApotropaiosError` parent.
- **BUG-003**: Firewalld backup/restore functionally broken — backup saved text dump, restore just reloaded. Fixed: saves/restores zone XML files from `/etc/firewalld/zones/`.
- **BUG-004**: ExpiryMonitor threshold documented inconsistently. Standardized to 10 minutes (600 seconds).
- **BUG-005**: `validate_rule_action()` allowed duplicate components ("log,log"). Added duplicate detection.
- **BUG-006**: `verify_checksum()` used `!=` instead of `hmac.compare_digest()` — timing side-channel (CWE-208). Fixed with constant-time comparison.

---

## [0.1.4-dev] — 2026-03-31

### Security Audit Fixes

- Added `encoding="utf-8"` to 9 `open()` calls missing explicit encoding
- Version string deduplicated: `__init__.py` imports from `constants.py`
- `DEFAULT_LOG_LEVEL` changed from `INFO` to `WARNING`
- `menu/__init__.py` docstring corrected from "7-category" to "8-option"
- Fixed 7 documentation inaccuracies (exception count, keywords, hierarchy, log levels, help count, mermaid, backend order)

---

## [0.1.3-dev] — 2026-03-31

### Documentation Overhaul

Complete rewrite of all 27 documentation files. Makefile expanded to 684 lines/56 targets.

---

## [0.1.2-dev] — 2026-03-30

### Bug Fixes
- **PY-007**: Post-shutdown console noise — `_shut_down` flag
- **PY-008**: `status` showed rules instead of service state
- **PY-009**: pip3 install build failure — explicit package discovery

### Enhancements
- Menu: System Info, Help submenu, Rule Management, Quick Actions improvements
- Position-independent `--log-level` and `--backend` flags
- Console default WARNING, `help` command, `import --dry-run`

---

## [0.1.1-dev] — 2026-03-30

### Critical Bug Fixes
- **PY-003**: 16/17 CLI handlers were dead stubs — all 18 rewired
- **PY-004**: Tests passed despite dead code — subprocess integration tests
- **PY-005**: `pip` → `pip3`
- **PY-006**: No standalone execution — created `apotropaios.py`

---

## [0.1.0-dev] — 2026-03-30

### Initial Release
Python 3.12+ rewrite targeting bash v1.1.10 parity. 35 files, stdlib-only, mypy --strict zero errors, 230 tests.
