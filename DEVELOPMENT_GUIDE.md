# Apotropaios Development Guide -- Contributor Standards and Workflow

This guide defines the coding standards, development workflow, and contribution requirements for the Apotropaios Firewall Manager Python variant. All contributors must follow these standards.

## Development Environment Setup

### Required Tools

| Tool | Minimum Version | Purpose |
|---|---|---|
| Python | 3.12 | Runtime and type annotation syntax |
| pip3 | 23.0 | Package management |
| Git | 2.30 | Version control |
| Linux | Any | Target platform (firewall operations require Linux kernel) |

### Setup Steps

```bash
# Clone
git clone https://github.com/Sandler73/Apotropaios-Firewall-Manager-Python-Variant.git
cd Apotropaios-Firewall-Manager-Python

# Option A: venv (recommended)
make venv
source .venv/bin/activate

# Option B: system-wide dev install
pip3 install -e ".[dev]" --break-system-packages

# Verify
make check     # mypy --strict + 322 tests
```

## Quality Gates -- Mandatory for All Changes

Every commit must pass these gates:

```bash
make typecheck   # mypy --strict: 0 errors across 35 files
make test        # pytest: 322/322 passing
make check       # Both combined
```

No exceptions. No "we'll fix the type errors later." No "this test is flaky, skip it." Zero tolerance.

## Continuous Integration

Five GitHub Actions workflows enforce the quality gates automatically. Every pull request must pass them before merge.

The main pipeline, `.github/workflows/ci.yml`, runs on every push and pull request. It has five jobs: a static lint job running pyflakes over the package, scripts, and tests; a strict type-check job running mypy; a test matrix executing the full pytest suite on Python 3.12 and 3.13 with coverage uploaded as an artifact; a security-test job running the injection suite; and a consistency job running the two validation scripts described below. Runs for superseded commits on the same ref are cancelled automatically.

`.github/workflows/release.yml` triggers on version tags (`v*`). Its first job gates the tag against the canonical version in `constants.py` and fails immediately if they disagree, so a mistagged release cannot proceed. It then runs the full CI checks, builds the package, generates a unified `SHA256SUMS.txt`, and publishes a GitHub release with checksummed assets.

`.github/workflows/security.yml` runs bandit static analysis on every push, pull request, and weekly schedule, uploading the findings report as an artifact and failing on medium-or-higher severity at medium-or-higher confidence. `B404` and `B603` are excluded because list-form subprocess usage with validated arguments is an audited design decision. `.github/workflows/codeql.yml` runs CodeQL semantic analysis for Python. `.github/workflows/docs-validate.yml` runs the consistency scripts and the CI meta-test suite whenever documentation, source, templates, or workflows change.

PyYAML is a required CI dependency alongside pytest: the CI meta-suite (`tests/ci/`) imports it, and without it those tests are silently excluded from collection, which both hides the meta-checks and makes the collected suite total fall below the documented count. Every job that runs the full suite or the documentation validator installs `pytest pyyaml`.

A `badges` job runs on pushes to `main` after every gate passes. It derives the collected test count, parses the coverage percentage from the test matrix's coverage artifact, and publishes shields endpoint JSON (`mypy.json`, `tests.json`, `coverage.json`) to a `badges` branch, which the README's dynamic badges read. The framework-version badge reads `pyproject.toml` directly and needs no workflow involvement.

Action pins follow a fixed standard: `actions/checkout@v6`, `actions/setup-python@v6`, `actions/upload-artifact@v6`, `actions/download-artifact@v6`, and `github/codeql-action/*@v4`. The CI meta-tests enforce these pins, so a drift in a workflow file fails the suite.

## Validation Scripts

Two stdlib-only scripts under `scripts/` back the consistency gates and are runnable locally:

```bash
python3 scripts/check_version_consistency.py   # all version locations agree
python3 scripts/validate_docs.py               # documentation matches source
```

`check_version_consistency.py` reads the canonical `VERSION` from `constants.py` and verifies that `pyproject.toml`, the package `__version__`, and the `# Version:` header of every module, test, script, workflow, issue template, the Makefile, the entrypoint, the shipped config file, and the PR template all agree. `validate_docs.py` verifies documentation against source: no version identifiers outside the changelogs (the fact-of policy), per-file and total line counts in the developer guides, suite-total test-count references against the collected pytest suite, CLI command-count references against `CLI_COMMANDS`, and internal wiki/relative links. Changelog files are exempt from the version and metric checks because their entries record the state at each release.

## Repository Templates

Issue reporting is structured through forms under `.github/ISSUE_TEMPLATE/`: `bug_report.yml`, `feature_request.yml`, `documentation.yml`, and `platform_support.yml`, each with required fields and backend/OS dropdowns. `config.yml` disables blank issues and routes security disclosures to `SECURITY.md` and questions to the FAQ wiki. `.github/PULL_REQUEST_TEMPLATE.md` carries the change description, verification-evidence checklist, and quality gates. The CI meta-test suite (`tests/ci/test_workflows.py`) validates all of these as structured data.

## Coding Standards

### 1. Type Annotations

Every function must have full type annotations on all parameters and return type:

```python
# CORRECT
def validate_port(value: str) -> int:
    """Validate a TCP/UDP port number."""
    ...

# WRONG -- missing return type
def validate_port(value: str):
    ...

# WRONG -- missing parameter type
def validate_port(value) -> int:
    ...
```

Use `from __future__ import annotations` at the top of every module to enable postponed evaluation of annotations (PEP 604 union syntax `X | None` instead of `Optional[X]`).

### 2. Module Headers

Every `.py` file must have a complete header:

```python
# ==============================================================================
# File:         apotropaios/module_name.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     One-line summary
# Description:  Multi-line detailed description of what the module does,
#               how it fits into the architecture, and what design choices
#               were made.
#
# Notes:        - Dependencies and import requirements
#               - Thread safety guarantees
#               - Parity target (bash file it mirrors)
# Version:      <current framework version>
# ==============================================================================
```

### 3. Docstrings

Google-style docstrings on all public functions and classes:

```python
def rule_create(params: dict[str, str]) -> str:
    """Create and apply a firewall rule.

    Validates all parameters, generates a UUID, applies via the active
    backend, and records in the rule index and state tracker.

    Args:
        params: Rule parameters dictionary. Common keys:
                direction, protocol, src_ip, dst_ip, src_port, dst_port,
                action, duration_type, ttl, description.

    Returns:
        The UUID of the newly created rule.

    Raises:
        RuleInvalidError: If parameter validation fails.
        RuleApplyError: If the backend fails to apply the rule.
    """
```

### 4. Security Requirements

**Subprocess execution**: NEVER use `shell=True`. Always use list-form arguments:

```python
# CORRECT -- list-form, no shell interpretation
subprocess.run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", port, "-j", "ACCEPT"],
               capture_output=True, text=True, timeout=30)

# WRONG -- shell=True enables injection
subprocess.run(f"iptables -A INPUT -p tcp --dport {port} -j ACCEPT", shell=True)
```

**Input validation**: Validate at every trust boundary before use. Never pass user input directly to subprocess or file operations without validation.

**File permissions**: All created files must use `Security.FILE_PERMS` (0o600) and directories `Security.DIR_PERMS` (0o700).

**Atomic writes**: All persistent data must use the temp-then-replace pattern:

```python
tmp_path = f"{final_path}.tmp.{os.getpid()}"
with open(tmp_path, "w") as f:
    f.write(data)
os.replace(tmp_path, final_path)  # Atomic on POSIX
os.chmod(final_path, Security.FILE_PERMS)
```

### 5. Error Handling

Use the framework's exception hierarchy. Never catch bare `Exception` at the engine layer -- be specific:

```python
# CORRECT -- specific exception
try:
    fw_add_rule(params)
except RuleApplyError as exc:
    _log("error", f"Failed to apply: {exc}")
    raise

# ACCEPTABLE at CLI layer -- catch broad, report specific
try:
    rule_id = rule_create(params)
except Exception as exc:
    sys.stderr.write(f"Error: {exc}\n")
    return ErrorCode.RULE_APPLY_FAIL
```

### 6. Naming Conventions

| Type | Convention | Example |
|---|---|---|
| Modules | `snake_case.py` | `os_detect.py`, `import_export.py` |
| Classes | `PascalCase` | `IptablesBackend`, `RuleIndex`, `ExpiryMonitor` |
| Functions | `snake_case` | `validate_port`, `rule_create`, `fw_add_rule` |
| Constants | `UPPER_SNAKE_CASE` | `TERMINAL_ACTIONS`, `MAX_RETAINED` |
| Private | `_leading_underscore` | `_build_match_args`, `_parse_compound_action` |
| Module singletons | `lower_snake_case` | `rule_index`, `rule_state`, `cleanup_stack` |
| Type variables | Single uppercase | `T = TypeVar("T")` |

### 7. Import Ordering

Follow PEP 8 import ordering, enforced by isort configuration:

1. `from __future__ import annotations` (always first)
2. Stdlib imports
3. Third-party imports (none for runtime)
4. Framework imports (layer order: constants → errors → validation → logging → security → utils)

```python
from __future__ import annotations

import os
import sys
import threading
from typing import Final

from apotropaios.core.constants import ErrorCode, LogLevel
from apotropaios.core.errors import RuleApplyError, cleanup_stack
from apotropaios.core.security import generate_uuid
```

### 8. Layer Dependency Rule

Never import upward in the layer stack:

```python
# WRONG -- Layer 1 (core) importing from Layer 3 (firewall)
# In core/validation.py:
from apotropaios.firewall.common import get_backend  # FORBIDDEN

# CORRECT -- Layer 3 importing from Layer 1
# In firewall/iptables.py:
from apotropaios.core.validation import validate_port  # OK
```

### 9. No Stubs or Placeholders

Every function must be fully implemented when committed. Never commit:
- `pass` body functions
- `raise NotImplementedError()`
- `print("Coming in Sprint X")`
- `# TODO: implement`

This was the root cause of PY-003 (16 dead CLI handlers) -- the most critical bug in the project's history.

## Testing Requirements

### All PRs Must Include Tests

- **New feature**: Unit tests covering normal path + error paths
- **Bug fix**: Regression test that fails before the fix
- **New validator**: Both valid and invalid input tests
- **New CLI command**: Integration test via subprocess

### Test File Organization

```
tests/
├── conftest.py              Shared fixtures (MockBackend, temp dirs)
├── unit/                    No subprocess, no root required
│   ├── test_validation.py   68 tests -- all 27 validators + sanitizer
│   ├── test_constants.py    18 tests -- enums, patterns, CLI commands
│   ├── test_errors.py       15 tests -- exception hierarchy, cleanup, retry
│   ├── test_logging.py      11 tests -- sanitizer families, logger lifecycle
│   ├── test_security.py     10 tests -- FileLock, checksum, UUID, perms
│   ├── test_utils.py        20 tests -- timestamps, duration, KV files
│   ├── test_detection.py    17 tests -- OS/FW detection dataclasses
│   ├── test_backends.py     23 tests -- ABC, registry, dispatch, helpers
│   └── test_rule_engine.py  22 tests -- index CRUD, state TTL, engine ops
├── integration/             Requires subprocess, may need root
│   ├── test_cli.py          7 tests -- CLI --version/--help/detect/status
│   └── test_lifecycle.py    4 tests -- full create→deactivate→activate→remove
└── security/                Hostile input testing
    └── test_injection.py    15 tests -- shell injection, path traversal, XSS
```

### Writing a Test

```python
class TestValidatePort:
    """Tests for validate_port()."""

    def test_valid_ports(self) -> None:
        """Boundary and mid-range values."""
        assert validate_port("1") == 1
        assert validate_port("80") == 80
        assert validate_port("443") == 443
        assert validate_port("65535") == 65535

    def test_invalid_ports(self) -> None:
        """Out-of-range and malformed input."""
        with pytest.raises(ValidationError):
            validate_port("0")
        with pytest.raises(ValidationError):
            validate_port("65536")
        with pytest.raises(ValidationError):
            validate_port("abc")
        with pytest.raises(ValidationError):
            validate_port("-1")
```

## Adding a New Backend

1. Create `apotropaios/firewall/newbackend.py`
2. Subclass `FirewallBackend` from `base.py`
3. Implement all 12 abstract methods
4. Register at module level: `register_backend(_instance)`
5. Add `FirewallInfo` entry to `SUPPORTED_FIREWALLS` in `constants.py`
6. Add detection logic in `fw_detect.py`
7. Import in `cli.py` `_initialize()` function
8. Add tests in `tests/unit/test_backends.py`
9. Update documentation: DEVELOPER_GUIDE, Architecture wiki
10. Run `make check` -- must pass

## Version Bumping

Update all of these locations:
- `apotropaios/core/constants.py` → `VERSION`
- `pyproject.toml` → `version`
- `docs/CHANGELOG.md` → new entry
- `docs/wiki/Changelog.md` → new entry
- Module headers → `Version:` line (where changed)

## Commit Message Format

```
type: brief description

feat: add rate limiting support for nftables backend
fix: firewalld reset now iterates ALL zones (Lesson #10)
docs: expand DEVELOPER_GUIDE with ipset validation detail
test: add injection tests for hostname validator
refactor: extract _build_match_args from iptables add/remove
chore: update .gitignore with Python venv patterns
```
