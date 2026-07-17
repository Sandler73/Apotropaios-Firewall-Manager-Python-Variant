# Contributing to Apotropaios

Thank you for your interest in contributing to the Apotropaios Firewall Manager Python variant. This document provides guidelines for all types of contributions.

## Table of Contents

- [Types of Contributions](#types-of-contributions)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Coding Standards Summary](#coding-standards-summary)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Commit Message Format](#commit-message-format)
- [Code Review Criteria](#code-review-criteria)
- [Security Contributions](#security-contributions)
- [Documentation Contributions](#documentation-contributions)
- [Known Pitfalls](#known-pitfalls)

---

## Types of Contributions

### Bug Reports

- Search existing issues before creating a new one
- Include: Python version, OS/distribution, firewall backend, full error output, log file contents (from `data/logs/`)
- Provide minimal reproduction steps with exact commands
- Tag with `bug` label

### Feature Requests

- Open an issue with the `enhancement` label
- Describe the use case and expected behavior
- Reference the bash variant (v1.1.10) if the feature exists there
- Explain how it fits within the 5-layer architecture

### Code Contributions

- Bug fixes, new features, performance improvements, documentation
- Must follow all coding standards and pass all quality gates
- Prefer small, focused PRs over large multi-feature changes
- One logical change per commit

### Documentation Improvements

- Fix inaccuracies, expand explanations, add examples
- Both `docs/` and `docs/wiki/` contributions welcome
- Documentation changes still require `make check` to pass (ensures no code breakage)
- Documentation should be exhaustive -- explain HOW things work, WHY decisions were made, and WHAT edge cases exist

---

## Getting Started

```bash
# 1. Fork the repository on GitHub

# 2. Clone your fork
git clone https://github.com/YOUR_USERNAME/Apotropaios-Firewall-Manager-Python.git
cd Apotropaios-Firewall-Manager-Python

# 3. Create venv with dev dependencies
make dev-setup
source .venv/bin/activate

# 4. Verify everything works
make check         # mypy --strict + 322 tests (MUST pass)
make security-scan # 6 static pattern checks (MUST pass)

# 5. Create feature branch from develop
git checkout -b feature/your-feature-name develop
```

---

## Development Environment

### Required Tools

| Tool | Minimum Version | Purpose |
|:-----|:----------------|:--------|
| Python | 3.12 | Runtime and type annotation syntax |
| pip3 | 23.0 | Package management |
| Git | 2.30 | Version control |
| Linux | Any | Target platform |

### Dev Dependencies (installed by `make dev-setup`)

| Package | Purpose |
|:--------|:--------|
| pytest ≥ 8.0 | Automated testing |
| mypy ≥ 1.10 | Static type checking (`--strict` mode) |

### Makefile Targets for Development

```bash
make check           # Full CI: mypy --strict + 322 tests
make test-quick      # Unit tests only (fast feedback loop)
make test-report     # Detailed per-file pass/fail report
make security-scan   # Static pattern analysis (6 checks)
make metrics         # Project statistics (lines, test count, etc.)
make check-deps      # Verify all tool availability
```

---

## Coding Standards Summary

These are the non-negotiable requirements for all code contributions. See [DEVELOPMENT_GUIDE.md](DEVELOPMENT_GUIDE.md) for detailed examples.

### Mandatory Quality Gates

1. **`mypy --strict`**: Zero errors across all 35 source files. No exceptions.
2. **All 322+ tests passing**: No skipped tests, no xfail, no flakiness.
3. **`make security-scan`**: All 6 static checks passing.

### Code Requirements

1. **Full type annotations** on every function: all parameters and return type
2. **`from __future__ import annotations`** at the top of every module
3. **Google-style docstrings** on all public functions and classes
4. **Module headers** with File, Project, Synopsis, Description, Notes, Version
5. **No `shell=True`** in any subprocess call -- always list-form arguments
6. **Always capture stderr** on subprocess calls
7. **Validate all input** through `core/validation.py` validators before use
8. **Atomic writes** for persistent data: temp file → `os.replace()` → `os.chmod(0o600)`
9. **Thread safety** via `threading.Lock` on shared mutable state
10. **No circular imports** -- strict layer dependency ordering
11. **No stubs or placeholders** -- every function fully implemented when committed

### Layer Dependency Rule

```
Layer 5 (UI) may import from Layer 4, 3, 2, 1
Layer 4 (Engine) may import from Layer 3, 2, 1
Layer 3 (Backends) may import from Layer 2, 1
Layer 2 (Detection) may import from Layer 1
Layer 1 (Core) has NO upward dependencies
```

Never import upward. This is verified by mypy --strict (circular imports cause type errors).

---

## Testing Requirements

### All PRs Must Include Tests

- **New feature**: Unit tests covering normal path + every error path
- **Bug fix**: Regression test that FAILS before the fix and PASSES after
- **New validator**: Both valid and invalid input tests
- **New CLI command**: Integration test via `subprocess.run()` (not import)
- **Backend change**: Test via MockBackend (no root/real firewall needed)

### Test Organization

| Directory | Purpose | Root Required? |
|:----------|:--------|:---------------|
| `tests/unit/` | Module-level isolation | No |
| `tests/integration/` | CLI subprocess + lifecycle | No (MockBackend) |
| `tests/security/` | Injection/traversal/XSS | No |

### Running Tests

```bash
make test              # Full suite: lint + unit + integration + security
make test-quick        # Unit only (fast development loop)
make test-validation   # Just validation tests (68 tests)
make test-backends     # Just backend tests (23 tests)
make test-injection    # Just injection tests (15 tests)
make test-report       # Detailed per-file breakdown
```

### Critical Testing Lesson (PY-004)

Tests that `import` engine functions and call them directly CAN PASS even when CLI handlers are dead stubs. Integration tests MUST test the actual user-facing path via `subprocess.run(["python3", "-m", "apotropaios", "command"])` to verify the full dispatch chain works.

---

## Pull Request Process

1. **Branch from `develop`** -- never from `main`
2. **One focus per PR** -- bug fix, feature, or documentation
3. **Run `make check` and `make security-scan`** before submitting -- both must pass
4. **Update documentation** -- CHANGELOG.md, affected guides, wiki if applicable
5. **Update `tasks/sync_function.md`** if adding/modifying modules
6. **Write descriptive PR title** using conventional commits format
7. **Reference issues** -- e.g., "Fixes #42"
8. **Respond to review feedback** promptly
9. **Squash fixup commits** before merge

### PR Checklist

```
- [ ] `make check` passes (mypy --strict + 322 tests)
- [ ] `make security-scan` passes (6 checks)
- [ ] Tests added for new functionality or bug regression
- [ ] Type annotations on all new functions
- [ ] Docstrings on all new public functions/classes
- [ ] Module header updated if file modified
- [ ] CHANGELOG.md updated
- [ ] No `shell=True`, `eval()`, `exec()`, or stubs
```

---

## Commit Message Format

Follow conventional commits:

```
type(scope): brief description

feat(nftables): add rate limiting support for nft backend
fix(firewalld): reset now iterates ALL zones (Lesson #10)
docs(developer): expand DEVELOPER_GUIDE with ipset validation detail
test(security): add injection tests for hostname validator
refactor(iptables): extract _build_match_args from add/remove
chore(ci): update GitHub Actions to Node.js 24
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `perf`, `ci`

---

## Code Review Criteria

Reviewers will check:

1. **Correctness**: Does the code do what it claims? Are edge cases handled?
2. **Security**: Are inputs validated? Are subprocess calls list-form? Are file perms set?
3. **Type safety**: Does `mypy --strict` pass with zero errors?
4. **Test coverage**: Are normal and error paths both tested?
5. **Layer compliance**: Does the import graph follow the 5-layer ordering?
6. **Naming**: Do names follow the project conventions?
7. **Documentation**: Are docstrings present and accurate?
8. **Atomicity**: Is one logical change per commit?

---

## Security Contributions

### Reporting Vulnerabilities

**DO NOT** use public issues. See [SECURITY.md](SECURITY.md) for the coordinated disclosure process.

### Security Fix PRs

- Tag with `security` label
- Include CWE reference if applicable
- Add regression test to `tests/security/test_injection.py`
- Update SECURITY.md "CWE Coverage" table if adding new checks
- Update `tasks/lessons.md` with the vulnerability pattern and prevention rule

---

## Documentation Contributions

- All documentation lives in `docs/` and `docs/wiki/`
- Wiki pages must be **standalone** -- not just links to docs/
- Use accurate line counts, function names, and constant values -- verify against source code
- Include examples showing both success AND failure cases
- Explain WHY design decisions were made, not just WHAT they are

---

## Known Pitfalls

These are patterns that have caused bugs in the past. Avoid them:

| Pitfall | Lesson Code | Description |
|:--------|:------------|:------------|
| Dead CLI stubs | PY-003 | CLI handlers scaffolded but never wired to engine. Always wire immediately. |
| Tests passing with dead code | PY-004 | Unit tests import functions directly, missing broken CLI dispatch. Use subprocess tests. |
| `pip` vs `pip3` | PY-005 | Always use `pip3` explicitly for Python 3.x projects. |
| No standalone execution | PY-006 | Always provide `apotropaios.py` for zero-install execution. |
| Post-shutdown log noise | PY-007 | Remove console handler before writing shutdown marker. |
| Status ≠ rules | PY-008 | "Status" means service state. "List rules" means rules. Never conflate. |
| Package discovery | PY-009 | Always configure explicit `[tool.setuptools.packages.find]` in pyproject.toml. |

See `tasks/lessons.md` for the full list of lessons learned.
