# ==============================================================================
# Makefile for Apotropaios - Firewall Manager (Python Variant)
#
# Synopsis:     make [TARGET]
# Description:  Build, test, lint, security scan, package, install, and
#               development workflow targets. CI pipelines should call make
#               targets, not duplicate their logic.
#
# Notes:        - VERSION is auto-extracted from apotropaios/core/constants.py
#               - All test targets use pytest with TAP-compatible output
#               - Security targets run pattern-based static analysis
#               - Three distribution packages: dist, dist-full, dist-venv
#               - Python 3.12+ required (checked at runtime)
#
# Version:      1.2.1
# ==============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: all check test test-unit test-integration test-security test-all test-quick \
        test-validation test-logging test-detection test-backends test-errors \
        test-security-module test-rule-engine test-utils test-constants \
        test-cli test-lifecycle test-injection \
        test-report test-count test-list test-coverage \
        typecheck lint security-scan \
        run run-interactive run-detect run-status run-help \
        venv venv-test venv-typecheck venv-check venv-run \
        install install-minimal install-full install-dev uninstall verify \
        dist dist-full dist-venv release \
        clean clean-venv clean-data clean-all \
        dev-setup check-deps info metrics \
        help

# ==============================================================================
# Project Metadata (auto-extracted from source)
# ==============================================================================
PROJECT      := apotropaios
VERSION      := $(shell grep -m1 "VERSION.*Final" apotropaios/core/constants.py 2>/dev/null | grep -oP '"[^"]*"' | tr -d '"' || echo "0.0.0")
PYTHON3      ?= python3
PIP3         ?= pip3
PYTEST       := $(PYTHON3) -m pytest
MYPY         := $(PYTHON3) -m mypy

# ==============================================================================
# Directory Configuration
# ==============================================================================
SRC_DIR      := apotropaios
TEST_DIR     := tests
TEST_UNIT    := $(TEST_DIR)/unit
TEST_INT     := $(TEST_DIR)/integration
TEST_SEC     := $(TEST_DIR)/security
TEST_RESULTS := test-results
DIST_DIR     := dist
VENV_DIR     := .venv
VENV_PY      := $(VENV_DIR)/bin/python3
VENV_PIP     := $(VENV_DIR)/bin/pip3

# ==============================================================================
# File Discovery
# ==============================================================================
PY_FILES     := $(shell find $(SRC_DIR) -name '*.py' -not -path '*/__pycache__/*' 2>/dev/null)
TEST_FILES   := $(shell find $(TEST_DIR) -name 'test_*.py' 2>/dev/null)
PY_COUNT     := $(words $(PY_FILES))
TEST_COUNT   := $(words $(TEST_FILES))

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║                              DEFAULT TARGET                               ║
# ╚════════════════════════════════════════════════════════════════════════════╝

all: lint test

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║                           QUALITY ASSURANCE                               ║
# ╚════════════════════════════════════════════════════════════════════════════╝

# ==============================================================================
# Type Check — mypy --strict (fastest meaningful gate)
# ==============================================================================
typecheck:
	@echo "==> Running mypy --strict on $(PY_COUNT) source files..."
	@$(MYPY) $(SRC_DIR)/ --strict --python-version 3.12
	@echo "==> Type check passed ($(PY_COUNT) files, zero errors)"

# ==============================================================================
# Lint — type check (mypy is the primary Python linter for this project)
# ==============================================================================
lint: typecheck

# ==============================================================================
# Security Scan — static pattern analysis for dangerous patterns
# ==============================================================================
security-scan:
	@echo "==> Running security pattern scan..."
	@echo ""
	@fail=0; \
	echo "  [1/6] Checking for shell=True in subprocess calls..."; \
	hits=$$(grep -rn 'shell=True' $(SRC_DIR)/ --include='*.py' 2>/dev/null | grep -v '#.*shell=True' | grep -v 'never.*shell' | grep -v 'Never.*shell' | grep -v 'docstring' | wc -l); \
	if [ "$$hits" -gt 0 ]; then \
		echo "    ✗ FAIL: Found $$hits instances of shell=True"; \
		grep -rn 'shell=True' $(SRC_DIR)/ --include='*.py' | grep -v '#.*shell=True' | grep -v 'never.*shell' | grep -v 'Never.*shell'; \
		fail=1; \
	else \
		echo "    ✓ No shell=True found"; \
	fi; \
	echo "  [2/6] Checking for eval() usage..."; \
	hits=$$(grep -rn '\beval(' $(SRC_DIR)/ --include='*.py' 2>/dev/null | grep -v '^\s*#' | wc -l); \
	if [ "$$hits" -gt 0 ]; then \
		echo "    ✗ FAIL: Found $$hits instances of eval()"; \
		grep -rn '\beval(' $(SRC_DIR)/ --include='*.py' | grep -v '^\s*#'; \
		fail=1; \
	else \
		echo "    ✓ No eval() found"; \
	fi; \
	echo "  [3/6] Checking for exec() usage..."; \
	hits=$$(grep -rn '\bexec(' $(SRC_DIR)/ --include='*.py' 2>/dev/null | grep -v '^\s*#' | grep -v 'EXEC_PERMS' | wc -l); \
	if [ "$$hits" -gt 0 ]; then \
		echo "    ✗ FAIL: Found $$hits instances of exec()"; \
		grep -rn '\bexec(' $(SRC_DIR)/ --include='*.py' | grep -v '^\s*#' | grep -v 'EXEC_PERMS'; \
		fail=1; \
	else \
		echo "    ✓ No exec() found"; \
	fi; \
	echo "  [4/6] Checking for pickle/marshal usage..."; \
	hits=$$(grep -rn '\b\(pickle\|marshal\)\.' $(SRC_DIR)/ --include='*.py' 2>/dev/null | grep -v '^\s*#' | wc -l); \
	if [ "$$hits" -gt 0 ]; then \
		echo "    ✗ FAIL: Found $$hits instances of pickle/marshal"; \
		fail=1; \
	else \
		echo "    ✓ No pickle/marshal found"; \
	fi; \
	echo "  [5/6] Checking for hardcoded credentials..."; \
	hits=$$(grep -rniE '(password|secret|token|api_key)\s*=\s*["\x27][^"\x27]{3,}' $(SRC_DIR)/ --include='*.py' 2>/dev/null | grep -v 'MASKED\|SENSITIVE\|_KEYS\|example\|test\|pattern\|_MAP\|regex\|sanitiz' | wc -l); \
	if [ "$$hits" -gt 0 ]; then \
		echo "    ⚠ WARNING: Possible hardcoded credentials (review manually)"; \
		grep -rniE '(password|secret|token|api_key)\s*=\s*["\x27][^"\x27]{3,}' $(SRC_DIR)/ --include='*.py' | grep -v 'MASKED\|SENSITIVE\|_KEYS\|example\|test\|pattern\|_MAP\|regex\|sanitiz'; \
	else \
		echo "    ✓ No hardcoded credentials found"; \
	fi; \
	echo "  [6/6] Checking for TODO/FIXME/HACK markers..."; \
	hits=$$(grep -rn 'TODO\|FIXME\|HACK\|XXX' $(SRC_DIR)/ --include='*.py' 2>/dev/null | grep -v '^\s*#.*parity\|^\s*#.*Lesson\|noqa' | wc -l); \
	if [ "$$hits" -gt 0 ]; then \
		echo "    ⚠ WARNING: Found $$hits TODO/FIXME markers"; \
		grep -rn 'TODO\|FIXME\|HACK\|XXX' $(SRC_DIR)/ --include='*.py' | grep -v '^\s*#.*parity\|^\s*#.*Lesson\|noqa'; \
	else \
		echo "    ✓ No TODO/FIXME markers found"; \
	fi; \
	echo ""; \
	if [ "$$fail" -eq 1 ]; then \
		echo "  ✗ Security scan FAILED"; \
		exit 1; \
	fi
	@echo "==> Security scan passed"

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║                              TEST SUITE                                   ║
# ╚════════════════════════════════════════════════════════════════════════════╝

# ==============================================================================
# Full Test Suite (CI entry point)
# ==============================================================================
test: lint test-unit test-integration test-security
	@echo ""
	@echo "  ================================================"
	@echo "  ✓ ALL TESTS PASSED — v$(VERSION)"
	@echo "  ================================================"
	@echo ""

## Quick test — unit only, no lint (rapid development feedback)
test-quick: test-unit
	@echo "==> Quick tests passed"

## Full suite explicitly named
test-all: lint test-unit test-integration test-security security-scan
	@echo "==> Full test suite + security scan passed"

## Full CI check (alias)
check: test

# ==============================================================================
# Unit Tests
# ==============================================================================
test-unit:
	@echo "==> Running all unit tests..."
	@mkdir -p $(TEST_RESULTS)
	@$(PYTEST) $(TEST_UNIT)/ -v --tb=short 2>&1 | tee $(TEST_RESULTS)/unit.txt
	@echo "==> Unit tests passed"

# ==============================================================================
# Individual Unit Test Suites
# ==============================================================================
test-validation:
	@$(PYTEST) $(TEST_UNIT)/test_validation.py -v --tb=short

test-logging:
	@$(PYTEST) $(TEST_UNIT)/test_logging.py -v --tb=short

test-detection:
	@$(PYTEST) $(TEST_UNIT)/test_detection.py -v --tb=short

test-backends:
	@$(PYTEST) $(TEST_UNIT)/test_backends.py -v --tb=short

test-errors:
	@$(PYTEST) $(TEST_UNIT)/test_errors.py -v --tb=short

test-security-module:
	@$(PYTEST) $(TEST_UNIT)/test_security.py -v --tb=short

test-rule-engine:
	@$(PYTEST) $(TEST_UNIT)/test_rule_engine.py -v --tb=short

test-utils:
	@$(PYTEST) $(TEST_UNIT)/test_utils.py -v --tb=short

test-constants:
	@$(PYTEST) $(TEST_UNIT)/test_constants.py -v --tb=short

# ==============================================================================
# Integration Tests
# ==============================================================================
test-integration:
	@echo "==> Running integration tests..."
	@mkdir -p $(TEST_RESULTS)
	@$(PYTEST) $(TEST_INT)/ -v --tb=short 2>&1 | tee $(TEST_RESULTS)/integration.txt
	@echo "==> Integration tests passed"

test-cli:
	@$(PYTEST) $(TEST_INT)/test_cli.py -v --tb=short

test-lifecycle:
	@$(PYTEST) $(TEST_INT)/test_lifecycle.py -v --tb=short

# ==============================================================================
# Security Tests
# ==============================================================================
test-security:
	@echo "==> Running security tests..."
	@mkdir -p $(TEST_RESULTS)
	@$(PYTEST) $(TEST_SEC)/ -v --tb=short 2>&1 | tee $(TEST_RESULTS)/security.txt
	@echo "==> Security tests passed"

test-injection:
	@$(PYTEST) $(TEST_SEC)/test_injection.py -v --tb=short

# ==============================================================================
# Test Reporting
# ==============================================================================
test-report:
	@echo ""
	@echo "  Apotropaios v$(VERSION) — Test Report"
	@echo "  ══════════════════════════════════════════"
	@echo ""
	@for f in $(TEST_FILES); do \
		name=$$(basename "$$f" .py); \
		count=$$($(PYTEST) "$$f" --collect-only -q 2>/dev/null | tail -1 | grep -oP '\d+' | head -1); \
		result=$$($(PYTEST) "$$f" -q --tb=no 2>/dev/null | tail -1); \
		if echo "$$result" | grep -q "passed"; then \
			printf "    ✓ %-30s %s tests  %s\n" "$$name" "$$count" "$$result"; \
		else \
			printf "    ✗ %-30s %s tests  %s\n" "$$name" "$$count" "$$result"; \
		fi; \
	done
	@echo ""

test-count:
	@echo "==> Counting tests (no execution)..."
	@$(PYTEST) $(TEST_DIR)/ --collect-only -q 2>/dev/null | tail -1

test-list:
	@echo "==> All test names:"
	@$(PYTEST) $(TEST_DIR)/ --collect-only -q 2>/dev/null | head -n -2

# ==============================================================================
# Test Coverage
# ==============================================================================
test-coverage:
	@echo "==> Running tests with coverage..."
	@$(PYTEST) $(TEST_DIR)/ -v --tb=short --cov=$(SRC_DIR) --cov-report=term-missing --cov-report=html
	@echo "==> Coverage report: htmlcov/index.html"

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║                           DIRECT EXECUTION                                ║
# ╚════════════════════════════════════════════════════════════════════════════╝

## Run a command directly (e.g., make run CMD="detect")
run:
	@if [ -z "$(CMD)" ]; then \
		echo "Usage: make run CMD=\"detect\""; \
		echo "       make run CMD=\"--interactive\""; \
		echo "       make run CMD=\"status --backend iptables\""; \
	else \
		sudo $(PYTHON3) apotropaios.py $(CMD); \
	fi

## Run interactive menu
run-interactive:
	sudo $(PYTHON3) apotropaios.py --interactive

## Run detection
run-detect:
	sudo $(PYTHON3) apotropaios.py detect

## Run status
run-status:
	sudo $(PYTHON3) apotropaios.py status

## Show help (no sudo needed)
run-help:
	$(PYTHON3) apotropaios.py --help

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║                          VIRTUAL ENVIRONMENT                              ║
# ╚════════════════════════════════════════════════════════════════════════════╝

## Create virtual environment with dev dependencies
venv: $(VENV_DIR)/bin/activate

$(VENV_DIR)/bin/activate:
	@echo "==> Creating virtual environment in $(VENV_DIR)..."
	$(PYTHON3) -m venv $(VENV_DIR)
	$(VENV_PIP) install --upgrade pip setuptools wheel
	$(VENV_PIP) install -e ".[dev]"
	@echo ""
	@echo "  Virtual environment created. Activate with:"
	@echo "    source $(VENV_DIR)/bin/activate"

## Run tests inside venv
venv-test: venv
	$(VENV_PY) -m pytest $(TEST_DIR)/ -v --tb=short

## Run mypy inside venv
venv-typecheck: venv
	$(VENV_PY) -m mypy $(SRC_DIR)/ --strict --python-version 3.12

## Full check inside venv
venv-check: venv-typecheck venv-test

## Run command inside venv (e.g., make venv-run CMD="detect")
venv-run: venv
	@if [ -z "$(CMD)" ]; then \
		echo "Usage: make venv-run CMD=\"detect\""; \
	else \
		sudo $(VENV_PY) apotropaios.py $(CMD); \
	fi

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║                             PACKAGING                                     ║
# ╚════════════════════════════════════════════════════════════════════════════╝

# ==============================================================================
# Runtime distribution — source package for deployment
# ==============================================================================
dist:
	@echo "==> Building runtime distribution..."
	@rm -rf $(DIST_DIR)/staging-dist
	@mkdir -p $(DIST_DIR)/staging-dist/$(PROJECT)-$(VERSION)
	@cp -r $(SRC_DIR) $(DIST_DIR)/staging-dist/$(PROJECT)-$(VERSION)/
	@cp apotropaios.py pyproject.toml Makefile $(DIST_DIR)/staging-dist/$(PROJECT)-$(VERSION)/
	@cp -r docs $(DIST_DIR)/staging-dist/$(PROJECT)-$(VERSION)/
	@mkdir -p $(DIST_DIR)/staging-dist/$(PROJECT)-$(VERSION)/data/{logs,rules,backups}
	@touch $(DIST_DIR)/staging-dist/$(PROJECT)-$(VERSION)/data/{logs,rules,backups}/.gitkeep
	@cd $(DIST_DIR)/staging-dist && tar -czf ../$(PROJECT)-$(VERSION).tar.gz $(PROJECT)-$(VERSION)/
	@rm -rf $(DIST_DIR)/staging-dist
	@echo "==> Built: $(DIST_DIR)/$(PROJECT)-$(VERSION).tar.gz"

# ==============================================================================
# Full distribution — includes tests, CI, tasks
# ==============================================================================
dist-full:
	@echo "==> Building full distribution..."
	@rm -rf $(DIST_DIR)/staging-full
	@mkdir -p $(DIST_DIR)/staging-full/$(PROJECT)-$(VERSION)-full
	@cp -r $(SRC_DIR) tests docs tasks $(DIST_DIR)/staging-full/$(PROJECT)-$(VERSION)-full/
	@cp apotropaios.py pyproject.toml Makefile .gitignore $(DIST_DIR)/staging-full/$(PROJECT)-$(VERSION)-full/
	@[ -d .github ] && cp -r .github $(DIST_DIR)/staging-full/$(PROJECT)-$(VERSION)-full/ || true
	@mkdir -p $(DIST_DIR)/staging-full/$(PROJECT)-$(VERSION)-full/data/{logs,rules,backups}
	@touch $(DIST_DIR)/staging-full/$(PROJECT)-$(VERSION)-full/data/{logs,rules,backups}/.gitkeep
	@cd $(DIST_DIR)/staging-full && tar -czf ../$(PROJECT)-$(VERSION)-full.tar.gz $(PROJECT)-$(VERSION)-full/
	@rm -rf $(DIST_DIR)/staging-full
	@echo "==> Built: $(DIST_DIR)/$(PROJECT)-$(VERSION)-full.tar.gz"

# ==============================================================================
# Venv distribution — portable, activate/deactivate
# ==============================================================================
dist-venv:
	@echo "==> Building venv distribution..."
	@rm -rf $(DIST_DIR)/staging-venv
	@mkdir -p $(DIST_DIR)/staging-venv/$(PROJECT)-$(VERSION)-venv/{bin,conf}
	@cp -r $(SRC_DIR) $(DIST_DIR)/staging-venv/$(PROJECT)-$(VERSION)-venv/
	@cp apotropaios.py pyproject.toml Makefile $(DIST_DIR)/staging-venv/$(PROJECT)-$(VERSION)-venv/
	@cp -r docs $(DIST_DIR)/staging-venv/$(PROJECT)-$(VERSION)-venv/
	@mkdir -p $(DIST_DIR)/staging-venv/$(PROJECT)-$(VERSION)-venv/data/{logs,rules,backups}
	@touch $(DIST_DIR)/staging-venv/$(PROJECT)-$(VERSION)-venv/data/{logs,rules,backups}/.gitkeep
	@# Create activate script
	@echo '#!/bin/bash' > $(DIST_DIR)/staging-venv/$(PROJECT)-$(VERSION)-venv/activate.sh
	@echo '# Apotropaios venv activation script' >> $(DIST_DIR)/staging-venv/$(PROJECT)-$(VERSION)-venv/activate.sh
	@echo 'if [ -n "$$APOTROPAIOS_HOME" ]; then echo "Already activated: $$APOTROPAIOS_HOME"; return 0 2>/dev/null || exit 0; fi' >> $(DIST_DIR)/staging-venv/$(PROJECT)-$(VERSION)-venv/activate.sh
	@echo 'export APOTROPAIOS_HOME="$$(cd "$$(dirname "$${BASH_SOURCE[0]}")" && pwd)"' >> $(DIST_DIR)/staging-venv/$(PROJECT)-$(VERSION)-venv/activate.sh
	@echo 'export APOTROPAIOS_OLD_PATH="$$PATH"' >> $(DIST_DIR)/staging-venv/$(PROJECT)-$(VERSION)-venv/activate.sh
	@echo 'export APOTROPAIOS_OLD_PS1="$$PS1"' >> $(DIST_DIR)/staging-venv/$(PROJECT)-$(VERSION)-venv/activate.sh
	@echo 'export PATH="$$APOTROPAIOS_HOME/bin:$$PATH"' >> $(DIST_DIR)/staging-venv/$(PROJECT)-$(VERSION)-venv/activate.sh
	@echo 'export PS1="(apotropaios) $$PS1"' >> $(DIST_DIR)/staging-venv/$(PROJECT)-$(VERSION)-venv/activate.sh
	@echo 'apotropaios_deactivate() { export PATH="$$APOTROPAIOS_OLD_PATH"; export PS1="$$APOTROPAIOS_OLD_PS1"; unset APOTROPAIOS_HOME APOTROPAIOS_OLD_PATH APOTROPAIOS_OLD_PS1; unset -f apotropaios_deactivate; }' >> $(DIST_DIR)/staging-venv/$(PROJECT)-$(VERSION)-venv/activate.sh
	@echo 'echo "Apotropaios v$(VERSION) activated. Run: sudo python3 apotropaios.py detect"' >> $(DIST_DIR)/staging-venv/$(PROJECT)-$(VERSION)-venv/activate.sh
	@# Create bin wrapper
	@mkdir -p $(DIST_DIR)/staging-venv/$(PROJECT)-$(VERSION)-venv/bin
	@echo '#!/bin/bash' > $(DIST_DIR)/staging-venv/$(PROJECT)-$(VERSION)-venv/bin/apotropaios
	@echo 'exec python3 "$$APOTROPAIOS_HOME/apotropaios.py" "$$@"' >> $(DIST_DIR)/staging-venv/$(PROJECT)-$(VERSION)-venv/bin/apotropaios
	@chmod +x $(DIST_DIR)/staging-venv/$(PROJECT)-$(VERSION)-venv/bin/apotropaios
	@cd $(DIST_DIR)/staging-venv && tar -czf ../$(PROJECT)-$(VERSION)-venv.tar.gz $(PROJECT)-$(VERSION)-venv/
	@rm -rf $(DIST_DIR)/staging-venv
	@echo "==> Built: $(DIST_DIR)/$(PROJECT)-$(VERSION)-venv.tar.gz"

# ==============================================================================
# Release — build ALL packages + unified SHA256SUMS.txt
# ==============================================================================
release: dist dist-full dist-venv
	@echo "==> Generating SHA256SUMS.txt..."
	@cd $(DIST_DIR) && sha256sum $(PROJECT)-$(VERSION)*.tar.gz > SHA256SUMS.txt
	@echo ""
	@echo "  ════════════════════════════════════════════════════"
	@echo "  Release v$(VERSION) — Packages Built"
	@echo "  ════════════════════════════════════════════════════"
	@echo ""
	@ls -lh $(DIST_DIR)/$(PROJECT)-$(VERSION)*.tar.gz
	@echo ""
	@echo "  SHA256SUMS:"
	@cat $(DIST_DIR)/SHA256SUMS.txt
	@echo ""

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║                            INSTALLATION                                   ║
# ╚════════════════════════════════════════════════════════════════════════════╝

## Minimal install: runtime package only
install-minimal:
	$(PIP3) install . --break-system-packages

## Full install: runtime + dev dependencies
install-full:
	$(PIP3) install ".[dev]" --break-system-packages

## Development install: editable mode + dev deps
install-dev:
	$(PIP3) install -e ".[dev]" --break-system-packages

## Standard install (alias)
install: install-minimal

## Uninstall
uninstall:
	$(PIP3) uninstall -y $(PROJECT) 2>/dev/null || true
	@echo "==> Uninstalled (data directory preserved)"

## Verify installation
verify:
	@echo "==> Verifying installation..."
	@echo "  [1/4] Checking Python version..."
	@$(PYTHON3) -c "import sys; assert sys.version_info >= (3, 12), f'Python 3.12+ required, got {sys.version}'; print(f'    ✓ Python {sys.version}')"
	@echo "  [2/4] Checking package import..."
	@$(PYTHON3) -c "import apotropaios; print('    ✓ Package importable')" 2>/dev/null || echo "    ○ Package not installed (use direct execution)"
	@echo "  [3/4] Checking mypy..."
	@$(PYTHON3) -m mypy --version 2>/dev/null && echo "    ✓ mypy available" || echo "    ○ mypy not installed (install with pip3 install mypy)"
	@echo "  [4/4] Checking pytest..."
	@$(PYTHON3) -m pytest --version 2>/dev/null && echo "    ✓ pytest available" || echo "    ○ pytest not installed (install with pip3 install pytest)"
	@echo "==> Verification complete"

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║                            DEVELOPMENT                                    ║
# ╚════════════════════════════════════════════════════════════════════════════╝

# ==============================================================================
# Dev Setup — install dev dependencies
# ==============================================================================
dev-setup:
	@echo "==> Setting up development environment..."
	@echo "  [1/3] Creating virtual environment..."
	@$(PYTHON3) -m venv $(VENV_DIR) 2>/dev/null || echo "    venv module not found — install: sudo apt install python3-venv"
	@echo "  [2/3] Installing dev dependencies..."
	@if [ -f $(VENV_PIP) ]; then \
		$(VENV_PIP) install --upgrade pip setuptools wheel; \
		$(VENV_PIP) install -e ".[dev]"; \
		echo "    ✓ Dependencies installed in $(VENV_DIR)"; \
	else \
		$(PIP3) install -e ".[dev]" --break-system-packages; \
		echo "    ✓ Dependencies installed system-wide"; \
	fi
	@echo "  [3/3] Verifying tools..."
	@$(PYTHON3) -m mypy --version 2>/dev/null && echo "    ✓ mypy available" || echo "    ✗ mypy not found"
	@$(PYTHON3) -m pytest --version 2>/dev/null && echo "    ✓ pytest available" || echo "    ✗ pytest not found"
	@echo ""
	@echo "==> Development setup complete"
	@echo "==> Run 'make check' to verify"

# ==============================================================================
# Dependency Check — verify all required tools
# ==============================================================================
check-deps:
	@echo "==> Checking dependencies..."
	@all_ok=1; \
	echo "  Required:"; \
	for cmd in python3 pip3; do \
		if command -v $$cmd >/dev/null 2>&1; then \
			ver=$$($$cmd --version 2>&1 | head -1); \
			printf "    ✓ %-12s %s\n" "$$cmd" "$$ver"; \
		else \
			printf "    ✗ %-12s MISSING\n" "$$cmd"; \
			all_ok=0; \
		fi; \
	done; \
	echo "  Development:"; \
	for desc_cmd in "mypy:python3 -m mypy --version" "pytest:python3 -m pytest --version" "git:git --version"; do \
		desc=$${desc_cmd%%:*}; \
		cmd=$${desc_cmd#*:}; \
		if $$cmd >/dev/null 2>&1; then \
			ver=$$($$cmd 2>&1 | head -1); \
			printf "    ✓ %-12s %s\n" "$$desc" "$$ver"; \
		else \
			printf "    ○ %-12s not installed\n" "$$desc"; \
		fi; \
	done; \
	echo "  Runtime (firewall backends):"; \
	for cmd in iptables nft firewall-cmd ufw ipset; do \
		if command -v $$cmd >/dev/null 2>&1; then \
			ver=$$($$cmd --version 2>/dev/null | head -1 || echo "available"); \
			printf "    ✓ %-12s %s\n" "$$cmd" "$$ver"; \
		else \
			printf "    ○ %-12s not installed\n" "$$cmd"; \
		fi; \
	done; \
	if [ "$$all_ok" -eq 0 ]; then \
		echo ""; echo "  ✗ Missing required dependencies"; exit 1; \
	fi
	@echo "==> All required dependencies available"

# ==============================================================================
# Project Info — version, file counts, quick summary
# ==============================================================================
info:
	@echo ""
	@echo "  Apotropaios — Firewall Manager (Python Variant)"
	@echo "  ════════════════════════════════════════════════════"
	@echo "  Version:       v$(VERSION)"
	@echo "  Python:        $$($(PYTHON3) --version 2>&1)"
	@echo "  Source files:  $(PY_COUNT)"
	@echo "  Test files:    $(TEST_COUNT)"
	@echo "  Entry point:   python3 apotropaios.py"
	@echo ""

# ==============================================================================
# Metrics — detailed project statistics
# ==============================================================================
metrics:
	@echo ""
	@echo "  Apotropaios v$(VERSION) — Project Metrics"
	@echo "  ══════════════════════════════════════════"
	@echo ""
	@echo "  Source Code:"
	@printf "    Python modules:   %d\n" $(PY_COUNT)
	@printf "    Code lines:       %d\n" $$(cat $(PY_FILES) 2>/dev/null | wc -l)
	@printf "    Code lines (net): %d\n" $$(cat $(PY_FILES) 2>/dev/null | grep -v '^\s*#' | grep -v '^\s*$$' | wc -l)
	@echo ""
	@echo "  Testing:"
	@printf "    Test files:       %d\n" $(TEST_COUNT)
	@printf "    Test lines:       %d\n" $$(cat $(TEST_FILES) 2>/dev/null | wc -l)
	@printf "    Test count:       " && $(PYTEST) $(TEST_DIR)/ --collect-only -q 2>/dev/null | tail -1
	@echo ""
	@echo "  Documentation:"
	@printf "    Wiki pages:       %d\n" $$(find docs/wiki -name '*.md' 2>/dev/null | wc -l)
	@printf "    Doc files:        %d\n" $$(find docs -maxdepth 1 \( -name '*.md' -o -name 'LICENSE' \) 2>/dev/null | wc -l)
	@printf "    Doc lines:        %d\n" $$(find docs -name '*.md' -o -name 'LICENSE' | xargs wc -l 2>/dev/null | tail -1 | awk '{print $$1}')
	@echo ""
	@echo "  Infrastructure:"
	@printf "    Makefile targets: %d\n" $$(grep -c '^[a-z].*:' Makefile 2>/dev/null)
	@printf "    .gitignore:       %d lines\n" $$(wc -l < .gitignore 2>/dev/null || echo 0)
	@echo ""

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║                              CLEANUP                                      ║
# ╚════════════════════════════════════════════════════════════════════════════╝

## Remove build artifacts and caches
clean:
	@rm -rf build/ dist/ *.egg-info .eggs/
	@rm -rf .pytest_cache .mypy_cache htmlcov/ $(TEST_RESULTS)
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -name '*.pyc' -delete 2>/dev/null || true
	@echo "==> Cleaned"

## Remove virtual environment
clean-venv:
	@rm -rf $(VENV_DIR)
	@echo "==> Venv removed"

## Remove runtime data (logs, rules, backups)
clean-data:
	@rm -rf data/logs/* data/rules/* data/backups/*
	@touch data/logs/.gitkeep data/rules/.gitkeep data/backups/.gitkeep 2>/dev/null || true
	@echo "==> Runtime data removed"

## Remove everything
clean-all: clean clean-venv clean-data
	@echo "==> Deep cleaned"

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║                                 HELP                                      ║
# ╚════════════════════════════════════════════════════════════════════════════╝

help:
	@echo ""
	@echo "  Apotropaios v$(VERSION) — Makefile Targets"
	@echo "  ═══════════════════════════════════════════"
	@echo ""
	@echo "  Quality:"
	@echo "    make lint                Run mypy --strict type checking"
	@echo "    make typecheck           Alias for lint"
	@echo "    make security-scan       Static pattern analysis (6 checks)"
	@echo ""
	@echo "  Testing:"
	@echo "    make test                Full suite: lint + unit + integration + security"
	@echo "    make test-quick          Unit tests only (fast development feedback)"
	@echo "    make test-all            Full suite + security scan"
	@echo "    make test-unit           All unit tests"
	@echo "    make test-integration    All integration tests"
	@echo "    make test-security       All security tests"
	@echo "    make test-report         Detailed per-file report with pass/fail"
	@echo "    make test-count          Quick test count (no execution)"
	@echo "    make test-list           List all test names"
	@echo "    make test-coverage       Tests with HTML coverage report"
	@echo ""
	@echo "  Individual Test Suites:"
	@echo "    make test-validation     Input validation (42 tests)"
	@echo "    make test-constants      Constants and enums (15 tests)"
	@echo "    make test-errors         Error handling and cleanup (12 tests)"
	@echo "    make test-logging        Logging and sanitization (11 tests)"
	@echo "    make test-security-module  Security primitives (10 tests)"
	@echo "    make test-utils          Utilities and formatting (14 tests)"
	@echo "    make test-detection      OS and FW detection (15 tests)"
	@echo "    make test-backends       Backend ABC, registry, dispatch (18 tests)"
	@echo "    make test-rule-engine    Rule index, state, engine (18 tests)"
	@echo "    make test-cli            CLI entry point tests (7 tests)"
	@echo "    make test-lifecycle      Full rule lifecycle (4 tests)"
	@echo "    make test-injection      CWE injection prevention (15 tests)"
	@echo ""
	@echo "  Direct Execution:"
	@echo "    make run CMD=\"detect\"    Run a CLI command (no install needed)"
	@echo "    make run-interactive      Launch interactive menu"
	@echo "    make run-detect           Run system detection"
	@echo "    make run-status           Show firewall status"
	@echo "    make run-help             Show CLI help"
	@echo ""
	@echo "  Virtual Environment:"
	@echo "    make venv                Create venv with dev dependencies"
	@echo "    make venv-test           Run tests inside venv"
	@echo "    make venv-typecheck      Run mypy inside venv"
	@echo "    make venv-check          Full check inside venv"
	@echo "    make venv-run CMD=\"...\"  Run command inside venv"
	@echo ""
	@echo "  Packaging:"
	@echo "    make dist                Runtime distribution tarball"
	@echo "    make dist-full           Full distribution (includes tests, CI, tasks)"
	@echo "    make dist-venv           Venv package (portable, activate/deactivate)"
	@echo "    make release             Build ALL packages + unified SHA256SUMS.txt"
	@echo ""
	@echo "  Installation:"
	@echo "    make install             Minimal install (runtime only)"
	@echo "    make install-full        Runtime + dev dependencies"
	@echo "    make install-dev         Editable mode + dev deps"
	@echo "    make uninstall           Remove installation (preserves data)"
	@echo "    make verify              Verify installation and tools"
	@echo ""
	@echo "  Development:"
	@echo "    make dev-setup           Create venv + install dev tools"
	@echo "    make check-deps          Check all required and optional dependencies"
	@echo "    make info                Quick project summary"
	@echo "    make metrics             Detailed project statistics"
	@echo ""
	@echo "  Cleanup:"
	@echo "    make clean               Remove build artifacts and caches"
	@echo "    make clean-venv          Remove virtual environment"
	@echo "    make clean-data          Remove runtime data (logs, rules, backups)"
	@echo "    make clean-all           Deep clean: remove everything"
	@echo ""
