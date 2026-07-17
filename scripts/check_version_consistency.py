#!/usr/bin/env python3
# ==============================================================================
# File:         scripts/check_version_consistency.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Programmatic version-consistency verification
# Description:  Verifies that every version location in the repository agrees
#               with the canonical VERSION in apotropaios/core/constants.py:
#               pyproject.toml, the package __version__ export, the shipped
#               configuration file header, and the "# Version:" header line
#               of every Python module, test file, workflow file, issue
#               template, Makefile, and entrypoint. Exits non-zero listing
#               every mismatch when any location disagrees.
# Notes:        - Documentation files are exempt: docs carry no version
#                 identifiers outside the changelogs (fact-of policy)
#               - Run from the repository root
#               - Stdlib-only; no third-party dependencies
# Execution:    python3 scripts/check_version_consistency.py
# Version:      1.6.2
# ==============================================================================
"""Verify version consistency across every version-bearing file."""

from __future__ import annotations

import glob
import re
import sys

HEADER_RE = re.compile(r"^#? ?# ?Version:\s+(\S+)\s*$", re.MULTILINE)
SIMPLE_HEADER_RE = re.compile(r"^# Version:\s+(\S+)\s*$", re.MULTILINE)


def canonical_version() -> str:
    """Extract the canonical version from core constants.

    Returns:
        The VERSION string from apotropaios/core/constants.py.

    Raises:
        SystemExit: If the canonical version cannot be located.
    """
    with open("apotropaios/core/constants.py", encoding="utf-8") as f:
        source = f.read()
    match = re.search(r'^VERSION: Final\[str\] = "([^"]+)"$', source, re.MULTILINE)
    if not match:
        sys.stderr.write("FATAL: canonical VERSION not found in constants.py\n")
        raise SystemExit(2)
    return match.group(1)


def header_targets() -> list[str]:
    """Collect every file whose header must carry the canonical version.

    Returns:
        Sorted list of file paths with version-bearing headers.
    """
    patterns = (
        "apotropaios/**/*.py",
        "tests/**/*.py",
        "scripts/*.py",
        ".github/workflows/*.yml",
        ".github/ISSUE_TEMPLATE/*.yml",
    )
    files: set[str] = set()
    for pattern in patterns:
        for path in glob.glob(pattern, recursive=True):
            if "__pycache__" not in path:
                files.add(path)
    files.update(
        (
            "apotropaios.py",
            "Makefile",
            "apotropaios/conf/apotropaios.conf",
            ".github/PULL_REQUEST_TEMPLATE.md",
        )
    )
    return sorted(files)


def main() -> int:
    """Run all consistency checks.

    Returns:
        0 when every location matches; 1 with a mismatch listing otherwise.
    """
    version = canonical_version()
    mismatches: list[str] = []

    # pyproject.toml
    with open("pyproject.toml", encoding="utf-8") as f:
        pyproject = f.read()
    if f'version = "{version}"' not in pyproject:
        mismatches.append("pyproject.toml: version differs from canonical")

    # Header lines across all version-bearing files
    for path in header_targets():
        try:
            with open(path, encoding="utf-8") as f:
                content = f.read()
        except OSError as exc:
            mismatches.append(f"{path}: unreadable ({exc})")
            continue
        regex = SIMPLE_HEADER_RE if not path.endswith(".md") else HEADER_RE
        found = regex.findall(content)
        if not found:
            mismatches.append(f"{path}: missing '# Version:' header line")
            continue
        for value in found:
            if value != version:
                mismatches.append(f"{path}: header version {value} != {version}")

    # Package export
    sys.path.insert(0, ".")
    import apotropaios  # noqa: PLC0415 -- deliberate late import after path setup

    if apotropaios.__version__ != version:
        mismatches.append(
            f"apotropaios.__version__ {apotropaios.__version__} != {version}"
        )

    if mismatches:
        sys.stderr.write(f"Version consistency FAILED (canonical {version}):\n")
        for line in mismatches:
            sys.stderr.write(f"  - {line}\n")
        return 1

    print(f"Version consistency OK: all locations at {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
