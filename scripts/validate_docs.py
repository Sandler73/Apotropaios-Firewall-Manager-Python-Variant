#!/usr/bin/env python3
# ==============================================================================
# File:         scripts/validate_docs.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Programmatic documentation verification
# Description:  Verifies documentation accuracy against source across docs/
#               and docs/wiki: (1) no version identifiers outside changelogs;
#               (2) per-file line counts in developer guides match source;
#               (3) total line-count references match source; (4) test-count
#               references match the collected pytest suite size; (5) CLI
#               command-count references match CLI_COMMANDS; (6) internal
#               wiki links resolve to existing pages; (7) relative links in
#               docs/ resolve to existing files. Exits non-zero listing every
#               finding when any check fails.
# Notes:        - Changelog files are exempt from version and metric checks:
#                 entries are historical records of the state at release
#               - Run from the repository root
#               - Stdlib-only; no third-party dependencies
# Execution:    python3 scripts/validate_docs.py
# Version:      1.6.2
# ==============================================================================
"""Verify documentation accuracy against the source tree."""

from __future__ import annotations

import glob
import os
import re
import subprocess
import sys

CHANGELOG_NAMES = ("CHANGELOG.md", "Changelog.md")
VERSION_REF_RE = re.compile(r"\bv\d+\.\d+\.\d+(?:-dev)?\b|\b\d+\.\d+\.\d+-dev\b")
LINE_COUNT_RE = re.compile(r"### `(apotropaios/[^`]+\.py)` \((\d+) lines\)")
REL_LINK_RE = re.compile(r"\[[^\]]*\]\((?!https?://|#|mailto:)([^)#\s]+)(?:#[^)\s]*)?\)")

# Version-like strings that are not framework version identifiers
VERSION_ALLOWLIST = {
    "1.1.10",  # bash reference variant parity target (v1.1.10)
}


def source_line_counts() -> tuple[dict[str, int], int]:
    """Count lines for every production module.

    Returns:
        Tuple of (per-file counts keyed by path, total).
    """
    counts: dict[str, int] = {}
    for path in glob.glob("apotropaios/**/*.py", recursive=True):
        if "__pycache__" in path:
            continue
        with open(path, encoding="utf-8") as f:
            content = f.read()
        counts[path] = content.count("\n") + (0 if content.endswith("\n") else 1)
    return counts, sum(counts.values())


def collected_test_count() -> int:
    """Collect the pytest suite size.

    Returns:
        Number of collected tests, or -1 if collection fails.
    """
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "--collect-only", "-q"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    match = re.search(r"(\d+) tests collected", result.stdout)
    return int(match.group(1)) if match else -1


def cli_command_count() -> int:
    """Count registered CLI commands.

    Returns:
        Length of CLI_COMMANDS from core constants.
    """
    sys.path.insert(0, ".")
    from apotropaios.core.constants import CLI_COMMANDS  # noqa: PLC0415

    return len(CLI_COMMANDS)


def doc_files() -> list[str]:
    """Collect every documentation file.

    Returns:
        Sorted list of markdown paths under docs/ (wiki included).
    """
    return sorted(glob.glob("docs/**/*.md", recursive=True))


def is_changelog(path: str) -> bool:
    """Return True when the path is a changelog file."""
    return os.path.basename(path) in CHANGELOG_NAMES


def check_version_refs(findings: list[str]) -> None:
    """Flag version identifiers outside changelogs."""
    for path in doc_files():
        if is_changelog(path):
            continue
        with open(path, encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                for match in VERSION_REF_RE.finditer(line):
                    value = match.group(0).lstrip("v")
                    if value in VERSION_ALLOWLIST:
                        continue
                    findings.append(
                        f"{path}:{lineno}: version identifier "
                        f"'{match.group(0)}' outside changelog"
                    )


def check_line_counts(findings: list[str]) -> None:
    """Verify per-file and total line counts in the developer guides."""
    counts, total = source_line_counts()
    total_fmt = f"{total:,}"
    for path in doc_files():
        if is_changelog(path):
            continue
        with open(path, encoding="utf-8") as f:
            content = f.read()
        for match in LINE_COUNT_RE.finditer(content):
            actual = counts.get(match.group(1))
            if actual is None:
                findings.append(
                    f"{path}: references nonexistent source file {match.group(1)}"
                )
            elif actual != int(match.group(2)):
                findings.append(
                    f"{path}: {match.group(1)} listed as {match.group(2)} "
                    f"lines, source has {actual}"
                )
        for stale in re.finditer(r"\b(\d{2},\d{3})\s+lines\b", content):
            if stale.group(1) != total_fmt:
                findings.append(
                    f"{path}: total line count {stale.group(1)} != {total_fmt}"
                )


def check_test_counts(findings: list[str]) -> None:
    """Verify test-count references against the collected suite."""
    import importlib.util

    if importlib.util.find_spec("yaml") is None:
        findings.append(
            "PyYAML is not installed: the CI meta-suite (tests/ci) is "
            "excluded from collection, so the collected total cannot match "
            "the documented suite size. Install pyyaml and re-run."
        )
        return
    actual = collected_test_count()
    if actual < 0:
        findings.append("pytest collection failed; cannot verify test counts")
        return
    # Only verify references that denote the SUITE TOTAL. Per-file and
    # per-tier subcounts (e.g. "68 tests" for one module) are legitimate and
    # not checked against the grand total.
    total_patterns = (
        re.compile(r"\b(\d+)\s+automated tests\b"),
        re.compile(r"\b(\d+)\s+tests across\b"),
        re.compile(r"\b(\d+)/(\d+)\s+(?:tests|passing)\b"),
        re.compile(r"mypy --strict \+ (\d+) tests\b"),
        re.compile(r"pytest:\s+(\d+)/(\d+)\b"),
    )
    for path in doc_files():
        if is_changelog(path):
            continue
        with open(path, encoding="utf-8") as f:
            content = f.read()
        for pattern in total_patterns:
            for match in pattern.finditer(content):
                for group in match.groups():
                    if group and int(group) != actual:
                        findings.append(
                            f"{path}: suite-total reference {group} "
                            f"!= collected {actual}"
                        )


def check_command_counts(findings: list[str]) -> None:
    """Verify CLI command-count references against CLI_COMMANDS."""
    actual = cli_command_count()
    pattern = re.compile(r"\b(\d+)\s+(?:CLI\s+commands|subcommands)\b")
    for path in doc_files():
        if is_changelog(path):
            continue
        with open(path, encoding="utf-8") as f:
            content = f.read()
        for match in pattern.finditer(content):
            if int(match.group(1)) != actual:
                findings.append(
                    f"{path}: command count {match.group(1)} != actual {actual}"
                )


def _link_targets(content: str) -> list[str]:
    """Extract markdown link targets, balancing nested parentheses.

    A simple regex cannot balance the nested parentheses in wiki page names
    such as "Frequently-Asked-Questions-(FAQ)", so the closing delimiter is
    found by paren-depth scanning from each "](" opener.

    Args:
        content: Markdown text.

    Returns:
        List of raw link target strings.
    """
    targets: list[str] = []
    idx = 0
    while True:
        start = content.find("](", idx)
        if start == -1:
            break
        cursor = start + 2
        depth = 1
        while cursor < len(content) and depth > 0:
            char = content[cursor]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            cursor += 1
        if depth == 0:
            targets.append(content[start + 2 : cursor - 1])
        idx = cursor
    return targets


def check_wiki_links(findings: list[str]) -> None:
    """Verify internal wiki links resolve to existing pages."""
    wiki_pages = {
        os.path.splitext(os.path.basename(p))[0]
        for p in glob.glob("docs/wiki/*.md")
    }
    for path in sorted(glob.glob("docs/wiki/*.md")):
        with open(path, encoding="utf-8") as f:
            content = f.read()
        for target in _link_targets(content):
            target = target.split("#", 1)[0]
            if not target or target.startswith(("http://", "https://", "mailto:")):
                continue
            if "/" in target or target.endswith(".md"):
                continue  # external or relative-file link
            if target not in wiki_pages:
                findings.append(f"{path}: wiki link to missing page '{target}'")


def check_relative_links(findings: list[str]) -> None:
    """Verify relative file links in docs/ (non-wiki) resolve."""
    for path in sorted(glob.glob("docs/*.md")):
        base = os.path.dirname(path)
        with open(path, encoding="utf-8") as f:
            content = f.read()
        for match in REL_LINK_RE.finditer(content):
            target = match.group(1)
            if not target.endswith((".md", ".py", ".toml", ".conf", ".yml")):
                continue
            resolved = os.path.normpath(os.path.join(base, target))
            if not os.path.exists(resolved):
                findings.append(f"{path}: relative link to missing file '{target}'")


def check_no_emdash(findings: list[str]) -> None:
    """Flag em-dash (U+2014) characters anywhere in the repository.

    Project style prohibits the em-dash in all code, comments,
    documentation, and configuration; approved substitutes are "--", "-",
    ":" and ",". The scan covers every text artifact type in the tree,
    not only documentation, because the prohibition is repository-wide.
    """
    em_dash = "\u2014"
    patterns = (
        "**/*.py", "**/*.md", "**/*.yml", "**/*.toml", "**/*.conf", "Makefile",
    )
    for pattern in patterns:
        for path in glob.glob(pattern, recursive=True):
            if "__pycache__" in path or path.startswith((".git/", "data/")):
                continue
            if path == "scripts/validate_docs.py":
                continue  # this file defines the character via escape only
            try:
                with open(path, encoding="utf-8") as f:
                    for lineno, line in enumerate(f, 1):
                        if em_dash in line:
                            findings.append(
                                f"{path}:{lineno}: em-dash (U+2014) present"
                            )
            except (OSError, UnicodeDecodeError):
                continue


def main() -> int:
    """Run all documentation checks.

    Returns:
        0 when documentation is accurate; 1 with a findings listing otherwise.
    """
    findings: list[str] = []
    check_no_emdash(findings)
    check_version_refs(findings)
    check_line_counts(findings)
    check_test_counts(findings)
    check_command_counts(findings)
    check_wiki_links(findings)
    check_relative_links(findings)

    if findings:
        sys.stderr.write(f"Documentation verification FAILED ({len(findings)}):\n")
        for line in findings:
            sys.stderr.write(f"  - {line}\n")
        return 1

    print("Documentation verification OK: all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
