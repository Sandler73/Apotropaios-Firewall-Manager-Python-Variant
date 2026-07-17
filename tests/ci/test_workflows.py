# ==============================================================================
# File:         tests/ci/test_workflows.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Meta-tests validating workflow and issue-template files
# Description:  Validates the repository's GitHub automation as data: every
#               workflow and issue template parses as YAML, action pins match
#               the project standard (checkout@v6, upload-artifact@v6), each
#               workflow declares triggers/permissions/jobs, issue templates
#               declare the required form fields, the chooser disables blank
#               issues, and version-bearing headers match the canonical
#               framework version. These tests fail a PR that breaks the
#               automation without needing to dispatch the workflows.
# Notes:        - Requires PyYAML (declared as a dev/CI dependency)
#               - Skips gracefully if the .github tree is absent
# Version:      1.6.2
# ==============================================================================
"""Validate GitHub workflows and issue templates as structured data."""

from __future__ import annotations

import glob
import os
import re

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)
WORKFLOW_DIR = os.path.join(REPO_ROOT, ".github", "workflows")
TEMPLATE_DIR = os.path.join(REPO_ROOT, ".github", "ISSUE_TEMPLATE")

# Project action-pin standard
PINNED_ACTIONS = {
    "actions/checkout": "v6",
    "actions/upload-artifact": "v6",
    "actions/download-artifact": "v6",
    "actions/setup-python": "v6",
    "github/codeql-action/init": "v4",
    "github/codeql-action/analyze": "v4",
}


def _canonical_version() -> str:
    """Read the canonical framework version from core constants."""
    path = os.path.join(REPO_ROOT, "apotropaios", "core", "constants.py")
    with open(path, encoding="utf-8") as f:
        match = re.search(
            r'^VERSION: Final\[str\] = "([^"]+)"$', f.read(), re.MULTILINE
        )
    assert match is not None, "canonical VERSION not found"
    return match.group(1)


def _workflow_files() -> list[str]:
    return sorted(glob.glob(os.path.join(WORKFLOW_DIR, "*.yml")))


def _template_files() -> list[str]:
    return sorted(
        p
        for p in glob.glob(os.path.join(TEMPLATE_DIR, "*.yml"))
        if os.path.basename(p) != "config.yml"
    )


def _uses_lines(path: str) -> list[str]:
    with open(path, encoding="utf-8") as f:
        return [
            line.split("uses:", 1)[1].strip()
            for line in f
            if "uses:" in line
        ]


# ==============================================================================
# Presence
# ==============================================================================

class TestPresence:
    """The expected automation files must exist."""

    def test_workflow_directory_exists(self) -> None:
        assert os.path.isdir(WORKFLOW_DIR)

    @pytest.mark.parametrize(
        "name", ["ci.yml", "release.yml", "security.yml", "codeql.yml", "docs-validate.yml"]
    )
    def test_expected_workflow_present(self, name: str) -> None:
        assert os.path.isfile(os.path.join(WORKFLOW_DIR, name))

    @pytest.mark.parametrize(
        "name",
        [
            "bug_report.yml",
            "feature_request.yml",
            "documentation.yml",
            "platform_support.yml",
            "config.yml",
        ],
    )
    def test_expected_template_present(self, name: str) -> None:
        assert os.path.isfile(os.path.join(TEMPLATE_DIR, name))

    def test_pull_request_template_present(self) -> None:
        assert os.path.isfile(
            os.path.join(REPO_ROOT, ".github", "PULL_REQUEST_TEMPLATE.md")
        )


# ==============================================================================
# Workflow validity
# ==============================================================================

class TestWorkflowValidity:
    """Every workflow must be well-formed and declare the required keys."""

    def test_all_workflows_parse(self) -> None:
        for path in _workflow_files():
            with open(path, encoding="utf-8") as f:
                assert yaml.safe_load(f) is not None, path

    def test_workflows_declare_triggers_and_jobs(self) -> None:
        for path in _workflow_files():
            with open(path, encoding="utf-8") as f:
                doc = yaml.safe_load(f)
            # PyYAML parses the bare `on:` key as boolean True
            assert True in doc or "on" in doc, f"{path}: no trigger"
            assert doc.get("jobs"), f"{path}: no jobs"
            assert "permissions" in doc, f"{path}: no permissions block"

    def test_action_pins_match_project_standard(self) -> None:
        for path in _workflow_files():
            for used in _uses_lines(path):
                if "@" not in used:
                    continue
                name, _, ref = used.partition("@")
                if name in PINNED_ACTIONS:
                    assert ref == PINNED_ACTIONS[name], (
                        f"{path}: {name} pinned at {ref}, "
                        f"expected {PINNED_ACTIONS[name]}"
                    )

    def test_no_bare_pip_or_python(self) -> None:
        # Project standard: pip3/python3, never bare pip/python in run steps
        bare = re.compile(r"(?:^|\s|&&|\|)(pip|python)(?:\s|$)")
        for path in _workflow_files():
            with open(path, encoding="utf-8") as f:
                for lineno, line in enumerate(f, 1):
                    stripped = line.strip()
                    if not stripped.startswith(("run:", "-", "python3", "pip3")) \
                            and "run:" not in stripped:
                        continue
                    # Only inspect command content, not YAML keys/comments
                    if stripped.startswith("#"):
                        continue
                    if bare.search(line) and "python-version" not in line:
                        raise AssertionError(
                            f"{path}:{lineno}: bare pip/python -- use pip3/python3"
                        )

    def test_ci_has_core_jobs(self) -> None:
        with open(os.path.join(WORKFLOW_DIR, "ci.yml"), encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        jobs = set(doc["jobs"].keys())
        for required in ("lint", "typecheck", "test", "security", "consistency"):
            assert required in jobs, f"ci.yml missing job: {required}"

    def test_release_gates_on_version(self) -> None:
        with open(os.path.join(WORKFLOW_DIR, "release.yml"), encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        assert "version-gate" in doc["jobs"], "release.yml lacks version gate"
        assert doc["jobs"]["ci"].get("needs") == "version-gate"


# ==============================================================================
# Issue-template validity
# ==============================================================================

class TestIssueTemplates:
    """Issue forms must be well-formed and declare required metadata."""

    def test_all_templates_parse(self) -> None:
        for path in _template_files():
            with open(path, encoding="utf-8") as f:
                assert yaml.safe_load(f) is not None, path

    def test_templates_declare_name_and_body(self) -> None:
        for path in _template_files():
            with open(path, encoding="utf-8") as f:
                doc = yaml.safe_load(f)
            assert doc.get("name"), f"{path}: no name"
            assert doc.get("description"), f"{path}: no description"
            assert isinstance(doc.get("body"), list) and doc["body"], (
                f"{path}: no body fields"
            )

    def test_body_fields_have_valid_types(self) -> None:
        valid = {"markdown", "input", "textarea", "dropdown", "checkboxes"}
        for path in _template_files():
            with open(path, encoding="utf-8") as f:
                doc = yaml.safe_load(f)
            for field in doc["body"]:
                assert field.get("type") in valid, (
                    f"{path}: invalid field type {field.get('type')}"
                )

    def test_config_disables_blank_issues(self) -> None:
        with open(os.path.join(TEMPLATE_DIR, "config.yml"), encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        assert doc.get("blank_issues_enabled") is False
        assert doc.get("contact_links"), "config.yml has no contact links"

    def test_security_disclosure_link_present(self) -> None:
        with open(os.path.join(TEMPLATE_DIR, "config.yml"), encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        names = " ".join(link.get("name", "") for link in doc["contact_links"])
        assert "Security" in names, "no security disclosure contact link"


# ==============================================================================
# Header version consistency
# ==============================================================================

class TestHeaderVersions:
    """Automation file headers must match the canonical framework version."""

    def test_workflow_headers_match(self) -> None:
        version = _canonical_version()
        for path in _workflow_files():
            with open(path, encoding="utf-8") as f:
                content = f.read()
            found = re.findall(r"^# Version:\s+(\S+)$", content, re.MULTILINE)
            assert found, f"{path}: no version header"
            assert all(v == version for v in found), f"{path}: {found} != {version}"

    def test_script_headers_match(self) -> None:
        version = _canonical_version()
        for path in glob.glob(os.path.join(REPO_ROOT, "scripts", "*.py")):
            with open(path, encoding="utf-8") as f:
                content = f.read()
            found = re.findall(r"^# Version:\s+(\S+)$", content, re.MULTILINE)
            assert found, f"{path}: no version header"
            assert all(v == version for v in found), f"{path}: {found} != {version}"

    def test_template_headers_match(self) -> None:
        version = _canonical_version()
        for path in glob.glob(os.path.join(TEMPLATE_DIR, "*.yml")):
            with open(path, encoding="utf-8") as f:
                content = f.read()
            found = re.findall(r"^# Version:\s+(\S+)$", content, re.MULTILINE)
            assert found, f"{path}: no version header"
            assert all(v == version for v in found), f"{path}: {found} != {version}"


# ==============================================================================
# Repository integrity
# ==============================================================================

class TestRepositoryIntegrity:
    """Critical paths must be tracked by git, not swallowed by ignore rules.

    A bare "core" gitignore pattern once excluded the entire
    apotropaios/core/ package from the repository, so pushes to GitHub were
    missing the framework's canonical constants and every core module, and
    the CI consistency and documentation jobs failed on checkout. This
    guard fails the suite whenever an ignore rule captures a critical path.
    """

    CRITICAL_PATHS = (
        "apotropaios/core/constants.py",
        "apotropaios/core/errors.py",
        "apotropaios/core/logging.py",
        "apotropaios/core/security.py",
        "apotropaios/core/utils.py",
        "apotropaios/core/validation.py",
        "apotropaios/conf/apotropaios.conf",
        "apotropaios/cli.py",
        "scripts/check_version_consistency.py",
        "scripts/validate_docs.py",
        "pyproject.toml",
        "Makefile",
    )

    def test_no_critical_path_is_gitignored(self) -> None:
        import subprocess

        probe = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, cwd=REPO_ROOT,
        )
        if probe.returncode != 0 or probe.stdout.strip() != "true":
            pytest.skip("not a git work tree")
        result = subprocess.run(
            ["git", "check-ignore", "--stdin"],
            input="\n".join(self.CRITICAL_PATHS),
            capture_output=True, text=True, cwd=REPO_ROOT,
        )
        ignored = [line for line in result.stdout.splitlines() if line.strip()]
        assert not ignored, (
            f"gitignore rules exclude critical framework paths: {ignored}"
        )
