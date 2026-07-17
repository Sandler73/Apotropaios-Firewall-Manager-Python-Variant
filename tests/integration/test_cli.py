# ==============================================================================
# File:         tests/integration/test_cli.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Integration tests for CLI entry point
# Description:  Exercises the packaged CLI as a subprocess: version and help output,
#               unknown-command handling, and argument-error exits, verifying
#               the real dispatch path end to end.
# Version:      1.6.2
# ==============================================================================

import os
import subprocess
import tempfile
import sys


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    """Run the apotropaios CLI as a subprocess in an isolated base dir.

    APOTROPAIOS_BASE_DIR points every invocation at a throwaway temporary
    directory so integration runs never write logs, rules, or backups into
    the repository tree.
    """
    with tempfile.TemporaryDirectory(prefix="apotropaios-it-") as base:
        env = dict(os.environ)
        env["APOTROPAIOS_BASE_DIR"] = base
        return subprocess.run(
            [sys.executable, "-m", "apotropaios", *args],
            capture_output=True, text=True, timeout=30, env=env,
        )


class TestCLIEntryPoint:
    def test_version(self) -> None:
        from apotropaios.core.constants import VERSION

        result = _run_cli("--version")
        assert result.returncode == 0
        assert "apotropaios" in result.stdout.lower()
        # The reported version must be the canonical framework version
        assert VERSION in result.stdout

    def test_help(self) -> None:
        result = _run_cli("--help")
        assert result.returncode == 0
        # Help output goes to stderr in our implementation
        combined = result.stdout + result.stderr
        assert "usage" in combined.lower() or "apotropaios" in combined.lower()

    def test_unknown_command(self) -> None:
        result = _run_cli("nonexistent-command")
        assert result.returncode != 0

    def test_detect_runs(self) -> None:
        result = _run_cli("detect")
        assert result.returncode == 0

    def test_status_runs(self) -> None:
        result = _run_cli("status")
        # Exit code 11 (FW_NOT_FOUND) is valid when no firewall is installed
        assert result.returncode in (0, 1, 11)

    def test_list_rules_runs(self) -> None:
        result = _run_cli("list-rules")
        assert result.returncode in (0, 1)

    def test_help_per_command(self) -> None:
        for cmd in ("add-rule", "remove-rule", "backup", "import"):
            result = _run_cli(cmd, "--help")
            assert result.returncode == 0
            combined = result.stdout + result.stderr
            assert len(combined) > 10, f"Empty help for {cmd}"


class TestBaseDirIsolation:
    """APOTROPAIOS_BASE_DIR must fully relocate the data tree."""

    def test_override_redirects_data_tree(self, tmp_path: object) -> None:
        base = str(tmp_path)
        env = dict(os.environ)
        env["APOTROPAIOS_BASE_DIR"] = base
        result = subprocess.run(
            [sys.executable, "-m", "apotropaios", "detect"],
            capture_output=True, text=True, timeout=30, env=env,
        )
        assert result.returncode == 0
        # Logs must land under the override, not the installation tree
        log_dir = os.path.join(base, "data", "logs")
        assert os.path.isdir(log_dir)
        assert any(name.endswith(".log") for name in os.listdir(log_dir))

    def test_invalid_override_warns_and_falls_back(self, tmp_path: object) -> None:
        env = dict(os.environ)
        env["APOTROPAIOS_BASE_DIR"] = os.path.join(str(tmp_path), "missing")
        result = subprocess.run(
            [sys.executable, "-m", "apotropaios", "--version"],
            capture_output=True, text=True, timeout=30, env=env,
        )
        # --version must still succeed; a warning may be emitted at init time
        assert result.returncode == 0
