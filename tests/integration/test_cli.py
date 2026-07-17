# ==============================================================================
# File:         tests/integration/test_cli.py
# Synopsis:     Integration tests for CLI entry point
# Version:      1.2.1
# ==============================================================================

import subprocess
import sys
import pytest


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    """Run the apotropaios CLI as a subprocess."""
    return subprocess.run(
        [sys.executable, "-m", "apotropaios", *args],
        capture_output=True, text=True, timeout=30,
    )


class TestCLIEntryPoint:
    def test_version(self) -> None:
        result = _run_cli("--version")
        assert result.returncode == 0
        assert "apotropaios" in result.stdout.lower() or "0.1.0" in result.stdout

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
