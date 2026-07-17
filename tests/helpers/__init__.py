# ==============================================================================
# File:         tests/helpers/__init__.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Shared test helper utilities
# Description:  Reusable helpers for the pytest suite: a fake subprocess
#               result factory and a patchable runner recorder for exercising
#               backend command paths without invoking real firewall tools.
# Notes:        - Import from tests via: from tests.helpers import make_completed
# Version:      1.6.2
# ==============================================================================
"""Shared helpers for the Apotropaios test suite."""

from __future__ import annotations

import subprocess
from typing import Any


def make_completed(
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
    args: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Build a subprocess.CompletedProcess for stubbing backend _run calls.

    Args:
        returncode: Process exit status to simulate.
        stdout:     Captured standard output text.
        stderr:     Captured standard error text.
        args:       The argument list the fake process represents.

    Returns:
        A CompletedProcess mirroring what backend _run helpers return.
    """
    return subprocess.CompletedProcess(
        args=args or [], returncode=returncode, stdout=stdout, stderr=stderr
    )


class RecordingRunner:
    """Callable that records invocations and returns queued fake results.

    Replaces a backend module's _run during a test so command construction
    can be asserted without executing firewall binaries. Each call pops the
    next queued result, defaulting to success when the queue is empty.
    """

    def __init__(self, results: list[subprocess.CompletedProcess[str]] | None = None) -> None:
        self.calls: list[list[str]] = []
        self._results: list[subprocess.CompletedProcess[str]] = list(results or [])

    def __call__(self, args: list[str], *rest: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(args))
        if self._results:
            return self._results.pop(0)
        return make_completed(0, args=list(args))
