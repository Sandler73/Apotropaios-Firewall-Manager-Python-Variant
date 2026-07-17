# ==============================================================================
# File:         tests/unit/test_install_interrupt.py
# Project:      Apotropaios - Firewall Manager (Python Variant)
# Synopsis:     Regression tests for installer hang and interrupt recovery
# Description:  Locks in the v1.6.1 installer non-interactive hardening
#               (every package operation closes stdin, apt carries dpkg
#               conffile force options and a lock timeout, single-package
#               upgrades use install --only-upgrade) and the v1.6.2
#               interruptible signal scope (SIGINT raises KeyboardInterrupt
#               inside the scope for menu recovery, terminates outside it,
#               and SIGTERM semantics are unaffected by the scope).
# Notes:        - Package managers are stubbed by patching subprocess.run in
#                 the installer module; no packages are touched
#               - Signal tests deliver a real SIGINT to this process inside
#                 pytest's main thread and restore handlers in finally
# Version:      1.6.2
# ==============================================================================
"""Regression tests for install/update hang and Ctrl+C recovery."""

from __future__ import annotations

import os
import signal
import subprocess
from typing import Any

import pytest

import apotropaios.install.installer as installer
from apotropaios.core.errors import CleanupStack, SignalHandler


# ==============================================================================
# Installer non-interactive invariants (finding: install/update hang)
# ==============================================================================

class _Recorder:
    """Records every subprocess.run invocation made by the installer."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        self.calls.append({"args": list(args), **kwargs})
        return subprocess.CompletedProcess(args=args, returncode=0, stdout=b"", stderr=b"")


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    rec = _Recorder()
    monkeypatch.setattr(installer.subprocess, "run", rec)
    return rec


class TestInstallerNonInteractive:
    """Every package operation must be incapable of blocking on stdin."""

    @pytest.mark.parametrize(
        "func",
        [
            installer._apt_install,
            installer._apt_update,
            installer._dnf_install,
            installer._dnf_update,
            installer._pacman_install,
            installer._pacman_update,
        ],
    )
    def test_stdin_closed_on_every_invocation(
        self, recorder: _Recorder, func: Any
    ) -> None:
        func("dummy-package")
        assert recorder.calls, "no subprocess invocation recorded"
        for call in recorder.calls:
            # An inherited stdin lets any residual package-manager prompt
            # block invisibly forever (the reported hang); DEVNULL delivers
            # EOF instead
            assert call.get("stdin") is subprocess.DEVNULL, call["args"]

    def test_every_invocation_has_timeout(self, recorder: _Recorder) -> None:
        for func in (
            installer._apt_install, installer._apt_update,
            installer._dnf_install, installer._dnf_update,
            installer._pacman_install, installer._pacman_update,
        ):
            func("dummy-package")
        for call in recorder.calls:
            assert call.get("timeout") == installer._CMD_T, call["args"]

    def test_apt_carries_conffile_and_lock_options(self, recorder: _Recorder) -> None:
        installer._apt_install("ufw")
        installer._apt_update("ufw")
        apt_ops = [c["args"] for c in recorder.calls
                   if c["args"][:2] in (["apt-get", "install"],)]
        assert apt_ops, "no apt-get install invocations recorded"
        for args in apt_ops:
            # dpkg conffile prompts are not silenced by -y; the force
            # options answer them with the safe default
            assert "Dpkg::Options::=--force-confdef" in args
            assert "Dpkg::Options::=--force-confold" in args
            assert "DPkg::Lock::Timeout=60" in args
        # apt-get update also bounds waiting on a concurrent dpkg lock
        update_ops = [c["args"] for c in recorder.calls
                      if c["args"][:2] == ["apt-get", "update"]]
        for args in update_ops:
            assert "DPkg::Lock::Timeout=60" in args

    def test_apt_environment_is_noninteractive(self, recorder: _Recorder) -> None:
        installer._apt_install("ufw")
        for call in recorder.calls:
            env = call.get("env") or {}
            assert env.get("DEBIAN_FRONTEND") == "noninteractive"
            assert env.get("APT_LISTCHANGES_FRONTEND") == "none"

    def test_apt_update_targets_single_package_upgrade(
        self, recorder: _Recorder
    ) -> None:
        installer._apt_update("ufw")
        upgrade_ops = [c["args"] for c in recorder.calls
                       if "--only-upgrade" in c["args"]]
        assert upgrade_ops, (
            "apt update path must use 'install --only-upgrade <pkg>' -- "
            "'apt-get upgrade <pkg>' does not upgrade a single package"
        )
        assert upgrade_ops[0][-1] == "ufw"


# ==============================================================================
# Interruptible signal scope (finding: Ctrl+C terminates the application)
# ==============================================================================

class TestInterruptibleScope:
    """SIGINT aborts the operation inside the scope; terminates outside it."""

    def _deliver_sigint(self) -> None:
        os.kill(os.getpid(), signal.SIGINT)

    def test_sigint_in_scope_raises_keyboard_interrupt(self) -> None:
        handler = SignalHandler(CleanupStack())
        handler.install()
        try:
            with pytest.raises(KeyboardInterrupt):
                with handler.interruptible():
                    self._deliver_sigint()
                    signal.pause() if hasattr(signal, "pause") else None
        finally:
            handler.uninstall()

    def test_sigint_outside_scope_executes_cleanup_and_exits(self) -> None:
        stack = CleanupStack()
        executed: list[str] = []
        stack.register(lambda: executed.append("cleanup"), "probe")
        handler = SignalHandler(stack)
        handler.install()
        try:
            with pytest.raises(SystemExit) as excinfo:
                self._deliver_sigint()
                signal.pause() if hasattr(signal, "pause") else None
            assert excinfo.value.code == 130
            assert executed == ["cleanup"]
        finally:
            handler.uninstall()

    def test_scope_nesting_restores_termination_semantics(self) -> None:
        handler = SignalHandler(CleanupStack())
        handler.install()
        try:
            with handler.interruptible():
                with handler.interruptible():
                    pass
                # Inner scope exit must not disable the outer scope
                with pytest.raises(KeyboardInterrupt):
                    self._deliver_sigint()
                    signal.pause() if hasattr(signal, "pause") else None
            # All scopes exited: SIGINT terminates again
            with pytest.raises(SystemExit):
                self._deliver_sigint()
                signal.pause() if hasattr(signal, "pause") else None
        finally:
            handler.uninstall()

    def test_sigterm_unaffected_by_scope(self) -> None:
        stack = CleanupStack()
        handler = SignalHandler(stack)
        handler.install()
        try:
            with handler.interruptible():
                with pytest.raises(SystemExit) as excinfo:
                    os.kill(os.getpid(), signal.SIGTERM)
                    signal.pause() if hasattr(signal, "pause") else None
                assert excinfo.value.code == 143
        finally:
            handler.uninstall()
