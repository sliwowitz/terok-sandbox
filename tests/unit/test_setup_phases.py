# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the sandbox-wide setup phase functions.

These cover the individual phases ``_handle_sandbox_setup`` wires together:
prereq reporting, shield / vault / gate / clearance install, and the
shared lifecycle helpers.  The aggregator orchestration itself is
tested in ``test_setup_aggregator.py``.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from terok_sandbox._setup import (
    _enable_user_unit,
    _PhaseResult,
    _stage,
    _stop_and_uninstall,
    run_clearance_install_phase,
    run_gate_install_phase,
    run_prereq_report,
    run_shield_install_phase,
    run_vault_install_phase,
)
from terok_sandbox.config import SandboxConfig

# ── Stage primitive ──────────────────────────────────────────────────


class TestStage:
    """The ``_stage`` helper is the one place unit output formatting lives."""

    def test_writes_label_marker_and_detail(self, capsys: pytest.CaptureFixture[str]) -> None:
        _stage("Vault", "ok", "systemd, tcp, reachable")
        out = capsys.readouterr().out
        assert "Vault" in out
        assert " ok " in out
        assert "(systemd, tcp, reachable)" in out

    def test_blank_detail_emits_no_parens(self, capsys: pytest.CaptureFixture[str]) -> None:
        _stage("Shield hooks", "ok")
        assert "()" not in capsys.readouterr().out

    def test_label_padded_to_consistent_column(self, capsys: pytest.CaptureFixture[str]) -> None:
        _stage("x", "ok", "a")
        _stage("a_longer_label", "ok", "b")
        # Splitlines with keepends=False drops the trailing newline but
        # preserves each line's leading indent — ``strip()`` would eat
        # the 2-space gutter that makes alignment work.
        lines = capsys.readouterr().out.splitlines()
        assert lines[0].index(" ok ") == lines[1].index(" ok ")


# ── Prereq report ────────────────────────────────────────────────────


class TestPrereqReport:
    """Prereq report writes stage lines for every probe — never raises."""

    def test_reports_host_binaries(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Stub shutil.which so we don't depend on the host's PATH.
        monkeypatch.setattr(
            "terok_sandbox._setup.shutil.which",
            lambda name: f"/usr/bin/{name}",
        )
        with (
            patch("terok_shield.check_firewall_binaries", return_value=()),
            patch(
                "terok_sandbox._setup.check_selinux_status",
                return_value=MagicMock(status=_selinux_na()),
            ),
        ):
            run_prereq_report(SandboxConfig.__new__(SandboxConfig))
        out = capsys.readouterr().out
        assert "podman" in out
        assert "git" in out
        assert "ssh-keygen" in out

    def test_reports_firewall_binaries_via_shield(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("terok_sandbox._setup.shutil.which", lambda _n: None)
        fake_check = MagicMock(name="nft", path="/usr/sbin/nft", purpose="ruleset enforcement")
        fake_check.name = "nft"  # MagicMock name= is a constructor kwarg, not an attr
        fake_check.ok = True
        with (
            patch("terok_shield.check_firewall_binaries", return_value=(fake_check,)),
            patch(
                "terok_sandbox._setup.check_selinux_status",
                return_value=MagicMock(status=_selinux_na()),
            ),
        ):
            run_prereq_report(SandboxConfig.__new__(SandboxConfig))
        out = capsys.readouterr().out
        assert "nft" in out
        assert "/usr/sbin/nft" in out

    def test_selinux_ok_renders_a_stage_line(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from terok_sandbox._setup import SelinuxStatus

        monkeypatch.setattr("terok_sandbox._setup.shutil.which", lambda _n: None)
        with (
            patch("terok_shield.check_firewall_binaries", return_value=()),
            patch(
                "terok_sandbox._setup.check_selinux_status",
                return_value=MagicMock(status=SelinuxStatus.OK),
            ),
        ):
            run_prereq_report(SandboxConfig.__new__(SandboxConfig))
        assert "SELinux policy" in capsys.readouterr().out

    def test_selinux_not_applicable_stays_silent(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Hosts where SELinux isn't enforcing shouldn't see a policy stage line."""
        from terok_sandbox._setup import SelinuxStatus

        monkeypatch.setattr("terok_sandbox._setup.shutil.which", lambda _n: None)
        with (
            patch("terok_shield.check_firewall_binaries", return_value=()),
            patch(
                "terok_sandbox._setup.check_selinux_status",
                return_value=MagicMock(status=SelinuxStatus.NOT_APPLICABLE_PERMISSIVE),
            ),
        ):
            run_prereq_report(SandboxConfig.__new__(SandboxConfig))
        assert "SELinux" not in capsys.readouterr().out


def _selinux_na():
    """Shortcut to the not-applicable SELinux status for compact fixtures."""
    from terok_sandbox._setup import SelinuxStatus

    return SelinuxStatus.NOT_APPLICABLE_TCP_MODE


# ── Shield install phase ─────────────────────────────────────────────


class TestShieldInstallPhase:
    """Shield phase: install hooks + verify health."""

    def test_clean_install_reports_ok(self, capsys: pytest.CaptureFixture[str]) -> None:
        with (
            patch("terok_sandbox.shield.run_setup") as setup,
            patch(
                "terok_sandbox._setup.check_environment",
                return_value=MagicMock(health="ok"),
            ),
        ):
            result = run_shield_install_phase(root=False)
        setup.assert_called_once_with(root=False, user=True)
        assert result == _PhaseResult(ok=True)
        assert "ok" in capsys.readouterr().out

    def test_bypass_mode_reports_warn_but_still_ok(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A bypass-firewall host lands as WARN but counts as ``ok`` for the aggregator."""
        with (
            patch("terok_sandbox.shield.run_setup"),
            patch(
                "terok_sandbox._setup.check_environment",
                return_value=MagicMock(health="bypass"),
            ),
        ):
            result = run_shield_install_phase(root=False)
        assert result == _PhaseResult(ok=True)
        assert "WARN" in capsys.readouterr().out

    def test_install_raises_reports_fail(self, capsys: pytest.CaptureFixture[str]) -> None:
        with patch("terok_sandbox.shield.run_setup", side_effect=RuntimeError("sudo required")):
            result = run_shield_install_phase(root=False)
        assert result == _PhaseResult(ok=False)
        assert "FAIL" in capsys.readouterr().out

    def test_unhealthy_post_install_reports_fail(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Install succeeded on the surface but ``check_environment`` disagrees."""
        with (
            patch("terok_sandbox.shield.run_setup"),
            patch(
                "terok_sandbox._setup.check_environment",
                return_value=MagicMock(health="setup-needed"),
            ),
        ):
            result = run_shield_install_phase(root=False)
        assert result == _PhaseResult(ok=False)
        assert "FAIL" in capsys.readouterr().out


# ── Vault install phase ──────────────────────────────────────────────


class TestVaultInstallPhase:
    """Vault phase: stop + uninstall + install + verify reachability."""

    def test_clean_reinstall_invokes_full_lifecycle(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from terok_sandbox.vault.lifecycle import VaultManager

        status = MagicMock(mode="systemd", transport="tcp")
        with (
            patch.object(VaultManager, "stop_daemon") as stop,
            patch.object(VaultManager, "uninstall_systemd_units") as uninstall,
            patch.object(VaultManager, "install_systemd_units") as install,
            patch.object(VaultManager, "ensure_reachable") as verify,
            patch.object(VaultManager, "get_status", return_value=status),
        ):
            result = run_vault_install_phase(SandboxConfig.__new__(SandboxConfig))
        stop.assert_called_once()
        uninstall.assert_called_once()
        install.assert_called_once()
        verify.assert_called_once()
        assert result == _PhaseResult(ok=True)
        assert "reachable" in capsys.readouterr().out

    def test_stop_or_uninstall_exceptions_soft_fail(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Dangling daemon / unit file from a broken install is tolerated."""
        from terok_sandbox.vault.lifecycle import VaultManager

        status = MagicMock(mode="systemd", transport="tcp")
        with (
            patch.object(VaultManager, "stop_daemon", side_effect=RuntimeError("no pid")),
            patch.object(
                VaultManager,
                "uninstall_systemd_units",
                side_effect=RuntimeError("no units"),
            ),
            patch.object(VaultManager, "install_systemd_units"),
            patch.object(VaultManager, "ensure_reachable"),
            patch.object(VaultManager, "get_status", return_value=status),
        ):
            result = run_vault_install_phase(SandboxConfig.__new__(SandboxConfig))
        assert result == _PhaseResult(ok=True)

    def test_install_systemexit_reports_fail(self, capsys: pytest.CaptureFixture[str]) -> None:
        from terok_sandbox.vault.lifecycle import VaultManager

        with (
            patch.object(VaultManager, "stop_daemon"),
            patch.object(VaultManager, "uninstall_systemd_units"),
            patch.object(
                VaultManager,
                "install_systemd_units",
                side_effect=SystemExit("no ports"),
            ),
        ):
            result = run_vault_install_phase(SandboxConfig.__new__(SandboxConfig))
        assert result == _PhaseResult(ok=False)
        assert "FAIL" in capsys.readouterr().out

    def test_verify_failure_reports_installed_but_unreachable(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from terok_sandbox.vault.lifecycle import VaultManager

        with (
            patch.object(VaultManager, "stop_daemon"),
            patch.object(VaultManager, "uninstall_systemd_units"),
            patch.object(VaultManager, "install_systemd_units"),
            patch.object(
                VaultManager,
                "ensure_reachable",
                side_effect=SystemExit("connection refused"),
            ),
        ):
            result = run_vault_install_phase(SandboxConfig.__new__(SandboxConfig))
        assert result == _PhaseResult(ok=False)
        assert "NOT reachable" in capsys.readouterr().out


# ── Gate install phase ───────────────────────────────────────────────


class TestGateInstallPhase:
    """Gate phase: same stop+install+verify shape as vault, plus systemd-detect."""

    def test_systemd_unavailable_is_warning_not_failure(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Hosts without user systemd (CI containers) skip the phase cleanly."""
        from terok_sandbox.gate.lifecycle import GateServerManager

        with patch.object(GateServerManager, "is_systemd_available", return_value=False):
            result = run_gate_install_phase(SandboxConfig.__new__(SandboxConfig))
        assert result == _PhaseResult(ok=True)
        assert "WARN" in capsys.readouterr().out

    def test_clean_reinstall_invokes_full_lifecycle(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from terok_sandbox.gate.lifecycle import GateServerManager

        status = MagicMock(mode="systemd", transport="tcp")
        with (
            patch.object(GateServerManager, "is_systemd_available", return_value=True),
            patch.object(GateServerManager, "stop_daemon") as stop,
            patch.object(GateServerManager, "uninstall_systemd_units") as uninstall,
            patch.object(GateServerManager, "install_systemd_units") as install,
            patch.object(GateServerManager, "ensure_reachable") as verify,
            patch.object(GateServerManager, "get_status", return_value=status),
        ):
            result = run_gate_install_phase(SandboxConfig.__new__(SandboxConfig))
        stop.assert_called_once()
        uninstall.assert_called_once()
        install.assert_called_once()
        verify.assert_called_once()
        assert result == _PhaseResult(ok=True)


# ── Clearance install phase ──────────────────────────────────────────


class TestClearanceInstallPhase:
    """Clearance phase: install the hub + verdict + notifier; soft-skip on missing import."""

    def test_happy_path_installs_hub_and_notifier(self, capsys: pytest.CaptureFixture[str]) -> None:
        with (
            patch("terok_clearance.runtime.installer.install_service") as install_hub,
            patch("terok_clearance.runtime.installer.install_notifier_service") as install_notifier,
            patch("terok_sandbox._setup._enable_user_unit"),
        ):
            result = run_clearance_install_phase()
        install_hub.assert_called_once()
        install_notifier.assert_called_once()
        assert result == _PhaseResult(ok=True)
        out = capsys.readouterr().out
        assert "Clearance hub" in out
        assert "Clearance notifier" in out

    def test_hub_failure_reports_fail(self, capsys: pytest.CaptureFixture[str]) -> None:
        with (
            patch(
                "terok_clearance.runtime.installer.install_service",
                side_effect=RuntimeError("template missing"),
            ),
            patch("terok_clearance.runtime.installer.install_notifier_service"),
            patch("terok_sandbox._setup._enable_user_unit"),
        ):
            result = run_clearance_install_phase()
        assert result == _PhaseResult(ok=False)
        assert "FAIL" in capsys.readouterr().out

    def test_notifier_failure_does_not_flip_exit_code(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Notifier is non-critical — a failure WARNs without failing the phase."""
        with (
            patch("terok_clearance.runtime.installer.install_service"),
            patch(
                "terok_clearance.runtime.installer.install_notifier_service",
                side_effect=RuntimeError("session bus missing"),
            ),
            patch("terok_sandbox._setup._enable_user_unit"),
        ):
            result = run_clearance_install_phase()
        assert result == _PhaseResult(ok=True)


# ── Lifecycle helpers ────────────────────────────────────────────────


class TestStopAndUninstall:
    """Both steps soft-fail — authoritative install is next, dangling bits reported by verify."""

    def test_both_succeed(self) -> None:
        stop, uninstall = MagicMock(), MagicMock()
        _stop_and_uninstall(stop, uninstall)
        stop.assert_called_once()
        uninstall.assert_called_once()

    def test_stop_raises_uninstall_still_runs(self) -> None:
        stop = MagicMock(side_effect=RuntimeError("no pid"))
        uninstall = MagicMock()
        _stop_and_uninstall(stop, uninstall)
        uninstall.assert_called_once()

    def test_both_raise_no_propagation(self) -> None:
        stop = MagicMock(side_effect=RuntimeError("no pid"))
        uninstall = MagicMock(side_effect=RuntimeError("no units"))
        # Must not re-raise.
        _stop_and_uninstall(stop, uninstall)


class TestEnableUserUnit:
    """``_enable_user_unit`` runs daemon-reload + enable + restart, silent without systemctl."""

    def test_missing_systemctl_silent(self) -> None:
        with (
            patch("terok_sandbox._setup.shutil.which", return_value=None),
            patch("terok_sandbox._setup.subprocess.run") as run,
        ):
            _enable_user_unit("terok-vault")
        run.assert_not_called()

    def test_invokes_reload_enable_restart(self) -> None:
        with (
            patch("terok_sandbox._setup.shutil.which", return_value="/usr/bin/systemctl"),
            patch("terok_sandbox._setup.subprocess.run") as run,
        ):
            _enable_user_unit("terok-vault")
        argvs = [call.args[0] for call in run.call_args_list]
        assert ["/usr/bin/systemctl", "--user", "daemon-reload"] in argvs
        assert ["/usr/bin/systemctl", "--user", "enable", "terok-vault"] in argvs
        assert ["/usr/bin/systemctl", "--user", "restart", "terok-vault"] in argvs
