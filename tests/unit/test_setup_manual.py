# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the interactive per-component hardening setup flow."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

from terok_sandbox import _setup_manual
from terok_sandbox._setup_manual import _Component, _run_component, handle_setup_component

_COMPONENT = _Component(
    status_line="The widget is not installed.",
    command="sudo bash /somewhere/install.sh /some/root",
    source="rule one,\nrule two,\n",
    script_args=("/somewhere/install.sh", "/some/root"),
)


def _flow(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    *,
    answers: list[str] | None = None,
    tty: bool = True,
    show_only: bool = False,
) -> tuple[int, str, mock.MagicMock]:
    """Drive _run_component with canned answers; return (exit, stdout, sudo mock)."""
    monkeypatch.setattr(_setup_manual.sys.stdin, "isatty", lambda: tty)
    if answers is not None:
        answer_iter = iter(answers)
        monkeypatch.setattr("builtins.input", lambda _prompt: next(answer_iter))
    sudo = mock.MagicMock(return_value=0)
    monkeypatch.setattr(_setup_manual, "_sudo_run", sudo)
    code = _run_component(_COMPONENT, show_only=show_only)
    return code, capsys.readouterr().out, sudo


class TestRunComponent:
    def test_show_only_prints_source_and_returns(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, out, sudo = _flow(monkeypatch, capsys, show_only=True)
        assert code == 0
        assert out == _COMPONENT.source
        sudo.assert_not_called()

    def test_default_shows_command_and_warns_about_sudo(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, out, _ = _flow(monkeypatch, capsys, answers=["n"])
        assert _COMPONENT.status_line in out
        assert "sudo asks for your password" in out
        assert _COMPONENT.command in out

    def test_yes_runs_the_shown_command(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, _, sudo = _flow(monkeypatch, capsys, answers=["y"])
        assert code == 0
        sudo.assert_called_once_with(_COMPONENT.script_args)

    def test_plain_enter_defaults_to_yes(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, _, sudo = _flow(monkeypatch, capsys, answers=[""])
        assert code == 0
        sudo.assert_called_once()

    def test_s_prints_source_then_asks_again(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, out, sudo = _flow(monkeypatch, capsys, answers=["s", "y"])
        assert code == 0
        assert _COMPONENT.source in out
        sudo.assert_called_once()

    def test_n_cancels_without_running(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, out, sudo = _flow(monkeypatch, capsys, answers=["n"])
        assert code == 1
        assert "Cancelled" in out
        sudo.assert_not_called()

    def test_non_terminal_prints_command_and_declines(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, out, sudo = _flow(monkeypatch, capsys, tty=False)
        assert code == 1
        assert _COMPONENT.command in out
        assert "Run the command above directly" in out
        sudo.assert_not_called()

    def test_sudo_exit_code_is_forwarded(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(_setup_manual.sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda _prompt: "y")
        monkeypatch.setattr(_setup_manual, "_sudo_run", mock.MagicMock(return_value=7))
        assert _run_component(_COMPONENT, show_only=False) == 7


class TestHandleSetupComponent:
    def test_unknown_component_exits_with_the_choices(self) -> None:
        with pytest.raises(SystemExit, match="selinux or apparmor"):
            handle_setup_component("bogus")

    def test_selinux_routes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        handler = mock.MagicMock(return_value=0)
        monkeypatch.setattr(_setup_manual, "handle_setup_selinux", handler)
        assert handle_setup_component("selinux", show_only=True) == 0
        handler.assert_called_once_with(show_only=True, cfg=None)

    def test_apparmor_routes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        handler = mock.MagicMock(return_value=0)
        monkeypatch.setattr(_setup_manual, "handle_setup_apparmor", handler)
        assert handle_setup_component("apparmor") == 0
        handler.assert_called_once_with(show_only=False)


class TestComponents:
    def test_apparmor_component_renders_for_the_default_root(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Command, source, and script args all speak about the same root."""
        from terok_sandbox._util import _apparmor

        root = tmp_path / "sandbox-live"
        monkeypatch.setattr(_setup_manual, "_apparmor_default_state_root", lambda: root)
        monkeypatch.setattr(
            _setup_manual,
            "_check_apparmor",
            lambda: _apparmor.AppArmorCheckResult(_apparmor.AppArmorStatus.PROFILE_MISSING),
        )
        comp = _setup_manual._apparmor_component()
        assert str(root) in comp.command
        assert f"owner {root}/tasks" in comp.source
        assert comp.script_args[-1] == str(root)
        assert "not installed" in comp.status_line

    def test_selinux_component_uses_the_cfg_services_mode(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from terok_sandbox._util import _selinux

        seen: dict[str, object] = {}

        def _fake_check(*, services_mode: object) -> _selinux.SelinuxCheckResult:
            seen["mode"] = services_mode
            return _selinux.SelinuxCheckResult(_selinux.SelinuxStatus.POLICY_MISSING)

        monkeypatch.setattr(_setup_manual, "_check_selinux", _fake_check)
        cfg = mock.MagicMock(services_mode="socket")
        comp = _setup_manual._selinux_component(cfg)
        assert seen["mode"] == "socket"
        assert comp.command.startswith("sudo bash ")
        assert "module terok_socket" in comp.source
        assert "not loaded" in comp.status_line
