# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for [`SandboxConfig`][terok_sandbox.SandboxConfig] — notably the services-mode branching."""

from __future__ import annotations

import shutil
import unittest.mock
from collections.abc import Iterator
from pathlib import Path

import pytest

from terok_sandbox.config import SandboxConfig


@pytest.mark.parametrize("value", [False, True])
def test_aslr_control_reads_global_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: bool
) -> None:
    """Standalone sandbox and embedded callers inherit the global opt-in."""
    path = tmp_path / "config.yml"
    path.write_text(f"run:\n  aslr_control: {str(value).lower()}\n")
    monkeypatch.setenv("TEROK_CONFIG_FILE", str(path))
    assert SandboxConfig().aslr_control is value
    assert SandboxConfig(aslr_control=not value).aslr_control is not value


def test_aslr_control_defaults_off() -> None:
    """Missing configuration leaves the host's seccomp policy untouched."""
    assert SandboxConfig().aslr_control is False


class TestServicesClearance:
    """``services.clearance`` resolves through the services schema into ``SandboxConfig``."""

    def test_defaults_to_prompt(self) -> None:
        """No setting asks the operator, as every task did before the knob existed."""
        assert SandboxConfig().clearance == "prompt"

    @pytest.mark.parametrize("value", ["prompt", "mute", "off"])
    def test_reads_global_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        """The value written unquoted reads back as written — ``off`` included.

        YAML 1.1 parsers read a bare ``off`` as the boolean ``False``, which the
        schema would not take for ``off``: it would warn and fall back to
        ``prompt``.  The config stack's YAML 1.2 reader keeps it the string an
        operator typed.
        """
        path = tmp_path / "config.yml"
        path.write_text(f"services:\n  clearance: {value}\n")
        monkeypatch.setenv("TEROK_CONFIG_FILE", str(path))
        assert SandboxConfig().clearance == value

    def test_explicit_value_wins(self) -> None:
        """An orchestrator's resolved per-project value overrides the global default."""
        with unittest.mock.patch("terok_sandbox.config.services_clearance", return_value="off"):
            assert SandboxConfig().clearance == "off"
            assert SandboxConfig(clearance="mute").clearance == "mute"

    def test_invalid_value_warns_and_keeps_the_rest_of_the_section(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A typo asks the operator rather than silencing anyone, and says so on stderr —
        and costs that key alone: the SELinux ``tcp`` opt-out beside it survives."""
        from terok_sandbox.config import services_clearance, services_mode

        path = tmp_path / "config.yml"
        path.write_text("services:\n  mode: tcp\n  clearance: silent\n")
        monkeypatch.setenv("TEROK_CONFIG_FILE", str(path))
        assert services_clearance() == "prompt"
        assert services_mode() == "tcp"
        err = capsys.readouterr().err
        assert "invalid services.clearance ('silent'" in err
        assert "invalid services section" not in err


class TestShieldBypassDuration:
    """``shield.bypass_duration`` resolves through the shield schema into ``SandboxConfig``."""

    @pytest.fixture(autouse=True)
    def _fresh_shield_section(self) -> Iterator[None]:
        """The shield section is read once per process; each test reads its own config."""
        from terok_sandbox import config as _config

        _config._shield_section.cache_clear()
        yield
        _config._shield_section.cache_clear()

    def test_reads_global_config(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A duration shield can arm reads back as written."""
        path = tmp_path / "config.yml"
        path.write_text("shield:\n  bypass_duration: 45s\n")
        monkeypatch.setenv("TEROK_CONFIG_FILE", str(path))
        assert SandboxConfig().shield_bypass_duration == "45s"

    def test_unusable_value_warns_and_keeps_the_rest_of_the_section(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A typo reads as the default with a warning at load — and only it: ``audit``
        beside it in the same section keeps what the operator wrote."""
        from terok_sandbox.config_schema import RawShieldSection

        path = tmp_path / "config.yml"
        path.write_text("shield:\n  bypass_duration: 5min\n  audit: false\n")
        monkeypatch.setenv("TEROK_CONFIG_FILE", str(path))
        cfg = SandboxConfig()
        assert cfg.shield_bypass_duration == RawShieldSection().bypass_duration
        assert cfg.shield_audit is False
        assert "invalid shield.bypass_duration" in capsys.readouterr().err


class TestSocketModeSkipsPortResolution:
    """``services.mode: socket`` must bypass the TCP port registry entirely."""

    def test_socket_mode_leaves_ports_unset(self) -> None:
        """No auto-allocation happens; port fields remain ``None``."""
        with (
            unittest.mock.patch("terok_sandbox.config.services_mode", return_value="socket"),
            unittest.mock.patch(
                "terok_sandbox.port_registry._default.resolve_service_ports"
            ) as resolve,
        ):
            cfg = SandboxConfig()
        resolve.assert_not_called()
        assert cfg.gate_port is None
        assert cfg.token_broker_port is None
        assert cfg.ssh_signer_port is None

    def test_invalid_mode_warns_and_falls_back(self, capsys: pytest.CaptureFixture[str]) -> None:
        """A typo in ``services.mode`` emits stderr warning and defaults to schema value.

        The fallback follows ``RawServicesSection`` — one schema default
        across both terok's and sandbox's readers (since the refactor,
        the hand-rolled ``"tcp"`` fallback is gone in favor of whatever
        the pydantic schema declares).
        """
        from terok_sandbox.config import services_mode
        from terok_sandbox.config_schema import RawServicesSection

        with unittest.mock.patch(
            "terok_sandbox.config.read_config_section", return_value={"mode": "soket"}
        ):
            assert services_mode() == RawServicesSection().mode
        captured = capsys.readouterr()
        assert "invalid services section" in captured.err

    def test_tcp_mode_construction_does_not_allocate(self) -> None:
        """Constructing ``SandboxConfig()`` is side-effect-free, even in tcp mode.

        The port registry is consulted on demand by callers that need
        real listeners — see ``with_resolved_ports`` — not by
        ``__post_init__``.  The user-facing principle (sandbox #156)
        is that *constructing* a config never bind-tests or persists.
        """
        with (
            unittest.mock.patch("terok_sandbox.config.services_mode", return_value="tcp"),
            unittest.mock.patch(
                "terok_sandbox.port_registry._default.resolve_service_ports",
            ) as resolve,
        ):
            cfg = SandboxConfig()
        resolve.assert_not_called()
        assert cfg.gate_port is None
        assert cfg.token_broker_port is None
        assert cfg.ssh_signer_port is None

    def test_with_resolved_ports_populates_via_registry_in_tcp_mode(self) -> None:
        """``with_resolved_ports`` is the explicit allocation step for consumers."""
        from terok_sandbox.port_registry import ServicePorts

        fake_ports = ServicePorts(gate=18700, proxy=18701, ssh_agent=18702)
        with (
            unittest.mock.patch("terok_sandbox.config.services_mode", return_value="tcp"),
            unittest.mock.patch(
                "terok_sandbox.port_registry._default.resolve_service_ports",
                return_value=fake_ports,
            ) as resolve,
        ):
            cfg = SandboxConfig().with_resolved_ports()
        resolve.assert_called_once()
        assert cfg.gate_port == 18700
        assert cfg.token_broker_port == 18701
        assert cfg.ssh_signer_port == 18702

    def test_with_resolved_ports_is_noop_in_socket_mode(self) -> None:
        """Socket-mode cfgs return ``self`` (no copy, no registry pass)."""
        with (
            unittest.mock.patch("terok_sandbox.config.services_mode", return_value="socket"),
            unittest.mock.patch(
                "terok_sandbox.port_registry._default.resolve_service_ports",
            ) as resolve,
        ):
            original = SandboxConfig()
            resolved = original.with_resolved_ports()
        resolve.assert_not_called()
        assert resolved is original

    def test_with_resolved_ports_is_idempotent_once_all_set(self) -> None:
        """A cfg with every port already set short-circuits — no registry pass."""
        with (
            unittest.mock.patch("terok_sandbox.config.services_mode", return_value="tcp"),
            unittest.mock.patch(
                "terok_sandbox.port_registry._default.resolve_service_ports",
            ) as resolve,
        ):
            cfg = SandboxConfig(gate_port=1, token_broker_port=2, ssh_signer_port=3)
            resolved = cfg.with_resolved_ports()
        resolve.assert_not_called()
        assert resolved is cfg


class TestExperimentalEnabled:
    """Tests for ``experimental_enabled`` — the top-level opt-in reader.

    Gates the krun runtime in terok and ``check_krun_binaries`` in
    sandbox's prereq report.  Single declaration on
    ``SandboxConfigView``; the reader walks the layered config and
    coerces defensively.
    """

    def test_returns_true_when_set(self) -> None:
        """``experimental: true`` in config.yml flips the bit on."""
        from terok_sandbox.config import experimental_enabled

        with unittest.mock.patch("terok_sandbox.config.read_config_top_level", return_value=True):
            assert experimental_enabled() is True

    def test_returns_false_when_unset(self) -> None:
        """Missing top-level key collapses to ``False`` (the safe default)."""
        from terok_sandbox.config import experimental_enabled

        with unittest.mock.patch("terok_sandbox.config.read_config_top_level", return_value=None):
            assert experimental_enabled() is False

    @pytest.mark.parametrize(
        "raw",
        [
            pytest.param("true", id="string-true"),
            pytest.param(1, id="int-one"),
            pytest.param([True], id="list"),
            pytest.param({"nested": True}, id="dict"),
        ],
    )
    def test_returns_false_for_non_bool_values(self, raw: object) -> None:
        """A malformed value (string, int, list, dict) falls through to ``False``.

        Defensive against operators who write ``experimental: "yes"``
        thinking YAML coerces; never crash, never accidentally enable
        an experimental code path on a typo.
        """
        from terok_sandbox.config import experimental_enabled

        with unittest.mock.patch("terok_sandbox.config.read_config_top_level", return_value=raw):
            assert experimental_enabled() is False

    def test_sandbox_config_picks_up_value(self) -> None:
        """``SandboxConfig().experimental`` flows through the default-factory."""
        with unittest.mock.patch("terok_sandbox.config.experimental_enabled", return_value=True):
            cfg = SandboxConfig()
        assert cfg.experimental is True

    def test_explicit_override_wins(self) -> None:
        """``SandboxConfig(experimental=False)`` overrides the config-derived value."""
        with unittest.mock.patch("terok_sandbox.config.experimental_enabled", return_value=True):
            cfg = SandboxConfig(experimental=False)
        assert cfg.experimental is False


class TestSidecarPath:
    """``sidecar_path`` — the one name → path rule the sidecar's writer and its editor share."""

    def test_derives_path_under_state_dir(self, tmp_path: Path) -> None:
        """``state_dir/sidecar/<name>.json``, derived without touching the disk."""
        cfg = SandboxConfig(state_dir=tmp_path / "state")
        assert cfg.sidecar_path("myc") == tmp_path / "state" / "sidecar" / "myc.json"
        assert not (tmp_path / "state").exists()

    @pytest.mark.parametrize(
        "bad", ["", ".", "..", "../escape", "a/b", "back\\slash", "nul\0byte"], ids=repr
    )
    def test_rejects_unsafe_container_names(self, tmp_path: Path, bad: str) -> None:
        """A name that is not one path component never becomes a path under ``state_dir``."""
        cfg = SandboxConfig(state_dir=tmp_path / "state")
        with pytest.raises(ValueError, match="unsafe container name"):
            cfg.sidecar_path(bad)

    def test_rejects_an_absolute_name(self, tmp_path: Path) -> None:
        """``Path / "/abs"`` would swallow the whole prefix; the name is refused first."""
        cfg = SandboxConfig(state_dir=tmp_path / "state")
        absolute_name = str(tmp_path)
        with pytest.raises(ValueError, match="unsafe container name"):
            cfg.sidecar_path(absolute_name)


class TestContainerRuntimeDir:
    """Per-container runtime dir derivation + idempotent (re)creation.

    The dir is the ``/run/terok`` bind-mount source; it must survive
    being wiped by a reboot and the supervisor's stop-time rmtree, so the
    ensure path rebuilds the whole chain on every (re)start.
    """

    def test_derives_path_under_runtime_dir(self, tmp_path: Path) -> None:
        """``container_runtime_dir`` is ``runtime_dir/run/<name>`` (pure, no I/O)."""
        cfg = SandboxConfig(runtime_dir=tmp_path / "rt")
        path = cfg.container_runtime_dir("myc")
        assert path == tmp_path / "rt" / "run" / "myc"
        assert not path.exists()

    def test_ensure_creates_mode_0700(self, tmp_path: Path) -> None:
        """``ensure_container_runtime_dir`` creates the dir at mode 0700."""
        cfg = SandboxConfig(runtime_dir=tmp_path / "rt")
        path = cfg.ensure_container_runtime_dir("myc")
        assert path.is_dir()
        assert (path.stat().st_mode & 0o777) == 0o700

    def test_ensure_rebuilds_after_reboot_wipe(self, tmp_path: Path) -> None:
        """After the whole runtime tree is gone (reboot), ensure rebuilds it.

        ``mkdir(parents=True)`` is what makes the post-reboot case work —
        the OS wipes ``$XDG_RUNTIME_DIR`` to nothing, so the leaf and every
        ancestor under ``runtime_dir`` must come back.
        """
        cfg = SandboxConfig(runtime_dir=tmp_path / "rt")
        cfg.ensure_container_runtime_dir("myc")
        shutil.rmtree(tmp_path / "rt")
        assert not cfg.container_runtime_dir("myc").exists()

        path = cfg.ensure_container_runtime_dir("myc")
        assert path.is_dir()

    def test_ensure_is_idempotent(self, tmp_path: Path) -> None:
        """A second ensure on an existing dir neither raises nor loosens perms."""
        cfg = SandboxConfig(runtime_dir=tmp_path / "rt")
        cfg.ensure_container_runtime_dir("myc")
        path = cfg.ensure_container_runtime_dir("myc")
        assert path.is_dir()
        assert (path.stat().st_mode & 0o777) == 0o700

    @pytest.mark.parametrize(
        "bad",
        ["", ".", "..", "/etc", "../escape", "a/b", "nested/../..", "back\\slash"],
        ids=[
            "empty",
            "dot",
            "dotdot",
            "absolute",
            "traversal",
            "separator",
            "nested-traversal",
            "backslash",
        ],
    )
    def test_rejects_unsafe_container_names(self, tmp_path: Path, bad: str) -> None:
        """A name that is not a single path component is refused before any I/O.

        ``Path("…/run") / "/etc"`` would swallow the whole prefix and
        ``…/run / ".."`` would climb out, so an unvalidated name could
        redirect the mkdir/chmod/rmtree the callers perform onto an
        unintended host path.  Both the pure derivation and the ``ensure``
        wrapper (which funnels through it) must reject it.
        """
        cfg = SandboxConfig(runtime_dir=tmp_path / "rt")
        with pytest.raises(ValueError, match="unsafe container name"):
            cfg.container_runtime_dir(bad)
        with pytest.raises(ValueError, match="unsafe container name"):
            cfg.ensure_container_runtime_dir(bad)
