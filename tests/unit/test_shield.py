# SPDX-FileCopyrightText: 2025 Jiri Vyskocil
# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the terok-shield adapter (``terok_sandbox.integrations.shield``)."""

from __future__ import annotations

import fnmatch
import tempfile
from datetime import date, timedelta
from pathlib import Path, PurePosixPath
from typing import Any
from unittest.mock import MagicMock, PropertyMock, patch

import pytest
from terok_shield import (
    AllowResult,
    EnvironmentCheck,
    ExecError,
    HarvestEntry,
    HarvestReport,
    NftNotFoundError,
    OverrideRevocation,
    RotationRisk,
    SecurityTierRefusal,
    Shield,
    ShieldMode,
    ShieldNeedsSetup,
    ShieldReading,
    ShieldState,
)

from terok_sandbox._util._apparmor import render_addendum
from terok_sandbox.config import SandboxConfig
from terok_sandbox.integrations.shield import (
    _DISABLED_WARNING,
    TIER_ALLOWLIST,
    DnsTier,
    ShieldHooks,
    ShieldManager,
    check_environment,
)
from terok_sandbox.paths import sandbox_live_root
from tests.constants import (
    DESTINATION_IP,
    FAKE_CONTAINER_ID,
    FAKE_CONTAINER_SHORT_ID,
    GATE_PORT,
    MOCK_BASE,
    MOCK_CONFIG_ROOT,
    MOCK_HOST_BIN,
    MOCK_TASK_DIR,
    PROMOTED_DOMAIN,
    SECURITY_TIER_DOMAIN,
)

CUSTOM_GATE_PORT = GATE_PORT + 1

OVERRIDE_REASON = "vendor SDK reaches the provider API directly"
"""Why a test break-glass is granted — shield requires one, sandbox passes it through."""

WINDOW_SECONDS_LEFT = 130
"""Whole seconds left on an open bypass window, as shield's countdown reports them."""


def make_mock_shield(
    *,
    shield_state: ShieldState = ShieldState.UP,
    pre_start_args: list[str] | None = None,
) -> MagicMock:
    """Create a mock ``Shield`` instance with useful defaults."""
    mock_shield = MagicMock(spec=Shield)
    mock_shield.state.return_value = shield_state
    mock_shield.pre_start.return_value = (
        ["--network", "hook-net"] if pre_start_args is None else pre_start_args
    )
    return mock_shield


# ── ShieldManager.shield (the lazy Shield builder) ───────────────────────


@pytest.mark.parametrize(
    ("cfg_kwargs", "expected_profiles", "expected_port", "audit_enabled"),
    [
        pytest.param(
            {"gate_port": GATE_PORT, "token_broker_port": 18731, "ssh_signer_port": 18732},
            (),
            GATE_PORT,
            True,
            id="defaults",
        ),
        pytest.param(
            {
                "shield_profiles": ("custom-a", "custom-b"),
                "shield_audit": False,
                "shield_dnsmasq_path": MOCK_TASK_DIR / "dnsmasq-nftset",
                "gate_port": CUSTOM_GATE_PORT,
                "token_broker_port": 18741,
                "ssh_signer_port": 18742,
            },
            ("custom-a", "custom-b"),
            CUSTOM_GATE_PORT,
            False,
            id="custom-values",
        ),
        pytest.param(
            {
                "shield_profiles": ("single-profile",),
                "gate_port": GATE_PORT,
                "token_broker_port": 18731,
                "ssh_signer_port": 18732,
            },
            ("single-profile",),
            GATE_PORT,
            True,
            id="single-profile",
        ),
    ],
)
def test_shield_property_maps_config_to_shield_config(
    cfg_kwargs: dict[str, object],
    expected_profiles: tuple[str, ...],
    expected_port: int,
    audit_enabled: bool,
) -> None:
    """SandboxConfig values are translated into the per-task ``ShieldConfig``."""
    cfg = SandboxConfig(**cfg_kwargs)
    with (
        patch("terok_shield.run.SubprocessRunner", autospec=True),
        patch("terok_sandbox.paths.namespace_config_root", return_value=MOCK_CONFIG_ROOT),
    ):
        shield = ShieldManager(MOCK_TASK_DIR, cfg=cfg).shield

    assert isinstance(shield, Shield)
    config = shield.config
    assert config.mode == ShieldMode.HOOK
    assert config.default_profiles == expected_profiles
    assert config.loopback_ports == (expected_port, cfg.token_broker_port, cfg.ssh_signer_port)
    assert config.audit_enabled is audit_enabled
    assert config.dnsmasq_path == cfg.shield_dnsmasq_path
    assert config.state_dir == MOCK_TASK_DIR / "shield"
    assert config.profiles_dir == MOCK_CONFIG_ROOT / "shield" / "profiles"


def test_shield_property_resolves_ports_for_auto_allocated_config() -> None:
    """A tcp-mode cfg with unset ports still produces a non-empty ``loopback_ports``.

    Regression guard for the post-#315 bug where Shield construction
    read the raw ``cfg.gate_port`` / ``token_broker_port`` /
    ``ssh_signer_port`` fields without calling
    [`SandboxConfig.with_resolved_ports`][terok_sandbox.SandboxConfig.with_resolved_ports]
    first.  Side-effect-free ``SandboxConfig`` construction leaves
    those fields ``None`` for auto-allocated configs, which silently
    produced an empty ``loopback_ports`` tuple — and a DOWN-posture ruleset
    with no ``tcp dport <p> ip daddr 169.254.1.2 accept`` rules, so
    every container→host loopback access fell through to the
    private-range reject after ``shield down``.
    """
    cfg = SandboxConfig(state_dir=MOCK_BASE / "state-tcp-auto", services_mode="tcp")
    assert cfg.gate_port is None
    assert cfg.token_broker_port is None
    assert cfg.ssh_signer_port is None

    with (
        patch("terok_shield.run.SubprocessRunner", autospec=True),
        patch("terok_sandbox.paths.namespace_config_root", return_value=MOCK_CONFIG_ROOT),
    ):
        shield = ShieldManager(MOCK_TASK_DIR, cfg=cfg).shield

    assert len(shield.config.loopback_ports) == 3
    assert all(isinstance(p, int) for p in shield.config.loopback_ports)
    assert len(set(shield.config.loopback_ports)) == 3  # gate, broker, signer all distinct


def test_shield_property_socket_mode_skips_port_resolution() -> None:
    """Socket-mode configs short-circuit ``with_resolved_ports`` and emit no loopback rules."""
    cfg = SandboxConfig(state_dir=MOCK_BASE / "state-socket", services_mode="socket")

    with (
        patch("terok_shield.run.SubprocessRunner", autospec=True),
        patch("terok_sandbox.paths.namespace_config_root", return_value=MOCK_CONFIG_ROOT),
    ):
        shield = ShieldManager(MOCK_TASK_DIR, cfg=cfg).shield

    assert shield.config.loopback_ports == ()


def test_shield_property_is_cached() -> None:
    """The shield instance is built once per manager — repeated reads return the same object."""
    cfg = SandboxConfig(gate_port=GATE_PORT, token_broker_port=18731, ssh_signer_port=18732)
    with (
        patch("terok_shield.run.SubprocessRunner", autospec=True),
        patch("terok_sandbox.paths.namespace_config_root", return_value=MOCK_CONFIG_ROOT),
    ):
        manager = ShieldManager(MOCK_TASK_DIR, cfg=cfg)
        first = manager.shield
        second = manager.shield
    assert first is second


# ── Re-exports ───────────────────────────────────────────────────────────


def test_nft_not_found_is_reexported() -> None:
    """``NftNotFoundError`` is re-exported from the adapter module."""
    from terok_sandbox.integrations.shield import NftNotFoundError as error_type

    assert error_type is NftNotFoundError


def test_shield_state_is_reexported() -> None:
    """``ShieldState`` is re-exported from the adapter module."""
    from terok_sandbox.integrations.shield import ShieldState as shield_state_type

    assert shield_state_type is ShieldState


# ── ShieldManager delegation to the underlying Shield ───────────────────


def test_manager_up_forwards_name_and_id() -> None:
    """``ShieldManager.up`` plumbs (container, container_id) into the Shield."""
    mock_shield = make_mock_shield()
    manager = ShieldManager(MOCK_TASK_DIR)
    with patch.object(ShieldManager, "shield", new=mock_shield):
        manager.up("ctr", "ctr-uuid")
    mock_shield.up.assert_called_once_with("ctr", "ctr-uuid")


def test_manager_quarantine_forwards_to_shield() -> None:
    """``ShieldManager.quarantine`` is the panic path — name only."""
    mock_shield = make_mock_shield()
    manager = ShieldManager(MOCK_TASK_DIR)
    with patch.object(ShieldManager, "shield", new=mock_shield):
        manager.quarantine("ctr")
    mock_shield.quarantine.assert_called_once_with("ctr")


def test_manager_state_returns_shield_state() -> None:
    """``ShieldManager.state`` reports what ``Shield.state`` returned."""
    mock_shield = make_mock_shield()
    manager = ShieldManager(MOCK_TASK_DIR)
    with patch.object(ShieldManager, "shield", new=mock_shield):
        assert manager.state("ctr") == ShieldState.UP
    mock_shield.state.assert_called_once_with("ctr")


def test_manager_dns_tier_reads_recorded_value(tmp_path: Path) -> None:
    """``ShieldManager.dns_tier`` returns the tier the task recorded, else None."""
    from terok_shield.state import StateBundle

    manager = ShieldManager(tmp_path)
    assert manager.dns_tier is None  # nothing recorded yet

    tier_file = StateBundle(manager.state_dir).dns_tier
    tier_file.parent.mkdir(parents=True)
    tier_file.write_text(f"{DnsTier.LOOKUP.value}\n")
    assert manager.dns_tier is DnsTier.LOOKUP

    # A container launched before a tier rename still reads as the tier it
    # named, so it restarts instead of being recreated.
    tier_file.write_text("dnsmasq\n")
    assert manager.dns_tier is DnsTier.DNSMASQ_LIVE


def test_manager_down_passes_disengaged() -> None:
    """``ShieldManager.down`` forwards ``container_id`` + ``disengaged=True`` to the underlying Shield."""
    mock_shield = make_mock_shield()
    manager = ShieldManager(MOCK_TASK_DIR)
    with patch.object(ShieldManager, "shield", new=mock_shield):
        manager.down("ctr", "ctr-uuid", disengaged=True)
    mock_shield.down.assert_called_once_with("ctr", "ctr-uuid", disengaged=True)


def test_manager_pre_start_threads_runtime_into_shield() -> None:
    """The runtime kwarg flows into the ShieldConfig the Shield is built from."""
    from terok_shield import ShieldRuntime

    cfg = SandboxConfig(gate_port=GATE_PORT, token_broker_port=18731, ssh_signer_port=18732)
    with (
        patch("terok_shield.run.SubprocessRunner", autospec=True),
        patch("terok_sandbox.paths.namespace_config_root", return_value=MOCK_CONFIG_ROOT),
    ):
        manager = ShieldManager(MOCK_TASK_DIR, cfg=cfg, runtime=ShieldRuntime.KRUN)
        assert manager.shield.config.runtime is ShieldRuntime.KRUN


def test_pre_start_threads_egress_projection_into_shield() -> None:
    """ShieldManager.pre_start passes the roster projection through to Shield.pre_start."""
    mock_shield = make_mock_shield(pre_start_args=["--hook"])
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig())
    with patch.object(ShieldManager, "shield", new=mock_shield):
        result = manager.pre_start(
            "ctr",
            security_deny=("api.anthropic.com",),
            provider_allow=("telemetry.example",),
            project_allow=("github.com",),
            override=("api.foo.com",),
        )
    assert result == ["--hook"]
    mock_shield.pre_start.assert_called_once_with(
        "ctr",
        security_deny=("api.anthropic.com",),
        provider_allow=("telemetry.example",),
        project_allow=("github.com",),
        override=("api.foo.com",),
    )


def test_pre_start_defaults_projection_to_empty() -> None:
    """With no projection, both generated tiers pass through as empty tuples."""
    mock_shield = make_mock_shield(pre_start_args=["--hook"])
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig())
    with patch.object(ShieldManager, "shield", new=mock_shield):
        manager.pre_start("ctr")
    mock_shield.pre_start.assert_called_once_with(
        "ctr", security_deny=(), provider_allow=(), project_allow=(), override=()
    )


def test_refresh_threads_tiers_into_shield() -> None:
    """ShieldManager.refresh passes the recomputed tiers through to Shield.refresh."""
    mock_shield = make_mock_shield()
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig())
    with patch.object(ShieldManager, "shield", new=mock_shield):
        manager.refresh(
            "ctr",
            security_deny=("api.anthropic.com",),
            provider_allow=("telemetry.example",),
            project_allow=("github.com",),
            override=("api.foo.com",),
        )
    mock_shield.refresh.assert_called_once_with(
        "ctr",
        security_deny=("api.anthropic.com",),
        provider_allow=("telemetry.example",),
        project_allow=("github.com",),
        override=("api.foo.com",),
    )


def test_disabled_refresh_is_noop_with_warning() -> None:
    """The kill-switch makes ``ShieldManager.refresh`` a loud no-op, like pre_start."""
    mock_shield = MagicMock(spec=Shield)
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig(shield_disabled=True))
    with patch.object(ShieldManager, "shield", new=mock_shield), pytest.warns(UserWarning):
        manager.refresh("ctr")
    mock_shield.refresh.assert_not_called()


def test_status_defaults() -> None:
    """Status reflects the default configured shield state."""
    assert ShieldManager(MOCK_TASK_DIR, SandboxConfig()).status() == {
        "mode": "hook",
        "profiles": [],
        "audit_enabled": True,
    }


def test_status_custom_config() -> None:
    """Status reflects custom configured profiles and audit settings."""
    cfg = SandboxConfig(shield_profiles=("custom",), shield_audit=False)
    assert ShieldManager(MOCK_TASK_DIR, cfg).status() == {
        "mode": "hook",
        "profiles": ["custom"],
        "audit_enabled": False,
    }


# ── Kill-switch handling ────────────────────────────────────────────────


@pytest.mark.parametrize("method_name", ["down", "up"])
def test_disabled_makes_down_and_up_noops(method_name: str) -> None:
    """The kill-switch makes ``ShieldManager.up`` / ``.down`` no-ops without touching Shield."""
    mock_shield = MagicMock(spec=Shield)
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig(shield_disabled=True))
    with patch.object(ShieldManager, "shield", new=mock_shield):
        getattr(manager, method_name)("ctr", "ctr-uuid")
    mock_shield.up.assert_not_called()
    mock_shield.down.assert_not_called()


def test_quarantine_ignores_disabled() -> None:
    """Quarantine overrides the kill-switch — panic must always work."""
    mock_shield = make_mock_shield()
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig(shield_disabled=True))
    with patch.object(ShieldManager, "shield", new=mock_shield):
        manager.quarantine("ctr")
    mock_shield.quarantine.assert_called_once_with("ctr")


def test_disabled_pre_start_returns_empty_with_warning() -> None:
    """With the kill-switch set, pre_start returns no podman args and warns loudly."""
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig(shield_disabled=True))
    with pytest.warns(UserWarning) as caught:
        assert manager.pre_start("ctr") == []
    assert any(_DISABLED_WARNING in str(item.message) for item in caught)


def test_disabled_state_still_queries_real_shield() -> None:
    """State lookup still queries the real shield — containers shielded before the kill-switch was set."""
    mock_shield = make_mock_shield(shield_state=ShieldState.UP)
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig(shield_disabled=True))
    with patch.object(ShieldManager, "shield", new=mock_shield):
        assert manager.state("ctr") == ShieldState.UP
    mock_shield.state.assert_called_once_with("ctr")


@pytest.mark.parametrize(
    ("disabled", "expected_key"),
    [
        pytest.param(True, True, id="disabled"),
        pytest.param(False, False, id="enabled"),
    ],
)
def test_status_includes_disabled_flag_only_when_active(
    disabled: bool,
    expected_key: bool,
) -> None:
    """Status output surfaces the dangerous kill-switch flag only when it is set."""
    result = ShieldManager(MOCK_TASK_DIR, SandboxConfig(shield_disabled=disabled)).status()
    assert ("disable_firewall_no_protection" in result) is expected_key
    assert result["mode"] == "hook"
    assert "profiles" in result


# ── Environment probe ──────────────────────────────────────────────────


def test_check_environment_forwards_result() -> None:
    """The free check_environment delegates to a throwaway ``ShieldManager``."""
    expected = EnvironmentCheck(ok=True, health="ok", podman_version=(5, 6, 0))
    mock_shield = make_mock_shield()
    mock_shield.check_environment.return_value = expected
    with patch.object(ShieldManager, "shield", new=mock_shield):
        assert check_environment() == expected
    mock_shield.check_environment.assert_called_once()


def test_check_environment_disabled_returns_synthetic_result() -> None:
    """The kill-switch surfaces a synthetic degraded environment result."""
    result = check_environment(cfg=SandboxConfig(shield_disabled=True))
    assert not result.ok
    assert result.health == "disabled"
    assert any("disable_firewall_no_protection" in issue for issue in result.issues)


def test_manager_check_environment_under_the_kill_switch_builds_no_shield() -> None:
    """A manager asked directly answers from config, as the free probe does — no Shield is built.

    terok and the executor hold managers of their own, so this branch is reached
    without the free function's early return in front of it.
    """
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig(shield_disabled=True))
    with patch.object(ShieldManager, "shield", new_callable=PropertyMock) as shield:
        result = manager.check_environment()
    shield.assert_not_called()
    assert result == check_environment(cfg=SandboxConfig(shield_disabled=True))
    assert not result.ok
    assert result.health == "disabled"
    assert any("disable_firewall_no_protection" in issue for issue in result.issues)


def test_pre_start_preserves_typed_setup_failure() -> None:
    """Typed setup errors survive the adapter for pre-stop handling."""
    mock_shield = make_mock_shield()
    mock_shield.pre_start.side_effect = ShieldNeedsSetup("hooks not installed")
    manager = ShieldManager(MOCK_TASK_DIR)
    with (
        patch.object(ShieldManager, "shield", new=mock_shield),
        pytest.raises(ShieldNeedsSetup, match="hooks not installed"),
    ):
        manager.pre_start("ctr")


# ── ShieldHooks (host-wide installer) ───────────────────────────────────


def test_shield_hooks_install_delegates() -> None:
    """``ShieldHooks.install`` builds a ``HooksInstaller`` and calls ``install``."""
    with patch("terok_sandbox.integrations.shield.HooksInstaller") as installer_cls:
        ShieldHooks.install()
        installer_cls.assert_called_once_with()
        installer_cls.return_value.install.assert_called_once()


def test_shield_hooks_uninstall_delegates() -> None:
    """``ShieldHooks.uninstall`` builds a ``HooksInstaller`` and calls ``uninstall``."""
    with patch("terok_sandbox.integrations.shield.HooksInstaller") as installer_cls:
        ShieldHooks.uninstall()
        installer_cls.assert_called_once_with()
        installer_cls.return_value.uninstall.assert_called_once()


# ── Session helpers ─────────────────────────────────────────────────────


@patch("terok_shield.simple_clearance.run_simple_clearance")
def test_interactive_session_delegates_to_simple_clearance(
    mock_run_simple_clearance: MagicMock,
) -> None:
    """Session helper forwards the shield state_dir and container to the terminal fallback."""
    ShieldManager(MOCK_TASK_DIR).interactive_session("task-ctr")
    mock_run_simple_clearance.assert_called_once_with(MOCK_TASK_DIR / "shield", "task-ctr")


@patch("terok_shield.watch.run_watch")
def test_watch_session_delegates_to_run_watch(mock_run_watch: MagicMock) -> None:
    """Session helper forwards the shield state_dir and container to terok-shield."""
    ShieldManager(MOCK_TASK_DIR).watch_session("task-ctr")
    mock_run_watch.assert_called_once_with(MOCK_TASK_DIR / "shield", "task-ctr")


# ── Round-trip ──────────────────────────────────────────────────────────


def test_install_then_uninstall_round_trip(tmp_path: Path, monkeypatch) -> None:
    """``HooksInstaller(target_dir).install() + .uninstall()`` leaves no residue."""
    from terok_shield import HooksInstaller

    tools = tmp_path / "bin"
    tools.mkdir()
    for name in ("podman", "nft", "nsenter"):
        binary = tools / name
        binary.write_text("#!/bin/sh\nexit 0\n")
        binary.chmod(0o755)
    monkeypatch.setenv("PATH", str(tools))
    target_dir = tmp_path / "hooks"
    installer = HooksInstaller(target_dir=target_dir)
    installer.install()
    assert target_dir.is_dir()
    assert any(target_dir.iterdir())
    installer.uninstall()
    # The directory itself is left in place (other tools may share it);
    # only our files are gone.
    assert list(target_dir.iterdir()) == []


# ── the timed allow-all window ───────────────────────────────────────────


def test_bypass_delegates_and_returns_the_duration_granted() -> None:
    """``bypass`` passes the duration through and reports what shield granted."""
    mock_shield = make_mock_shield()
    mock_shield.bypass.return_value = "5m"
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig())
    with patch.object(ShieldManager, "shield", new=mock_shield):
        assert manager.bypass("ctr", "5m") == "5m"
    mock_shield.bypass.assert_called_once_with("ctr", "5m")


def test_bypass_with_no_duration_lets_shield_apply_its_configured_one() -> None:
    """Sandbox does not second-guess the default — shield owns it."""
    mock_shield = make_mock_shield()
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig())
    with patch.object(ShieldManager, "shield", new=mock_shield):
        manager.bypass("ctr")
    mock_shield.bypass.assert_called_once_with("ctr", None)


def test_bypass_off_closes_the_window() -> None:
    """``bypass_off`` hands the close straight through to shield."""
    mock_shield = make_mock_shield()
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig())
    with patch.object(ShieldManager, "shield", new=mock_shield):
        manager.bypass_off("ctr")
    mock_shield.bypass_off.assert_called_once_with("ctr")


def test_disabled_bypass_refuses_rather_than_pretending() -> None:
    """With the kill-switch set there is no window to open, and saying so beats a no-op."""
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig(shield_disabled=True))
    with pytest.raises(RuntimeError, match="shield is disabled"):
        manager.bypass("ctr")


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(RuntimeError("ctr is down: raise the shield first"), id="not-up"),
        pytest.param(ValueError("Invalid window duration: '0s'"), id="bad-duration"),
    ],
)
def test_bypass_lets_shields_refusals_through_unchanged(error: Exception) -> None:
    """Shield's own refusals — a posture other than UP, a duration it cannot arm — reach
    the caller as shield raised them; sandbox's kill-switch refusal is a separate one."""
    mock_shield = make_mock_shield()
    mock_shield.bypass.side_effect = error
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig())
    with (
        patch.object(ShieldManager, "shield", new=mock_shield),
        pytest.raises(type(error)) as raised,
    ):
        manager.bypass("ctr")
    assert raised.value is error


@pytest.mark.parametrize(
    ("method_name", "args", "closed"),
    [
        pytest.param("bypass_off", ("ctr",), None, id="bypass-off"),
        pytest.param(
            "revoke_override",
            ("ctr", SECURITY_TIER_DOMAIN),
            OverrideRevocation(target=SECURITY_TIER_DOMAIN, closed=(DESTINATION_IP,)),
            id="revoke-override",
        ),
    ],
)
def test_disabled_narrowing_changes_still_reach_the_real_shield(
    method_name: str, args: tuple[str, ...], closed: OverrideRevocation | None
) -> None:
    """A close only ever narrows egress, so the kill-switch never swallows one.

    A container started before the switch was thrown can still have a window open
    or an override in force — the reads say so — and a close dropped in silence
    would leave that door open while reading as shut.
    """
    mock_shield = make_mock_shield()
    getattr(mock_shield, method_name).return_value = closed
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig(shield_disabled=True))
    with patch.object(ShieldManager, "shield", new=mock_shield):
        assert getattr(manager, method_name)(*args) is closed
    getattr(mock_shield, method_name).assert_called_once_with(*args)


@pytest.mark.parametrize(
    ("method_name", "args", "error"),
    [
        pytest.param(
            "bypass_off",
            ("ctr",),
            ExecError(["nft"], 1, "Error: No such file or directory"),
            id="bypass-off-no-ruleset",
        ),
        pytest.param(
            "revoke_override",
            ("ctr", SECURITY_TIER_DOMAIN),
            RuntimeError(f"ctr has no override of {SECURITY_TIER_DOMAIN} to revoke"),
            id="revoke-override-none-in-force",
        ),
    ],
)
def test_disabled_narrowing_change_with_nothing_to_close_fails_visibly(
    method_name: str, args: tuple[str, ...], error: Exception
) -> None:
    """On a container launched under the kill-switch there is nothing to close, and
    shield's own refusal says so — it reaches the caller unchanged, never as a success."""
    mock_shield = make_mock_shield()
    getattr(mock_shield, method_name).side_effect = error
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig(shield_disabled=True))
    close = getattr(manager, method_name)
    with (
        patch.object(ShieldManager, "shield", new=mock_shield),
        pytest.raises(type(error)) as raised,
    ):
        close(*args)
    assert raised.value is error


def test_disabled_bypass_remaining_still_queries_the_real_shield() -> None:
    """A container started before the kill-switch can still have a window open."""
    mock_shield = make_mock_shield()
    mock_shield.bypass_remaining.return_value = WINDOW_SECONDS_LEFT
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig(shield_disabled=True))
    with patch.object(ShieldManager, "shield", new=mock_shield):
        assert manager.bypass_remaining("ctr") == WINDOW_SECONDS_LEFT


def test_bypass_duration_reaches_the_shield_config() -> None:
    """``shield.bypass_duration`` is threaded into ShieldConfig, not re-read by shield."""
    with (
        patch("terok_shield.run.SubprocessRunner", autospec=True),
        patch("terok_sandbox.paths.namespace_config_root", return_value=MOCK_CONFIG_ROOT),
    ):
        manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig(shield_bypass_duration="45s"))
        assert manager.shield.config.bypass_duration == "45s"


def test_harvest_reads_the_audit_log_even_with_the_kill_switch_set() -> None:
    """The log records what happened; a disabled shield does not unwrite it."""
    mock_shield = make_mock_shield()
    mock_shield.harvest.return_value = HarvestReport()
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig(shield_disabled=True))
    with patch.object(ShieldManager, "shield", new=mock_shield):
        assert manager.harvest() == HarvestReport()
    mock_shield.harvest.assert_called_once_with()


def test_harvest_hands_back_shields_report_whole() -> None:
    """The report keeps what a bare entry list would lose: each entry's tier and remedies,
    and whether audit was on at all — an empty harvest with audit off is no all-clear."""
    entry = HarvestEntry(
        action="blocked",
        target=PROMOTED_DOMAIN,
        count=1,
        first_seen="",
        last_seen="",
        ports=(),
        addresses=(DESTINATION_IP,),
    )
    report = HarvestReport(entries=(entry,), audit_enabled=False)
    mock_shield = make_mock_shield()
    mock_shield.harvest.return_value = report
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig())
    with patch.object(ShieldManager, "shield", new=mock_shield):
        harvested = manager.harvest()
    assert harvested is report
    assert harvested.audit_enabled is False
    assert [e.tier for e in harvested] == [TIER_ALLOWLIST]


# ── Operator grants: promotion and break-glass ───────────────────────────


def test_allow_delegates_and_returns_the_allow_result() -> None:
    """``allow`` is a pass-through: shield's ``AllowResult`` says how the grant landed."""
    granted = AllowResult(target=PROMOTED_DOMAIN, ips=(DESTINATION_IP,))
    mock_shield = make_mock_shield()
    mock_shield.allow.return_value = granted
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig())
    with patch.object(ShieldManager, "shield", new=mock_shield):
        assert manager.allow("ctr", PROMOTED_DOMAIN) is granted
    mock_shield.allow.assert_called_once_with("ctr", PROMOTED_DOMAIN)


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(
            SecurityTierRefusal(SECURITY_TIER_DOMAIN, entry=SECURITY_TIER_DOMAIN),
            id="security-tier-refusal",
        ),
        pytest.param(ShieldNeedsSetup("wildcards need the live tier"), id="static-tier-wildcard"),
    ],
)
def test_allow_lets_shields_refusals_through_unchanged(error: Exception) -> None:
    """The security tier's refusal reaches the caller as shield raised it — the very object,
    so the promotion engine can name the entry that refused and offer the break-glass."""
    mock_shield = make_mock_shield()
    mock_shield.allow.side_effect = error
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig())
    with (
        patch.object(ShieldManager, "shield", new=mock_shield),
        pytest.raises(type(error)) as raised,
    ):
        manager.allow("ctr", SECURITY_TIER_DOMAIN)
    assert raised.value is error


def test_override_threads_expiry_and_reason_into_shield() -> None:
    """The break-glass carries its expiry and its reason through untouched; shield enforces both."""
    expires = date.today() + timedelta(days=1)
    mock_shield = make_mock_shield()
    mock_shield.override.return_value = [DESTINATION_IP]
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig())
    with patch.object(ShieldManager, "shield", new=mock_shield):
        opened = manager.override("ctr", SECURITY_TIER_DOMAIN, expires, reason=OVERRIDE_REASON)
    assert opened == [DESTINATION_IP]
    mock_shield.override.assert_called_once_with(
        "ctr", SECURITY_TIER_DOMAIN, expires, reason=OVERRIDE_REASON
    )


def test_revoke_override_returns_what_shield_closed() -> None:
    """The revocation says what closed and whether it took hold live — sandbox adds nothing."""
    revoked = OverrideRevocation(target=SECURITY_TIER_DOMAIN, closed=(DESTINATION_IP,))
    mock_shield = make_mock_shield()
    mock_shield.revoke_override.return_value = revoked
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig())
    with patch.object(ShieldManager, "shield", new=mock_shield):
        assert manager.revoke_override("ctr", SECURITY_TIER_DOMAIN) is revoked
    mock_shield.revoke_override.assert_called_once_with("ctr", SECURITY_TIER_DOMAIN)


@pytest.mark.parametrize(
    ("method_name", "args", "kwargs"),
    [
        pytest.param("allow", ("ctr", PROMOTED_DOMAIN), {}, id="allow"),
        pytest.param(
            "override",
            ("ctr", SECURITY_TIER_DOMAIN, date.max),
            {"reason": OVERRIDE_REASON},
            id="override",
        ),
    ],
)
def test_disabled_operator_changes_refuse_rather_than_pretend(
    method_name: str, args: tuple[object, ...], kwargs: dict[str, object]
) -> None:
    """Under the kill-switch sandbox opens nothing, and says so instead of dropping the ask.

    The refusal is a plain ``RuntimeError`` — never shield's ``SecurityTierRefusal`` —
    so a caller tells "the shield is off" from "the tier refused it".  Closes are
    another matter: see the narrowing-change tests above.
    """
    mock_shield = make_mock_shield()
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig(shield_disabled=True))
    grant = getattr(manager, method_name)
    with (
        patch.object(ShieldManager, "shield", new=mock_shield),
        pytest.raises(RuntimeError, match="shield is disabled") as raised,
    ):
        grant(*args, **kwargs)
    assert not isinstance(raised.value, SecurityTierRefusal)
    assert mock_shield.method_calls == []


# ── One-listing reading of the live ruleset ──────────────────────────────


@pytest.mark.parametrize("disabled", [False, True], ids=["enabled", "kill-switch"])
def test_inspect_reads_the_live_ruleset_even_under_the_kill_switch(disabled: bool) -> None:
    """Posture and window come back from one reading; a container started before the
    kill-switch keeps its rules, so the switch does not stop the read."""
    reading = ShieldReading(state=ShieldState.UP, bypass_remaining=WINDOW_SECONDS_LEFT)
    mock_shield = make_mock_shield()
    mock_shield.inspect.return_value = reading
    manager = ShieldManager(MOCK_TASK_DIR, SandboxConfig(shield_disabled=disabled))
    with patch.object(ShieldManager, "shield", new=mock_shield):
        assert manager.inspect("ctr") is reading
    mock_shield.inspect.assert_called_once_with("ctr")


# ── File reads: no Shield wire-up, kill-switch or not ────────────────────


def test_rotation_risk_reads_the_recorded_bundle(tmp_path: Path) -> None:
    """Nothing recorded reads as no risk; a static tier pins the allowlisted names it resolved."""
    from terok_shield.state import StateBundle

    manager = ShieldManager(tmp_path, SandboxConfig(shield_disabled=True))
    assert manager.rotation_risk is None

    bundle = StateBundle(manager.state_dir)
    bundle.ensure_dirs()
    bundle.dns_tier.write_text(f"{DnsTier.LOOKUP.value}\n")
    bundle.write_tier("project_allow", f"+{PROMOTED_DOMAIN}\n+{DESTINATION_IP}\n")
    with patch.object(ShieldManager, "shield", new_callable=PropertyMock) as shield:
        risk = manager.rotation_risk
    shield.assert_not_called()
    # The literal address cannot rotate, so only the name is at risk.
    assert risk == RotationRisk(tier=DnsTier.LOOKUP, allow=(PROMOTED_DOMAIN,))


def test_rotation_risk_is_none_on_the_live_tier(tmp_path: Path) -> None:
    """dnsmasq-live follows every name as it resolves — an allowlist there pins nothing."""
    from terok_shield.state import StateBundle

    manager = ShieldManager(tmp_path)
    bundle = StateBundle(manager.state_dir)
    bundle.ensure_dirs()
    bundle.dns_tier.write_text(f"{DnsTier.DNSMASQ_LIVE.value}\n")
    bundle.write_tier("project_allow", f"+{PROMOTED_DOMAIN}\n")
    assert manager.rotation_risk is None


def test_container_short_id_reads_what_the_hook_recorded(tmp_path: Path) -> None:
    """The hub's key, not the podman name: ``None`` before the first start, the
    12-character lowercase short id after — under the kill-switch too."""
    from terok_shield.state import StateBundle

    manager = ShieldManager(tmp_path, SandboxConfig(shield_disabled=True))
    assert manager.container_short_id is None

    bundle = StateBundle(manager.state_dir)
    bundle.ensure_dirs()
    bundle.container_id.write_text(f"{FAKE_CONTAINER_ID}\n")
    with patch.object(ShieldManager, "shield", new_callable=PropertyMock) as shield:
        assert manager.container_short_id == FAKE_CONTAINER_SHORT_ID
    shield.assert_not_called()


# ── Host-level environment probe: a state dir the addendum covers (#1246) ──


def _addendum_file_glob(live_root: Path) -> PurePosixPath:
    """The ``owner <glob> rwk`` path the rendered AppArmor addendum grants dnsmasq."""
    (rule,) = (
        line for line in render_addendum(live_root).splitlines() if line.startswith("owner ")
    )
    return PurePosixPath(rule.split()[1])


def _apparmor_glob_matches(path: Path, glob: PurePosixPath) -> bool:
    """``fnmatch`` *path* against *glob* one component at a time, the way AppArmor's ``*`` matches.

    A whole-path ``fnmatch`` lets ``*`` run across ``/``; AppArmor's never
    does, so a state dir one level too deep or too shallow must not pass.
    """
    parts = PurePosixPath(path).parts
    return len(parts) == len(glob.parts) and all(
        fnmatch.fnmatchcase(part, pattern) for part, pattern in zip(parts, glob.parts, strict=True)
    )


def test_check_environment_probes_a_created_state_dir_the_addendum_covers() -> None:
    """The host probe stands in for a task: a state dir that exists, where the addendum reaches.

    An uncreated one let shield's AppArmor probe fail open and report the
    dnsmasq tier on hosts where every real launch falls to a static tier
    (terok-ai/terok#1246).  Afterwards nothing is left in the tasks tree.
    """
    probed: list[Path] = []

    def probe(manager: ShieldManager) -> EnvironmentCheck:
        assert manager.state_dir.is_dir()
        probed.append(manager.state_dir)
        return EnvironmentCheck(dns_tier=DnsTier.LOOKUP.value)

    with patch.object(ShieldManager, "check_environment", autospec=True, side_effect=probe):
        result = check_environment(SandboxConfig())

    assert result == EnvironmentCheck(dns_tier=DnsTier.LOOKUP.value)
    (state_dir,) = probed
    live_root = sandbox_live_root()
    assert _apparmor_glob_matches(state_dir, _addendum_file_glob(live_root).parent)
    assert not state_dir.exists()
    assert list((live_root / "tasks").iterdir()) == []


def test_host_probe_runs_dnsmasq_on_a_file_the_addendum_grants() -> None:
    """Through shield's own probe: ``dnsmasq --test`` really runs, on a file the
    addendum's ``dnsmasq.*`` rule covers — the access a launch needs, tested as a launch has it."""
    from terok_shield.dns.apparmor import dnsmasq_can_read_state_dir

    probe_files: list[Path] = []

    def probe(manager: ShieldManager) -> EnvironmentCheck:
        runner = MagicMock()
        runner.run.side_effect = lambda *_a, **_kw: probe_files.extend(manager.state_dir.iterdir())
        assert dnsmasq_can_read_state_dir(runner, str(MOCK_HOST_BIN / "dnsmasq"), manager.state_dir)
        return EnvironmentCheck()

    with patch.object(ShieldManager, "check_environment", autospec=True, side_effect=probe):
        check_environment(SandboxConfig())

    (probe_file,) = probe_files
    assert _apparmor_glob_matches(probe_file, _addendum_file_glob(sandbox_live_root()))


def test_check_environment_cleans_up_when_the_probe_raises() -> None:
    """The stand-in goes however the probe ends — an operator's tasks tree keeps no debris."""
    probed: list[Path] = []

    def probe(manager: ShieldManager) -> EnvironmentCheck:
        probed.append(manager.state_dir)
        raise RuntimeError("probe failed")

    cfg = SandboxConfig()
    with (
        patch.object(ShieldManager, "check_environment", autospec=True, side_effect=probe),
        pytest.raises(RuntimeError, match="probe failed"),
    ):
        check_environment(cfg)

    (state_dir,) = probed
    assert not state_dir.exists()
    assert list((sandbox_live_root() / "tasks").iterdir()) == []


def test_check_environment_leaves_a_concurrent_probe_alone() -> None:
    """Cleanup removes its own stand-in only; a concurrent probe's, beside it in ``tasks/``, stays."""
    others: list[Path] = []

    def probe(manager: ShieldManager) -> EnvironmentCheck:
        other = manager.state_dir.parents[2] / "_host-probe-concurrent" / "host" / "shield"
        other.mkdir(parents=True)
        others.append(other)
        return EnvironmentCheck()

    with patch.object(ShieldManager, "check_environment", autospec=True, side_effect=probe):
        check_environment(SandboxConfig())

    (other,) = others
    assert other.is_dir()
    assert list((sandbox_live_root() / "tasks").iterdir()) == [other.parents[1]]


def test_a_probe_ending_mid_setup_never_pushes_another_onto_the_fallback() -> None:
    """Probes overlap — terok checks from more than one worker.  One that ends just as
    another sets up must not pull a directory from under it: that probe would land on
    the fallback, whose uncreated state dir reads as the dnsmasq tier (#1246 again)."""
    probed: list[Path] = []
    overlapped: list[bool] = []
    real_temporary_directory = tempfile.TemporaryDirectory

    def probe(manager: ShieldManager) -> EnvironmentCheck:
        assert manager.state_dir.is_dir()
        probed.append(manager.state_dir)
        return EnvironmentCheck()

    def overlapping(*args: Any, **kwargs: Any) -> tempfile.TemporaryDirectory[str]:
        # The outer probe is setting up: a whole second probe runs, start to
        # finish, before the outer one makes its own directory.
        if not overlapped:
            overlapped.append(True)
            check_environment(SandboxConfig())
        return real_temporary_directory(*args, **kwargs)

    with (
        patch.object(ShieldManager, "check_environment", autospec=True, side_effect=probe),
        patch.object(tempfile, "TemporaryDirectory", new=overlapping),
    ):
        check_environment(SandboxConfig())

    inner, outer = probed
    live_root = sandbox_live_root()
    assert inner != outer
    assert live_root in outer.parents
    assert not inner.exists()
    assert not outer.exists()
    assert list((live_root / "tasks").iterdir()) == []


def test_check_environment_falls_back_to_a_bare_temp_dir_when_sandbox_live_is_unwritable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With sandbox-live unwritable the probe runs as it always did: a temp dir whose state
    dir is never created, so shield fails open rather than crying AppArmor."""
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("")
    monkeypatch.setenv("TEROK_SANDBOX_LIVE_DIR", str(blocker / "sandbox-live"))
    probed: list[Path] = []

    def probe(manager: ShieldManager) -> EnvironmentCheck:
        assert manager.state_dir.parent.is_dir()
        assert not manager.state_dir.exists()
        probed.append(manager.state_dir)
        return EnvironmentCheck()

    with patch.object(ShieldManager, "check_environment", autospec=True, side_effect=probe):
        check_environment(SandboxConfig())

    (state_dir,) = probed
    assert blocker not in state_dir.parents
    assert not state_dir.parent.exists()


def test_disabled_check_environment_touches_no_disk() -> None:
    """The kill-switch answers from config alone — no stand-in task dir is made for it."""
    check_environment(cfg=SandboxConfig(shield_disabled=True))
    assert not (sandbox_live_root() / "tasks").exists()
