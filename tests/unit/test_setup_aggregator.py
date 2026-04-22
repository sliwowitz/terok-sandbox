# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Top-level ``sandbox setup`` and ``sandbox uninstall`` orchestration.

The aggregators compose shield-hook, vault, and gate lifecycle handlers
into a single bootstrap and a symmetric teardown.  Phase ordering and
opt-out flags are the contract under test — the individual phase
handlers have their own dedicated tests elsewhere.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from terok_sandbox.commands import (
    _handle_sandbox_setup,
    _handle_sandbox_uninstall,
)

# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
def phase_spies():
    """Replace every phase handler with a MagicMock so order is observable."""
    with (
        patch("terok_sandbox.commands._handle_shield_setup") as shield_install,
        patch("terok_sandbox.commands._handle_shield_uninstall") as shield_uninstall,
        patch("terok_sandbox.commands._handle_vault_install") as vault_install,
        patch("terok_sandbox.commands._handle_vault_uninstall") as vault_uninstall,
        patch("terok_sandbox.commands._handle_gate_install") as gate_install,
        patch("terok_sandbox.commands._handle_gate_uninstall") as gate_uninstall,
    ):
        yield {
            "shield_install": shield_install,
            "shield_uninstall": shield_uninstall,
            "vault_install": vault_install,
            "vault_uninstall": vault_uninstall,
            "gate_install": gate_install,
            "gate_uninstall": gate_uninstall,
        }


# ── Setup aggregator ──────────────────────────────────────────────────────


class TestSandboxSetup:
    """``sandbox setup`` orchestrates shield → vault → gate in that order."""

    def test_default_installs_all_three_phases(self, phase_spies) -> None:
        _handle_sandbox_setup()
        phase_spies["shield_install"].assert_called_once_with(user=True, root=False)
        phase_spies["vault_install"].assert_called_once_with()
        phase_spies["gate_install"].assert_called_once_with()

    def test_root_flag_installs_shield_system_wide(self, phase_spies) -> None:
        _handle_sandbox_setup(root=True)
        phase_spies["shield_install"].assert_called_once_with(user=False, root=True)

    @pytest.mark.parametrize(
        ("skip_kwarg", "skipped_spy_key"),
        [
            ("no_shield", "shield_install"),
            ("no_vault", "vault_install"),
            ("no_gate", "gate_install"),
        ],
    )
    def test_opt_out_flag_skips_exactly_its_phase(
        self, phase_spies, skip_kwarg: str, skipped_spy_key: str
    ) -> None:
        _handle_sandbox_setup(**{skip_kwarg: True})
        phase_spies[skipped_spy_key].assert_not_called()
        # The two non-skipped phases still run.
        for key in ("shield_install", "vault_install", "gate_install"):
            if key != skipped_spy_key:
                assert phase_spies[key].called, f"{key} should still run"


# ── Uninstall aggregator ──────────────────────────────────────────────────


class TestSandboxUninstall:
    """``sandbox uninstall`` runs gate → vault → shield (reverse of install)."""

    def test_default_uninstalls_all_three_phases(self, phase_spies) -> None:
        _handle_sandbox_uninstall()
        phase_spies["gate_uninstall"].assert_called_once_with()
        phase_spies["vault_uninstall"].assert_called_once_with()
        phase_spies["shield_uninstall"].assert_called_once_with(user=True, root=False)

    def test_phases_run_in_reverse_install_order(self, phase_spies) -> None:
        """Gate first (it may depend on vault), vault next, shield last — symmetric to setup."""
        order: list[str] = []
        phase_spies["gate_uninstall"].side_effect = lambda: order.append("gate")
        phase_spies["vault_uninstall"].side_effect = lambda: order.append("vault")
        phase_spies["shield_uninstall"].side_effect = lambda **_: order.append("shield")

        _handle_sandbox_uninstall()

        assert order == ["gate", "vault", "shield"]

    def test_root_flag_removes_shield_hooks_system_wide(self, phase_spies) -> None:
        _handle_sandbox_uninstall(root=True)
        phase_spies["shield_uninstall"].assert_called_once_with(user=False, root=True)

    @pytest.mark.parametrize(
        ("skip_kwarg", "skipped_spy_key"),
        [
            ("no_shield", "shield_uninstall"),
            ("no_vault", "vault_uninstall"),
            ("no_gate", "gate_uninstall"),
        ],
    )
    def test_opt_out_flag_skips_exactly_its_phase(
        self, phase_spies, skip_kwarg: str, skipped_spy_key: str
    ) -> None:
        _handle_sandbox_uninstall(**{skip_kwarg: True})
        phase_spies[skipped_spy_key].assert_not_called()
        for key in ("shield_uninstall", "vault_uninstall", "gate_uninstall"):
            if key != skipped_spy_key:
                assert phase_spies[key].called, f"{key} should still run"
