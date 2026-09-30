# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Pin the public API for the sandbox-wide uninstall aggregator.

External consumers (``terok``, ``terok-executor``) reach the
sandbox-wide install/uninstall aggregators in two shapes:

- ``sandbox_uninstall`` is published on the package root for the
  ``terok`` CLI's ``uninstall`` command, which calls it directly.
- The corresponding setup verb (``_handle_sandbox_setup``) is imported
  by ``terok-executor`` from ``terok_sandbox.commands`` via its
  integrations adapter — no top-level alias is published for it.

This test fixes the identity link between the top-level
``sandbox_uninstall`` and the implementation handler so a renamed
implementation can't silently leave the public name pointing at a
stale callable.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

import terok_sandbox
from terok_sandbox.commands import _handle_sandbox_uninstall

#: Shield's promotion vocabulary the package root re-exports, each with the
#: shield module that owns it.  terok's promotion engine and TUI match on
#: these — the tier standing in a harvest entry's way, the remedies that
#: could lift it, what a grant returned — never on a copy spelled locally.
SHIELD_PROMOTION_VOCABULARY = (
    ("AllowResult", "terok_shield"),
    ("OverrideRevocation", "terok_shield"),
    ("SecurityTierRefusal", "terok_shield"),
    ("validate_target", "terok_shield"),
    ("ShieldReading", "terok_shield"),
    ("ShieldState", "terok_shield"),
    ("RotationRisk", "terok_shield"),
    ("HarvestEntry", "terok_shield.harvest"),
    ("HarvestReport", "terok_shield.harvest"),
    ("TIER_ALLOWLIST", "terok_shield.harvest"),
    ("TIER_OPERATOR_DENY", "terok_shield.harvest"),
    ("TIER_SECURITY", "terok_shield.harvest"),
    ("TIER_PRIVATE", "terok_shield.harvest"),
    ("TIER_HARD_DENY", "terok_shield.harvest"),
    ("REMEDY_TASK", "terok_shield.harvest"),
    ("REMEDY_PROJECT", "terok_shield.harvest"),
    ("REMEDY_SET", "terok_shield.harvest"),
    ("REMEDY_OVERRIDE", "terok_shield.harvest"),
    ("REMEDY_HOST_PORT", "terok_shield.harvest"),
)


def test_sandbox_uninstall_is_public_alias_of_aggregator() -> None:
    assert terok_sandbox.sandbox_uninstall is _handle_sandbox_uninstall


def test_sandbox_uninstall_listed_in_all() -> None:
    """``__all__`` lists ``sandbox_uninstall`` — pins the star-import contract."""
    assert "sandbox_uninstall" in terok_sandbox.__all__


def test_nested_container_socket_paths_are_public() -> None:
    """Upper layers consume one canonical set of container socket paths."""
    assert terok_sandbox.CONTAINER_VAULT_SOCKET == "/run/terok/vault/vault.sock"
    assert terok_sandbox.CONTAINER_SSH_SIGNER_SOCKET == "/run/terok/signer/ssh-agent.sock"
    assert terok_sandbox.CONTAINER_GATE_SOCKET == "/run/terok/gate/gate-server.sock"


def test_combined_annotations_resolver_is_public_alias() -> None:
    """The renamed re-export pins to shield's combined resolver and rides ``__all__``."""
    from terok_shield.container import ShieldAnnotations, resolve_annotations

    assert terok_sandbox.resolve_container_annotations is resolve_annotations
    assert terok_sandbox.ShieldAnnotations is ShieldAnnotations
    assert "resolve_container_annotations" in terok_sandbox.__all__
    assert "ShieldAnnotations" in terok_sandbox.__all__


@pytest.mark.parametrize(
    ("name", "owner"), SHIELD_PROMOTION_VOCABULARY, ids=[n for n, _ in SHIELD_PROMOTION_VOCABULARY]
)
def test_shield_promotion_vocabulary_is_public(name: str, owner: str) -> None:
    """Each name resolves lazily to shield's own object and rides ``__all__``."""
    assert getattr(terok_sandbox, name) is getattr(importlib.import_module(owner), name)
    assert name in terok_sandbox._LAZY
    assert name in terok_sandbox.__all__


def _type_checking_imports() -> set[str]:
    """Names the barrel imports under ``if TYPE_CHECKING:`` — its view for type checkers."""
    tree = ast.parse(Path(terok_sandbox.__file__).read_text(encoding="utf-8"))
    return {
        alias.asname or alias.name
        for node in tree.body
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Name)
        and node.test.id == "TYPE_CHECKING"
        for stmt in node.body
        if isinstance(stmt, ast.ImportFrom)
        for alias in stmt.names
    }


def test_shield_promotion_vocabulary_is_typed_for_checkers() -> None:
    """Every name also sits in the barrel's ``TYPE_CHECKING`` import: without it a
    type checker resolves the name through ``__getattr__`` and sees ``Any``."""
    missing = {name for name, _ in SHIELD_PROMOTION_VOCABULARY} - _type_checking_imports()
    assert missing == set()


def test_clearance_mode_is_public_and_typed() -> None:
    """``ClearanceMode`` — the ``services.clearance`` vocabulary terok's project schema
    and ``make_sandbox_config`` annotate with — is the schema's own alias, rides
    ``__all__``, and sits in the ``TYPE_CHECKING`` import for type checkers."""
    from terok_sandbox.config_schema import ClearanceMode

    assert terok_sandbox.ClearanceMode is ClearanceMode
    assert "ClearanceMode" in terok_sandbox._LAZY
    assert "ClearanceMode" in terok_sandbox.__all__
    assert "ClearanceMode" in _type_checking_imports()
