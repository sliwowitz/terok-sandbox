# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the flock-based shared port registry."""

from __future__ import annotations

import fcntl
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from terok_sandbox import port_registry as reg


@pytest.fixture(autouse=True)
def _isolated_registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Redirect registry to a tmp dir and release all held locks."""
    registry = tmp_path / "terok-ports"
    registry.mkdir()
    monkeypatch.setattr(reg, "REGISTRY_DIR", registry)
    reg.reset_cache()


# ---------------------------------------------------------------------------
# claim_port — basic allocation
# ---------------------------------------------------------------------------


def test_claim_preferred_free() -> None:
    """Preferred port is returned when available."""
    assert reg.claim_port("proxy", preferred=18700) == 18700


def test_claim_defaults_to_range_start() -> None:
    """No preference → starts from PORT_RANGE.start."""
    assert reg.claim_port("gate") == reg.PORT_RANGE.start


def test_claim_busy_increments() -> None:
    """When preferred port is busy, scan upward for the next free one."""
    busy = {18700, 18701}
    original = reg._is_port_free

    def mock_free(p: int) -> bool:
        return p not in busy and original(p)

    with patch.object(reg, "_is_port_free", side_effect=mock_free):
        assert reg.claim_port("proxy", preferred=18700) == 18702


def test_self_collision_avoidance() -> None:
    """Consecutive claims from the same process don't collide."""
    a = reg.claim_port("gate")
    b = reg.claim_port("proxy")
    c = reg.claim_port("ssh_agent")
    assert len({a, b, c}) == 3


# ---------------------------------------------------------------------------
# claim_port — cross-process isolation via flock
# ---------------------------------------------------------------------------


def test_claim_skips_flocked_port() -> None:
    """A port whose lock file is held by another fd is skipped."""
    lock_path = reg.REGISTRY_DIR / "18700.lock"
    # Simulate another process holding the flock
    rival = lock_path.open("w")
    fcntl.flock(rival, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        port = reg.claim_port("proxy", preferred=18700)
        assert port != 18700
    finally:
        rival.close()


def test_released_flock_becomes_available() -> None:
    """After the holder closes its fd, the port is claimable again."""
    lock_path = reg.REGISTRY_DIR / "18700.lock"
    rival = lock_path.open("w")
    fcntl.flock(rival, fcntl.LOCK_EX | fcntl.LOCK_NB)
    rival.close()  # releases the flock

    assert reg.claim_port("proxy", preferred=18700) == 18700


# ---------------------------------------------------------------------------
# claim_port — explicit override
# ---------------------------------------------------------------------------


def test_explicit_busy_fails() -> None:
    """Explicit pin + busy port → SystemExit."""
    with (
        patch.object(reg, "_is_port_free", return_value=False),
        pytest.raises(SystemExit, match="unavailable"),
    ):
        reg.claim_port("proxy", preferred=19000, explicit=True)


def test_explicit_flocked_fails() -> None:
    """Explicit pin + flock held → SystemExit."""
    lock_path = reg.REGISTRY_DIR / "19000.lock"
    rival = lock_path.open("w")
    fcntl.flock(rival, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(SystemExit, match="unavailable"):
            reg.claim_port("proxy", preferred=19000, explicit=True)
    finally:
        rival.close()


def test_explicit_invalid_port_number() -> None:
    """Explicit pin with out-of-range port number → SystemExit."""
    with pytest.raises(SystemExit, match="not a valid port number"):
        reg.claim_port("proxy", preferred=0, explicit=True)
    with pytest.raises(SystemExit, match="not a valid port number"):
        reg.claim_port("proxy", preferred=70000, explicit=True)


# ---------------------------------------------------------------------------
# claim_port — idempotency
# ---------------------------------------------------------------------------


def test_repeated_claim_returns_same_port() -> None:
    """Claiming the same service_key again returns the cached port."""
    a = reg.claim_port("gate", preferred=18700)
    b = reg.claim_port("gate", preferred=18800)  # different preferred, ignored
    assert a == b == 18700


# ---------------------------------------------------------------------------
# release_port
# ---------------------------------------------------------------------------


def test_release_frees_port() -> None:
    """After release, the port can be claimed by a new key."""
    reg.claim_port("web:proj/task-1", preferred=18710)
    reg.release_port("web:proj/task-1")
    # Now claimable under a different key
    assert reg.claim_port("web:proj/task-2", preferred=18710) == 18710


def test_release_nonexistent_is_noop() -> None:
    """Releasing an unclaimed key does not raise."""
    reg.release_port("never-claimed")


# ---------------------------------------------------------------------------
# resolve_service_ports
# ---------------------------------------------------------------------------


def test_resolve_auto_allocates_distinct() -> None:
    """Auto-resolve assigns three distinct ports."""
    ports = reg.resolve_service_ports(None, None, None)
    assert len({ports.gate, ports.proxy, ports.ssh_agent}) == 3


def test_resolve_cached() -> None:
    """Second call returns the same cached result."""
    assert reg.resolve_service_ports(None, None, None) == reg.resolve_service_ports(
        None, None, None
    )


def test_resolve_explicit() -> None:
    """Explicit ports are passed through."""
    ports = reg.resolve_service_ports(
        19100,
        19200,
        19300,
        gate_explicit=True,
        proxy_explicit=True,
        ssh_explicit=True,
    )
    assert (ports.gate, ports.proxy, ports.ssh_agent) == (19100, 19200, 19300)


# ---------------------------------------------------------------------------
# Persistent claims (state_dir)
# ---------------------------------------------------------------------------


def test_resolve_persists_to_state_dir(tmp_path: Path) -> None:
    """resolve_service_ports writes a claims file to state_dir."""
    state = tmp_path / "state"
    state.mkdir()
    ports = reg.resolve_service_ports(None, None, None, state_dir=state)
    claims = json.loads((state / reg._CLAIMS_FILENAME).read_text())
    assert claims == {"gate": ports.gate, "proxy": ports.proxy, "ssh_agent": ports.ssh_agent}


def test_resolve_prefers_saved_ports(tmp_path: Path) -> None:
    """Saved ports are reclaimed when free."""
    state = tmp_path / "state"
    state.mkdir()
    (state / reg._CLAIMS_FILENAME).write_text(
        json.dumps({"gate": 18750, "proxy": 18751, "ssh_agent": 18752})
    )
    ports = reg.resolve_service_ports(None, None, None, state_dir=state)
    assert (ports.gate, ports.proxy, ports.ssh_agent) == (18750, 18751, 18752)


def test_resolve_fails_when_saved_taken(tmp_path: Path) -> None:
    """SystemExit when a saved port is claimed by another user."""
    state = tmp_path / "state"
    state.mkdir()
    (state / reg._CLAIMS_FILENAME).write_text(
        json.dumps({"gate": 18750, "proxy": 18751, "ssh_agent": 18752})
    )
    # Rival holds the gate port
    lock_path = reg.REGISTRY_DIR / "18750.lock"
    rival = lock_path.open("w")
    fcntl.flock(rival, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(SystemExit, match="previously assigned"):
            reg.resolve_service_ports(None, None, None, state_dir=state)
    finally:
        rival.close()


def test_resolve_explicit_overrides_saved(tmp_path: Path) -> None:
    """Explicit config port wins over saved claim."""
    state = tmp_path / "state"
    state.mkdir()
    (state / reg._CLAIMS_FILENAME).write_text(
        json.dumps({"gate": 18750, "proxy": 18751, "ssh_agent": 18752})
    )
    ports = reg.resolve_service_ports(
        19100, None, None, gate_explicit=True, state_dir=state,
    )
    assert ports.gate == 19100
    assert ports.proxy == 18751


def test_corrupt_claims_file_ignored(tmp_path: Path) -> None:
    """Garbage claims file → auto-allocate normally."""
    state = tmp_path / "state"
    state.mkdir()
    (state / reg._CLAIMS_FILENAME).write_text("not json at all!!!")
    ports = reg.resolve_service_ports(None, None, None, state_dir=state)
    assert len({ports.gate, ports.proxy, ports.ssh_agent}) == 3


# ---------------------------------------------------------------------------
# SandboxConfig integration
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Security hardening
# ---------------------------------------------------------------------------


def test_symlink_registry_rejected(tmp_path: Path) -> None:
    """Registry directory that is a symlink → SystemExit."""
    target = tmp_path / "real"
    target.mkdir()
    symlink = tmp_path / "link"
    symlink.symlink_to(target)

    reg._registry_ensured = False
    reg.REGISTRY_DIR = symlink  # type: ignore[assignment]
    with pytest.raises(SystemExit, match="symlink"):
        reg.claim_port("gate")


def test_symlink_lock_file_skipped(tmp_path: Path) -> None:
    """A lock file that is a symlink is silently skipped (O_NOFOLLOW)."""
    lock_path = reg.REGISTRY_DIR / "18700.lock"
    target = tmp_path / "decoy"
    target.touch()
    lock_path.symlink_to(target)

    # Should skip port 18700 and allocate the next one
    port = reg.claim_port("proxy", preferred=18700)
    assert port != 18700


def test_auto_clamps_out_of_range_preferred() -> None:
    """Auto-allocation ignores a preferred port outside PORT_RANGE."""
    port = reg.claim_port("gate", preferred=50000)
    assert port in reg.PORT_RANGE


def test_sandbox_config_auto_resolves(tmp_path: Path) -> None:
    """SandboxConfig with default (None) ports auto-resolves and persists."""
    from terok_sandbox import SandboxConfig

    state = tmp_path / "sandbox-state"
    state.mkdir()
    cfg = SandboxConfig(state_dir=state)
    assert isinstance(cfg.gate_port, int)
    assert len({cfg.gate_port, cfg.proxy_port, cfg.ssh_agent_port}) == 3
    # Claims file written
    assert (state / reg._CLAIMS_FILENAME).exists()


def test_sandbox_config_explicit_passthrough() -> None:
    """SandboxConfig with explicit ports does not auto-resolve."""
    from terok_sandbox import SandboxConfig

    cfg = SandboxConfig(gate_port=9418, proxy_port=18731, ssh_agent_port=18732)
    assert (cfg.gate_port, cfg.proxy_port, cfg.ssh_agent_port) == (9418, 18731, 18732)
