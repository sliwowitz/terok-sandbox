# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the post-start supervision check (issue #458, fix 2)."""

from __future__ import annotations

import json
import shutil
import socket
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from terok_sandbox import supervision
from terok_sandbox.config import SandboxConfig
from terok_sandbox.supervision import (
    MIN_RUNTIME_PROTOCOL,
    ServiceEndpoint,
    SupervisionStatus,
    outdated_container_warning,
    verify_supervision,
    warn_unsupervised,
)
from tests.constants import MOCK_BASE

_NAME = "demo-cli-w9xk3"
_FAST = 0.2  # timeout for the intentionally-missing cases — keep the suite snappy


def _cfg(state_dir: Path) -> SandboxConfig:
    return SandboxConfig(state_dir=state_dir)


def _write_sidecar(
    state_dir: Path,
    runtime_dir: Path,
    *,
    ipc_mode: str = "socket",
    gate: bool = False,
    ports: dict[str, int] | None = None,
) -> None:
    """Drop a valid sidecar under ``<state>/sidecar/<name>.json``."""
    sidecar_dir = state_dir / "sidecar"
    sidecar_dir.mkdir(parents=True, exist_ok=True)
    payload: dict[str, object] = {
        "container_name": _NAME,
        "ipc_mode": ipc_mode,
        "db_path": str(state_dir / "v.db"),
        "runtime_dir": str(runtime_dir),
    }
    if gate:
        payload["gate_base_path"] = str(state_dir / "gate")
        payload["gate_token"] = "tok123"
    payload.update(ports or {})
    (sidecar_dir / f"{_NAME}.json").write_text(json.dumps(payload))


def _socket_paths(runtime_dir: Path) -> tuple[Path, Path, Path]:
    """The (vault, signer, gate) sockets the supervisor binds for ``_NAME``."""
    per_container = runtime_dir / "run" / _NAME
    return (
        per_container / "vault" / "vault.sock",
        per_container / "signer" / "ssh-agent.sock",
        per_container / "gate" / "gate-server.sock",
    )


def _services(endpoints: tuple[ServiceEndpoint, ...]) -> set[str]:
    """The service names in *endpoints* — what a status checked or missed."""
    return {endpoint.service for endpoint in endpoints}


def _listen_tcp() -> tuple[socket.socket, int]:
    """Listen on a kernel-assigned loopback port; return the handle and the port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    return sock, sock.getsockname()[1]


def _bind(path: Path) -> socket.socket:
    """Bind a real AF_UNIX socket at *path* (kept alive by the returned handle)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(str(path))
    return sock


@pytest.fixture
def short_rt() -> Iterator[Path]:
    """A short runtime dir for the tests that bind real sockets.

    The supervisor binds sockets at ``<rt>/run/<name>/…/vault.sock``.  Under
    pytest's deep ``tmp_path`` that overruns AF_UNIX's 108-byte ``sun_path``
    in the container filesystem — the same overflow production avoids by
    keeping the runtime dir short (``/run/user/<uid>/…``).  Mirror that with
    a short unique dir under ``MOCK_BASE``; the sidecar/state stay on
    ``tmp_path``.
    """
    MOCK_BASE.mkdir(parents=True, exist_ok=True)
    rt = Path(tempfile.mkdtemp(dir=MOCK_BASE, prefix="sv"))
    try:
        yield rt
    finally:
        shutil.rmtree(rt, ignore_errors=True)


class TestVerifySupervision:
    def test_no_sidecar_is_skipped(self, tmp_path: Path) -> None:
        """No sidecar on disk ⇒ nothing to verify, no polling, healthy-ok."""
        status = verify_supervision(_cfg(tmp_path), _NAME, timeout=_FAST)
        assert status.skipped and status.ok
        assert status.checked == () and status.missing == ()

    def test_sockets_present_are_ok(self, tmp_path: Path, short_rt: Path) -> None:
        rt = short_rt
        _write_sidecar(tmp_path, rt)
        vault, signer, _gate = _socket_paths(rt)
        bound = [_bind(vault), _bind(signer)]
        try:
            status = verify_supervision(_cfg(tmp_path), _NAME)
        finally:
            for sock in bound:
                sock.close()
        assert status.ok and not status.skipped
        assert _services(status.checked) == {"vault", "signer"}

    def test_missing_vault_socket_is_flagged(self, tmp_path: Path) -> None:
        _write_sidecar(tmp_path, tmp_path / "rt")
        status = verify_supervision(_cfg(tmp_path), _NAME, timeout=_FAST)
        assert not status.ok
        assert _services(status.missing) == {"vault", "signer"}

    def test_missing_signer_socket_is_flagged(self, tmp_path: Path, short_rt: Path) -> None:
        """The signer is a service in its own right — a dead one costs the task its git keys."""
        rt = short_rt
        _write_sidecar(tmp_path, rt)
        vault, _signer, _gate = _socket_paths(rt)
        keepalive = _bind(vault)
        try:
            status = verify_supervision(_cfg(tmp_path), _NAME, timeout=_FAST)
        finally:
            keepalive.close()
        assert _services(status.missing) == {"signer"}

    def test_gate_socket_polled_only_when_wired(self, tmp_path: Path, short_rt: Path) -> None:
        rt = short_rt
        _write_sidecar(tmp_path, rt, gate=True)
        vault, signer, gate = _socket_paths(rt)
        bound = [_bind(vault), _bind(signer), _bind(gate)]
        try:
            status = verify_supervision(_cfg(tmp_path), _NAME)
        finally:
            for sock in bound:
                sock.close()
        assert status.ok
        assert _services(status.checked) == {"vault", "signer", "gate"}

    def test_missing_gate_socket_is_flagged(self, tmp_path: Path, short_rt: Path) -> None:
        """Vault and signer up but the wired gate never bound ⇒ only the gate is reported."""
        rt = short_rt
        _write_sidecar(tmp_path, rt, gate=True)
        vault, signer, _gate = _socket_paths(rt)
        bound = [_bind(vault), _bind(signer)]
        try:
            status = verify_supervision(_cfg(tmp_path), _NAME, timeout=_FAST)
        finally:
            for sock in bound:
                sock.close()
        assert _services(status.missing) == {"gate"}


class TestVerifySupervisionOverTcp:
    """The transport that binds ports, not sockets — thor's mode, and the silent one."""

    def test_listening_ports_are_ok(self, tmp_path: Path) -> None:
        vault_sock, vault_port = _listen_tcp()
        signer_sock, signer_port = _listen_tcp()
        _write_sidecar(
            tmp_path,
            tmp_path / "rt",
            ipc_mode="tcp",
            ports={"tcp_port": vault_port, "ssh_signer_port": signer_port},
        )
        try:
            status = verify_supervision(_cfg(tmp_path), _NAME)
        finally:
            vault_sock.close()
            signer_sock.close()
        assert status.ok and not status.skipped
        assert _services(status.checked) == {"vault", "signer"}

    def test_a_port_nothing_listens_on_is_flagged(self, tmp_path: Path) -> None:
        """The failure this check exists for: the child died, the port stayed free."""
        vault_sock, vault_port = _listen_tcp()
        dead_sock, dead_port = _listen_tcp()
        dead_sock.close()  # the signer child that never came up
        _write_sidecar(
            tmp_path,
            tmp_path / "rt",
            ipc_mode="tcp",
            ports={"tcp_port": vault_port, "ssh_signer_port": dead_port},
        )
        try:
            status = verify_supervision(_cfg(tmp_path), _NAME, timeout=_FAST)
        finally:
            vault_sock.close()
        assert not status.ok
        assert _services(status.missing) == {"signer"}
        assert str(dead_port) in status.warning()

    def test_sidecar_without_ports_is_skipped(self, tmp_path: Path) -> None:
        """A TCP sidecar that records no port states no expectation to check."""
        _write_sidecar(tmp_path, tmp_path / "rt", ipc_mode="tcp")
        status = verify_supervision(_cfg(tmp_path), _NAME, timeout=_FAST)
        assert status.skipped and status.ok

    def test_unreadable_tcp_table_is_skipped_not_failed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A host that will not say which ports listen gets no verdict, not a false alarm."""
        monkeypatch.setattr(
            "terok_sandbox.supervision._PROC_NET_TCP", (tmp_path / "no-such-table",)
        )
        _write_sidecar(
            tmp_path,
            tmp_path / "rt",
            ipc_mode="tcp",
            ports={"tcp_port": 1, "ssh_signer_port": 2},
        )
        status = verify_supervision(_cfg(tmp_path), _NAME, timeout=_FAST)
        assert status.skipped and status.ok


class TestListeningPorts:
    """Reading the kernel's TCP tables — the port alone is not the endpoint."""

    @staticmethod
    def _table(tmp_path: Path, name: str, rows: list[tuple[str, str]]) -> Path:
        """Write a ``/proc/net/tcp``-shaped table of ``(local_address, state)`` rows."""
        header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt\n"
        lines = [
            f"   {n}: {address} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000"
            for n, (address, state) in enumerate(rows)
        ]
        table = tmp_path / name
        table.write_text(header + "\n".join(lines) + "\n")
        return table

    def _ports(
        self, monkeypatch: pytest.MonkeyPatch, tables: tuple[Path, ...]
    ) -> frozenset[int] | None:
        """Read *tables* through the module's own reader."""
        monkeypatch.setattr("terok_sandbox.supervision._PROC_NET_TCP", tables)
        return supervision._listening_ports()

    def test_loopback_listener_counts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        table = self._table(tmp_path, "tcp", [("0100007F:B6C1", "0A")])
        assert self._ports(monkeypatch, (table,)) == frozenset({46785})

    def test_a_listener_on_another_interface_does_not_count(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The container dials the host loopback. Another interface is another endpoint."""
        table = self._table(tmp_path, "tcp", [("0500A8C0:B6C1", "0A")])
        assert self._ports(monkeypatch, (table,)) == frozenset()

    def test_a_wildcard_listener_counts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """It is not how the supervisor binds, but it does answer on the loopback."""
        table = self._table(tmp_path, "tcp", [("00000000:B6C1", "0A")])
        assert self._ports(monkeypatch, (table,)) == frozenset({46785})

    def test_a_connection_is_not_a_listener(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """State 01 is ESTABLISHED. Only 0A binds the port."""
        table = self._table(tmp_path, "tcp", [("0100007F:B6C1", "01")])
        assert self._ports(monkeypatch, (table,)) == frozenset()

    def test_ipv6_loopback_and_mapped_addresses_count(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        table = self._table(
            tmp_path,
            "tcp6",
            [
                ("00000000000000000000000001000000:B6C1", "0A"),
                ("0000000000000000FFFF00000100007F:1F90", "0A"),
                ("0000000000000000FFFF00000500A8C0:1F91", "0A"),
            ],
        )
        assert self._ports(monkeypatch, (table,)) == frozenset({46785, 8080})

    def test_a_malformed_row_costs_only_itself(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """This reader never raises — a start must not fail on a row it cannot parse."""
        table = self._table(
            tmp_path,
            "tcp",
            [
                ("zzzzzzzz:B6C1", "0A"),  # not hexadecimal
                ("010000:B6C2", "0A"),  # too short to be an address
                ("0100007F:zzzz", "0A"),  # not a port
                ("0100007F:1F90", "0A"),  # the good row
            ],
        )
        assert self._ports(monkeypatch, (table,)) == frozenset({8080})

    def test_no_readable_table_is_an_unknown(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``None``, not an empty set: the difference is a false alarm on every start."""
        assert self._ports(monkeypatch, (tmp_path / "absent",)) is None


class TestSupervisionStatus:
    def test_warning_names_container_service_and_diary(self, tmp_path: Path) -> None:
        missing = ServiceEndpoint("vault", socket=tmp_path / "run" / _NAME / "vault" / "vault.sock")
        hook_log = tmp_path / "logs" / "hook.log"
        status = SupervisionStatus(_NAME, (missing,), (missing,), hook_log)
        text = status.warning()
        assert _NAME in text
        assert "vault" in text
        assert str(missing.socket) in text
        assert str(hook_log) in text

    def test_warn_unsupervised_is_silent_when_healthy(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        healthy = SupervisionStatus(_NAME, (), (), tmp_path / "logs" / "hook.log")
        warn_unsupervised(healthy)
        assert capsys.readouterr().err == ""

    def test_warn_unsupervised_shouts_on_failure(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        missing = ServiceEndpoint("signer", port=46785)
        warn_unsupervised(SupervisionStatus(_NAME, (missing,), (missing,), tmp_path / "hook.log"))
        err = capsys.readouterr().err
        assert "never bound" in err
        assert "signer (127.0.0.1:46785)" in err


class TestOutdatedContainer:
    """A container's frozen protocol stamp vs the layout this sandbox binds."""

    def test_current_stamp_is_silent(self) -> None:
        """A container created against today's contract needs no warning."""
        env = {"TEROK_CONTAINER_PROTOCOL": str(MIN_RUNTIME_PROTOCOL)}
        assert outdated_container_warning(_NAME, env) is None

    def test_older_stamp_names_both_numbers_and_the_remedy(self) -> None:
        """The common case: a container carried over from the previous release."""
        warning = outdated_container_warning(_NAME, {"TEROK_CONTAINER_PROTOCOL": "2"})
        assert warning is not None
        assert _NAME in warning
        assert str(MIN_RUNTIME_PROTOCOL) in warning
        assert "recreate the container" in warning

    def test_unstamped_container_is_silent(self) -> None:
        """Sidecar tool containers carry no stamp; an absent one says nothing about age."""
        assert outdated_container_warning(_NAME, {}) is None

    def test_unparseable_stamp_is_silent(self) -> None:
        """An unreadable stamp is no more evidence of age than a missing one."""
        assert outdated_container_warning(_NAME, {"TEROK_CONTAINER_PROTOCOL": "v2"}) is None

    def test_newer_stamp_is_silent(self) -> None:
        """A container from a newer host is not this check's business."""
        env = {"TEROK_CONTAINER_PROTOCOL": str(MIN_RUNTIME_PROTOCOL + 1)}
        assert outdated_container_warning(_NAME, env) is None
