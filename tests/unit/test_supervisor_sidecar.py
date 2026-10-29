# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for [`load_sidecar`][terok_sandbox.supervisor.main.load_sidecar].

The supervisor's first action is to parse the per-container sidecar
JSON at the path the OCI hook pinned via the ``terok.sandbox.sidecar``
annotation.  No XDG guessing — the function opens the named file
directly and either returns a [`SidecarConfig`][terok_sandbox.supervisor.main.SidecarConfig]
or soft-fails to ``None`` on every error path.

The write side is pinned here too: the one writer, and the one edit a
sidecar takes after creation — its ``clearance`` field, refreshed before
a restart.
"""

from __future__ import annotations

import dataclasses
import errno
import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor, wait
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from terok_sandbox.supervisor import sidecar as sidecar_module
from terok_sandbox.supervisor.sidecar import (
    SidecarConfig,
    load_sidecar,
    refresh_clearance,
    remove_sidecar,
    store_sidecar,
)
from tests.constants import FAKE_SERVICE_PORTS

if TYPE_CHECKING:
    from collections.abc import Callable
    from concurrent.futures import Future

    from terok_sandbox import ClearanceMode

#: Seconds a concurrent change gets to land in a window the lock keeps shut.
#: An unlink or a rename takes microseconds, so this is ample for a change
#: nothing holds back — and a held one never lands, however long it waits.
_RACE_GRACE_S = 0.5

#: Ceiling for a test that could block — on a FIFO, on a lock — so a
#: regression fails the test rather than stalling the job until CI's limit.
_HANG_GUARD_S = 10

#: One second in nanoseconds: an mtime shift no filesystem's timestamp
#: granularity can swallow.
_ONE_SECOND_NS = 1_000_000_000


def _write_sidecar(tmp_path: Path, payload: dict[str, object]) -> Path:
    """Drop a sidecar JSON under a sidecar-shaped layout for the test."""
    target = tmp_path / "sidecar" / "demo.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload))
    return target


class TestLoadSidecar:
    """Schema + I/O contract for the supervisor's sidecar reader."""

    def test_missing_file_returns_none(self, tmp_path: Path) -> None:
        """A path that doesn't exist soft-fails to None."""
        assert load_sidecar(tmp_path / "missing.json") is None

    def test_unix_sidecar_is_loaded(self, tmp_path: Path) -> None:
        """A socket-mode sidecar parses; vault/ssh socket paths are NOT
        carried (the supervisor derives them from container_name +
        runtime_dir via ``SupervisorPaths.for_container``)."""
        payload = {
            "container_name": "demo",
            "ipc_mode": "socket",
            "db_path": "/home/dev/.terok/vault.db",
            "runtime_dir": "/run/user/1000/terok/sandbox",
            "scope_id": "default",
        }
        path = _write_sidecar(tmp_path, payload)

        cfg = load_sidecar(path)
        assert isinstance(cfg, SidecarConfig)
        assert cfg.container_name == "demo"
        assert cfg.ipc_mode == "socket"
        assert cfg.scope_id == "default"
        assert cfg.tcp_port is None
        assert cfg.ssh_signer_port is None

    def test_credential_policy_round_trips(self, tmp_path: Path) -> None:
        """Credential policy is captured before the child installs Landlock."""
        payload = {
            "container_name": "demo",
            "ipc_mode": "socket",
            "db_path": "/home/dev/.terok/vault/credentials.db",
            "runtime_dir": "/run/user/1000/terok/sandbox",
            "routes_path": "/home/dev/.terok/vault/routes.json",
            "vault_systemd_creds_file": "/home/dev/.terok/vault/vault.passphrase.cred",
            "credentials_use_keyring": False,
            "credentials_passphrase_command": "pass show terok/vault",
        }
        cfg = load_sidecar(_write_sidecar(tmp_path, payload))
        assert cfg is not None
        assert cfg.routes_path == Path(str(payload["routes_path"]))
        assert cfg.vault_systemd_creds_file == Path(str(payload["vault_systemd_creds_file"]))
        assert cfg.credentials_use_keyring is False
        assert cfg.credentials_passphrase_command == "pass show terok/vault"

    def test_security_booleans_reject_strings(self, tmp_path: Path) -> None:
        """JSON strings cannot truthily opt into debugger or keyring access."""
        base = {
            "container_name": "demo",
            "ipc_mode": "socket",
            "db_path": "/home/dev/.terok/vault.db",
            "runtime_dir": "/run/user/1000/terok/sandbox",
        }
        for field in ("allow_debugger", "credentials_use_keyring"):
            assert load_sidecar(_write_sidecar(tmp_path, {**base, field: "false"})) is None

    def test_invalid_field_logs_do_not_expose_values(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Schema diagnostics report types without serializing untrusted values."""
        marker = "do-not-log-this-value"
        base = {
            "container_name": "demo",
            "ipc_mode": "socket",
            "db_path": "/home/dev/.terok/vault.db",
            "runtime_dir": "/run/user/1000/terok/sandbox",
        }

        with caplog.at_level("ERROR"):
            for field in ("allow_debugger", "credentials_passphrase_command"):
                assert (
                    load_sidecar(_write_sidecar(tmp_path, {**base, field: {"private": marker}}))
                    is None
                )

        assert marker not in caplog.text
        assert caplog.text.count("got dict") == 2

    def test_null_container_name_is_rejected(self, tmp_path: Path) -> None:
        """A JSON ``null`` container_name is missing, not the literal ``"None"``."""
        path = _write_sidecar(
            tmp_path,
            {
                "container_name": None,
                "ipc_mode": "socket",
                "db_path": "/home/dev/.terok/vault.db",
                "runtime_dir": "/run/user/1000/terok/sandbox",
            },
        )
        assert load_sidecar(path) is None

    def test_allow_debugger_flag_parsed(self, tmp_path: Path) -> None:
        """The debug-mode opt-in round-trips; absent means fully hardened."""
        base = {
            "container_name": "demo",
            "ipc_mode": "socket",
            "db_path": "/home/dev/.terok/vault.db",
            "runtime_dir": "/run/user/1000/terok/sandbox",
        }
        default = load_sidecar(_write_sidecar(tmp_path, base))
        assert default is not None
        assert default.allow_debugger is False

        opted_in = load_sidecar(_write_sidecar(tmp_path, {**base, "allow_debugger": True}))
        assert opted_in is not None
        assert opted_in.allow_debugger is True

    def test_null_ipc_mode_defaults_to_socket(self, tmp_path: Path) -> None:
        """A JSON ``null`` ipc_mode falls back to the default, not the literal ``"None"``."""
        path = _write_sidecar(
            tmp_path,
            {
                "container_name": "demo",
                "ipc_mode": None,
                "db_path": "/home/dev/.terok/vault.db",
                "runtime_dir": "/run/user/1000/terok/sandbox",
            },
        )
        cfg = load_sidecar(path)
        assert isinstance(cfg, SidecarConfig)
        assert cfg.ipc_mode == "socket"

    def test_tcp_mode_parses_port(self, tmp_path: Path) -> None:
        """TCP-mode sidecar carries per-container ``tcp_port`` +
        ``ssh_signer_port`` (allocated by the launch path via bind(0))."""
        payload = {
            "container_name": "demo-tcp",
            "ipc_mode": "tcp",
            "db_path": "/home/dev/.terok/vault.db",
            "runtime_dir": "/run/user/1000/terok/sandbox",
            "tcp_port": 54321,
            "ssh_signer_port": 54322,
        }
        path = _write_sidecar(tmp_path, payload)

        cfg = load_sidecar(path)
        assert cfg is not None
        assert cfg.ipc_mode == "tcp"
        assert cfg.tcp_port == 54321
        assert cfg.ssh_signer_port == 54322

    def test_gate_fields_parsed(self, tmp_path: Path) -> None:
        """``gate_base_path`` / ``gate_token`` / ``gate_port`` round-trip."""
        payload = {
            "container_name": "demo-gate",
            "ipc_mode": "tcp",
            "db_path": "/home/dev/.terok/vault.db",
            "runtime_dir": "/run/user/1000/terok/sandbox",
            "project_id": "myproj",
            "gate_base_path": "/home/dev/.terok/gate",
            "gate_token": "terok-g-abc",
            "gate_port": 54323,
        }
        path = _write_sidecar(tmp_path, payload)

        cfg = load_sidecar(path)
        assert cfg is not None
        assert cfg.gate_base_path == Path("/home/dev/.terok/gate")
        assert cfg.gate_token == "terok-g-abc"
        assert cfg.gate_port == 54323
        assert cfg.project_id == "myproj"

    def test_gate_fields_absent_default_to_none(self, tmp_path: Path) -> None:
        """A sidecar without gate fields parses with gate disabled."""
        payload = {
            "container_name": "demo",
            "ipc_mode": "socket",
            "db_path": "/home/dev/.terok/vault.db",
            "runtime_dir": "/run/user/1000/terok/sandbox",
        }
        cfg = load_sidecar(_write_sidecar(tmp_path, payload))
        assert cfg is not None
        assert cfg.gate_base_path is None
        assert cfg.gate_token is None
        assert cfg.gate_port is None

    def test_relative_gate_base_path_returns_none(self, tmp_path: Path) -> None:
        """A relative ``gate_base_path`` soft-fails like the other paths."""
        payload = {
            "container_name": "demo",
            "ipc_mode": "socket",
            "db_path": "/home/dev/.terok/vault.db",
            "runtime_dir": "/run/user/1000/terok/sandbox",
            "gate_base_path": "relative/gate",
            "gate_token": "terok-g-abc",
        }
        assert load_sidecar(_write_sidecar(tmp_path, payload)) is None

    def test_malformed_json_returns_none(self, tmp_path: Path) -> None:
        """A non-JSON file degrades to ``None`` rather than raising."""
        bad = tmp_path / "sidecar" / "demo.json"
        bad.parent.mkdir(parents=True, exist_ok=True)
        bad.write_text("{ this is not json")
        assert load_sidecar(bad) is None

    def test_non_object_root_returns_none(self, tmp_path: Path) -> None:
        """JSON arrays / scalars at root degrade to ``None``."""
        bad = tmp_path / "sidecar" / "demo.json"
        bad.parent.mkdir(parents=True, exist_ok=True)
        bad.write_text("[]")
        assert load_sidecar(bad) is None

    def test_missing_required_field_returns_none(self, tmp_path: Path) -> None:
        """Missing ``db_path`` triggers the soft-fail KeyError path."""
        path = _write_sidecar(tmp_path, {"ipc_mode": "socket"})
        assert load_sidecar(path) is None

    def test_unsafe_container_name_rejected(self, tmp_path: Path) -> None:
        """A ``container_name`` that escapes its runtime subdir is refused.

        The name is interpolated into ``runtime_dir/run/<name>`` which the
        supervisor mkdir's / chmod's / rmtree's, so a value with a path
        separator or ``..`` must soft-fail rather than redirect those
        filesystem operations.
        """
        for bad_name in ("../evil", "a/b", "/abs", "..", "."):
            payload = {
                "container_name": bad_name,
                "ipc_mode": "socket",
                "db_path": "/home/dev/.terok/vault.db",
                "runtime_dir": "/run/user/1000/terok/sandbox",
            }
            path = _write_sidecar(tmp_path, payload)
            assert load_sidecar(path) is None, bad_name

    def test_invalid_ipc_mode_rejected(self, tmp_path: Path) -> None:
        """``ipc_mode`` outside {socket, tcp} soft-fails to ``None``.

        The supervisor branches on this value to pick the bind transport;
        an unknown mode would fall through to the socket path silently, so
        the parser refuses it up front.
        """
        payload = {
            "container_name": "demo",
            "ipc_mode": "carrier-pigeon",
            "db_path": "/home/dev/.terok/vault.db",
            "runtime_dir": "/run/user/1000/terok/sandbox",
        }
        assert load_sidecar(_write_sidecar(tmp_path, payload)) is None

    def test_missing_ipc_mode_defaults_to_socket(self, tmp_path: Path) -> None:
        """An absent ``ipc_mode`` defaults to socket (the common case)."""
        payload = {
            "container_name": "demo",
            "db_path": "/home/dev/.terok/vault.db",
            "runtime_dir": "/run/user/1000/terok/sandbox",
        }
        cfg = load_sidecar(_write_sidecar(tmp_path, payload))
        assert cfg is not None
        assert cfg.ipc_mode == "socket"

    def test_relative_db_path_returns_none(self, tmp_path: Path) -> None:
        """A relative ``db_path`` soft-fails — the supervisor binds/rmtrees
        against it and must not resolve against the hook's cwd."""
        payload = {
            "container_name": "demo",
            "ipc_mode": "socket",
            "db_path": "relative/vault.db",
            "runtime_dir": "/run/user/1000/terok/sandbox",
        }
        assert load_sidecar(_write_sidecar(tmp_path, payload)) is None

    def test_relative_runtime_dir_returns_none(self, tmp_path: Path) -> None:
        """A relative ``runtime_dir`` soft-fails for the same reason."""
        payload = {
            "container_name": "demo",
            "ipc_mode": "socket",
            "db_path": "/home/dev/.terok/vault.db",
            "runtime_dir": "run/sandbox",
        }
        assert load_sidecar(_write_sidecar(tmp_path, payload)) is None

    def test_absolute_dossier_path_round_trips(self, tmp_path: Path) -> None:
        """An absolute ``dossier_path`` parses through to the config."""
        payload = {
            "container_name": "demo",
            "ipc_mode": "socket",
            "db_path": "/home/dev/.terok/vault.db",
            "runtime_dir": "/run/user/1000/terok/sandbox",
            "dossier_path": "/home/dev/.terok/dossier.json",
        }
        cfg = load_sidecar(_write_sidecar(tmp_path, payload))
        assert cfg is not None
        assert cfg.dossier_path == Path("/home/dev/.terok/dossier.json")

    def test_relative_dossier_path_returns_none(self, tmp_path: Path) -> None:
        """A relative ``dossier_path`` soft-fails like the other paths."""
        payload = {
            "container_name": "demo",
            "ipc_mode": "socket",
            "db_path": "/home/dev/.terok/vault.db",
            "runtime_dir": "/run/user/1000/terok/sandbox",
            "dossier_path": "relative/dossier.json",
        }
        assert load_sidecar(_write_sidecar(tmp_path, payload)) is None

    def test_non_integer_port_returns_none(self, tmp_path: Path) -> None:
        """A non-integer ``tcp_port`` trips the schema-error soft-fail path.

        ``int(raw["tcp_port"])`` raises ``ValueError`` for a non-numeric
        string; ``load_sidecar`` must collapse that to ``None`` rather than
        propagate (the supervisor surfaces ``None`` as exit-code 2)."""
        payload = {
            "container_name": "demo",
            "ipc_mode": "tcp",
            "db_path": "/home/dev/.terok/vault.db",
            "runtime_dir": "/run/user/1000/terok/sandbox",
            "tcp_port": "not-a-port",
        }
        assert load_sidecar(_write_sidecar(tmp_path, payload)) is None


class TestClearanceField:
    """``clearance`` is parsed leniently: no value of it can cost the supervisor.

    Every other field rejects a bad value and with it the whole sidecar — the
    container then runs with no vault, gate or signer.  A clearance value is
    not worth that, so an unreadable one reads as ``prompt``: audible, the
    safe direction for a setting about who is asked.
    """

    @staticmethod
    def _base(tmp_path: Path) -> dict[str, object]:
        """A minimal socket-mode sidecar payload with no ``clearance`` key."""
        return {
            "container_name": "demo",
            "ipc_mode": "socket",
            "db_path": str(tmp_path / "vault.db"),
            "runtime_dir": str(tmp_path / "rt" / "sandbox"),
        }

    def test_absent_key_prompts(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """A sidecar written before the setting existed prompts, as it always did — quietly."""
        with caplog.at_level("WARNING"):
            cfg = load_sidecar(_write_sidecar(tmp_path, self._base(tmp_path)))
        assert cfg is not None
        assert cfg.clearance == "prompt"
        assert "clearance" not in caplog.text

    def test_null_prompts(self, tmp_path: Path) -> None:
        """A JSON ``null`` is an unset value, not the string ``"None"``."""
        cfg = load_sidecar(_write_sidecar(tmp_path, {**self._base(tmp_path), "clearance": None}))
        assert cfg is not None
        assert cfg.clearance == "prompt"

    @pytest.mark.parametrize("value", ["prompt", "mute", "off"])
    def test_known_values_parse(self, tmp_path: Path, value: str) -> None:
        cfg = load_sidecar(_write_sidecar(tmp_path, {**self._base(tmp_path), "clearance": value}))
        assert cfg is not None
        assert cfg.clearance == value

    @pytest.mark.parametrize(
        "value",
        ["do-not-log-this-value", "OFF", True, 0, ["off"], {"private": "do-not-log-this-value"}],
        ids=repr,
    )
    def test_unknown_value_prompts_and_keeps_the_supervisor(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture, value: object
    ) -> None:
        """A bad value is a warning, never ``_BadSidecar`` — and is reported by type, not echoed."""
        with caplog.at_level("WARNING"):
            cfg = load_sidecar(
                _write_sidecar(tmp_path, {**self._base(tmp_path), "clearance": value})
            )
        assert cfg is not None
        assert cfg.clearance == "prompt"
        assert "sidecar clearance must be one of prompt, mute, off" in caplog.text
        assert "do-not-log-this-value" not in caplog.text

    def test_mode_vocabulary_matches_the_schema(self) -> None:
        """The stdlib-only copy agrees with ``ClearanceMode``, which this module cannot import."""
        from typing import get_args

        from terok_sandbox.config_schema import ClearanceMode
        from terok_sandbox.supervisor.sidecar import _CLEARANCE_MODES

        assert get_args(ClearanceMode) == _CLEARANCE_MODES


_MODES = ("prompt", "mute", "off")


def _launch_payload(tmp_path: Path) -> dict[str, object]:
    """A TCP-mode sidecar as a launch writes it — every JSON type the file carries.

    Strings, ints, booleans and a null, so "every other field survives"
    is checked across each type the round trip could disturb.
    """
    vault_port, signer_port, gate_port = FAKE_SERVICE_PORTS
    return {
        "container_name": "demo",
        "ipc_mode": "tcp",
        "clearance": "prompt",
        "db_path": str(tmp_path / "vault" / "credentials.db"),
        "routes_path": str(tmp_path / "vault" / "routes.json"),
        "vault_systemd_creds_file": str(tmp_path / "vault" / "vault.passphrase.cred"),
        "credentials_use_keyring": False,
        "credentials_passphrase_command": None,
        "scope_id": "proj",
        "project_id": "proj",
        "task_id": "7",
        "runtime_dir": str(tmp_path / "rt" / "sandbox"),
        "tcp_port": vault_port,
        "ssh_signer_port": signer_port,
        "dossier_path": str(tmp_path / "dossier.json"),
        "gate_base_path": str(tmp_path / "gate"),
        "gate_token": "terok-g-refresh",
        "gate_port": gate_port,
        "allow_debugger": True,
    }


def _entries(directory: Path) -> list[str]:
    """Names in *directory* bar its sidecar lock — a leftover temp file would show up here.

    The lock file is the one permanent addition every change makes to a
    sidecar directory; anything else beside the sidecars is litter.
    """
    return sorted(
        entry.name for entry in directory.iterdir() if entry.name != sidecar_module._LOCK_NAME
    )


class TestRefreshClearance:
    """``refresh_clearance`` edits one field of an existing sidecar, under the writer's rules.

    A restart calls it (through ``Sandbox.clearance_refresh``) so the next
    start honours the current ``services.clearance``.  The file holds the
    gate token and the ports the container's immutable env was created
    with, so everything but that one field must come back unchanged, and
    the file is trusted only the way the OCI hook trusts it.
    """

    @pytest.mark.parametrize("mode", _MODES)
    def test_rewrites_only_the_clearance_field(self, tmp_path: Path, mode: ClearanceMode) -> None:
        """Same keys, same order, same values — bar the one field asked for."""
        original = _launch_payload(tmp_path)
        path = _write_sidecar(tmp_path, original)
        refresh_clearance(path, mode)
        rewritten = json.loads(path.read_text())
        assert rewritten == {**original, "clearance": mode}
        assert list(rewritten) == list(original)

    def test_sidecar_from_before_the_setting_gains_the_key(self, tmp_path: Path) -> None:
        """A sidecar written before ``clearance`` existed is completed, not refused."""
        original = _launch_payload(tmp_path)
        del original["clearance"]
        path = _write_sidecar(tmp_path, original)
        refresh_clearance(path, "mute")
        assert json.loads(path.read_text()) == {**original, "clearance": "mute"}

    @pytest.mark.parametrize("mode", _MODES)
    def test_round_trips_through_the_parser(self, tmp_path: Path, mode: ClearanceMode) -> None:
        """What the supervisor parses afterwards differs in ``clearance`` alone."""
        path = _write_sidecar(tmp_path, _launch_payload(tmp_path))
        before = load_sidecar(path)
        assert before is not None
        refresh_clearance(path, mode)
        assert load_sidecar(path) == dataclasses.replace(before, clearance=mode)

    def test_missing_sidecar_is_refused_and_never_created(self, tmp_path: Path) -> None:
        """No sidecar means no supervisor to configure; writing one would invent wiring."""
        path = tmp_path / "sidecar" / "demo.json"
        with pytest.raises(FileNotFoundError, match="no sidecar to refresh"):
            refresh_clearance(path, "mute")
        assert not path.parent.exists()

    def test_symlinked_sidecar_is_refused(self, tmp_path: Path) -> None:
        """``O_NOFOLLOW``: neither the link nor the file it points at is rewritten."""
        victim = tmp_path / "victim.json"
        victim.write_text(json.dumps(_launch_payload(tmp_path)))
        before = victim.read_bytes()
        path = tmp_path / "sidecar" / "demo.json"
        path.parent.mkdir()
        path.symlink_to(victim)
        with pytest.raises(OSError, match="symlink") as caught:
            refresh_clearance(path, "off")
        assert caught.value.errno == errno.ELOOP
        assert path.is_symlink()
        assert victim.read_bytes() == before
        assert _entries(path.parent) == ["demo.json"]

    @pytest.mark.timeout(_HANG_GUARD_S)
    def test_fifo_is_refused_rather_than_waited_on(self, tmp_path: Path) -> None:
        """``O_NONBLOCK`` lets a planted FIFO fail the regular-file check instead of hanging.

        Without the flag the open would wait for a writer that never comes, so
        the timeout turns that regression into a failure, not a stalled job.
        """
        path = tmp_path / "sidecar" / "demo.json"
        path.parent.mkdir()
        os.mkfifo(path)
        with pytest.raises(OSError, match="not a regular file"):
            refresh_clearance(path, "off")
        assert stat.S_ISFIFO(path.lstat().st_mode)

    def test_sidecar_owned_by_another_user_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The OCI hook's ownership rule: only a sidecar this user owns is trusted, or edited."""
        path = _write_sidecar(tmp_path, _launch_payload(tmp_path))
        before = path.read_bytes()
        owner = path.stat().st_uid
        monkeypatch.setattr(os, "geteuid", lambda: owner + 1)
        with pytest.raises(PermissionError, match=f"owned by uid {owner}"):
            refresh_clearance(path, "off")
        assert path.read_bytes() == before

    def test_rewrite_is_0600_over_a_looser_file(self, tmp_path: Path) -> None:
        """The gate token never sits world-readable: a 0644 leftover comes back 0600."""
        path = _write_sidecar(tmp_path, _launch_payload(tmp_path))
        path.chmod(0o644)
        refresh_clearance(path, "mute")
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert _entries(path.parent) == ["demo.json"]

    @pytest.mark.parametrize("value", ["OFF", "silent", "", None, True, ["off"]], ids=repr)
    def test_unknown_mode_is_refused_before_anything_is_touched(
        self, tmp_path: Path, value: object
    ) -> None:
        """Strict where the parser is lenient: nothing outside the vocabulary is written."""
        path = _write_sidecar(tmp_path, _launch_payload(tmp_path))
        before = path.read_bytes()
        with pytest.raises(ValueError, match="unknown clearance mode"):
            refresh_clearance(path, value)  # type: ignore[arg-type]
        assert path.read_bytes() == before

    @pytest.mark.parametrize(
        "content",
        ["not json", "[1, 2]", '"prompt"', "\udcff"],
        ids=["text", "array", "str", "utf8"],
    )
    def test_unreadable_sidecar_is_refused(self, tmp_path: Path, content: str) -> None:
        """Only a JSON object can have one field rewritten; anything else is left as it is."""
        path = tmp_path / "sidecar" / "demo.json"
        path.parent.mkdir()
        path.write_bytes(content.encode("utf-8", "surrogateescape"))
        before = path.read_bytes()
        with pytest.raises(ValueError, match="sidecar is not"):
            refresh_clearance(path, "off")
        assert path.read_bytes() == before

    def test_sidecar_directory_that_is_a_file_is_refused(self, tmp_path: Path) -> None:
        """A path through a regular file fails as such, and nothing is made in its place."""
        not_a_directory = tmp_path / "sidecar"
        not_a_directory.write_text("x")
        with pytest.raises(NotADirectoryError):
            refresh_clearance(not_a_directory / "demo.json", "off")
        assert not_a_directory.is_file()
        assert not_a_directory.read_text() == "x"

    def test_other_open_failures_surface_as_they_are(self, tmp_path: Path) -> None:
        """Only a missing sidecar and a symlink get refusals of their own.

        Any other failed open is raised as the open raised it, never passed off
        as a missing sidecar.  ``EACCES`` is the everyday case, but root opens
        anything; a name one byte past the filesystem's limit fails the open
        for every user, root included.
        """
        directory = tmp_path / "sidecar"
        directory.mkdir()
        too_long = "x" * (os.pathconf(directory, "PC_NAME_MAX") + 1)
        with pytest.raises(OSError) as caught:
            refresh_clearance(directory / too_long, "off")
        assert caught.value.errno == errno.ENAMETOOLONG
        assert _entries(directory) == []


def _sidecar_target(tmp_path: Path) -> Path:
    """``<tmp>/sidecar/demo.json`` with its directory made — a dir nothing else writes to."""
    target = tmp_path / "sidecar" / "demo.json"
    target.parent.mkdir()
    return target


class TestStoreSidecar:
    """``store_sidecar`` — the one writer: 0600, atomic, never through a symlink."""

    def test_creates_a_0600_file_and_no_temp_file(self, tmp_path: Path) -> None:
        """Mode 0600 from the start, and only the target is left in the directory."""
        target = _sidecar_target(tmp_path)
        store_sidecar(target, _launch_payload(tmp_path))
        assert json.loads(target.read_text()) == _launch_payload(tmp_path)
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        assert _entries(target.parent) == ["demo.json"]

    def test_failed_write_keeps_the_previous_file(self, tmp_path: Path) -> None:
        """Atomic: a write that fails midway leaves the old sidecar whole."""
        target = _sidecar_target(tmp_path)
        store_sidecar(target, _launch_payload(tmp_path))
        before = target.read_bytes()
        edited = {**_launch_payload(tmp_path), "clearance": "off"}
        with (
            patch.object(sidecar_module.json, "dump", side_effect=OSError("no space left")),
            pytest.raises(OSError, match="no space left"),
        ):
            store_sidecar(target, edited)
        assert target.read_bytes() == before
        assert _entries(target.parent) == ["demo.json"]

    def test_symlink_at_target_is_refused_not_replaced(self, tmp_path: Path) -> None:
        """A planted link is neither followed nor swapped for a token-bearing file."""
        victim = tmp_path / "victim"
        victim.write_text("precious")
        target = _sidecar_target(tmp_path)
        target.symlink_to(victim)
        payload = _launch_payload(tmp_path)
        with pytest.raises(OSError, match="symlink"):
            store_sidecar(target, payload)
        assert target.is_symlink()
        assert victim.read_text() == "precious"
        assert _entries(target.parent) == ["demo.json"]

    def test_edit_never_recreates_a_removed_sidecar(self, tmp_path: Path) -> None:
        """With *replacing*, a sidecar removed mid-edit stays removed."""
        target = _sidecar_target(tmp_path)
        store_sidecar(target, _launch_payload(tmp_path))
        read = target.stat()
        target.unlink()
        payload = _launch_payload(tmp_path)
        with pytest.raises(FileNotFoundError, match="not recreating"):
            store_sidecar(target, payload, replacing=read)
        assert _entries(target.parent) == []

    def test_edit_never_overwrites_a_sidecar_replaced_meanwhile(self, tmp_path: Path) -> None:
        """A concurrent relaunch's fresh sidecar wins over an edit of the one it replaced."""
        target = _sidecar_target(tmp_path)
        stale = {**_launch_payload(tmp_path), "gate_token": "terok-g-stale"}
        store_sidecar(target, stale)
        read = target.stat()
        fresh = {**_launch_payload(tmp_path), "gate_token": "terok-g-fresh"}
        store_sidecar(target, fresh)
        with pytest.raises(OSError, match="replaced during the rewrite"):
            store_sidecar(target, {**stale, "clearance": "off"}, replacing=read)
        assert json.loads(target.read_text()) == fresh
        assert _entries(target.parent) == ["demo.json"]

    @pytest.mark.parametrize(
        ("rewritten_token", "mtime_shift_ns"),
        [("terok-g-a-longer-token", 0), ("terok-g-same", _ONE_SECOND_NS)],
        ids=["other-size", "same-size-later"],
    )
    def test_edit_never_overwrites_a_sidecar_rewritten_in_place(
        self, tmp_path: Path, rewritten_token: str, mtime_shift_ns: int
    ) -> None:
        """A writer that takes no lock and rewrites the same inode still gives itself away.

        An older writer truncated the file and wrote it where it stood: the
        inode is the one that was read, so its size — or, at the same size,
        its modification time — is what says the read is out of date.  Each
        case moves exactly one of the two.
        """
        target = _sidecar_target(tmp_path)
        store_sidecar(target, {**_launch_payload(tmp_path), "gate_token": "terok-g-read"})
        read = target.stat()
        rewritten = {**_launch_payload(tmp_path), "gate_token": rewritten_token}
        target.write_text(json.dumps(rewritten, indent=2))
        os.utime(target, ns=(read.st_atime_ns, read.st_mtime_ns + mtime_shift_ns))
        assert target.stat().st_ino == read.st_ino
        edited = {**_launch_payload(tmp_path), "clearance": "off"}
        with pytest.raises(OSError, match="changed in place"):
            store_sidecar(target, edited, replacing=read)
        assert json.loads(target.read_text()) == rewritten
        assert _entries(target.parent) == ["demo.json"]

    def test_symlink_at_the_lock_is_refused_not_followed(self, tmp_path: Path) -> None:
        """The lock file is opened ``O_NOFOLLOW`` too: a link planted there writes nothing."""
        victim = tmp_path / "victim"
        victim.write_text("precious")
        target = _sidecar_target(tmp_path)
        (target.parent / sidecar_module._LOCK_NAME).symlink_to(victim)
        payload = _launch_payload(tmp_path)
        with pytest.raises(OSError) as caught:
            store_sidecar(target, payload)
        assert caught.value.errno == errno.ELOOP
        assert victim.read_text() == "precious"
        assert not target.exists()


class TestRemoveSidecar:
    """``remove_sidecar`` — the one removal, under the lock the writes hold."""

    def test_removes_the_sidecar(self, tmp_path: Path) -> None:
        target = _sidecar_target(tmp_path)
        store_sidecar(target, _launch_payload(tmp_path))
        remove_sidecar(target)
        assert _entries(target.parent) == []

    def test_missing_sidecar_is_a_no_op(self, tmp_path: Path) -> None:
        target = _sidecar_target(tmp_path)
        remove_sidecar(target)
        assert _entries(target.parent) == []

    def test_missing_directory_is_a_no_op_and_stays_missing(self, tmp_path: Path) -> None:
        """No sidecar directory, no sidecar — and no directory or lock file made to find out."""
        target = tmp_path / "sidecar" / "demo.json"
        remove_sidecar(target)
        assert not target.parent.exists()


def _race_into_the_window(
    monkeypatch: pytest.MonkeyPatch,
    pool: ThreadPoolExecutor,
    change: Callable[[Path], None],
) -> list[Future[None]]:
    """Start *change* the moment an edit's check has passed, and give it time to land.

    Between ``_check_replaceable`` and the rename is the window the identity
    check alone cannot shut.  *change* runs on *pool*, as a teardown or a
    relaunch in another process would; were the lock not held across the
    window, it would land within the grace period, and the assertion here
    fails the edit.  Returns the list the started change is put on.
    """
    real_check = sidecar_module._check_replaceable
    racing: list[Future[None]] = []

    def check_then_race(target: Path, replacing: os.stat_result | None) -> None:
        real_check(target, replacing)
        if racing:
            return  # the racing change's own check, when it writes
        racing.append(pool.submit(change, target))
        landed, _ = wait(racing, timeout=_RACE_GRACE_S)
        assert not landed, "a concurrent change landed between the edit's check and its rename"

    monkeypatch.setattr(sidecar_module, "_check_replaceable", check_then_race)
    return racing


class TestOneChangeAtATime:
    """Creation, the clearance edit and removal take turns under the directory's lock.

    Each checks what sits at the path, then acts on it.  A concurrent change
    landing between an edit's check and its rename used to slip past the
    identity check: a torn-down sidecar came back, a relaunch's fresh one
    was overwritten with the old container's gate token.  Here a change is
    started in exactly that window, and must wait its turn instead.
    """

    @pytest.mark.timeout(_HANG_GUARD_S)
    def test_teardown_racing_an_edit_waits_and_the_sidecar_stays_removed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _write_sidecar(tmp_path, _launch_payload(tmp_path))
        with ThreadPoolExecutor(max_workers=1) as pool:
            racing = _race_into_the_window(monkeypatch, pool, remove_sidecar)
            refresh_clearance(path, "mute")
            [teardown] = racing
            teardown.result(timeout=_HANG_GUARD_S)
        assert _entries(path.parent) == []

    @pytest.mark.timeout(_HANG_GUARD_S)
    def test_relaunch_racing_an_edit_waits_and_its_sidecar_wins(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The fresh sidecar matches the new container's env; the edit's old token never lands on it."""
        path = _write_sidecar(tmp_path, {**_launch_payload(tmp_path), "gate_token": "terok-g-old"})
        fresh = {**_launch_payload(tmp_path), "gate_token": "terok-g-new"}
        with ThreadPoolExecutor(max_workers=1) as pool:
            racing = _race_into_the_window(
                monkeypatch, pool, lambda target: store_sidecar(target, fresh)
            )
            refresh_clearance(path, "mute")
            [relaunch] = racing
            relaunch.result(timeout=_HANG_GUARD_S)
        assert json.loads(path.read_text()) == fresh
        assert _entries(path.parent) == ["demo.json"]

    @pytest.mark.timeout(_HANG_GUARD_S)
    def test_edit_waits_for_a_teardown_under_way_and_then_refuses(self, tmp_path: Path) -> None:
        """The lock comes before the read: an edit started mid-teardown reads its outcome."""
        path = _write_sidecar(tmp_path, _launch_payload(tmp_path))
        with ThreadPoolExecutor(max_workers=1) as pool:
            with sidecar_module._sidecars_locked(path.parent):
                edit = pool.submit(refresh_clearance, path, "mute")
                started, _ = wait([edit], timeout=_RACE_GRACE_S)
                assert not started, "the edit ran while another change held the lock"
                path.unlink()
            with pytest.raises(FileNotFoundError, match="no sidecar to refresh"):
                edit.result(timeout=_HANG_GUARD_S)
        assert _entries(path.parent) == []
