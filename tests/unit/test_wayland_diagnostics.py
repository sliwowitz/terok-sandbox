# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Invalid desktop mounts and optional state failures remain visible without adding grants."""

import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from terok_sandbox import (
    ContainerInspection,
    LifecycleHooks,
    RunSpec,
    Sandbox,
    SandboxConfig,
    SocketSpec,
    WaylandMode,
    WaylandRecreationRequired,
)
from terok_sandbox.podman_args import CONTAINER_WAYLAND_SOCKET
from terok_sandbox.supervisor.sidecar import load_sidecar, record_wayland, store_sidecar
from terok_sandbox.wayland import WaylandSession


@pytest.fixture
def spec(tmp_path: Path) -> RunSpec:
    """A desktop request with no pre-existing mount grants."""
    return RunSpec(
        container_name="desktop-diagnostics",
        image="test-image",
        env={},
        volumes=(),
        command=(),
        task_dir=tmp_path,
        wayland=WaylandMode.MITM,
    )


@pytest.mark.parametrize("host_coordinate", [False, True])
@pytest.mark.parametrize("invalid", ["relative", *':,"\r\n\0'])
def test_socket_coordinates_cannot_change_mount_options(
    tmp_path: Path, host_coordinate: bool, invalid: str
) -> None:
    """Both coordinates reject relative paths and every mount-option delimiter before stat."""
    source, destination = tmp_path / "socket", CONTAINER_WAYLAND_SOCKET
    coordinate = Path("relative") if invalid == "relative" else tmp_path / f"socket{invalid}"
    if host_coordinate:
        source = coordinate
    else:
        destination = str(coordinate)
    reason = "must be absolute" if invalid == "relative" else "mount-option delimiters"
    with pytest.raises(ValueError, match=reason):
        SocketSpec(source, destination).to_mount_arg()


def test_sealed_creation_rejects_explicit_host_socket(spec: RunSpec) -> None:
    """A caller cannot bypass sealed isolation by supplying its own SocketSpec."""
    socket = SocketSpec(spec.task_dir / "socket", CONTAINER_WAYLAND_SOCKET)
    sandbox = Sandbox(runtime=MagicMock())
    with (
        patch.object(sandbox, "pre_start_args", return_value=[]),
        pytest.raises(ValueError, match="existing host sockets are not supported in sealed"),
    ):
        sandbox._build_cmd(replace(spec, sealed=True, sockets=(socket,)))


@pytest.mark.parametrize("failure", [OSError, ValueError])
def test_unrecorded_session_drops_prepared_mounts(
    spec: RunSpec, failure: type[Exception], capsys: pytest.CaptureFixture[str]
) -> None:
    """A failed state write cannot leave an untracked desktop grant on the container."""
    sandbox = Sandbox(runtime=MagicMock())
    warnings: list[str] = []
    session = WaylandSession(spec.wayland, spec.task_dir / "upstream", spec.task_dir / "wl-mitm")
    with (
        patch("terok_sandbox.wayland.resolve_session", return_value=session),
        patch(
            "terok_sandbox.supervisor.sidecar.record_wayland", side_effect=failure("state denied")
        ),
    ):
        prepared, direct_selinux = sandbox._prepare_wayland(
            spec, hooks=LifecycleHooks(warning=warnings.append)
        )
    assert prepared is spec and not direct_selinux
    assert "cannot record desktop wiring: state denied" in warnings[-1]
    assert "Task continues" in warnings[-1]
    assert warnings[-1] in capsys.readouterr().err


@pytest.mark.parametrize("failure", [OSError, ValueError])
def test_session_refresh_failure_warns_without_stopping_restart(
    spec: RunSpec, failure: type[Exception], capsys: pytest.CaptureFixture[str]
) -> None:
    """Unreadable optional state remains a warning, including the deferred runner summary."""
    sandbox = Sandbox(runtime=MagicMock())
    path = sandbox.config.sidecar_path(spec.container_name)
    path.parent.mkdir(parents=True)
    path.touch()
    warnings: list[str] = []
    with patch(
        "terok_sandbox.supervisor.sidecar.refresh_wayland", side_effect=failure("state denied")
    ):
        sandbox._refresh_wayland(spec.container_name, hooks=LifecycleHooks(warning=warnings.append))
    assert len(warnings) == 1
    assert "could not refresh desktop session: state denied" in warnings[0]
    assert "Task continues" in warnings[0]
    assert warnings[0] in capsys.readouterr().err


@pytest.fixture
def recorded_sandbox(spec: RunSpec, tmp_path: Path) -> Sandbox:
    """Retained task metadata and runtime observations stay inside the fixture."""
    cfg = SandboxConfig(state_dir=tmp_path / "state", runtime_dir=tmp_path / "runtime")
    path = cfg.sidecar_path(spec.container_name)
    path.parent.mkdir(parents=True)
    store_sidecar(
        path,
        {
            "container_name": spec.container_name,
            "broker_context": {"scope": "project", "subject": "task", "credential_set": "default"},
            "db_path": str(tmp_path / "vault.db"),
            "runtime_dir": str(cfg.runtime_dir),
        },
    )
    runtime = MagicMock()
    runtime.container.return_value.inspect.return_value = ContainerInspection(
        "fixture-id",
        "running",
        None,
        {},
        (),
    )
    return Sandbox(cfg, runtime=runtime)


@pytest.mark.parametrize("damage", ["missing", "invalid-json", "invalid-schema", "forgotten-mode"])
@pytest.mark.parametrize("operation", ["wayland_preflight", "start"])
def test_retained_direct_mount_requires_verifiable_saved_state(
    recorded_sandbox: Sandbox, spec: RunSpec, damage: str, operation: str
) -> None:
    """A warning cannot remove an existing direct compositor bind."""
    sandbox = recorded_sandbox
    source = spec.task_dir / "compositor"
    handle = sandbox.runtime.container.return_value
    handle.inspect.return_value = replace(
        handle.inspect.return_value, mounts=((str(source), CONTAINER_WAYLAND_SOCKET),)
    )
    path = sandbox.config.sidecar_path(spec.container_name)
    if damage == "missing":
        path.unlink()
    elif damage == "invalid-json":
        path.write_text("{broken")
    elif damage == "invalid-schema":
        path.write_text("{}")
    before = path.read_bytes() if path.exists() else None
    with pytest.raises(WaylandRecreationRequired, match="cannot verify"):
        getattr(sandbox, operation)(spec.container_name)
    handle.start.assert_not_called()
    assert (path.read_bytes() if path.exists() else None) == before


def test_wayland_preflight_is_read_only_and_rejects_changed_socket(
    recorded_sandbox: Sandbox, spec: RunSpec
) -> None:
    """Orchestrators can refuse a restart without stopping or rewriting the task."""
    sandbox = recorded_sandbox
    path = sandbox.config.sidecar_path(spec.container_name)
    session = WaylandSession(WaylandMode.DIRECT, spec.task_dir / "old")
    record_wayland(path, session)
    before = path.read_bytes()
    with patch(
        "terok_sandbox.wayland.resolve_session",
        return_value=replace(session, upstream=spec.task_dir / "new"),
    ):
        with pytest.raises(WaylandRecreationRequired, match="recreation required"):
            sandbox.wayland_preflight(spec.container_name)
    assert path.read_bytes() == before
    assert not sandbox.config.runtime_dir.exists()
    sandbox.runtime.container.return_value.stop.assert_not_called()


def test_proxy_mount_failure_cannot_gain_wiring_on_restart(
    recorded_sandbox: Sandbox, spec: RunSpec
) -> None:
    """Only recreation can add mounts omitted after a creation-time filesystem failure."""
    sandbox = recorded_sandbox
    session = WaylandSession(WaylandMode.MITM, spec.task_dir / "upstream", spec.task_dir / "proxy")
    with (
        patch("terok_sandbox.wayland.resolve_session", return_value=session),
        patch.object(sandbox, "_mount_wayland", side_effect=OSError("runtime unavailable")),
    ):
        prepared, _ = sandbox._prepare_wayland(spec)
    saved = load_sidecar(sandbox.config.sidecar_path(spec.container_name)).wayland
    assert prepared is spec and saved.disabled_reason
    assert "recreate" in saved.disabled_reason
    with patch("terok_sandbox.wayland._session_socket") as resolve:
        sandbox._refresh_wayland(spec.container_name)
    resolve.assert_not_called()
    assert not load_sidecar(sandbox.config.sidecar_path(spec.container_name)).wayland.proxied


@pytest.mark.parametrize("verb", ["run", "create"])
def test_optional_socket_disappearing_during_assembly_drops_only_desktop_wiring(
    recorded_sandbox: Sandbox, spec: RunSpec, verb: str
) -> None:
    """A late optional failure never aborts a task or removes caller-supplied grants."""
    sandbox = recorded_sandbox
    spec = replace(
        spec,
        wayland=WaylandMode.DIRECT,
        unrestricted=True,
        env={"KEEP": "yes"},
        sockets=(SocketSpec(spec.task_dir / "explicit", str(spec.task_dir / "caller-socket")),),
    )
    session = WaylandSession(WaylandMode.DIRECT, spec.task_dir / "upstream")
    with (
        patch("terok_sandbox.wayland.resolve_session", return_value=session),
        patch("terok_sandbox._util._selinux.is_selinux_enabled", return_value=False),
        patch.object(
            SocketSpec,
            "to_mount_arg",
            side_effect=["explicit-socket-mount", "valid", FileNotFoundError("vanished")],
        ),
        patch.object(sandbox, "pre_start_args", return_value=[]),
        patch.object(sandbox, "_exec_podman") as execute,
        patch.object(sandbox, "_verify_supervision"),
        patch.object(sandbox, "_verify_wayland"),
    ):
        getattr(sandbox, verb)(spec)
    command = execute.call_args.args[0]
    assert "KEEP=yes" in command and "explicit-socket-mount" in command
    assert not any("type=tmpfs" in arg or "WAYLAND_DISPLAY=" in arg for arg in command)
    saved = load_sidecar(sandbox.config.sidecar_path(spec.container_name)).wayland
    assert saved.upstream is None and "vanished" in saved.error


def test_explicit_socket_failure_remains_fatal(recorded_sandbox: Sandbox, spec: RunSpec) -> None:
    """Optional desktop recovery cannot hide a broken caller-requested socket grant."""
    spec = replace(spec, sockets=(SocketSpec(spec.task_dir / "missing", CONTAINER_WAYLAND_SOCKET),))
    with patch.object(recorded_sandbox, "_exec_podman") as execute:
        with pytest.raises(FileNotFoundError):
            recorded_sandbox.create(spec)
    execute.assert_not_called()


def test_malformed_wayland_payload_remains_visible_to_doctor(
    recorded_sandbox: Sandbox, spec: RunSpec
) -> None:
    """Malformed saved mode data is a warning, not absence of desktop configuration."""
    from terok_sandbox.doctor import _make_wayland_check

    path = recorded_sandbox.config.sidecar_path(spec.container_name)
    payload = json.loads(path.read_text())
    payload["wayland"] = {"mode": "invalid"}
    store_sidecar(path, payload)
    with patch("terok_sandbox.config.SandboxConfig", return_value=recorded_sandbox.config):
        check = _make_wayland_check(spec.container_name)
    assert check is not None and check.host_side
    assert "invalid Wayland sidecar" in check.evaluate(0, "", "").detail


def test_late_optional_failure_survives_unwritable_metadata(
    recorded_sandbox: Sandbox, spec: RunSpec
) -> None:
    """Even an unavailable rollback record cannot turn optional wiring into a launch failure."""
    sandbox = recorded_sandbox
    spec = replace(spec, wayland=WaylandMode.DIRECT, unrestricted=True)
    session = WaylandSession(WaylandMode.DIRECT, spec.task_dir / "upstream")
    with (
        patch("terok_sandbox.wayland.resolve_session", return_value=session),
        patch("terok_sandbox._util._selinux.is_selinux_enabled", return_value=False),
        patch.object(SocketSpec, "to_mount_arg", side_effect=["valid", OSError("vanished")]),
        patch(
            "terok_sandbox.supervisor.sidecar.record_wayland", side_effect=[None, OSError("denied")]
        ),
        patch.object(sandbox, "pre_start_args", return_value=[]),
    ):
        warnings: list[str] = []
        command = sandbox._prepare_launch_command(
            spec, verb="create", hooks=LifecycleHooks(warning=warnings.append)
        )
    assert not any("WAYLAND_DISPLAY=" in arg for arg in command)
    assert any("cannot record desktop wiring: denied" in warning for warning in warnings)


def test_sidecar_corruption_during_refresh_cannot_restart_direct_mount(
    recorded_sandbox: Sandbox, spec: RunSpec
) -> None:
    """Start-time refresh rechecks retained grants before downgrading metadata failures."""
    sandbox = recorded_sandbox
    path = sandbox.config.sidecar_path(spec.container_name)
    session = WaylandSession(WaylandMode.DIRECT, spec.task_dir / "upstream")
    record_wayland(path, session)
    handle = sandbox.runtime.container.return_value
    handle.inspect.return_value = replace(
        handle.inspect.return_value, mounts=((str(session.upstream), CONTAINER_WAYLAND_SOCKET),)
    )

    def corrupt(_path: Path) -> None:
        """Replace state after preflight, before the refresh can record it."""
        _path.write_text("{broken")
        raise ValueError("invalid state")

    with (
        patch("terok_sandbox.wayland.resolve_session", return_value=session),
        patch("terok_sandbox.supervisor.sidecar.refresh_wayland", side_effect=corrupt),
        pytest.raises(WaylandRecreationRequired, match="cannot verify"),
    ):
        sandbox.start(spec.container_name)
    handle.start.assert_not_called()


def test_failed_retained_mount_inspection_aborts_start(
    recorded_sandbox: Sandbox, spec: RunSpec
) -> None:
    """Unobservable runtime grants are not evidence that desktop access is absent."""
    handle = recorded_sandbox.runtime.container.return_value
    handle.inspect.side_effect = RuntimeError("inspection unavailable")
    with pytest.raises(RuntimeError, match="inspection unavailable"):
        recorded_sandbox.start(spec.container_name)
    handle.start.assert_not_called()
