# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Wayland grants expose only a validated socket and preserve confinement."""

import os
import socket
from pathlib import Path
from unittest.mock import patch

import pytest

from terok_sandbox.podman_args import CONTAINER_WAYLAND_SOCKET, validate_passthrough_args
from terok_sandbox.runtime.wayland import wayland_run_args


@pytest.fixture
def display(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Bind a real Unix socket without needing a compositor or Podman."""
    path = tmp_path / "wayland-test"
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(path))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setenv("WAYLAND_DISPLAY", path.name)
    return path


@pytest.mark.parametrize("absolute", [False, True])
def test_single_socket(display: Path, monkeypatch: pytest.MonkeyPatch, absolute: bool) -> None:
    """Only the selected socket is mounted, without relabeling or host runtime env."""
    if absolute:
        monkeypatch.setenv("WAYLAND_DISPLAY", str(display))
        monkeypatch.delenv("XDG_RUNTIME_DIR")
    before = display.stat()
    args = wayland_run_args(sealed=False, runtime="crun")
    assert args == [
        "--mount",
        f"type=bind,source={display},destination={CONTAINER_WAYLAND_SOCKET},readonly",
        "--env",
        f"WAYLAND_DISPLAY={CONTAINER_WAYLAND_SOCKET}",
        "--unsetenv",
        "WAYLAND_SOCKET",
        "--unsetenv",
        "DISPLAY",
        "--unsetenv",
        "XAUTHORITY",
    ]
    assert display.stat() == before


@pytest.mark.parametrize("value", [None, "", "../wayland-test", "nested/wayland-test", ".", ".."])
def test_invalid_display(monkeypatch: pytest.MonkeyPatch, value: str | None) -> None:
    """Unset and relative path-shaped selectors never guess another display."""
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    if value is not None:
        monkeypatch.setenv("WAYLAND_DISPLAY", value)
    with pytest.raises(SystemExit, match="WAYLAND_DISPLAY"):
        wayland_run_args(sealed=False, runtime=None)


@pytest.mark.parametrize("value", [None, "", "relative"])
def test_invalid_runtime_dir(
    display: Path, monkeypatch: pytest.MonkeyPatch, value: str | None
) -> None:
    """A socket name requires an explicit absolute host runtime directory."""
    monkeypatch.delenv("XDG_RUNTIME_DIR")
    if value is not None:
        monkeypatch.setenv("XDG_RUNTIME_DIR", value)
    with pytest.raises(SystemExit, match="XDG_RUNTIME_DIR"):
        wayland_run_args(sealed=False, runtime=None)


@pytest.mark.parametrize("kind", ["missing", "file", "directory", "symlink"])
def test_not_a_socket(display: Path, kind: str) -> None:
    """Never turn a missing path, ordinary file, directory, or symlink into a grant."""
    display.unlink()
    if kind == "file":
        display.touch()
    elif kind == "directory":
        display.mkdir()
    elif kind == "symlink":
        target = display.with_name("other")
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(str(target))
        display.symlink_to(target)
    with pytest.raises(SystemExit, match="run.wayland"):
        wayland_run_args(sealed=False, runtime=None)


@pytest.mark.parametrize("mode", [0o770, 0o777])
def test_writable_parent(display: Path, mode: int) -> None:
    """Other users must not be able to replace the socket at its mount source."""
    display.parent.chmod(mode)
    with pytest.raises(SystemExit, match="socket directory"):
        wayland_run_args(sealed=False, runtime=None)


def test_foreign_owner(display: Path) -> None:
    """A session belonging to another host user is never forwarded."""
    with (
        patch("terok_sandbox.runtime.wayland.os.geteuid", return_value=os.geteuid() + 1),
        pytest.raises(SystemExit, match="socket directory"),
    ):
        wayland_run_args(sealed=False, runtime=None)


def test_foreign_socket(display: Path) -> None:
    """A foreign socket inside our directory is still refused."""
    info = display.lstat()
    foreign = os.stat_result((*info[:4], info.st_uid + 1, *info[5:]))
    with (
        patch.object(Path, "lstat", return_value=foreign),
        pytest.raises(SystemExit, match="socket owned"),
    ):
        wayland_run_args(sealed=False, runtime=None)


def test_inaccessible_socket(display: Path) -> None:
    """Report permissions without chmod or chown of the host session socket."""
    display.chmod(0o400)
    with pytest.raises(SystemExit, match="cannot access"):
        wayland_run_args(sealed=False, runtime=None)


@pytest.mark.parametrize("suffix", [",ro=false", '"quoted'])
def test_mount_delimiters(display: Path, monkeypatch: pytest.MonkeyPatch, suffix: str) -> None:
    """Socket names cannot inject additional Podman mount options."""
    renamed = display.with_name(display.name + suffix)
    display.rename(renamed)
    monkeypatch.setenv("WAYLAND_DISPLAY", renamed.name)
    with pytest.raises(SystemExit, match="mount-option characters"):
        wayland_run_args(sealed=False, runtime=None)


@pytest.mark.parametrize(("sealed", "runtime"), [(True, None), (False, "krun")])
def test_unsupported_isolation(sealed: bool, runtime: str | None) -> None:
    """Reject incompatible isolation before probing the desktop session."""
    with pytest.raises(SystemExit, match="not supported"):
        wayland_run_args(sealed=sealed, runtime=runtime)


def test_rootful() -> None:
    """Do not expose a desktop socket through a root-owned container."""
    with (
        patch("terok_sandbox.runtime.wayland.os.geteuid", return_value=0),
        pytest.raises(SystemExit, match="rootless"),
    ):
        wayland_run_args(sealed=False, runtime=None)


def test_protected_mount(display: Path) -> None:
    """Freeform mounts cannot shadow the typed Wayland grant."""
    with pytest.raises(SystemExit, match="managed"):
        validate_passthrough_args(["-v", f"{display}:{CONTAINER_WAYLAND_SOCKET}"])
