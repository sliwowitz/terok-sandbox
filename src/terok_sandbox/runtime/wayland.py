# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Expose one desktop compositor socket without sharing the desktop session.

The operator grants the compositor's protocol surface, not a window-only
permission. Read-only mounting protects the socket inode, not the messages
sent through it. Host SELinux policy remains authoritative: never relabel
the compositor socket or disable container confinement to make it work.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from ..podman_args import CONTAINER_WAYLAND_SOCKET

WAYLAND_ENV_UNSET = ("WAYLAND_SOCKET", "DISPLAY", "XAUTHORITY")
"""Inherited display endpoints that must not override the selected compositor."""


def wayland_run_args(*, sealed: bool, runtime: str | None) -> list[str]:
    """Grant the current user's Wayland socket to a rootless local container.

    Resolve an explicit ``WAYLAND_DISPLAY`` (absolute path or a socket name
    beneath ``XDG_RUNTIME_DIR``). No default display is guessed. The container
    uses an absolute display path; its own runtime directory stays private.
    X11 and inherited Wayland file descriptors are not forwarded.

    Raises:
        SystemExit: The session socket is missing, unsafe, or incompatible
            with sealed isolation or the microVM runtime.
    """
    if sealed or runtime == "krun":
        raise SystemExit("run.wayland is not supported with sealed isolation or run.runtime: krun")
    uid = os.geteuid()
    if uid == 0:
        raise SystemExit("run.wayland requires rootless Podman, launched as the desktop user")
    socket = _session_socket(uid)
    return [
        "--mount",
        f"type=bind,source={socket},destination={CONTAINER_WAYLAND_SOCKET},readonly",
        "--env",
        f"WAYLAND_DISPLAY={CONTAINER_WAYLAND_SOCKET}",
        *(arg for name in WAYLAND_ENV_UNSET for arg in ("--unsetenv", name)),
    ]


def _session_socket(uid: int) -> Path:
    """Validate the session-selected socket before handing its path to Podman."""
    display = os.environ.get("WAYLAND_DISPLAY")
    if not display:
        raise SystemExit("run.wayland requires WAYLAND_DISPLAY; launch from your Wayland session")
    path = Path(display)
    if not path.is_absolute():
        if path.name != display or display in {".", ".."}:
            raise SystemExit("WAYLAND_DISPLAY must be a socket name or an absolute path")
        runtime_dir = Path(os.environ.get("XDG_RUNTIME_DIR", ""))
        if not runtime_dir.is_absolute():
            raise SystemExit("run.wayland requires an absolute XDG_RUNTIME_DIR")
        path = runtime_dir / display
    try:
        parent = path.parent.resolve(strict=True)
        parent_info = parent.stat()
        path = parent / path.name
        info = path.lstat()
    except (OSError, ValueError) as exc:
        raise SystemExit(f"run.wayland cannot inspect session socket {path}: {exc}") from exc
    if parent_info.st_uid != uid or parent_info.st_mode & 0o022:
        raise SystemExit("run.wayland requires a socket directory owned and writable only by you")
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != uid:
        raise SystemExit(f"run.wayland requires a socket owned by the desktop user: {path}")
    if not os.access(path, os.W_OK):
        raise SystemExit(f"run.wayland cannot access the session socket: {path}")
    if any(char in str(path) for char in ',"\r\n\0'):
        raise SystemExit("run.wayland socket path contains unsupported mount-option characters")
    return path
