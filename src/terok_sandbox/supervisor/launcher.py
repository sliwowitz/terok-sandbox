# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""How the parent supervisor spawns one child process per service.

Each service runs as its own ``python -m terok_sandbox supervise-child
<service> <container_id> <sidecar_path>`` process on the *parent's* own
interpreter — ``-m`` resolves through ``terok_sandbox.__main__``
whatever the install layout, so a child needs neither ``terok-sandbox``
on ``$PATH`` nor a rendered wrapper.

Isolation is the child's own job: the instant it starts it hardens
itself ([`harden_self`][terok_util.harden_self]) and labels its own
sockets for SELinux, all *before* it opens the credential store.  Nothing
about that depends on how the process was spawned, so the launch here is
a plain fork-exec. The parent's package search path survives wrapper-based
Python installations, but cwd imports remain excluded.
"""

from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .._util._subprocess_env import child_process_env

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class ChildHandle:
    """A launched child: its service name and the process running it."""

    service: str
    process: asyncio.subprocess.Process

    @property
    def pid(self) -> int:
        """The child's process id."""
        return self.process.pid


async def launch_child(service: str, container_id: str, sidecar_path: Path) -> ChildHandle:
    """Fork+exec ``python -m terok_sandbox supervise-child <service> …``.

    The parent's one spawn primitive.  The child hardens itself and binds
    its own socket. The environment preserves the parent's package paths; the
    returned [`ChildHandle`][terok_sandbox.supervisor.launcher.ChildHandle]
    is what the supervisor waits on and, at shutdown, signals.
    """
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-P",
        "-m",
        "terok_sandbox",
        "supervise-child",
        service,
        container_id,
        str(sidecar_path),
        env=child_process_env(),
    )
    return ChildHandle(service=service, process=process)


__all__ = ["ChildHandle", "launch_child"]
