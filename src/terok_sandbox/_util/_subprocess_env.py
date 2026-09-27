# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Environment helper for spawned ``terok_sandbox`` child processes.

Centralises the ``PYTHONPATH`` shim every ``subprocess.run`` /
``Popen`` of ``sys.executable`` must use, so adding a new spawn site
can't silently regress the Nix-wrapped-Python fix.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def child_process_env(overrides: dict[str, str] | None = None) -> dict[str, str]:
    """Build the environment for a spawned ``terok_sandbox`` child process.

    Threads the parent's absolute, non-cwd ``sys.path`` through as ``PYTHONPATH`` so the
    child can import ``terok_sandbox`` regardless of how the parent was
    launched. Under Nix, the launcher augments the parent's import path,
    but spawning ``sys.executable`` directly bypasses that launcher,
    leaving the child unable to find the ``terok_sandbox`` package.
    This shim restores it.

    *overrides* are applied on top of the parent env; ``PYTHONPATH``
    always wins so a stray ambient value can't shadow the parent's
    real import path. Cwd and relative entries are excluded to preserve
    the child's ``-P`` isolation, including symlink aliases of the cwd.
    """
    cwd = Path.cwd()
    import_paths = (
        entry for entry in sys.path if os.path.isabs(entry) and Path(entry).resolve() != cwd
    )
    return {**os.environ, **(overrides or {}), "PYTHONPATH": os.pathsep.join(import_paths)}
