# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Process-table reads shared by the supervisor's diagnostics.

The supervisor spawns one child per service, each identified by its own
argv:

    <python> -P -m terok_sandbox supervise-child <service> <id> <sidecar>

That argv is the only handle a later process has on those children.  They
write no PID files of their own — the parent's covers the bundle — so
every question about *which services are actually running* is answered by
reading ``/proc``, and this module is where that read lives rather than in
each of the three callers that ask (the uninstall sweep, the host
diagnostics, and the doctor's per-container checks).

Bytes, not text: ``/proc/*/cmdline`` holds arbitrary byte sequences for
foreign processes, and a decode error must not abort a sweep mid-flight.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Iterator

#: argv fingerprints of a process-per-service child.
CHILD_MODULE_MARK: Final = b"terok_sandbox"
CHILD_VERB_MARK: Final = b"supervise-child"

#: Where the sweeps read process argvs from (patchable in tests).
PROC_DIR = Path("/proc")


def iter_process_argvs() -> Iterator[tuple[int, list[bytes]]]:
    """Yield ``(pid, argv_elements)`` for every process whose cmdline is readable."""
    for proc_dir in PROC_DIR.glob("[0-9]*"):
        with contextlib.suppress(OSError):
            raw = (proc_dir / "cmdline").read_bytes()
            yield int(proc_dir.name), raw.rstrip(b"\x00").split(b"\x00")


def iter_service_children() -> Iterator[tuple[int, str, str]]:
    """Yield ``(pid, service, container_id)`` for every live supervisor child.

    Every child on the host, of every container — callers filter.  A child
    whose argv is truncated past the verb is reported with ``"?"`` for the
    field it lost, because a process that *is* one of ours matters even
    when it cannot say which one it is.
    """
    for pid, args in iter_process_argvs():
        if CHILD_MODULE_MARK not in args or CHILD_VERB_MARK not in args:
            continue
        verb = args.index(CHILD_VERB_MARK)
        yield pid, _argv_field(args, verb + 1), _argv_field(args, verb + 2)


def service_children(container_id: str) -> tuple[str, ...]:
    """The service names of the live supervisor children for *container_id*.

    Sorted, so a caller can print or compare it without deciding an order.
    An empty tuple means no child of that container is running — which for
    a container whose supervisor is alive is the interesting failure: the
    parent survives its children, so a bundle can be half dead and look
    healthy from the PID file alone.
    """
    return tuple(
        sorted(service for _pid, service, cid in iter_service_children() if cid == container_id)
    )


def _argv_field(args: list[bytes], index: int) -> str:
    """The argv element at *index*, or ``"?"`` when the argv is shorter."""
    return args[index].decode(errors="replace") if index < len(args) else "?"
