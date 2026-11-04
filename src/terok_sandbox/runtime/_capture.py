# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Capture short command replies within a shared byte budget and deadline."""

from __future__ import annotations

import os
import selectors
import signal
import subprocess  # nosec B404 - runtime transport subprocesses
import time
from contextlib import suppress
from typing import BinaryIO, cast

from .protocol import ExecResult

_READ_SIZE = 64 * 1024


def _run_bounded(
    argv: list[str],
    *,
    max_output_bytes: int,
    timeout: float | None,
    executable: str | None = None,
) -> ExecResult:
    """Capture stdout and stderr without retaining more than their combined budget.

    Overflow raises ``RuntimeError`` rather than returning a partial reply.
    The deadline covers both pipe reads and process exit. Failure closes the
    pipes and kills the local transport process group; it does not promise
    to stop processes inside a container or remote guest.
    """
    _check_output_limit(0, max_output_bytes)
    deadline = None if timeout is None else time.monotonic() + timeout
    outputs = (bytearray(), bytearray())
    with subprocess.Popen(  # nosec B603 - argv supplied by the runtime transport
        argv,
        executable=executable,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
        start_new_session=True,
    ) as proc:
        streams = (cast(BinaryIO, proc.stdout), cast(BinaryIO, proc.stderr))
        try:
            with selectors.DefaultSelector() as selector:
                for stream, output in zip(streams, outputs, strict=True):
                    selector.register(stream, selectors.EVENT_READ, output)
                size = 0
                while selector.get_map():
                    remaining = _remaining_time(argv, timeout, deadline)
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fd, min(_READ_SIZE, max_output_bytes - size + 1))
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        size += len(chunk)
                        _check_output_limit(size, max_output_bytes)
                        key.data.extend(chunk)
            exit_code = proc.wait(timeout=_remaining_time(argv, timeout, deadline))
        except BaseException:
            # No reader threads hold buffered locks; inherited writers cannot
            # delay pipe closure or keep the selector waiting beyond its deadline.
            for stream in streams:
                stream.close()
            with suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            raise
    return ExecResult(exit_code, *(output.decode("utf-8", errors="replace") for output in outputs))


def _check_output_limit(size: int, limit: int | None) -> None:
    """Reject invalid budgets and replies that exceed the selected byte budget."""
    if limit is not None:
        if limit <= 0:
            raise ValueError("max_output_bytes must be positive")
        if size > limit:
            raise RuntimeError(f"Command output exceeded {limit} bytes")


def _remaining_time(argv: list[str], timeout: float | None, deadline: float | None) -> float | None:
    """Use one deadline for the reads and the final process wait."""
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise subprocess.TimeoutExpired(argv, cast(float, timeout))
    return remaining
