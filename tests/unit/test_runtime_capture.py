# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Bound hostile transport replies using local subprocesses, without Podman."""

from __future__ import annotations

import os
import subprocess
import sys
from unittest.mock import patch

import pytest

from terok_sandbox.runtime import ExecResult, FakeKrunTransport, KrunRuntime, NullRuntime
from terok_sandbox.runtime._capture import _run_bounded

_BUDGET = 1024
_TIMEOUT = 5.0


@pytest.fixture
def children(monkeypatch):
    """Record real local children so every outcome can assert cleanup."""
    popen = subprocess.Popen
    children = []

    def spawn(*args, **kwargs):
        child = popen(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr("terok_sandbox.runtime._capture.subprocess.Popen", spawn)
    yield children
    for child in children:
        assert child.returncode is not None
        assert child.stdout.closed
        assert child.stderr.closed


@pytest.mark.parametrize("timeout", [None, _TIMEOUT])
def test_small_reply_preserves_streams_and_exit_status(timeout, children) -> None:
    """Both streams and a nonzero exit remain available to the evaluator."""
    result = _run_bounded(
        [sys.executable, "-c", "import os; os.write(1, b'hello'); os.write(2, b'error'); exit(7)"],
        max_output_bytes=_BUDGET,
        timeout=timeout,
    )
    assert result == ExecResult(7, "hello", "error")


@pytest.mark.parametrize("fd", [1, 2])
def test_flood_is_stopped_at_the_byte_budget(fd, children) -> None:
    """A constant-memory producer on either stream cannot grow host capture."""
    with pytest.raises(RuntimeError, match=f"output exceeded {_BUDGET} bytes"):
        _run_bounded(
            [sys.executable, "-c", f"import os\nwhile True: os.write({fd}, b'x' * 8192)"],
            max_output_bytes=_BUDGET,
            timeout=_TIMEOUT,
        )


@pytest.mark.parametrize("budget", [5, 6])
def test_budget_is_combined_and_exact_boundary_succeeds(budget, children) -> None:
    """Neither stream gets a separate full budget; exactly the budget is valid."""
    argv = [sys.executable, "-c", "import os; os.write(1, b'abc'); os.write(2, b'def')"]
    if budget == 5:
        with pytest.raises(RuntimeError, match="output exceeded"):
            _run_bounded(argv, max_output_bytes=budget, timeout=_TIMEOUT)
    else:
        assert _run_bounded(argv, max_output_bytes=budget, timeout=_TIMEOUT) == ExecResult(
            0, "abc", "def"
        )


def test_invalid_utf8_cannot_crash_diagnostics(children) -> None:
    """Decode only bounded output and replace invalid bytes in both streams."""
    result = _run_bounded(
        [sys.executable, "-c", "import os; os.write(1, b'\\xff'); os.write(2, b'\\xfe')"],
        max_output_bytes=2,
        timeout=_TIMEOUT,
    )
    assert result == ExecResult(0, "\ufffd", "\ufffd")


@pytest.mark.parametrize("close_pipes", [False, True])
def test_deadline_covers_pipes_and_process_wait(close_pipes, children) -> None:
    """Silence and premature pipe EOF cannot bypass the overall deadline."""
    close = "os.close(1); os.close(2); " if close_pipes else ""
    with pytest.raises(subprocess.TimeoutExpired):
        _run_bounded(
            [sys.executable, "-c", f"import os, time; {close}time.sleep(30)"],
            max_output_bytes=_BUDGET,
            timeout=0.2,
        )


def test_inherited_writer_cannot_outlive_capture_deadline(children) -> None:
    """A child keeping its exited parent's pipes open cannot stall cleanup."""
    with patch("terok_sandbox.runtime._capture.os.killpg", wraps=os.killpg) as kill_group:
        with pytest.raises(subprocess.TimeoutExpired):
            _run_bounded(
                [sys.executable, "-c", "import os, time\nif os.fork() == 0: time.sleep(30)"],
                max_output_bytes=_BUDGET,
                timeout=0.2,
            )
    kill_group.assert_called_once()
    assert kill_group.call_args.args[0] == children[0].pid


@pytest.mark.parametrize("budget", [0, -1])
def test_invalid_limit_does_not_spawn(budget, children) -> None:
    """A byte budget must be positive before a process is launched."""
    with pytest.raises(ValueError, match="must be positive"):
        _run_bounded([sys.executable, "-c", "pass"], max_output_bytes=budget, timeout=_TIMEOUT)
    assert not children


@pytest.mark.parametrize("backend", ["null", "krun"])
def test_scripted_backends_enforce_byte_budget(backend) -> None:
    """Dry-run runtimes model combined bytes rather than Unicode character counts."""
    null = NullRuntime()
    result = ExecResult(0, "\u00e9", "x")
    if backend == "null":
        null.set_exec_result("ctr", ("probe",), result)
        runtime = null
    else:
        transport = FakeKrunTransport()
        transport.set_result("ctr", ("probe",), result)
        runtime = KrunRuntime(transport=transport, podman=null)
    container = runtime.container("ctr")
    assert runtime.exec(container, ["probe"], max_output_bytes=3) == result
    with pytest.raises(RuntimeError, match="output exceeded"):
        runtime.exec(container, ["probe"], max_output_bytes=2)
    with pytest.raises(ValueError, match="must be positive"):
        runtime.exec(container, ["probe"], max_output_bytes=0)
    assert runtime.exec(container, ["probe"]) == result
