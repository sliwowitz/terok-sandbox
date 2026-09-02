# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the shared ``/proc`` sweep behind the supervisor diagnostics.

Driven against a fake ``/proc`` tree so the sweep never reads — or
reports on — the host's real processes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from terok_sandbox._util import _proc

_SIDECAR = "/state/sidecar/demo-cli-w9xk3.json"
_CID = "a9a623c6543d"


@pytest.fixture
def fake_proc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the sweep at an empty fake ``/proc`` under ``tmp_path``."""
    proc = tmp_path / "proc"
    proc.mkdir()
    monkeypatch.setattr(_proc, "PROC_DIR", proc)
    return proc


def _add_process(proc: Path, pid: int, argv: list[str]) -> None:
    """Materialise one fake ``/proc/<pid>`` with a null-separated cmdline."""
    pid_dir = proc / str(pid)
    pid_dir.mkdir()
    (pid_dir / "cmdline").write_bytes(b"\x00".join(a.encode() for a in argv) + b"\x00")


def _add_child(proc: Path, pid: int, service: str, container_id: str = _CID) -> None:
    """Materialise one fake supervisor child, argv and all."""
    _add_process(
        proc,
        pid,
        [
            "/venv/bin/python",
            "-P",
            "-m",
            "terok_sandbox",
            "supervise-child",
            service,
            container_id,
            _SIDECAR,
        ],
    )


def test_children_are_reported_by_service(fake_proc: Path) -> None:
    _add_child(fake_proc, 101, "vault")
    _add_child(fake_proc, 102, "gate")
    assert _proc.service_children(_CID) == ("gate", "vault")


def test_another_containers_children_are_not_ours(fake_proc: Path) -> None:
    """Every child of every container is on one host — the ID is what separates them."""
    _add_child(fake_proc, 101, "vault")
    _add_child(fake_proc, 102, "signer", container_id="ffffffffffff")
    assert _proc.service_children(_CID) == ("vault",)


def test_a_supervisor_with_no_children_reports_none(fake_proc: Path) -> None:
    """The failure worth naming: the parent lives, every child of it has exited."""
    _add_process(fake_proc, 101, ["/venv/bin/python", "/state/supervisor_wrapper.py", _CID])
    assert _proc.service_children(_CID) == ()


def test_foreign_processes_are_ignored(fake_proc: Path) -> None:
    _add_process(fake_proc, 101, ["/usr/bin/vim", "supervise-child"])
    _add_process(fake_proc, 102, ["python", "-m", "terok_sandbox", "supervisor", _CID])
    assert _proc.service_children(_CID) == ()


def test_the_words_alone_are_not_a_child(fake_proc: Path) -> None:
    """The uninstall sweep kills what this reports, so a near miss must not match.

    An editor opened on the launcher has every word of the invocation in
    its argv. The words are also read by position after the verb, so a
    loose match would take the neighbours of those words for a service
    name and a container ID.
    """
    _add_process(
        fake_proc, 101, ["/usr/bin/vim", "terok_sandbox", "supervise-child", "vault", _CID]
    )
    _add_process(
        fake_proc, 102, ["python", "-m", "terok_sandbox.tools", "supervise-child", "vault", _CID]
    )
    assert _proc.service_children(_CID) == ()
    assert list(_proc.iter_service_children()) == []


def test_truncated_argv_keeps_the_child_visible(fake_proc: Path) -> None:
    """A child that cannot say which service it is still counts as one of ours."""
    _add_process(fake_proc, 101, ["python", "-m", "terok_sandbox", "supervise-child"])
    assert list(_proc.iter_service_children()) == [(101, "?", "?")]


def test_unreadable_entries_do_not_abort_the_sweep(fake_proc: Path) -> None:
    """A process that vanishes mid-sweep costs its own row, never the rest."""
    (fake_proc / "999").mkdir()  # a pid dir with no readable cmdline
    _add_child(fake_proc, 101, "vault")
    assert _proc.service_children(_CID) == ("vault",)
