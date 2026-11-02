# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Emergency containment operates on strict runtime identities, never name prefixes."""

import json
import subprocess
from unittest.mock import Mock

import pytest

from terok_sandbox import NullRuntime, PodmanRuntime, RuntimeContainer

_ID = "a" * 64


def _record(**changes):
    """Return one normal daemon inspection record."""
    return {
        "Id": _ID,
        "Name": "/unrelated-name",
        "State": {"Status": "running"},
        "Config": {"Annotations": {"dossier.meta_path": "host-recorded"}},
        **changes,
    }


@pytest.fixture
def run(monkeypatch):
    """Replace Podman at the subprocess boundary, including host-tool discovery."""
    monkeypatch.setattr("terok_sandbox.runtime.podman.require_host_tool", lambda _: "podman")
    run = Mock()
    monkeypatch.setattr("terok_sandbox.runtime.podman.subprocess.run", run)
    return run


def test_inventory_preserves_full_ids_and_host_annotations(run):
    """Selection belongs to the caller; names neither include nor exclude records."""
    run.side_effect = [Mock(stdout=_ID + "\n"), Mock(stdout=json.dumps([_record()]))]
    assert PodmanRuntime().inventory(timeout=2) == [
        RuntimeContainer(_ID, "unrelated-name", "running", {"dossier.meta_path": "host-recorded"})
    ]
    assert run.call_args_list[0].args[0] == ["podman", "ps", "-aq", "--no-trunc"]
    assert run.call_args.kwargs["check"] is True
    assert 0 < run.call_args.kwargs["timeout"] <= 2


@pytest.mark.parametrize(
    "record",
    [
        [],
        [_record(Id="short")],
        [_record(State={})],
        [_record(Config={"Annotations": []})],
        [_record(), _record()],
        {},
    ],
)
def test_invalid_or_incomplete_inventory_raises(run, record):
    """Malformed metadata and vanished records cannot masquerade as successful discovery."""
    run.side_effect = [Mock(stdout=_ID), Mock(stdout=json.dumps(record))]
    with pytest.raises(RuntimeError):
        PodmanRuntime().inventory()


@pytest.mark.parametrize(
    "failure",
    [subprocess.CalledProcessError(125, "podman"), subprocess.TimeoutExpired("podman", 2)],
)
def test_inventory_propagates_runtime_failures(run, failure):
    """The orchestrator must report failed containment instead of claiming an empty host."""
    run.side_effect = failure
    with pytest.raises(type(failure)):
        PodmanRuntime().inventory(timeout=2)


def test_empty_inventory_and_unannotated_containers(run):
    """An empty host and ordinary unannotated containers are valid inventories."""
    run.return_value = Mock(stdout="")
    assert PodmanRuntime().inventory() == []
    run.side_effect = [Mock(stdout=_ID), Mock(stdout=json.dumps([_record(Config={})]))]
    assert PodmanRuntime().inventory()[0].annotations == {}


def test_force_stop_requires_full_id_and_propagates_timeout(run):
    """No ambiguous names, swallowed errors or unbounded stop command."""
    with pytest.raises(ValueError):
        PodmanRuntime().force_stop("looks-like-a-task")
    run.assert_not_called()
    run.side_effect = subprocess.TimeoutExpired("podman", 2)
    with pytest.raises(subprocess.TimeoutExpired):
        PodmanRuntime().force_stop(_ID, timeout=2)
    assert run.call_args.args[0] == ["podman", "stop", "--time", "0", _ID]
    assert run.call_args.kwargs["timeout"] == 2
    assert run.call_args.kwargs["check"] is True


def test_null_runtime_models_inventory_and_stop():
    """The recording backend exercises the same identity-based API without Podman."""
    runtime = NullRuntime()
    runtime.set_container_state("demo", "running")
    runtime.set_container_id("demo", _ID)
    runtime.set_container_annotations("demo", {"trusted": "annotation"})
    assert runtime.inventory() == [
        RuntimeContainer(_ID, "demo", "running", {"trusted": "annotation"})
    ]
    runtime.force_stop(_ID)
    assert runtime.inventory()[0].state == "exited"
    with pytest.raises(RuntimeError):
        runtime.force_stop("b" * 64)
    runtime.force_remove([runtime.container("demo")])
    assert runtime.inventory() == []
