# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Destructive decisions require observed metadata, not best-effort display defaults."""

import json
import subprocess
from dataclasses import FrozenInstanceError
from unittest.mock import Mock

import pytest

from terok_sandbox import (
    ContainerInspection,
    ImageInspection,
    KrunRuntime,
    NullRuntime,
    PodmanRuntime,
    RuntimeInspectionError,
)
from terok_sandbox.runtime import FakeKrunTransport
from tests.constants import MOCK_BASE

_ID = "a" * 64
_IMAGE_ID = "b" * 64
_SOURCE = str(MOCK_BASE / "workspace")
_DESTINATION = "/workspace"


def _container_record(**changes):
    """A complete observation pins the origin image independently of its mutable launch tag."""
    return {
        "Id": _ID,
        "State": {"Status": "exited"},
        "Image": _IMAGE_ID,
        "Config": {"Env": ["INPUT_PROTOCOL=3", "OPTS=a=b"], "Image": "mutable:tag"},
        "Mounts": [{"Source": _SOURCE, "Destination": _DESTINATION}],
        **changes,
    }


def _completed(code=0, stdout=""):
    """Supply real return-code checking without invoking Podman."""
    return subprocess.CompletedProcess(["podman"], code, stdout=stdout, stderr="runtime error")


@pytest.fixture
def run(monkeypatch):
    """Replace runtime I/O and host-tool discovery at their boundaries."""
    monkeypatch.setattr("terok_sandbox.runtime.podman.require_host_tool", lambda _: "podman")
    run = Mock()
    monkeypatch.setattr("terok_sandbox.runtime.podman.subprocess.run", run)
    return run


@pytest.fixture(params=["container", "image"])
def handle(request):
    """Exercise the same observation-failure contract on both handle kinds."""
    return getattr(PodmanRuntime(), request.param)("target")


@pytest.mark.parametrize("backend", [PodmanRuntime(), KrunRuntime(transport=FakeKrunTransport())])
def test_container_snapshot_is_one_observation_with_pinned_image(run, backend):
    """Environment, mounts, state and image identity cannot come from separate name lookups."""
    run.return_value = _completed(stdout=json.dumps([_container_record()]))
    snapshot = backend.container("target").inspect()
    assert isinstance(snapshot, ContainerInspection)
    assert snapshot.id == _ID
    assert snapshot.state == "exited"
    assert snapshot.env == {"INPUT_PROTOCOL": "3", "OPTS": "a=b"}
    assert snapshot.mounts == ((_SOURCE, _DESTINATION),)
    assert snapshot.image.ref == _IMAGE_ID
    assert run.call_count == 1
    assert run.call_args.args[0] == ["podman", "container", "inspect", "--", "target"]
    assert run.call_args.kwargs["timeout"] > 0


@pytest.mark.parametrize("empty", [None, []])
def test_observed_empty_container_inputs_are_not_inspection_errors(run, empty):
    """Explicit empty fields differ from missing or unreadable metadata."""
    run.return_value = _completed(
        stdout=json.dumps([_container_record(Image="", Config={"Env": empty}, Mounts=empty)])
    )
    snapshot = PodmanRuntime().container("target").inspect()
    assert snapshot.image is None
    assert snapshot.env == {}
    assert snapshot.mounts == ()


@pytest.mark.parametrize("labels", [None, {}, {"protocol": "3"}])
def test_image_snapshot_preserves_observed_labels(run, labels):
    """No labels is a valid observed fact, not the result of a failed command."""
    run.return_value = _completed(
        stdout=json.dumps([{"Id": _IMAGE_ID, "Config": {"Labels": labels}}])
    )
    assert PodmanRuntime().image("mutable:tag").inspect() == ImageInspection(
        _IMAGE_ID, labels or {}
    )
    assert run.call_args.args[0] == ["podman", "image", "inspect", "--", "mutable:tag"]


@pytest.mark.parametrize("stdout", ["not JSON", "[]", "{}", "[{}, {}]", "[42]"])
def test_malformed_inspection_never_becomes_absence(run, handle, stdout):
    """Even successful commands must return exactly one complete record."""
    run.return_value = _completed(stdout=stdout)
    with pytest.raises(RuntimeInspectionError, match="Invalid inspection"):
        handle.inspect()
    assert run.call_count == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"Id": "short"},
        {"State": {}},
        {"State": {"Status": None}},
        {"State": {"Status": ""}},
        {"Image": None},
        {"Image": "mutable:tag"},
        {"Config": {}},
        {"Config": {"Env": "INPUT_PROTOCOL=3"}},
        {"Config": {"Env": [42]}},
        {"Config": {"Env": ["INVALID"]}},
        {"Config": {"Env": ["=missing-name"]}},
        {"Mounts": {}},
        {"Mounts": [42]},
        {"Mounts": [{"Source": _SOURCE}]},
        {"Mounts": [{"Source": None, "Destination": _DESTINATION}]},
        {"Mounts": [{"Source": _SOURCE, "Destination": 42}]},
        {"Mounts": [{"Source": "", "Destination": _DESTINATION}]},
        {"Mounts": [{"Source": _SOURCE, "Destination": ""}]},
        {"Mounts": [{"Source": _SOURCE, "Destination": _DESTINATION}, {}]},
    ],
)
def test_invalid_container_fields_never_supply_partial_evidence(run, changes):
    """A valid-looking workspace mount cannot hide another malformed mount record."""
    run.return_value = _completed(stdout=json.dumps([_container_record(**changes)]))
    container = PodmanRuntime().container("target")
    with pytest.raises(RuntimeInspectionError, match="Invalid inspection"):
        container.inspect()


@pytest.mark.parametrize("field", ["Id", "State", "Image", "Config", "Mounts"])
def test_missing_container_fields_are_not_assumed_empty(run, field):
    """Only an explicitly observed empty field can establish missing protocol or mounts."""
    record = _container_record()
    del record[field]
    run.return_value = _completed(stdout=json.dumps([record]))
    container = PodmanRuntime().container("target")
    with pytest.raises(RuntimeInspectionError, match="Invalid inspection"):
        container.inspect()


@pytest.mark.parametrize(
    "record",
    [
        {},
        {"Id": None, "Config": {"Labels": {}}},
        {"Id": "short", "Config": {"Labels": {}}},
        {"Id": _IMAGE_ID, "Config": None},
        {"Id": _IMAGE_ID, "Config": {}},
        {"Id": _IMAGE_ID, "Config": {"Labels": []}},
        {"Id": _IMAGE_ID, "Config": {"Labels": {"protocol": 3}}},
    ],
)
def test_invalid_image_fields_never_look_like_missing_protocol(run, record):
    """Labels must be an observed string map, not coerced or invented values."""
    run.return_value = _completed(stdout=json.dumps([record]))
    image = PodmanRuntime().image("target")
    with pytest.raises(RuntimeInspectionError, match="Invalid inspection"):
        image.inspect()


def test_absence_requires_explicit_exists_exit_one(run, handle):
    """Generic inspect errors cannot prove that a retained object is gone."""
    run.side_effect = [_completed(125), _completed(1)]
    assert handle.inspect() is None
    assert run.call_args.args[0][-3:] == ["exists", "--", "target"]


def test_absence_probe_receives_only_the_remaining_budget(run, handle, monkeypatch):
    """Successful absence confirmation spends the same bounded observation budget."""
    monkeypatch.setattr("terok_sandbox.runtime.podman.time.monotonic", Mock(side_effect=[0, 4]))
    run.side_effect = [_completed(125), _completed(1)]
    assert handle.inspect() is None
    assert run.call_args.kwargs["timeout"] == run.call_args_list[0].kwargs["timeout"] - 4


@pytest.mark.parametrize("exists_code", [0, 125, -9])
def test_failed_inspection_with_present_or_unavailable_object_raises(run, handle, exists_code):
    """A container that appears between failed inspect and existence probe is not absent."""
    run.side_effect = [_completed(125), _completed(exists_code)]
    with pytest.raises(RuntimeInspectionError, match="Cannot inspect") as caught:
        handle.inspect()
    assert isinstance(caught.value.__cause__, subprocess.CalledProcessError)


@pytest.mark.parametrize("phase", ["inspect", "exists"])
@pytest.mark.parametrize(
    "failure", [OSError("unavailable"), subprocess.TimeoutExpired("podman", 30)]
)
def test_runtime_failures_do_not_become_empty_snapshots(run, handle, phase, failure):
    """No command timeout or host-tool failure permits destructive fallback."""
    run.side_effect = [failure] if phase == "inspect" else [_completed(125), failure]
    with pytest.raises(RuntimeInspectionError, match="Cannot inspect") as caught:
        handle.inspect()
    assert caught.value.__cause__ is failure


def test_missing_host_tool_fails_before_subprocess(run, handle, monkeypatch):
    """A host without Podman has no evidence that retained state is absent."""
    monkeypatch.setattr(
        "terok_sandbox.runtime.podman.require_host_tool", Mock(side_effect=FileNotFoundError)
    )
    with pytest.raises(RuntimeInspectionError, match="Cannot inspect"):
        handle.inspect()
    run.assert_not_called()


def test_absence_confirmation_shares_inspection_deadline(run, handle, monkeypatch):
    """The fallback probe cannot double the wait or run after the budget expires."""
    monkeypatch.setattr("terok_sandbox.runtime.podman.time.monotonic", Mock(side_effect=[0, 31]))
    run.return_value = _completed(125)
    with pytest.raises(RuntimeInspectionError, match="deadline expired"):
        handle.inspect()
    assert run.call_count == 1


def test_null_snapshots_are_detached_and_require_known_identity():
    """Fixtures model absence and incomplete evidence distinctly, without subprocesses."""
    runtime = NullRuntime()
    container = runtime.container("target")
    assert container.inspect() is None
    assert runtime.image(_IMAGE_ID).inspect() is None
    runtime.set_container_state("target", "exited")
    with pytest.raises(RuntimeInspectionError, match="no ID"):
        container.inspect()
    runtime.set_container_id("target", _ID)
    runtime.set_container_image("target", _IMAGE_ID)
    runtime.set_container_env("target", {"protocol": "3"})
    runtime.set_container_mounts("target", ((_SOURCE, _DESTINATION),))
    runtime.add_image(_IMAGE_ID, labels={"protocol": "3"})
    snapshot = container.inspect()
    assert snapshot.image.inspect() == ImageInspection(_IMAGE_ID, {"protocol": "3"})
    assert snapshot.mounts == ((_SOURCE, _DESTINATION),)
    snapshot.env.clear()
    assert container.inspect().env == {"protocol": "3"}
    with pytest.raises(FrozenInstanceError):
        snapshot.id = "changed"
