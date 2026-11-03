# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Storage diagnostics report observations without replacing or diagnosing the failure."""

from __future__ import annotations

import errno
import json
import os
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from terok_sandbox import PodmanRuntime, Sandbox
from terok_sandbox.runtime.storage_diagnostics import storage_permission_diagnostics
from tests.constants import MOCK_HOST_BIN


@pytest.fixture
def storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    """A private storage parent whose group falls outside the rootless mapping."""
    parent = tmp_path / "private"
    root = parent / "storage"
    root.mkdir(parents=True)
    parent.chmod(0o700)
    root.chmod(0o755)
    uid = parent.stat().st_uid
    mapped_gid = parent.stat().st_gid
    ownership = {"uid": uid, "gid": mapped_gid + 1}
    real_stat = Path.stat

    def directory_metadata(path: Path, **kwargs: object) -> os.stat_result:
        metadata = real_stat(path, **kwargs)
        if path == parent:
            fields = list(metadata)
            fields[4:6] = ownership["uid"], ownership["gid"]
            return os.stat_result(fields)
        return metadata

    monkeypatch.setattr(Path, "stat", directory_metadata)
    info = {
        "host": {
            "security": {"rootless": True},
            "serviceIsRemote": False,
            "idMappings": {
                "uidmap": [{"host_id": uid, "size": 1}],
                "gidmap": [{"host_id": mapped_gid, "size": 1}],
            },
        },
        "store": {"graphRoot": str(root)},
    }
    run = Mock(side_effect=lambda *a, **kw: subprocess.CompletedProcess(a, 0, json.dumps(info)))
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(
        "terok_sandbox.runtime.storage_diagnostics.require_host_tool",
        lambda name: str(MOCK_HOST_BIN / name),
    )
    acl = Mock(side_effect=OSError(errno.ENODATA, "no ACL"))
    monkeypatch.setattr(os, "getxattr", acl)
    error = (
        "Error: runc: runc create failed: unable to start container process: "
        "error during container init: error preparing rootfs: remount-propagation "
        f"dst={root}/overlay/layer/merged, flags=MS_PRIVATE: permission denied: OCI permission denied"
    )
    return {
        "parent": parent,
        "root": root,
        "info": info,
        "ownership": ownership,
        "run": run,
        "acl": acl,
        "error": error,
    }


def test_matching_failure_reports_metadata_without_diagnosis(storage: dict) -> None:
    before = storage["parent"].stat()
    report = storage_permission_diagnostics(storage["error"])
    assert report.startswith("\n\nStorage diagnostics (host IDs vs Podman's rootless mappings):\n")
    assert str(storage["parent"]) in report
    assert "mode=0700" in report
    assert f"owner UID={before.st_uid} (mapped)" in report
    assert f"group GID={before.st_gid} (unmapped)" in report
    assert "access ACL=absent" in report
    assert "Hint:" not in report
    assert "chown" not in report
    assert storage["parent"].stat() == before
    storage["run"].assert_called_once_with(
        [str(MOCK_HOST_BIN / "podman"), "info", "--format", "json"],
        capture_output=True,
        text=True,
        check=True,
        timeout=3,
    )


@pytest.mark.parametrize(
    "case",
    [
        "unrelated",
        "rootful",
        "remote",
        "mapped",
        "traversable",
        "empty-map",
        "invalid-gid-map",
        "invalid-mappings",
        "relative-store",
        "outside-store",
    ],
)
def test_unrelated_failures_or_no_observations_add_nothing(storage: dict, case: str) -> None:
    error = storage["error"]
    match case:
        case "unrelated":
            error = "permission denied opening an unrelated file"
        case "rootful":
            storage["info"]["host"]["security"]["rootless"] = False
        case "remote":
            storage["info"]["host"]["serviceIsRemote"] = True
        case "mapped":
            storage["info"]["host"]["idMappings"]["gidmap"].append(
                {"host_id": storage["parent"].stat().st_gid, "size": 1}
            )
        case "traversable":
            storage["parent"].chmod(0o701)
        case "empty-map":
            storage["info"]["host"]["idMappings"]["gidmap"] = []
        case "invalid-gid-map":
            storage["info"]["host"]["idMappings"]["gidmap"] = [{"host_id": -1, "size": 1}]
        case "invalid-mappings":
            storage["info"]["host"]["idMappings"] = None
        case "relative-store":
            storage["info"]["store"]["graphRoot"] = storage["root"].name
        case "outside-store":
            different = storage["root"] / "different"
            different.mkdir()
            storage["info"]["store"]["graphRoot"] = str(different)
    assert storage_permission_diagnostics(error) == ""
    if case == "unrelated":
        storage["run"].assert_not_called()


@pytest.mark.parametrize(
    "failure",
    [
        FileNotFoundError("podman missing"),
        subprocess.TimeoutExpired("podman info", 3),
        subprocess.CalledProcessError(125, "podman info"),
        ValueError("invalid JSON"),
    ],
)
def test_failed_probe_leaves_original_error_alone(storage: dict, failure: Exception) -> None:
    storage["run"].side_effect = failure
    assert storage_permission_diagnostics(storage["error"]) == ""


@pytest.mark.parametrize(
    "mapping",
    [None, [], [None], [{}], [{"host_id": -1, "size": 1}], [{"host_id": 0, "size": 0}]],
)
def test_unknown_owner_mapping_does_not_hide_observed_group(storage: dict, mapping: object) -> None:
    storage["info"]["host"]["idMappings"]["uidmap"] = mapping
    report = storage_permission_diagnostics(storage["error"])
    assert f"owner UID={storage['ownership']['uid']} (unknown)" in report
    assert f"group GID={storage['ownership']['gid']} (unmapped)" in report


@pytest.mark.parametrize("status", ["present", "unknown"])
def test_acl_status_is_context_not_a_gate(storage: dict, status: str) -> None:
    storage["acl"].side_effect = (
        None if status == "present" else OSError(errno.EOPNOTSUPP, "unknown ACL support")
    )
    storage["acl"].return_value = b"an access ACL"
    report = storage_permission_diagnostics(storage["error"])
    assert f"access ACL={status}" in report
    assert f"group GID={storage['ownership']['gid']} (unmapped)" in report


def test_unmapped_owner_is_reported_even_with_mapped_group(storage: dict) -> None:
    storage["ownership"]["uid"] += 1
    storage["ownership"]["gid"] -= 1
    report = storage_permission_diagnostics(storage["error"])
    assert f"owner UID={storage['ownership']['uid']} (unmapped)" in report
    assert f"group GID={storage['ownership']['gid']} (mapped)" in report


def test_reports_multiple_restrictive_ancestors(storage: dict) -> None:
    storage["root"].chmod(0o700)
    storage["info"]["host"]["idMappings"]["gidmap"] = [
        {"host_id": storage["ownership"]["gid"] + 1, "size": 1}
    ]
    report = storage_permission_diagnostics(storage["error"])
    assert f"  {storage['root']}: mode=0700" in report
    assert f"  {storage['parent']}: mode=0700" in report


def test_inaccessible_ancestor_does_not_discard_observations(
    storage: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = Path.stat

    def directory_metadata(path: Path, **kwargs: object) -> os.stat_result:
        if path == storage["parent"].parent:
            raise PermissionError("cannot stat ancestor")
        return original(path, **kwargs)

    monkeypatch.setattr(Path, "stat", directory_metadata)
    assert str(storage["parent"]) in storage_permission_diagnostics(storage["error"])


def test_symlinked_storage_checks_resolved_ancestors(storage: dict, tmp_path: Path) -> None:
    link = tmp_path / "store-link"
    link.symlink_to(storage["root"], target_is_directory=True)
    storage["info"]["store"]["graphRoot"] = str(link)
    error = storage["error"].replace(str(storage["root"]), str(link))
    assert str(storage["parent"]) in storage_permission_diagnostics(error)


def test_launch_preserves_original_error_and_cause(storage: dict) -> None:
    failure = subprocess.CalledProcessError(126, "podman run", stderr=storage["error"].encode())
    storage["run"].side_effect = [
        failure,
        subprocess.CompletedProcess([], 0, json.dumps(storage["info"])),
    ]
    with pytest.raises(SystemExit) as caught:
        Sandbox()._exec_podman(["podman", "run"])
    assert str(caught.value).startswith("Container launch failed:\n" + storage["error"])
    assert "Storage diagnostics" in str(caught.value)
    assert caught.value.__cause__ is failure


def test_start_preserves_original_error_and_exit_status(storage: dict) -> None:
    storage["run"].side_effect = [
        subprocess.CompletedProcess([], 126, stderr=storage["error"]),
        subprocess.CompletedProcess([], 0, json.dumps(storage["info"])),
    ]
    with pytest.raises(RuntimeError) as caught:
        PodmanRuntime().container("task").start()
    assert "rc=126" in str(caught.value)
    assert storage["error"] in str(caught.value)
    assert "Storage diagnostics" in str(caught.value)


@pytest.mark.parametrize("operation", ["launch", "start"])
def test_success_never_runs_storage_probes(storage: dict, operation: str) -> None:
    storage["run"].side_effect = None
    storage["run"].return_value = subprocess.CompletedProcess([], 0)
    if operation == "launch":
        Sandbox()._exec_podman(["podman", "run"])
    else:
        PodmanRuntime().container("task").start()
    storage["run"].assert_called_once()
