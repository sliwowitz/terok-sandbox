# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Report local storage metadata after a rootfs permission failure, without diagnosing it."""

from __future__ import annotations

import errno
import json
import os
import re
import stat
import subprocess  # nosec B404 - read-only Podman diagnostics
from pathlib import Path

from terok_util import require_host_tool, sanitize_tty

_ROOTFS_DENIED = re.compile(
    r"error preparing rootfs: remount-propagation dst=(/[^\n]+), "
    r"flags=MS_PRIVATE: permission denied"
)
_PROBE_TIMEOUT = 3
_ACCESS_ACL = "system.posix_acl_access"


def storage_permission_diagnostics(stderr: str) -> str:
    """Report restrictive storage ancestors with unmapped host owners or groups.

    One bounded Podman info query identifies the relevant local rootless store.
    Modes, numeric IDs, mapping status and ACL presence are observations, not
    a cause or repair recommendation. Unavailable fields stay unknown; probe
    failures leave the original error alone. Never inspect or launch a container.
    """
    match = _ROOTFS_DENIED.search(stderr)
    if match is None:
        return ""
    try:
        result = subprocess.run(  # nosec B603 - fixed read-only Podman command
            [require_host_tool("podman"), "info", "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=_PROBE_TIMEOUT,
        )
        info = json.loads(result.stdout)
        host = info["host"]
        if host["security"]["rootless"] is not True or host["serviceIsRemote"] is not False:
            return ""
        root = Path(info["store"]["graphRoot"])
        if not root.is_absolute():
            return ""
        root = root.resolve(strict=True)
        if root not in Path(match[1]).resolve().parents:
            return ""
        mappings = host["idMappings"]
        if not isinstance(mappings, dict):
            return ""
        observations = []
        for directory in (root, *root.parents):
            try:
                metadata = directory.stat()
            except OSError:
                continue
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & stat.S_IXOTH:
                continue
            owner = _mapping_status(metadata.st_uid, mappings.get("uidmap"))
            group = _mapping_status(metadata.st_gid, mappings.get("gidmap"))
            if "unmapped" in (owner, group):
                observations.append(
                    f"  {sanitize_tty(str(directory))}: mode={stat.S_IMODE(metadata.st_mode):04o}, "
                    f"owner UID={metadata.st_uid} ({owner}), group GID={metadata.st_gid} ({group}), "
                    f"access ACL={_acl_status(directory)}"
                )
        if observations:
            return (
                "\n\nStorage diagnostics (host IDs vs Podman's rootless mappings):\n"
                + "\n".join(observations)
            )
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, RuntimeError):
        # Diagnostics must never replace the launch error with a probe error.
        return ""
    return ""


def _mapping_status(identifier: int, entries: list[dict] | None) -> str:
    """Compare a host ID with complete positive ranges, or report unknown data."""
    try:
        ranges = [(entry["host_id"], entry["size"]) for entry in entries or ()]
        if not ranges or any(
            type(start) is not int or type(size) is not int or start < 0 or size <= 0
            for start, size in ranges
        ):
            return "unknown"
        return (
            "mapped"
            if any(start <= identifier < start + size for start, size in ranges)
            else "unmapped"
        )
    except (KeyError, TypeError):
        return "unknown"


def _acl_status(directory: Path) -> str:
    """Report ACL presence without trying to evaluate its access rules."""
    try:
        os.getxattr(directory, _ACCESS_ACL)
    except OSError as exc:
        return "absent" if exc.errno == errno.ENODATA else "unknown"
    return "present"
