# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Opt-in perf and ASLR grants without discarding unrelated host restrictions.

ThreadSanitizer queries the current personality, adds ``ADDR_NO_RANDOMIZE``,
and re-executes when its shadow-memory layout conflicts with ASLR. Grant only
that flag on the Linux personalities supported by the containers/common default.
Never permit arbitrary personality bits such as ``READ_IMPLIES_EXEC``. Perf
requires an explicit syscall grant: host profiles may deny it even with PERFMON.
"""

import json
import tempfile
from pathlib import Path

from .podman import default_seccomp_profile

_ADDR_NO_RANDOMIZE = 0x40000
_PERSONALITY_QUERY = 0xFFFFFFFF
_LINUX_PERSONALITIES = (0, 8, 0x20000, 0x20008)
"""PER_LINUX/PER_LINUX32, with or without UNAME26."""
_PERF_EVENT_OPEN = "perf_event_open"
_PROFILE_NAME = "seccomp.json"


def seccomp_args(
    state_dir: Path,
    *,
    aslr_control: bool = False,
    perf: bool = False,
    runtime: str | None = None,
) -> list[str]:
    """Write a per-container profile and return its Podman security option.

    Perf replaces only ``perf_event_open`` entries with one unconditional allow;
    kernel permissions still apply. ASLR adds narrow personality grants, refusing
    explicit personality denials. Preserve all unrelated host rules and metadata.
    The file stays in host-side state for container restarts, outside its mounts.
    Discovery verifies the effective runtime before any profile is written.
    Without either opt-in, leave Podman's policy untouched and skip discovery.
    """
    if not (aslr_control or perf):
        return []
    source = default_seccomp_profile(runtime=runtime)
    try:
        profile = json.loads(source.read_text())
        if profile["defaultAction"] != "SCMP_ACT_ERRNO":
            raise ValueError("expected a default-deny SCMP_ACT_ERRNO profile")
        rules = profile["syscalls"]
        if aslr_control:
            if any(
                "personality" in rule["names"] and rule["action"] != "SCMP_ACT_ALLOW"
                for rule in rules
            ):
                raise ValueError("the host profile explicitly denies personality; review it first")
            rules.extend(
                {
                    "names": ["personality"],
                    "action": "SCMP_ACT_ALLOW",
                    "args": [{"index": 0, "value": value, "op": "SCMP_CMP_EQ"}],
                }
                for value in (
                    _PERSONALITY_QUERY,
                    *(base | _ADDR_NO_RANDOMIZE for base in _LINUX_PERSONALITIES),
                )
            )
        if perf:
            profile["syscalls"] = _allow_perf_event_open(rules)
        state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        destination = state_dir / _PROFILE_NAME
        with tempfile.TemporaryDirectory(dir=state_dir) as staging:
            staged = Path(staging) / _PROFILE_NAME
            with staged.open("w") as stream:
                json.dump(profile, stream, indent=2)
                stream.write("\n")
            staged.replace(destination)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SystemExit(f"seccomp policy: cannot extend seccomp profile {source}: {exc}") from exc
    return ["--security-opt", f"seccomp={destination}"]


def _allow_perf_event_open(rules: list[dict]) -> list[dict]:
    """Replace perf policy without dropping other syscalls or shared-rule conditions."""
    retained = []
    for rule in rules:
        if _PERF_EVENT_OPEN not in rule["names"]:
            retained.append(rule)
        elif names := [name for name in rule["names"] if name != _PERF_EVENT_OPEN]:
            retained.append({**rule, "names": names})
    retained.append({"names": [_PERF_EVENT_OPEN], "action": "SCMP_ACT_ALLOW"})
    return retained
