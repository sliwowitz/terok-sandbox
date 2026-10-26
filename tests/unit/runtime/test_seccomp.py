# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Requested seccomp grants preserve every unrelated host-policy restriction."""

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from terok_sandbox.runtime.podman import default_seccomp_profile
from terok_sandbox.runtime.seccomp import seccomp_args

_ENABLED_POLICIES = [(True, False), (False, True), (True, True)]
_PROFILE_INFO_FORMAT = "{{.Host.OCIRuntime.Name}}\n{{.Host.Security.SECCOMPProfilePath}}"
_PERF_ALLOW = {"names": ["perf_event_open"], "action": "SCMP_ACT_ALLOW"}
_ASLR_ALLOWS = [
    {
        "names": ["personality"],
        "action": "SCMP_ACT_ALLOW",
        "args": [{"index": 0, "value": value, "op": "SCMP_CMP_EQ"}],
    }
    for value in (0xFFFFFFFF, 0x40000, 0x40008, 0x60000, 0x60008)
]
_SYS_ADMIN_SYSCALLS = [
    "bpf",
    "fanotify_init",
    "lookup_dcookie",
    "perf_event_open",
    "quotactl",
    "setdomainname",
    "sethostname",
    "setns",
]


@pytest.fixture
def host_profile(tmp_path: Path) -> Path:
    """A default-deny policy with architecture and capability conditions."""
    path = tmp_path / "host-seccomp.json"
    path.write_text(
        json.dumps(
            {
                "defaultAction": "SCMP_ACT_ERRNO",
                "defaultErrnoRet": 38,
                "archMap": [
                    {"architecture": "SCMP_ARCH_AARCH64", "subArchitectures": ["SCMP_ARCH_ARM"]}
                ],
                "syscalls": [
                    {"names": ["read", "write"], "action": "SCMP_ACT_ALLOW"},
                    {
                        "names": ["perf_event_open"],
                        "action": "SCMP_ACT_ALLOW",
                        "includes": {"caps": ["CAP_PERFMON"]},
                    },
                    {"names": ["ptrace"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1},
                    {
                        "names": ["personality"],
                        "action": "SCMP_ACT_ALLOW",
                        "args": [{"index": 0, "value": 0, "op": "SCMP_CMP_EQ"}],
                    },
                ],
            }
        )
    )
    return path


@pytest.fixture(params=["CAP_SYS_ADMIN", "CAP_PERFMON", None], ids=["legacy", "modern", "absent"])
def perf_host_profile(host_profile: Path, request: pytest.FixtureRequest) -> Path:
    """Host profiles with grouped legacy/modern perf rules, or no perf membership."""
    profile = json.loads(host_profile.read_text())
    if capability := request.param:
        profile["syscalls"].extend(
            [
                {
                    "names": _SYS_ADMIN_SYSCALLS,
                    "action": "SCMP_ACT_ALLOW",
                    "includes": {"caps": [capability]},
                },
                {
                    "names": _SYS_ADMIN_SYSCALLS,
                    "action": "SCMP_ACT_ERRNO",
                    "errnoRet": 1,
                    "excludes": {"caps": [capability]},
                },
                {
                    "names": ["perf_event_open"],
                    "action": "SCMP_ACT_ERRNO",
                    "errnoRet": 1,
                    "excludes": {"caps": ["CAP_SYS_ADMIN"]},
                },
            ]
        )
    else:
        profile["syscalls"] = [
            rule for rule in profile["syscalls"] if "perf_event_open" not in rule["names"]
        ]
    host_profile.write_text(json.dumps(profile))
    return host_profile


@pytest.mark.parametrize("runtime", [None, "crun"])
def test_aslr_profile_preserves_every_existing_rule(
    host_profile: Path, tmp_path: Path, runtime: str | None
) -> None:
    """No host rule, capability condition, architecture, or default is replaced."""
    original = host_profile.read_text()
    with patch(
        "terok_sandbox.runtime.seccomp.default_seccomp_profile", return_value=host_profile
    ) as discover:
        args = seccomp_args(tmp_path / "state", aslr_control=True, runtime=runtime)
    discover.assert_called_once_with(runtime=runtime)
    assert args[0] == "--security-opt"
    profile_path = Path(args[1].removeprefix("seccomp="))
    profile = json.loads(profile_path.read_text())
    added = profile["syscalls"][-5:]
    assert added == _ASLR_ALLOWS
    del profile["syscalls"][-5:]
    assert profile == json.loads(original)
    assert host_profile.read_text() == original
    assert list(profile_path.parent.iterdir()) == [profile_path]


@pytest.mark.parametrize("runtime", [None, "crun", "krun"])
def test_no_policy_request_has_no_side_effects(tmp_path: Path, runtime: str | None) -> None:
    """The default launch neither discovers a host profile nor creates state."""
    state = tmp_path / "state"
    with patch("terok_sandbox.runtime.seccomp.default_seccomp_profile") as discover:
        assert seccomp_args(state, runtime=runtime) == []
    discover.assert_not_called()
    assert not state.exists()


@pytest.mark.parametrize(("aslr_control", "perf"), _ENABLED_POLICIES)
@pytest.mark.parametrize("absolute_runtime", [False, True])
def test_default_krun_rejects_custom_policy(
    host_profile: Path, tmp_path: Path, aslr_control: bool, perf: bool, absolute_runtime: bool
) -> None:
    """A configured krun default must reject host seccomp customization before writing."""
    state = tmp_path / "state"
    runtime_name = str(tmp_path / "krun") if absolute_runtime else "krun"

    with patch(
        "terok_sandbox.runtime.podman.subprocess.run",
        return_value=subprocess.CompletedProcess([], 0, f"{runtime_name}\n{host_profile}\n"),
    ):
        with pytest.raises(SystemExit, match="not supported.*krun"):
            seccomp_args(state, aslr_control=aslr_control, perf=perf)
    assert not state.exists()


@pytest.mark.parametrize(("aslr_control", "perf"), _ENABLED_POLICIES)
def test_perf_replaces_conflicting_host_rules(
    perf_host_profile: Path, tmp_path: Path, aslr_control: bool, perf: bool
) -> None:
    """Only requested grants change, including in profiles that deny perf despite CAP_PERFMON."""
    original = perf_host_profile.read_text()
    expected = json.loads(original)
    preserved_rules = []
    for rule in expected["syscalls"]:
        names = [name for name in rule["names"] if not (perf and name == "perf_event_open")]
        if names:
            preserved_rules.append(rule | {"names": names})
    state = tmp_path / "state"
    with patch(
        "terok_sandbox.runtime.seccomp.default_seccomp_profile", return_value=perf_host_profile
    ) as discover:
        args = seccomp_args(state, aslr_control=aslr_control, perf=perf)
    discover.assert_called_once_with(runtime=None)
    profile_path = state / "seccomp.json"
    assert args == ["--security-opt", f"seccomp={profile_path}"]
    actual = json.loads(profile_path.read_text())
    rules = actual.pop("syscalls")
    expected.pop("syscalls")
    assert actual == expected
    assert rules[: len(preserved_rules)] == preserved_rules
    added = rules[len(preserved_rules) :]
    grants = (_ASLR_ALLOWS if aslr_control else []) + ([_PERF_ALLOW] if perf else [])
    assert len(added) == len(grants)
    assert all(grant in added for grant in grants)
    if perf:
        assert [rule for rule in rules if "perf_event_open" in rule["names"]] == [_PERF_ALLOW]
    assert all(rule["names"] for rule in rules)
    assert perf_host_profile.read_text() == original
    assert list(state.iterdir()) == [profile_path]


@pytest.mark.parametrize(
    "body",
    [
        "not JSON",
        "[]",
        "{}",
        '{"defaultAction": "SCMP_ACT_ALLOW", "syscalls": []}',
        '{"defaultAction": "SCMP_ACT_ERRNO", "syscalls": [null]}',
    ],
)
@pytest.mark.parametrize(("aslr_control", "perf"), _ENABLED_POLICIES)
def test_unusable_profile_fails_closed(
    tmp_path: Path, body: str, aslr_control: bool, perf: bool
) -> None:
    """Invalid or conflicting profiles never silently become an unconfined launch."""
    source = tmp_path / "bad.json"
    source.write_text(body)
    state = tmp_path / "state"
    with patch("terok_sandbox.runtime.seccomp.default_seccomp_profile", return_value=source):
        with pytest.raises(SystemExit, match="seccomp policy: cannot extend"):
            seccomp_args(state, aslr_control=aslr_control, perf=perf)
    assert not state.exists()


@pytest.mark.parametrize(("aslr_control", "perf"), _ENABLED_POLICIES)
def test_personality_denial_only_blocks_aslr(
    host_profile: Path, tmp_path: Path, aslr_control: bool, perf: bool
) -> None:
    """Perf-only policy leaves explicit personality denials intact; ASLR refuses them."""
    profile = json.loads(host_profile.read_text())
    denial = {"names": ["personality", "ptrace"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1}
    profile["syscalls"].append(denial)
    host_profile.write_text(json.dumps(profile))
    original = host_profile.read_text()
    state = tmp_path / "state"
    with patch("terok_sandbox.runtime.seccomp.default_seccomp_profile", return_value=host_profile):
        if aslr_control:
            with pytest.raises(SystemExit, match="explicitly denies personality"):
                seccomp_args(state, aslr_control=aslr_control, perf=perf)
            assert not state.exists()
        else:
            args = seccomp_args(state, perf=True)
            actual = json.loads(Path(args[1].removeprefix("seccomp=")).read_text())
            assert [rule for rule in actual["syscalls"] if "personality" in rule["names"]] == [
                profile["syscalls"][-2],
                denial,
            ]
    assert host_profile.read_text() == original


@pytest.mark.parametrize(("aslr_control", "perf"), _ENABLED_POLICIES)
def test_profile_read_failure_fails_closed(tmp_path: Path, aslr_control: bool, perf: bool) -> None:
    """A disappearing profile is not replaced by a less restrictive fallback."""
    state = tmp_path / "state"
    with patch(
        "terok_sandbox.runtime.seccomp.default_seccomp_profile", return_value=tmp_path / "missing"
    ):
        with pytest.raises(SystemExit, match="seccomp policy: cannot extend"):
            seccomp_args(state, aslr_control=aslr_control, perf=perf)
    assert not state.exists()


@pytest.mark.parametrize(("aslr_control", "perf"), _ENABLED_POLICIES)
def test_profile_can_be_regenerated(
    host_profile: Path, tmp_path: Path, aslr_control: bool, perf: bool
) -> None:
    """Recreation picks up current host policy and drops grants no longer requested."""
    state = tmp_path / "state"
    with patch("terok_sandbox.runtime.seccomp.default_seccomp_profile", return_value=host_profile):
        first_args = seccomp_args(state, aslr_control=True, perf=True)
        profile = json.loads(host_profile.read_text())
        profile["defaultErrnoRet"] = 1
        host_profile.write_text(json.dumps(profile))
        args = seccomp_args(state, aslr_control=aslr_control, perf=perf)
    profile_path = Path(args[1].removeprefix("seccomp="))
    actual = json.loads(profile_path.read_text())
    assert args == first_args
    assert actual["defaultErrnoRet"] == 1
    personality_rules = [rule for rule in actual["syscalls"] if "personality" in rule["names"]]
    assert personality_rules == [profile["syscalls"][-1]] + (_ASLR_ALLOWS if aslr_control else [])
    perf_rules = [rule for rule in actual["syscalls"] if "perf_event_open" in rule["names"]]
    assert perf_rules == ([_PERF_ALLOW] if perf else [profile["syscalls"][1]])
    assert list(state.iterdir()) == [profile_path]


@pytest.mark.parametrize(
    ("runtime", "reported_runtime"), [(None, "crun"), (None, "runc"), ("crun", "crun")]
)
def test_discover_configured_profile(
    host_profile: Path, runtime: str | None, reported_runtime: str
) -> None:
    """Probe the selected runtime and configured path together, honoring explicit overrides."""
    with patch(
        "terok_sandbox.runtime.podman.subprocess.run",
        return_value=subprocess.CompletedProcess([], 0, f"{reported_runtime}\n{host_profile}\n"),
    ) as run:
        assert default_seccomp_profile(runtime=runtime) == host_profile
    assert run.call_args.args[0] == [
        "podman",
        *(["--runtime", runtime] if runtime is not None else []),
        "info",
        "--format",
        _PROFILE_INFO_FORMAT,
    ]
    assert run.call_args.kwargs["check"] is True
    assert run.call_args.kwargs["timeout"] > 0


@pytest.mark.parametrize(
    "output", ["", "crun", "{profile}", "\n{profile}", "<no value>\n{profile}"]
)
def test_missing_runtime_metadata_is_rejected(host_profile: Path, output: str) -> None:
    """An absent runtime or missing separator cannot silently bypass the krun check."""
    with patch(
        "terok_sandbox.runtime.podman.subprocess.run",
        return_value=subprocess.CompletedProcess([], 0, output.format(profile=host_profile)),
    ):
        with pytest.raises(SystemExit, match="runtime"):
            default_seccomp_profile()


@pytest.mark.parametrize("output", ["", "<no value>", "unconfined"])
def test_missing_profile_path_is_rejected(output: str) -> None:
    """A built-in or disabled profile cannot be safely extended from a file."""
    with patch(
        "terok_sandbox.runtime.podman.subprocess.run",
        return_value=subprocess.CompletedProcess([], 0, f"crun\n{output}\n"),
    ):
        with pytest.raises(SystemExit, match="readable host Podman seccomp profile"):
            default_seccomp_profile()


@pytest.mark.parametrize(
    "error",
    [
        FileNotFoundError(),
        subprocess.CalledProcessError(125, "podman"),
        subprocess.TimeoutExpired("podman", 30),
    ],
)
def test_profile_discovery_failure_is_fatal(error: Exception) -> None:
    """Failed or timed-out discovery cannot skip the requested confinement."""
    with patch("terok_sandbox.runtime.podman.subprocess.run", side_effect=error):
        with pytest.raises(SystemExit, match="seccomp policy: cannot discover"):
            default_seccomp_profile()


@pytest.mark.parametrize("stderr", [None, "", "Error: cannot evaluate profile field\n"])
def test_profile_discovery_failure_preserves_diagnostics(stderr: str | None) -> None:
    """Show Podman's explanation alongside the failed-command context, when available."""
    error = subprocess.CalledProcessError(125, "podman", stderr=stderr)
    with (
        patch("terok_sandbox.runtime.podman.subprocess.run", side_effect=error),
        pytest.raises(SystemExit, match="seccomp policy: cannot discover") as caught,
    ):
        default_seccomp_profile()
    message = str(caught.value)
    assert str(error) in message
    if stderr:
        assert message.endswith(f"\n{stderr.strip()}")
