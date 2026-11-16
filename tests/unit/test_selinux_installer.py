# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""The optional policy shares the audited installer's validation and compile path."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from terok_sandbox._util._selinux import (
    install_script_path,
    policy_source_path,
    wayland_direct_policy_source_path,
    wayland_policy_source_path,
)

_MODULES = ("terok_socket", "terok_wayland", "terok_wayland_direct")
_READ_AND_RUN = {
    "search", "getattr", "open", "read", "map", "execute", "execute_no_trans", "entrypoint",
}  # fmt: skip
"""Everything the proxy domain may do to a file type it does not own."""


@pytest.fixture
def installer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """Copy installer inputs and substitute tools that record, but never install, policy."""
    resources = tmp_path / "resources"
    resources.mkdir(mode=0o700)
    for name in ("install_policy.sh", *(f"{module}.te" for module in _MODULES)):
        shutil.copyfile(install_script_path().parent / name, resources / name)
        (resources / name).chmod(0o600)
    script = resources / "install_policy.sh"
    binaries = tmp_path / "bin"
    binaries.mkdir()
    trace = tmp_path / "trace"
    monkeypatch.setenv("TRACE", str(trace))
    monkeypatch.setenv("PATH", f"{binaries}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    for tool in ("checkmodule", "semodule_package", "semodule"):
        program = binaries / tool
        program.write_text(
            "#!/bin/bash\n"
            f"printf '%s\\n' '{tool}' \"$@\" >> \"$TRACE\"\n"
            'if [[ "$1" == "-l" ]]; then '
            'printf "terok_socket 1.1\\nterok_wayland 1.2\\nterok_wayland_direct 1.2\\n"; fi\n'
        )
        program.chmod(0o700)
    return script, trace


def _allow_rules(source: Path) -> list[tuple[set[str], set[str], set[str], set[str]]]:
    """Parse a module's one-line ``allow`` statements into (sources, targets, classes, perms)."""

    def names(token: str) -> set[str]:
        return set(token.strip("{} ").split())

    rule = re.compile(
        r"allow\s+(\{[^}]*\}|\S+)\s+(\{[^}]*\}|[^\s:]+):(\{[^}]*\}|\S+)\s+(\{[^}]*\}|[^;]+);"
    )
    return [
        tuple(map(names, match.groups()))
        for line in source.read_text().splitlines()
        if (match := rule.fullmatch(line.strip()))
    ]


@pytest.mark.parametrize("with_wayland", [False, True])
@pytest.mark.parametrize("with_direct", [False, True])
def test_selected_modules_compile_then_install_together(
    installer, with_wayland: bool, with_direct: bool
) -> None:
    """Independent flags add either or both modules; neither removes existing policy."""
    script, trace = installer
    flags = ["--with-wayland"] if with_wayland else []
    if with_direct:
        flags.append("--with-wayland-direct")
    result = subprocess.run(["bash", str(script), *flags], text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    calls = trace.read_text()
    assert "terok_socket.te" in calls
    assert ("terok_wayland.te" in calls) is with_wayland
    assert ("terok_wayland_direct.te" in calls) is with_direct
    assert calls.count("\n-i\n") == 1
    assert "\n-r\n" not in calls
    packages = calls[calls.index("\n-i\n") :]
    assert ("terok_wayland.pp" in packages) is with_wayland
    assert ("terok_wayland_direct.pp" in packages) is with_direct


def test_unknown_installer_option_is_rejected_before_tools_run(installer) -> None:
    script, trace = installer
    result = subprocess.run(["bash", str(script), "--bogus"], text=True, capture_output=True)
    assert result.returncode == 2
    assert "Usage:" in result.stderr
    assert not trace.exists()


@pytest.mark.parametrize(
    "module,flag",
    [
        ("terok_wayland", "--with-wayland"),
        ("terok_wayland_direct", "--with-wayland-direct"),
    ],
)
def test_optional_source_gets_same_symlink_protection(installer, module: str, flag: str) -> None:
    script, trace = installer
    source = script.parent / f"{module}.te"
    source.unlink()
    source.symlink_to(script.parent / "terok_socket.te")
    result = subprocess.run(["bash", str(script), flag], text=True, capture_output=True)
    assert result.returncode == 1
    assert "is a symlink" in result.stderr
    assert not trace.exists()


def test_installer_runs_through_safe_venv_directory_alias(installer) -> None:
    """A lib64-style alias no longer prevents installation before any tools run."""
    script, trace = installer
    alias = script.parent.parent / "lib64"
    alias.symlink_to(script.parent.name, target_is_directory=True)
    result = subprocess.run(["bash", str(alias / script.name)], text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert "\n-i\n" in trace.read_text()


@pytest.mark.parametrize("flag", ["--with-wayland", "--with-wayland-direct"])
def test_failed_optional_build_never_installs_any_module(installer, flag: str) -> None:
    """A failed optional build cannot partially install the selected policy set."""
    script, trace = installer
    compiler = script.parent.parent / "bin" / "checkmodule"
    compiler.write_text('#!/bin/bash\n[[ "$*" != *terok_wayland* ]] || exit 7\n')
    result = subprocess.run(["bash", str(script), flag], text=True, capture_output=True)
    assert result.returncode == 7
    assert not trace.exists() or "\n-i\n" not in trace.read_text()


def test_missing_build_tool_fails_before_compiling(
    installer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every module needs the same three tools, checked before any policy package exists."""
    script, trace = installer
    bash = shutil.which("bash")
    binaries = script.parent.parent / "bin"
    (binaries / "semodule_package").unlink()
    for tool in ("dirname", "stat", "readlink"):
        (binaries / tool).symlink_to(shutil.which(tool))
    monkeypatch.setenv("PATH", str(binaries))
    result = subprocess.run(
        [bash, str(script), "--with-wayland", "--with-wayland-direct"],
        text=True,
        capture_output=True,
    )
    assert result.returncode == 1
    assert "Required tool 'semodule_package' not found" in result.stderr
    assert not trace.exists()


def test_proxy_policy_changes_other_domains_only_as_its_header_says() -> None:
    """Outside its own domain the module adds entry for the launchers and two container grants."""
    foreign = [
        (sources, targets, classes, perms)
        for sources, targets, classes, perms in _allow_rules(wayland_policy_source_path())
        if sources != {"terok_wayland_t"}
    ]
    launchers = {"unconfined_t", "container_runtime_t"}
    assert all(
        targets == {"terok_wayland_t"} and classes <= {"process", "process2"}
        for sources, targets, classes, _perms in foreign
        if sources == launchers
    )
    container = {
        (*map(frozenset, (targets, classes, perms)),)
        for sources, targets, classes, perms in foreign
        if sources == {"container_t"}
    }
    assert container == {
        (frozenset({"terok_wayland_t"}), frozenset({"unix_stream_socket"}), frozenset({"connectto"})),
        (frozenset({"user_tmp_t"}), frozenset({"file"}), frozenset({"write", "map"})),
        (frozenset({"unconfined_t"}), frozenset({"memfd_file"}), frozenset({"read", "write", "getattr", "map"})),
    }  # fmt: skip
    assert {frozenset(sources) for sources, *_ in foreign} == {
        frozenset(launchers),
        frozenset({"container_t"}),
    }


def test_proxy_policy_reads_and_runs_every_file_type_without_writing_any() -> None:
    """Breadth buys install-layout compatibility; it never extends to mutation."""
    wide = [
        (classes, perms)
        for sources, targets, classes, perms in _allow_rules(wayland_policy_source_path())
        if "file_type" in targets
    ]
    assert {next(iter(classes)) for classes, _ in wide} == {"dir", "lnk_file", "file"}
    assert all(perms <= _READ_AND_RUN for _classes, perms in wide)
    assert {"entrypoint", "execute", "read", "open", "map"} <= next(
        perms for classes, perms in wide if classes == {"file"}
    )


def test_direct_policy_changes_no_other_domain() -> None:
    """The sibling domain receives every grant itself; container_t gains nothing here."""
    rules = _allow_rules(wayland_direct_policy_source_path())
    assert {frozenset(sources) for sources, *_ in rules} == {
        frozenset({"terok_wayland_direct_t"}),
        frozenset({"systemd_coredump_t"}),
    }
    desktop = {
        (*targets, *classes): perms
        for sources, targets, classes, perms in rules
        if targets & {"unconfined_t", "user_tmp_t", "terok_socket_t"}
    }
    assert desktop == {
        ("terok_socket_t", "unix_stream_socket"): {"connectto"},
        ("unconfined_t", "unix_stream_socket"): {"connectto"},
        ("user_tmp_t", "sock_file"): {"write", "getattr"},
        ("user_tmp_t", "file"): {"read", "write", "getattr", "map"},
        ("unconfined_t", "memfd_file"): {"read", "write", "getattr", "map"},
    }


@pytest.mark.parametrize(
    "boolean,marker",
    [
        ("virt_sandbox_use_sys_admin", "self:capability sys_admin;"),
        ("virt_sandbox_use_audit", "self:capability audit_write;"),
        ("container_use_xserver_devices", "xserver_misc_device_t:chr_file"),
    ],
)
def test_direct_policy_keeps_stock_grants_behind_existing_booleans(
    boolean: str, marker: str
) -> None:
    """Desktop selection must not enable host capabilities or NVIDIA device access."""
    source = wayland_direct_policy_source_path().read_text()
    guarded = source.split(f"if ({boolean}) {{", 1)[1].split("}\n", 1)[0]
    assert marker in guarded
    assert source.count(marker) == 1


def test_installer_packages_every_module_with_the_host_compiler(installer) -> None:
    """With real build tools, all selected modules reach ``semodule -i`` as packages."""
    script, trace = installer
    binaries = script.parent.parent / "bin"
    for tool in ("checkmodule", "semodule_package"):
        (binaries / tool).unlink()
        if not shutil.which(tool):
            pytest.skip("SELinux policy compiler not installed")
    (binaries / "semodule").write_text(
        "#!/bin/bash\n"
        f'if [[ "$1" != -i ]]; then printf "%s\\n" {" ".join(_MODULES)}; exit; fi\n'
        'shift; for package in "$@"; do\n'
        '    [[ -s "$package" ]] || exit 9; printf "%s\\n" "${package##*/}" >> "$TRACE"\n'
        "done\n"
    )
    result = subprocess.run(
        ["bash", str(script), "--with-wayland", "--with-wayland-direct"],
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    assert trace.read_text().split() == [f"{module}.pp" for module in _MODULES]


@pytest.mark.parametrize(
    "source",
    [policy_source_path, wayland_policy_source_path, wayland_direct_policy_source_path],
)
def test_policy_compiles_when_host_tools_are_available(tmp_path: Path, source) -> None:
    """Compile and package only; this never loads policy into the test host."""
    if not (compiler := shutil.which("checkmodule")) or not (
        packager := shutil.which("semodule_package")
    ):
        pytest.skip("SELinux policy compiler not installed")
    # checkmodule insists that the output is named after the module.
    module = tmp_path / f"{source().stem}.mod"
    package = module.with_suffix(".pp")
    subprocess.run([compiler, "-M", "-m", "-o", str(module), str(source())], check=True)
    subprocess.run([packager, "-o", str(package), "-m", str(module)], check=True)
    assert package.stat().st_size > 0
