# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Interactive per-component hardening setup — SELinux policy, AppArmor addendum.

One ``[Y/s/n]`` flow shared by every frontend: print the exact ``sudo
bash`` command, offer to run it, or print the source of the rules it
installs.  ``terok setup selinux`` / ``terok-executor setup selinux`` /
``terok-sandbox setup selinux`` (and the ``apparmor`` twins) all route
here, and the aggregate setup's hints name the same verbs via
[`setup_invocation`][terok_sandbox.operator_cli.setup_invocation].

The split matters for sudo: everything that needs the operator's context
— the venv path of the bundled installer, the resolved sandbox-live root
— is resolved and rendered *before* privilege escalation, and a ``y``
answer then executes exactly the command that was shown.  Installing is
therefore always interactive — sudo asks for the password mid-flow — so
there is deliberately no ``--yes``: an unattended run copies the printed
``sudo bash`` command and executes it directly instead.
"""

from __future__ import annotations

import shutil
import subprocess  # nosec B404 — runs the bundled, audited installer via sudo
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ._util._apparmor import (
    AppArmorStatus,
    check_status as _check_apparmor,
    default_state_root as _apparmor_default_state_root,
    install_command as _apparmor_install_command,
    install_script_path as _apparmor_install_script,
    render_addendum as _render_addendum,
)
from ._util._selinux import (
    SelinuxStatus,
    check_status as _check_selinux,
    install_command as _selinux_install_command,
    install_script_path as _selinux_install_script,
    policy_source_display as _policy_source_display,
)

if TYPE_CHECKING:
    from .config import SandboxConfig

_SELINUX_STATUS_LINES = {
    SelinuxStatus.OK: "The terok_socket policy is loaded and current.",
    SelinuxStatus.POLICY_MISSING: "The terok_socket policy is not loaded.",
    SelinuxStatus.POLICY_OUTDATED: "The loaded terok_socket policy is outdated.",
    SelinuxStatus.LIBSELINUX_MISSING: "libselinux is not loadable; the policy state is unknown.",
    SelinuxStatus.NOT_APPLICABLE_TCP_MODE: (
        "Services run in TCP mode. No SELinux policy is needed on this host."
    ),
    SelinuxStatus.NOT_APPLICABLE_PERMISSIVE: (
        "SELinux is disabled or permissive. No policy is needed on this host."
    ),
}

_APPARMOR_STATUS_LINES = {
    AppArmorStatus.OK: "The terok dnsmasq addendum is installed and current.",
    AppArmorStatus.PROFILE_MISSING: (
        "dnsmasq is AppArmor-confined here; the terok addendum is not installed."
    ),
    AppArmorStatus.PROFILE_OUTDATED: "The installed terok dnsmasq addendum is an older revision.",
    AppArmorStatus.NOT_APPLICABLE: (
        "AppArmor does not confine dnsmasq on this host. Nothing to install."
    ),
}


@dataclass(frozen=True)
class _Component:
    """One hardening component the interactive flow can install."""

    status_line: str
    """One-sentence current state, printed first."""

    command: str
    """The exact ``sudo bash …`` invocation a ``y`` answer runs."""

    source: str
    """The rules the installer applies — the ``s`` / ``--show`` answer."""

    script_args: tuple[str, ...]
    """``bash`` argv tail (script path + its arguments) for the sudo run."""


def _selinux_component(cfg: SandboxConfig) -> _Component:
    """Assemble the SELinux policy component for *cfg*'s services mode."""
    status = _check_selinux(services_mode=cfg.services_mode).status
    return _Component(
        status_line=_SELINUX_STATUS_LINES[status],
        command=_selinux_install_command(),
        source=_policy_source_display(),
        script_args=(str(_selinux_install_script()),),
    )


def _apparmor_component() -> _Component:
    """Assemble the AppArmor addendum component for the default state root."""
    status = _check_apparmor().status
    root = _apparmor_default_state_root()
    return _Component(
        status_line=_APPARMOR_STATUS_LINES[status],
        command=_apparmor_install_command(root),
        source=_render_addendum(root),
        script_args=(str(_apparmor_install_script()), str(root)),
    )


def _sudo_run(script_args: tuple[str, ...]) -> int:
    """Run ``sudo bash <script> …`` with inherited stdio.

    Inherited stdio keeps sudo's password prompt working.  Missing
    binaries fail with a plain sentence naming the alternative.
    """
    sudo = shutil.which("sudo")
    if sudo is None:
        raise SystemExit("sudo not found on PATH. Run the command above as root instead.")
    bash = shutil.which("bash")
    if bash is None:
        raise SystemExit("bash not found on PATH.")
    return subprocess.run([sudo, bash, *script_args], check=False).returncode  # nosec B603


def _run_component(comp: _Component, *, show_only: bool) -> int:
    """The shared show-ask-run flow.  Returns the process exit code.

    ``--show`` prints the rules and returns.  Otherwise the exact sudo
    command is printed first and a terminal gets the ``[Y/s/n]``
    question (``s`` prints the rules, then the question is asked
    again); a non-terminal only gets the command — the install needs a
    terminal for the sudo password.  ``n`` and end-of-input cancel with
    exit 1; Ctrl-C cancels with exit 130.
    """
    if show_only:
        print(comp.source, end="")
        return 0
    print(comp.status_line)
    print()
    print("This will run (sudo asks for your password):")
    print(f"  {comp.command}")
    if not sys.stdin.isatty():
        print()
        print("Not a terminal. Run the command above directly to install.")
        return 1
    print()
    while True:
        try:
            answer = input("Proceed? [Y/s/n] (s = show the rules first): ").strip().lower()
        except EOFError:
            print()
            return 1
        except KeyboardInterrupt:
            print()
            return 130
        if answer in ("", "y", "yes"):
            print()
            return _sudo_run(comp.script_args)
        if answer == "s":
            print()
            print(comp.source, end="")
            print()
            continue
        if answer in ("n", "no"):
            print("Cancelled. You can run the command above yourself at any time.")
            return 1


def handle_setup_selinux(*, show_only: bool = False, cfg: SandboxConfig | None = None) -> int:
    """``setup selinux`` — show, confirm, and run the policy installer."""
    from .config import SandboxConfig

    return _run_component(_selinux_component(cfg or SandboxConfig()), show_only=show_only)


def handle_setup_apparmor(*, show_only: bool = False) -> int:
    """``setup apparmor`` — show, confirm, and run the addendum installer."""
    return _run_component(_apparmor_component(), show_only=show_only)


def handle_setup_component(
    component: str, *, show_only: bool = False, cfg: SandboxConfig | None = None
) -> int:
    """Route a ``setup <component>`` verb to its interactive installer."""
    if component == "selinux":
        return handle_setup_selinux(show_only=show_only, cfg=cfg)
    if component == "apparmor":
        return handle_setup_apparmor(show_only=show_only)
    raise SystemExit(f"unknown setup component {component!r} (expected: selinux or apparmor)")


__all__ = [
    "handle_setup_apparmor",
    "handle_setup_component",
    "handle_setup_selinux",
]
