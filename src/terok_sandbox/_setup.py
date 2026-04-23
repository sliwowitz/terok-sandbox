# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Sandbox-wide setup orchestration — the phases ``_handle_sandbox_setup`` runs.

Each phase is self-contained and idempotent:

* Prereq probes are report-only.  A missing ``nft`` or ``podman`` later
  fails the relevant service with a clearer message; reporting here
  lets the operator spot the root cause before scrolling past install
  noise.
* Service install phases do the full stop → uninstall → install →
  verify cycle so a re-run after ``pipx install terok-sandbox``
  guarantees the running unit picks up the new code, not just the
  rewritten on-disk unit file.
* The clearance phase is optional — headless servers that skip the
  desktop bridge still get a working shield+vault+gate install.

Printed output is plain-text stage lines; higher-level frontends that
want ANSI colour can wrap the aggregator call in their own renderer.
Kept internal (underscore-prefixed module) because every public
entry point goes through :func:`commands._handle_sandbox_setup`.
"""

from __future__ import annotations

import contextlib
import shutil
import subprocess  # nosec B404 — systemctl is a trusted host binary
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from ._util._selinux import (
    SelinuxStatus,
    check_status as check_selinux_status,
    install_command as selinux_install_command,
)
from .config import SandboxConfig, _services_mode
from .shield import check_environment

#: Padding width for stage-line labels — widest label is "Clearance
#: notifier" (18 chars) plus a 2-char gutter before the status marker.
_STAGE_WIDTH = 20

#: Host binaries that terok-sandbox's own code shells out to during
#: container runtime.  Other packages (terok-shield, terok-clearance)
#: publish their own lists and the prereq phase reports all of them.
_HOST_BINARIES: tuple[str, ...] = ("podman", "git", "ssh-keygen")


# ── Stage-line primitive ──────────────────────────────────────────────


def _stage(label: str, marker: str, detail: str = "") -> None:
    """Write one ``'  <label>  <marker> (<detail>)'`` line."""
    suffix = f" ({detail})" if detail else ""
    print(f"  {label:<{_STAGE_WIDTH}} {marker}{suffix}")


# ── Prereq reporting (host binaries, firewall binaries, SELinux) ─────


def run_prereq_report(cfg: SandboxConfig) -> None:
    """Print host prerequisites.  Never blocks — purely informational.

    A missing binary here surfaces as a ``MISSING`` stage line; the
    install phase that actually needs it will fail with a more
    specific error if the operator proceeds without fixing it.
    """
    print("Prerequisites:")
    _report_host_binaries()
    _report_firewall_binaries()
    _report_selinux(cfg)


def _report_host_binaries() -> None:
    """Check that sandbox's own runtime dependencies are on PATH."""
    for name in _HOST_BINARIES:
        path = shutil.which(name)
        if path:
            _stage(name, "ok", path)
        else:
            _stage(name, "MISSING", "not on PATH")


def _report_firewall_binaries() -> None:
    """Delegate the nft / dnsmasq / dig probes to terok-shield.

    Shield owns the binaries its own hooks invoke; publishing them
    there keeps the list honest when shield's dependencies change.
    """
    from terok_shield import check_firewall_binaries

    for check in check_firewall_binaries():
        if check.ok:
            _stage(check.name, "ok", check.path)
        else:
            _stage(check.name, "MISSING", check.purpose)


def _report_selinux(cfg: SandboxConfig) -> None:
    """Check SELinux policy — prints only when the host needs policy installed.

    ``NOT_APPLICABLE_*`` statuses mean SELinux isn't enforcing or the
    active transport doesn't need a policy (TCP mode); in those cases
    the prereq report stays silent to keep the output compact on the
    common-case host.
    """
    result = check_selinux_status(services_mode=_services_mode())
    match result.status:
        case SelinuxStatus.NOT_APPLICABLE_TCP_MODE | SelinuxStatus.NOT_APPLICABLE_PERMISSIVE:
            return
        case SelinuxStatus.OK:
            _stage("SELinux policy", "ok", "installed")
        case SelinuxStatus.POLICY_MISSING:
            _stage("SELinux policy", "MISSING", f"install: {selinux_install_command()}")
        case SelinuxStatus.LIBSELINUX_MISSING:
            _stage("SELinux policy", "MISSING", "libselinux.so.1 not loadable")


# ── Service install phases ────────────────────────────────────────────


@dataclass(frozen=True)
class _PhaseResult:
    """Return value from each service install phase — structured for the aggregator's summary."""

    ok: bool
    """True when the service is installed and (where applicable) reachable."""


def run_shield_install_phase(*, root: bool) -> _PhaseResult:
    """Install shield OCI hooks — per-user or system-wide depending on *root*."""
    from .shield import run_setup

    try:
        run_setup(root=root, user=not root)
    except Exception as exc:  # noqa: BLE001 — aggregator reports all failures uniformly
        _stage("Shield hooks", "FAIL", str(exc))
        return _PhaseResult(ok=False)

    # Verify the hooks landed in a working state.
    env = check_environment()
    if env.health == "ok":
        _stage("Shield hooks", "ok", "active")
        return _PhaseResult(ok=True)
    if env.health == "bypass":
        _stage("Shield hooks", "WARN", "bypass_firewall_no_protection is active")
        return _PhaseResult(ok=True)
    _stage("Shield hooks", "FAIL", f"installed but health: {env.health}")
    return _PhaseResult(ok=False)


def run_vault_install_phase(cfg: SandboxConfig) -> _PhaseResult:
    """Clean reinstall of the vault systemd units; verify reachability."""
    from .vault.lifecycle import VaultManager, VaultUnreachableError

    mgr = VaultManager(cfg)
    _stop_and_uninstall(mgr.stop_daemon, mgr.uninstall_systemd_units)

    try:
        mgr.install_systemd_units()
    except SystemExit as exc:
        _stage("Vault", "FAIL", str(exc))
        return _PhaseResult(ok=False)
    except Exception as exc:  # noqa: BLE001
        _stage("Vault", "FAIL", f"install: {exc}")
        return _PhaseResult(ok=False)

    try:
        mgr.ensure_reachable()
    except (VaultUnreachableError, SystemExit) as exc:
        _stage("Vault", "FAIL", f"installed but NOT reachable: {exc}")
        return _PhaseResult(ok=False)
    status = mgr.get_status()
    _stage(
        "Vault",
        "ok",
        f"{status.mode or 'systemd'}, {status.transport or 'tcp'}, reachable",
    )
    return _PhaseResult(ok=True)


def run_gate_install_phase(cfg: SandboxConfig) -> _PhaseResult:
    """Clean reinstall of the gate systemd units; verify reachability."""
    from .gate.lifecycle import GateServerManager

    mgr = GateServerManager(cfg)
    if not mgr.is_systemd_available():
        _stage("Gate server", "WARN", "systemd unavailable, skipping")
        return _PhaseResult(ok=True)

    _stop_and_uninstall(mgr.stop_daemon, mgr.uninstall_systemd_units)

    try:
        mgr.install_systemd_units()
    except Exception as exc:  # noqa: BLE001
        _stage("Gate server", "FAIL", f"install: {exc}")
        return _PhaseResult(ok=False)

    try:
        mgr.ensure_reachable()
    except SystemExit as exc:
        _stage("Gate server", "FAIL", f"installed but NOT reachable: {exc}")
        return _PhaseResult(ok=False)
    status = mgr.get_status()
    _stage(
        "Gate server",
        "ok",
        f"{status.mode or 'systemd'}, {status.transport or 'tcp'}, reachable",
    )
    return _PhaseResult(ok=True)


def run_clearance_install_phase() -> _PhaseResult:
    """Install the clearance hub + verdict + notifier units.

    Soft-skip when ``terok_clearance`` isn't importable — headless
    servers don't need the desktop bridge, and the sandbox shield /
    vault / gate stack is perfectly functional without it.
    """
    try:
        from terok_clearance.runtime.installer import (
            HUB_UNIT_NAME,
            NOTIFIER_UNIT_NAME,
            VERDICT_UNIT_NAME,
            install_notifier_service,
            install_service,
        )
    except ImportError:
        _stage("Clearance", "skip", "terok_clearance not installed")
        return _PhaseResult(ok=True)

    # Avoid ``shutil.which("terok-clearance-hub")``: a hostile PATH
    # could otherwise poison the ExecStart= baked into the persistent
    # user unit.  ``sys.executable`` isn't resolved through PATH, so
    # the pipx venv's own python is the one the unit invokes.
    hub_ok = _install_clearance_unit_pair(
        label="Clearance hub",
        install_fn=lambda: install_service([sys.executable, "-m", "terok_clearance.cli.main"]),
        units_to_enable=(HUB_UNIT_NAME, VERDICT_UNIT_NAME),
    )
    # Notifier failure is non-fatal — the hub is the critical path;
    # the notifier only enriches desktop popups.  The return value is
    # discarded so a notifier glitch (e.g. missing session bus on a
    # remote SSH install) doesn't flip the aggregator's exit code.
    _install_clearance_unit_pair(
        label="Clearance notifier",
        install_fn=lambda: install_notifier_service(
            [sys.executable, "-m", "terok_clearance.notifier.app"]
        ),
        units_to_enable=(NOTIFIER_UNIT_NAME,),
    )
    return _PhaseResult(ok=hub_ok)


def _install_clearance_unit_pair(
    *, label: str, install_fn: Callable[[], object], units_to_enable: Iterable[str]
) -> bool:
    """Render the unit file(s), then enable + start each, reporting one stage line."""
    try:
        install_fn()
        for unit in units_to_enable:
            _enable_user_unit(unit)
    except Exception as exc:  # noqa: BLE001 — aggregator uniform error surface
        _stage(label, "FAIL", str(exc))
        return False
    _stage(label, "ok", "installed + enabled")
    return True


# ── Lifecycle helpers ─────────────────────────────────────────────────


def _stop_and_uninstall(stop: Callable[[], None], uninstall: Callable[[], None]) -> None:
    """Best-effort stop + uninstall; lets ``install_systemd_units`` start fresh.

    Both steps soft-fail — the install afterwards is authoritative,
    and a dangling daemon or unit file is reported by the verify step
    below, not by this helper.
    """
    with contextlib.suppress(Exception):
        stop()
    with contextlib.suppress(Exception):
        uninstall()


def _enable_user_unit(unit: str) -> None:
    """``systemctl --user daemon-reload`` + ``enable`` + ``restart`` for *unit*.

    ``restart`` matters for pipx-upgrade scenarios: after
    ``pipx install --force terok-sandbox``, the on-disk venv has fresh
    code but the running daemon holds the old ExecStart's python
    process.  Restarting guarantees the new code is loaded.  Silent
    on hosts without ``systemctl`` so ``--check``-style callers on
    CI images don't crash.
    """
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return
    for argv in (
        [systemctl, "--user", "daemon-reload"],
        [systemctl, "--user", "enable", unit],
        [systemctl, "--user", "restart", unit],
    ):
        subprocess.run(argv, check=False, capture_output=True)  # nosec B603
