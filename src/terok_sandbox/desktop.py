# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""A task's optional Wayland desktop across its lifetime: launch, restart, verification.

The sandbox facade puts four questions to
[`DesktopAccess`][terok_sandbox.desktop.DesktopAccess] and keeps none of the
answers itself:

- at creation, what the selected mode adds to the container's launch
  ([`prepare`][terok_sandbox.desktop.DesktopAccess.prepare]);
- before a retained container is disturbed, whether its grant can still be
  kept ([`preflight`][terok_sandbox.desktop.DesktopAccess.preflight]);
- before each start, where the desktop is now
  ([`refresh`][terok_sandbox.desktop.DesktopAccess.refresh]);
- after a start, whether the endpoint answers from inside the container
  ([`verify`][terok_sandbox.desktop.DesktopAccess.verify]).

A failure here costs GUI access and a warning, never the task.  The one
exception is a grant that cannot be kept as it was created: that raises
[`WaylandRecreationRequired`][terok_sandbox.wayland.WaylandRecreationRequired],
because starting anyway would hand the container a different desktop, or
none, behind the operator's back.

Everything a grant adds to the launch travels as Podman arguments and
environment on the prepared [`RunSpec`][terok_sandbox.sandbox.RunSpec]; the
command assembly knows nothing about desktops.
"""

from __future__ import annotations

import logging
import subprocess  # nosec B404 - only the timeout type of the runtime's own exec
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from terok_util import sanitize_log_text

from . import wayland
from ._util import _selinux
from .operator_cli import setup_invocation
from .podman_args import (
    CONTAINER_USER_RUNTIME_DIR,
    CONTAINER_WAYLAND_DIR,
    CONTAINER_WAYLAND_SOCKET,
    WAYLAND_RUNTIME_SUBDIR,
    socket_bind_mount,
)
from .supervisor import sidecar
from .wayland import WaylandMode, WaylandRecreationRequired, WaylandSession

if TYPE_CHECKING:
    from collections.abc import Callable

    from .config import SandboxConfig
    from .runtime import ContainerRuntime
    from .sandbox import LifecycleHooks, RunSpec

_logger = logging.getLogger(__name__)

_UNSET_INHERITED = tuple(arg for name in wayland.WAYLAND_ENV_UNSET for arg in ("--unsetenv", name))
"""Keeps an image's own display variables from overriding the selected endpoint."""

_PRIVATE_RUNTIME = (
    "--mount",
    # Podman resolves image USER/--user itself; no UID is assumed here.
    f"type=tmpfs,destination={CONTAINER_USER_RUNTIME_DIR},"
    "tmpfs-mode=0700,U,nosuid,nodev,noexec,notmpcopyup",
)
"""An empty, user-owned ``XDG_RUNTIME_DIR``; the host's is never mounted."""

_PROBE_TIMEOUT = 3
"""Seconds the in-container endpoint probe may take."""


class DesktopAccess:
    """One sandbox's Wayland wiring, from a container's creation to each later start."""

    def __init__(self, cfg: SandboxConfig, runtime: ContainerRuntime) -> None:
        self._cfg = cfg
        self._runtime = runtime

    def prepare(self, spec: RunSpec, *, hooks: LifecycleHooks | None = None) -> RunSpec:
        """Return *spec* with its desktop wired in, and record what was granted.

        Creation is the only moment mounts can be added, so what is recorded
        here stands for the container's lifetime: a request that wires
        nothing now — no reachable desktop for a direct bind, an isolation
        mode without desktop support, a mount that could not be prepared —
        stays without GUI on every later start.
        """
        if spec.wayland == WaylandMode.NONE:
            return spec
        warn = _observer(hooks)
        unwired = replace(spec, extra_args=(*spec.extra_args, *_UNSET_INHERITED))
        session, endpoint = self._grant(spec)
        try:
            sidecar.record_wayland(self._cfg.sidecar_path(spec.container_name), session)
        except (OSError, ValueError) as exc:
            # A mount no restart could account for is not made.
            wayland.warn_wayland(
                spec.wayland, f"cannot record desktop wiring: {exc}", observer=warn
            )
            return unwired
        if endpoint:
            wayland.warn_desktop_access(spec.wayland, observer=warn)
        if session.error:
            wayland.warn_wayland(spec.wayland, session.error, observer=warn)
        self._check_direct_domain(session, warn)
        if not endpoint:
            return unwired
        inherited = {k: v for k, v in spec.env.items() if k not in wayland.WAYLAND_ENV_UNSET}
        return replace(
            unwired,
            extra_args=(*unwired.extra_args, *endpoint, *_PRIVATE_RUNTIME),
            env={
                **inherited,
                "WAYLAND_DISPLAY": CONTAINER_WAYLAND_SOCKET,
                "XDG_RUNTIME_DIR": CONTAINER_USER_RUNTIME_DIR,
            },
        )

    def preflight(self, container_name: str) -> None:
        """Validate retained desktop access without stopping the task or rewriting state.

        Orchestrators call this before disrupting a running task; the
        start-time [`refresh`][terok_sandbox.desktop.DesktopAccess.refresh]
        repeats it, because a desktop may change in between.  A retained
        direct bind needs readable metadata that matches it: missing optional
        state cannot remove a mount Podman already recorded.

        Raises:
            WaylandRecreationRequired: The retained desktop grant cannot be verified.
            RuntimeError: The runtime cannot inspect the retained container reliably.
        """
        saved = self._saved(container_name)
        if saved is not None and saved.mode != WaylandMode.MITM:
            current = saved.refreshed()
            if current.direct_selinux:
                # Only the refusal applies here; the warnings belong to a start.
                self._check_direct_domain(current, None)
        inspection = self._runtime.container(container_name).inspect()
        bound = tuple(
            Path(source)
            for source, target in (inspection.mounts if inspection is not None else ())
            if target == CONTAINER_WAYLAND_SOCKET
        )
        if bound and bound != (saved.bound_socket if saved is not None else None,):
            raise WaylandRecreationRequired(
                "wl-direct recreation required: cannot verify saved desktop access "
                "against the retained compositor bind"
            )

    def refresh(self, container_name: str, *, hooks: LifecycleHooks | None = None) -> None:
        """Point the saved grant at the invoking desktop, as every start must.

        A reboot or a new desktop session moves the compositor socket; the
        container's mounts stay what creation made them.
        """
        warn = _observer(hooks)
        self.preflight(container_name)
        path = self._cfg.sidecar_path(container_name)
        if not path.exists():
            return
        try:
            session = sidecar.update_wayland(path, WaylandSession.refreshed)
            if session.mounted:
                wayland.warn_desktop_access(session.mode, observer=warn)
            self._check_direct_domain(session, warn)
            if session.mode == WaylandMode.MITM and session.mounted:
                self._proxy_directory(container_name)
            if session.error:
                wayland.warn_wayland(session.mode, session.error, observer=warn)
        except (OSError, ValueError) as exc:
            self.preflight(container_name)
            # The saved mode is unknown here, so the warning claims none.
            wayland.emit_warning(
                f"WARNING: Wayland: could not refresh desktop session: {exc}. "
                "Task continues; GUI access may be unavailable.",
                observer=warn,
            )

    def verify(self, container_name: str, *, hooks: LifecycleHooks | None = None) -> None:
        """Probe the endpoint from the container's own security domain; failure stays optional.

        A socket visible on the host proves nothing about what the container
        may reach, so the question is asked from inside.  Only a start that
        was wired at all is probed.
        """
        warn = _observer(hooks)
        session = self._saved(container_name)
        if session is None or not session.wired:
            return
        try:
            handle = self._runtime.container(container_name)
            result = self._runtime.exec(handle, wayland.WAYLAND_PROBE, timeout=_PROBE_TIMEOUT)
            if result.ok:
                return
            detail = result.stderr.strip()
            reason = detail.splitlines()[-1] if detail else "container cannot reach its endpoint"
            _logger.debug(
                "Wayland endpoint probe failed: %s", sanitize_log_text(detail, color=False)
            )
            if result.exit_code == 127:
                wayland.emit_warning(
                    f"WARNING: unable to verify Wayland access (python3 unavailable): {reason}; task continues",
                    observer=warn,
                )
            else:
                log = self._cfg.state_dir / "logs" / f"{handle.id}.log"
                wayland.warn_wayland(session.mode, reason, log=log, observer=warn)
        except Exception as exc:  # noqa: BLE001 - optional diagnostics never fail container startup
            detail = str(exc).strip()
            reason = detail.splitlines()[-1] if detail else type(exc).__name__
            if isinstance(exc, subprocess.TimeoutExpired):
                reason = "timed out"
            wayland.warn_wayland(
                session.mode, f"container endpoint probe failed: {reason}", observer=warn
            )

    def _saved(self, container_name: str) -> WaylandSession | None:
        """The wiring recorded for *container_name*, or ``None`` without a readable sidecar."""
        path = self._cfg.sidecar_path(container_name)
        saved = sidecar.load_sidecar(path) if path.exists() else None
        return saved.wayland if saved is not None else None

    def _grant(self, spec: RunSpec) -> tuple[WaylandSession, tuple[str, ...]]:
        """Decide what *spec*'s container gets for good: the wiring to record, and its arguments.

        No arguments means no mounts, and the session then says so in a way
        every later start respects.
        """
        session = wayland.resolve_session(
            spec.wayland,
            unavailable=(
                "not supported with sealed isolation or the krun runtime"
                if spec.sealed or spec.runtime == "krun"
                else None
            ),
        )
        endpoint = None
        try:
            if not session.disabled_reason:
                endpoint = self._endpoint(spec.container_name, session)
        except (OSError, ValueError) as exc:
            session = WaylandSession(spec.wayland, error=str(exc))
        if endpoint is None:
            withheld = session.disabled_reason or wayland.MOUNTS_NOT_PREPARED
            return replace(session, disabled_reason=withheld), ()
        if session.mode == WaylandMode.DIRECT and _direct_domain_available():
            label = f"label=type:{_selinux.SELINUX_WAYLAND_DIRECT_TYPE}"
            return replace(session, direct_selinux=True), (*endpoint, "--security-opt", label)
        return session, endpoint

    def _endpoint(self, container_name: str, session: WaylandSession) -> tuple[str, str] | None:
        """The Podman option exposing *session*'s endpoint, or ``None`` with nothing to expose.

        The filtered mode mounts the proxy's own directory, which exists
        whether or not a desktop is reachable yet.  The direct mode binds the
        compositor socket itself, and only an existing one.
        """
        if session.mode == WaylandMode.MITM:
            proxy_dir = self._proxy_directory(container_name)
            return "-v", f"{proxy_dir}:{CONTAINER_WAYLAND_DIR}:z,ro"
        if session.upstream is None:
            return None
        return "--mount", socket_bind_mount(session.upstream, CONTAINER_WAYLAND_SOCKET)

    def _proxy_directory(self, container_name: str) -> Path:
        """Ensure the private directory the proxy binds its listener in, and return it."""
        directory = self._cfg.ensure_container_runtime_dir(container_name) / WAYLAND_RUNTIME_SUBDIR
        directory.mkdir(mode=0o700, exist_ok=True)
        return directory

    def _check_direct_domain(
        self, session: WaylandSession, warn: Callable[[str], None] | None
    ) -> None:
        """Hold a direct container to the SELinux domain it was created with.

        A container keeps its creation-time process type: a policy removed
        since cannot be worked around by starting unlabelled, and a policy
        installed since cannot be applied without recreation.
        """
        if session.mode != WaylandMode.DIRECT or not _selinux.is_selinux_enabled():
            return
        installed = _selinux.is_wayland_direct_policy_installed()
        install = f"{setup_invocation()} selinux --with-wayland-direct"
        if session.direct_selinux and not installed:
            raise WaylandRecreationRequired(
                "wl-direct recreation required: the container's SELinux policy was removed; "
                f"restore it with '{install}' or recreate the task"
            )
        if session.wired and not session.direct_selinux:
            reason = (
                "this task was created without the direct-access SELinux domain"
                if installed
                else "the optional direct-access SELinux policy is not installed"
            )
            wayland.emit_warning(
                f"WARNING: Wayland (wl-direct): {reason}. The task keeps its normal SELinux "
                f"domain and GUI access may be denied. Run '{install}' "
                "and recreate the task to enable that domain.",
                observer=warn,
            )


def _observer(hooks: LifecycleHooks | None) -> Callable[[str], None] | None:
    """The warning observer of *hooks*, if any."""
    return hooks.warning if hooks else None


def _direct_domain_available() -> bool:
    """Whether a new direct container can be given its dedicated SELinux domain."""
    return _selinux.is_selinux_enabled() and _selinux.is_wayland_direct_policy_installed()
