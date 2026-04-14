# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shared port registry for multi-user isolation.

Every port allocation — infrastructure services and container web ports —
flows through :func:`claim_port`.  Claims are ``flock``-ed files in a
sticky-bit ``/tmp`` directory: the OS manages crash recovery (process
dies → fd closes → flock releases) and cross-user visibility (any user
can probe any file's lock state via ``LOCK_NB``).
"""

from __future__ import annotations

import fcntl
import io
import json
import os
import socket
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

from .paths import port_registry_dir, read_config_section

_DEFAULT_RANGE_START = 18700
_DEFAULT_RANGE_END = 32767


def _resolve_port_range() -> range:
    """Resolve the port allocation range from config or defaults.

    Reads ``network.port_range_start`` / ``network.port_range_end`` from
    the layered config.  Falls back to 18700–32767 (below the typical
    Linux ephemeral range at 32768).
    """
    net = read_config_section("network")
    start = int(net.get("port_range_start", _DEFAULT_RANGE_START))
    end = int(net.get("port_range_end", _DEFAULT_RANGE_END))
    return range(start, end + 1)


PORT_RANGE = _resolve_port_range()
"""Contiguous range for all auto-allocated ports (infra + web)."""

REGISTRY_DIR = port_registry_dir()
"""Shared directory for per-port lock files (sticky-bit protected)."""

SERVICE_GATE = "gate"
SERVICE_PROXY = "proxy"
SERVICE_SSH_AGENT = "ssh_agent"

_LOCALHOST = "127.0.0.1"
_CLAIMS_FILENAME = "port-claims.json"


@dataclass(frozen=True)
class ServicePorts:
    """Resolved infrastructure service ports for one terok session."""

    gate: int
    proxy: int
    ssh_agent: int


class _Claim(NamedTuple):
    """One held port claim — the open *lock_fh* keeps the flock alive."""

    port: int
    lock_fh: io.TextIOWrapper


# Open file handles whose lifetime IS the claim — closing releases the flock.
_held: dict[str, _Claim] = {}
_cached_service_ports: ServicePorts | None = None
_registry_ensured = False


def resolve_service_ports(
    gate_pref: int | None,
    proxy_pref: int | None,
    ssh_pref: int | None,
    *,
    gate_explicit: bool = False,
    proxy_explicit: bool = False,
    ssh_explicit: bool = False,
    state_dir: Path | None = None,
) -> ServicePorts:
    """Resolve and claim infrastructure ports (cached after first call).

    Each *_pref* is a preferred starting port or ``None`` for auto-allocation.
    When ``*_explicit`` is True the port is a hard pin (``SystemExit`` if busy).

    When *state_dir* is provided, port assignments are persisted across
    restarts.  If a previously saved port cannot be reclaimed, the call
    fails with ``SystemExit`` so the user can resolve the conflict.
    """
    global _cached_service_ports  # noqa: PLW0603
    if _cached_service_ports is not None:
        return _cached_service_ports

    saved = _load_saved_ports(state_dir) if state_dir else {}

    # Prefer previously saved ports when no explicit preference is given.
    if not gate_explicit and gate_pref is None:
        gate_pref = saved.get(SERVICE_GATE)
    if not proxy_explicit and proxy_pref is None:
        proxy_pref = saved.get(SERVICE_PROXY)
    if not ssh_explicit and ssh_pref is None:
        ssh_pref = saved.get(SERVICE_SSH_AGENT)

    gate = claim_port(SERVICE_GATE, gate_pref, explicit=gate_explicit)
    proxy = claim_port(SERVICE_PROXY, proxy_pref, explicit=proxy_explicit)
    ssh = claim_port(SERVICE_SSH_AGENT, ssh_pref, explicit=ssh_explicit)

    # Fail-closed: if a saved port was displaced (not explicitly overridden),
    # containers are broken — the user must resolve the conflict.
    explicits = {SERVICE_GATE: gate_explicit, SERVICE_PROXY: proxy_explicit, SERVICE_SSH_AGENT: ssh_explicit}
    for key, port in [(SERVICE_GATE, gate), (SERVICE_PROXY, proxy), (SERVICE_SSH_AGENT, ssh)]:
        expected = saved.get(key)
        if expected is not None and port != expected and not explicits[key]:
            raise SystemExit(
                f"Port {expected} ({key}) was previously assigned but is now taken.\n"
                f"Existing containers expect this port.\n\n"
                f"Options:\n"
                f"  - Resolve the conflict and retry\n"
                f"  - Delete {state_dir / _CLAIMS_FILENAME} to force re-allocation\n"
                f"    (existing containers will need re-creation)"
            )

    if state_dir:
        _save_ports(state_dir, {SERVICE_GATE: gate, SERVICE_PROXY: proxy, SERVICE_SSH_AGENT: ssh})

    _cached_service_ports = ServicePorts(gate=gate, proxy=proxy, ssh_agent=ssh)
    return _cached_service_ports


def claim_port(
    service_key: str,
    preferred: int | None = None,
    *,
    explicit: bool = False,
) -> int:
    """Claim one port via flock in the shared registry.

    Tries *preferred* (or the range start) first, then scans upward.
    The caller's file handle is kept open — the flock (and thus the
    claim) lives exactly as long as this process.
    """
    if service_key in _held:
        return _held[service_key][0]

    _ensure_registry()

    if explicit and preferred is not None:
        if not 1 <= preferred <= 65535:
            raise SystemExit(f"Port {preferred} for {service_key} is not a valid port number")
        if not _try_lock_and_bind(service_key, preferred):
            raise SystemExit(f"Port {preferred} for {service_key} is unavailable")
        return preferred

    # Auto-allocation: clamp preferred to PORT_RANGE, scan with wrap-around.
    start = preferred if preferred in PORT_RANGE else PORT_RANGE.start
    for candidate in range(start, PORT_RANGE.stop):
        if _try_lock_and_bind(service_key, candidate):
            return candidate
    for candidate in range(PORT_RANGE.start, start):
        if _try_lock_and_bind(service_key, candidate):
            return candidate

    raise SystemExit(
        f"No free port for {service_key} in range {PORT_RANGE.start}–{PORT_RANGE.stop - 1}"
    )


def release_port(service_key: str) -> None:
    """Release a previously claimed port (closes the flock fd)."""
    entry = _held.pop(service_key, None)
    if entry is not None:
        entry.lock_fh.close()


def reset_cache() -> None:
    """Release all held ports and clear caches (for testing)."""
    global _cached_service_ports, _registry_ensured  # noqa: PLW0603
    for claim in _held.values():
        claim.lock_fh.close()
    _held.clear()
    _cached_service_ports = None
    _registry_ensured = False


# ---------------------------------------------------------------------------
# Persistent claims (survive process restarts)
# ---------------------------------------------------------------------------


def _load_saved_ports(state_dir: Path) -> dict[str, int]:
    """Load previously saved infra port claims, or empty dict on failure."""
    try:
        return json.loads((state_dir / _CLAIMS_FILENAME).read_text())
    except (OSError, ValueError, TypeError):
        return {}


def _save_ports(state_dir: Path, ports: dict[str, int]) -> None:
    """Persist infra port claims to *state_dir* (best-effort).

    Only writes if *state_dir* already exists — avoids creating
    directories as a side effect (important for test isolation).
    """
    if not state_dir.is_dir():
        return
    try:
        (state_dir / _CLAIMS_FILENAME).write_text(json.dumps(ports))
    except OSError:
        pass  # non-critical — worst case, ports may change on next restart


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _try_lock_and_bind(service_key: str, port: int) -> bool:
    """Attempt to flock *port* and verify it can be bound.

    On success the file handle is stashed in :data:`_held` (keeping the
    flock alive).  On failure the handle is closed immediately.
    """
    if any(c.port == port for c in _held.values()):
        return False
    lock_path = REGISTRY_DIR / f"{port}.lock"
    # O_NOFOLLOW prevents symlink traversal in the shared directory.
    try:
        fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError:
        return False  # symlink, FIFO, or other non-openable node
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        return False
    fh = os.fdopen(fd, "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        return False
    try:
        if not _is_port_free(port):
            fh.close()
            return False
        fh.write(f"{os.getuid()}:{service_key}\n")
        fh.flush()
    except Exception:
        fh.close()
        raise
    _held[service_key] = _Claim(port, fh)
    return True


def _ensure_registry() -> None:
    """Create the registry directory with sticky-bit permissions.

    Fail-closed if the directory is a symlink or lacks the sticky bit
    and we cannot fix it (another user pre-created it insecurely).
    """
    global _registry_ensured  # noqa: PLW0603
    if _registry_ensured:
        return
    REGISTRY_DIR.mkdir(mode=0o1777, exist_ok=True)
    st = os.lstat(REGISTRY_DIR)
    if stat.S_ISLNK(st.st_mode):
        raise SystemExit(f"Port registry dir must not be a symlink: {REGISTRY_DIR}")
    if not stat.S_ISDIR(st.st_mode):
        raise SystemExit(f"Port registry path is not a directory: {REGISTRY_DIR}")
    if not stat.S_IMODE(st.st_mode) & stat.S_ISVTX:
        try:
            REGISTRY_DIR.chmod(0o1777)
        except PermissionError:
            raise SystemExit(
                f"Port registry dir {REGISTRY_DIR} lacks sticky bit"
                " and cannot be fixed (owned by another user)"
            )
    _registry_ensured = True


def _is_port_free(port: int) -> bool:
    """Return True if *port* can be bound on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((_LOCALHOST, port))
        except OSError:
            return False
    return True
