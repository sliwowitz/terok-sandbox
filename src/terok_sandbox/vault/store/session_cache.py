# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""The volatile unlock cache — one tier, two backings.

The cache tier of the passphrase chain holds the vault passphrase for
the login session: untimed, cleared by ``vault lock``, gone on reboot.
Its primary backing is the kernel keyring
([`kernel_keyring`][terok_sandbox.vault.store.kernel_keyring]).  On a
host where the kernel facility is unusable, the tier degrades to a
tmpfs session file ([`session_file`][terok_sandbox.vault.store.session_file])
with the same lifetime and exposure — and the status surfaces say so,
so the degradation is never silent.

Callers use this module, not a backing, for every cache operation.
``forget`` clears *both* backings: facility availability can change
between boots, and ``vault lock`` must never leave a live cache behind
in a backing the current boot happens not to prefer.
"""

from __future__ import annotations

import os

from . import kernel_keyring as _kernel_keyring, session_file as _session_file


def store(passphrase: str, db_path: str | os.PathLike[str]) -> bool:
    """Cache *passphrase* for *db_path* in the session's preferred backing."""
    return _backend().store(passphrase, db_path)


def load(db_path: str | os.PathLike[str]) -> str | None:
    """Return the cached passphrase for *db_path*, or ``None`` on any miss."""
    return _backend().load(db_path)


def forget(db_path: str | os.PathLike[str]) -> bool:
    """Clear the cache for *db_path* from both backings.

    Returns:
        True when no backing can still hold the cache, False when either
        removal failed and a live cache may remain.
    """
    kernel_cleared = _kernel_keyring.forget(db_path)
    file_cleared = _session_file.forget(db_path)
    return kernel_cleared and file_cleared


def is_cached(db_path: str | os.PathLike[str]) -> bool:
    """Return ``True`` when the preferred backing holds a cache for *db_path*."""
    return _backend().is_cached(db_path)


def unavailable_reason() -> str | None:
    """Explain why no backing can hold the cache here, or ``None`` when one can."""
    kernel_reason = _kernel_keyring.unavailable_reason()
    if kernel_reason is None:
        return None
    file_reason = _session_file.unavailable_reason()
    if file_reason is None:
        return None
    return f"{kernel_reason}; {file_reason}"


def backing_detail(*, cached: bool) -> str:
    """Human detail for the cache tier in the ``vault status`` chain.

    Separates the states an operator acts on differently: which backing
    serves this session, whether it holds a passphrase, and why the
    tier cannot run at all.
    """
    reason = unavailable_reason()
    if reason is not None:
        return f"unusable here: {reason}"
    kernel_reason = _kernel_keyring.unavailable_reason()
    if kernel_reason is None:
        return "cached in the user keyring" if cached else "no passphrase cached"
    where = f"session file (kernel keyring unusable here: {kernel_reason})"
    return f"cached in a {where}" if cached else f"no passphrase cached — {where}"


def _backend():
    """Return the session's cache backing: kernel keyring, else session file."""
    return _kernel_keyring if _kernel_keyring.unavailable_reason() is None else _session_file


__all__ = [
    "backing_detail",
    "forget",
    "is_cached",
    "load",
    "store",
    "unavailable_reason",
]
