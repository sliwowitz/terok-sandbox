# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tmpfs-file backing for the volatile unlock cache.

[`session_cache`][terok_sandbox.vault.store.session_cache] engages this
backing when the kernel key facility is unusable on a host.  The cache
file lives under ``$XDG_RUNTIME_DIR``: a per-login tmpfs that systemd
wipes at the last logout and that never survives a reboot.  The file
has ``0600`` permissions in a ``0700`` directory.  This construction
reproduces the kernel-keyring guarantees: memory-backed, user-only,
gone with the session.  Nothing here touches durable storage.

The file name embeds the same ``(hostname, DB path)`` digest as
[`kernel_keyring.key_description`][terok_sandbox.vault.store.kernel_keyring.key_description],
so the cache for one vault never resolves another's.
"""

from __future__ import annotations

import contextlib
import logging
import os
from pathlib import Path
from typing import Final

from terok_util import write_sensitive_file

from . import kernel_keyring as _kernel_keyring

_logger = logging.getLogger(__name__)

#: Cache directory relative to ``$XDG_RUNTIME_DIR``.
_RUNTIME_RELATIVE: Final = Path("terok") / "vault-session"


def store(passphrase: str, db_path: str | os.PathLike[str]) -> bool:
    """Cache *passphrase* for *db_path* in the session runtime directory.

    Returns:
        True when the cache file was written, False when the session
        runtime directory is unusable or the write failed.
    """
    path = _cache_path(db_path)
    if path is None:
        return False
    # ``write_sensitive_file`` owns the secure write: 0700 parent, 0600
    # file, symlinked-parent refusal, ``O_NOFOLLOW`` on the final path.
    # It creates only, so an existing cache is unlinked first.
    try:
        path.unlink(missing_ok=True)
        return write_sensitive_file(path, passphrase)
    except (OSError, RuntimeError) as exc:
        _logger.warning("session-file cache write failed: %s", exc)
        return False


def load(db_path: str | os.PathLike[str]) -> str | None:
    """Return the passphrase cached for *db_path*, or ``None`` on any miss.

    Silent on every miss, mirroring
    [`kernel_keyring.load`][terok_sandbox.vault.store.kernel_keyring.load].
    An absent file and an unusable runtime directory are both the
    ordinary "locked" outcome, and the next tier handles it.
    """
    path = _cache_path(db_path)
    if path is None:
        return None
    try:
        return path.read_text() or None
    except OSError:
        return None


def forget(db_path: str | os.PathLike[str]) -> bool:
    """Remove the cache file for *db_path*.

    Returns:
        True when the file is gone (removed or never present), False
        when it may still exist.
    """
    path = _cache_path(db_path)
    if path is None:
        return True
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        _logger.warning("session-file cache removal failed: %s", exc)
        return False
    return True


def is_cached(db_path: str | os.PathLike[str]) -> bool:
    """Return ``True`` when a non-empty cache file exists for *db_path*."""
    path = _cache_path(db_path)
    if path is None:
        return False
    with contextlib.suppress(OSError):
        return path.stat().st_size > 0
    return False


def unavailable_reason() -> str | None:
    """Explain why this session cannot hold the cache file, or ``None`` if it can."""
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    if not runtime_dir:
        return "no session runtime directory (XDG_RUNTIME_DIR unset)"
    if not Path(runtime_dir).is_dir():
        return f"session runtime directory missing ({runtime_dir})"
    return None


def _cache_path(db_path: str | os.PathLike[str]) -> Path | None:
    """Return the per-vault cache file path, or ``None`` without a runtime dir."""
    if unavailable_reason() is not None:
        return None
    runtime_dir = os.environ["XDG_RUNTIME_DIR"]
    return Path(runtime_dir) / _RUNTIME_RELATIVE / _kernel_keyring.cache_digest(db_path)


__all__ = [
    "forget",
    "is_cached",
    "load",
    "store",
    "unavailable_reason",
]
