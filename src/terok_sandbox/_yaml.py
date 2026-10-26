# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Write-back for the few sandbox sites that mutate config files, and for secrets.

Config edits go through the shared round-trip YAML facade
([`terok_util.yaml`][terok_util.yaml]) and are written as operator-owned
config ([`write_config_file`][terok_util.fs.write_config_file]).
Secrets get [`write_secret_text`][terok_sandbox._yaml.write_secret_text]
instead: atomic, and always ``0o600``.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from terok_util import write_config_file
from terok_util.yaml import dump, load

__all__ = ["update_section", "write_secret_text"]


def update_section(path: Path, section: str, updates: dict[str, Any]) -> None:
    """Merge *updates* into ``data[section]`` at *path*, preserving comments.

    The file is operator-owned config: an existing one is rewritten in
    place and keeps its symlinks, mode and owner, and a new one is
    created ``0o600``.
    """
    existing = (load(path.read_text(encoding="utf-8")) or {}) if path.exists() else {}
    if not isinstance(existing, dict):
        raise ValueError(
            f"{path} top-level is {type(existing).__name__}, expected a mapping;"
            " refusing to silently overwrite — fix or move aside the file by hand"
        )
    # ``setdefault`` returns whatever sits at the key — a stale scalar
    # written by a previous schema version would explode on ``.update``.
    if not isinstance(existing.get(section), dict):
        existing[section] = {}
    existing[section].update(updates)
    write_config_file(path, dump(existing))


def write_secret_text(path: Path, text: str) -> None:
    """Atomically create-or-replace *path* with mode 0o600.

    Writes a temp file in the same directory, fsyncs, then
    ``os.replace``s it onto *path*.  A crash mid-write leaves either
    the old file intact or no file at all — never a truncated one.
    ``mkstemp`` opens with mode 0o600 from the kernel, so a passphrase
    never has a window of world-readable visibility.
    """
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        # POSIX ``write`` is allowed to return a short count; loop until
        # the full payload is committed.  A truncated vault.passphrase
        # would lock the operator out of the vault.
        data = memoryview(text.encode("utf-8"))
        while data:
            data = data[os.write(fd, data) :]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(tmp_path, path)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        tmp_path.unlink(missing_ok=True)
        raise
