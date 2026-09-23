# SPDX-FileCopyrightText: 2025 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""SSH keypair generation for a project scope.

[`SSHManager`][terok_sandbox.vault.ssh.manager.SSHManager] generates an SSH keypair in memory, stores the private
material in the credential DB, and assigns it to a project scope.  The
generated key never touches the filesystem — the signer serves it over the
per-scope agent socket managed by the vault.

See `.ssh_keypair` for import/export against OpenSSH files and for the
bytes-level keypair vocabulary (``GeneratedKeypair``, fingerprint helpers).
"""

from __future__ import annotations

from itertools import count
from pathlib import Path
from typing import TYPE_CHECKING, TypedDict, cast

from ..store.db import CredentialDB, _require_user_scope
from .keypair import DEFAULT_RSA_BITS, GeneratedKeypair, generate_keypair

if TYPE_CHECKING:
    from terok_sandbox.config import SandboxConfig


class SSHInitResult(TypedDict):
    """Public summary of an ``ssh-init`` invocation."""

    key_id: int
    key_type: str
    fingerprint: str
    comment: str
    public_line: str


class SSHManager:
    """Mints SSH keypairs for a scope and stores them in the vault.

    Each scope may hold multiple keys (e.g. GitHub + GitLab), each with a
    distinct fingerprint.  ``init`` reuses the scope's default key unless
    an explicit comment requests another key or ``force=True`` rotates
    the scope to a new sole key.  ``mint`` always creates an additional
    key without changing an existing default.  Comments are labels only;
    default selection belongs to the scope assignment.

    Two constructors for two ownership stories:

    - ``SSHManager(scope=..., db=...)`` binds the manager to a
      caller-owned [`CredentialDB`][terok_sandbox.CredentialDB].  The manager uses it and
      never closes it.  Right shape for tests and pooled connections.
    - [`SSHManager.open_for_config`][terok_sandbox.vault.ssh.manager.SSHManager.open_for_config]
      opens its own DB via the supplied config's chain seam
      (``cfg.open_credential_db``) and closes it on
      [`close`][terok_sandbox.vault.ssh.manager.SSHManager.close] /
      context exit / garbage collection.  Right shape for one-shot
      CLI commands.  Pass ``db_path`` when the caller already holds a
      runtime path (typically ``VaultStatus.db_path``) so the open
      targets that DB while still using *cfg*'s tier policy.
    """

    def __init__(self, *, scope: str, db: CredentialDB) -> None:
        """Bind the manager to a caller-provided [`CredentialDB`][terok_sandbox.CredentialDB]."""
        self._scope = scope
        self._db = db
        self._owned_db: CredentialDB | None = None

    @classmethod
    def open_for_config(
        cls,
        *,
        scope: str,
        cfg: SandboxConfig,
        db_path: Path | None = None,
        prompt_on_tty: bool = False,
    ) -> SSHManager:
        """Return a manager that owns a connection opened via ``cfg.open_credential_db``.

        *db_path* defaults to ``cfg.db_path``; callers with a runtime
        path override (e.g. the daemon's actual ``VaultStatus.db_path``)
        pass it explicitly.  Tier knobs always come from *cfg* — no
        cross-package fan-out when sandbox adds a new chain tier.
        """
        db = cfg.open_credential_db(db_path, prompt_on_tty=prompt_on_tty)
        manager = cls(scope=scope, db=db)
        manager._owned_db = db
        return manager

    def close(self) -> None:
        """Close the DB connection if this manager opened it (idempotent)."""
        if self._owned_db is not None:
            self._owned_db.close()
            self._owned_db = None

    def __enter__(self) -> SSHManager:
        """Enter the runtime context; returns self."""
        return self

    def __exit__(self, *exc: object) -> None:
        """Close the owned DB on exit."""
        self.close()

    def __del__(self) -> None:
        """Best-effort close on garbage collection."""
        try:
            self.close()
        except Exception:  # noqa: BLE001  # nosec B110 — best-effort __del__ close on GC
            pass

    def init(
        self,
        key_type: str = "ed25519",
        comment: str | None = None,
        force: bool = False,
    ) -> SSHInitResult:
        """Provision a keypair for the scope.

        Args:
            key_type: ``"ed25519"`` (default) or ``"rsa"``.
            comment: An explicit label requests an additional key.
                ``None`` reuses the default key, or generates a
                ``<scope>-<number>`` label when creating the first key.
                An explicit empty string is preserved.
            force: When ``True``, rotate — the new key takes the scope in
                a single transaction that drops every prior assignment.

        Returns:
            Metadata sufficient to display the key to the user or register
            it with a remote.  No filesystem paths.

        Raises:
            InvalidScopeName: if the scope fails validation.  Checked
                *before* any key material is generated so a rejected
                call leaves no orphaned row in ``ssh_keys``.
        """
        _require_user_scope(self._scope)
        with self._db.transaction():
            if not force and comment is None:
                if existing := self._db.list_ssh_keys_for_scope(self._scope):
                    record = existing[0]
                    return SSHInitResult(
                        key_id=record.id,
                        key_type=record.key_type,
                        fingerprint=record.fingerprint,
                        comment=record.comment,
                        public_line=cast(str, self._db.get_ssh_public_key(record.id)),
                    )
            return self._create_key(key_type, comment, rotate=force)

    def mint(self, key_type: str = "ed25519", comment: str | None = None) -> SSHInitResult:
        """Create an additional key, preserving the scope's existing default.

        With no explicit *comment*, use the next unused ``<scope>-<number>``
        label.  The first key assigned to a scope becomes its default.
        """
        _require_user_scope(self._scope)
        with self._db.transaction():
            return self._create_key(key_type, comment, rotate=False)

    def suggested_comment(self) -> str:
        """Return the smallest unused positive ``<scope>-<number>`` label."""
        comments = {row.comment for row in self._db.list_ssh_keys_for_scope(self._scope)}
        return next(
            candidate
            for number in count(1)
            if (candidate := f"{self._scope}-{number}") not in comments
        )

    def _create_key(self, key_type: str, comment: str | None, *, rotate: bool) -> SSHInitResult:
        """Store and assign a new key within the caller's transaction."""
        effective_comment = self.suggested_comment() if comment is None else comment
        keypair = generate_keypair(key_type, comment=effective_comment)
        key_id = self._db.store_ssh_key(
            key_type=keypair.key_type,
            private_der=keypair.private_der,
            public_blob=keypair.public_blob,
            comment=keypair.comment,
            fingerprint=keypair.fingerprint,
        )
        if rotate:
            self._db.replace_ssh_keys_for_scope(self._scope, keep_key_id=key_id)
        else:
            self._db.assign_ssh_key(self._scope, key_id)

        return SSHInitResult(
            key_id=key_id,
            key_type=keypair.key_type,
            fingerprint=keypair.fingerprint,
            comment=keypair.comment,
            public_line=keypair.public_line,
        )


__all__ = ["SSHInitResult", "SSHManager", "DEFAULT_RSA_BITS", "GeneratedKeypair"]
