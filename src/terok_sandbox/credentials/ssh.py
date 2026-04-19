# SPDX-FileCopyrightText: 2025 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""SSH keypair generation for a project scope.

:class:`SSHManager` generates an SSH keypair in memory, stores the private
material in the credential DB, and assigns it to a project scope.  The
generated key never touches the filesystem — the signer serves it over the
per-scope agent socket managed by the vault.

See :mod:`.ssh_keypair` for import/export against OpenSSH files and for the
bytes-level keypair vocabulary (``GeneratedKeypair``, fingerprint helpers).
"""

from __future__ import annotations

from typing import TypedDict

from .db import CredentialDB
from .ssh_keypair import DEFAULT_RSA_BITS, GeneratedKeypair, generate_keypair


class SSHInitResult(TypedDict):
    """Public summary of an ``ssh-init`` invocation."""

    key_id: int
    key_type: str
    fingerprint: str
    comment: str
    public_line: str


class SSHManager:
    """Generates SSH keypairs for a scope and stores them in the vault.

    Each scope may hold multiple keys (e.g. GitHub + GitLab), each with a
    distinct fingerprint.  ``init`` is additive by default: re-running on an
    already-provisioned scope returns the most recently registered key
    without disturbing anything.  ``force=True`` rotates — unassigns every
    existing key from the scope (cascade-deleting orphans) and installs a
    fresh one.
    """

    def __init__(self, *, scope: str, db: CredentialDB) -> None:
        self._scope = scope
        self._db = db

    def init(
        self,
        key_type: str = "ed25519",
        comment: str | None = None,
        force: bool = False,
    ) -> SSHInitResult:
        """Provision a keypair for the scope.

        Args:
            key_type: ``"ed25519"`` (default) or ``"rsa"``.
            comment: Comment to embed in the public key.  Defaults to
                ``tk-main:<scope>`` so the signer can promote the primary
                workspace key to the front of the identity list.
            force: When ``True``, rotate — unassign every currently
                assigned key from the scope and generate a new one.

        Returns:
            Metadata sufficient to display the key to the user or register
            it with a remote.  No filesystem paths.
        """
        if force:
            self._db.unassign_all_ssh_keys(self._scope)
        else:
            existing = self._db.list_ssh_keys_for_scope(self._scope)
            if existing:
                return self._result_from_row(existing[-1])

        comment = comment or f"tk-main:{self._scope}"
        keypair = generate_keypair(key_type, comment=comment)
        key_id = self._db.store_ssh_key(
            key_type=keypair.key_type,
            private_pem=keypair.private_pem,
            public_blob=keypair.public_blob,
            comment=keypair.comment,
            fingerprint=keypair.fingerprint,
        )
        self._db.assign_ssh_key(self._scope, key_id)
        return SSHInitResult(
            key_id=key_id,
            key_type=keypair.key_type,
            fingerprint=keypair.fingerprint,
            comment=keypair.comment,
            public_line=keypair.public_line,
        )

    def _result_from_row(self, row) -> SSHInitResult:
        """Render an :class:`SSHInitResult` from an existing DB row."""
        records = self._db.load_ssh_keys_for_scope(self._scope)
        record = next(r for r in records if r.id == row.id)
        return SSHInitResult(
            key_id=row.id,
            key_type=row.key_type,
            fingerprint=row.fingerprint,
            comment=row.comment,
            public_line=_public_line(record.key_type, record.public_blob, record.comment),
        )


def _public_line(key_type: str, public_blob: bytes, comment: str) -> str:
    """Render the one-line OpenSSH public key form ``<type> <base64> <comment>``."""
    import base64

    algo = "ssh-ed25519" if key_type == "ed25519" else "ssh-rsa"
    b64 = base64.b64encode(public_blob).decode("ascii")
    return f"{algo} {b64} {comment}".rstrip()


__all__ = ["SSHInitResult", "SSHManager", "DEFAULT_RSA_BITS", "GeneratedKeypair"]
