# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for :class:`SSHManager` with the DB-backed storage."""

from __future__ import annotations

from pathlib import Path

import pytest

from terok_sandbox.credentials.db import CredentialDB
from terok_sandbox.credentials.ssh import SSHManager


@pytest.fixture()
def db(tmp_path: Path) -> CredentialDB:
    """Return a fresh DB."""
    return CredentialDB(tmp_path / "vault" / "credentials.db")


class TestInit:
    """Verify :meth:`SSHManager.init` contract."""

    def test_creates_key_and_assignment(self, db: CredentialDB) -> None:
        """First init on an empty scope generates + assigns a new key."""
        result = SSHManager(scope="proj", db=db).init()
        assert result["key_id"] >= 1
        assert result["key_type"] == "ed25519"
        assert result["public_line"].startswith("ssh-ed25519 ")
        rows = db.list_ssh_keys_for_scope("proj")
        assert len(rows) == 1
        assert rows[0].id == result["key_id"]

    def test_default_comment_is_tk_main(self, db: CredentialDB) -> None:
        """The default comment is ``tk-main:<scope>`` for signer promotion."""
        result = SSHManager(scope="myproj", db=db).init()
        assert result["comment"] == "tk-main:myproj"

    def test_explicit_comment_overrides(self, db: CredentialDB) -> None:
        """An explicit comment lands verbatim in the stored record."""
        result = SSHManager(scope="myproj", db=db).init(comment="custom")
        assert result["comment"] == "custom"

    def test_idempotent_without_force(self, db: CredentialDB) -> None:
        """Re-running init on a scope that already has a key is a no-op."""
        first = SSHManager(scope="proj", db=db).init()
        second = SSHManager(scope="proj", db=db).init()
        assert first["key_id"] == second["key_id"]
        assert len(db.list_ssh_keys_for_scope("proj")) == 1

    def test_force_rotates(self, db: CredentialDB) -> None:
        """force=True unassigns existing keys and provisions a fresh one."""
        first = SSHManager(scope="proj", db=db).init()
        second = SSHManager(scope="proj", db=db).init(force=True)
        assert first["key_id"] != second["key_id"]
        rows = db.list_ssh_keys_for_scope("proj")
        assert [r.id for r in rows] == [second["key_id"]]

    def test_rsa_keytype(self, db: CredentialDB) -> None:
        """RSA keytype flows through end-to-end."""
        result = SSHManager(scope="proj", db=db).init(key_type="rsa")
        assert result["key_type"] == "rsa"
        assert result["public_line"].startswith("ssh-rsa ")
