# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for [`CredentialDB`][terok_sandbox.CredentialDB] SSH key + assignment methods."""

from __future__ import annotations

from pathlib import Path

import pytest
import sqlcipher3.dbapi2 as sqlcipher

from terok_sandbox.vault.store.db import (
    CredentialDB,
    InvalidScopeName,
    UnsafeCommentError,
    _require_safe_scope,
)


@pytest.fixture()
def db(tmp_path: Path) -> CredentialDB:
    """Return a fresh DB rooted under a per-test tmp dir."""
    return CredentialDB(tmp_path / "vault" / "credentials.db", passphrase="test")


def _store_key(db: CredentialDB, fp: str, *, comment: str = "c") -> int:
    """Insert an SSH key with the given fingerprint; return its id."""
    return db.store_ssh_key(
        key_type="ed25519",
        private_der=b"priv-der-" + fp.encode(),
        public_blob=b"pub-blob-" + fp.encode(),
        comment=comment,
        fingerprint=fp,
    )


class TestStoreAndDedup:
    """Verify store_ssh_key honours the fingerprint uniqueness constraint."""

    def test_insert_new_key_returns_id(self, db: CredentialDB) -> None:
        """First insert of a fingerprint returns a fresh autoincrement id."""
        key_id = _store_key(db, "fp-1")
        assert key_id >= 1

    def test_duplicate_fingerprint_is_no_op_and_returns_same_id(self, db: CredentialDB) -> None:
        """Second INSERT OR IGNORE on the same fingerprint returns the original id."""
        first = _store_key(db, "fp-1", comment="first")
        second = _store_key(db, "fp-1", comment="SECOND")
        assert first == second
        # The original comment is preserved — re-assertion doesn't mutate stored bytes.
        row = db.get_ssh_key_by_fingerprint("fp-1")
        assert row is not None
        assert row.comment == "first"


class TestCountSshKeys:
    """Verify count_ssh_keys feeds VaultStatus.ssh_keys_stored."""

    def test_zero_when_empty(self, db: CredentialDB) -> None:
        """Fresh DB → no keypairs → 0."""
        assert db.count_ssh_keys() == 0

    def test_counts_distinct_fingerprints(self, db: CredentialDB) -> None:
        """One row per fingerprint, regardless of how many scopes hold the key."""
        k1 = _store_key(db, "fp-1")
        _store_key(db, "fp-2")
        db.assign_ssh_key("proj-a", k1)
        db.assign_ssh_key("proj-b", k1)
        assert db.count_ssh_keys() == 2


class TestAssignments:
    """Verify scope → key_id assignment invariants."""

    def test_assign_and_list(self, db: CredentialDB) -> None:
        """Assigned keys appear in list_ssh_keys_for_scope."""
        key_id = _store_key(db, "fp-1")
        db.assign_ssh_key("proj", key_id)
        rows = db.list_ssh_keys_for_scope("proj")
        assert len(rows) == 1
        assert rows[0].fingerprint == "fp-1"

    def test_multi_scope_assignment(self, db: CredentialDB) -> None:
        """A single key can be assigned to multiple scopes."""
        key_id = _store_key(db, "fp-1")
        db.assign_ssh_key("proj-a", key_id)
        db.assign_ssh_key("proj-b", key_id)
        assert {r.id for r in db.list_ssh_keys_for_scope("proj-a")} == {key_id}
        assert {r.id for r in db.list_ssh_keys_for_scope("proj-b")} == {key_id}

    def test_list_scopes_covers_only_nonempty(self, db: CredentialDB) -> None:
        """list_scopes_with_ssh_keys skips unassigned scopes."""
        k1 = _store_key(db, "fp-1")
        _store_key(db, "fp-2")
        db.assign_ssh_key("has-keys", k1)
        assert db.list_scopes_with_ssh_keys() == ["has-keys"]

    def test_unassign_is_idempotent(self, db: CredentialDB) -> None:
        """Unassigning a non-existent assignment is a no-op."""
        key_id = _store_key(db, "fp-1")
        db.unassign_ssh_key("nope", key_id)  # never assigned → idempotent
        assert db.list_ssh_keys_for_scope("nope") == []


class TestDefaults:
    """Defaults belong to scope assignments, never to keys or their comments."""

    def test_first_assignment_is_default_and_additions_preserve_it(self, db: CredentialDB) -> None:
        """First assignment, not key creation order or legacy labels, picks the default."""
        older = _store_key(db, "old", comment="tk-main:proj")
        first = _store_key(db, "first", comment="custom")
        db.assign_ssh_key("proj", first)
        db.assign_ssh_key("proj", older)
        db.assign_ssh_key("proj", older)
        assert db.list_ssh_key_defaults() == {"proj": first}
        assert [r.id for r in db.list_ssh_keys_for_scope("proj")] == [first, older]
        assert [r.id for r in db.load_ssh_keys_for_scope("proj")] == [first, older]

    def test_default_can_be_shared_and_changed_independently(self, db: CredentialDB) -> None:
        """A shared key may be default in several scopes, or in only one."""
        shared, alternate = _store_key(db, "shared"), _store_key(db, "alternate")
        for scope in ("alpha", "beta"):
            db.assign_ssh_key(scope, shared)
            db.assign_ssh_key(scope, alternate)
        assert db.list_ssh_key_defaults() == {"alpha": shared, "beta": shared}
        db.set_default_ssh_key("beta", alternate)
        db.set_ssh_key_comment("alternate", "tk-main:alpha")
        assert db.list_ssh_key_defaults() == {"alpha": shared, "beta": alternate}
        assert [r.id for r in db.list_ssh_keys_for_scope("beta")] == [alternate, shared]

    @pytest.mark.parametrize("missing", [False, True])
    def test_rejecting_unassigned_default_preserves_old_default(
        self, db: CredentialDB, missing: bool
    ) -> None:
        """A missing link cannot clear the previous selection or create a new link."""
        current = _store_key(db, "current")
        target = current + 1 if missing else _store_key(db, "unassigned")
        db.assign_ssh_key("proj", current)
        with pytest.raises(ValueError, match="not assigned"):
            db.set_default_ssh_key("proj", target)
        assert db.list_ssh_key_defaults() == {"proj": current}
        assert db.list_ssh_key_assignments() == [("proj", current)]

    def test_unassign_default_promotes_oldest_remaining(self, db: CredentialDB) -> None:
        """Removal advances deterministically and preserves defaults in other scopes."""
        first, second, third = (_store_key(db, str(i)) for i in range(3))
        for key_id in (first, second, third):
            db.assign_ssh_key("proj", key_id)
        db.assign_ssh_key("other", first)
        db.unassign_ssh_key("proj", first)
        assert db.list_ssh_key_defaults() == {"other": first, "proj": second}
        db.unassign_ssh_key("proj", third)
        assert db.list_ssh_key_defaults()["proj"] == second
        db.unassign_ssh_key("proj", second)
        assert db.list_ssh_key_defaults() == {"other": first}

    def test_delete_promotes_replacements_in_every_scope(self, db: CredentialDB) -> None:
        """Deleting a shared default selects each scope's own remaining key."""
        shared, alpha, beta = (_store_key(db, str(i)) for i in range(3))
        for scope, replacement in (("alpha", alpha), ("beta", beta)):
            db.assign_ssh_key(scope, shared)
            db.assign_ssh_key(scope, replacement)
        db.delete_ssh_key(shared)
        assert db.list_ssh_key_defaults() == {"alpha": alpha, "beta": beta}

    def test_index_rejects_multiple_defaults(self, db: CredentialDB) -> None:
        """SQLite enforces the one-default-per-scope ceiling independently of methods."""
        first, second = _store_key(db, "first"), _store_key(db, "second")
        db.assign_ssh_key("proj", first)
        db.assign_ssh_key("proj", second)
        with pytest.raises(sqlcipher.IntegrityError), db.transaction():
            db._conn.execute(
                "UPDATE ssh_key_assignments SET is_default = 1 WHERE key_id = ?", (second,)
            )
        assert db.list_ssh_key_defaults() == {"proj": first}

    def test_default_flag_rejects_non_boolean_values(self, db: CredentialDB) -> None:
        """The marker cannot hold values outside zero and one."""
        first = _store_key(db, "first")
        db.assign_ssh_key("proj", first)
        with pytest.raises(sqlcipher.IntegrityError), db.transaction():
            db._conn.execute("UPDATE ssh_key_assignments SET is_default = 2")

    @pytest.mark.parametrize("operation", ["select", "unassign", "delete", "replace"])
    def test_outer_transaction_rolls_back_defaults_and_assignments(
        self, db: CredentialDB, operation: str
    ) -> None:
        """Every assignment mutation composes with an enclosing transaction."""
        first, second = _store_key(db, "first"), _store_key(db, "second")
        db.assign_ssh_key("proj", first)
        db.assign_ssh_key("proj", second)
        with pytest.raises(RuntimeError), db.transaction():
            match operation:
                case "select":
                    db.set_default_ssh_key("proj", second)
                case "unassign":
                    db.unassign_ssh_key("proj", first)
                case "delete":
                    db.delete_ssh_key(first)
                case "replace":
                    db.replace_ssh_keys_for_scope("proj", keep_key_id=second)
            raise RuntimeError("abort")
        assert db.list_ssh_key_defaults() == {"proj": first}
        assert db.list_ssh_key_assignments() == [("proj", first), ("proj", second)]
        assert db.count_ssh_keys() == 2

    def test_infra_default_requires_explicit_opt_in(self, db: CredentialDB) -> None:
        """Default selection cannot bypass infrastructure-scope protection."""
        first, second = _store_key(db, "first"), _store_key(db, "second")
        for key_id in (first, second):
            db.assign_ssh_key("%host", key_id, allow_infra=True)
        with pytest.raises(InvalidScopeName):
            db.set_default_ssh_key("%host", second)
        db.set_default_ssh_key("%host", second, allow_infra=True)
        assert db.list_ssh_key_defaults() == {"%host": second}


class TestDefaultMigration:
    """Both DB openers upgrade legacy assignments without interpreting labels."""

    @pytest.mark.parametrize("reader", [False, True])
    def test_v3_assignments_gain_one_default_per_scope(self, tmp_path: Path, reader: bool) -> None:
        """Oldest assignments win independently in each scope, with key-ID tie breaks."""
        from terok_sandbox.vault.daemon.token_broker import _TokenDB
        from terok_sandbox.vault.store.encryption import open_sqlcipher
        from terok_sandbox.vault.store.migrations import (
            SCHEMA_VERSION,
            ensure_credentials_schema,
        )

        path = tmp_path / "legacy.db"
        conn = open_sqlcipher(path, "test")
        conn.execute(
            "CREATE TABLE ssh_key_assignments ("
            "scope TEXT NOT NULL, key_id INTEGER NOT NULL REFERENCES ssh_keys(id) ON DELETE CASCADE,"
            "assigned_at TEXT NOT NULL DEFAULT (datetime('now')), PRIMARY KEY (scope, key_id))"
        )
        ensure_credentials_schema(conn)
        for fingerprint, comment in (("one", "custom"), ("two", "tk-main:alpha")):
            conn.execute(
                "INSERT INTO ssh_keys (key_type, private_der, public_blob, comment, fingerprint)"
                " VALUES ('ed25519', ?, ?, ?, ?)",
                (b"private", b"public", comment, fingerprint),
            )
        conn.executemany(
            "INSERT INTO ssh_key_assignments (scope, key_id, assigned_at) VALUES (?, ?, ?)",
            [
                ("alpha", 1, "2026-01-01"),
                ("alpha", 2, "2026-01-01"),
                ("beta", 2, "2026-01-01"),
                ("beta", 1, "2026-01-02"),
            ],
        )
        conn.execute("PRAGMA user_version = 3")
        conn.commit()
        conn.close()

        opened = (
            _TokenDB(str(path), passphrase="test")
            if reader
            else CredentialDB(path, passphrase="test")
        )
        try:
            assert [r.id for r in opened.load_ssh_keys_for_scope("alpha")] == [1, 2]
            assert [r.id for r in opened.load_ssh_keys_for_scope("beta")] == [2, 1]
            assert opened._conn.execute("PRAGMA user_version").fetchone() == (SCHEMA_VERSION,)
        finally:
            opened._conn.close()

        reopened = CredentialDB(path, passphrase="test")
        try:
            assert reopened.list_ssh_key_defaults() == {"alpha": 1, "beta": 2}
            assert [r.comment for r in reopened.list_all_ssh_keys()] == ["custom", "tk-main:alpha"]
            reopened.set_default_ssh_key("alpha", 2)
        finally:
            reopened.close()
        verified = CredentialDB(path, passphrase="test")
        try:
            assert verified.list_ssh_key_defaults() == {"alpha": 2, "beta": 2}
        finally:
            verified.close()


class TestPublicKey:
    """Public-key display never queries secret columns."""

    @pytest.mark.parametrize("key_type", ["ed25519", "rsa"])
    def test_renders_key_without_reading_private_material(
        self, db: CredentialDB, key_type: str
    ) -> None:
        """The public line matches generation while private column reads are denied."""
        from terok_sandbox.vault.ssh.manager import SSHManager

        result = SSHManager(scope="proj", db=db).mint(key_type=key_type)

        def deny_private_read(action, table, column, *_):
            if action == sqlcipher.SQLITE_READ and table == "ssh_keys" and column == "private_der":
                return sqlcipher.SQLITE_DENY
            return sqlcipher.SQLITE_OK

        db._conn.set_authorizer(deny_private_read)
        assert db.get_ssh_public_key(result["key_id"]) == result["public_line"]
        assert db.get_ssh_public_key(result["key_id"] + 1) is None


class TestCascadeOrphan:
    """Verify orphan cleanup — a key with no remaining assignments is dropped."""

    def test_removing_last_assignment_drops_key(self, db: CredentialDB) -> None:
        """Unassigning the last scope deletes the ssh_keys row too."""
        key_id = _store_key(db, "fp-1")
        db.assign_ssh_key("proj", key_id)
        db.unassign_ssh_key("proj", key_id)
        assert db.get_ssh_key_by_fingerprint("fp-1") is None

    def test_removing_one_of_many_keeps_key(self, db: CredentialDB) -> None:
        """The key survives while any scope still references it."""
        key_id = _store_key(db, "fp-1")
        db.assign_ssh_key("proj-a", key_id)
        db.assign_ssh_key("proj-b", key_id)
        db.unassign_ssh_key("proj-a", key_id)
        assert db.get_ssh_key_by_fingerprint("fp-1") is not None
        # proj-b can still load the key.
        assert {r.id for r in db.list_ssh_keys_for_scope("proj-b")} == {key_id}

    def test_unassign_all_for_scope(self, db: CredentialDB) -> None:
        """unassign_all_ssh_keys wipes every assignment for a scope."""
        k1 = _store_key(db, "fp-1")
        k2 = _store_key(db, "fp-2")
        db.assign_ssh_key("proj", k1)
        db.assign_ssh_key("proj", k2)
        count = db.unassign_all_ssh_keys("proj")
        assert count == 2
        assert db.list_ssh_keys_for_scope("proj") == []


class TestRoutingProjection:
    """Verify the scope-independent listings that feed a routing matrix."""

    def test_list_all_ssh_keys_is_empty_on_fresh_db(self, db: CredentialDB) -> None:
        """No keys stored → empty row axis."""
        assert db.list_all_ssh_keys() == []

    def test_list_all_ssh_keys_spans_scopes_without_duplication(self, db: CredentialDB) -> None:
        """A key shared across scopes appears once; ordering is by id."""
        k1 = _store_key(db, "fp-1", comment="one")
        k2 = _store_key(db, "fp-2", comment="two")
        db.assign_ssh_key("proj-a", k1)
        db.assign_ssh_key("proj-b", k1)  # k1 shared — still one row
        db.assign_ssh_key("proj-b", k2)
        rows = db.list_all_ssh_keys()
        assert [r.id for r in rows] == [k1, k2]
        assert {r.fingerprint for r in rows} == {"fp-1", "fp-2"}

    def test_list_assignments_returns_full_edge_set(self, db: CredentialDB) -> None:
        """Every (scope, key_id) pair is returned, sorted deterministically."""
        k1 = _store_key(db, "fp-1")
        k2 = _store_key(db, "fp-2")
        db.assign_ssh_key("proj-b", k1)
        db.assign_ssh_key("proj-a", k1)
        db.assign_ssh_key("proj-a", k2)
        assert db.list_ssh_key_assignments() == [
            ("proj-a", k1),
            ("proj-a", k2),
            ("proj-b", k1),
        ]


class TestDeleteSshKey:
    """Verify delete_ssh_key drops a key and cascades its assignments."""

    def test_delete_removes_key_and_all_edges(self, db: CredentialDB) -> None:
        """The key vanishes from every scope in one call."""
        key_id = _store_key(db, "fp-del")
        db.assign_ssh_key("proj-a", key_id)
        db.assign_ssh_key("proj-b", key_id)
        assert db.delete_ssh_key(key_id) is True
        assert db.get_ssh_key_by_fingerprint("fp-del") is None
        assert db.list_ssh_key_assignments() == []

    def test_delete_unknown_key_returns_false(self, db: CredentialDB) -> None:
        """Deleting an absent id is a no-op that reports nothing happened."""
        assert db.delete_ssh_key(9999) is False

    def test_delete_rejects_infra_assigned_key_by_default(self, db: CredentialDB) -> None:
        """A key bound to a ``%`` scope is protected from caller-driven delete."""
        key_id = _store_key(db, "fp-infra-del")
        db.assign_ssh_key("%host", key_id, allow_infra=True)
        with pytest.raises(InvalidScopeName, match="reserved for sandbox"):
            db.delete_ssh_key(key_id)
        assert db.get_ssh_key_by_fingerprint("fp-infra-del") is not None

    def test_delete_accepts_infra_assigned_key_with_flag(self, db: CredentialDB) -> None:
        """Infra-aware callers can decommission a key bound to a reserved scope."""
        key_id = _store_key(db, "fp-infra-del-ok")
        db.assign_ssh_key("%host", key_id, allow_infra=True)
        assert db.delete_ssh_key(key_id, allow_infra=True) is True
        assert db.get_ssh_key_by_fingerprint("fp-infra-del-ok") is None


class TestLoadRecords:
    """Verify load_ssh_keys_for_scope returns full records with raw bytes."""

    def test_carries_bytes(self, db: CredentialDB) -> None:
        """The raw DER and public blob round-trip through the DB."""
        key_id = _store_key(db, "fp-raw", comment="hello")
        db.assign_ssh_key("proj", key_id)
        records = db.load_ssh_keys_for_scope("proj")
        assert len(records) == 1
        r = records[0]
        assert r.id == key_id
        assert r.private_der.startswith(b"priv-der-fp-raw")
        assert r.public_blob == b"pub-blob-fp-raw"
        assert r.comment == "hello"
        assert r.fingerprint == "fp-raw"


class TestSetSshKeyComment:
    """Verify set_ssh_key_comment edits the stored comment in place."""

    def test_updates_existing_row(self, db: CredentialDB) -> None:
        """A matching fingerprint has its comment rewritten and id preserved."""
        key_id = _store_key(db, "fp-rename", comment="old@host")
        assert db.set_ssh_key_comment("fp-rename", "new@host") is True
        row = db.get_ssh_key_by_fingerprint("fp-rename")
        assert row is not None
        assert row.id == key_id
        assert row.comment == "new@host"

    def test_unknown_fingerprint_returns_false(self, db: CredentialDB) -> None:
        """Missing fingerprint → returns False, no row touched."""
        _store_key(db, "fp-other", comment="kept")
        assert db.set_ssh_key_comment("fp-missing", "irrelevant") is False
        row = db.get_ssh_key_by_fingerprint("fp-other")
        assert row is not None
        assert row.comment == "kept"

    def test_rejects_unsafe_input(self, db: CredentialDB) -> None:
        """Control characters are refused and the existing comment is preserved."""
        _store_key(db, "fp-safe", comment="safe")
        with pytest.raises(UnsafeCommentError):
            db.set_ssh_key_comment("fp-safe", "bad\x01comment")
        row = db.get_ssh_key_by_fingerprint("fp-safe")
        assert row is not None
        assert row.comment == "safe"


class TestScopeNameGuard:
    """``_require_safe_scope`` blocks path-unsafe and oversized scope names."""

    @pytest.mark.parametrize(
        "bad",
        [
            "",  # empty
            "../escape",  # traversal
            "with/slash",  # slash
            "with\\backslash",  # backslash
            "-starts-with-dash",  # leading dash
            ".hidden",  # leading dot
            "_underscore",  # leading underscore
            "space in name",  # whitespace
            "null\x00char",  # NUL byte
            "a" * 65,  # over the 64-char cap
            "%",  # bare sigil, no infra name
            "%Host",  # infra form is lowercase only
            "%host-suffix",  # infra form allows only [a-z]+
            "%host.x",  # ditto
            "prefix%host",  # sigil only valid at position 0
        ],
    )
    def test_rejects_unsafe_names(self, bad: str) -> None:
        """A representative set of hostile inputs are refused."""
        with pytest.raises(InvalidScopeName):
            _require_safe_scope(bad)

    @pytest.mark.parametrize(
        "good",
        [
            "proj",
            "My-Project",
            "alpha.beta",
            "0xdeadbeef",
            "a" * 64,
            "%host",  # reserved infra scope: krun host-side keypair
            "%vault",  # any %[a-z]+ form is structurally accepted
        ],
    )
    def test_accepts_reasonable_names(self, good: str) -> None:
        """Valid scope identifiers pass the guard silently."""
        _require_safe_scope(good)  # must not raise

    def test_assign_rejects_unsafe_scope(self, db: CredentialDB) -> None:
        """[`CredentialDB.assign_ssh_key`][terok_sandbox.vault.store.db.CredentialDB.assign_ssh_key]
        refuses to persist a hostile scope name."""
        key_id = _store_key(db, "fp-x")
        with pytest.raises(InvalidScopeName):
            db.assign_ssh_key("../evil", key_id)

    def test_assign_rejects_infra_scope_by_default(self, db: CredentialDB) -> None:
        """Caller-driven writes can't target the ``%`` infrastructure space.

        The DB-layer validator is structurally permissive (both forms
        round-trip through it), so a separate user-vs-infra guard at the
        write entry point is what keeps a non-CLI bypass from creating
        keys under ``%host`` or any future reserved name.
        """
        key_id = _store_key(db, "fp-infra")
        with pytest.raises(InvalidScopeName, match="reserved for sandbox"):
            db.assign_ssh_key("%host", key_id)

    def test_assign_accepts_infra_scope_with_explicit_flag(self, db: CredentialDB) -> None:
        """Sandbox internals provisioning ``%host`` opt in explicitly."""
        key_id = _store_key(db, "fp-infra-ok")
        db.assign_ssh_key("%host", key_id, allow_infra=True)  # no raise
        rows = db.list_ssh_keys_for_scope("%host")
        assert len(rows) == 1

    def test_unassign_rejects_infra_scope_by_default(self, db: CredentialDB) -> None:
        """User-facing remove paths can't decommission infra-reserved keys."""
        key_id = _store_key(db, "fp-infra-2")
        db.assign_ssh_key("%host", key_id, allow_infra=True)
        with pytest.raises(InvalidScopeName, match="reserved for sandbox"):
            db.unassign_ssh_key("%host", key_id)

    def test_unassign_accepts_infra_scope_with_explicit_flag(self, db: CredentialDB) -> None:
        """Infra-aware callers can decommission a reserved-scope key."""
        key_id = _store_key(db, "fp-infra-unassign")
        db.assign_ssh_key("%host", key_id, allow_infra=True)
        db.unassign_ssh_key("%host", key_id, allow_infra=True)
        assert db.list_ssh_keys_for_scope("%host") == []

    def test_replace_rejects_infra_scope_by_default(self, db: CredentialDB) -> None:
        """[`CredentialDB.replace_ssh_keys_for_scope`][terok_sandbox.vault.store.db.CredentialDB.replace_ssh_keys_for_scope]
        is gated the same as assign."""
        key_id = _store_key(db, "fp-infra-3")
        with pytest.raises(InvalidScopeName, match="reserved for sandbox"):
            db.replace_ssh_keys_for_scope("%host", keep_key_id=key_id)

    def test_replace_accepts_infra_scope_with_explicit_flag(self, db: CredentialDB) -> None:
        """Infra-aware rotation: old infra keys are revoked, new one survives."""
        old = _store_key(db, "fp-infra-old")
        new = _store_key(db, "fp-infra-new")
        db.assign_ssh_key("%host", old, allow_infra=True)
        db.replace_ssh_keys_for_scope("%host", keep_key_id=new, allow_infra=True)
        rows = db.list_ssh_keys_for_scope("%host")
        assert [r.fingerprint for r in rows] == ["fp-infra-new"]

    def test_unassign_all_rejects_infra_scope_by_default(self, db: CredentialDB) -> None:
        """[`CredentialDB.unassign_all_ssh_keys`][terok_sandbox.vault.store.db.CredentialDB.unassign_all_ssh_keys]
        is gated the same as the single-key form."""
        with pytest.raises(InvalidScopeName, match="reserved for sandbox"):
            db.unassign_all_ssh_keys("%host")

    def test_unassign_all_accepts_infra_scope_with_explicit_flag(self, db: CredentialDB) -> None:
        """``allow_infra=True`` lets sandbox internals drop every infra key."""
        k1 = _store_key(db, "fp-infra-a")
        k2 = _store_key(db, "fp-infra-b")
        db.assign_ssh_key("%host", k1, allow_infra=True)
        db.assign_ssh_key("%host", k2, allow_infra=True)
        removed = db.unassign_all_ssh_keys("%host", allow_infra=True)
        assert removed == 2
        assert db.list_ssh_keys_for_scope("%host") == []
