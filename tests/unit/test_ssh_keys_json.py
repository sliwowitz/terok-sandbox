# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for SSH key JSON sidecar management (update_ssh_keys_json)."""

from __future__ import annotations

import json
from pathlib import Path

from terok_sandbox.ssh import SSHInitResult, update_ssh_keys_json


def _result(priv: str = "/k/priv", pub: str = "/k/pub") -> SSHInitResult:
    """Build a minimal SSHInitResult for testing."""
    return SSHInitResult(
        dir="/keys", private_key=priv, public_key=pub, config_path="/keys/config", key_name="id"
    )


class TestUpdateSshKeysJson:
    """Verify update_ssh_keys_json read-modify-write behavior."""

    def test_creates_file_if_missing(self, tmp_path: Path) -> None:
        """Creates ssh-keys.json (and parent dirs) on first call."""
        keys_path = tmp_path / "proxy" / "ssh-keys.json"
        update_ssh_keys_json(keys_path, "proj-a", _result("/a/priv", "/a/pub"))

        data = json.loads(keys_path.read_text())
        assert data == {"proj-a": {"private_key": "/a/priv", "public_key": "/a/pub"}}

    def test_appends_to_existing(self, tmp_path: Path) -> None:
        """Adds a new project without overwriting existing entries."""
        keys_path = tmp_path / "ssh-keys.json"
        keys_path.write_text(json.dumps({"old": {"private_key": "/o", "public_key": "/o.pub"}}))

        update_ssh_keys_json(keys_path, "new", _result("/n", "/n.pub"))

        data = json.loads(keys_path.read_text())
        assert "old" in data
        assert data["new"] == {"private_key": "/n", "public_key": "/n.pub"}

    def test_overwrites_existing_project(self, tmp_path: Path) -> None:
        """Re-running ssh-init for a project updates its entry."""
        keys_path = tmp_path / "ssh-keys.json"
        update_ssh_keys_json(keys_path, "proj", _result("/v1", "/v1.pub"))
        update_ssh_keys_json(keys_path, "proj", _result("/v2", "/v2.pub"))

        data = json.loads(keys_path.read_text())
        assert data["proj"]["private_key"] == "/v2"

    def test_handles_empty_file(self, tmp_path: Path) -> None:
        """Handles a pre-existing empty file (e.g. from lifecycle.start_daemon)."""
        keys_path = tmp_path / "ssh-keys.json"
        keys_path.write_text("")

        update_ssh_keys_json(keys_path, "proj", _result())

        data = json.loads(keys_path.read_text())
        assert "proj" in data
