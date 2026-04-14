# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for security hardening: template validation, path validation, and file permissions."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from terok_sandbox._util._fs import systemd_user_unit_dir, write_sensitive_file
from terok_sandbox._util._templates import render_template


class TestRenderTemplateValidation:
    """Issue #151: render_template must reject control characters in values."""

    def test_rejects_newline_in_value(self, tmp_path: Path) -> None:
        """Newline in a template variable is rejected."""
        tpl = tmp_path / "test.service"
        tpl.write_text("ExecStart={{BIN}}")
        with pytest.raises(ValueError, match="forbidden control characters"):
            render_template(tpl, {"BIN": "/usr/bin/evil\n[Install]"})

    def test_rejects_carriage_return(self, tmp_path: Path) -> None:
        """Carriage return in a template variable is rejected."""
        tpl = tmp_path / "test.service"
        tpl.write_text("ExecStart={{BIN}}")
        with pytest.raises(ValueError, match="forbidden control characters"):
            render_template(tpl, {"BIN": "path\rwith\rcr"})

    def test_rejects_nul(self, tmp_path: Path) -> None:
        """NUL byte in a template variable is rejected."""
        tpl = tmp_path / "test.service"
        tpl.write_text("ExecStart={{BIN}}")
        with pytest.raises(ValueError, match="forbidden control characters"):
            render_template(tpl, {"BIN": "path\x00evil"})

    def test_accepts_clean_values(self, tmp_path: Path) -> None:
        """Normal values without control characters are accepted."""
        tpl = tmp_path / "test.service"
        tpl.write_text("ExecStart={{BIN}} --port={{PORT}}")
        result = render_template(tpl, {"BIN": "/usr/local/bin/terok-gate", "PORT": "9418"})
        assert result == "ExecStart=/usr/local/bin/terok-gate --port=9418"

    def test_error_names_offending_key(self, tmp_path: Path) -> None:
        """Error message identifies which variable was invalid."""
        tpl = tmp_path / "test.service"
        tpl.write_text("{{SAFE}} {{BAD}}")
        with pytest.raises(ValueError, match="BAD"):
            render_template(tpl, {"SAFE": "ok", "BAD": "not\nok"})


class TestSystemdUserUnitDir:
    """Issue #152: _systemd_unit_dir must validate XDG_CONFIG_HOME and refuse root."""

    def test_refuses_root(self) -> None:
        """Raises SystemExit when running as root."""
        with (
            patch("os.geteuid", return_value=0),
            pytest.raises(SystemExit, match="root"),
        ):
            systemd_user_unit_dir()

    def test_rejects_path_outside_home(self) -> None:
        """Raises SystemExit when XDG_CONFIG_HOME is outside $HOME."""
        with (
            patch("os.geteuid", return_value=1000),
            patch.dict(os.environ, {"XDG_CONFIG_HOME": "/etc/evil"}),
            pytest.raises(SystemExit, match="outside the home directory"),
        ):
            systemd_user_unit_dir()

    def test_default_path(self) -> None:
        """Falls back to ~/.config/systemd/user when XDG_CONFIG_HOME is unset."""
        env = {k: v for k, v in os.environ.items() if k != "XDG_CONFIG_HOME"}
        with (
            patch("os.geteuid", return_value=1000),
            patch.dict(os.environ, env, clear=True),
        ):
            result = systemd_user_unit_dir()
        assert result == Path.home() / ".config" / "systemd" / "user"

    def test_valid_xdg_under_home(self, tmp_path: Path) -> None:
        """Accepts XDG_CONFIG_HOME that resolves under $HOME."""
        xdg = tmp_path / "my-config"
        xdg.mkdir()
        with (
            patch("os.geteuid", return_value=1000),
            patch.dict(os.environ, {"XDG_CONFIG_HOME": str(xdg)}),
            patch("pathlib.Path.home", return_value=tmp_path),
        ):
            result = systemd_user_unit_dir()
        assert result == xdg / "systemd" / "user"


class TestWriteSensitiveFile:
    """Issue #153: sensitive files must be created with restrictive permissions."""

    def test_creates_file_with_0600(self, tmp_path: Path) -> None:
        """New file gets mode 0o600."""
        target = tmp_path / "secrets" / "creds.json"
        assert write_sensitive_file(target, '{"key": "val"}\n') is True
        assert target.read_text() == '{"key": "val"}\n'
        assert oct(target.stat().st_mode & 0o777) == oct(0o600)

    def test_parent_dir_is_0700(self, tmp_path: Path) -> None:
        """Parent directory is hardened to 0o700."""
        target = tmp_path / "secrets" / "creds.json"
        write_sensitive_file(target, "{}\n")
        assert oct(target.parent.stat().st_mode & 0o777) == oct(0o700)

    def test_existing_file_not_overwritten(self, tmp_path: Path) -> None:
        """Returns False and leaves existing content untouched."""
        target = tmp_path / "existing.json"
        target.write_text("original")
        assert write_sensitive_file(target, "overwrite") is False
        assert target.read_text() == "original"
