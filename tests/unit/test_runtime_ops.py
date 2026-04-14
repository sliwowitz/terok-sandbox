# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for sandbox_exec, login_command, container_start, container_stop."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from terok_sandbox.runtime import (
    _DEFAULT_LOGIN_COMMAND,
    _START_TIMEOUT,
    _STOP_TIMEOUT_BUFFER,
    container_start,
    container_stop,
    login_command,
    sandbox_exec,
)


class TestSandboxExec:
    """sandbox_exec delegates to podman exec with correct args."""

    @patch("terok_sandbox.runtime.subprocess.run")
    def test_calls_podman_exec(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="ok\n", stderr=""
        )
        result = sandbox_exec("mycontainer", ["cat", "/etc/hostname"])

        mock_run.assert_called_once_with(
            ["podman", "exec", "mycontainer", "cat", "/etc/hostname"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0
        assert result.stdout == "ok\n"

    @patch("terok_sandbox.runtime.subprocess.run")
    def test_custom_timeout(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        sandbox_exec("c1", ["true"], timeout=5)

        assert mock_run.call_args[1]["timeout"] == 5

    @patch("terok_sandbox.runtime.subprocess.run")
    def test_nonzero_returncode_does_not_raise(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="fail"
        )
        result = sandbox_exec("c1", ["false"])

        assert result.returncode == 1
        assert result.stderr == "fail"

    @patch("terok_sandbox.runtime.subprocess.run")
    def test_filenotfounderror_propagates(self, mock_run) -> None:
        mock_run.side_effect = FileNotFoundError("podman")

        with pytest.raises(FileNotFoundError):
            sandbox_exec("c1", ["true"])

    @patch("terok_sandbox.runtime.subprocess.run")
    def test_timeout_expired_propagates(self, mock_run) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="podman", timeout=30)

        with pytest.raises(subprocess.TimeoutExpired):
            sandbox_exec("c1", ["sleep", "99"], timeout=30)


class TestLoginCommand:
    """login_command builds a podman exec -it command list."""

    def test_default_tmux_session(self) -> None:
        result = login_command("proj-cli-1")

        assert result == ["podman", "exec", "-it", "proj-cli-1", *_DEFAULT_LOGIN_COMMAND]

    def test_custom_command(self) -> None:
        result = login_command("proj-cli-1", command=("bash",))

        assert result == ["podman", "exec", "-it", "proj-cli-1", "bash"]

    def test_no_subprocess_call(self) -> None:
        """login_command is pure — it never touches subprocess."""
        with patch("terok_sandbox.runtime.subprocess.run") as mock_run:
            login_command("c1")
            mock_run.assert_not_called()


class TestContainerStart:
    """container_start delegates to podman start."""

    @patch("terok_sandbox.runtime.subprocess.run")
    def test_calls_podman_start(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stderr="")
        result = container_start("proj-cli-1")

        mock_run.assert_called_once_with(
            ["podman", "start", "proj-cli-1"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=_START_TIMEOUT,
        )
        assert result.returncode == 0

    @patch("terok_sandbox.runtime.subprocess.run")
    def test_failure_returns_nonzero(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=125, stderr="Error: no such container\n"
        )
        result = container_start("gone")

        assert result.returncode == 125
        assert "no such container" in result.stderr

    @patch("terok_sandbox.runtime.subprocess.run")
    def test_filenotfounderror_propagates(self, mock_run) -> None:
        mock_run.side_effect = FileNotFoundError("podman")

        with pytest.raises(FileNotFoundError):
            container_start("c1")


class TestContainerStop:
    """container_stop delegates to podman stop --time."""

    @patch("terok_sandbox.runtime.subprocess.run")
    def test_calls_podman_stop_with_default_timeout(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stderr="")
        result = container_stop("proj-cli-1")

        mock_run.assert_called_once_with(
            ["podman", "stop", "--time", "10", "proj-cli-1"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10 + _STOP_TIMEOUT_BUFFER,
        )
        assert result.returncode == 0

    @patch("terok_sandbox.runtime.subprocess.run")
    def test_custom_timeout(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stderr="")
        container_stop("c1", timeout=30)

        args = mock_run.call_args[0][0]
        assert args == ["podman", "stop", "--time", "30", "c1"]
        assert mock_run.call_args[1]["timeout"] == 30 + _STOP_TIMEOUT_BUFFER

    @patch("terok_sandbox.runtime.subprocess.run")
    def test_failure_returns_nonzero(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=125, stderr="Error: no such container\n"
        )
        result = container_stop("gone")

        assert result.returncode == 125

    @patch("terok_sandbox.runtime.subprocess.run")
    def test_filenotfounderror_propagates(self, mock_run) -> None:
        mock_run.side_effect = FileNotFoundError("podman")

        with pytest.raises(FileNotFoundError):
            container_stop("c1")
