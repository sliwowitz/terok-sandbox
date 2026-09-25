# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""The vault TLS bridge's certificate, as ``ensure-bridges.sh`` makes it."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from terok_sandbox.launch import bridges_resource_dir

pytestmark = pytest.mark.skipif(
    not (shutil.which("bash") and shutil.which("openssl")), reason="needs bash and openssl"
)


def _make_cert(tls_dir: Path) -> None:
    """Source the bridge script inertly and make the certificate into *tls_dir*.

    ``mkdir`` is shadowed while sourcing so the script's PID-dir setup never
    touches the real ``/tmp``; the empty environment keeps every bridge down.
    """
    script = bridges_resource_dir() / "ensure-bridges.sh"
    subprocess.run(
        [
            "bash",
            "-c",
            f'mkdir() {{ :; }}; source "{script}"; unset -f mkdir; '
            f'_TEROK_VAULT_TLS_DIR="{tls_dir}"; _terok_make_vault_tls_cert',
        ],
        env={"PATH": "/usr/bin:/bin"},
        check=True,
    )


def _cert_text(tls_dir: Path) -> str:
    """Return openssl's rendering of the certificate in *tls_dir*."""
    return subprocess.run(
        ["openssl", "x509", "-in", tls_dir / "cert.pem", "-noout", "-text"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def test_certificate_is_a_localhost_server_leaf(tmp_path: Path) -> None:
    """A server certificate for localhost only, unable to sign anything else."""
    tls_dir = tmp_path / "vault-tls"
    _make_cert(tls_dir)
    text = _cert_text(tls_dir)
    assert "DNS:localhost, IP Address:127.0.0.1" in text
    assert "CA:FALSE" in text
    assert "TLS Web Server Authentication" in text
    assert (tls_dir / "key.pem").stat().st_mode & 0o077 == 0


def test_existing_certificate_is_kept(tmp_path: Path) -> None:
    """A second shell keeps the first shell's pair and leaves no debris."""
    tls_dir = tmp_path / "bridges" / "vault-tls"
    tls_dir.parent.mkdir()
    _make_cert(tls_dir)
    first = (tls_dir / "cert.pem").read_bytes()
    _make_cert(tls_dir)
    assert (tls_dir / "cert.pem").read_bytes() == first
    assert [p.name for p in tls_dir.parent.iterdir()] == ["vault-tls"]
