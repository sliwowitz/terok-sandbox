# SPDX-FileCopyrightText: 2025 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shared naming conventions for SSH key files."""


def effective_ssh_key_name(
    scope: str, *, ssh_key_name: str | None = None, key_type: str = "ed25519"
) -> str:
    """Return the SSH key filename to use.

    Precedence:
      1. Explicit *ssh_key_name* (from caller config)
      2. Derived default: ``id_<type>_<scope>``
    """
    if ssh_key_name:
        return ssh_key_name
    algo = "ed25519" if key_type == "ed25519" else "rsa"
    return f"id_{algo}_{scope}"
