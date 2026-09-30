# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Human-facing passphrase tier labels stay distinct from stable machine IDs."""

import pytest

from terok_sandbox import PassphraseTier


@pytest.mark.parametrize(
    ("value", "display_name"),
    [
        ("keyring", "desktop keyring"),
        ("kernel-keyring", "session cache"),
        ("systemd-creds", "systemd-creds"),
        ("passphrase-command", "passphrase-command"),
        ("prompt", "prompt"),
    ],
)
def test_display_names_preserve_machine_ids(value: str, display_name: str) -> None:
    """CLI/config and JSON keep their IDs while operators see explicit labels."""
    tier = PassphraseTier(value)
    assert str(tier) == value
    assert tier.display_name == display_name
