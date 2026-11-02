# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Bind a container's credential requests to one task and one credential set."""

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class BrokerContext:
    """Host-issued identity shared by token creation and the container's broker.

    ``scope`` and ``subject`` identify the task's revocable grants.
    ``credential_set`` is the only credential namespace the task may use.
    None of these fields may come from an incoming credential request.
    """

    scope: str
    subject: str
    credential_set: str

    def __post_init__(self) -> None:
        """Refuse incomplete identities instead of falling back to shared credentials."""
        if any(
            not isinstance(value, str) or not value.strip()
            for value in (self.scope, self.subject, self.credential_set)
        ):
            raise ValueError("Broker context requires nonempty scope, subject and credential_set")

    def matches(self, grant: Mapping[str, object]) -> bool:
        """Return whether a live grant belongs to this container's authorization context."""
        return (grant.get("scope"), grant.get("subject"), grant.get("credential_set")) == (
            self.scope,
            self.subject,
            self.credential_set,
        )
