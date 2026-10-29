# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Adapter for terok-clearance — clearance hub + verdict server + subscribers.

Re-export catalog: every ``from terok_clearance …`` import in
``terok_sandbox`` lives here.  The contract is enforced by
``.importlinter`` (``terok_clearance`` is a protected module with
``terok_sandbox.integrations.clearance`` as the sole allowed importer).

Clearance runs as two of the per-container supervisor's children: the
verdict child serves
[`VerdictServer`][terok_clearance.VerdictServer], and the clearance
child composes [`ClearanceHub`][terok_clearance.ClearanceHub] +
[`EventSubscriber`][terok_clearance.EventSubscriber] (driven by
[`create_notifier`][terok_clearance.create_notifier]).  TUI clients
multiplex across per-container hub sockets via
[`MultiSocketSubscriber`][terok_clearance.MultiSocketSubscriber].  The
supervisor composes these objects directly, so there is no per-service
systemd install.

``terok_clearance`` is a hard dependency, and there is no clearance
setup phase to skip.  Whether a container runs the two children is
decided per launch by ``services.clearance``: ``off`` and the
supervisor starts neither, ``mute`` and the hub starts with the
container muted.
"""

from terok_clearance import (  # noqa: F401 — re-exported public API
    ALL_NOTIFY_CATEGORIES,
    NOTIFY_BLOCKED,
    NOTIFY_VERDICT,
    ClearanceClient,
    ClearanceEvent,
    ClearanceHub,
    EventSubscriber,
    MultiSocketSubscriber,
    VerdictClient,
    VerdictServer,
    create_notifier,
    default_clearance_socket_path,
)
