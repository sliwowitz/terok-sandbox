# terok-sandbox

The hardened-Podman runtime that powers [terok](https://terok-ai.github.io/terok/).

terok-sandbox launches per-task containers with a credential vault,
a gated git server, and egress firewall.

![terok ecosystem — terok-sandbox sits between the per-task launcher and the firewall it installs](architecture.svg)

## What it provides

- **Hardened container lifecycle** — rootless Podman containers launched through a `Sandbox` facade,
  services are provided by a supervisor whose lifecycle is managed by the container's OCI hooks
- **Credential vault** — long-lived secrets stay on the host,
  [SQLCipher-encrypted at rest](credentials-encryption.md).  The
  container receives short-lived phantom tokens that are exchanged
  for the real value at the moment of use, scoped per route, audited
  per request.
- **Per-task git gate** — a token-authenticated HTTP mirror of the
  upstream repository.  Tasks clone and push only through the gate;
  the operator chooses whether the gate forwards to upstream
  automatically or only on human review.
- **Shield install + drive** — a thin adapter that installs the
  terok-shield OCI hooks at setup time and drives the firewall at
  runtime (allow / deny / up / down).
- **Clearance composed in-supervisor** — every container gets a
  per-container supervisor, spawned by an OCI hook, that hosts the
  hub, verdict server, and desktop notifier alongside the other
  services; it exits when `podman wait` returns and the poststop hook
  reaps it.  No lingering daemons between tasks; `pgrep terok` is
  empty when no containers are running.  `services.clearance` decides
  who is asked about a refused connection — the operator, nobody
  (muted), or no clearance arm at all; see
  [Clearance prompts](#clearance-prompts).
- **Setup as one call** — `terok-sandbox setup` brings the whole stack
  up idempotently; `terok-sandbox uninstall` undoes it.

## Per-container supervisor

The supervisor composes the vault proxy, git gate, SSH signer,
clearance hub, verdict server, and desktop notifier per container,
each service in its own hardened child process.
Lifecycle, end-to-end:

1. `terok-sandbox prepare` writes a sidecar config to
   `<state_root>/sidecar/<container-name>.json` (state root defaults
   to `~/.local/share/terok/sandbox`) and emits the podman flags for
   the container (the `/run/terok` bind-mount, shield annotations,
   gate token, …) — including a `terok.sandbox.sidecar` annotation
   carrying the sidecar's absolute path.
2. The operator (or the calling orchestrator) runs `podman run`.
3. The OCI `createRuntime` hook installed by `terok-sandbox setup` reads
   the sidecar, then `Popen`s a stdlib-only wrapper that supervises
   `terok-sandbox supervisor <id> <sidecar-path>` — the actual
   long-running asyncio loop.  On non-zero exit the wrapper re-runs
   the supervisor with exponential backoff, up to five attempts.
4. The supervisor brings up a `VerdictServer` and a `ClearanceHub`
   with its desktop notifier subscriber (unless the sidecar says
   `services.clearance: off`), the git `GateServer` (when the sidecar
   wires a gate), and a `VaultProxy` and the SSH signer (in `socket` or
   `tcp` mode per the sidecar); awaits
   `podman wait <id>`; tears
   them down in reverse order on container exit.  Services degrade
   independently — a single failed bring-up (say, a TCP port stolen
   while the container sat stopped) is logged and skipped, never
   fatal to the rest; the container itself starts regardless.
5. The OCI poststop hook SIGTERMs the wrapper PID (recorded under
   `<state_root>/pids/supervisor-<id>.pid`, SIGKILL after a 2 s
   grace) and unlinks the PID file.  The sidecar stays: OCI hooks fire per run-cycle, so a
   later `podman start` re-runs step 3 with the same wiring the
   container's immutable env was created with — restarts come back
   supervised.  The one field a restart may rewrite first is
   `clearance` (see [Clearance prompts](#clearance-prompts)); the
   ports and tokens never change.  The sidecar is removed at real teardown
   (`terok-sandbox cleanup`, terok's task delete) or by the doctor's
   stray sweep once the container is gone.

Operators don't usually invoke `terok-sandbox supervisor` directly —
it's hidden from the main help and spawned by the hook chain — but
running it under a debugger after `terok-sandbox prepare` is a
supported way to step through a faulty composition without involving
podman.

## Clearance prompts

When the shield refuses a connection, the clearance hub can put the
refusal to the operator — as a desktop prompt, or as a row in a
clearance UI such as terok's — and the verdict server applies the
answer.  One setting in the `services:` section of `config.yml`
decides who is asked:

```yaml
services:
  clearance: prompt   # prompt | mute | off
```

| Value | Supervisor runs | The shield | Who is asked |
|-------|-----------------|------------|--------------|
| `prompt` (default) | verdict + clearance | refuses | the operator, live |
| `mute` | verdict + clearance, hub muted from the start | refuses | nobody, until the operator unmutes the task |
| `off` | neither | refuses | nobody, ever |

Whatever the value, the shield records each refused destination in the
container's audit log while `shield.audit` is on (the default) — one
line per destination per 30 seconds, however often it is retried.
Under `mute` and `off` that log is the only record a refusal leaves:
with `shield.audit` off as well, nothing records it at all.

- **`mute` silences the question, not the firewall.**  Every blocked
  connection is still refused, and its destination still recorded in
  the audit log while `shield.audit` is on.  Muting drops the prompt
  and nothing else: nothing is allowed, nothing is auto-denied.  The
  hub keeps running, so the operator can unmute the running task from
  a clearance client; a runtime mute or unmute lasts until the
  container stops, and every start re-applies the configured value.
- **`off` leaves the clearance arm out.**  Refusals stay enforced, but
  nobody is asked and there is no hub to unmute: the supervisor starts
  no clearance hub and no verdict server, so no verdict path exists
  that could widen the firewall, and the task runs two fewer
  processes.  The doctor's supervisor-children check expects neither.
  Grant what a task needs through its egress policy instead — with
  `shield.audit` on, the audit log shows what it reached for.
- **A change applies at the next start of the task** — create,
  recreate, or a terok restart.  The value travels to the supervisor in
  the per-container sidecar, which every `podman start` re-reads.
  Creation writes it; a restart that should honour a changed setting
  rewrites the sidecar's `clearance` field from current config just
  before the start (`Sandbox.clearance_refresh`), the way it refreshes
  the shield's policy tiers, and writes every other field back as it
  was.  terok's restart does this.  A running task keeps the mode it
  started with, and a bare `podman start` replays whatever the sidecar
  last recorded.  Embedded callers set `SandboxConfig(clearance=…)`;
  orchestrators with per-project settings pass the resolved project
  value the same way.
- **A bad value never costs the supervisor.**  An unrecognised value in
  a sidecar is read as `prompt`, with a warning in the supervisor log,
  and a sidecar written before the setting existed prompts as it always
  did.  An invalid value in `config.yml` warns and reads as `prompt`,
  and costs that key alone: `services.mode` beside it keeps what the
  operator wrote, so a typo here cannot quietly undo a `tcp` opt-out.

## Where it sits in the stack

terok-sandbox is the boundary layer.  Above it, single-task callers
([terok-executor](https://github.com/terok-ai/terok-executor)) and
multi-task orchestrators
([terok](https://github.com/terok-ai/terok)) treat the sandbox as a
black-box "give me a hardened container."  Below it, it composes
[terok-shield](https://github.com/terok-ai/terok-shield) for egress
filtering and
[terok-clearance](https://github.com/terok-ai/terok-clearance) for
the operator-in-the-loop verdict path.

The split exists so that callers do not need to understand
nftables, OCI hook wiring, vault sockets, or supervisor lifecycles
to get a safe container.

## Installation

```bash
pip install terok-sandbox
```

For most users this dependency is pulled in transitively by
`terok-executor` or `terok`.  Install it directly only when building
a custom orchestrator on top of the sandbox API.

## Quick start

```python
from pathlib import Path

from terok_sandbox import RunSpec, Sandbox, SandboxConfig

sandbox = Sandbox(SandboxConfig())
sandbox.run(
    RunSpec(
        container_name="task-001",
        image="terok-l1-cli:ubuntu-24.04",
        env={},
        volumes=(),
        command=(),
        task_dir=Path("/var/lib/myapp/task-001"),
    )
)
```

See the developer guide for the full lifecycle and integration
patterns.
