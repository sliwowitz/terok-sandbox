# SPDX-FileCopyrightText: 2025 Jiri Vyskocil
# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Adapter for terok-shield egress firewall.

Two classes carry the sandbox-side policy layer over terok-shield:

* [`ShieldManager`][terok_sandbox.integrations.shield.ShieldManager] —
  per-task wrapper around [`Shield`][terok_shield.Shield].  Caches the
  underlying instance.  The kill-switch (``shield_disabled``) treats each
  method by what it means: lifecycle steps the orchestrator takes on every
  start (``pre_start``, ``refresh``, ``up``, ``down``) and the environment
  probe (``check_environment``) short-circuit; changes an operator asks
  for that widen egress (``bypass``, ``allow``, ``override``) refuse out
  loud; changes that only narrow it (``bypass_off``, ``revoke_override``),
  panic (``quarantine``) and reads of what the container has and did
  (``state``, ``inspect``, ``bypass_remaining``, ``harvest``) always hit
  the real shield; file reads (``dns_tier``, ``rotation_risk``,
  ``container_short_id``) never build one.  ``status`` is config-level
  only and surfaces the kill-switch flag in its dict rather than
  short-circuiting.
* [`ShieldHooks`][terok_sandbox.integrations.shield.ShieldHooks] — the
  host-wide OCI hooks installer, scoped to the root/user dual-scope
  flag pair the ``terok setup`` and ``terok-sandbox`` CLIs expose.
  Delegates to terok-shield's [`HooksInstaller`][terok_shield.HooksInstaller]
  for the actual file writes; terok-shield owns the on-disk install
  layout, so sandbox carries no private mirror of it.

The module also re-exports the vocabulary a promotion engine above it
needs — what an allow or an override returned, what the security tier
refused, what a harvest found and the tier and remedy identifiers it
classifies by — so a consumer matches on shield's own values instead of
spelling them.
"""

from __future__ import annotations

import contextlib
import tempfile
import warnings
from datetime import date
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING

from terok_shield import (
    AllowResult,
    DnsTier,  # noqa: F401 - re-exported
    EnvironmentCheck,  # noqa: F401 - re-exported
    HarvestEntry,  # noqa: F401 - re-exported
    HarvestReport,
    HooksInstaller,
    OverrideRevocation,
    RotationRisk,
    SecurityTierRefusal,  # noqa: F401 - re-exported; ``allow`` lets it propagate unchanged
    Shield,
    ShieldConfig,
    ShieldMode,
    ShieldReading,
    ShieldRuntime,
    ShieldState,  # noqa: F401 - re-exported
    recorded_container_id,
    recorded_rotation_risk,
    validate_target,  # noqa: F401 - re-exported for callers that keep host lists of their own
)
from terok_shield.container import (
    ShieldAnnotations,  # noqa: F401 - re-exported
    resolve_annotations as resolve_container_annotations,  # noqa: F401 - re-exported
    resolve_shield_version as resolve_container_shield_version,  # noqa: F401 - re-exported
    resolve_state_dir as resolve_container_state_dir,  # noqa: F401 - re-exported
)

# The identifiers a harvest classifies each target by — the tier standing in
# the way, the remedies that could lift it.  Shield publishes them from its
# ``harvest`` module only, not its facade; they ride this adapter so a
# promotion engine matches on shield's values instead of spelling them.
from terok_shield.harvest import (  # noqa: F401 - re-exported
    REMEDY_HOST_PORT,
    REMEDY_OVERRIDE,
    REMEDY_PROJECT,
    REMEDY_SET,
    REMEDY_TASK,
    TIER_ALLOWLIST,
    TIER_HARD_DENY,
    TIER_OPERATOR_DENY,
    TIER_PRIVATE,
    TIER_SECURITY,
)

# ``ensure_user_hooks_dir_configured`` lives behind shield's lazy ``__getattr__``
# (so the package's top-level import stays light); pull it from the owning
# submodule for a concrete callable type.
from terok_shield.hooks.install import (
    ensure_user_hooks_dir_configured,  # noqa: F401 - re-exported with concrete type
    user_hooks_dir_configured,  # noqa: F401 - public readiness predicate
)

# Several symbols are exposed via the top-level ``terok_shield.__getattr__``
# lazy importer which returns ``object`` to type-checkers — that breaks
# both ``except`` narrowing on the error classes and concrete typing on
# the prereqs dataclasses.  Pull them straight from the owning submodules.
from terok_shield.prereqs import (  # noqa: F401 - re-exported with concrete types
    BinaryCheck,
    check_firewall_binaries,
    check_krun_binaries,
)
from terok_shield.profiles import UnknownProfileError  # noqa: F401 - re-exported for the CLI
from terok_shield.run import NftNotFoundError  # noqa: F401
from terok_shield.state import (
    BUNDLE_VERSION as BUNDLE_VERSION,  # noqa: F401 - re-exported
    recorded_dns_tier,  # concrete type; the top-level lazy re-export is ``object``
)
from terok_util import SetupCheck

from ..config import SandboxConfig
from ..paths import sandbox_live_root

if TYPE_CHECKING:
    from collections.abc import Iterator

    from terok_shield import HOOK_ENTRYPOINT_NAME  # noqa: F401 - re-export typing

#: Warning emitted by every kill-switch-aware [`ShieldManager`][terok_sandbox.integrations.shield.ShieldManager]
#: method when ``shield_disabled`` is set.  DANGEROUS TRANSITIONAL OVERRIDE —
#: will be removed once terok-shield supports all target podman versions
#: (see terok-shield#71, #101).
_DISABLED_WARNING = (
    "WARNING: shield.disable_firewall_no_protection is set — "
    "the egress firewall is DISABLED.  Containers have unrestricted "
    "network access.  Remove this setting once your podman version "
    "is compatible with terok-shield."
)


# ── Per-task shield manager ─────────────────────────────


class ShieldManager:
    """Per-task wrapper around [`Shield`][terok_shield.Shield].

    Holds the (task_dir, cfg, runtime) tuple a Shield is built from
    and caches the constructed instance — the previous free-function
    surface rebuilt a Shield on every call, which paid the
    ``ShieldConfig`` + collaborator-wiring cost twice for every
    transition pair (``pre_start`` → ``up``, ``up`` → ``down``, …).

    The kill-switch (``shield_disabled`` on the configuration) is honoured
    per method, by what the method means:

    * lifecycle steps the orchestrator takes on every start and stop
      (``pre_start``, ``refresh``, ``up``, ``down``) short-circuit —
      refusing would fail every launch; the environment probe
      (``check_environment``) answers from the configuration alone;
    * changes an operator asks for that widen egress (``bypass``,
      ``allow``, ``override``) refuse with [`RuntimeError`][RuntimeError] —
      sandbox opens nothing while the switch is set, and a change silently
      dropped would read as one made;
    * changes that only narrow it (``bypass_off``, ``revoke_override``)
      and panic (``quarantine``) always run — a container started before
      the switch was thrown keeps its rules, its window and its overrides,
      and a close silently dropped would leave a door open that reads as
      shut.  On a container launched under the switch shield itself
      refuses, since there is nothing to close;
    * reads of the live ruleset (``state``, ``inspect``,
      ``bypass_remaining``) and of the audit log (``harvest``) always run,
      for the same reason: such a container keeps its rules and its record;
    * file reads (``dns_tier``, ``rotation_risk``, ``container_short_id``)
      never build a Shield at all.
    """

    def __init__(
        self,
        task_dir: Path,
        cfg: SandboxConfig | None = None,
        *,
        runtime: ShieldRuntime = ShieldRuntime.DEFAULT,
        loopback_ports_override: tuple[int, ...] | None = None,
    ) -> None:
        """Bind the manager to a task directory and shield configuration.

        *runtime* selects the container runtime category — ``DEFAULT``
        for crun/runc/youki (dnsmasq on netns ``127.0.0.1``), ``KRUN``
        for the libkrun microVM path (dnsmasq on a link-local address
        the guest can reach via passt).  Callers that drive the launch
        path map their runtime string (``RunSpec.runtime``) to the
        enum.

        *loopback_ports_override* replaces the cfg-derived
        ``(gate_port, token_broker_port, ssh_signer_port)`` triple — the
        per-container launch path passes the freshly-allocated broker
        and signer ports so shield's nft rules allow the actual host
        ports the supervisor binds.
        """
        self._task_dir = task_dir
        self._cfg = cfg or SandboxConfig()
        self._runtime = runtime
        self._loopback_ports_override = loopback_ports_override

    @property
    def state_dir(self) -> Path:
        """Per-task shield state directory: ``{task_dir}/shield``."""
        return self._task_dir / "shield"

    @property
    def disabled(self) -> bool:
        """True when ``shield_disabled`` is set on the sandbox configuration."""
        return self._cfg.shield_disabled

    @cached_property
    def shield(self) -> Shield:
        """Lazily constructed [`Shield`][terok_shield.Shield] instance.

        Built from a [`ShieldConfig`][terok_shield.ShieldConfig] whose
        ``loopback_ports`` reflect the *actual* gate/broker/signer
        ports — auto-allocated configs default those fields to ``None``,
        which would otherwise silently produce an empty tuple and a
        shield ruleset with no
        ``tcp dport <p> ip daddr 169.254.1.2 accept`` rules, causing
        container→host TCP traffic to fall through to the
        private-range reject (#156 regression follow-up).
        """
        resolved = self._cfg.with_resolved_ports()
        # ``loopback_ports_override`` wins when set (the per-container
        # launch path's freshly-allocated broker/signer ports).  Falls
        # back to the cfg-resolved triple for callers that haven't been
        # plumbed through yet.  Socket-mode transports emit no loopback
        # traffic; filter ``None`` so the nft rule generator only sees
        # ports that actually exist.
        loopback = (
            self._loopback_ports_override
            if self._loopback_ports_override is not None
            else tuple(
                p
                for p in (resolved.gate_port, resolved.token_broker_port, resolved.ssh_signer_port)
                if p is not None
            )
        )
        config = ShieldConfig(
            state_dir=self.state_dir,
            mode=ShieldMode.HOOK,
            default_profiles=resolved.shield_profiles,
            loopback_ports=loopback,
            audit_enabled=resolved.shield_audit,
            profiles_dir=resolved.shield_profiles_dir,
            runtime=self._runtime,
            dnsmasq_path=resolved.shield_dnsmasq_path,
            bypass_duration=resolved.shield_bypass_duration,
        )
        return Shield(config)

    # ── Kill-switch-aware lifecycle operations ──────────

    def pre_start(
        self,
        container: str,
        *,
        security_deny: tuple[str, ...] = (),
        provider_allow: tuple[str, ...] = (),
        project_allow: tuple[str, ...] = (),
        override: tuple[str, ...] = (),
    ) -> list[str]:
        """Return extra ``podman run`` args for egress firewalling.

        The four tier arguments are the orchestrator's generated policy tiers,
        which shield writes into the bundle so this layer only carries the data:
        *security_deny* → t20 (deny direct-to-vault-host), *provider_allow* → t30
        (provider egress), *project_allow* → t40 (git remote + custom, merged
        with the composed profiles), *override* → t10 (break-glass allow above
        the deny).  Shield owns each tier outright: an empty tuple (the
        default) *clears* that tier, so every call must carry the full
        current data — never rely on a previous launch's content surviving.

        Returns an empty list (no firewall args) when the dangerous
        ``disable_firewall_no_protection`` override is active.

        Propagates [`SetupRequiredError`][terok_util.SetupRequiredError] when
        the podman environment requires one-time hook installation.
        """
        if self.disabled:
            warnings.warn(_DISABLED_WARNING, stacklevel=2)
            return []
        return self.shield.pre_start(
            container,
            security_deny=security_deny,
            provider_allow=provider_allow,
            project_allow=project_allow,
            override=override,
        )

    def refresh(
        self,
        container: str,
        *,
        security_deny: tuple[str, ...] = (),
        provider_allow: tuple[str, ...] = (),
        project_allow: tuple[str, ...] = (),
        override: tuple[str, ...] = (),
    ) -> None:
        """Recompute an existing container's policy bundle before a plain restart.

        Same tier data and owns-and-clears semantics as
        [`pre_start`][terok_sandbox.integrations.shield.ShieldManager.pre_start],
        but for a container that already exists: shield rewrites the tiers and
        regenerates the pre-applied artifacts (``ruleset.nft``, dnsmasq
        config) so the next ``podman start`` enforces *current* policy
        instead of the bundle frozen at creation.  No podman args are
        produced — the container keeps its launch-time configuration.
        """
        if self.disabled:
            warnings.warn(_DISABLED_WARNING, stacklevel=2)
            return
        self.shield.refresh(
            container,
            security_deny=security_deny,
            provider_allow=provider_allow,
            project_allow=project_allow,
            override=override,
        )

    def up(self, container: str, container_id: str) -> None:
        """Set shield to deny-all mode for a running container.

        *container* is the operator-facing podman name (audit-log key);
        *container_id* is the full podman UUID — terok-shield's per-
        container hub socket is keyed on it.  Both are mandatory:
        terok-shield removed the global-hub fallback in
        ``feat/per-container-supervisor``.
        """
        if self.disabled:
            return
        self.shield.up(container, container_id)

    def down(self, container: str, container_id: str, *, disengaged: bool = False) -> None:
        """Switch shield to the DOWN posture (allow egress) for a running container.

        *container* / *container_id* — see
        [`up`][terok_sandbox.integrations.shield.ShieldManager.up].  When
        *disengaged* is True, the container takes the DISENGAGED posture
        instead: nothing is enforced — no deny set, no private-range or
        hard-deny reject.
        """
        if self.disabled:
            return
        self.shield.down(container, container_id, disengaged=disengaged)

    def bypass(self, container: str, duration: str | None = None) -> str:
        """Open the timed bypass window on a running container; return the duration granted.

        The window admits what the allowlist alone would refuse, and nothing
        above it: the t20 security tier (the vault-relayed provider hosts),
        the private ranges and the hard-deny floor sit higher in the chain and
        stay refused while it is open.  It opens in the UP posture only — the
        one chain that reads it; DOWN accepts by default already.  The window
        lives in the kernel: its element's timeout closes it, a rebuild or a
        restart closes it sooner, and nothing renews it.

        *duration* is an nft timeout, a non-zero count and one unit (``30s``,
        ``5m``, ``2h``); ``None`` takes the configured
        ``shield_bypass_duration``.

        Raises:
            RuntimeError: Two refusals with their own messages.  Sandbox's,
                when the kill-switch is set: a disabled shield opens nothing.
                Shield's, when the container's posture is not UP (a stopped
                container included): the message names the posture and says
                to raise the shield first.  A caller that must tell the two
                apart checks
                [`disabled`][terok_sandbox.integrations.shield.ShieldManager.disabled]
                before calling.
            ValueError: When *duration* is not a non-zero nft timeout.
        """
        if self.disabled:
            raise RuntimeError("shield is disabled — there is no window to open")
        return self.shield.bypass(container, duration)

    def bypass_off(self, container: str) -> None:
        """Close the timed bypass window now, before its timeout runs out.

        An operator's close: no lifecycle step takes it.  Closing a window
        that is already closed is harmless — shield flushes the window sets,
        which the UP and DOWN rulesets (DISENGAGED too) declare.  A container with no such
        ruleset (stopped, quarantined, or launched with the shield off) makes
        shield's nft call fail, and that error propagates rather than passing
        for a close.

        Kill-switch: closes anyway, like
        [`quarantine`][terok_sandbox.integrations.shield.ShieldManager.quarantine]
        — a close only ever narrows egress, and a container started before
        the switch was thrown can still have a window open, as
        [`bypass_remaining`][terok_sandbox.integrations.shield.ShieldManager.bypass_remaining]
        reads.  A close silently dropped would leave that window open while
        reading as shut.
        """
        self.shield.bypass_off(container)

    def bypass_remaining(self, container: str) -> int | None:
        """Whole seconds left on the window, or ``None`` when none is open.

        The kernel's own countdown, read from the live ruleset — the window
        half of [`inspect`][terok_sandbox.integrations.shield.ShieldManager.inspect],
        which a caller that also shows the posture should use instead, to pay
        for one listing rather than two.  Only the UP posture reads the window
        set, so any other posture reports ``None``.

        Kill-switch: reads anyway — a container started before the switch was
        thrown can still have a window open.
        """
        return self.shield.bypass_remaining(container)

    # ── Operator grants: promotion and break-glass ──────

    def allow(self, container: str, target: str) -> AllowResult:
        """Allow *target* for this task: live while the container runs, from its next start if not.

        The pass-through a promotion to "this task" takes.  Shield settles
        tier authority before anything changes: a target the t20 security tier
        refuses — that very host, a name under one of its domains, or anything
        resolving to one of its addresses — raises shield's
        ``SecurityTierRefusal``, propagated unchanged, and nothing is granted.
        Only a break-glass
        [`override`][terok_sandbox.integrations.shield.ShieldManager.override]
        gets past that tier.  The refusal is a ``RuntimeError`` subclass, so a
        caller that also handles the kill-switch refusal below catches it
        first.  A ``*.`` target on a DNS tier that resolves names once raises
        shield's ``ShieldNeedsSetup``, also unchanged.

        The returned ``AllowResult`` says how the grant landed: ``live`` with
        the addresses the running ruleset admits now — empty means nothing was
        allowed, and a caller must report it so — or not live, recorded in the
        task's runtime overlay for its next start to apply.

        Kill-switch: refuses with [`RuntimeError`][RuntimeError], like
        [`bypass`][terok_sandbox.integrations.shield.ShieldManager.bypass] —
        sandbox drives no firewall while the switch is set.  A container
        launched under it has no ruleset to allow through, and a grant
        silently dropped would read as one made.
        """
        if self.disabled:
            raise RuntimeError("shield is disabled — there is no ruleset to allow through")
        return self.shield.allow(container, target)

    def override(
        self, container: str, target: str, expires: date | str, *, reason: str
    ) -> list[str]:
        """Break glass for *target* on the running container, through *expires*, for *reason*.

        The one way past the t20 security tier on a live task — direct reach
        to a vault-relayed provider host, a LAN service in a private range.
        Agents keep using the vault for key relaying; the override only adds
        the direct route.  Shield puts *target* in the t10 override set with a
        kernel timeout, so the kernel itself ends it when *expires* runs out (a
        date holds through that day, host local time), and records *reason* on
        the tier entry and in the audit trail.  The hard-deny floor (link-local,
        cloud metadata) is never overridden.

        Both the reason and the expiry are required: shield raises
        ``ValueError`` for an empty *reason*, an *expires* already passed, or a
        target no override can carry, and ``RuntimeError`` when the container
        has no running ruleset or the target resolves to no address.  The grant
        lasts until it expires or the next restart re-derives the tier from the
        orchestrator's policy — persist it there too (``shield.override``) for
        it to outlive this run.

        Returns the addresses opened.

        Kill-switch: refuses with [`RuntimeError`][RuntimeError] — sandbox
        drives no firewall while the switch is set, and a break-glass silently
        dropped would read as one granted.
        """
        if self.disabled:
            raise RuntimeError("shield is disabled — there is no security tier to break glass")
        return self.shield.override(container, target, expires, reason=reason)

    def revoke_override(self, container: str, target: str) -> OverrideRevocation:
        """End *target*'s break-glass on this task now, before its expiry runs out.

        Closes a door [`override`][terok_sandbox.integrations.shield.ShieldManager.override]
        opened, or one the orchestrator authored as ``shield.override``.
        Shield orders the revoke to fail closed — the tier entry goes first, so
        no posture change re-opens it — and raises ``RuntimeError`` when
        *target* has no override in force, rather than passing for a success.
        A revoke stops new connections; those already open run until they
        close.  An override authored in the orchestrator's policy comes back at
        the next restart unless it is removed there too.

        The returned ``OverrideRevocation`` names the addresses closed, those
        another override still in force holds open, and whether the container
        was running (``live``) or the revoke applies from its next start.

        Kill-switch: revokes anyway, like
        [`bypass_off`][terok_sandbox.integrations.shield.ShieldManager.bypass_off]
        — a revoke only ever narrows egress, and a container created before
        the switch was thrown can still hold an override, live or in the
        bundle its next start replays.  Refusing would leave that door open
        while the switch is set.  A container launched under the switch has
        no override, and shield's own refusal says so.
        """
        return self.shield.revoke_override(container, target)

    # ── Always-on operations ────────────────────────────

    def quarantine(self, container: str) -> None:
        """Total network blackout — drop all traffic, log dropped traffic.

        Ignores ``shield_disabled`` because panic overrides the kill-switch.
        """
        self.shield.quarantine(container)

    def harvest(self) -> HarvestReport:
        """Summarise what this container reached for, from its audit log.

        A read, never a policy change.  The ``HarvestReport`` carries the
        entries in review order — what an operator can promote outright first,
        break-glass next, the unreachable floor last — each a ``HarvestEntry``
        with the action the shield took, the tier that stands between the task
        and the target, and the remedies that could lift it.  Its
        ``audit_enabled`` says whether the container was created with audit on:
        with it off the reader recorded nothing, so an empty report is no
        all-clear.  Iterating the report yields its entries.

        Kill-switch: reads anyway — the log is a record of what happened, and a
        container started before the switch was thrown has one worth reading.
        """
        return self.shield.harvest()

    def state(self, container: str) -> ShieldState:
        """Return the live shield state for a running container.

        Queries actual nft state even when the kill-switch is set,
        because containers started *before* it was enabled may still
        have active rules.
        """
        return self.shield.state(container)

    def inspect(self, container: str) -> ShieldReading:
        """Read the container's posture and its timed window from one ruleset listing.

        One ``nft -T`` listing answers both, so a task pane showing the posture
        and the bypass countdown pays for one netns entry rather than two
        ([`state`][terok_sandbox.integrations.shield.ShieldManager.state] plus
        [`bypass_remaining`][terok_sandbox.integrations.shield.ShieldManager.bypass_remaining]),
        and never pairs a posture with a window read a moment apart.  The
        ``ShieldReading`` holds the posture as a ``ShieldState`` and the
        countdown in whole seconds, reported for UP only — the one posture
        whose chain reads the window set.

        Kill-switch: reads anyway, like
        [`state`][terok_sandbox.integrations.shield.ShieldManager.state] — a
        container started before the switch was thrown keeps its live rules.
        """
        return self.shield.inspect(container)

    # ── Configuration probes ────────────────────────────

    @property
    def dns_tier(self) -> DnsTier | None:
        """The DNS tier this task launched with; ``None`` when none was recorded.

        Reads only the recorded tier file — like
        [`status`][terok_sandbox.integrations.shield.ShieldManager.status], it
        pays no Shield wire-up cost.  The tier says what it provides: whether
        its allow sets are ``live``, and a ``hint`` for the operator when not.
        """
        return recorded_dns_tier(self.state_dir)

    @property
    def rotation_risk(self) -> RotationRisk | None:
        """Policy names this task's DNS tier pins to the addresses they resolved to.

        The degraded-tier warning.  On a tier that resolves names itself, a
        provider moving its host to a new address goes unseen until the shield
        re-resolves: an allowlisted name is refused there while the shield is
        UP, a break-glass override stops reaching its host, and — on tiers that
        run no dnsmasq — a denied vault host's new address escapes the deny.
        ``RotationRisk`` keeps those three apart, and its ``lines(posture)``
        words them for a ``ShieldState`` (``None`` for a launch or restart).

        Computed by shield on read from the recorded tier and the authored
        policy, so it never disagrees with what the container runs; ``None``
        when nothing is at risk or nothing was recorded yet.  A file read like
        [`dns_tier`][terok_sandbox.integrations.shield.ShieldManager.dns_tier]:
        no Shield wire-up, and it reads under the kill-switch too — the bundle
        records what the container was launched with, whatever the switch says
        now.
        """
        return recorded_rotation_risk(self.state_dir)

    @property
    def container_short_id(self) -> str | None:
        """The 12-character short id of this task's container, as its OCI hook recorded it.

        The one key every per-container surface shares: the NFLOG reader stamps
        it on each event, and the clearance hub keys its socket and its mutes
        on it.  A caller muting the task or asking whether it is muted names the
        container by this — never by the podman name or a task label, which the
        hub has never seen.  ``None`` until the container's first start.  A
        file read, so it works under the kill-switch and builds no Shield.
        """
        return recorded_container_id(self.state_dir)

    def status(self) -> dict:
        """Return shield status dict from the sandbox configuration.

        Reads only the sandbox configuration — does not instantiate
        the underlying Shield, so callers that only want
        configuration-level shape don't pay the Shield wire-up cost.
        """
        result: dict = {
            "mode": "hook",
            "profiles": list(self._cfg.shield_profiles),
            "audit_enabled": self._cfg.shield_audit,
        }
        if self.disabled:
            result["disable_firewall_no_protection"] = True
        return result

    def check_environment(self) -> EnvironmentCheck:
        """Check the podman environment for shield compatibility.

        Returns a synthetic [`EnvironmentCheck`][terok_shield.EnvironmentCheck]
        flagging the kill-switch when the dangerous disable override is active.
        """
        if self.disabled:
            return _disabled_environment()
        return self.shield.check_environment()

    # ── Operator-facing session helpers ─────────────────

    def interactive_session(self, container: str) -> None:
        """Run the terminal clearance fallback for this task's shield.

        Thin wrapper that spares callers from reaching into
        [`terok_shield.simple_clearance`][terok_shield.simple_clearance]
        and rebuilding the ``state_dir`` themselves.  Refuses to run
        when the D-Bus clearance hub is already handling the session.
        """
        from terok_shield.simple_clearance import run_simple_clearance

        run_simple_clearance(self.state_dir, container)

    def watch_session(self, container: str) -> None:
        """Stream shield blocked-access events for this task as JSON lines.

        Thin wrapper that spares callers from reaching into
        [`terok_shield.watch`][terok_shield.watch] and rebuilding the
        ``state_dir`` themselves.
        """
        from terok_shield.watch import run_watch

        run_watch(self.state_dir, container)


# ── Host-wide OCI hooks ──────────────────────────────────


class ShieldHooks:
    """Host-wide OCI hooks installer — no task context.

    Thin pass-through to terok-shield's
    [`HooksInstaller`][terok_shield.HooksInstaller].  Kept as a class
    so the sandbox setup aggregator can swap it out in tests without
    poking around terok-shield internals.
    """

    @staticmethod
    def check_setup(*, live: bool = False) -> tuple[SetupCheck, ...]:
        """Delegate readiness to Shield, which owns its installation."""
        return HooksInstaller().check_setup(live=live)

    @staticmethod
    def install() -> None:
        """Install global OCI hooks for shield egress firewalling.

        Global hooks are required on all podman versions to survive
        container stop/start cycles (terok-shield#122).  Single
        layout: scripts, ballast, and JSON descriptors all land in
        ``namespace_state_dir("shield") / "hooks"``;
        ``containers.conf`` is patched to register that path.
        """
        HooksInstaller().install()

    @staticmethod
    def uninstall() -> None:
        """Remove the global OCI hooks [`install`][terok_sandbox.integrations.shield.ShieldHooks.install] writes.

        Idempotent — missing files are tolerated.
        """
        HooksInstaller().uninstall()


# ── Kill-switch-aware environment probe (no task context) ────

#: Name prefix of the stand-in project directory each host-level probe makes
#: for itself: ``<sandbox-live>/tasks/_host-probe-<random>/host/shield`` sits
#: two levels below ``tasks/`` exactly as a real task's
#: ``tasks/<project>/<task>/shield`` does, so the AppArmor addendum's
#: ``tasks/*/*/shield/dnsmasq.*`` grant covers the probe the same way it covers
#: a launch.  The leading ``_`` keeps it clear of every project id, which
#: starts with a lowercase letter or a digit.  Each probe owns its directory
#: outright and ``tasks/`` is never removed, so no probe's cleanup can pull a
#: parent from under another probe's setup.
_HOST_PROBE_PREFIX = "_host-probe-"

#: The stand-in task directory inside a probe's own project directory.
_HOST_PROBE_TASK = "host"


def _disabled_environment() -> EnvironmentCheck:
    """The synthetic [`EnvironmentCheck`][terok_shield.EnvironmentCheck] the kill-switch reports."""
    return EnvironmentCheck(
        ok=False,
        health="disabled",
        issues=["disable_firewall_no_protection is set — egress firewall disabled"],
    )


def check_environment(cfg: SandboxConfig | None = None) -> EnvironmentCheck:
    """Probe the podman environment with no task context.

    Returns a synthetic [`EnvironmentCheck`][terok_shield.EnvironmentCheck]
    when ``shield_disabled`` is set; otherwise binds a throwaway
    [`ShieldManager`][terok_sandbox.integrations.shield.ShieldManager] to a
    stand-in task directory and delegates to its
    [`check_environment`][terok_sandbox.integrations.shield.ShieldManager.check_environment].
    Kept as a free function because the setup CLI runs before any task
    directory exists.

    The stand-in has to sit where a real task's would.  Shield picks the DNS
    tier by writing a ``dnsmasq.*`` probe into the state dir and running
    ``dnsmasq --test`` on it, and it fails open — reports the dnsmasq tier —
    when it cannot write the probe at all.  A state dir that was never
    created therefore read as a dnsmasq tier wherever dnsmasq is installed —
    even on an AppArmor host whose confined dnsmasq drives every real launch
    to a static tier (terok-ai/terok#1246); a created one outside the
    addendum's glob would err the other way, refused even with the addendum
    installed.  So the probe creates
    ``<sandbox-live>/tasks/_host-probe-<random>/host/shield`` — inside the
    glob, like a launch — and removes it again however the probe ends.  Two
    probes at once (terok checks from more than one worker) each get their
    own directory, and neither touches the other's.

    Only when sandbox-live cannot be written does it fall back to a bare
    temp dir whose state dir is never created: shield then fails open, the
    answer this probe gave before, rather than crying AppArmor on a host
    that may well have the addendum.
    """
    cfg = cfg or SandboxConfig()
    if cfg.shield_disabled:
        return _disabled_environment()
    with _host_probe_task_dir() as task_dir:
        return ShieldManager(task_dir, cfg).check_environment()


@contextlib.contextmanager
def _host_probe_task_dir() -> Iterator[Path]:
    """Yield the stand-in task dir the host-level probe runs in; remove it on exit.

    Under sandbox-live with its ``shield`` state dir created, when sandbox-live
    can be written; a bare temp dir with no state dir otherwise — see
    [`check_environment`][terok_sandbox.integrations.shield.check_environment]
    for why each.

    The probe's own project directory is made in one ``mkdtemp`` under
    ``tasks/``, a directory no probe ever removes: a parent shared between
    probes and removed by whichever finished last could vanish between one
    probe creating it and making its own directory inside, and push that
    probe onto the fallback — the false dnsmasq answer this probe exists to
    avoid.
    """
    tasks_root = sandbox_live_root() / "tasks"
    try:
        tasks_root.mkdir(parents=True, exist_ok=True)
        workdir = tempfile.TemporaryDirectory(
            prefix=_HOST_PROBE_PREFIX, dir=tasks_root, ignore_cleanup_errors=True
        )
    except OSError:
        with tempfile.TemporaryDirectory() as fallback:
            yield Path(fallback)
        return
    with workdir as tmp:
        task_dir = Path(tmp) / _HOST_PROBE_TASK
        (task_dir / "shield").mkdir(parents=True)
        yield task_dir
