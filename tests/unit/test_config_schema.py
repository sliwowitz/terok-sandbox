# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the sandbox-owned slice of ``config.yml``.

Two layers of validation matter here, and the tests pin both:

1. **Owned sub-sections are strict.** A typo inside a section that
   sandbox owns (e.g. ``paths.rooot``) must surface as a pydantic error
   so users notice — sandbox is the source of truth for these keys.
2. **Top-level is tolerant.** Unknown sections (terok's ``tui:``,
   executor's ``image:``, future-package keys we haven't seen yet)
   pass through silently when sandbox is run standalone.  The
   alternative — vendoring a list of foreign keys into sandbox — would
   invert the dep hierarchy.
"""

from __future__ import annotations

from typing import get_args

import pytest
from pydantic import ValidationError

from terok_sandbox.config_schema import (
    ClearanceMode,
    RawCredentialsSection,
    RawHooksSection,
    RawNetworkSection,
    RawPathsSection,
    RawRunSection,
    RawServicesSection,
    RawShieldSection,
    RawSSHSection,
    RawVaultSection,
    SandboxConfigView,
)
from tests.constants import MOCK_HOST_BIN

# ── Owned sub-section strictness ──────────────────────────────────────


def test_paths_section_rejects_typo_in_owned_key() -> None:
    """``extra="forbid"`` on owned sections turns ``paths.rooot`` into a clear error."""
    with pytest.raises(ValidationError) as excinfo:
        RawPathsSection.model_validate({"rooot": "/tmp"})
    assert "Extra inputs are not permitted" in str(excinfo.value)


def test_paths_section_accepts_known_keys() -> None:
    """Documented keys validate cleanly — no false-positive rejections."""
    section = RawPathsSection.model_validate(
        {"root": "/v", "build_dir": "/b", "user_projects_dir": "/p"}
    )
    assert section.root == "/v"
    assert section.build_dir == "/b"


def test_network_section_rejects_inverted_port_range() -> None:
    """The model-level validator catches ``start > end`` instead of letting it through."""
    with pytest.raises(ValidationError, match="port_range_start must be <= port_range_end"):
        RawNetworkSection.model_validate({"port_range_start": 32700, "port_range_end": 18700})


def test_credentials_section_rejects_removed_plaintext_passphrase() -> None:
    """The removed plaintext tier fails with migration directions, not pydantic noise."""
    with pytest.raises(ValidationError, match="passphrase_command: cat /path/to/that/file"):
        RawCredentialsSection.model_validate({"passphrase": "hunter2"})


def test_credentials_section_accepts_explicit_null_passphrase() -> None:
    """``passphrase: null`` (a commented-out-then-nulled config) stays valid."""
    section = RawCredentialsSection.model_validate({"passphrase": None})
    assert section.passphrase is None


def test_vault_section_rejects_out_of_range_port() -> None:
    """Pydantic's numeric constraint surfaces a port outside ``[1, 65535]``."""
    with pytest.raises(ValidationError):
        RawVaultSection.model_validate({"port": 70000})


def test_shield_section_rejects_unknown_on_task_restart() -> None:
    """``Literal["retain", "up"]`` keeps typos like ``"restart"`` out."""
    with pytest.raises(ValidationError):
        RawShieldSection.model_validate({"on_task_restart": "restart"})


def test_shield_section_rejects_profiles_key() -> None:
    """The ``shield:`` section names no profiles; ``SandboxConfig.shield_profiles`` does."""
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RawShieldSection.model_validate({"profiles": {"dev-standard": {}}})


# ── shield.bypass_duration ────────────────────────────────────────────

USABLE_DURATIONS = ("1s", "30s", "5m", "2h", "1d", "05m", "90m")
"""Window durations shield can arm: a non-zero count and one unit."""

UNUSABLE_DURATIONS = ("0s", "00m", "5min", "1h30m", "5", "m", "", " 5m", "5m ", "-5m", "5M", "5ms")
"""Typos and zeros shield refuses to arm — a zero count would be a window that never closes."""


@pytest.mark.parametrize("value", USABLE_DURATIONS)
def test_shield_bypass_duration_keeps_a_duration_shield_can_arm(
    value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert RawShieldSection.model_validate({"bypass_duration": value}).bypass_duration == value
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("value", [*UNUSABLE_DURATIONS, 300, None, True])
def test_shield_bypass_duration_falls_back_for_that_key_alone(
    value: object, capsys: pytest.CaptureFixture[str]
) -> None:
    """A typo shows at load, not when an operator opens a window — and costs only itself.

    Rejecting it would reset the whole ``shield:`` section, kill-switch included,
    and in terok, whose global config composes this section, the whole file.
    """
    section = RawShieldSection.model_validate(
        {
            "bypass_duration": value,
            "disable_firewall_no_protection": True,
            "audit": False,
            "dnsmasq_path": str(MOCK_HOST_BIN / "dnsmasq"),
        }
    )
    assert section.bypass_duration == RawShieldSection().bypass_duration
    assert section.disable_firewall_no_protection is True
    assert section.audit is False
    assert section.dnsmasq_path == MOCK_HOST_BIN / "dnsmasq"
    err = capsys.readouterr().err
    assert "invalid shield.bypass_duration" in err
    assert repr(value) in err


def test_shield_bypass_duration_default_is_one_shield_can_arm() -> None:
    """The fallback must itself be usable, or falling back would only move the error."""
    from terok_shield.nft.rules import arm_bypass_window

    arm_bypass_window(RawShieldSection().bypass_duration)


@pytest.mark.parametrize("value", [*USABLE_DURATIONS, *UNUSABLE_DURATIONS])
def test_shield_bypass_duration_grammar_is_shields(value: str) -> None:
    """Sandbox keeps exactly what shield arms, and what shield's own config file accepts.

    The grammar is spelled in sandbox because its schema may not import shield;
    this keeps the two from drifting apart.
    """
    from terok_shield.config_file import ShieldFileConfig
    from terok_shield.nft.rules import arm_bypass_window

    try:
        arm_bypass_window(value)
        shield_arms = True
    except ValueError:
        shield_arms = False
    try:
        ShieldFileConfig.model_validate({"bypass_duration": value})
        shield_loads = True
    except ValidationError:
        shield_loads = False
    kept = RawShieldSection.model_validate({"bypass_duration": value}).bypass_duration == value
    assert kept == shield_arms == shield_loads


def test_view_keeps_the_rest_of_the_config_past_a_bad_bypass_duration() -> None:
    """terok validates its whole global config through this view: a duration typo
    must not reset the file — the kill-switch and the other sections stay as written."""
    view = SandboxConfigView.model_validate(
        {
            "shield": {"bypass_duration": "5min", "disable_firewall_no_protection": True},
            "services": {"mode": "tcp", "clearance": "off"},
        }
    )
    assert view.shield.bypass_duration == RawShieldSection().bypass_duration
    assert view.shield.disable_firewall_no_protection is True
    assert view.services.mode == "tcp"
    assert view.services.clearance == "off"


# ── services.clearance ────────────────────────────────────────────────


def test_services_clearance_defaults_to_prompt() -> None:
    """Unset, the operator is asked — the behaviour every task had before the setting."""
    assert RawServicesSection.model_validate({}).clearance == "prompt"


@pytest.mark.parametrize("value", ["prompt", "mute", "off"])
def test_services_clearance_accepts_each_value(value: str) -> None:
    assert RawServicesSection.model_validate({"clearance": value}).clearance == value


@pytest.mark.parametrize("value", ["silent", "Mute", "", True, False, None, 0, ["off"]], ids=repr)
def test_services_clearance_falls_back_for_that_key_alone(
    value: object, capsys: pytest.CaptureFixture[str]
) -> None:
    """A YAML boolean or a case variant is a typo to surface, not a mode to guess at —
    surfaced as a warning at load, at the cost of this key alone.

    Rejecting it would reset the whole ``services:`` section, so a typo here would
    quietly undo the SELinux ``tcp`` opt-out in ``mode`` — and in terok, whose global
    config composes this section, the whole file.
    """
    section = RawServicesSection.model_validate({"mode": "tcp", "clearance": value})
    assert section.clearance == RawServicesSection().clearance
    assert section.mode == "tcp"
    err = capsys.readouterr().err
    assert "invalid services.clearance" in err
    assert repr(value) in err


@pytest.mark.parametrize("value", ["prompt", "mute", "off"])
def test_services_clearance_keeps_a_known_mode_quietly(
    value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert RawServicesSection.model_validate({"clearance": value}).clearance == value
    assert capsys.readouterr().err == ""


def test_services_section_stays_strict_on_its_keys() -> None:
    """The new key keeps ``extra="forbid"``: a misspelt ``clearance`` is still an error."""
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RawServicesSection.model_validate({"clearence": "off"})


def test_clearance_mode_is_the_field_vocabulary() -> None:
    """The exported alias names exactly the values the field accepts, and nothing else."""
    assert get_args(ClearanceMode) == ("prompt", "mute", "off")
    assert RawServicesSection.model_fields["clearance"].annotation == ClearanceMode


def test_view_carries_services_clearance() -> None:
    """The view terok's global config inherits validates the key in its ``services:`` section."""
    view = SandboxConfigView.model_validate({"services": {"mode": "tcp", "clearance": "off"}})
    assert view.services.clearance == "off"
    assert view.services.mode == "tcp"


def test_view_keeps_the_rest_of_the_config_past_a_bad_clearance() -> None:
    """terok validates its whole global config through this view: a clearance typo
    must not reset the file — ``mode``, the kill-switch and the other sections stay."""
    view = SandboxConfigView.model_validate(
        {
            "services": {"mode": "tcp", "clearance": "silent"},
            "shield": {"disable_firewall_no_protection": True, "audit": False},
        }
    )
    assert view.services.clearance == RawServicesSection().clearance
    assert view.services.mode == "tcp"
    assert view.shield.disable_firewall_no_protection is True
    assert view.shield.audit is False


def test_ssh_section_use_personal_defaults_to_none() -> None:
    """``None`` (not False) is the default so layered configs can distinguish unset."""
    section = RawSSHSection.model_validate({})
    assert section.use_personal is None


def test_run_section_defaults_runtime_to_none_so_layers_can_distinguish_unset() -> None:
    """``runtime: None`` (not ``"crun"``) at the field level lets the orchestrator
    tell "operator didn't set it" from "operator picked crun explicitly" — the
    distinction matters when project values inherit/override global values.
    """
    section = RawRunSection.model_validate({})
    assert section.runtime is None
    assert section.shutdown_timeout == 10
    assert section.nested_containers is False
    assert section.hooks == RawHooksSection()


def test_run_section_rejects_legacy_podman_value() -> None:
    """``"podman"`` was the v0 value name and is now invalid.  Hard error
    rather than silent acceptance — the new value is ``"crun"`` (the
    actual OCI runtime podman drives by default).
    """
    with pytest.raises(ValidationError, match="runtime"):
        RawRunSection.model_validate({"runtime": "podman"})


@pytest.mark.parametrize(
    ("value", "expected"),
    [(True, True), (False, False), ("all", "all"), ("nvidia,amd", "nvidia,amd"), (None, None)],
    ids=repr,
)
def test_run_section_gpus_accepts_selector_shapes(value: object, expected: object) -> None:
    """Booleans, selector strings, and None pass through unchanged."""
    assert RawRunSection.model_validate({"gpus": value}).gpus == expected


@pytest.mark.parametrize("value", [0, 1, 1.0], ids=repr)
def test_run_section_gpus_rejects_numeric(value: object) -> None:
    """``gpus: 1`` must not lax-coerce into ``True`` and enable every GPU."""
    with pytest.raises(ValidationError, match="gpus"):
        RawRunSection.model_validate({"gpus": value})


def test_run_section_gpus_rejects_unknown_vendor() -> None:
    """Unknown vendor tokens fail at parse time — even alongside ``all``."""
    with pytest.raises(ValidationError, match="matrox"):
        RawRunSection.model_validate({"gpus": "all,matrox"})


def test_run_section_blank_memory_cpus_normalised_to_none() -> None:
    """An accidentally-empty ``memory: ""`` in YAML reads as None rather
    than as the literal empty string, so podman doesn't receive a bare
    ``--memory ""`` flag."""
    section = RawRunSection.model_validate({"memory": "  ", "cpus": ""})
    assert section.memory is None
    assert section.cpus is None


@pytest.mark.parametrize(
    "value",
    [
        "4g",
        "512m",
        "256K",
        "1.5G",
        "1024",
        "2B",
        "0",
        "4gb",  # podman accepts the redundant trailing 'b'
        "4gib",  # binary-IEC suffix
        "4GiB",  # case-insensitive across the board
        "4 g",  # podman tolerates one space between number and unit
    ],
)
def test_run_section_memory_accepts_podman_grammar(value: str) -> None:
    """Mirrors ``docker/go-units.sizeRegex`` (what podman's ``--memory`` accepts).

    ``"0"`` is format-valid; semantics are podman's call (the validator
    is format-only — see [`RawRunSection`][terok_sandbox.config_schema.RawRunSection]).
    """
    assert RawRunSection.model_validate({"memory": value}).memory == value


@pytest.mark.parametrize("value", ["two", "-1g", "4g ", "4.g", ".5g", "4  g", ""])
def test_run_section_memory_rejects_malformed(value: str) -> None:
    """Malformed values fail at parse time, not task launch.

    Blank → ``None`` via ``_blank_to_none``; listed only as a marker
    that the format check fires for non-blank inputs.  Leading-dot
    decimals (``".5g"``) are rejected — the regex requires a leading
    digit, so the canonical form is ``"0.5g"`` / ``"512m"``.  Trailing
    whitespace and double spaces are rejected (only the single
    podman-tolerated space between number and unit is accepted).
    """
    if value == "":
        # blank → None via the upstream coercion, not a validator failure
        assert RawRunSection.model_validate({"memory": value}).memory is None
        return
    with pytest.raises(ValidationError, match="memory"):
        RawRunSection.model_validate({"memory": value})


@pytest.mark.parametrize("value", ["2", "2.0", "0.5", "16", "0"])
def test_run_section_cpus_accepts_decimals(value: str) -> None:
    """Non-negative decimal; ``"0"`` is format-valid (same format-only
    contract as memory)."""
    assert RawRunSection.model_validate({"cpus": value}).cpus == value


@pytest.mark.parametrize(
    "raw,expected",
    [(2, "2"), (4, "4"), (0, "0"), (0.5, "0.5"), (1024, "1024")],
)
def test_run_section_accepts_numeric_yaml_input(raw: object, expected: str) -> None:
    """``cpus: 2`` / ``memory: 1024`` (YAML int/float) coerce to str.

    Without this, a perfectly valid project.yml would fail with a
    confusing "Input should be a valid string" pydantic error.
    """
    assert RawRunSection.model_validate({"cpus": raw}).cpus == expected
    assert RawRunSection.model_validate({"memory": raw}).memory == expected


@pytest.mark.parametrize("raw", [True, False])
def test_run_section_rejects_bool(raw: bool) -> None:
    """``bool`` is an ``int`` subclass — reject explicitly so ``cpus: true``
    doesn't silently coerce to ``"True"`` and then fail the format check
    with a less helpful message."""
    with pytest.raises(ValidationError):
        RawRunSection.model_validate({"cpus": raw})
    with pytest.raises(ValidationError):
        RawRunSection.model_validate({"memory": raw})


@pytest.mark.parametrize("value", ["two", "-1", "1.5x", "1,5", "2.0 ", ".5"])
def test_run_section_cpus_rejects_malformed(value: str) -> None:
    """``".5"`` is rejected for the same leading-digit reason as
    ``".5g"`` — canonical form is ``"0.5"``."""
    with pytest.raises(ValidationError, match="cpus"):
        RawRunSection.model_validate({"cpus": value})


def test_run_section_none_hooks_becomes_empty_subsection() -> None:
    """``hooks:`` written with no value (YAML null) shouldn't crash — coerce
    to empty defaults so all four hook fields stay ``None``.
    """
    section = RawRunSection.model_validate({"hooks": None})
    assert section.hooks.pre_start is None
    assert section.hooks.post_start is None
    assert section.hooks.post_ready is None
    assert section.hooks.post_stop is None


def test_run_section_rejects_typo_in_owned_key() -> None:
    """Sandbox-owned strictness — a misspelled key surfaces loudly."""
    with pytest.raises(ValidationError, match="shutdwon_timeout"):
        RawRunSection.model_validate({"shutdwon_timeout": 5})


# ── Top-level tolerance for foreign sections ──────────────────────────


def test_view_tolerates_unknown_top_level_sections() -> None:
    """Foreign sections (terok's ``tui:``, executor's ``image:``) pass through silently.

    Without this, every standalone sandbox invocation would crash the
    moment it sees a complete ecosystem config — and we'd be forced to
    vendor a list of foreign keys into sandbox to keep ``extra="forbid"``
    tractable.  ``extra="allow"`` is what makes ownership-by-package
    work without that vendoring.
    """
    raw = {
        "paths": {"root": "/v"},
        "tui": {"default_tmux": True},  # terok-owned
        "image": {"base_image": "ubuntu:24.04"},  # executor-owned
        "some_future_package": {"foo": "bar"},  # not even in v0
    }
    view = SandboxConfigView.model_validate(raw)
    assert view.paths.root == "/v"


def test_view_strictness_propagates_into_owned_sections() -> None:
    """Top-level allow doesn't leak into owned sections — typos inside still error."""
    raw = {"paths": {"rooot": "/tmp"}}  # typo inside an owned section
    with pytest.raises(ValidationError) as excinfo:
        SandboxConfigView.model_validate(raw)
    assert "rooot" in str(excinfo.value)


def test_view_default_construction_is_empty() -> None:
    """An empty ``config.yml`` is valid — every field uses safe defaults."""
    view = SandboxConfigView.model_validate({})
    assert view.paths.root is None
    assert view.shield.audit is True
    assert view.services.mode == "socket"
    assert view.network.port_range_start == 18700


# ── Composition story (subclass inherits + tolerates owned-section validators) ──


def test_subclass_can_compose_extra_sections_and_inherit_strictness() -> None:
    """A higher-level package can subclass + add fields; sandbox validators still fire.

    This is the contract [`terok_executor.config_schema.ExecutorConfigView`][terok_executor.config_schema.ExecutorConfigView]
    and terok's ``RawGlobalConfig`` rely on — sandbox-section strictness must
    survive composition.
    """
    from pydantic import BaseModel, ConfigDict, Field

    class _ToySection(BaseModel):
        model_config = ConfigDict(extra="forbid")
        toy_value: int = 0

    class _Composed(SandboxConfigView):
        model_config = ConfigDict(extra="allow")
        toy: _ToySection = Field(default_factory=_ToySection)

    # Sandbox-owned strictness still fires through the subclass.
    with pytest.raises(ValidationError, match="rooot"):
        _Composed.model_validate({"paths": {"rooot": "/tmp"}})

    # The added field validates on its own keys.
    composed = _Composed.model_validate({"toy": {"toy_value": 42}, "paths": {"root": "/v"}})
    assert composed.toy.toy_value == 42
    assert composed.paths.root == "/v"


# ── gate_use_personal_ssh_default reader ──────────────────────────────


def test_gate_use_personal_ssh_default_returns_false_when_unset(monkeypatch) -> None:
    """A missing or empty ``ssh:`` section collapses to ``False`` — the safe default."""
    from terok_sandbox.config_schema import gate_use_personal_ssh_default

    monkeypatch.setattr(
        "terok_sandbox.config_schema.read_config_section",
        lambda _section: {},
        raising=False,
    )
    # The patch above doesn't take if the symbol isn't already a module-level
    # attribute; the function imports lazily.  Patch the source module instead.
    import terok_sandbox.paths as _paths

    monkeypatch.setattr(_paths, "read_config_section", lambda _section: {})
    assert gate_use_personal_ssh_default() is False


def test_gate_use_personal_ssh_default_reads_true_from_config(monkeypatch) -> None:
    """``ssh: {use_personal: true}`` in config.yml flips the default to True."""
    import terok_sandbox.paths as _paths
    from terok_sandbox.config_schema import gate_use_personal_ssh_default

    monkeypatch.setattr(_paths, "read_config_section", lambda _section: {"use_personal": "true"})
    # ``read_config_section`` returns ``dict[str, str]`` (everything stringified
    # before merge); pydantic coerces the string to bool.  Verifying both that
    # the wiring works and the coercion holds.
    assert gate_use_personal_ssh_default() is True


def test_gate_use_personal_ssh_default_swallows_malformed_section(monkeypatch) -> None:
    """A typo inside ``ssh:`` doesn't crash the gate — falls back to False.

    The reader is called by gate-sync paths that must be robust to a
    partially-broken config; surfacing a pydantic error here would mean
    a single bad key in the global config takes down ``terok task start``
    on every project.  The strict validation path lives in terok's
    top-level ``RawGlobalConfig`` (``extra="forbid"``) — by the time
    the gate runs, terok would already have rejected the file there.
    """
    import terok_sandbox.paths as _paths
    from terok_sandbox.config_schema import gate_use_personal_ssh_default

    monkeypatch.setattr(_paths, "read_config_section", lambda _section: {"use_persoanl": "true"})
    assert gate_use_personal_ssh_default() is False


def test_run_section_perf_defaults_off() -> None:
    """``run.perf`` is opt-in; the default grants no capability."""
    assert RawRunSection().perf is False
    assert RawRunSection(perf=True).perf is True


def test_run_section_aslr_control_defaults_off() -> None:
    """The default grants no ASLR control; invalid booleans are rejected."""
    assert RawRunSection().aslr_control is False
    assert RawRunSection(aslr_control=True).aslr_control is True
    with pytest.raises(ValidationError):
        RawRunSection.model_validate({"aslr_control": "sometimes"})


def test_run_section_podman_args_accepts_benign_flags() -> None:
    args = ["-e", "HTTPS_PROXY=http://host:8118", "--shm-size=2g"]
    assert RawRunSection(podman_args=args).podman_args == args


@pytest.mark.parametrize(
    "bad",
    [
        ["--cap-add", "perfmon"],
        ["--net=host"],
        ["--privileged"],
        ["--security-opt", "label=disable"],
        ["-v", "/foo:/run/terok/vault.sock"],
    ],
)
def test_run_section_podman_args_rejects_managed_and_weakening(bad: list[str]) -> None:
    """Parse-time rejection mirrors the launch gate exactly."""
    with pytest.raises(ValidationError, match="podman_args"):
        RawRunSection(podman_args=bad)
