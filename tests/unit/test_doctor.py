# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for the container health check protocol and sandbox-level diagnostics."""

from __future__ import annotations

import pytest

import terok_sandbox.doctor as _doctor
from terok_sandbox.doctor import (
    CheckVerdict,
    DoctorCheck,
    _kernel_keyring_quota,
    _make_shield_check,
    _make_ssh_signer_check,
    _make_token_broker_check,
    _make_vault_unlocked_check,
    make_kernel_keyring_quota_check,
    sandbox_doctor_checks,
)


class _FakeKeyUsers:
    """Stand-in for ``Path("/proc/key-users")`` returning canned text."""

    def __init__(self, text: str) -> None:
        self._text = text

    def read_text(self, encoding: str = "utf-8") -> str:
        return self._text


_KEY_USERS_SAMPLE = " 1000:    19 19/19 19/200 264/20000\n    0:    14 14/14 14/200 154/20000\n"


class TestKernelKeyringQuota:
    """The per-uid kernel-keyring quota gauge (reads ``/proc/key-users``)."""

    def _patch(self, monkeypatch: pytest.MonkeyPatch, *, text: str | None, uid: int = 1000) -> None:
        monkeypatch.setattr(_doctor.os, "geteuid", lambda: uid)
        if text is None:
            monkeypatch.setattr(
                _doctor,
                "Path",
                lambda _p: _FakeMissing(),  # type: ignore[arg-type,return-value]
            )
        else:
            monkeypatch.setattr(_doctor, "Path", lambda _p: _FakeKeyUsers(text))

    def test_parses_this_uids_line(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch(monkeypatch, text=_KEY_USERS_SAMPLE)
        assert _kernel_keyring_quota() == (19, 200, 264, 20000)

    def test_none_when_no_line_for_uid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch(monkeypatch, text=_KEY_USERS_SAMPLE, uid=4242)
        assert _kernel_keyring_quota() is None

    def test_none_when_file_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch(monkeypatch, text=None)
        assert _kernel_keyring_quota() is None

    def test_ok_far_below_the_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(_doctor, "_kernel_keyring_quota", lambda: (19, 200, 264, 20000))
        verdict = make_kernel_keyring_quota_check().evaluate(0, "", "")
        assert verdict.severity == "ok"

    def test_warns_when_keys_near_full(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(_doctor, "_kernel_keyring_quota", lambda: (195, 200, 264, 20000))
        verdict = make_kernel_keyring_quota_check().evaluate(0, "", "")
        assert verdict.severity == "warn"
        assert "195/200 keys" in verdict.detail
        assert "kernel-keyring" in verdict.detail  # the docs link

    def test_warns_when_bytes_near_full(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(_doctor, "_kernel_keyring_quota", lambda: (19, 200, 19900, 20000))
        assert make_kernel_keyring_quota_check().evaluate(0, "", "").severity == "warn"

    def test_ok_when_quota_unaccounted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(_doctor, "_kernel_keyring_quota", lambda: None)
        assert make_kernel_keyring_quota_check().evaluate(0, "", "").severity == "ok"


class _FakeMissing:
    """``/proc/key-users`` absent — ``read_text`` raises like the real file would."""

    def read_text(self, encoding: str = "utf-8") -> str:
        raise OSError("No such file or directory")


TOKEN_BROKER_PORT = 18731
SSH_SIGNER_PORT = 18732


class TestCheckVerdict:
    """CheckVerdict dataclass basics."""

    def test_default_fixable_is_false(self) -> None:
        v = CheckVerdict("ok", "all good")
        assert v.fixable is False

    def test_fixable_flag(self) -> None:
        v = CheckVerdict("error", "broken", fixable=True)
        assert v.fixable is True

    def test_frozen(self) -> None:
        v = CheckVerdict("ok", "fine")
        with pytest.raises(AttributeError):
            v.severity = "error"  # type: ignore[misc]


class TestDoctorCheck:
    """DoctorCheck dataclass basics."""

    def test_defaults(self) -> None:
        c = DoctorCheck(
            category="test",
            label="Test",
            probe_cmd=["true"],
            evaluate=lambda rc, out, err: CheckVerdict("ok", "ok"),
        )
        assert c.fix_cmd is None
        assert c.fix_description == ""
        assert c.host_side is False

    def test_host_side_check(self) -> None:
        c = DoctorCheck(
            category="shield",
            label="Shield",
            probe_cmd=[],
            evaluate=lambda rc, out, err: CheckVerdict("ok", "ok"),
            host_side=True,
        )
        assert c.host_side is True


class TestTokenBrokerCheck:
    """Token broker TCP reachability check."""

    def test_ok_on_success(self) -> None:
        check = _make_token_broker_check(TOKEN_BROKER_PORT)
        verdict = check.evaluate(0, "", "")
        assert verdict.severity == "ok"
        assert str(TOKEN_BROKER_PORT) in verdict.detail

    def test_error_on_failure(self) -> None:
        check = _make_token_broker_check(TOKEN_BROKER_PORT)
        verdict = check.evaluate(4, "", "connection refused")
        assert verdict.severity == "error"
        assert "unreachable" in verdict.detail

    def test_probe_cmd_uses_health_endpoint(self) -> None:
        check = _make_token_broker_check(TOKEN_BROKER_PORT)
        cmd_str = " ".join(check.probe_cmd)
        assert str(TOKEN_BROKER_PORT) in cmd_str
        assert "/-/health" in cmd_str
        assert "wget" in cmd_str

    def test_category_is_network(self) -> None:
        check = _make_token_broker_check(TOKEN_BROKER_PORT)
        assert check.category == "network"


class TestSSHSignerCheck:
    """SSH signer TCP reachability check."""

    def test_ok_on_success(self) -> None:
        check = _make_ssh_signer_check(SSH_SIGNER_PORT)
        verdict = check.evaluate(0, "", "")
        assert verdict.severity == "ok"
        assert str(SSH_SIGNER_PORT) in verdict.detail

    def test_error_on_failure(self) -> None:
        check = _make_ssh_signer_check(SSH_SIGNER_PORT)
        verdict = check.evaluate(1, "", "timeout")
        assert verdict.severity == "error"

    def test_probe_cmd_uses_nc(self) -> None:
        check = _make_ssh_signer_check(SSH_SIGNER_PORT)
        cmd_str = " ".join(check.probe_cmd)
        assert "nc" in cmd_str
        assert str(SSH_SIGNER_PORT) in cmd_str


class TestShieldCheck:
    """Shield state verification check.

    These tests exercise the ``evaluate`` callable in isolation by passing
    state strings via the *stdout* parameter.  This matches how the
    orchestrator (terok's ``container_doctor``) calls evaluate after
    resolving the actual shield state on the host.  The host_side flag
    means the orchestrator bypasses ``podman exec`` — it does NOT mean
    the evaluate function itself performs a side-effect.
    """

    def test_no_desired_state(self) -> None:
        check = _make_shield_check(None)
        verdict = check.evaluate(0, "", "")
        assert verdict.severity == "ok"
        assert "not managed" in verdict.detail

    def test_matching_state(self) -> None:
        check = _make_shield_check("up")
        verdict = check.evaluate(0, "up", "")
        assert verdict.severity == "ok"
        assert "matches" in verdict.detail

    def test_mismatched_state(self) -> None:
        check = _make_shield_check("up")
        verdict = check.evaluate(0, "down", "")
        assert verdict.severity == "warn"
        assert verdict.fixable is True
        assert "mismatch" in verdict.detail

    def test_host_side_flag(self) -> None:
        check = _make_shield_check("up")
        assert check.host_side is True

    def test_empty_probe_cmd(self) -> None:
        check = _make_shield_check("up")
        assert check.probe_cmd == []


class TestVaultUnlockedCheck:
    """Host-side check: passphrase resolves through *some* tier or vault stays locked."""

    def test_ok_when_resolution_chain_yields(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Any tier returning a passphrase → ok verdict."""
        from terok_sandbox.vault.store import encryption as enc

        monkeypatch.setattr(enc, "resolve_passphrase", lambda **_kw: "found-it")
        check = _make_vault_unlocked_check()
        verdict = check.evaluate(0, "", "")
        assert verdict.severity == "ok"
        assert "available" in verdict.detail

    def test_error_when_chain_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Every tier empty → actionable error verdict with the unlock hint."""
        from terok_sandbox.vault.store import encryption as enc

        monkeypatch.setattr(enc, "resolve_passphrase", lambda **_kw: None)
        check = _make_vault_unlocked_check()
        verdict = check.evaluate(0, "", "")
        assert verdict.severity == "error"
        assert "vault is locked" in verdict.detail
        assert "vault unlock" in verdict.detail


class TestSandboxDoctorChecks:
    """Integration: sandbox_doctor_checks() assembly."""

    def test_all_checks_present(self) -> None:
        checks = sandbox_doctor_checks(
            token_broker_port=TOKEN_BROKER_PORT,
            ssh_signer_port=SSH_SIGNER_PORT,
            desired_shield_state="up",
        )
        labels = {c.label for c in checks}
        assert "Credentials DB passphrase" in labels
        assert "Token broker (TCP)" in labels
        assert "SSH signer (TCP)" in labels
        assert "Shield state" in labels
        assert len(checks) == 4

    def test_recovery_acknowledged_not_in_per_task_bundle(self) -> None:
        """The recovery check is host-only — terok's sickbay loops over tasks
        and would otherwise duplicate this row per container.  Top-level
        callers (the standalone CLI, terok's host-level sickbay) invoke
        ``make_recovery_acknowledged_check`` directly instead.
        """
        checks = sandbox_doctor_checks(
            token_broker_port=TOKEN_BROKER_PORT,
            ssh_signer_port=SSH_SIGNER_PORT,
            desired_shield_state="up",
        )
        assert "Recovery key acknowledged" not in {c.label for c in checks}

    def test_skips_broker_when_none(self) -> None:
        checks = sandbox_doctor_checks(
            token_broker_port=None,
            ssh_signer_port=SSH_SIGNER_PORT,
            desired_shield_state=None,
        )
        labels = {c.label for c in checks}
        assert "Token broker (TCP)" not in labels
        assert "SSH signer (TCP)" in labels

    def test_skips_ssh_signer_when_none(self) -> None:
        checks = sandbox_doctor_checks(
            token_broker_port=TOKEN_BROKER_PORT,
            ssh_signer_port=None,
            desired_shield_state=None,
        )
        labels = {c.label for c in checks}
        assert "SSH signer (TCP)" not in labels
        assert "Token broker (TCP)" in labels

    def test_minimal(self) -> None:
        """With no ports, only the always-on vault and shield checks remain."""
        checks = sandbox_doctor_checks(
            token_broker_port=None,
            ssh_signer_port=None,
            desired_shield_state=None,
        )
        categories = [c.category for c in checks]
        # One vault check: unlocked-passphrase.  Recovery-acknowledged
        # is host-only (see
        # ``test_recovery_acknowledged_not_in_per_task_bundle``) so it
        # doesn't appear here.
        assert categories == ["vault", "shield"]

    def test_all_checks_are_doctor_check_instances(self) -> None:
        checks = sandbox_doctor_checks(
            token_broker_port=TOKEN_BROKER_PORT,
            ssh_signer_port=SSH_SIGNER_PORT,
            desired_shield_state="down",
        )
        for check in checks:
            assert isinstance(check, DoctorCheck)
