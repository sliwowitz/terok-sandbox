# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
# terok:container — this file is deployed into containers, not used on the host.

# Idempotent socat bridge launcher for container ↔ host-side sandbox services.
#
# Manages up to four bridges:
#
#   1. SSH signer        — UNIX socket → ssh-agent-bridge.sh → TCP or host socket
#   2. Vault (HTTP leg)  — in socket mode: TCP-LISTEN → TEROK_VAULT_SOCKET
#                          (lets HTTP-only clients reach the vault via localhost)
#   3. Vault (socket leg) — in TCP mode:    /tmp/terok-vault.sock → TCP broker
#                          (lets socket-only clients — gh, claude — reach the
#                          broker, which is only exposed on TCP)
#   4. Gate server       — TCP listener → host UNIX socket (socket mode) or
#                          host loopback TCP port (TCP mode); git HTTP either way
#
# Transport selection is env-var driven (set at container creation):
#
#   Socket mode: TEROK_VAULT_LOOPBACK_PORT=<port>,
#                TEROK_VAULT_SOCKET=<path>, TEROK_GATE_SOCKET=<path>
#   TCP mode:    TEROK_TOKEN_BROKER_PORT=<port>, TEROK_GATE_PORT=<port>
#
# Uses PID files (not socket existence) to detect dead bridges — stale
# socket files persist after process death and are unreliable sentinels.
#
# Designed to be *sourced* (not executed) so SSH_AUTH_SOCK propagates
# to the caller.  Typical call sites:
#   - container entrypoint (first boot)
#   - per-shell init (self-heal after restart)

_TEROK_PIDDIR=/tmp/.terok
mkdir -p "$_TEROK_PIDDIR" 2>/dev/null

# Locate ssh-agent-bridge.sh — installed alongside this script.  Resolved
# from BASH_SOURCE so the SYSTEM: invocation below works regardless of
# CWD (the script may be sourced from /, /workspace, or anywhere else).
# Falls back to a name-only invocation if BASH_SOURCE is unavailable so
# operators who put the bridges on $PATH still work.
_TEROK_BRIDGES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-./ensure-bridges.sh}")" 2>/dev/null && pwd)"
if [[ -x "${_TEROK_BRIDGES_DIR}/ssh-agent-bridge.sh" ]]; then
  _TEROK_SSH_BRIDGE="${_TEROK_BRIDGES_DIR}/ssh-agent-bridge.sh"
else
  _TEROK_SSH_BRIDGE="ssh-agent-bridge.sh"
fi

# Is the bridge recorded in *pidfile* still the one running under that PID?
#
# A PID file records a number, not an identity.  Container PIDs restart from 1
# on every boot and /tmp is the image's writable layer, so the file outlives
# the process it named: after a restart yesterday's number can land on today's
# keepalive, read as alive, and leave the bridge unstarted.  *listen_spec* —
# the socat listen address up to and including its trailing comma, so a port
# 941 cannot pass for 9418 — settles identity against the process's own
# command line.  That line answers liveness too: a dead PID has no entry and a
# zombie an empty one, and neither can contain the spec.  The empty-PID guard
# is load-bearing: "/proc//cmdline" resolves to the kernel's boot command line.
_terok_bridge_alive() {
  local pidfile="$1" listen_spec="$2" pid cmdline
  [[ -f "$pidfile" ]] || return 1
  pid=$(cat "$pidfile" 2>/dev/null)
  [[ -n "$pid" ]] || return 1
  cmdline=$(tr '\0' ' ' 2>/dev/null < "/proc/${pid}/cmdline")
  [[ "$cmdline" == *"$listen_spec"* ]]
}

# Name the bridge targets this container's environment advertises but does not
# have.  Deliberately not a start-time guard: the supervisor binds after the
# container's first shell comes up, which is why every bridge starts regardless
# and lets socat's retry absorb the delay.  By the time an interactive shell
# calls this, that window is long past, so an absent target is real — and worth
# saying out loud, because a bridge aimed at nothing still listens and still
# accepts, and fails only at the far end as a hang and an empty reply.  Callers
# are the per-shell layer, never the boot path.
_terok_report_missing_bridge_targets() {
  local var path
  local -a missing=()
  for var in TEROK_VAULT_SOCKET TEROK_SSH_SIGNER_SOCKET TEROK_GATE_SOCKET; do
    path="${!var:-}"
    if [[ -n "$path" && ! -S "$path" ]]; then
      missing+=("terok:     ${var}=${path}")
    fi
  done
  if [[ ${#missing[@]} -eq 0 ]]; then
    return 0
  fi
  {
    echo "terok: bridge target(s) advertised by this container's environment are absent:"
    printf '%s\n' "${missing[@]}"
    echo "terok:   the container predates the current /run/terok layout, so its git gate"
    echo "terok:   and vault-routed providers connect nowhere.  Recreate the task to fix"
    echo "terok:   them; everything else in the container keeps working until you do."
  } >&2
}

# ── SSH signer bridge ────────────────────────────────────────────────────
# Requires a phantom token.  Transport: TEROK_SSH_SIGNER_SOCKET (mounted
# host socket) or TEROK_SSH_SIGNER_PORT (TCP to host loopback).
if [[ -n "${TEROK_SSH_SIGNER_TOKEN:-}" ]] \
   && { [[ -n "${TEROK_SSH_SIGNER_SOCKET:-}" ]] || [[ -n "${TEROK_SSH_SIGNER_PORT:-}" ]]; } \
   && command -v socat >/dev/null 2>&1 \
   && ! _terok_bridge_alive "$_TEROK_PIDDIR/ssh-agent.pid" "UNIX-LISTEN:/tmp/ssh-agent.sock,"; then
  rm -f /tmp/ssh-agent.sock
  socat "UNIX-LISTEN:/tmp/ssh-agent.sock,fork" "SYSTEM:${_TEROK_SSH_BRIDGE}" &
  echo $! > "$_TEROK_PIDDIR/ssh-agent.pid"
  export SSH_AUTH_SOCK=/tmp/ssh-agent.sock
fi

# ── Vault loopback bridge (socket mode) ──────────────────────────────────
# The host vault socket is mounted at TEROK_VAULT_SOCKET.  Socket-native
# clients (gh, claude) use it directly; everyone else reaches it via this
# TCP loopback so their "base URL" knob has something to point at.
# retry=/interval= (as on the gate bridge) hold each connection until the
# host-side broker is accepting — the vault comes up after the gate, so an
# early credentialed request would otherwise race the broker's bind.
#
# Socket mode is TEROK_VAULT_LOOPBACK_PORT set with NO TEROK_TOKEN_BROKER_PORT
# (that pins TCP mode, handled below).  The socket path may not exist yet when
# shell startup races the supervisor's bind; start socat anyway and let its
# retry policy absorb that delay.  An unset path is a configuration error.
if [[ -n "${TEROK_VAULT_LOOPBACK_PORT:-}" ]] && [[ -z "${TEROK_TOKEN_BROKER_PORT:-}" ]]; then
  if [[ -z "${TEROK_VAULT_SOCKET:-}" ]]; then
    echo "terok: vault loopback bridge skipped — socket mode announced" \
      "(TEROK_VAULT_LOOPBACK_PORT=${TEROK_VAULT_LOOPBACK_PORT}) but" \
      "TEROK_VAULT_SOCKET is unset" >&2
  else
    # Stable alias for shared agent configs: /tmp/terok-vault.sock is the
    # one vault-socket path every container generation serves (TCP mode
    # binds a real socket there).  The env var carries this generation's
    # mounted path; the alias shields the shared singleton config files
    # from mount-layout changes between generations.
    ln -sfn "${TEROK_VAULT_SOCKET}" /tmp/terok-vault.sock
    if command -v socat >/dev/null 2>&1 \
       && ! _terok_bridge_alive "$_TEROK_PIDDIR/vault-loopback.pid" \
         "TCP-LISTEN:${TEROK_VAULT_LOOPBACK_PORT},"; then
      socat "TCP-LISTEN:${TEROK_VAULT_LOOPBACK_PORT},bind=127.0.0.1,fork,reuseaddr" \
        UNIX-CONNECT:"${TEROK_VAULT_SOCKET}",retry=300,interval=0.1 &
      echo $! > "$_TEROK_PIDDIR/vault-loopback.pid"
    fi
  fi
fi

# ── Vault socket bridge (TCP mode) ───────────────────────────────────────
# Unix-socket facade for socket-only clients (gh, claude) when the broker
# lives on host TCP.
if [[ -n "${TEROK_TOKEN_BROKER_PORT:-}" ]] \
   && command -v socat >/dev/null 2>&1 \
   && ! _terok_bridge_alive "$_TEROK_PIDDIR/vault-socket.pid" \
     "UNIX-LISTEN:/tmp/terok-vault.sock,"; then
  rm -f /tmp/terok-vault.sock
  socat UNIX-LISTEN:/tmp/terok-vault.sock,fork \
    TCP:host.containers.internal:"${TEROK_TOKEN_BROKER_PORT}",retry=300,interval=0.1 &
  echo $! > "$_TEROK_PIDDIR/vault-socket.pid"
fi

# ── Vault loopback bridge (TCP mode) ─────────────────────────────────────
# Mirror of the socket-mode bridge so URL-based clients always get to
# http://localhost:9419/v1 regardless of transport.  Per-container host
# port comes from TEROK_TOKEN_BROKER_PORT.
if [[ -n "${TEROK_TOKEN_BROKER_PORT:-}" ]] \
   && [[ -n "${TEROK_VAULT_LOOPBACK_PORT:-}" ]] \
   && command -v socat >/dev/null 2>&1 \
   && ! _terok_bridge_alive "$_TEROK_PIDDIR/vault-loopback.pid" \
         "TCP-LISTEN:${TEROK_VAULT_LOOPBACK_PORT},"; then
  socat "TCP-LISTEN:${TEROK_VAULT_LOOPBACK_PORT},bind=127.0.0.1,fork,reuseaddr" \
    TCP:host.containers.internal:"${TEROK_TOKEN_BROKER_PORT}",retry=300,interval=0.1 &
  echo $! > "$_TEROK_PIDDIR/vault-loopback.pid"
fi

# ── Gate server bridge (socket mode) ─────────────────────────────────────
# In socket mode the gate HTTP server listens on a per-container Unix socket
# the supervisor bound inside /run/terok/.  Git needs HTTP URLs, so we bridge
# localhost:9418 to that socket.  CODE_REPO / CLONE_FROM point to
# http://localhost:9418/.
if [[ -n "${TEROK_GATE_SOCKET:-}" ]] \
   && command -v socat >/dev/null 2>&1 \
   && ! _terok_bridge_alive "$_TEROK_PIDDIR/gate.pid" "TCP-LISTEN:9418,"; then
  # retry=/interval= make socat hold each git connection and re-attempt the
  # backend connect until the supervisor has bound the gate socket, rather
  # than returning an empty reply when the container clones before the gate
  # is up.  The supervisor binds the gate early (before its vault DB open),
  # so this usually connects on the first try; the 0.1s interval keeps the
  # rare cold-start race down to ~100ms instead of a full second, while
  # retry*interval still tolerates a ~30s laggard.
  socat TCP-LISTEN:9418,fork,reuseaddr \
    UNIX-CONNECT:"${TEROK_GATE_SOCKET}",retry=300,interval=0.1 &
  echo $! > "$_TEROK_PIDDIR/gate.pid"
fi

# ── Gate server bridge (TCP mode) ────────────────────────────────────────
# In TCP mode the supervisor binds the gate on a per-container host loopback
# port.  Mirror the socket-mode bridge so git's http://localhost:9418/ URL
# works regardless of transport.  Per-container host port comes from
# TEROK_GATE_PORT.
if [[ -n "${TEROK_GATE_PORT:-}" ]] \
   && command -v socat >/dev/null 2>&1 \
   && ! _terok_bridge_alive "$_TEROK_PIDDIR/gate.pid" "TCP-LISTEN:9418,"; then
  # See the socket-mode note above: retry=/interval= wait for the
  # supervisor's gate listener instead of failing the container's first clone.
  socat TCP-LISTEN:9418,fork,reuseaddr \
    TCP:host.containers.internal:"${TEROK_GATE_PORT}",retry=300,interval=0.1 &
  echo $! > "$_TEROK_PIDDIR/gate.pid"
fi
