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
[[ -d "$_TEROK_PIDDIR" ]] || mkdir -p "$_TEROK_PIDDIR" 2>/dev/null

# The sockets this script exposes to the container.  Shared agent configs point
# at them, so they are contract, not implementation detail.
_TEROK_SSH_AGENT_SOCK=/tmp/ssh-agent.sock
_TEROK_VAULT_SOCK=/tmp/terok-vault.sock

# The address each bridge listens on.  Named once: _terok_start_bridge binds
# it, and the liveness guard matches it against a running process.  Two
# spellings would drift, and the guard would quietly stop recognising its own
# bridge.
_TEROK_SSH_LISTEN="UNIX-LISTEN:${_TEROK_SSH_AGENT_SOCK},fork"
_TEROK_VAULT_SOCKET_LISTEN="UNIX-LISTEN:${_TEROK_VAULT_SOCK},fork"
_TEROK_VAULT_LOOPBACK_LISTEN="TCP-LISTEN:${TEROK_VAULT_LOOPBACK_PORT:-},bind=127.0.0.1,fork,reuseaddr"
_TEROK_GATE_LISTEN="TCP-LISTEN:9418,fork,reuseaddr"

# How long a bridge waits for its backend.  socat holds each connection and
# re-attempts the connect for about thirty seconds.  The supervisor binds its
# sockets after the container's first shell comes up, so without this the first
# git clone or credentialed request gets an empty reply instead of waiting.
_TEROK_BRIDGE_RETRY="retry=300,interval=0.1"

# Locate ssh-agent-bridge.sh — installed alongside this script.  Resolved
# from BASH_SOURCE so the SYSTEM: invocation below works regardless of
# CWD (the script may be sourced from /, /workspace, or anywhere else).
# Falls back to a name-only invocation if BASH_SOURCE is unavailable so
# operators who put the bridges on $PATH still work.  Parameter expansion
# rather than dirname: this file is sourced by every shell in the container,
# so it spawns no process it can avoid.
_TEROK_BRIDGES_DIR="${BASH_SOURCE[0]:-./ensure-bridges.sh}"
if [[ "$_TEROK_BRIDGES_DIR" == */* ]]; then
  _TEROK_BRIDGES_DIR="${_TEROK_BRIDGES_DIR%/*}"
else
  _TEROK_BRIDGES_DIR="."
fi
if [[ -x "${_TEROK_BRIDGES_DIR}/ssh-agent-bridge.sh" ]]; then
  _TEROK_SSH_BRIDGE="${_TEROK_BRIDGES_DIR}/ssh-agent-bridge.sh"
else
  _TEROK_SSH_BRIDGE="ssh-agent-bridge.sh"
fi

# Is the process recorded in *pidfile* still the bridge that wrote it?
#
# A PID file records a number, not an identity.  Container PIDs restart from 1
# on every boot, and /tmp survives a restart.  A stale file therefore names
# whatever inherited its number — the entrypoint keepalive, typically — and a
# signal probe reports that as a healthy bridge.  Comparing *listen* against
# the process's own argument list settles identity instead.
#
# This is the all-clear path, reached by every shell in the container, so it
# runs on builtins alone and spawns nothing.  ``mapfile -d ''`` splits
# /proc/<pid>/cmdline on its NUL separators, giving socat's arguments exactly
# as it was invoked with them; a dead PID has no such file and a zombie an
# empty one, and neither yields a match.
_terok_bridge_alive() {
  # ``pid`` and ``arg`` start empty: init-ssh-and-repo.sh sources this file
  # under ``set -u``, where a declared-but-unset local is fatal on first boot,
  # when no PID file exists yet and ``read`` assigns nothing.
  local pidfile="$1" listen="$2" pid="" arg=""
  local -a args=()
  read -r pid 2>/dev/null < "$pidfile"
  [[ -n "$pid" && -r "/proc/${pid}/cmdline" ]] || return 1
  mapfile -d '' -t args < "/proc/${pid}/cmdline"
  for arg in "${args[@]}"; do
    [[ "$arg" == "$listen" ]] && return 0
  done
  return 1
}

# Name the bridge targets this container advertises but does not have.
#
# The per-shell layer calls this, never the boot path.  The supervisor binds
# after the container's first shell comes up, which is why each bridge starts
# regardless and lets socat's retry cover the delay.  A shell that runs later
# is past that window, so an absent target is real.  It is worth saying out
# loud: a bridge aimed at nothing still listens and still accepts, and fails
# only at the far end.
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
    echo "terok: this container advertises bridge targets that do not exist:"
    printf '%s\n' "${missing[@]}"
    echo "terok:   its git gate and vault-routed providers connect nowhere.  Recreate the"
    echo "terok:   task to fix them.  Everything else in the container keeps working."
  } >&2
}

# Is *listen* free for socat to bind?
#
# Only a UNIX-LISTEN address can be blocked by a leftover file.  A path nobody
# answers on is the remains of a bridge that died; remove it so socat can bind.
# A path that answers belongs to a live bridge whose PID file we lost — most
# often a second shell racing this one — so leave the socket and that bridge
# alone.  A bare connect is the test: it sends nothing, and the peers accept
# and close one without harm.
_terok_listen_free() {
  local listen="$1" path
  [[ "$listen" == UNIX-LISTEN:* ]] || return 0
  path="${listen#UNIX-LISTEN:}"
  path="${path%%,*}"
  [[ -e "$path" ]] || return 0
  socat -u /dev/null "UNIX-CONNECT:${path}" 2>/dev/null && return 1
  rm -f "$path"
}

# Start the bridge from *listen* to *target*, unless it is already running.
#
# Records the PID so the next call can tell.  Silently does nothing when socat
# is absent — an image without it simply has no bridges.
_terok_start_bridge() {
  local pidfile="$1" listen="$2" target="$3"
  command -v socat >/dev/null 2>&1 || return 0
  _terok_bridge_alive "$pidfile" "$listen" && return 0
  _terok_listen_free "$listen" || return 0
  socat "$listen" "$target" &
  echo $! > "$pidfile"
}

# ── SSH signer bridge ────────────────────────────────────────────────────
# Requires a phantom token.  Transport: TEROK_SSH_SIGNER_SOCKET (mounted
# host socket) or TEROK_SSH_SIGNER_PORT (TCP to host loopback).
if [[ -n "${TEROK_SSH_SIGNER_TOKEN:-}" ]] \
   && { [[ -n "${TEROK_SSH_SIGNER_SOCKET:-}" ]] || [[ -n "${TEROK_SSH_SIGNER_PORT:-}" ]]; }; then
  _terok_start_bridge "$_TEROK_PIDDIR/ssh-agent.pid" "$_TEROK_SSH_LISTEN" \
    "SYSTEM:${_TEROK_SSH_BRIDGE}"
  export SSH_AUTH_SOCK="$_TEROK_SSH_AGENT_SOCK"
fi

# ── Vault loopback bridge (socket mode) ──────────────────────────────────
# The host vault socket is mounted at TEROK_VAULT_SOCKET.  Socket-native
# clients (gh, claude) use it directly; everyone else reaches it via this
# TCP loopback so their "base URL" knob has something to point at.
#
# Socket mode is TEROK_VAULT_LOOPBACK_PORT set with NO TEROK_TOKEN_BROKER_PORT
# (that pins TCP mode, handled below).  An unset socket path is a
# configuration error.
if [[ -n "${TEROK_VAULT_LOOPBACK_PORT:-}" ]] && [[ -z "${TEROK_TOKEN_BROKER_PORT:-}" ]]; then
  if [[ -z "${TEROK_VAULT_SOCKET:-}" ]]; then
    echo "terok: vault loopback bridge skipped — socket mode announced" \
      "(TEROK_VAULT_LOOPBACK_PORT=${TEROK_VAULT_LOOPBACK_PORT}) but" \
      "TEROK_VAULT_SOCKET is unset" >&2
  else
    # Stable alias for shared agent configs: this is the one vault-socket path
    # every container generation serves (TCP mode binds a real socket there).
    # The env var carries this generation's mounted path; the alias shields the
    # shared singleton config files from mount-layout changes between
    # generations.
    # ``ln`` is a process, and this file is sourced by every shell, so pay for
    # it only when the alias is missing or dangling.  Within one container the
    # mounted path never changes, so an alias that already resolves is correct.
    [[ -L "$_TEROK_VAULT_SOCK" && -e "$_TEROK_VAULT_SOCK" ]] \
      || ln -sfn "${TEROK_VAULT_SOCKET}" "$_TEROK_VAULT_SOCK"
    _terok_start_bridge "$_TEROK_PIDDIR/vault-loopback.pid" \
      "$_TEROK_VAULT_LOOPBACK_LISTEN" \
      "UNIX-CONNECT:${TEROK_VAULT_SOCKET},${_TEROK_BRIDGE_RETRY}"
  fi
fi

# ── Vault socket bridge (TCP mode) ───────────────────────────────────────
# Unix-socket facade for socket-only clients (gh, claude) when the broker
# lives on host TCP.
if [[ -n "${TEROK_TOKEN_BROKER_PORT:-}" ]]; then
  _terok_start_bridge "$_TEROK_PIDDIR/vault-socket.pid" "$_TEROK_VAULT_SOCKET_LISTEN" \
    "TCP:host.containers.internal:${TEROK_TOKEN_BROKER_PORT},${_TEROK_BRIDGE_RETRY}"
fi

# ── Vault loopback bridge (TCP mode) ─────────────────────────────────────
# Mirror of the socket-mode bridge so URL-based clients always get to
# http://localhost:9419/v1 regardless of transport.  Per-container host
# port comes from TEROK_TOKEN_BROKER_PORT.
if [[ -n "${TEROK_TOKEN_BROKER_PORT:-}" ]] && [[ -n "${TEROK_VAULT_LOOPBACK_PORT:-}" ]]; then
  _terok_start_bridge "$_TEROK_PIDDIR/vault-loopback.pid" "$_TEROK_VAULT_LOOPBACK_LISTEN" \
    "TCP:host.containers.internal:${TEROK_TOKEN_BROKER_PORT},${_TEROK_BRIDGE_RETRY}"
fi

# ── Gate server bridge (socket mode) ─────────────────────────────────────
# In socket mode the gate HTTP server listens on a per-container Unix socket
# the supervisor bound inside /run/terok/.  Git needs HTTP URLs, so we bridge
# localhost:9418 to that socket.  CODE_REPO / CLONE_FROM point to
# http://localhost:9418/.
if [[ -n "${TEROK_GATE_SOCKET:-}" ]]; then
  _terok_start_bridge "$_TEROK_PIDDIR/gate.pid" "$_TEROK_GATE_LISTEN" \
    "UNIX-CONNECT:${TEROK_GATE_SOCKET},${_TEROK_BRIDGE_RETRY}"
fi

# ── Gate server bridge (TCP mode) ────────────────────────────────────────
# In TCP mode the supervisor binds the gate on a per-container host loopback
# port.  Mirror the socket-mode bridge so git's http://localhost:9418/ URL
# works regardless of transport.  Per-container host port comes from
# TEROK_GATE_PORT.
if [[ -n "${TEROK_GATE_PORT:-}" ]]; then
  _terok_start_bridge "$_TEROK_PIDDIR/gate.pid" "$_TEROK_GATE_LISTEN" \
    "TCP:host.containers.internal:${TEROK_GATE_PORT},${_TEROK_BRIDGE_RETRY}"
fi
