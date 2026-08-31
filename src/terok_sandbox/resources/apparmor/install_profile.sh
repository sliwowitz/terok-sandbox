#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0
#
# Install the terok-shield AppArmor addendum for the per-container dnsmasq.
#
# Adds an owner-scoped rule block to the host's dnsmasq AppArmor profile
# (via its ``local/`` include) permitting the per-task shield state tree,
# then reloads the profile.  No compilation — just ``apparmor_parser -r``.
# Kept short and readable so it can be audited before invocation with sudo.
#
# Usage:
#
#     sudo bash /path/to/install_profile.sh <STATE_ROOT>
#
# <STATE_ROOT> is the sandbox-live dir (e.g. ~/.local/share/terok/sandbox-live).
# It must be passed: under sudo this script cannot resolve the operator's
# home, and AppArmor mediates by pathname so the rules must name the root.

set -euo pipefail

if [[ -t 1 ]]; then
    _bold=$'\033[1m' _reset=$'\033[0m' _green=$'\033[32m' _red=$'\033[31m'
else
    _bold="" _reset="" _green="" _red=""
fi

state_root="${1:-}"
if [[ -z "$state_root" ]]; then
    echo "${_red}Usage:${_reset} sudo bash $0 <STATE_ROOT>" >&2
    echo "       <STATE_ROOT> = your sandbox-live dir, e.g. ~/.local/share/terok/sandbox-live" >&2
    exit 2
fi
state_root="${state_root%/}"

# Defence-in-depth against sudo executing attacker-tampered content: every
# file this sudo run consumes must not be swappable or rewritable by any
# user other than its owner.  Covers:
#
#  * symlink redirection — reject symlinks outright (following one would
#    trust a target we did not stat);
#  * file rewrite — reject group/world-writable file mode bits;
#  * file replacement via directory — reject a group/world-writable parent
#    ("mv newfile oldfile" works there even on a read-only file).
#
# The files *are* legitimately user-owned (pipx, pip --user, editable
# checkouts), so we accept that but require their owner is the only writer.
_reject_unsafe() {
    local f="$1"
    if [[ -L "$f" ]]; then
        echo "${_red}Refusing to run:${_reset} $f is a symlink." >&2
        echo "       A file sudo-bash'd must be a concrete regular file, not a link." >&2
        exit 1
    fi
    if [[ ! -f "$f" ]]; then
        echo "${_red}Refusing to run:${_reset} $f is not a regular file." >&2
        exit 1
    fi
    _perm=$(stat -c '%a' "$f")
    if (( 8#$_perm & 8#022 )); then
        echo "${_red}Refusing to run:${_reset} $f is group- or world-writable (mode $_perm)." >&2
        echo "       A file sudo-bash'd must not be writable by any user other than its owner." >&2
        echo "       Reinstall the package into a location you control (e.g. pipx install --force)." >&2
        exit 1
    fi
    _dir_perm=$(stat -c '%a' "$(dirname "$f")")
    if (( 8#$_dir_perm & 8#022 )); then
        echo "${_red}Refusing to run:${_reset} parent of $f is group- or world-writable (mode $_dir_perm)." >&2
        echo "       A writable parent lets another user replace the file via 'mv'." >&2
        exit 1
    fi
}

_self="${BASH_SOURCE[0]}"
_tmpl="$(dirname "$_self")/dnsmasq_addendum.template"
_reject_unsafe "$_self"
_reject_unsafe "$_tmpl"

if ! command -v apparmor_parser >/dev/null 2>&1; then
    echo "${_red}apparmor_parser not found.${_reset} Install the 'apparmor' package." >&2
    exit 1
fi

# Locate the stock dnsmasq profile (profile-set dependent) and its local include.
profile=""
for p in /etc/apparmor.d/usr.sbin.dnsmasq /etc/apparmor.d/dnsmasq; do
    if [[ -f "$p" ]]; then profile="$p"; break; fi
done
if [[ -z "$profile" ]]; then
    echo "${_red}No dnsmasq AppArmor profile found${_reset} in /etc/apparmor.d." >&2
    echo "       dnsmasq is not AppArmor-confined on this host; nothing to install." >&2
    exit 1
fi
local_include="/etc/apparmor.d/local/$(basename "$profile")"

# Idempotent: strip any prior managed block, then append the freshly
# rendered one.  The rules come from the sibling template — the single
# source of truth the show option prints — with @STATE_ROOT@ substituted
# here (pure bash: no sed delimiter or envsubst availability traps).
# Owner-scoping limits the grant to files dnsmasq owns; the glob covers
# every per-task shield dir under STATE_ROOT.
mkdir -p "$(dirname "$local_include")"
if [[ -f "$local_include" ]]; then
    sed -i '/# >>> terok-shield apparmor/,/# <<< terok-shield apparmor/d' "$local_include"
fi
_content="$(<"$_tmpl")"
printf '%s\n' "${_content//@STATE_ROOT@/"$state_root"}" >> "$local_include"

echo "Reloading ${profile} ..."
apparmor_parser -r -W "$profile"

echo
echo "${_green}terok-shield AppArmor addendum installed.${_reset}"
echo "Profile: ${_bold}${profile}${_reset}  (rules added to ${local_include})"
