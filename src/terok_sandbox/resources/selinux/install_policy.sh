#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0
#
# Install the ``terok_socket`` SELinux policy module.
#
# Compiles the ``terok_socket.te`` source that lives next to this
# script into a loadable ``.pp`` module and installs it via
# ``semodule``.  Runs as root.  Kept deliberately short and readable
# so it can be audited before invocation with ``sudo``.
#
# Usage:
#
#     sudo bash /path/to/install_policy.sh
#
# After the policy loads, running services still hold sockets bound
# under the old context — re-run ``terok setup`` as your user so
# services rebind with ``terok_socket_t``.

set -euo pipefail

if [[ -t 1 ]]; then
    _bold=$'\033[1m' _reset=$'\033[0m' _green=$'\033[32m' _red=$'\033[31m'
else
    _bold= _reset= _green= _red=
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
te_source="${script_dir}/terok_socket.te"

if [[ ! -f "$te_source" ]]; then
    echo "${_red}Policy source not found:${_reset} $te_source" >&2
    exit 1
fi

for tool in checkmodule semodule_package semodule; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "${_red}Required tool '$tool' not found.${_reset}" >&2
        echo "Install: dnf install selinux-policy-devel policycoreutils" >&2
        exit 1
    fi
done

workdir=$(mktemp -d -t terok-selinux-XXXXXX)
trap 'rm -rf "$workdir"' EXIT

mod="${workdir}/terok_socket.mod"
pp="${workdir}/terok_socket.pp"

echo "Compiling policy..."
checkmodule -M -m -o "$mod" "$te_source"

echo "Packaging module..."
semodule_package -o "$pp" -m "$mod"

echo "Installing into system policy (rebuilds active store — may take a few seconds)..."
semodule -i "$pp"

echo "Verifying..."
if ! semodule -l | grep -qwF terok_socket; then
    echo "${_red}ERROR:${_reset} semodule -i reported success but 'terok_socket'" >&2
    echo "       is not in 'semodule -l'.  Check the active SELinux store:" >&2
    echo "         semodule -l | grep terok_socket" >&2
    echo "         getenforce" >&2
    exit 1
fi

echo
echo "${_green}terok_socket policy installed.${_reset}"
echo
echo "Next: run ${_bold}terok setup${_reset} as your user so services rebind"
echo "their sockets with the new terok_socket_t labeling."
