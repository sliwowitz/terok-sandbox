# SELinux policies

The service-socket policy and optional filtered/direct Wayland policies are
separate modules. The installer never disables SELinux or changes the real
compositor's socket label.

```console
terok-sandbox setup selinux
terok-sandbox setup selinux --with-wayland
terok-sandbox setup selinux --with-wayland-direct
terok-sandbox setup selinux --with-wayland --with-wayland-direct
terok-sandbox setup selinux --with-wayland --show
```

The first command installs only `terok_socket`. `--with-wayland` adds
`terok_wayland` for `wl-mitm`; `--with-wayland-direct` adds
`terok_wayland_direct` for `wl-direct`. The flags are independent and can be
combined. Omitting either flag later does not remove an installed module.
`--show` prints the exact sources without installing anything. The interactive
flow displays the command and asks before running the installer with `sudo`.
The `terok` and `terok-executor` frontends expose the same commands.

All three modules are written in plain module syntax and build with
`checkmodule` and `semodule_package` alone; no policy development packages
are needed.

Wayland still uses a Unix socket when the other services use TCP. Its optional
policy is therefore independent of the `services.mode` setting. Install the
`wl-mitm` binary separately as the desktop user to use `wl-mitm` mode; setup
does not install that binary. Direct access does not need it.

The supported modes are `none`, `wl-mitm`, and `wl-direct`. An ordinary restart
cannot change a task's saved access grant; recreate the task to change its mode.

## Filtered access: `--with-wayland`

The launcher explicitly selects `terok_wayland_t` for the trusted Wayland
supervisor child and its stock `wl-mitm` subprocess. It preserves the current
SELinux user, role and range. There is no
automatic transition for other invocations of the binary and no binary relabel.
The policy permits the transition under `no_new_privs` and on `nosuid` mounts.
The child enters the domain before arming parent-death signals because SELinux
clears those signals on a domain transition. The subsequent same-domain proxy
exec retains them. The child sends logs through a pipe instead of obtaining
home-file write access.

The domain can create the task's proxy listener, connect to the desktop
compositor, and forward the file descriptors that Wayland rendering and focused
keyboard input require. The container can connect to that proxy domain, not
directly to arbitrary `unconfined_t` sockets. Shared-memory and keymap descriptor
permissions do not grant containers permission to open host files by pathname.
The module does not add TCP/UDP, D-Bus, ptrace, or GPU-device-open permissions.
GPU passthrough remains a separate container setting.

While Wayland access is experimental the domain is deliberately broad in one
respect: it may **read and run every file type**. Python and `wl-mitm` then
start from wherever they are installed — distribution packages, pipx, uv,
`pip --user`, a checkout in the home directory — without one rule per layout.
Ordinary file permissions still apply, the domain can write only the task's
runtime directory, and the proxy's Landlock rules remain much narrower than
the SELinux domain. This breadth is to be reduced before the feature leaves
experimental status.

For every container on the host the module adds exactly two things:
`container_t` may connect to sockets of the proxy domain, and may write and
map `user_tmp_t` files it has been handed, such as compositor keymaps.

The proxy requires filesystem restrictions that narrow its executable and
writable paths further. They are not an exact-endpoint Unix-socket sandbox. SELinux also cannot
distinguish the selected compositor from another host socket with the same
process and inode labels. A compromised proxy could reach those same-label
sockets. The protocol filter and immutable configuration remain part of the
security boundary; the optional module is defense in depth, not a complete
containment guarantee.

## Direct access: `--with-wayland-direct`

This module defines `terok_wayland_direct_t`. Only `wl-direct` containers select
that process type. It is `container_t` plus desktop access: the type joins the
attributes `container_t` carries, so it receives the same stock rules, Podman's
per-container MCS categories and the host's booleans, and the module repeats
the few grants `container-selinux` gives `container_t` by name. Other
containers keep their existing type; this module does not grant `container_t`
permission to connect to desktop sockets.

The module links against the current policies of Fedora 43 to 45, CentOS
Stream 9 and 10, and openSUSE Tumbleweed. On each of them the domain holds
every permission of `container_t` except the connection to the filtered
proxy, which a direct task never uses. It is not an unconfined process
domain. A distribution that renames one of those attributes makes installation
fail visibly instead of producing a narrower domain.

The selected container can access the mounted compositor socket and receive
rendering/keymap file descriptors. The policy also preserves its access to
terok service sockets. It does not grant pathname access to host buffer files
or enable GPU passthrough. DRM access follows the ordinary container policy;
NVIDIA access retains the existing `container_use_xserver_devices` boolean.
Installing this module neither changes that boolean nor mounts GPU devices.

Direct access has **no protocol filter**. SELinux cannot distinguish the selected
compositor from other sockets with the same process and inode labels. The exact
socket mount and container namespaces limit which endpoints are reachable; the
policy is not an endpoint-specific compositor permission.

## Failures and removal

An absent optional module leaves the administrator's existing policy in charge.
Once the module is installed, a failed domain transition stops that proxy; terok
does not retry it unconfined. Proxy or container access failures produce a
warning and leave the task running without GUI access. The filtered module does
not authorize `wl-direct` access to the real compositor. Missing direct policy
also leaves the task running with a warning, not disabled SELinux labeling.

Remove either optional module independently:

```console
sudo semodule -r terok_wayland
sudo semodule -r terok_wayland_direct
```

Package upgrades do not reload host policy. After an upgrade that changes a
module, rerun setup with the same flags. A process already in a domain receives
the updated rules at once; containers using `terok_wayland_direct_t` need no
recreation. An older proxy module that does not cover the Python installation
shows up as `No module named terok_sandbox` in the supervisor log, although the
package imports normally in the host shell.

Restart filtered tasks after changing their policy. Recreate direct tasks only
when changing their container process type; an ordinary restart cannot change it.
Policy changes do not retroactively change an existing process's domain. On a denial, inspect
the supervisor log and the host's AVC audit records before changing policy.
Do not disable SELinux or generate blanket `audit2allow` rules.

## Private application runtime directory

When desktop wiring is prepared, both Wayland modes set `XDG_RUNTIME_DIR` to
`/run/terok-user` inside the container. This is a private, empty tmpfs with mode
`0700`, owned by the container's initial user. It is separate from the mounted Wayland endpoint.
The tmpfs contents disappear when the container stops; Podman creates a fresh
tmpfs on the next start. The host's desktop runtime directory is never mounted.

Recreate existing containers to receive this mount and environment variable.
An ordinary restart cannot add them. No image rebuild is required.

## Host acceptance checks

Compilation and packaging do not prove an enforcing desktop works. Check on
Fedora's enforcing default desktop before relying on this policy:

- A proxy process has type `terok_wayland_t`; its container uses `container_t`.
- A direct container has type `terok_wayland_direct_t` and retains distinct MCS
  categories. Ordinary containers still cannot connect to desktop sockets.
- Normal windows, focused keyboard input, SHM rendering and GPU DMA-buf rendering
  work. A connection-only readiness check cannot validate FD transfer.
- Clipboard, capture and synthetic-input protocols remain unavailable through
  the proxy.
- Removing the module, denying the transition, or denying the container's socket
  access keeps the task alive and emits a warning instead of exposing the raw
  compositor socket.
- Stop, restart, host reboot and task removal leave no stray proxy processes.
- Direct tasks retain gate/vault access; plain restart preserves the container
  label and reports when a changed socket or label requires recreation.

Custom SELinux users, executable labels or compositor domains can require
administrator-maintained additions. Report the specific denied operation rather
than broadening the default policy speculatively.
