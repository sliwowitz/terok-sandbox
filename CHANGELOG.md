# Changelog

## v0.7.1 — Twenty-Six Hours

## What's Changed
* fix: hand clearance.verdict_ttl to the confined clearance hub in https://github.com/terok-ai/terok-sandbox/pull/615

**Full Changelog**: https://github.com/terok-ai/terok-sandbox/compare/v0.7.0...v0.7.1

## v0.7.0 — A Man Alone

- **Breaking:** no shield profile applies unless one is named. `shield_profiles` is empty by
  default ([#549](https://github.com/terok-ai/terok-sandbox/pull/549)).
- **Breaking:** the desktop keyring has its own names. `credentials.use_keyring` is now
  `credentials.use_desktop_keyring`, the passphrase tiers are `desktop-keyring` and
  `session-cache`, and the command is `vault passphrase to-desktop-keyring`. The old names
  are not read. Re-create containers to renew their sidecar policy ([#568](https://github.com/terok-ai/terok-sandbox/pull/568)).
- **Breaking:** a credential broker serves only the task of its `BrokerContext` (scope,
  subject and credential set). A container with a legacy or malformed context is refused:
  re-create it ([#606](https://github.com/terok-ai/terok-sandbox/pull/606)).
- Optional Wayland desktop access. `RunSpec.wayland` takes `none`, `wl-mitm` or `wl-direct`.
  `wl-mitm` runs the stock wl-mitm proxy as a supervised child of the task, with a fixed
  allowlist of Wayland globals; `wl-direct` binds the compositor socket. A task gets a
  private `XDG_RUNTIME_DIR`. Each start follows the current desktop session, and a failure
  costs GUI access and a warning, not the task ([#611](https://github.com/terok-ai/terok-sandbox/pull/611)).
- `setup selinux --with-wayland` and `--with-wayland-direct` each install one optional
  SELinux policy for those modes. Both are built with the distribution's policy development
  files ([#611](https://github.com/terok-ai/terok-sandbox/pull/611)).
- `run.hosts_file` sets the base of a container's `/etc/hosts`: `none` (the default),
  `image`, or an absolute host path. The `/etc/hosts` of the host no longer reaches
  containers on podman 5.4 or later ([#604](https://github.com/terok-ai/terok-sandbox/pull/604)).
- `run.aslr_control` lets the processes of a container query and disable ASLR, as sanitizer
  runs need. The grant goes into a seccomp profile derived for that container; the profile
  of the host is not changed ([#569](https://github.com/terok-ai/terok-sandbox/pull/569), [#591](https://github.com/terok-ai/terok-sandbox/pull/591)). `run.perf` allows `perf_event_open` in the same
  way ([#592](https://github.com/terok-ai/terok-sandbox/pull/592)).
- `ShieldManager` gains `allow` (also for a stopped container), `override`,
  `revoke_override`, `inspect`, `rotation_risk`, `container_short_id` and `harvest`.
  `services.clearance: prompt | mute | off` sets the mode of each container's clearance hub
  ([#595](https://github.com/terok-ai/terok-sandbox/pull/595)).
- Moving the vault passphrase to the desktop keyring validates the passphrase, verifies
  what the keyring stored and what the configuration says, and only then removes the other
  copies. A failure keeps them, and its report carries no secret ([#568](https://github.com/terok-ai/terok-sandbox/pull/568), [#599](https://github.com/terok-ai/terok-sandbox/pull/599)).
- `CredentialsConfigError` names the files of a failed global credentials policy, so a
  caller can tell it from an invalid project ([#597](https://github.com/terok-ai/terok-sandbox/pull/597)).
- A revoked grant ends the HTTP and WebSocket forwarding that uses it, and the SSH signer
  checks token and key assignment before every operation. A strict runtime inventory and
  bounded kills serve an emergency stop ([#606](https://github.com/terok-ai/terok-sandbox/pull/606), [#607](https://github.com/terok-ai/terok-sandbox/pull/607)).
- Capture every `exec` reply within a byte budget (16 MiB by default) and one deadline;
  overflow raises `ExecOutputLimitError` instead of returning partial output. Container log
  lines and doctor details are terminal-safe ([#608](https://github.com/terok-ai/terok-sandbox/pull/608)).
- `update_section` updates a config file in place: a symlink stays a symlink, and the file
  keeps its mode and owner ([#593](https://github.com/terok-ai/terok-sandbox/pull/593)).
- A sealed container keeps the file overlays of its task over shared configuration
  ([#605](https://github.com/terok-ai/terok-sandbox/pull/605)).
- After a rootfs permission failure of runc, the error lists the storage directories whose
  owner or group the rootless mapping lacks ([#600](https://github.com/terok-ai/terok-sandbox/pull/600)).
- The vault answers an empty Bearer token with 401, not 500 ([#576](https://github.com/terok-ai/terok-sandbox/pull/576)).
- Every option of the config schema has a description ([#601](https://github.com/terok-ai/terok-sandbox/pull/601)).
- Python 3.15 is supported.

**Full Changelog**: https://github.com/terok-ai/terok-sandbox/compare/v0.6.0...v0.7.0

## v0.6.0 — At Your Service

- Own sandbox setup readiness and compose Shield checks downward. Rerun setup after upgrading; downgrades are unsupported.
- Use the launching host PATH for tools and setup-bound standalone Python hooks, including on NixOS.
- Serialize setup and uninstall with the other packages.
- Refuse stale initial passphrase provisioning without replacing an existing key.

## What's Changed
* vault: forward compressed request bodies undecoded in https://github.com/terok-ai/terok-sandbox/pull/559
* bridges: TLS leg in front of the vault loopback in https://github.com/terok-ai/terok-sandbox/pull/560
* vault: scope-specific SSH defaults and consistent key naming in https://github.com/terok-ai/terok-sandbox/pull/558

**Full Changelog**: https://github.com/terok-ai/terok-sandbox/compare/v0.5.0...v0.6.0

## v0.5.0 — Past Prologue

## What's Changed
* fix: stoppable task containers — --init pid1 + state-watching stop() in https://github.com/terok-ai/terok-sandbox/pull/454
* feat(vault): programmatic passphrase-tier provisioning API for TUI frontends in https://github.com/terok-ai/terok-sandbox/pull/456
* feat(gpu): per-device grants + vendor-scoped raw DRM mounts in https://github.com/terok-ai/terok-sandbox/pull/463
* fix(gpu): by-path binds must use --mount — PCI addresses break -v parsing in https://github.com/terok-ai/terok-sandbox/pull/464
* feat(gate): agent-op backups + push marker via sandbox-owned hooks in https://github.com/terok-ai/terok-sandbox/pull/483
* feat(vault): replace session-file tier with a kernel-keyring cache in https://github.com/terok-ai/terok-sandbox/pull/489
* refactor!: rename the shield kill-switch to 'disabled' and the DOWN flag to 'disengaged' in https://github.com/terok-ai/terok-sandbox/pull/521
* feat: user-friendly hints for AppArmor and SELinux in https://github.com/terok-ai/terok-sandbox/pull/537
* feat: forward credential metadata as OAuth headers in https://github.com/terok-ai/terok-sandbox/pull/548


**Full Changelog**: https://github.com/terok-ai/terok-sandbox/compare/v0.4.1...v0.5.0

## v0.4.1 — You Exist Here

* Resilient clone-cache refresh, https://github.com/terok-ai/terok-sandbox/pull/430
* Fast cold-start reconnect for gate + retry on vault bridges, https://github.com/terok-ai/terok-sandbox/pull/426
* Resilient gate restart after upgrade https://github.com/terok-ai/terok-sandbox/pull/428

**Full Changelog**: https://github.com/terok-ai/terok-sandbox/compare/v0.4.0...v0.4.1

## v0.4.0 — The Celestial Temple

* Better UI for vault passphrase handling, https://github.com/terok-ai/terok-sandbox/pull/408, https://github.com/terok-ai/terok-sandbox/pull/399, https://github.com/terok-ai/terok-sandbox/pull/402, https://github.com/terok-ai/terok-sandbox/pull/400, https://github.com/terok-ai/terok-sandbox/pull/398
* Container lifecycle verbs, https://github.com/terok-ai/terok-sandbox/pull/411
* Operator hints https://github.com/terok-ai/terok-sandbox/pull/417, https://github.com/terok-ai/terok-sandbox/pull/419

**Full Changelog**: https://github.com/terok-ai/terok-sandbox/compare/v0.3.1...v0.4.0

## v0.3.2 — We are constantly searching

## What's Changed
* Vault diagnostics improved https://github.com/terok-ai/terok-sandbox/pull/408, https://github.com/terok-ai/terok-sandbox/pull/399, https://github.com/terok-ai/terok-sandbox/pull/400
* Remote API fix: preserve URL-encoded path segments when forwarding, https://github.com/terok-ai/terok-sandbox/pull/402

**Full Changelog**: https://github.com/terok-ai/terok-sandbox/compare/v0.3.1...v0.3.2

## v0.3.1 — Start Again

hotfix: rebuild the per-container runtime dir in Sandbox.start, https://github.com/terok-ai/terok-sandbox/pull/396

**Full Changelog**: https://github.com/terok-ai/terok-sandbox/compare/v0.3.0...v0.3.1

## v0.3.0 — Locks and Hooks

Hotfix for vault passphrase error modes [#390](https://github.com/terok-ai/terok-sandbox/pull/390) and supervisor restart [#389](https://github.com/terok-ai/terok-sandbox/pull/389)

**Full Changelog**: https://github.com/terok-ai/terok-sandbox/compare/v0.2.0...v0.3.0

## v0.2.0 — Emissary, Part II

## What's Changed
* Combining LLM providers × agents, https://github.com/terok-ai/terok-sandbox/pull/374
* podman container event stream, https://github.com/terok-ai/terok-sandbox/pull/375
* SSH key M:N routing to projects, https://github.com/terok-ai/terok-sandbox/pull/385
* Vault debugging and safer locking, https://github.com/terok-ai/terok-sandbox/pull/386

**Full Changelog**: https://github.com/terok-ai/terok-sandbox/compare/v0.1.0...v0.2.0

## v0.1.0 — The Emissary

**First public PyPi release**

## What's Changed

* resolve gate binary via sys.executable -m, like vault, https://github.com/terok-ai/terok-sandbox/pull/309
* accept %host-style infrastructure scopes, https://github.com/terok-ai/terok-sandbox/pull/320
* KrunRuntime — KVM microVM isolation backend (Phase 3), https://github.com/terok-ai/terok-sandbox/pull/324
* Install PYTHONPATH to SystemD service files by @franzpoeschel in https://github.com/terok-ai/terok-sandbox/pull/338
* add check_gpu_available(), https://github.com/terok-ai/terok-sandbox/pull/362
* AppArmor profile installer for the dnsmasq DNS tier, https://github.com/terok-ai/terok-sandbox/pull/367
* per-container supervisor; retire host vault + gate daemons, https://github.com/terok-ai/terok-sandbox/pull/366

## New Contributors
* @franzpoeschel made their first contribution in https://github.com/terok-ai/terok-sandbox/pull/338

**Full Changelog**: https://github.com/terok-ai/terok-sandbox/compare/v0.0.123...v0.1.0
