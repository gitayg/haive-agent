# Per-device relay secrets — wire contract

**Problem.** A device authenticates every `/relay/*` call with the owner's enrollment token
(`htok_…`). That one token is shared by the owner's whole fleet, it sits on the agent's argv
and in every autostart/service entry, and rotating it disconnects every device.

**Goal.** The enrollment token is used once, to enroll. The hub then issues each device its
own secret (`hdev_…`), which the agent keeps in a private file and uses from then on.
Rotating the enrollment token leaves enrolled devices connected; one device's secret can
be revoked alone; no token is left on any command line.

This file is the contract between the hub (`RemoteScreen/crates/hub`) and the agent
(`haive-agent/crates/agent`). Change it here first.

## Hub (3.16.0)

**Store.** `<HUB_DATA>/device_secrets.json`, written with `secretfile` (0600, dir 0700):
`{ "<relay_id>": { "hash": "<sha256 hex of the secret>", "owner": "<owner id>", "issued": <unix secs> } }`.
Only the hash is stored. Secrets are `hdev_` + 32 random bytes as lowercase hex.

**`POST /relay/hello?id=<rid>&tok=<t>[&ds=1]`**
- `t` starts with `hdev_` → valid only if `sha256(t)` equals `store[rid].hash`
  (constant-time). Owner = `store[rid].owner`. A valid device secret proves identity, so it
  may heartbeat an existing tunnel even if that tunnel was bound to a different token
  (re-bind the tunnel's `auth` to `auth_hash(t)`). Invalid → 401, body
  `device credential rejected`.
- Otherwise: today's enrollment-token / shared-token behaviour, unchanged. In addition,
  when the call carries `ds=1`, authenticated with an **enrollment token** (`htok_…`), the
  hub mints a fresh secret for `rid` (replacing any previous one, but only if the existing
  entry's owner equals this token's owner; a different owner → 403
  `relay id in use by another enrollment`), stores it, and answers
  **200 `{"device_secret":"hdev_…"}`** instead of 204. Without `ds=1` (agents ≤ 3.6.x) the
  hub never mints and always answers 204 as today.

**Every other `/relay/*` route (`relay_ok`).** Also accept `tok=hdev_…` when it matches
`store[id].hash` for the request's `id` query param. A device secret without `id`, or not
matching that `id`, is rejected. The shared `RELAY_TOKEN` comparison becomes constant-time.

**Rotation.** `rotate_enroll_token` keeps deleting the old enrollment token. Devices
holding a device secret are unaffected; devices still on their enrollment token (no
secret yet, i.e. agent ≤ 3.6.x) are disconnected, as today. Fix the comment, the confirm
dialog, and `docs/SECURITY.md` to say exactly this.

**Revoke.** `POST /x/device-secret/revoke?target=<t>` (dashboard; `may_control`, audited
as "revoke device secret") deletes `store[rid]`. The device's next call gets 401. Removing
or dissolving a device also deletes its entry.

**Dashboard.**
- Each device shows whether it holds a device secret ("own credential" vs "enrollment
  token").
- A Revoke button sits next to it.
- The Register-a-device panel warns before Rotate: "N of M devices still authenticate
  with the enrollment token and will be disconnected."

## Agent (3.7.0)

**Credential file.** `~/.it-ai/relay.cred` (`$HOME`; `%USERPROFILE%` on Windows), mode
0600 in a 0700 dir: `{ "hub": "<normalized hub URL>", "enroll": "htok_…"?, "device": "hdev_…"? }`.

**Which token a relay call uses, at startup:**
1. `relay.cred` exists, its `hub` equals the normalized `--relay`, and `device` is set → use
   `device`.
2. Otherwise the enrollment token from `--relay-token`, then `HIVE_RELAY_TOKEN`, then
   `relay.cred`'s `enroll`. None → the existing "relay mode requires an enrollment token"
   error.

**Hello.** Always send `ds=1`. On a 200 whose body has `device_secret`:
- write `relay.cred` as `{hub, device}`, **dropping `enroll`**;
- switch every relay caller (hello/poll/reply, config poll, cap-key, hub cert, analysis,
  AI relay) to the new secret in memory, via one shared credential holder, not per-thread
  copies;
- log `relay: device credential issued`.

**Rejected secret.** If a call made with a device secret gets 401: log loudly
`relay: device credential rejected — re-enroll this device`. If an enrollment token was
supplied on this start (flag or env), fall back to it with `ds=1` to re-enroll. Otherwise
keep retrying slowly (≥ 60 s); never exit.

**Every relay URL carries `id=<relay_id>`.** Add it where it is missing today: config
poll, cap-key, hub cert.

**Token off the command line.**
- `persist_args()` strips `--relay-token <v>` and `--relay-token=<v>`. Before an autostart or
  service entry is written, if `relay.cred` has no `device`, write `{hub, enroll}` so the
  entry works after a reboot that happens before the first hello.
- **Re-enroll.** An enrollment token given to a command-line `--persist` / `--install` replaces
  the stored credential (device secret included) with `{hub, enroll}`; the next hello mints a
  fresh secret. Two paths that carry the original start's arguments are exempt and never drop
  a stored secret: the self-update restart (marked with `IT_AI_SELF_RESTART=1`, which `main`
  reads and clears) and `POST /persist`.
- **Startup fetches.** The capability-key and hub-cert fetches handle a 401 on a device secret
  like hello does: fall back to the enrollment token supplied on this start and retry once.
- `relaunch_detached()` strips the token from the child's argv and passes it as
  `HIVE_RELAY_TOKEN` in the child's environment.
- **Service installs (`--install`, root).** A service may start with no `HOME` (systemd
  without `User=`) or a different one from the `sudo` that installed it. So for service
  installs, both the `relay.cred` write and the service's home come from the **passwd
  entry of the effective uid** (`getpwuid(geteuid())`, e.g. `/root` on Linux, `/var/root`
  on macOS); any inherited `HOME` is ignored. That dir is pinned in the entry:
  `Environment=HOME=<dir>` in the systemd unit, `EnvironmentVariables/HOME` in the
  LaunchDaemon plist. Windows (schtasks runs as the installing user) and `--persist`
  autostart entries are unchanged. Existing service entries keep working because they still
  carry `--relay-token`; from agent 3.8.2 the agent removes it itself (below).

**Unchanged:** `direct_token` / LAN-direct semantics. If its derivation depends on the
relay token, keep its value stable across the switch, and report how.

**Compatibility.**
- An old agent with a new hub: never sends `ds=1`, so nothing changes for it.
- A new agent with an old hub: the hub ignores `ds`, answers 204, and the agent stays on
  its enrollment token.
- Existing installs with `--relay-token` in their autostart entry keep working. `POST /persist`
  (or re-running `--install`) rewrites the entry without it.
- **Agent 3.8.2: an agent removes the token from its own old entry** (`entryclean.rs`). At every
  start in relay mode, once it holds a device secret for this hub, each of its own entries that
  still carries `--relay-token` (`.desktop` / `it-ai.service`, the `com.itai.agent` plists, the
  `IT-AI` Run value / scheduled task) is rewritten without it, but only when the rewritten entry
  provably finds the same `relay.cred`: the HOME it runs with is read from the entry (an unpinned
  root unit: `/`, its cwd), and that `relay.cred` must be the file the secret was loaded from
  (`RelayCred::file`, absolute). If it differs, HOME is pinned in a root unit/LaunchDaemon when the
  agent is root (and in a LaunchAgent), otherwise the entry is left with a log line. The pinned
  HOME is `service_home()` when the credential is found there, else the directory holding it, and
  only if it and its `.it-ai` pass `securefs::check_trusted_dir`: every component from `/` down,
  symlinks and their targets included, owned by root or the agent's euid and not group/world
  writable. Credentials are never moved or copied. The new text
  is read back and checked again before it is written. Files are touched only through
  `entryclean/securefs.rs`: no symlink is followed (the directory is opened `O_DIRECTORY|O_NOFOLLOW`,
  the entry `lstat`ed and opened `O_NOFOLLOW` relative to it, same dev/ino), the file and its
  directory must be owned by the agent's euid and every directory above by it or root, none
  group/world-writable, the file single-linked; the temp file is `O_CREAT|O_EXCL|O_NOFOLLOW` in that
  directory and `renameat` on the directory fd replaces the entry after re-checking it is still the
  inode that was read. A scheduled task is changed only when its principal is this user. Write-only: atomic file replace (mode and
  owner kept), `systemctl daemon-reload`, `schtasks /Change /TR` on an `InteractiveToken` task of
  this user; nothing is started, stopped or loaded. Hello sysinfo gains
  `autostart_token: bool`.
