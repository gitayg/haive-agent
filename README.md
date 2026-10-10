# IT-AI — endpoint agent

Open-source endpoint client for **IT-AI** — a self-hosted, LAN-first + reverse-tunnel
remote-administration hub. This repo holds the three pieces that run **on your machines** (the
hub itself is separate and private):

| Binary | Crate | What it is |
|---|---|---|
| `IT-AI` (`it-ai`) | `crates/agent` | the endpoint agent — connects out to a hub over an HTTPS relay tunnel, serves screen/input/shell/camera/telemetry |
| `it-ai-mcp` | `crates/mcp` | an MCP server your coding agent (Claude Code, etc.) talks to, to drive the fleet |
| `itai` | `crates/cli` | a small command-line client for the hub |

Everything here is **MIT** and built in public CI. Nothing phones home to a hardcoded host:
the hub URL and any token are runtime parameters (`--relay <url>` with `--relay-token htok_…`
or `HIVE_RELAY_TOKEN` for the agent, `HAIVE_HUB` for the MCP and CLI) — there are no embedded
endpoints or secrets.

## Why this is public

So you (and your tools) don't have to trust an opaque binary. A coding agent *should* refuse to
download and run an unknown executable — here the source is auditable, and every released binary
carries **signed build provenance** (see below) tying it to the exact commit + workflow that
produced it.

## Install

Downloads are anonymous from the GitHub Release. Pick the asset for your OS/arch:
`it-ai-linux` · `it-ai-linux-arm64` · `it-ai-macos` · `it-ai-windows.exe`
(same suffixes for `it-ai-mcp-*` and `itai-*`).

**macOS (Apple Silicon):**
```sh
curl -fsSL -o ~/.it-ai/it-ai-mcp https://github.com/gitayg/haive-agent/releases/latest/download/it-ai-mcp-macos && chmod +x ~/.it-ai/it-ai-mcp
```
**Linux x86-64 / arm64:** swap the asset name (`it-ai-mcp-linux` or `it-ai-mcp-linux-arm64`).

Register the MCP with Claude Code (fill in your own hub + token + owner):
```sh
claude mcp add-json itai '{
  "command": "'"$HOME"'/.it-ai/it-ai-mcp",
  "env": {
    "HAIVE_HUB": "https://your-hub.example.com",
    "HIVE_MCP_TOKEN": "<your-mcp-token>",
    "HIVE_OWNER": "<your-owner-id>"
  }
}'
```
`/mcp` → approve once. The agent then calls the tools and downloads nothing at runtime.

**`itai` CLI on macOS / Linux, one command** (from a checkout of this repo):
```sh
export HAIVE_HUB=https://your-hub.example.com
export HIVE_MCP_TOKEN=...          # from your secret manager; the script never prompts for it
sh scripts/setup-itai.sh
```
`scripts/setup-itai.sh` fails before downloading anything if `HAIVE_HUB` or `HIVE_MCP_TOKEN` is
unset, and warns when `HAIVE_HUB` is not `https://` (localhost excepted). It picks the asset for
the machine (`itai-linux`, `itai-linux-arm64`, or `itai-macos` on Apple Silicon, including a shell
under Rosetta; Intel macOS and Windows are refused), downloads it with the release `SHA256SUMS`,
and refuses to install on a missing, malformed or mismatched checksum. It installs `itai` into
`$INSTALL_DIR`, notes when that directory is not on `PATH`, then runs `itai list` as a read-only
connectivity check with any `mtok=` value in its output replaced by `REDACTED`. The token is read
from the environment only: never put on a command line, printed, or written to disk.

| Variable | Default | |
|---|---|---|
| `HAIVE_HUB` | *(required)* | hub URL |
| `HIVE_MCP_TOKEN` | *(required)* | token for the hub's `/m` API |
| `HIVE_OWNER` | *(unset)* | owner id, when the hub serves several users |
| `ITAI_VERSION` | latest | release tag to install, with or without the leading `v` |
| `INSTALL_DIR` | `$HOME/.local/bin` | install directory |
| `ITAI_BASE_URL` | `https://github.com/gitayg/haive-agent/releases` | releases base URL |

## Enroll a device

The hub dashboard's *Register a device* panel shows the exact command. Its shape:
```sh
HIVE_RELAY_TOKEN=htok_… ./it-ai --relay https://your-hub.example.com --name <device> --persist
```
`--relay-token htok_…` works too, but the environment variable keeps the token off the command
line. `--persist` adds a per-user autostart entry; `--install` (run as root/admin) installs a boot
service instead.

From agent 3.7.0, with hub 3.16.0 or later:
- **The enrollment token is used only to enroll.** On its first hello the agent asks the hub for
  its own credential, a device secret (`hdev_…`), logs `relay: device credential issued`, and
  uses that secret for every relay call from then on. The enrollment token is dropped.
- **Where it lives:** `~/.it-ai/relay.cred` (`%USERPROFILE%\.it-ai\relay.cred` on Windows), mode
  0600 in a 0700 directory; on Windows it inherits the profile's ACL. It is tied to the hub URL,
  and a file written for another hub is ignored. For `--install` on macOS and Linux the file goes
  in the home directory of the service user from the passwd entry (`/var/root`, `/root`), not the
  `HOME` of the `sudo` that ran it, and that `HOME` is pinned in the LaunchDaemon plist / systemd
  unit.
- **The token is not kept on any command line.** Autostart and service entries written by
  `--persist`, `--install` or `POST /persist` no longer contain `--relay-token`. Until the device
  has its own secret, the enrollment token is saved in `relay.cred` instead, so the entry still
  enrolls after a reboot. `--background` and the restart after a self-update pass the token to the
  new process in `HIVE_RELAY_TOKEN`, not in its arguments.
- **At startup** the agent uses the device secret in `relay.cred` if there is one for this hub;
  otherwise `--relay-token`, then `HIVE_RELAY_TOKEN`, then an enrollment token saved in
  `relay.cred`. With none of these it exits with `relay mode requires an enrollment token`.
- **Existing installs keep working.** An entry written by an older agent still carries
  `--relay-token`; the agent enrolls with it and gets its own secret on the first hello. Against a
  hub older than 3.16.0 the agent simply stays on the enrollment token.
- **Existing installs clean themselves up (agent 3.8.2+).** At every start, once the agent holds a
  device secret for this hub, it removes `--relay-token` from its own old entry: the `.desktop`
  autostart and the `it-ai.service` unit on Linux, the `com.itai.agent` LaunchAgent and LaunchDaemon
  on macOS, the `IT-AI` Run value and the `IT-AI` scheduled task on Windows. So the first start on
  3.8.2, which is usually the restart after the self-update, takes the token off the command line.
  - **It rewrites an entry only if the rewritten entry will find the same `relay.cred`.** The
    agent works out the HOME the entry runs with from the entry itself and compares that
    `relay.cred` with the file it loaded its secret from. An old systemd unit has no HOME, so it
    looks in `/.it-ai`. When the secret is elsewhere, the agent pins `Environment=HOME=` in the
    unit, or `EnvironmentVariables/HOME` in a plist, but only for a root service when the agent
    is root, and only to a directory that root (or the agent's own user) alone can change, checked
    from `/` down, symlinks included. That is the service account's passwd home when the
    secret is there, otherwise the directory that holds it. A root service is never pointed at a
    directory a user could plant a credential, certificate or job in. No credential is ever moved
    or copied. A `.desktop` entry, a Run value and a scheduled task cannot pin HOME, so they are
    rewritten only when they already find the file. A task is changed only when it runs as this
    user with no stored password (`InteractiveToken`). Every other case is left as it is, with a
    log line saying why.
  - **It only rewrites a file nobody else can change.** It never follows a symlink: the entry's
    directory is opened once, and the entry is read, checked and replaced through that
    directory with `O_NOFOLLOW`, `O_EXCL` and `renameat`. The file and its directory must belong to
    the agent's own user, every directory above them to that user or root, and none of them may
    be writable by others, as with ssh's `StrictModes`. So a root agent never rewrites a
    file in a directory a user can change. An entry that fails these checks is left as it is,
    with a log line.
  - **Group-write is allowed only in the user's private group (agent 3.8.3+).** Debian and Ubuntu
    give each user a group of their own and umask 002, so a desktop user's `~/.config/autostart`
    is 0775 and `it-ai.desktop` 0664, both `user:user`. 3.8.2 refused any group-writable file or
    directory, so on most Ubuntu desktops the clean-up never ran and the token stayed in the file.
    Group-write on a path owned by the agent's user now counts as safe only when every one of
    these is proven, and the log line names the first that is not:
    - the path's gid is the user's primary gid, and the group's name is the user's name;
    - the group lists no supplementary members, and no other passwd entry has that gid as its
      primary group;
    - `/etc/nsswitch.conf` provably takes users and groups only from this machine, where all of
      them can be listed, so "no other user has this group" can be checked. It is read strictly
      and anything this reading might get differently from glibc is refused. The file must exist
      and be readable, and every non-comment line must be `database: sources`. It needs exactly
      one `passwd:` and exactly one `group:` line, with database names compared ignoring case. Those
      lines may have no `[...]` action items. Their sources may only be `files` and `systemd`, or
      `compat` when there is no `passwd_compat:`/`group_compat:` line and `/etc/passwd`
      (`/etc/group`) has no `+`/`-` NIS entry. Any other source (`sss`, `ldap`, `winbind`, `nis`,
      `cache`, an unknown or differently-cased name), a missing or duplicated line, or an
      unreadable file means the group is not proven private, and the entry is left alone. A
      vendor file such as openSUSE's `/usr/etc/nsswitch.conf` is not read: without
      `/etc/nsswitch.conf` the rule never applies, and neither does it on macOS, which has none.

    This is the rule Debian patches into OpenSSH's `StrictModes`
    (`debian/patches/user-group-modes.patch`, "Allow harmless group-writability", Debian bug
    #314347), made stricter. Debian also accepts the owner listed as the group's only member, and
    it trusts NSS enumeration from any source. World-writable is always refused, so is group-write
    in any shared group, and root-owned paths never get the exception (no group-write at all). The
    same rule applies to the HOME a root service would be pinned to, which must still be root's own.
  - **It never starts, stops or loads anything.** Files are replaced atomically and keep their
    mode and owner. A unit is followed by `systemctl daemon-reload` only. A plist takes effect at
    its next load. The task is changed in place with `schtasks /Change /TN IT-AI /TR …` and no `/RU`, `/RP` or
    `/RL`, so its principal and run level are not part of the change.
  - It logs one `autostart:` line per entry it rewrites or leaves, and nothing once the entries
    are clean. Each hello reports `autostart_token: true|false`: whether any of the agent's own
    entries still carries the token. A hub that does not know the field ignores it.
  - `scripts/entryclean-e2e.sh` checks this in Docker against old `.desktop` and unit entries,
    and starts each rewritten entry to confirm it finds the device secret. It also checks that a
    root agent leaves a user-owned entry and a symlinked unit alone, and never pins a unit's HOME
    to a user-owned directory. Since 3.8.3 it also strips a 0664 entry in a 0775 directory of a
    user whose private group has no members, and leaves the same entry alone in a shared group
    (another member, or another user's primary group), when the group is not named for the user,
    when nsswitch.conf takes users from `sss` or has a second `PASSWD:` line, and when it is
    world-writable. It also checks that a
    root agent never follows an `agent.log` or `~/.it-ai` symlink another user planted.
- **After a revoke.** When the hub refuses the device secret, the agent logs
  `relay: device credential rejected — re-enroll this device` and retries every 60 s; it never
  exits. If an enrollment token was passed on this start (flag or `HIVE_RELAY_TOKEN`), it
  re-enrolls with it at once. Otherwise re-run the enrollment command (`--persist` or
  `--install` with a current `--relay-token`): a token given on the command line replaces the
  stored credential, and the next hello issues a fresh secret. A self-update restart and
  `POST /persist` never do this — they keep a working secret even though they carry the
  original start's arguments.

## Verify what you downloaded

**Integrity** — every release ships a `SHA256SUMS`:
```sh
curl -fsSL -O https://github.com/gitayg/haive-agent/releases/latest/download/SHA256SUMS
shasum -a 256 it-ai-mcp-macos    # compare against the matching line
```
**Provenance** — each binary has a Sigstore-signed attestation:
```sh
gh attestation verify it-ai-mcp-macos --repo gitayg/haive-agent
```

## Updates

An enrolled agent keeps itself on the build its hub serves. Every two minutes it fetches the hub's
small `/bin/SHA256SUMS` and compares the published hash for its platform with its own executable;
only when they differ does it download the binary, check its ed25519 signature against the pinned
key, and replace itself. A hub that publishes no checksum file gets the older behaviour (download
and compare bytes). A hub can also push an update (`POST /update`); if the pushed binary is
byte-identical to the one running, the agent answers "already running this build" instead of
reinstalling and restarting. The checksum file is not signed — a hub lying about it can only
delay an update, never install one, because every installed binary must carry a valid signature.

From agent 3.7.1 only one update runs at a time. A pushed `POST /update` that arrives while the
two-minute check is installing (or the other way round) answers `409 an update is already in
progress` and the check skips that cycle. Each update writes its own temp file, and the agent
refuses to install a 0-byte binary or one whose size on disk does not match what it downloaded.
It stays on the current version instead. Before 3.7.1 the two updaters shared one temp file and
could install an empty binary, which left the device dead until it was reinstalled by hand.

On macOS, an agent started by launchd (`--persist` LaunchAgent or `--install` LaunchDaemon) now
writes stdout and stderr to `~/.it-ai/agent.log`. For the LaunchDaemon that is the service account's
home, `/var/root/.it-ai/agent.log`. A `--background` agent already logged there. The installer
creates the file as 0600 in a 0700 directory. At startup the agent empties it in place if it has passed 1 MB.
Re-run `--persist` or `--install` to add logging to an existing install.

On Windows, from agent 3.8.2, the agent that a self-update starts appends its stdout and stderr to
the same `%USERPROFILE%\.it-ai\agent.log` as a `--background` start, with the same 0600 file and
1 MB cap. Before 3.8.2 that output went nowhere, so after an update the log stopped at the old
version. On macOS and Linux an update `exec`s the new binary, which keeps the old process's stdout
and stderr. A test checks this.

On Linux and macOS, from agent 3.8.3, an agent started without a terminal points its own stdout and
stderr at `~/.it-ai/agent.log` (0600, appending, the same 1 MB cap) at startup. This is the Linux
desktop autostart: the `.desktop` entry's `Exec=` has no `--background`, so the agent used to write
wherever the session sent its output, and `agent.log` stopped at the last `--background` start
(measured on Ubuntu 26.04 GNOME: the log stopped at 3.3.1 while the agent ran 3.8.2). It applies
when stdout is a pipe, a socket, `/dev/null` or closed. It does not apply when stdout is a terminal,
or a regular file: launchd's `StandardOutPath` is already `agent.log`, so a launchd agent is not
redirected a second time, and neither is a `--background` child or a `> file`. A systemd service
keeps logging to the journal (`journalctl -u it-ai`): the agent stays on it when `$JOURNAL_STREAM`
names the device and inode of its own stdout or stderr, as systemd.exec(5) says to check, and
`$SYSTEMD_EXEC_PID`, when set, is the agent's own pid. A variable merely inherited from a service
further up the tree (a desktop session started by systemd) does not count. A Linux autostart agent
therefore logs to `~/.it-ai/agent.log` of the user it runs as. The unix restart after an update
`exec`s with the same descriptors, so it keeps logging there too.

On Linux and macOS the agent never opens its log through a link (3.8.3). `~/.it-ai` is opened
`O_DIRECTORY|O_NOFOLLOW` and must be a directory of the agent's own user. `agent.log` is opened
relative to it with `O_NOFOLLOW` and must be a regular file of that user with one link. A mode an
older agent left loose is tightened through those descriptors (0700 and 0600), and the 1 MB trim
truncates that descriptor, never a path. Otherwise the agent does not log there and says why on
stderr. This covers the `--background` relaunch, the trim at every start and the redirect above. So
a root agent whose `~/.it-ai/agent.log`, or `~/.it-ai`, another user turned into a link never
appends to, chmods or truncates the file it points at. Windows opens the path as before.

## LAN-direct

When a controller and an agent share a network, traffic goes **straight over the LAN** instead of
round-tripping through the cloud hub — screen frames, file transfer, shell, input and exec all ride
the same shortcut, because it is chosen once at the transport layer rather than per feature.

It is automatic. The agent listens on `0.0.0.0:8765` serving the hub-signed leaf cert whose SANs are
its own LAN IPs, so the controller validates it against the hub CA — no self-signed exception. The
controller probes that address and **the probe succeeding is the detection**; any failure (no LAN
route, refused, TLS, timeout) falls back to the relay, so nothing breaks off-LAN.

**A direct call is still governed.** Reaching an agent over the LAN does not bypass the hub: before
each direct call the controller mints a short-lived (60 s) ed25519 **capability** from the hub, and
the hub issues it only after running the same authorization, command deny-list and audit it runs on
the relay path. The agent verifies the capability — bound to the device, the operation, and a hash of
the arguments — in addition to its own token gate, and refuses the call without one. So the audit
trail and policy apply wherever the command came from. The cost is one hub round-trip per operation,
which is why the win here is bandwidth (screen, files) rather than latency on tiny commands.

Set `HIVE_LAN=0` on the agent to opt out and bind loopback only.

`itai` talks to the hub's `/m/*` API, so it needs a token: `--mtok` / `HIVE_MCP_TOKEN`, plus
`--owner` / `HIVE_OWNER` when a hub serves several users.

The token travels as `?mtok=` in the request URL, and transport errors quote that URL. `itai`
and `it-ai-mcp` mask the value (`mtok=***`) in every error they print or return.

## Background jobs

A job is a long-running command on a device (a dev server, a build) that outlives the ~65 s
limit of a single exec. Start it, read its output as it grows, stop it; each is a separate short
call. The wire contract is [`docs/JOBS-API.md`](docs/JOBS-API.md).

```sh
itai job start <device> [--cwd DIR] -- <command…>   # prints the job id
itai job logs  <device> <id> [--offset N] [--follow]
itai job stop  <device> <id>
itai job list  <device>
```
- The words after `--` are joined with spaces and run by the device's shell, so inner quoting
  is lost: `-- sh -c 'a; b'` does not work. Pass a compound command as one quoted argument:
  `itai job start dev -- 'for i in 1 2 3; do echo $i; sleep 1; done'`. (`itai exec` behaves the same.)
- `job logs` prints the output from `--offset` (default 0), then `[next offset N · running]` or
  `[next offset N · exited <code>]` on stderr; pass that offset back to read only what is new.
- `--follow` keeps reading from the returned offset, waiting 2 s whenever it has caught up,
  until the job has exited and all output is read, then prints `exit code: <n>`.
- `job stop` ends the job **and its child processes**.

MCP tools, same operations:

| Tool | Returns |
|---|---|
| `job_start(device, command, cwd?)` | job id, pid and log path |
| `job_logs(device, id, offset?)` | a JSON line with the next `offset`, `running`, `exit_code`, `eof`, `size`, then the output text |
| `job_stop(device, id)` | whether it was running, and the exit code |
| `job_list(device)` | id, running or exit code, pid, start time (unix secs), command |

On the agent:

- Four endpoints, `POST /jobs/start` (body `{"cmd","cwd"?}`), `GET /jobs/logs?id=&offset=&max=`,
  `POST /jobs/stop?id=`, `GET /jobs/list`. All are privileged like `/exec`, and `/jobs/start`
  answers 403 `remote exec disabled` when the agent runs with `SCREEN_EXEC=0`.
- The command runs through the same shell as `/exec` (`sh -c` / `cmd /S /C`) in its own process
  group, stdin closed, stdout and stderr appended to one file, `~/.it-ai/jobs/<id>.log`.
- Ids are `j` + unix milliseconds + 4 hex chars; anything outside `[a-z0-9]` gets 400, an unknown
  id 404 `unknown job`.
- A logs read returns at most `max` bytes (default 64 KiB, capped at 1 MiB). `eof` is true only
  once the job has exited and the read reached the end of the log.
- Stop: unix sends SIGTERM to the process group and SIGKILL after 5 s; Windows runs
  `taskkill /T /F /PID`.
- The job list is in memory. It keeps the 50 most recent jobs, dropping the oldest finished ones
  (running jobs are never dropped); an agent restart forgets it. Log files stay on disk.

The hub authorizes, deny-list-checks (as a `launch`) and audits `job/start` exactly like an exec;
a read-only MCP token cannot start or stop a job. Jobs are **relay-only** in this version: the CLI
and MCP call the hub's `/m/job/*` routes, not the LAN-direct path. A device needs agent 3.6.0 or
later; for an older one the hub returns `the agent does not support jobs — update it`.

## VPN exit

A device can act as a WireGuard exit, so pass holders browse with its public IP even when it sits
behind CGNAT: the agent dials out to the hub's UDP relay, and the relay only carries WireGuard
ciphertext. It is enabled per device from the hub dashboard, which drives the privileged
`/vpn/status`, `/vpn/apply` and `/vpn/disable` endpoints.

- **Linux only.** Other platforms answer `/vpn/apply` with 400.
- **Needs root**, meaning the service install (`--install`). The agent checks for uid 0, so
  `CAP_NET_ADMIN` alone is not enough. It installs `wireguard-tools` and `iptables` with `apt-get`
  when they are missing.
- It creates the `itai-wg` interface (`10.77.0.1/24`, falling back to `wireguard-go` when the
  kernel has no WireGuard module), turns on IPv4 forwarding, and adds iptables NAT and filter
  rules tagged `it-ai-vpn`. Those rules block the device itself, private and CGNAT ranges, and
  peer-to-peer traffic, and drop any other forwarded traffic to or from `itai-wg`. Every apply,
  and every uplink change (Wi-Fi to Ethernet), first deletes all tagged rules whatever interface
  they named, then inserts the full set at fixed positions at the top of each chain, so the
  peer-to-peer and private-range drops always sit above the accepts. Disabling removes the interface
  and every tagged rule.
- **IPv4 forwarding is put back.** Before turning it on, the agent records the previous
  `ip_forward` value in `~/.it-ai/vpn/ip_forward.before`. If it was `0`, the agent is the reason
  forwarding is on: a tagged rule then drops every forwarded packet that does not involve
  `itai-wg`, and disabling sets `ip_forward` back to `0`. If it was already `1` (a Docker host, a
  router), the agent adds no such rule and leaves it on when disabled. The FORWARD chain policy is
  never changed.
- The agent only receives each pass's public key and preshared key; it never sees a client's
  private key. Pass expiry is enforced on the device too, and the applied state is restored after
  a reboot.
- Apply, disable, the boot resume and the expiry ticker run one at a time. A disable stops a resume
  that is still retrying, and the ticker cannot write back a pass list that a disable or a newer
  apply replaced.

## Operator skill

[`skills/it-ai/SKILL.md`](skills/it-ai/SKILL.md) is a Claude Code skill for operating a fleet
through `it-ai-mcp` or `itai`: which tool fits which task (short command vs job, `upload_file` vs
`push_file`), how to treat hub refusals (report them, never route around the deny-list), which
actions to confirm first, reading `update_agent` replies, and keeping the token out of command
lines and output. Install it by copying `skills/it-ai` into `~/.claude/skills/`.

## Build from source

```sh
cargo build --release            # produces target/release/{IT-AI,it-ai-mcp,itai}
```
Linux release binaries are cross-linked against glibc 2.31 via `cargo-zigbuild` (see
`.github/workflows/build.yml`) so one binary runs on Debian 12, Ubuntu 22.04+, and ARM SBCs.

## License

MIT. See `LICENSE`.
