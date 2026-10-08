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
  `--relay-token`; the agent enrolls with it and gets its own secret on the first hello. Re-run
  `--persist` / `--install` (or `POST /persist`) to rewrite the entry without the token. Against a
  hub older than 3.16.0 the agent simply stays on the enrollment token.
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
