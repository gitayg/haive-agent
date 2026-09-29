---
name: it-ai
description: Operate an IT-AI fleet (self-hosted IT management hub + endpoint agents) through the it-ai-mcp MCP tools or the itai CLI. Use when asked to run commands on, inspect, update, move files to or from, or control devices enrolled in an IT-AI / HaiveControl hub, or to set up itai on a dev box. Covers picking the right tool, long-running jobs, large-file transfer, agent updates, and working within the hub's deny-list and audit log.
---

# Operating IT-AI

IT-AI is a hub plus an agent on each device. You drive devices **by hub name** through the
hub's `/m` API, either with the `it-ai-mcp` MCP server (tools below) or the `itai` CLI. Both
use the same transport: LAN-direct when the device answers on its LAN address, the hub relay
otherwise. Either way the hub authorizes, deny-list-checks and audits the call first.

## Non-negotiables

1. **Never echo a token.** `HIVE_MCP_TOKEN` is sent as `?mtok=` in the request URL, and
   transport errors quote that URL verbatim (`error sending request for url
   (https://hub/m/agents?mtok=…)`). If an error contains `mtok=`, redact the value before
   repeating it. Never put a token in a command line (`--mtok` is visible in `ps`), a command
   you run on a device, a file, or a message. Read it from the environment only.
2. **A refusal is policy, not a bug.** The hub refuses before the device is contacted:
   - `command blocked by hub policy (matched '<pattern>')` / `action '<kind>' is blocked by hub policy` - deny-list
   - `this MCP token is read-only` (403) - the token cannot do write actions
   - `forbidden` - this owner may not control that device
   - `remote exec disabled` (403) - the agent runs with exec turned off

   Report the refusal and the matched rule to the user and stop. Do **not** reword, split,
   alias, base64-encode, wrap in a script, move to `run_script`/`run_plugin`/`fleet_run`/
   `job_start`/`detach`, or type it into a terminal with `type_text` to get past it.
3. **Everything is audited.** The hub records actor, source (`mcp` or `browser`), action,
   device and the full command text. Assume an admin reads it: no secrets in command text,
   and say what you're about to do before you do it.
4. **Confirm before destructive or fleet-wide actions**: `device_action` (reboot, shutdown,
   sleep, logoff, firewall_off, usb_lock), `dissolve_agent`, `uninstall_package`, and every
   `fleet_*` / `run_script_fleet` call, which hits every device the owner has.

## Pick the tool

| Need | Tool |
|---|---|
| What devices exist, OS, user, load, last-seen | `list_devices` |
| Short command, output back (< ~65 s) | `run_command(device, command)` |
| Long-running: dev server, build, tail (**new**) | `job_start` → `job_logs` → `job_stop` (`job_list`) |
| Fire-and-forget GUI app launch | `run_command(..., detach: true)` (returns a pid only, no output) |
| File from device → local | `download_file(device, remote_path, save_as?)` (default `~/Downloads/<name>`) |
| Small file (≤ 100 MB) local → device | `upload_file(device, local_path, remote_dir?)` |
| Large file local → device | `push_file(device, local_path, remote_dir?)` |
| See / drive the screen | `screenshot`, `click(x, y, button?)`, `type_text`, `press_key` |
| Webcam photo | `camera_snapshot(device, index?)` |
| Inventory / state | `system_report(device, kind)` kind: hardware, av, encryption, firewall, processes, services, network, packages |
| Security score | `compliance_posture(device)`; all devices: `fleet_compliance` |
| Pending OS/app updates | `check_updates(device)` |
| Software | `install_package` / `uninstall_package(device, package)` (winget / brew / apt id) |
| Power / firewall / USB | `device_action(device, action)` |
| Tell the logged-in user something | `message_user(device, text)` |
| Maintained diagnostic script | `search_scripts(query)` → `run_script(device, script)` |
| Hub-defined custom action | `list_plugins` → `run_plugin(device, plugin, arg?)` |
| Same thing on every device | `fleet_run(command)`, `fleet_report(kind)`, `run_script_fleet(script)` |
| Known CVEs for a product | `cve_lookup(query)` (an NVD lookup, not a scan) |
| Agent lifecycle | `update_agent(device)`, `dissolve_agent(device)` |

Device names resolve exact first, then by substring; an ambiguous substring errors, so use
the full name from `list_devices`. An empty `list_devices` usually means `HIVE_OWNER` doesn't
match the email the device enrolled under; the tool says so.

## Commands: short vs long-running

- `run_command` has a ~65 s limit. Use it for things that finish: `uname -a`, `df -h`,
  `systemctl status x`, `Get-Service`. `run_script` has the same cap.
- Anything that outlives that (dev servers, builds, `npm install`, log follows) is a **job**
  (**new**, see `docs/JOBS-API.md`; check your tool list, older MCP builds lack it):
  1. `job_start(device, command, cwd?)` returns a job id (`j…`).
  2. `job_logs(device, id, offset?)` returns output from `offset`, plus the next `offset`,
     `running`, `exit_code` and `eof`. Pass the returned offset back and poll until `eof`.
     Don't re-read from 0.
  3. `job_stop(device, id)` ends the job **and its children** (process group / `taskkill /T`).
  4. `job_list(device)` shows recent jobs (the last 50; an agent restart forgets the list,
     but log files stay on disk).

  `job_start` goes through the same deny-list (as a `launch`) and audit as `run_command`,
  and is a write action (a read-only token gets 403). Jobs are relay-only for now.
- **Without job tools:** `run_command(detach: true)` with output redirected to a file, then
  short `run_command` reads of that file. Never block `run_command` on a long task hoping
  it finishes.
- **Windows quoting:** the typed-input path can drop `$`, `%` and quotes. For PowerShell
  with variables or quotes, send `powershell -NoProfile -EncodedCommand <base64 UTF-16LE>`.
  This fixes quoting. It is not a way around the deny-list (rule 2).

## Files

- `upload_file` is capped at **100 MB**. The hub buffers the whole body in RAM and the relay
  sends it as one message, so a larger file is rejected before sending, with a pointer
  to `push_file`. Don't retry a big upload that failed; switch to `push_file`.
- `push_file` is **stage-and-pull**: the hub stages the bytes (owner-scoped, sha256-hashed,
  1 h TTL) and the device pulls them with an integrity check. The tool polls up to 10 min.
  Use it for anything large (installers, datasets). It reads the local file into memory
  on the MCP host first.
- Never move files as base64 through `run_command`/`type_text`. It wedges the tunnel.
- `download_file` writes on the machine running the MCP server, not the device.

## Agent updates

`update_agent(device)` asks the hub to push its hosted build to the device. The agent replies
in plain text, passed through verbatim:

- `already running this build (N bytes); nothing to do`: success, no-op. The pushed binary is
  byte-identical to the running one, so nothing was installed and nothing restarted. Don't
  retry or "force" it.
- `updated (N bytes); restarting`: installed, and the agent restarts. Confirm it's back
  with `list_devices`.
- `update signature missing` / `update signature invalid`: refused. Every installed binary
  must carry an ed25519 signature matching the key pinned in the agent. **Never** work around
  this by pushing a binary with `push_file` and replacing the agent via `run_command`. Report it.
- `update url must be https`, `download failed`: hub-side problem. Report it.

Enrolled agents also self-update: every 2 min they fetch the hub's `/bin/SHA256SUMS`, compare
the published hash with their own executable, and only download and verify a signed binary
when it differs. That checksum file isn't signed. A lying hub can delay an update but
can't install one. So a device on an old version is usually waiting for its next check, not
broken.

`dissolve_agent` stops the agent and removes its autostart (the binary stays). The device then
leaves the fleet until someone re-runs the agent on it. Confirm first.

## CLI: `itai`

```
itai list                                  # devices: name + target
itai exec <device> <command…>              # ~65 s timeout; exits with the remote exit code
itai get  <device> <remote> [local]        # download
itai put  <device> <local> [remote_dir]    # upload (direct path; same size caveat)
itai job start <device> [--cwd DIR] -- <command…>   # new
itai job logs  <device> <id> [--offset N] [--follow] # new; --follow polls every 2 s to eof
itai job stop  <device> <id>  ·  itai job list <device>   # new
```

Global flags and their env equivalents: `--hub`/`HAIVE_HUB`, `--mtok`/`HIVE_MCP_TOKEN`,
`--owner`/`HIVE_OWNER`, `--password`/`SCREEN_PW`, `--cafile`/`HAIVE_CAFILE`. **Always use the
env vars for secrets**, never `--mtok`/`--password`. TLS is verified by default.
`HAIVE_INSECURE_TLS=1` disables it (self-signed LAN only; it prints a warning). Don't set it
against a public hub.

Install on a dev box: `scripts/setup-itai.sh` picks the right release asset, verifies it
against the release `SHA256SUMS`, installs to `~/.local/bin`, and runs `itai list` with the
token redacted. Needs `HAIVE_HUB` + `HIVE_MCP_TOKEN` already exported. Pin with `ITAI_VERSION`.

## MCP setup (reference)

`it-ai-mcp` reads `HAIVE_HUB`, `HIVE_MCP_TOKEN`, `HIVE_OWNER`, and optionally `HAIVE_CAFILE`
/ `HAIVE_INSECURE_TLS` from its environment (set them in the `claude mcp add-json` env
block, see README). Released assets are `it-ai-mcp-{linux,linux-arm64,macos,windows.exe}`.
The macOS build is Apple Silicon. Verify with the release `SHA256SUMS` and
`gh attestation verify <file> --repo gitayg/haive-agent`.
