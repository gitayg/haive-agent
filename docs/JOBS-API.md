# Background jobs — wire contract

A **job** is a long-running command on a device (a dev server, a build, `camrelay --preview`)
that outlives the ~65 s limit of a single `run_command`. You start it, read its output as it
grows, and stop it — each a separate, short call.

This file is the contract between the agent, the hub, the CLI and the MCP server. Change it
here first; every implementation follows it.

## Agent (`haive-agent`, `crates/agent`)

All four endpoints are **privileged** (listed in `privileged_path`), exactly like `/exec`: the
per-device token is required on every path, including loopback. `/jobs/start` refuses when
remote exec is disabled (`cfg.exec_enabled == false`) with the same 403 body `/exec` uses.

| Method | Path | Request | Response (JSON) |
|---|---|---|---|
| POST | `/jobs/start` | body `{"cmd": "<shell command>", "cwd": "<dir>"?}` | `{"ok":true,"id":"<job id>","pid":<u32>,"log":"<path>"}` |
| GET | `/jobs/logs?id=<id>&offset=<n>&max=<n>` | `offset` default 0; `max` default 65536, capped at 1048576 | `{"ok":true,"id","running":<bool>,"exit_code":<int\|null>,"offset":<next offset>,"size":<total bytes>,"eof":<bool>,"data":"<text>"}` |
| POST | `/jobs/stop?id=<id>` | — | `{"ok":true,"id","stopped":<bool>,"exit_code":<int\|null>}` |
| GET | `/jobs/list` | — | `{"ok":true,"jobs":[{"id","cmd","pid","started":<unix secs>,"running","exit_code"}]}` |

- **Job id:** `j` + unix milliseconds + 4 hex chars, e.g. `j1790420836094a3f1`. Only
  `[a-z0-9]` — ids are validated on every endpoint (reject anything else with 400).
- **Output:** stdout and stderr both append to one log file,
  `~/.it-ai/jobs/<id>.log` (`$HOME`; `%USERPROFILE%` on Windows). `data` is the bytes `[offset, offset+max)` decoded as
  UTF-8 lossily; `offset` in the response is where the next read should start (callers pass it
  back). `eof` = the job has exited AND the caller has read to the end.
- **Process tree:** the job runs in its own process group (unix: `setsid`/new process group;
  Windows: `CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW`, stdin null) so `stop` ends the job's
  children too — unix: SIGTERM to the group, SIGKILL after 5 s; Windows: `taskkill /T /F /PID`.
- **Lifetime:** jobs are tracked in memory; an agent restart forgets the registry (the log files
  stay on disk). The registry keeps the most recent 50 jobs; older finished jobs are dropped
  from `list` (their logs remain).
- Unknown id → `{"ok":false,"error":"unknown job"}` with 404.

## Hub (`HaiveControl`, `crates/hub`) — `/m/*` for MCP/CLI, `/x/*` for the dashboard

| Hub route | Forwards to | Checks, in order |
|---|---|---|
| `POST /m/job/start?target=<t>` · `POST /x/job/start?target=<t>` | `POST /jobs/start` | `may_control` → `policy::enforce("launch", cmd)` → `record_mcp_access` (via MCP) → `audit(actor, source, "start job", device, cmd)` → forward |
| `GET /m/job/logs?target=&id=&offset=&max=` · `/x/job/logs` | `GET /jobs/logs` | the normal `/m`/`/x` preamble (`may_control` on `target`) |
| `POST /m/job/stop?target=&id=` · `/x/job/stop` | `POST /jobs/stop` | preamble + `audit(…, "stop job", device, id)` |
| `GET /m/job/list?target=` · `/x/job/list` | `GET /jobs/list` | preamble |

- `/m/job/start` must be **exempt from the generic preamble** and do its own checks, exactly
  like `/m/exec` — the deny-list needs the command text, which only the body has. Starting a
  job must never be a way around the command deny-list or the audit log.
- `job/start` and `job/stop` are **write** actions: a read-only MCP token gets 403.
- The agent's JSON is passed back verbatim; hub-side refusals use the `/m/exec` shape
  `{"ok":false,"error":"…"}`.
- **Relay only** in this version: jobs do not use the LAN-direct path.
- **Dashboard:** each device gets a Jobs panel — list, start (command + optional cwd), a log
  view that polls `/x/job/logs` with the returned offset while the job runs, and Stop.

## CLI (`itai`) and MCP (`it-ai-mcp`)

- `itai job start <device> [--cwd DIR] -- <command…>` → prints the job id.
- `itai job logs <device> <id> [--offset N] [--follow]` → prints output; `--follow` polls every
  2 s from the returned offset until `eof`, then prints the exit code.
- `itai job stop <device> <id>` · `itai job list <device>`.
- MCP tools: `job_start(device, command, cwd?)`, `job_logs(device, id, offset?)` (returns the
  text plus the next offset, `running` and `exit_code`), `job_stop(device, id)`,
  `job_list(device)`.
