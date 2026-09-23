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
the hub URL and any token are runtime parameters (`--relay <url>`, `--relay-token <tok>` /
`HAIVE_HUB`, `HIVE_RELAY_TOKEN`) — there are no embedded endpoints or secrets.

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

## Build from source

```sh
cargo build --release            # produces target/release/{IT-AI,it-ai-mcp,itai}
```
Linux release binaries are cross-linked against glibc 2.31 via `cargo-zigbuild` (see
`.github/workflows/build.yml`) so one binary runs on Debian 12, Ubuntu 22.04+, and ARM SBCs.

## License

MIT. See `LICENSE`.
