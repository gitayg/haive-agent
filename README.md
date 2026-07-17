# haive-agent

Open-source endpoint client for **HaiveControl** — a self-hosted, LAN-first + reverse-tunnel
remote-administration hub. This repo holds the three pieces that run **on your machines** (the
hub itself is separate and private):

| Binary | Crate | What it is |
|---|---|---|
| `HaiveControl` (`airm`) | `crates/agent` | the endpoint agent — connects out to a hub over an HTTPS relay tunnel, serves screen/input/shell/camera/telemetry |
| `haive-mcp` | `crates/mcp` | an MCP server your coding agent (Claude Code, etc.) talks to, to drive the fleet |
| `haivectl` | `crates/cli` | a small command-line client for the hub |

Everything here is **AGPL-3.0** and built in public CI. Nothing phones home to a hardcoded host:
the hub URL and any token are runtime parameters (`--relay <url>`, `--relay-token <tok>` /
`HAIVE_HUB`, `HIVE_RELAY_TOKEN`) — there are no embedded endpoints or secrets.

## Why this is public

So you (and your tools) don't have to trust an opaque binary. A coding agent *should* refuse to
download and run an unknown executable — here the source is auditable, and every released binary
carries **signed build provenance** (see below) tying it to the exact commit + workflow that
produced it.

## Install

Downloads are anonymous from the GitHub Release. Pick the asset for your OS/arch:
`HaiveControl-linux` · `HaiveControl-linux-arm64` · `HaiveControl-macos` · `HaiveControl-windows.exe`
(same suffixes for `haive-mcp-*` and `haivectl-*`).

**macOS (Apple Silicon):**
```sh
curl -fsSL -o ~/.haive/haive-mcp https://github.com/gitayg/haive-agent/releases/latest/download/haive-mcp-macos && chmod +x ~/.haive/haive-mcp
```
**Linux x86-64 / arm64:** swap the asset name (`haive-mcp-linux` or `haive-mcp-linux-arm64`).

Register the MCP with Claude Code (fill in your own hub + token + owner):
```sh
claude mcp add-json haive '{
  "command": "'"$HOME"'/.haive/haive-mcp",
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
shasum -a 256 haive-mcp-macos    # compare against the matching line
```
**Provenance** — each binary has a Sigstore-signed attestation:
```sh
gh attestation verify haive-mcp-macos --repo gitayg/haive-agent
```

## Build from source

```sh
cargo build --release            # produces target/release/{HaiveControl,haive-mcp,haivectl}
```
Linux release binaries are cross-linked against glibc 2.31 via `cargo-zigbuild` (see
`.github/workflows/build.yml`) so one binary runs on Debian 12, Ubuntu 22.04+, and ARM SBCs.

## License

AGPL-3.0-or-later. See `LICENSE`.
