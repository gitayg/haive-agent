#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 Itay Glick
#
# One-command setup of the `itai` CLI on a dev box:
#   1. detect OS/arch and pick the matching release asset
#   2. download it plus the release's SHA256SUMS
#   3. verify the checksum (a mismatch or a missing entry is fatal)
#   4. install to $INSTALL_DIR (default ~/.local/bin)
#   5. run a read-only connectivity check (`itai list`)
#
# Configuration comes from the environment only:
#   HAIVE_HUB       hub URL (required)
#   HIVE_MCP_TOKEN  token for the hub's /m API (required; read from env, never prompted,
#                   printed, written to disk or passed on a command line)
#   HIVE_OWNER      owner id, when the hub serves several users (optional)
#   ITAI_VERSION    release tag to install, e.g. v3.5.2 (default: latest)
#   INSTALL_DIR     install directory (default: $HOME/.local/bin)
#   ITAI_BASE_URL   releases base URL (default: https://github.com/gitayg/haive-agent/releases)
#
# Usage:  HAIVE_HUB=https://hub.example.com HIVE_MCP_TOKEN=... sh setup-itai.sh
set -eu

BASE_URL=${ITAI_BASE_URL:-https://github.com/gitayg/haive-agent/releases}
INSTALL_DIR=${INSTALL_DIR:-$HOME/.local/bin}

die() {
    printf 'setup-itai: error: %s\n' "$*" >&2
    exit 1
}
say() { printf 'setup-itai: %s\n' "$*"; }

# ---- 0. environment (fail before downloading anything) -------------------------------
[ -n "${HAIVE_HUB:-}" ] || die "HAIVE_HUB is not set. Export your hub URL first, e.g.
    export HAIVE_HUB=https://your-hub.example.com"
[ -n "${HIVE_MCP_TOKEN:-}" ] || die "HIVE_MCP_TOKEN is not set. Export the hub's MCP token in
    your environment (e.g. from your secret manager). This script never prompts for it."
case "$HAIVE_HUB" in
    https://*) ;;
    http://localhost* | http://127.0.0.1*) ;;
    *) say "warning: HAIVE_HUB is not https:// — the token travels in the request URL" >&2 ;;
esac

# ---- 1. OS / arch -> release asset (names from .github/workflows/build.yml) ----------
os=$(uname -s)
arch=$(uname -m)
case "$os" in
    Linux)
        case "$arch" in
            x86_64 | amd64) asset=itai-linux ;;
            aarch64 | arm64) asset=itai-linux-arm64 ;;
            *) die "no itai build for Linux/$arch (released: x86_64, aarch64)" ;;
        esac
        ;;
    Darwin)
        # The release's macOS build is Apple Silicon only. A shell under Rosetta
        # reports x86_64 on an arm64 Mac, so ask the hardware.
        if [ "$arch" = arm64 ] || [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = 1 ]; then
            asset=itai-macos
        else
            die "no itai build for Intel macOS (the release ships Apple Silicon only)"
        fi
        ;;
    *) die "unsupported OS '$os' — on Windows download itai-windows.exe from $BASE_URL" ;;
esac

if [ -n "${ITAI_VERSION:-}" ]; then
    case "$ITAI_VERSION" in v*) tag=$ITAI_VERSION ;; *) tag=v$ITAI_VERSION ;; esac
    dl="$BASE_URL/download/$tag"
else
    tag=latest
    dl="$BASE_URL/latest/download"
fi

# ---- tools ---------------------------------------------------------------------------
if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -q -O "$2" "$1"; }
else
    die "need curl or wget"
fi
if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
    die "need sha256sum or shasum"
fi

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t setup-itai)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 130' INT TERM

# ---- 2. download ---------------------------------------------------------------------
say "installing $asset ($tag) from $dl"
fetch "$dl/SHA256SUMS" "$tmp/SHA256SUMS" || die "could not download $dl/SHA256SUMS"
fetch "$dl/$asset" "$tmp/$asset" || die "could not download $dl/$asset"

# ---- 3. verify -----------------------------------------------------------------------
expected=$(awk -v a="$asset" '$2 == a || $2 == "*" a { print $1 }' "$tmp/SHA256SUMS")
case "$expected" in
    "") die "SHA256SUMS has no entry for $asset — refusing to install" ;;
    *[!0-9a-fA-F]* | *"
"*) die "SHA256SUMS entry for $asset is malformed or duplicated — refusing to install" ;;
esac
[ ${#expected} -eq 64 ] || die "SHA256SUMS entry for $asset is not a sha256 — refusing to install"
expected=$(printf '%s' "$expected" | tr 'A-F' 'a-f')
actual=$(sha256 "$tmp/$asset")
if [ "$actual" != "$expected" ]; then
    die "checksum MISMATCH for $asset — refusing to install
    expected $expected
    actual   $actual"
fi
say "sha256 OK  $actual"

# ---- 4. install ----------------------------------------------------------------------
mkdir -p "$INSTALL_DIR"
chmod 755 "$tmp/$asset"
mv -f "$tmp/$asset" "$INSTALL_DIR/.itai.new.$$"
mv -f "$INSTALL_DIR/.itai.new.$$" "$INSTALL_DIR/itai"
bin="$INSTALL_DIR/itai"
say "installed $bin ($("$bin" --version 2>&1 || echo 'version unknown'))"
case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) say "note: $INSTALL_DIR is not on PATH — add: export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac

# ---- 5. connectivity check (read-only) -----------------------------------------------
# itai reads HAIVE_HUB / HIVE_MCP_TOKEN / HIVE_OWNER from the environment itself, so the
# token is never on a command line. Its error messages can quote the request URL, which
# carries the token as ?mtok=… — redact that before printing anything.
say "checking hub connectivity (itai list) ..."
set +e
out=$("$bin" list 2>&1)
rc=$?
set -e
out=$(printf '%s\n' "$out" | sed -E 's/mtok=[^&)[:space:]]*/mtok=REDACTED/g')
if [ "$rc" -ne 0 ]; then
    printf '%s\n' "$out" >&2
    die "connectivity check failed (exit $rc) — check HAIVE_HUB, HIVE_MCP_TOKEN and network"
fi
if [ -z "$out" ]; then
    say "connected; no devices visible (if you expected some, check HIVE_OWNER)"
else
    printf '%s\n' "$out"
    say "connected; $(printf '%s\n' "$out" | wc -l | tr -d ' ') device(s) visible"
fi
