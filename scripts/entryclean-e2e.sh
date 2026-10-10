#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 Itay Glick
#
# End-to-end check, in Docker, that an agent removes the enrollment token from its own
# old autostart/service entries (crates/agent/src/entryclean.rs), and that each rewritten
# entry still finds the device secret. No real device and no real hub: the hub is a perl
# listener on loopback that answers 404 and records what the agent sends, and the
# container has no network. There is no systemd in the image, so `systemctl daemon-reload`
# fails and is logged; nothing is ever started from an entry except by this script.
#
# Usage: scripts/entryclean-e2e.sh        (IMG overrides the build image)
set -euo pipefail

if [ "${1:-}" != inside ]; then
  IMG=${IMG:-itai-vpn-build:bookworm}
  REPO=$(cd "$(dirname "$0")/.." && pwd)
  # Crates are fetched (crates.io only) before the test container, which has no network.
  docker run --rm -v "$REPO":/src:ro -v itai-vpn-cargo:/usr/local/cargo/registry -w /src "$IMG" cargo fetch -q --locked
  exec docker run --rm --network none -e CARGO_TARGET_DIR=/target \
    -v "$REPO":/src:ro -v itai-vpn-cargo:/usr/local/cargo/registry -v itai-vpn-target:/target -w /src \
    "$IMG" bash /src/scripts/entryclean-e2e.sh inside
fi

cargo build -q -p it-ai-agent --locked --offline
BIN=/target/debug/it-ai
HUB=http://127.0.0.1:18080
FAIL=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAIL=1; }

# The fake hub: one line per request body containing "relay_id" (the hello).
perl -MIO::Socket::INET -e '
  my $s = IO::Socket::INET->new(LocalAddr => "127.0.0.1:18080", Listen => 50, ReuseAddr => 1) or die $!;
  while (my $c = $s->accept) {
    my ($len, $line, $req) = (0, "", scalar <$c>);
    while (defined($line = <$c>) && $line ne "\r\n") { $len = $1 if $line =~ /^content-length:\s*(\d+)/i }
    my $body = ""; read($c, $body, $len) if $len;
    open(my $a, ">>", "/tmp/requests.log"); print $a $req; close $a;
    if ($req =~ m{^POST /relay/hello}) { open(my $f, ">>", "/tmp/hello.log"); print $f "$body\n"; close $f }
    print $c "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"; close $c;
  }' &

cred() { # cred <home> <device|enroll>
  mkdir -p "$1/.it-ai" && chmod 700 "$1/.it-ai"
  if [ "$2" = device ]; then echo "{\"hub\":\"$HUB\",\"device\":\"hdev_e2e\"}"; else echo "{\"hub\":\"$HUB\",\"enroll\":\"htok_e2e\"}"; fi > "$1/.it-ai/relay.cred"
  chmod 600 "$1/.it-ai/relay.cred"
}
desktop() { # desktop <home>
  mkdir -p "$1/.config/autostart"
  printf '[Desktop Entry]\nType=Application\nName=IT-AI\nExec=%s --relay %s --relay-token htok_old --name e2e\nX-GNOME-Autostart-enabled=true\n' "$BIN" "$HUB" > "$1/.config/autostart/it-ai.desktop"
}
unit() { # the pre-3.7.0 unit: token on ExecStart, no HOME
  mkdir -p /etc/systemd/system
  printf '[Unit]\nDescription=IT-AI agent\nAfter=network.target\n\n[Service]\nExecStart=%s --relay %s --relay-token htok_old --name e2e\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n' "$BIN" "$HUB" > /etc/systemd/system/it-ai.service
  chmod 644 /etc/systemd/system/it-ai.service
}
run_agent() { # run_agent <log> <cmd...>: start, give it SECS (4) seconds, stop
  local log=$1; shift
  : > /tmp/hello.log; : > /tmp/requests.log
  timeout -s TERM "${SECS:-4}" "$@" > "$log" 2>&1 || true
}
has_token() { grep -q -- '--relay-token' "$1"; }
reset() { rm -rf /h /n /.it-ai /.config /etc/systemd/system/it-ai.service /tmp/unit.target; }

echo "== 1. root, HOME=/h, no device secret yet: entries left alone, hub told autostart_token=true"
reset; cred /h enroll; desktop /h; unit
SECS=12 run_agent /tmp/1.log env HOME=/h "$BIN" --relay "$HUB" --name e2e
has_token /h/.config/autostart/it-ai.desktop && has_token /etc/systemd/system/it-ai.service && pass "entries untouched" || fail "entries changed"
grep -q 'left as is until this device holds its own secret' /tmp/1.log && pass "logged why" || fail "no log line"
grep -q '"autostart_token":true' /tmp/hello.log && pass "hello says autostart_token=true" || fail "hello: $(head -c 300 /tmp/hello.log)"

echo "--- requests the hub saw"; sort /tmp/requests.log | uniq -c | sed 's/tok=[^& ]*/tok=REDACTED/'
echo "== 2. root, HOME=/h, device secret: desktop stripped, unit stripped and HOME pinned to /h"
reset; cred /h device; desktop /h; unit
cp /etc/systemd/system/it-ai.service /tmp/unit.before
SECS=12 run_agent /tmp/2.log env HOME=/h "$BIN" --relay "$HUB" --name e2e
cat /tmp/2.log | grep autostart || true
! has_token /h/.config/autostart/it-ai.desktop && pass "desktop has no token" || fail "desktop still has it"
grep -qx "Exec=$BIN --relay $HUB --name e2e" /h/.config/autostart/it-ai.desktop && pass "desktop Exec keeps the other args" || fail "desktop: $(cat /h/.config/autostart/it-ai.desktop)"
! has_token /etc/systemd/system/it-ai.service && pass "unit has no token" || fail "unit still has it"
grep -qx 'Environment=HOME=/h' /etc/systemd/system/it-ai.service && pass "unit pins HOME=/h" || fail "unit: $(cat /etc/systemd/system/it-ai.service)"
[ "$(stat -c %a /etc/systemd/system/it-ai.service)" = 644 ] && pass "unit mode kept 644" || fail "unit mode $(stat -c %a /etc/systemd/system/it-ai.service)"
diff /tmp/unit.before /etc/systemd/system/it-ai.service || true
grep -q 'daemon-reload failed' /tmp/2.log && pass "daemon-reload attempted (no systemd here) and nothing else" || fail "no daemon-reload line"
grep -q '"autostart_token":false' /tmp/hello.log && pass "hello says autostart_token=false" || fail "hello: $(head -c 300 /tmp/hello.log)"
ls -a /etc/systemd/system /h/.config/autostart | grep -q it-ai-tmp && fail "temp file left" || pass "no temp file left"
s1=$(sha256sum /etc/systemd/system/it-ai.service /h/.config/autostart/it-ai.desktop)
run_agent /tmp/2b.log env HOME=/h "$BIN" --relay "$HUB" --name e2e
[ "$s1" = "$(sha256sum /etc/systemd/system/it-ai.service /h/.config/autostart/it-ai.desktop)" ] && ! grep -q autostart: /tmp/2b.log && pass "second start: no change, no log" || fail "not idempotent"

echo "== 3. the rewritten entries, started as their launcher would, find the device secret"
home=$(sed -n 's/^Environment=HOME=//p' /etc/systemd/system/it-ai.service)
exec_start=$(sed -n 's/^ExecStart=//p' /etc/systemd/system/it-ai.service)
(cd / && run_agent /tmp/3u.log env -i PATH=/usr/bin:/bin HOME="$home" $exec_start)
grep -q "using this device's own credential" /tmp/3u.log && pass "unit as systemd runs it (HOME=$home, cwd /)" || fail "unit: $(head -5 /tmp/3u.log)"
exec_line=$(sed -n 's/^Exec=//p' /h/.config/autostart/it-ai.desktop)
run_agent /tmp/3d.log env -i PATH=/usr/bin:/bin HOME=/h $exec_line
grep -q "using this device's own credential" /tmp/3d.log && pass "desktop entry in the user's session (HOME=/h)" || fail "desktop: $(head -5 /tmp/3d.log)"

echo "== 4. root service with no HOME (cwd /): /.it-ai/relay.cred; unit stripped WITHOUT a pin"
reset; cred / device; unit
(cd / && run_agent /tmp/4.log env -i PATH=/usr/bin:/bin "$BIN" --relay "$HUB" --name e2e)
! has_token /etc/systemd/system/it-ai.service && ! grep -q '^Environment=' /etc/systemd/system/it-ai.service && pass "unit stripped, no HOME added" || fail "unit: $(cat /etc/systemd/system/it-ai.service)"
grep -q 'it uses /.it-ai/relay.cred' /tmp/4.log && pass "logged the absolute cred path" || fail "log: $(grep autostart /tmp/4.log)"
exec_start=$(sed -n 's/^ExecStart=//p' /etc/systemd/system/it-ai.service)
(cd / && run_agent /tmp/4b.log env -i PATH=/usr/bin:/bin $exec_start)
grep -q "using this device's own credential" /tmp/4b.log && pass "the stripped unit, as systemd runs it, finds it" || fail "4b: $(head -5 /tmp/4b.log)"

echo "== 5. not root, HOME=/n: own desktop rewritten, root's unit (would look in /) left alone"
reset; mkdir -p /n; cred /n device; desktop /n; chown -R nobody /n; unit
cp /etc/systemd/system/it-ai.service /tmp/unit.before
(cd / && SECS=12 run_agent /tmp/5.log runuser -u nobody -- env HOME=/n "$BIN" --relay "$HUB" --name e2e)
! has_token /n/.config/autostart/it-ai.desktop && pass "nobody's desktop stripped" || fail "desktop still has it"
cmp -s /tmp/unit.before /etc/systemd/system/it-ai.service && pass "root's unit untouched" || fail "unit changed"
grep -q 'it-ai.service still carries the enrollment token — left as is:' /tmp/5.log && pass "logged the skip" || fail "log: $(grep autostart /tmp/5.log)"
grep -q '"autostart_token":true' /tmp/hello.log && pass "hello says autostart_token=true (the unit)" || fail "hello: $(head -c 300 /tmp/hello.log)"

echo "== 6. root agent, HOME=/h, but /h/.config/autostart belongs to nobody: never rewritten by root"
reset; cred /h device; desktop /h; chown nobody /h/.config/autostart /h/.config/autostart/it-ai.desktop
cp /h/.config/autostart/it-ai.desktop /tmp/desk.before
run_agent /tmp/6.log env HOME=/h "$BIN" --relay "$HUB" --name e2e
cmp -s /tmp/desk.before /h/.config/autostart/it-ai.desktop && pass "user-owned entry untouched" || fail "root rewrote a user-owned entry"
grep -q 'owned by uid' /tmp/6.log && pass "logged the refusal" || fail "log: $(grep autostart /tmp/6.log)"

echo "== 7. root agent: the unit is a symlink to another file: not followed, target untouched"
reset; cred /h device; unit; mv /etc/systemd/system/it-ai.service /tmp/unit.target; ln -s /tmp/unit.target /etc/systemd/system/it-ai.service
cp /tmp/unit.target /tmp/unit.target.before
run_agent /tmp/7.log env HOME=/h "$BIN" --relay "$HUB" --name e2e
cmp -s /tmp/unit.target.before /tmp/unit.target && [ -L /etc/systemd/system/it-ai.service ] && pass "symlink and its target untouched" || fail "symlink followed"
grep -q 'was not inspected — it is a symlink' /tmp/7.log && pass "logged the refusal" || fail "log: $(grep autostart /tmp/7.log)"
rm -f /etc/systemd/system/it-ai.service

echo "== 8. root agent whose secret is in /u, a directory nobody (a non-root user) owns: the root unit is NOT pinned there"
reset; rm -rf /u; mkdir -p /u; cred /u device; chown nobody /u; unit
cp /etc/systemd/system/it-ai.service /tmp/unit.before
run_agent /tmp/8.log env HOME=/u "$BIN" --relay "$HUB" --name e2e
cmp -s /tmp/unit.before /etc/systemd/system/it-ai.service && pass "unit untouched" || fail "unit pinned to a user-owned dir: $(cat /etc/systemd/system/it-ai.service)"
grep -q 'HOME=/u is not safe to pin' /tmp/8.log && pass "logged why" || fail "log: $(grep autostart /tmp/8.log)"
[ -f /u/.it-ai/relay.cred ] && [ ! -e /.it-ai/relay.cred ] && [ ! -e /root/.it-ai/relay.cred ] && pass "no credential moved or copied" || fail "credential moved/copied"
rm -rf /u

# A user laid out as Ubuntu lays out a desktop user: a user-private group with no members
# (useradd -U, as adduser does), umask 002, so ~/.config/autostart is 0775 and the entry 0664.
upg_user() { # upg_user <name>: home 750, .config 700, autostart 775, .desktop 664, cred 700/600
  id "$1" >/dev/null 2>&1 || useradd -m -U -s /bin/bash "$1"
  local h=/home/$1
  rm -rf "$h/.config" "$h/.it-ai"; cred "$h" device; desktop "$h"
  chown -R "$1:$1" "$h"; chmod 750 "$h"; chmod 700 "$h/.config"; chmod 775 "$h/.config/autostart"; chmod 664 "$h/.config/autostart/it-ai.desktop"
}

echo "== 9. Ubuntu user-private group: opswat:opswat, group has no members, autostart 775, entry 664: stripped"
reset; upg_user opswat
echo "   getent group opswat: $(getent group opswat)"; stat -c '   %a %U:%G %n' /home/opswat /home/opswat/.config /home/opswat/.config/autostart /home/opswat/.config/autostart/it-ai.desktop
SECS=12 run_agent /tmp/9.log runuser -u opswat -- env HOME=/home/opswat "$BIN" --relay "$HUB" --name e2e
! has_token /home/opswat/.config/autostart/it-ai.desktop && pass "UPG entry stripped" || fail "UPG entry still has it: $(grep autostart: /tmp/9.log)"
[ "$(stat -c '%a %U:%G' /home/opswat/.config/autostart/it-ai.desktop)" = "664 opswat:opswat" ] && pass "mode 664 and owner kept" || fail "now $(stat -c '%a %U:%G' /home/opswat/.config/autostart/it-ai.desktop)"
grep -q "removed the enrollment token from /home/opswat/.config/autostart/it-ai.desktop" /tmp/9.log && pass "logged the rewrite" || fail "log: $(grep autostart: /tmp/9.log)"
grep -q '"autostart_token":false' /tmp/hello.log && pass "hello says autostart_token=false" || fail "hello: $(head -c 300 /tmp/hello.log)"

echo "== 10a. shared group: autostart 775 and entry 664 in group team (members opswat, eve): left alone"
reset; upg_user opswat; id eve >/dev/null 2>&1 || useradd -m -U eve; getent group team >/dev/null || groupadd team
usermod -aG team opswat; usermod -aG team eve
chgrp team /home/opswat/.config/autostart /home/opswat/.config/autostart/it-ai.desktop
echo "   getent group team: $(getent group team)"
cp /home/opswat/.config/autostart/it-ai.desktop /tmp/desk.before
SECS=12 run_agent /tmp/10a.log runuser -u opswat -- env HOME=/home/opswat "$BIN" --relay "$HUB" --name e2e
cmp -s /tmp/desk.before /home/opswat/.config/autostart/it-ai.desktop && pass "shared-group entry untouched" || fail "rewritten in a shared group"
grep -q 'left as is: .*writable by group' /tmp/10a.log && pass "logged why" || fail "log: $(grep autostart: /tmp/10a.log)"
grep -q '"autostart_token":true' /tmp/hello.log && pass "hello says autostart_token=true" || fail "hello: $(head -c 300 /tmp/hello.log)"

echo "== 10b. the group is opswat's, but mallory has it as HER primary group: left alone"
reset; upg_user opswat; id mallory >/dev/null 2>&1 || useradd -m -g opswat mallory
echo "   getent group opswat: $(getent group opswat); getent passwd mallory: $(getent passwd mallory)"
cp /home/opswat/.config/autostart/it-ai.desktop /tmp/desk.before
SECS=12 run_agent /tmp/10b.log runuser -u opswat -- env HOME=/home/opswat "$BIN" --relay "$HUB" --name e2e
cmp -s /tmp/desk.before /home/opswat/.config/autostart/it-ai.desktop && pass "entry untouched" || fail "rewritten though another user shares the group"
grep -q 'left as is: .*writable by group' /tmp/10b.log && pass "logged why" || fail "log: $(grep autostart: /tmp/10b.log)"
userdel -r mallory >/dev/null 2>&1 || true

echo "== 10c. user-private group but the entry is world-writable (666): left alone"
reset; upg_user opswat; chmod 666 /home/opswat/.config/autostart/it-ai.desktop
cp /home/opswat/.config/autostart/it-ai.desktop /tmp/desk.before
SECS=12 run_agent /tmp/10c.log runuser -u opswat -- env HOME=/home/opswat "$BIN" --relay "$HUB" --name e2e
cmp -s /tmp/desk.before /home/opswat/.config/autostart/it-ai.desktop && pass "world-writable entry untouched" || fail "rewritten though world-writable"
grep -q 'left as is: it is world-writable' /tmp/10c.log && pass "logged why" || fail "log: $(grep autostart: /tmp/10c.log)"

echo "== 10d. user-private group, but passwd/group also come from SSSD (not enumerable): left alone"
reset; upg_user opswat; cp /etc/nsswitch.conf /tmp/nsswitch.before
sed -i -E 's/^(passwd|group):.*/\1: files sss/' /etc/nsswitch.conf; grep -E '^(passwd|group):' /etc/nsswitch.conf | sed 's/^/   /'
cp /home/opswat/.config/autostart/it-ai.desktop /tmp/desk.before
SECS=12 run_agent /tmp/10d.log runuser -u opswat -- env HOME=/home/opswat "$BIN" --relay "$HUB" --name e2e
cp /tmp/nsswitch.before /etc/nsswitch.conf
cmp -s /tmp/desk.before /home/opswat/.config/autostart/it-ai.desktop && pass "entry untouched with sss in nsswitch" || fail "rewritten though NSS has sss"
grep -q 'uses `sss`' /tmp/10d.log && pass "logged why" || fail "log: $(grep autostart: /tmp/10d.log)"

echo "== 10f. nsswitch.conf keeps 'passwd: files' but adds a second 'PASSWD: files ldap' line: left alone"
reset; upg_user opswat; cp /etc/nsswitch.conf /tmp/nsswitch.before; printf 'PASSWD: files ldap\n' >> /etc/nsswitch.conf
grep -iE '^(passwd|group) *:' /etc/nsswitch.conf | sed 's/^/   /'
cp /home/opswat/.config/autostart/it-ai.desktop /tmp/desk.before
SECS=12 run_agent /tmp/10f.log runuser -u opswat -- env HOME=/home/opswat "$BIN" --relay "$HUB" --name e2e
cp /tmp/nsswitch.before /etc/nsswitch.conf
cmp -s /tmp/desk.before /home/opswat/.config/autostart/it-ai.desktop && pass "entry untouched with a duplicate passwd line" || fail "rewritten though nsswitch.conf has two passwd lines"
grep -q 'has 2 passwd: lines' /tmp/10f.log && pass "logged why" || fail "log: $(grep autostart: /tmp/10f.log)"

echo "== 10e. rita's primary group has no members and no other user, but is named ritagrp, not rita: left alone"
reset; getent group ritagrp >/dev/null || groupadd ritagrp; id rita >/dev/null 2>&1 || useradd -m -g ritagrp rita
rm -rf /home/rita/.config /home/rita/.it-ai; cred /home/rita device; desktop /home/rita
chown -R rita:ritagrp /home/rita; chmod 775 /home/rita/.config/autostart; chmod 664 /home/rita/.config/autostart/it-ai.desktop
echo "   getent group ritagrp: $(getent group ritagrp); getent passwd rita: $(getent passwd rita)"
cp /home/rita/.config/autostart/it-ai.desktop /tmp/desk.before
SECS=12 run_agent /tmp/10e.log runuser -u rita -- env HOME=/home/rita "$BIN" --relay "$HUB" --name e2e
cmp -s /tmp/desk.before /home/rita/.config/autostart/it-ai.desktop && pass "entry untouched" || fail "rewritten though the group is not named for the user"
grep -q "its name \`ritagrp\` is not the user name \`rita\`" /tmp/10e.log && pass "logged why" || fail "log: $(grep autostart: /tmp/10e.log)"

echo "== 11. where a desktop-autostart agent logs: stdout to /dev/null or a pipe -> ~/.it-ai/agent.log"
LOG=/home/opswat/.it-ai/agent.log
count() { local n=0; [ -f "$LOG" ] && n=$(grep -c -- '— serving' "$LOG") || true; echo "$n"; }
reset; upg_user opswat
: > /tmp/hello.log; timeout -s TERM 20 runuser -u opswat -- env HOME=/home/opswat "$BIN" --relay "$HUB" --name e2e >/dev/null 2>&1 || true
grep -q -- '— serving' "$LOG" && grep -q 'removed the enrollment token' "$LOG" && pass "/dev/null: agent.log has the startup and autostart lines" || fail "/dev/null: agent.log: $(cat "$LOG" 2>&1 | head -5)"
[ "$(stat -c '%a %U' "$LOG")" = "600 opswat" ] && pass "agent.log is 600 opswat" || fail "agent.log $(stat -c '%a %U' "$LOG")"
n=$(count)
: > /tmp/pipe.out; (timeout -s TERM 20 runuser -u opswat -- env HOME=/home/opswat "$BIN" --relay "$HUB" --name e2e 2>&1 | cat > /tmp/pipe.out) || true
[ "$(count)" = $((n + 1)) ] && ! grep -q -- '— serving' /tmp/pipe.out && pass "pipe: appended to agent.log, nothing on the pipe" || fail "pipe: log $(count), pipe $(head -c 300 /tmp/pipe.out)"
n=$(count)
timeout -s TERM 20 runuser -u opswat -- env HOME=/home/opswat "$BIN" --relay "$HUB" --name e2e > /tmp/file.out 2>&1 || true
[ "$(count)" = "$n" ] && grep -q -- '— serving' /tmp/file.out && pass "stdout a regular file (launchd, --background, > file): left there, agent.log untouched" || fail "file: log $(count), file $(head -c 300 /tmp/file.out)"
echo "--- $LOG"; [ -f "$LOG" ] && sed 's/^/    /' "$LOG" || echo "    (none)"

echo "== 12. root agent, HOME=/h: agent.log (then .it-ai) is a symlink another user planted: never followed"
reset; mkdir -p /h/.it-ai; chmod 700 /h/.it-ai; cred /h device
head -c 1500000 /dev/zero | tr '\0' v > /etc/victim; s0=$(sha256sum < /etc/victim)
ln -s /etc/victim /h/.it-ai/agent.log
timeout -s TERM 10 env HOME=/h "$BIN" --relay "$HUB" --name e2e >/dev/null 2>/tmp/12.err || true
[ "$s0" = "$(sha256sum < /etc/victim)" ] && [ -L /h/.it-ai/agent.log ] && pass "agent.log symlink: target (1.5 MB) not appended to or truncated" || fail "victim now $(stat -c %s /etc/victim) bytes"
grep -q 'not trimming /h/.it-ai/agent.log' /tmp/12.err && grep -q 'not writing to /h/.it-ai/agent.log' /tmp/12.err && pass "logged the refusals" || fail "stderr: $(head -3 /tmp/12.err)"
rm -rf /h/.it-ai/agent.log /tmp/victimdir; mkdir -p /tmp/victimdir; chown nobody /tmp/victimdir
mv /h/.it-ai /h/real-it-ai; ln -s /tmp/victimdir /h/.it-ai
timeout -s TERM 10 env HOME=/h "$BIN" --relay "$HUB" --name e2e >/dev/null 2>/tmp/12b.err || true
[ ! -e /tmp/victimdir/agent.log ] && [ "$(stat -c '%a %U' /tmp/victimdir)" = "755 nobody" ] && pass ".it-ai symlink: no agent.log created in its target, its mode and owner unchanged" || fail "victimdir: $(ls -la /tmp/victimdir)"
# Not logfile's: the TLS cert is still written by path (tls::ensure_cert), so it lands in the target.
echo "   NOT COVERED (tls.rs, outside this fix): files the agent wrote through the .it-ai symlink: $(ls -A /tmp/victimdir | tr '\n' ' ')"
grep -q 'cannot be opened as a directory without following a link' /tmp/12b.err && pass "logged the refusal" || fail "stderr: $(head -3 /tmp/12b.err)"
rm -f /h/.it-ai; rm -rf /tmp/victimdir /etc/victim

for f in /tmp/1.log /tmp/2.log /tmp/4.log /tmp/5.log /tmp/6.log /tmp/7.log /tmp/8.log /tmp/9.log /tmp/10a.log /tmp/10b.log /tmp/10c.log /tmp/10d.log /tmp/10f.log /tmp/10e.log; do echo "--- autostart lines in $f"; grep autostart: "$f" || true; done
[ $FAIL = 0 ] && echo "ALL PASS" || { echo "SOME FAILED"; exit 1; }
