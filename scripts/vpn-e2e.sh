#!/usr/bin/env bash
# End-to-end check of the VPN exit (crates/agent/src/vpn.rs) in Docker, no real device:
#
#   client (stock kernel WireGuard) ──UDP──▶ exit :51821 ─loopback─▶ itai-wg ──NAT──▶ target
#
# The exit runs the ignored test `vpn::tests::e2e_exit_serves_a_stock_wireguard_client`, which
# drives the real apply/status/disable entry points. On the userspace backend it then kills
# boringtun's worker (the real 0.7.1 panic) and later holds it stuck, and the client checks its
# traffic after each recovery ("rounds", coordinated through files). The hub relay and the shim are NOT in the
# path: a loopback forwarder in the test stands in for the shim. The subnet is 198.18.0.0/24
# because the exit's own rules drop forwarded traffic to private ranges, Docker's included.
#
# Usage: scripts/vpn-e2e.sh [userspace|kernel]   (default userspace = HIVE_VPN_USERSPACE=1)
# Needs an image with the agent's Linux build deps and iproute2 but NOT iptables (the exit
# must install it); IMG overrides the default tag. Containers get NET_ADMIN and
# /dev/net/tun only, never --privileged. Everything it starts is removed on exit.
set -euo pipefail

BACKEND=${1:-userspace}
IMG=${IMG:-itai-vpn-build:bookworm}
REPO=$(cd "$(dirname "$0")/.." && pwd)
NET=itai-vpn-e2e
WORK=$(mktemp -d)
chmod 777 "$WORK"

cleanup() {
  docker rm -f itai-vpn-exit itai-vpn-client itai-vpn-target >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

case "$BACKEND" in
  userspace) EXIT_ENV=(-e HIVE_VPN_USERSPACE=1) PRE="" ;;
  kernel) EXIT_ENV=() PRE="apt-get update -qq && apt-get install -y -qq wireguard-tools >/dev/null && " ;;
  *) echo "usage: $0 [userspace|kernel]" >&2; exit 2 ;;
esac

docker network create --subnet 198.18.0.0/24 "$NET" >/dev/null
docker run -d --name itai-vpn-target --network "$NET" --ip 198.18.0.30 \
  python:3.12-alpine python3 -u -m http.server 8080 >/dev/null

docker run -d --name itai-vpn-exit --network "$NET" --ip 198.18.0.10 \
  --cap-add NET_ADMIN --device /dev/net/tun --sysctl net.ipv4.ip_forward=1 \
  "${EXIT_ENV[@]}" -e E2E_BACKEND="$BACKEND" -e E2E_DIR=/e2e -e HOME=/root -e CARGO_TARGET_DIR=/target \
  -v "$WORK":/e2e -v "$REPO":/src:ro -v itai-vpn-cargo:/usr/local/cargo/registry -v itai-vpn-target:/target -w /src \
  "$IMG" sh -c "${PRE}exec cargo test -q -p it-ai-agent --locked e2e_exit_serves -- --ignored --nocapture --test-threads=1" >/dev/null

docker run -d --name itai-vpn-client --network "$NET" --ip 198.18.0.20 --cap-add NET_ADMIN \
  -v "$WORK":/e2e debian:bookworm sh -c '
set -eu
apt-get update -qq >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends wireguard-tools iproute2 iputils-ping curl >/dev/null
cd /e2e && umask 077
wg genkey > client.key && wg genpsk > p.tmp && mv p.tmp client.psk && wg pubkey < client.key > k.tmp && mv k.tmp client.pub
for i in $(seq 300); do [ -s server.pub ] && break; sleep 1; done
ip link add wg0 type wireguard
wg set wg0 private-key ./client.key peer "$(cat server.pub)" preshared-key ./client.psk \
  endpoint 198.18.0.10:51821 allowed-ips 198.18.0.30/32,10.77.0.1/32 persistent-keepalive 5
ip address add 10.77.0.2/32 dev wg0 && ip link set wg0 mtu 1380 up
ip route add 198.18.0.30/32 dev wg0 && ip route add 10.77.0.1/32 dev wg0
echo "== client: route to the target";  ip route get 198.18.0.30
echo "== client: ping the target through the tunnel"; ping -c 3 -W 2 198.18.0.30
echo "== client: curl the target through the tunnel"
curl -sS -m 10 -o /dev/null -w "HTTP %{http_code} from %{remote_ip}:%{remote_port}\n" http://198.18.0.30:8080/
echo "== client: the exit itself must not answer pass holders"
if ping -c 2 -W 1 10.77.0.1 >/dev/null; then echo "UNEXPECTED: 10.77.0.1 answered"; exit 1; else echo "10.77.0.1 refused, as designed"; fi
echo "== client: wg show"; wg show wg0
echo ok > client.done
n=1
while :; do
  for i in $(seq 300); do [ -s "round$n" ] && break; sleep 1; done
  what=$(cat "round$n" 2>/dev/null || echo "no request")
  [ "$what" = end ] && break
  [ "$what" = "no request" ] && { echo "the exit never asked for round $n"; exit 1; }
  echo "== client: round $n: the exit rebuilt its WireGuard $what; same tunnel, nothing reconfigured here"
  for i in $(seq 60); do
    if ping -c 1 -W 1 198.18.0.30 >/dev/null; then echo "first reply after $i attempt(s) (WireGuard re-handshakes on its own)"; break; fi
    [ "$i" = 60 ] && { echo "no reply through the rebuilt exit"; exit 1; }
  done
  echo "== client: ping the target again"; ping -c 3 -W 2 198.18.0.30
  echo "== client: curl the target again"
  curl -sS -m 10 -o /dev/null -w "HTTP %{http_code} from %{remote_ip}:%{remote_port}\n" http://198.18.0.30:8080/
  echo "== client: wg show"; wg show wg0
  echo ok > "round$n.done"
  n=$((n + 1))
done
' >/dev/null

client_rc=$(docker wait itai-vpn-client)
exit_rc=$(docker wait itai-vpn-exit)
echo "######## exit ($BACKEND) — exit code $exit_rc"; docker logs itai-vpn-exit 2>&1 | grep -v '^\s*$'
echo "######## client — exit code $client_rc"; docker logs itai-vpn-client 2>&1
echo "######## target (http.server access log: the source address it saw)"; docker logs itai-vpn-target 2>&1
[ "$client_rc" = 0 ] && [ "$exit_rc" = 0 ]
