#!/usr/bin/env bash
set -uo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: lab/netns_down.sh must be run as root." >&2
  exit 1
fi

for n in gw victim att; do
  if ip netns list | grep -q "^sx-$n\b"; then
    ip netns pids "sx-$n" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    ip netns del "sx-$n" 2>/dev/null || true
  fi
  ip link del "p-$n" 2>/dev/null || true
done

if ip link show sxbr0 >/dev/null 2>&1; then
  ip link set sxbr0 down 2>/dev/null || true
  ip link del sxbr0 type bridge 2>/dev/null || true
fi

echo "Lab namespaces and sxbr0 cleaned up."
