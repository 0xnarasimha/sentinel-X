#!/usr/bin/env bash
set -euo pipefail

# Lab setup for Sentinel-X (§7 of PLAN.md)
# Topology:
#   sxbr0 (bridge in root netns, no IP)
#   sx-gw     (v-gw:     10.77.0.1/24)
#   sx-victim (v-victim: 10.77.0.10/24, default route via 10.77.0.1)
#   sx-att    (v-att:    10.77.0.66/24)

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: lab/netns_up.sh must be run as root." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bash "$SCRIPT_DIR/netns_down.sh" >/dev/null 2>&1 || true

ip link add sxbr0 type bridge
ip link set sxbr0 up

# Disable bridge netfilter iptables hook if module is loaded so bridged ARP/ICMP is not filtered
sysctl -w net.bridge.bridge-nf-call-iptables=0 >/dev/null 2>&1 || true
sysctl -w net.bridge.bridge-nf-call-arptables=0 >/dev/null 2>&1 || true

for n in gw victim att; do
  ip netns add "sx-$n"
  ip link add "v-$n" type veth peer name "p-$n"
  ip link set "v-$n" netns "sx-$n"
  ip link set "p-$n" master sxbr0 up
  ip -n "sx-$n" link set lo up
  ip -n "sx-$n" link set "v-$n" up
done

# Deterministic MAC addresses for reproducible tests/debugging while still real kernel interfaces
ip -n sx-gw     link set dev v-gw     address 02:77:00:00:00:01
ip -n sx-victim link set dev v-victim address 02:77:00:00:00:10
ip -n sx-att    link set dev v-att    address 02:77:00:00:00:66

ip -n sx-gw     addr add 10.77.0.1/24  dev v-gw
ip -n sx-victim addr add 10.77.0.10/24 dev v-victim
ip -n sx-victim route add default via 10.77.0.1 dev v-victim
ip -n sx-att    addr add 10.77.0.66/24 dev v-att

# Prime initial ARP connectivity between victim and gateway
ip netns exec sx-victim ping -c 1 -W 1 10.77.0.1 >/dev/null 2>&1 || true

echo "Lab namespaces up: sx-gw (10.77.0.1), sx-victim (10.77.0.10), sx-att (10.77.0.66) on bridge sxbr0."
