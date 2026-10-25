#!/usr/bin/env bash
set -euo pipefail

# Generate continuous ICMP traffic from sx-victim to sx-gw (10.77.0.1)
NS="sx-victim"
GW_IP="10.77.0.1"
COUNT="${1:-10}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: lab/traffic.sh must be run as root." >&2
  exit 1
fi

if ! ip netns list | awk '{print $1}' | grep -qx "$NS"; then
  echo "ERROR: Namespace '$NS' does not exist. Run 'make lab-up' first." >&2
  exit 1
fi

exec ip netns exec "$NS" ping -i 0.5 -c "$COUNT" "$GW_IP"
