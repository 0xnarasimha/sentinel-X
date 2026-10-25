#!/usr/bin/env bash
set -euo pipefail

# End-to-end verification in network namespaces (Round 2 Definition of Done #2)
# Flow: lab-up -> start daemon in sx-victim -> tofu_learned -> arpspoof in sx-att ->
#       detect -> heal (verified=true) -> verify-log OK -> SIGTERM unpins & writes daemon_stop

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
STATE_DIR="${SX_E2E_STATE_DIR:-/tmp/sentinelx-e2e-$$}"
DAEMON_PID=""

cleanup() {
  if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  bash "$SCRIPT_DIR/netns_down.sh" >/dev/null 2>&1 || true
  if [[ -z "${SX_KEEP_STATE:-}" ]]; then
    rm -rf "$STATE_DIR"
  fi
}
trap cleanup EXIT

rm -rf "$STATE_DIR"
mkdir -p "$STATE_DIR"

echo "[e2e] 1/6 Bringing up lab namespaces..."
bash "$SCRIPT_DIR/netns_up.sh"

echo "[e2e] 2/6 Starting sentinelx daemon in sx-victim (state_dir=$STATE_DIR)..."
ip netns exec sx-victim python3 -m sentinelx run \
  --iface v-victim \
  --state-dir "$STATE_DIR" &
DAEMON_PID=$!

# Wait up to 8s for tofu_learned
for _ in $(seq 1 40); do
  if [[ -f "$STATE_DIR/log.jsonl" ]] && grep -q '"type": *"tofu_learned"\|"type":"tofu_learned"' "$STATE_DIR/log.jsonl" 2>/dev/null; then
    break
  fi
  sleep 0.2
done

if ! grep -q '"tofu_learned"' "$STATE_DIR/log.jsonl" 2>/dev/null; then
  echo "FAIL: tofu_learned not logged within timeout" >&2
  cat "$STATE_DIR/log.jsonl" 2>/dev/null || true
  exit 1
fi
echo "[e2e]   -> TOFU learned and gateway pinned."

echo "[e2e] 3/6 Running stock arpspoof inside sx-att for 3s..."
bash "$SCRIPT_DIR/attack.sh" 3

# Wait briefly for detect + heal processing
for _ in $(seq 1 25); do
  if grep -q '"heal"' "$STATE_DIR/log.jsonl" 2>/dev/null; then
    break
  fi
  sleep 0.2
done

if ! grep -q '"detect"' "$STATE_DIR/log.jsonl"; then
  echo "FAIL: detect entry missing from log.jsonl" >&2
  cat "$STATE_DIR/log.jsonl"
  exit 1
fi

if ! grep -q '"heal"' "$STATE_DIR/log.jsonl"; then
  echo "FAIL: heal entry missing from log.jsonl" >&2
  cat "$STATE_DIR/log.jsonl"
  exit 1
fi

if ! python3 -c "
import json, sys
lines = [json.loads(line) for line in open('$STATE_DIR/log.jsonl') if line.strip()]
heals = [e for e in lines if e['type'] == 'heal']
assert heals and any(h['data'].get('verified') is True for h in heals), f'No verified heal in {heals}'
"; then
  echo "FAIL: heal entry did not have verified=true" >&2
  exit 1
fi

NEIGH_OUT="$(ip -n sx-victim neigh show 10.77.0.1 dev v-victim)"
if [[ "$NEIGH_OUT" != *"02:77:00:00:00:01"* ]] || [[ "$NEIGH_OUT" != *"PERMANENT"* ]]; then
  echo "FAIL: victim neighbour entry not PERMANENT with real gateway MAC: $NEIGH_OUT" >&2
  exit 1
fi
echo "[e2e]   -> Attack detected and healed (verified=true; neighbour entry: $NEIGH_OUT)."

echo "[e2e] 4/6 Sending SIGTERM to daemon (PID $DAEMON_PID)..."
kill -TERM "$DAEMON_PID"
wait "$DAEMON_PID" || true
DAEMON_PID=""

if ! grep -q '"daemon_stop"' "$STATE_DIR/log.jsonl"; then
  echo "FAIL: daemon_stop entry missing after SIGTERM" >&2
  cat "$STATE_DIR/log.jsonl"
  exit 1
fi

NEIGH_AFTER="$(ip -n sx-victim neigh show 10.77.0.1 dev v-victim || true)"
if [[ "$NEIGH_AFTER" == *"PERMANENT"* ]]; then
  echo "FAIL: gateway remained PERMANENT after SIGTERM unpin: $NEIGH_AFTER" >&2
  exit 1
fi
echo "[e2e]   -> SIGTERM handled: gateway unpinned and daemon_stop recorded."

echo "[e2e] 5/6 Verifying hash-chained log via 'sentinelx verify-log'..."
python3 -m sentinelx verify-log --path "$STATE_DIR/log.jsonl"

echo "[e2e] 6/6 Testing 1-byte tamper detection..."
TAMPER_LOG="$STATE_DIR/log.tampered.jsonl"
cp "$STATE_DIR/log.jsonl" "$TAMPER_LOG"
# Flip one character in the data payload of line 2 (idx 1)
python3 -c "
from pathlib import Path
p = Path('$TAMPER_LOG')
lines = p.read_text().splitlines()
lines[1] = lines[1].replace('daemon_start', 'daemon_starX', 1)
p.write_text('\n'.join(lines) + '\n')
"
if python3 -m sentinelx verify-log --path "$TAMPER_LOG" >/dev/null 2>&1; then
  echo "FAIL: verify-log succeeded on tampered log!" >&2
  exit 1
fi
echo "[e2e] PASS: All end-to-end checks succeeded."
