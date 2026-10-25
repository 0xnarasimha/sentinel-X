# Sentinel-X — 4-Pane Live Demo Runbook

This runbook reproduces the ~2.5-minute Round 2 screening demonstration using the isolated Linux network namespace lab (`sx-gw`, `sx-victim`, `sx-att`). **Never run `arpspoof` on a real or campus network.**

---

## Pre-Flight Checklist

```bash
sudo make lab-down
rm -rf /tmp/sx-demo && mkdir -p /tmp/sx-demo
sudo make lab-up
```

Verify the three namespaces exist and victim can ping gateway:

```bash
ip netns list
sudo ip netns exec sx-victim ping -c 1 10.77.0.1
```

Open **4 terminal panes** (plus a browser at `http://127.0.0.1:8787`):

- **Pane 1 (Top-Left):** Victim (`sx-victim`)
- **Pane 2 (Top-Right):** Attacker (`sx-att` — `arpspoof`)
- **Pane 3 (Bottom-Left):** Attacker Packet Capture (`sx-att` — `tcpdump`)
- **Pane 4 (Bottom-Right):** Dashboard & Log Verification (`host`)

---

## Step 1 — Show the Problem *Without* Sentinel-X (30s)

**Pane 1 (Victim):** Start continuous ping to the gateway and check the neighbour table:
```bash
sudo ip netns exec sx-victim ping -i 0.5 10.77.0.1
```

**Pane 3 (Attacker `tcpdump`):** Watch ICMP packets arriving at the attacker interface:
```bash
sudo ip netns exec sx-att tcpdump -ni v-att icmp
```
*(Initially quiet — victim talks directly to `sx-gw`.)*

**Pane 2 (Attacker):** Launch bidirectional ARP poisoning inside `sx-att`:
```bash
sudo bash lab/attack.sh
```

**Pane 4 (Host inspection):** Show that `sx-victim`'s ARP cache is now poisoned with the attacker's MAC (`02:77:00:00:00:66`) and Pane 3 (`tcpdump`) is intercepting victim ICMP traffic:
```bash
sudo ip -n sx-victim neigh show 10.77.0.1
```

Stop the attack in **Pane 2** (`Ctrl+C`) and restore the clean lab:
```bash
sudo make lab-up
```

---

## Step 2 — Baseline *With* Sentinel-X Running (30s)

**Pane 4 (Dashboard):** Start the local read-only dashboard:
```bash
sentinelx dashboard --port 8787 --state-dir /tmp/sx-demo &
```
Open `http://127.0.0.1:8787` in the browser.

**Pane 1 (Victim):** Start the Sentinel-X daemon inside `sx-victim`:
```bash
sudo ip netns exec sx-victim sentinelx run --iface v-victim --state-dir /tmp/sx-demo
```

Verify baseline in **Pane 4**:
```bash
sentinelx status --state-dir /tmp/sx-demo
sudo ip -n sx-victim neigh show 10.77.0.1
```
- Neighbour entry shows `10.77.0.1 dev v-victim lladdr 02:77:00:00:00:01 PERMANENT`.
- Dashboard banner is **Green**: *"Protected — your router (10.77.0.1) is locked to 02:77:00:00:00:01"*.
- Integrity badge shows **"Verified, 3 entries"**.

---

## Step 3 — Live Attack Detection & Active Healing (45s)

**Pane 3 (Attacker `tcpdump`):** Start packet capture in `sx-att` while victim pings gateway:
```bash
sudo ip netns exec sx-victim ping -i 0.5 10.77.0.1 >/dev/null &
sudo ip netns exec sx-att tcpdump -ni v-att icmp
```

**Pane 2 (Attacker):** Launch `arpspoof` for 5 seconds:
```bash
sudo bash lab/attack.sh 5
```

Observe across panes:
1. **Dashboard:** Banner immediately turns **Red**: *"Under attack — a device (MAC 02:77:00:00:00:66) is pretending to be your router. Sentinel-X is blocking it."*
2. **Incident Feed:** Plain-English entries appear for `detect` and `heal` (*"Correct entry restored, router warned. Verified."*).
3. **Victim & Gateway Neighbour Tables:** Victim stays locked to `02:77:00:00:00:01 PERMANENT`, and corrective ARP keeps `sx-gw` pointing to `02:77:00:00:00:10`.
4. After `incident_idle_s` (10s) of silence, `incident_close` is logged and the banner returns to **Green (Protected)**.

---

## Step 4 — Tamper Detection on Hash-Chained Log (30s)

**Pane 4:** Verify the intact log chain:
```bash
sentinelx verify-log --path /tmp/sx-demo/log.jsonl
```
Output: `OK: verified N entries (head=...)` (exit code `0`).

Now tamper with a single character in `/tmp/sx-demo/log.jsonl`:
```bash
sed -i 's/02:77:00:00:00:66/02:77:00:00:00:99/' /tmp/sx-demo/log.jsonl
sentinelx verify-log --path /tmp/sx-demo/log.jsonl ; echo "Exit code: $?"
```
- CLI prints `TAMPERED: bad_idx=3 reason=bad_hash` and exits with code `1`.
- Dashboard badge flips to **Red**: `TAMPERED at entry #3`.

---

## Step 5 — Clean Shutdown & Teardown (15s)

Stop the daemon in **Pane 1** (`Ctrl+C` / `SIGTERM`):
- Daemon unpins `10.77.0.1` (`unpin_on_exit = true`) and logs `daemon_stop`.
- Tear down namespaces:
```bash
sudo make lab-down
```
