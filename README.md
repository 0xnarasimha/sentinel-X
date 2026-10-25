# Sentinel-X

Lightweight Linux daemon (Python 3.11 + Scapy + iproute2) that protects a host from **ARP-poisoning MITM** on untrusted networks (hostel Wi-Fi, small office, MSME LANs without managed switches).

1. **TOFU (Trust on First Use)** — probes the default gateway on first contact, detects multi-MAC conflicts, and pins the legitimate MAC (`nud permanent`) in the kernel neighbour table.
2. **Detect** — watches live ARP traffic; any frame claiming the gateway IP from an unauthorized MAC triggers an incident.
3. **Heal** — re-asserts the permanent kernel neighbour entry, verifies it by read-back, and sends a unicast corrective ARP reply to repair the router's cache of our host.
4. **Log** — appends every event into a **SHA-256 hash-chained, tamper-evident JSONL log** (`flock` + `fsync`).
5. **Dashboard** — read-only localhost web console (`127.0.0.1:8787`) showing plain-English protection status, incident feed, and live hash-chain verification.

---

## 🎬 Interactive Concept Simulator (Live)

Want to *see* the whole story before running the daemon? An interactive 3D web simulator walks through the exact concepts Sentinel-X implements — launched live in your browser, nothing to install:

**▶ [https://sentinel-x-interactive-explainer.vercel.app](https://sentinel-x-interactive-explainer.vercel.app)**

Chapters cover: the switched-LAN baseline → ARP-poisoning MITM (watch the victim's cache get poisoned live) → TOFU gateway pinning → Rule-R1 detection with automatic corrective-ARP heal → a hands-on SHA-256 hash-chain tamper lab (edit / delete / truncate and see the chain break).

> The simulator is a visual teaching aid for the **concept behind the project**; the daemon in this repo is the real implementation.

---

## 5-Line Quickstart (Isolated Namespace Lab)

```bash
pip install -e ".[dev]"
sudo make lab-up
sudo ip netns exec sx-victim sentinelx run --iface v-victim --state-dir /tmp/sx-demo &
sudo bash lab/attack.sh 4
sentinelx verify-log --path /tmp/sx-demo/log.jsonl && sudo make lab-down
```

---

## Architecture

```
 NIC ──► Sniffer (thread: Scapy AsyncSniffer, BPF "arp") ── ArpEvent ──► asyncio.Queue (bounded, drop+count)
                                                                              │
 NetWatcher (poll default route + network id, 2 s) ── NetState ──┐            ▼
                                                                  └────►  Engine  (PURE state machine)
                                                                              │  list[Action]
                                                                              ▼
                                                                  Executor (daemon.py)
                                                  ┌───────────────┬───────────┴──────────┬──────────────────┐
                                                  ▼               ▼                      ▼                  ▼
                                           NetBackend.pin   NetBackend.send_arp   ChainLog.append    status.json (1 Hz)
                                           (ip neigh)       (corrective ARP)      (log.jsonl)

 Read-only consumers of log.jsonl + status.json:  CLI (status, verify-log, trust)  ·  Dashboard (127.0.0.1:8787)
```

---

## Performance & Reliability (Targets + Measured)

The deck figures below are **engineering targets**, now shown against a first **native-Linux namespace-lab measurement** (Oct 25 2026; CachyOS, Python 3.14.8; one session of 10 real `arpspoof` cycles against a live daemon, benign ping traffic runs, CPU sampling `psutil`, and a 1-byte tamper check). The ≥95 %-over-50-runs campaign is still outstanding — targets are not yet production claims.

| Metric | Deck Target (Being Measured) | Measured (Oct 25 2026 namespace lab) | Evaluation Method |
|---|---|---|---|
| Detection + Verified Heal Latency | **< 500 ms** *(target)* | **min 1.75 ms · median 2.32 ms · max 2.62 ms** — first verified heal per incident, n=10/10 attacks, all under target (repeat heals inside the heal-cooldown suppression window are excluded by design) | First spoofed ARP timestamp `t0` to verified `heal` entry timestamp |
| Active MITM Mitigation Rate | **≥ 95 % over 50 runs** *(target)* | **10/10 cycles** — neighbour entry stayed `PERMANENT` with legitimate gateway MAC between and after every cycle (50-run campaign outstanding) | Neighbour entry stays `PERMANENT` with legitimate gateway MAC under `arpspoof -r` |
| False Positives (Simulated Packet Scenarios) | **0 FP over 50+ scenarios** *(target)* | **0 FP** — benign ICMP/ARP lab traffic raised zero `detect` events; simulated packet scenarios stay green (`tests/test_scenarios_fp.py`) | Simulated packet scenarios covering DHCP renew, RFC 5227 probes, GARP, VRRP/HSRP |
| Daemon CPU Overhead | **< 5 % of one core** *(target)* | **avg 0.60 % of one core under live `arpspoof`** (brief single-interval peak 5.00 %) | `psutil` sampling across idle, 50 pps benign ARP, and active `arpspoof` |
| Tamper-Evident Audit Log | **SHA-256 hash chain** | **verified 57 entries (`OK`); tampered copy rejected (`bad_idx=1 reason=bad_hash`, exit 1)** | Verified by `sentinelx verify-log` and `tests/test_chainlog.py` |

---

## Known Limits & Threat Model Summary (§13)

- **First-Contact Trust (TOFU):** TOFU is only as trustworthy as the initial connection window. Multi-probe conflict detection (`State.CONFLICT` when ≥ 2 distinct MACs answer) catches noisy spoofers at join time, but cannot defeat an attacker who suppresses the real router's replies before the host joins.
- **Host ↔ Gateway Scope Only:** Protects IPv4 traffic between this host and its default gateway. Peer-to-peer LAN traffic between two non-gateway hosts is out of scope.
- **IPv4 ARP Only:** IPv6 Neighbour Discovery Protocol (NDP / RA spoofing) is out of scope.
- **Root Compromise & Log Tail Truncation:** A root-level adversary on the protected host itself can stop the daemon or rewrite local files. The SHA-256 hash chain (`log.jsonl`) detects **mid-file edits, field modifications, deletions, and line reordering**, but **does not detect tail truncation or full chain regeneration by root** unless the chain head hash is anchored externally.
- **VRRP/HSRP Virtual MAC Trade-Off:** Virtual router MAC ranges (`00:00:5e:00:01:xx`, `00:00:0c:07:ac:xx`, `00:00:0c:9f:f0:xx`) are permitted **only** when the gateway was originally learned as a virtual MAC (`virtual_gateway=true`).
- **Legitimate Router Replacement:** Swapping the physical router triggers a mismatch alert while the permanent pin holds; the operator authorizes the new hardware via `sentinelx trust --add-mac <MAC>`.
- **Round 2 Namespace Safety Guard:** Network-change auto-unpinning (§6.5) is scheduled for Phase 2. In Round 2, `sentinelx run` refuses to start in the host network namespace unless `--allow-host` is explicitly passed.
- **Virtual Lab Benchmarks:** All end-to-end tests and benchmarks execute inside Linux network namespaces (`sx-gw`, `sx-victim`, `sx-att`) bridged over `sxbr0`.

---

## CLI Reference

```bash
sentinelx run --iface v-victim --state-dir /var/lib/sentinelx
sentinelx status --state-dir /var/lib/sentinelx
sentinelx verify-log --path /var/lib/sentinelx/log.jsonl
sentinelx trust --state-dir /var/lib/sentinelx --show
sentinelx trust --state-dir /var/lib/sentinelx --key "v-victim|wired|10.77.0.1" --add-mac 02:77:00:00:00:02
sentinelx sniff --iface v-victim --count 10
sentinelx dashboard --port 8787 --state-dir /var/lib/sentinelx
```
