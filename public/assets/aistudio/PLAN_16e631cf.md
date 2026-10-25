# Sentinel-X — Build Plan

> Source of truth for humans **and coding agents**. Read all of it before touching code.
> Event: YUKTHI 2026 (Mohan Babu University) · Team Aparajitha (5) · Theme: Blockchain & Cybersecurity
> **Round 2 is due Sun 25 Oct 2026, 11:59 PM IST** (prototype + GitHub repo link + screening recording, submitted on Unstop) — see §0.1. Offline finale (shortlisted teams only): **30–31 Oct 2026**. Plan written Sat 24 Oct 2026.
> Deliverables: public repo + working prototype + screening recording (Round 2), then live demo (finale). Copy this file to `AGENTS.md` and `CLAUDE.md` in the repo root so agents auto-load it.

---

## 0. What we are building (one screen)

Sentinel-X is a lightweight **Linux daemon (Python + Scapy)** that protects one host from **ARP-poisoning MITM** on a network the user does not control (hostel Wi-Fi, small office, MSME without managed switches).

1. **TOFU** — on first contact, learn the gateway's MAC and pin it in the kernel neighbour table.
2. **Detect** — watch ARP traffic; any packet claiming "gateway IP is at a *different* MAC" is an incident.
3. **Heal** — re-assert the pin and send a corrective ARP to the router (fixes the router's poisoned cache of us).
4. **Log** — every incident goes into a **hash-chained, tamper-evident log**.
5. **Report** — local template-based incident report. Optional LLM summary: opt-in, anonymized.

Deck targets (these are **targets, not facts** until `bench/` measures them): detect+heal < 500 ms · ≥ 95 % mitigation over 50 attack runs · 0 false positives over 50+ DHCP/VRRP scenarios · < 5 % CPU.

### Scope
| In | Out (do not build) |
|---|---|
| Linux, IPv4 ARP, **gateway protection only**, one interface, run as root | Windows/Android, IPv6 NDP, protecting LAN peers other than the gateway, DNS-level defence, switch features (DAI) |

---

## 0.1 Round 2 — due **Sun 25 Oct 2026, 11:59 PM IST** (Unstop)

Round 1 (PPT) is passed. Round 2 = "basic prototype": submit **prototype + GitHub repo link + screening recording**. Unstop says the submission links and instructions arrive **by email — find that email tonight** and check what exactly it asks for. The finale is only for shortlisted teams, so Round 2 decides whether the rest of this plan matters.

**Submit by Sun 18:00, not 23:55.** Submission pages and links break near deadlines. Anything not working by **Sun 16:00 is cut** from the video and the README, not faked.

What the Round 2 slice must show (nothing else counts for this round):

| Must have for R2 | WP |
|---|---|
| Public repo; README with 5-line quickstart, architecture diagram, known limits (§13) | WP9-lite |
| Lab: `make lab-up / attack / lab-down` | WP0 |
| Learn gateway MAC (TOFU) + detect gateway-MAC mismatch | WP1 + WP2 |
| Heal: pin + corrective ARP, verified by read-back | WP3 |
| Hash-chained log + `verify-log` + tamper demo | WP4 |
| `sentinelx run` + `status` | WP5 |
| **Dashboard** (live status, incident feed, chain-integrity badge) | **WP8, promoted to P0** |
| Screening recording: 2–3 min screen capture of the §12 script | — |

**Deferred until after submission:** WP7 (reports + LLM), WP9 bench numbers, `pin_mode=on_detect`, network-change handling (§6.5), vMAC rules, and the full ≥ 50 / ≥ 15 scenario suites. Where a WP's acceptance lists large test counts, **R2 needs only the smoke subset (≥ 5 tests per WP)**; full counts are for the finale.

**R2 rules:**
- Run the daemon **only inside the lab namespaces** until §6.5 (network change) is built. A stale pin on your real Wi-Fi can cut your internet.
- The README and video must not quote the deck's numbers (<500 ms, ≥ 95 %, 0 FP, < 5 % CPU) as results. Call them "targets, being measured".
- No mock data in the real path: the dashboard shows only what is in `status.json` / `log.jsonl`. If the daemon isn't wired by Sun 13:00, show the pieces separately in the video (attack on/off, detect + heal, tamper + verify) instead of faking one flow.

---

## 1. Rules for coding agents (read first)

1. Work **only on the work package (WP) you were assigned** (§9). Touch only the files that WP owns.
2. **Contracts in §5 are frozen.** Additive changes only; if you change one, edit §5 in the same commit and say so in the commit message.
3. Need something from another WP? Code against its interface in §5 using a fake. Do not edit their files.
4. `engine.py` and the rule parts of `trust.py` are **pure**: no `subprocess`, no sockets, no `time.time()` (time is passed in as `now`), no file I/O except through the injected `TrustStore`.
5. Every system-modifying call (`ip neigh`, sending packets) goes through `NetBackend`. `DryRunBackend` and `FakeBackend` must exist so tests need **no root** (except tests marked `integration`).
6. Before every commit: `ruff check . && pytest -m "not integration"`. Integration tests: `sudo -E pytest -m integration`.
7. **Attack tooling policy:** the repo contains no attack code. Lab scripts only call the stock `arpspoof` (dsniff) and **refuse to run unless the target interface lives in a namespace named `sx-*`**. Never run anything against the campus or any real network.
8. No secrets in the repo. LLM keys come from environment variables only.
9. **No invented numbers.** Any metric in README/slides must come from a file in `bench/results/`.
10. One branch per WP (`wp3-healer`), small commits, PR into `main`. Final report of each WP: what you built, how you verified it, what in this plan was wrong or ambiguous.

**Kickoff prompt template (paste to an agent):**
```
Read PLAN.md fully. You are implementing WP<N> only. Touch only the files listed for WP<N>.
Contracts in section 5 are frozen. Write tests alongside the code and run `pytest -m "not integration"`.
Finish with: what you built, how you verified it, and anything in PLAN.md that was wrong or unclear.
```

---

## 2. ARP in 60 seconds (domain context for agents)

- ARP maps IPv4 → MAC on the local segment. Hosts accept **unsolicited** replies and overwrite their cache. No authentication.
- **MITM (what `arpspoof -r` does):** every ~2 s it tells the victim "gateway IP is at attacker MAC" and tells the gateway "victim IP is at attacker MAC". All traffic flows through the attacker. (Attacker needs `ip_forward=1` to stay invisible; without it the victim just loses connectivity.)
- **Outbound protection (victim → gateway):** a `PERMANENT` neighbour entry. The kernel refuses to overwrite it from received ARP packets.
- **Inbound protection (gateway → victim):** the *router's* cache is what is poisoned. That poison is a unicast to the router, so **we cannot see it**. Design consequence: whenever victim-side poisoning is detected, assume the attack is bidirectional and send a corrective ARP to the router.
- **Why TOFU is weak:** if the attacker is already active when we first join a network, we learn the attacker's MAC. Mitigation: probe several times and refuse to pin if more than one MAC answers (§6.1). Residual risk goes in the README/threat model, not hidden.

---

## 3. Architecture

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

 Read-only consumers of log.jsonl + status.json:  CLI (status, verify-log, report)  ·  Dashboard  ·  Reporter/LLM
```

Key decisions:
- **Engine is a pure state machine** → unit-testable with synthetic packets, no root, no network.
- **Log is the source of truth.** Dashboard and reports read the chain, re-verify it, and show the result.
- **Executor** is the only place with side effects; it verifies after healing (reads the neighbour entry back) and records the result.

---

## 4. Repo layout

```
sentinel-x/
├── PLAN.md  (= AGENTS.md = CLAUDE.md)      README.md      pyproject.toml     Makefile     config.example.toml
├── sentinelx/
│   ├── __main__.py  cli.py  config.py
│   ├── models.py        # §5 contracts (FROZEN)
│   ├── sniffer.py       # WP1
│   ├── engine.py        # WP2 (pure)
│   ├── trust.py         # WP2 + WP6  TrustStore + whitelist rules
│   ├── netctl.py        # WP3  LinuxBackend, DryRunBackend, FakeBackend
│   ├── healer.py        # WP3  corrective ARP + verify helpers
│   ├── chainlog.py      # WP4
│   ├── daemon.py        # WP5  asyncio wiring + Executor
│   ├── netwatch.py      # WP5
│   ├── report.py  anonymize.py  llm.py  templates/incident.md.j2     # WP7
│   └── dashboard/       # WP8  app.py, static/index.html
├── lab/    netns_up.sh  netns_down.sh  attack.sh  traffic.sh  README.md      # WP0
├── bench/  run_attacks.py  cpu_profile.py  results/                          # WP9
├── tests/  test_engine.py test_trust.py test_scenarios_fp.py test_scenarios_attack.py
│           test_chainlog.py test_anonymize.py test_report.py test_healer.py test_e2e_netns.py (integration)
└── docs/   architecture.md  threat-model.md  demo-runbook.md
```

Stack (decided): Python ≥ 3.11 · `scapy` · `jinja2` · `httpx` (LLM calls) · stdlib `argparse`, `tomllib`, `asyncio`, `hashlib`, `json` · dashboard extra: `fastapi` + `uvicorn` + plain HTML/JS (no build step) · dev: `pytest`, `ruff`, `psutil`. Shell out to `ip` (iproute2) for neighbour/route/addr; use `ip -j` JSON output.

---

## 5. Contracts (FROZEN — additive changes only)

```python
# sentinelx/models.py
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

MAC = str    # lowercase, colon-separated  "aa:bb:cc:dd:ee:ff"
IPv4 = str

@dataclass(frozen=True, slots=True)
class ArpEvent:
    ts: float        # capture time, epoch seconds
    iface: str
    op: int          # 1 = who-has, 2 = is-at
    eth_src: MAC     # Ethernet-layer source MAC
    arp_sha: MAC     # ARP sender hardware address
    arp_spa: IPv4    # ARP sender protocol address
    arp_tha: MAC
    arp_tpa: IPv4

@dataclass(frozen=True, slots=True)
class NetState:
    iface: str
    network_id: str  # SSID, or "wired"
    our_ip: IPv4
    our_mac: MAC
    gw_ip: IPv4

class State(str, Enum):
    WAITING_NET = "waiting_net"
    TOFU = "tofu"
    MONITOR = "monitor"
    CONFLICT = "conflict"          # >1 MAC answered during TOFU -> not pinned
    UNPROTECTED = "unprotected"    # gateway never answered

# ---- Engine output ----
@dataclass(frozen=True, slots=True)
class RunTofuProbe:  net: NetState
@dataclass(frozen=True, slots=True)
class Pin:           iface: str; gw_ip: IPv4; gw_mac: MAC
@dataclass(frozen=True, slots=True)
class Unpin:         iface: str; gw_ip: IPv4
@dataclass(frozen=True, slots=True)
class Heal:          # re-assert pin + (optionally) corrective ARP; executor verifies and logs a "heal" entry
    net: NetState; gw_mac: MAC; send_corrective: bool; reason: str
@dataclass(frozen=True, slots=True)
class LogRecord:     type: str; data: dict

Action = RunTofuProbe | Pin | Unpin | Heal | LogRecord

# ---- Engine ----
class Engine:
    def __init__(self, trust: "TrustStore", cfg: "EngineConfig") -> None: ...
    @property
    def state(self) -> State: ...
    def on_net(self, net: NetState | None, now: float) -> list[Action]: ...        # None = link/route lost
    def on_tofu_result(self, replies: dict[MAC, int], now: float) -> list[Action]: ...  # mac -> reply count
    def on_arp(self, ev: ArpEvent, now: float) -> list[Action]: ...
    def on_tick(self, now: float) -> list[Action]: ...                              # closes idle incidents

# ---- System access (all side effects) ----
@dataclass(frozen=True, slots=True)
class NeighEntry:
    ip: IPv4; mac: MAC; state: str      # e.g. "PERMANENT", "REACHABLE", "STALE"

class NetBackend(Protocol):
    def default_route(self) -> tuple[str, IPv4] | None: ...          # (iface, gw_ip)
    def net_state(self, iface: str, gw_ip: IPv4) -> NetState: ...
    def neigh_get(self, iface: str, ip: IPv4) -> NeighEntry | None: ...
    def neigh_pin(self, iface: str, ip: IPv4, mac: MAC) -> None: ... # ip neigh replace ... nud permanent
    def neigh_unpin(self, iface: str, ip: IPv4) -> None: ...         # ip neigh del
    def probe_gateway(self, net: NetState, count: int, window_ms: int) -> dict[MAC, int]: ...
    def send_arp_reply(self, iface: str, src_mac: MAC, src_ip: IPv4, dst_mac: MAC, dst_ip: IPv4) -> None: ...

# ---- Log ----
class ChainLog:
    def __init__(self, path: "Path") -> None: ...
    def append(self, type: str, data: dict) -> dict: ...             # returns the entry; flock + fsync
    def head(self) -> str: ...
    @staticmethod
    def verify(path: "Path") -> "VerifyResult": ...                 # ok, entries, bad_idx, reason, head

# ---- Trust store ----
class TrustStore(Protocol):
    def get(self, key: str) -> dict | None: ...                      # key = f"{iface}|{network_id}|{gw_ip}"
    def put(self, key: str, entry: dict) -> None: ...
    def add_allowed_mac(self, key: str, mac: MAC) -> None: ...
    def forget(self, key: str) -> None: ...
```
Implementations: `JsonTrustStore(path)` (atomic write: tmp + rename) and `MemoryTrustStore()` (tests).

### Files at runtime (`state_dir`, default `/var/lib/sentinelx`, dev: `./.sentinelx`)
| File | Writer | Content |
|---|---|---|
| `state.json` | TrustStore | `{ "<iface>\|<network_id>\|<gw_ip>": {"gw_mac", "allowed_macs": [...], "learned_at", "virtual_gateway": bool} }` |
| `log.jsonl` | ChainLog | hash-chained entries (§6.6) |
| `status.json` | daemon, 1 Hz | `{state, iface, network_id, gw_ip, gw_mac, pinned, under_attack, incidents_total, last_incident_ts, chain_head, dropped_events, updated}` |

---

## 6. Behaviour spec

### 6.1 Startup and TOFU
1. `default_route()` → `(iface, gw_ip)`. `None` → state `WAITING_NET`, poll every 2 s.
2. Trust key = `iface | network_id | gw_ip`. `network_id` = SSID if Wi-Fi (best effort), else `"wired"`. (Same `192.168.1.1` on two different networks must not look like an attack.)
3. Key exists in `TrustStore` → `Pin` (idempotent) → `MONITOR`.
4. Otherwise `RunTofuProbe`: `tofu_probes` (default 5) ARP who-has requests, 200 ms apart, collect replies for `tofu_window_ms`.
   - **exactly one distinct MAC** → store, `Pin` (if `pin_mode=always`), log `tofu_learned`, `MONITOR`.
   - **0 replies** → retry up to 3×, then `UNPROTECTED` + log `tofu_unprotected`.
   - **≥ 2 distinct MACs** → `CONFLICT`: **do not pin**, log `tofu_conflict` with counts. The operator resolves with `sentinelx trust --add-mac`. This is the partial defence against "attacker already active at join".
5. If the learned MAC is a known VRRP/HSRP virtual MAC (`00:00:5e:00:01:xx`, `00:00:0c:07:ac:xx`, `00:00:0c:9f:f0:xx`) set `virtual_gateway=true` in the entry.

### 6.2 Pin modes (`[core] pin_mode`)
- `always` (default): pin at TOFU. Spoofed replies never change the kernel entry (prevention). Detection then provides visibility + inbound repair.
- `on_detect`: pin only when an incident fires. Lets you show *"entry poisoned → restored in N ms"* exactly like the deck flow. Bench runs both.

### 6.3 Detection (state `MONITOR`)
Ignore packets with `arp_sha == our_mac`. Otherwise:

**R1 — gateway claim mismatch (the only trigger in MVP):** `arp_spa == gw_ip` (any op: request, reply, gratuitous) **and** `arp_sha ∉ allowed_macs` → `gateway_mac_mismatch`.
`allowed_macs` = pinned MAC ∪ `trust.allowed_macs` (config / `trust --add-mac`) ∪ VRRP rule below.
**VRRP/HSRP rule:** a vMAC-pattern sender is allowed **only if the pinned MAC is itself a vMAC** (`virtual_gateway=true`). Otherwise an attacker could spoof `00:00:5e:00:01:01` to evade. State this trade-off in `docs/threat-model.md`.
Enrichment (not a trigger): record `eth_src != arp_sha` as `eth_src_mismatch` in the detection data.

Things that must **never** alert (these become the ≥ 50 FP scenarios, §11): gateway packets carrying the pinned MAC (request/reply/GARP) · other hosts' ARP/GARP · ARP probes (`spa=0.0.0.0`) · our own packets · DHCP renew with same gateway · move to a different network (re-TOFU) · VRRP/HSRP vMAC group on a virtual gateway · mixed-case MAC strings · duplicate/replayed legit packets.

### 6.4 Incident handling and healing
- Incident key = `(gw_ip, observed_mac)`. **Aggregate**; never one log entry per packet (an attacker can flood at 1000+ pps).
- First packet of an incident → actions: `LogRecord("detect", …)`, `Heal(send_corrective=True)`.
- Further packets in the same incident → count them; `Heal(send_corrective=True)` at most once per `heal_cooldown_ms` (default 1000). No per-packet log entries.
- `on_tick`: no packet for `incident_idle_s` (default 10) → `LogRecord("incident_close", {packets, duration_s, first_seen, last_seen, observed_mac, heals})`.
- **Executor on `Heal`:** `neigh_pin` → `neigh_get` read-back → if `send_corrective`, `send_arp_reply` → write `heal` log entry `{verified: bool, pinned_mac, latency_ms_from_first_pkt, corrective_sent}`.
- **Corrective ARP (exact spec):** unicast reply to the router telling it our real binding:
  `Ether(src=our_mac, dst=gw_mac) / ARP(op=2, hwsrc=our_mac, psrc=our_ip, hwdst=gw_mac, pdst=gw_ip)`
- **Pin command:** `ip neigh replace <gw_ip> lladdr <gw_mac> dev <iface> nud permanent`. **Unpin:** `ip neigh del <gw_ip> dev <iface>`.
- Sniffer → engine queue is bounded (e.g. 1000). On overflow drop and count (`dropped_events` goes into status and the incident record). Floods must not eat the CPU budget.

### 6.5 Network change (easy to miss, will break the demo laptop if skipped)
`netwatch.py` polls `default_route()` + `network_id` every 2 s. A change in `(iface, network_id, gw_ip)` or loss of route → `Unpin` old gateway, log `network_changed`, start TOFU for the new one. **Do not assume the kernel flushes a permanent entry on reconnect** — a stale pin for `192.168.1.1` on the next network black-holes the user. Also `Unpin` on SIGINT/SIGTERM when `unpin_on_exit=true`. DHCP renew with unchanged `(iface, network_id, gw_ip)` → do nothing.

### 6.6 Hash-chained log (`log.jsonl`, one JSON object per line)
```json
{"idx":3,"ts":"2026-10-27T10:15:02.114233Z","type":"detect","data":{"kind":"gateway_mac_mismatch","gw_ip":"10.77.0.1","expected_mac":"aa:..","observed_mac":"bb:..","op":2,"eth_src_mismatch":false,"first_pkt_ts":1792836902.1139},"prev":"<64 hex>","hash":"<64 hex>"}
```
- `hash = sha256( prev + canonical_json({"idx","ts","type","data"}) )` where `canonical_json = json.dumps(obj, sort_keys=True, separators=(",", ":"))`.
- Entry 0 is `genesis` with `prev = "0"*64`.
- Types: `genesis, daemon_start, daemon_stop, tofu_learned, tofu_conflict, tofu_unprotected, network_changed, detect, heal, incident_close`.
- Append = `flock` + write + `flush` + `fsync`. A crash must leave a verifiable prefix.
- `verify` walks the file → `(ok, entries, bad_idx, reason, head)`. Reasons: `bad_hash`, `bad_prev`, `bad_idx`, `bad_json`, `bad_genesis`.
- **Honest limit:** detects edits, reordering and deletion *in the middle*. It does **not** detect truncation of the tail or a full regeneration by root unless the head hash is anchored somewhere else (stretch: print/sync head to S3 or a webhook). Say this in the README before a judge does.

### 6.7 Reports
`sentinelx report [--last | --incident N]` renders `templates/incident.md.j2` from log entries → `reports/incident-<ts>.md`: timeline, observed MAC, heal result, chain status, static recommended next steps. **No network access.**

### 6.8 LLM summary (opt-in, anonymized)
`[llm] enabled = false` by default. `sentinelx report --llm`:
1. `anonymize.py` maps MAC → `MAC-1…`, IPs → `IP-GW` / `IP-SELF` / `IP-PEER-n`; drops SSID/hostnames; timestamps → relative (`t+0.0s`); keeps only kinds, counts, durations.
2. Print the exact payload and require `--yes` (or interactive confirm) before sending.
3. Providers: `ollama` (default, `http://localhost:11434`) or `anthropic` (key from `ANTHROPIC_API_KEY`). Result is appended under "AI summary (anonymized input)".
4. Test: serialized outgoing payload must contain **no** MAC or IPv4 regex match from the original incident.

### 6.9 Config (`config.toml`)
```toml
[core]
iface = "auto"                 # "auto" = default-route interface
state_dir = "/var/lib/sentinelx"
pin_mode = "always"            # always | on_detect
unpin_on_exit = true
dry_run = false

[detect]
heal_cooldown_ms = 1000
incident_idle_s = 10
tofu_probes = 5
tofu_window_ms = 1000
queue_max = 1000

[whitelist]
allowed_macs = []              # extra legitimate gateway MACs

[llm]
enabled = false
provider = "ollama"            # ollama | anthropic
model = ""                     # set per provider
```

### 6.10 CLI
`sentinelx run [--iface X] [--config P] [--state-dir D] [--dry-run]` · `status` · `verify-log [--path P]` (exit 0 ok / 1 broken, prints first bad idx) · `report [--last|--incident N] [--llm] [--yes]` · `trust [--show | --add-mac MAC | --forget]` · `sniff --iface X` (debug) · `dashboard [--port 8787]` (binds 127.0.0.1 only)

### 6.11 Daemon wiring (pseudo-code for WP5)
```python
async def handle(actions):
    for a in actions:
        match a:
            case RunTofuProbe(net):
                replies = await asyncio.to_thread(backend.probe_gateway, net, cfg.tofu_probes, cfg.tofu_window_ms)
                await handle(engine.on_tofu_result(replies, now()))
            case Pin():      backend.neigh_pin(a.iface, a.gw_ip, a.gw_mac)
            case Unpin():    backend.neigh_unpin(a.iface, a.gw_ip)
            case Heal():     do_heal(a)            # pin, read back, corrective ARP, log "heal"
            case LogRecord(): chainlog.append(a.type, a.data)

# tasks: sniffer->queue consumer (engine.on_arp), netwatch (engine.on_net), 1 Hz tick (engine.on_tick + status.json)
```

---

## 7. Lab (network namespaces — dev, tests, benchmarks, demo Plan B)

```
                 sxbr0  (bridge in root ns, no IP)
        ┌─────────────┼──────────────┐
   sx-gw  10.77.0.1   sx-victim 10.77.0.10   sx-att 10.77.0.66      (subnet 10.77.0.0/24)
```
Outline for `lab/netns_up.sh` (needs root):
```bash
ip link add sxbr0 type bridge && ip link set sxbr0 up
for n in gw victim att; do
  ip netns add sx-$n
  ip link add v-$n type veth peer name p-$n
  ip link set v-$n netns sx-$n
  ip link set p-$n master sxbr0 up
  ip -n sx-$n link set lo up && ip -n sx-$n link set v-$n up
done
ip -n sx-gw     addr add 10.77.0.1/24  dev v-gw
ip -n sx-victim addr add 10.77.0.10/24 dev v-victim && ip -n sx-victim route add default via 10.77.0.1
ip -n sx-att    addr add 10.77.0.66/24 dev v-att
```
Attack (inside `sx-att`; `attack.sh` must check the namespace name):
```bash
ip netns exec sx-att sysctl -w net.ipv4.ip_forward=1
ip netns exec sx-att arpspoof -i v-att -t 10.77.0.10 -r 10.77.0.1     # -r = poison both directions
ip netns exec sx-att tcpdump -ni v-att icmp                            # what the attacker "sees"
```
Victim: `ip netns exec sx-victim python -m sentinelx run --iface v-victim` · `ip netns exec sx-victim ping 10.77.0.1` · `watch -n0.5 ip -n sx-victim neigh show 10.77.0.1`

Gotchas: if `br_netfilter` is loaded (Docker), set `net.bridge.bridge-nf-call-iptables=0` or bridged frames get filtered · `dsniff`/`arpspoof` comes from BlackArch/AUR on Arch · `ip neigh` needs `CAP_NET_ADMIN`, Scapy needs `CAP_NET_RAW` (run as root for the prototype) · `network_id` in netns is `"wired"`.

Make targets: `lab-up`, `lab-down`, `attack`, `e2e` (up → run daemon → attack → assert → down).

---

## 8. Parallelism map

```
WP0 ─┬─► WP1 sniffer ──┐
     ├─► WP2 engine ───┤
     ├─► WP3 backend ──┼─► WP5 daemon+cli ─┬─► WP6 whitelist scenarios ─┐
     └─► WP4 chainlog ─┘                   ├─► WP7 report/LLM           ├─► WP9 bench+docs+demo
                                           └─► WP8 dashboard ───────────┘
```
WP1–WP4 are independent given §5. Start all four as soon as WP0 merges the contracts.

---

## 9. Work packages

Roles follow the deck: **Core-1, Core-2** (backend), **OS** (OS integration), **Pipe-1, Pipe-2** (pipeline / QA / LLM API / presentation).

### WP0 — Skeleton, contracts, lab · *OS + Core-1* · depends: —
- Files: `pyproject.toml`, `Makefile`, `sentinelx/{__init__,__main__,cli,config,models}.py`, `lab/*`, `config.example.toml`, empty test dirs, `ruff` config.
- Accept: `pip install -e .[dev]` works · `make lab-up && make attack` → `ip -n sx-victim neigh show 10.77.0.1` shows the **attacker's** MAC and `tcpdump` in `sx-att` sees victim ICMP · `make lab-down` leaves no namespaces/bridge · `models.py` matches §5.

### WP1 — Sniffer · *Core-1* · depends: WP0
- Files: `sentinelx/sniffer.py`, `tests/test_sniffer.py`.
- Pure `parse_arp(pkt, iface) -> ArpEvent | None` (lowercases MACs, rejects non-ARP). `Sniffer` wraps `AsyncSniffer(iface, filter="arp", store=False)` and pushes into an `asyncio.Queue` via `loop.call_soon_threadsafe`; bounded queue, drop + count on overflow; survives iface down/up.
- Accept: unit tests build `Ether/ARP` packets with Scapy and assert fields (≥ 8 cases incl. non-ARP, truncated, mixed-case) · `sentinelx sniff --iface v-victim` in the lab prints events live.

### WP2 — Engine + TrustStore · *Core-2* · depends: WP0
- Files: `sentinelx/engine.py`, `sentinelx/trust.py` (store + rules), `tests/test_engine.py`, `tests/test_trust.py`.
- Implements §6.1–6.5 exactly as specified. No I/O in the engine.
- Accept: ≥ 30 table-driven tests · covers TOFU 1/0/≥2 MACs, R1 hit/miss, incident aggregation, cooldown, idle close, network change, `pin_mode` both values · mutation sanity check: flipping R1's comparison makes tests fail.

### WP3 — NetBackend + Healer · *OS* · depends: WP0
- Files: `sentinelx/netctl.py`, `sentinelx/healer.py`, `tests/test_healer.py`, `tests/test_e2e_netns.py` (healing part).
- `LinuxBackend` (`ip -j route/neigh/addr`, Scapy for probe + corrective ARP), `DryRunBackend` (logs what it would do), `FakeBackend` (records calls, scriptable replies). Corrective ARP exactly as §6.4.
- Accept (integration, root): with the victim already poisoned, `neigh_pin` → `PERMANENT` with the real MAC, and continued `arpspoof` does **not** change it · `send_arp_reply` makes `ip -n sx-gw neigh show 10.77.0.10` show the victim's real MAC again · `neigh_unpin` removes the entry.

### WP4 — ChainLog + verify · *Pipe-1* · depends: WP0
- Files: `sentinelx/chainlog.py`, `tests/test_chainlog.py`, `verify-log` subcommand body.
- Accept: ≥ 12 tests: append+verify OK · edit a field · edit a `ts` · delete a middle line · swap two lines · insert a forged line · corrupt JSON · wrong genesis · empty file · concurrent appends from 2 processes · crash-prefix still verifies · documented-known-miss test (`test_truncation_not_detected`, asserts current behaviour, marked `xfail(strict=False)` with a reason) · `sentinelx verify-log` exit code 0/1 and prints first bad `idx`.

### WP5 — Daemon + CLI + NetWatcher · *Core-1 + Core-2* · depends: WP1–WP4
- Files: `sentinelx/daemon.py`, `netwatch.py`, `cli.py` (run/status/trust/sniff), `tests/test_daemon_fake.py`.
- Wire §3 / §6.11. Signal handling (unpin on exit), status.json at 1 Hz, `--dry-run`.
- Accept: with `FakeBackend` + synthetic events the daemon logs `detect → heal → incident_close` · **`make e2e` green in the lab**: start daemon → `arpspoof` → victim entry stays/returns to real MAC → `log.jsonl` has `tofu_learned, detect, heal` → `verify-log` OK → SIGTERM unpins and writes `daemon_stop`.

### WP6 — Whitelist + scenario suites · *Core-2 + Pipe-1* · depends: WP5 (can start on WP2)
- Files: `tests/test_scenarios_fp.py`, `tests/test_scenarios_attack.py`, whitelist code in `trust.py`.
- Accept: **≥ 50 no-alert scenarios** (generated from the §6.3 list × variations: ops, case, GARP, VRRP/HSRP vMAC with and without `virtual_gateway`, renew vs new network) and **≥ 15 must-alert scenarios** (spoofed reply/request/GARP, repeated, flood, near-miss MAC, vMAC spoof on a non-virtual gateway). All green. README labels these "simulated packet scenarios".

### WP7 — Report + anonymizer + LLM · *Pipe-2* · depends: WP4 (WP5 for end-to-end)
- Files: `sentinelx/report.py`, `anonymize.py`, `llm.py`, `templates/incident.md.j2`, `tests/test_report.py`, `tests/test_anonymize.py`.
- Accept: report renders from a sample log with no network access (test blocks sockets) · anonymizer is deterministic per report and leaves **zero** MAC/IPv4 matches in the payload (regex test over ≥ 5 sample incidents) · `--llm` without `--yes` only prints the payload · provider is swappable via config · default `enabled=false`.

### WP8 — Dashboard · **P0 for Round 2** · *Pipe-1 + Pipe-2* · depends: WP0 for fixtures; wire to real data after WP5
- Files: `sentinelx/dashboard/app.py`, `static/index.html`, `tests/fixtures/status.json`, `tests/fixtures/log.jsonl`.
- Build against the committed fixtures first (§5 defines both files), then point it at the daemon's `state_dir`. FastAPI on `127.0.0.1`, plain HTML/JS, polls every 1 s. **Read-only** — no actions from the UI (revisit only if the team asks for it).
- The audience is a normal user, not a network engineer. Show:
  1. **Status banner in plain English**, driven by `status.json`: green "Protected — your router (10.77.0.1) is locked to aa:bb:…" · red "Under attack — a device (MAC …) is pretending to be your router. Sentinel-X is blocking it." · amber "Not protected — your router didn't answer" · amber "Conflict — two devices claim to be your router; nothing was pinned".
  2. **Incident feed in sentences**, rendered from `detect` / `heal` / `incident_close` entries, e.g. "10:15:02 — Someone claimed to be your router (3 packets). Correct entry restored, router warned. Verified." A "details" toggle shows the raw log entry.
  3. **Log-integrity badge:** re-runs `ChainLog.verify` on load and every 5 s → "Verified, N entries" or "TAMPERED at entry #k".
  4. Small cards: pinned gateway (IP, MAC, pin mode), total incidents, last incident, dropped events.
- Accept: with fixtures it renders all four banner states · in the lab the banner flips to UNDER ATTACK within 2 s of the attack starting and returns to Protected after `incident_idle_s` · hand-editing one line of `log.jsonl` turns the badge to TAMPERED with the right `idx` · no mock data anywhere in the real path.

### WP9 — Bench, docs, demo · *Pipe-2 + OS (+ everyone for rehearsal)* · depends: WP5 (WP6–WP8 for final)
- Files: `bench/run_attacks.py`, `bench/cpu_profile.py`, `bench/results/*.json`, `README.md`, `docs/*`, demo video.
- Accept: §11 evidence table is complete; README quickstart works on a clean clone; `docs/demo-runbook.md` rehearsed 3×.

---

## 10. Schedule — re-baselined for Round 2 (written Sat 24 Oct)

Two deadlines: **Round 2 = Sun 25 Oct 23:59 IST** (prototype + repo + recording) and **Finale = 30–31 Oct** (shortlisted teams only). Plan for Round 2 first; everything outside §0.1 waits.

| When (IST) | Milestone | Exit check |
|---|---|---|
| **Sat 24**, next ~2 h | WP0 merged (skeleton, contracts, lab, dashboard fixtures) | `make lab-up && make attack` poisons the victim; contracts on `main` |
| **Sat night** | WP1, WP2, WP3, WP4, WP8 in parallel, one agent each (WP8 on fixtures) | each WP's smoke acceptance passes |
| **Sun 25**, 09:00–13:00 | WP5 wiring; dashboard on real data | `make e2e` green: attack → detect → heal → log → verify |
| Sun 13:00–16:00 | Fixes, README, dashboard polish. **Cut whatever isn't working at 16:00.** | one clean run of the §12 script |
| Sun 16:00–17:00 | Record the screening video (2–3 min, two takes) | video file saved |
| **Sun 18:00** | **Submit on Unstop**: repo public, link, video, prototype | confirmation saved |
| Sun 18:00–23:59 | Buffer only. Fix/resubmit if Unstop rejects something | |
| Mon 26 – Wed 28 | Finale work: WP6 (≥ 50 FP), WP7, WP9 bench, §6.5 network change, `on_detect` | §11 evidence files exist |
| Thu 29 | Freeze 18:00 · rehearse ×3 · tag `v1.0` · polished fallback video | fresh clone runs the quickstart |
| Fri 30 – Sat 31 | Finale, offline at MBU. Bug-fix only, on a branch | |

**Round 2 cut line — if `make e2e` is not green by Sun 13:00:**
1. Record the pieces separately (see §0.1 rules); do not stitch or fake a flow.
2. Drop dashboard polish before dropping its integrity badge.
3. Drop everything in the "deferred" list.
**Never cut:** chainlog + `verify-log`, a working heal in the lab, the README limits section.

---

## 11. Tests and benchmarks — claim → evidence

Round 2 needs only the tamper-evident-log row. The rest are for the finale. Until measured, the README calls the deck numbers "targets".

| Deck claim | Evidence (must exist in repo) | How it is measured |
|---|---|---|
| Detected and healed in < 500 ms | `bench/results/latency.json` | per run: `t0` = kernel/pcap timestamp of the first spoofed packet at the victim iface; `t_heal` = `heal` log `ts` with `verified=true`; report p50 / p95 / max of `t_heal − t0` |
| ≥ 95 % mitigation over 50 runs | `bench/results/mitigation.json` | a run **succeeds** iff (1) `detect` logged, (2) victim's neighbour entry for gateway = real MAC and `PERMANENT` at `t0+2 s`, (3) still true at `t0+10 s` while the attacker keeps poisoning. Also **report** (not gate) packets leaked to the attacker after heal. Run for both `pin_mode`s. |
| 0 false positives over 50+ DHCP/VRRP tests | `tests/test_scenarios_fp.py` (≥ 50 cases) | pytest; README says "simulated packet scenarios". Add real DHCP renewals in the lab only if time remains. |
| < 5 % CPU | `bench/results/cpu.json` | `psutil` sampling of the daemon, 60 s each: idle · 50 pps benign ARP · active `arpspoof`. Report mean/p95 as **% of one core** (stricter than % of total). Optional 1000 pps flood: report only. |
| Tamper-evident logs | `tests/test_chainlog.py` + demo | tamper-then-verify in the demo; limits stated in README |
| LLM opt-in and anonymized | `tests/test_anonymize.py`, default `enabled=false` | regex test: no MAC/IPv4 in outgoing payload |

If a number misses its target, **publish the measured number** and fix the slide. If CPU misses: first `store=False` + BPF are already in; next step is replacing Scapy dissection on the hot path with a raw `AF_PACKET` socket + `struct` parse (keep Scapy for sending/probing).

Test layers: unit (no root) → fake-backend daemon tests (no root) → `integration` marker (root + netns) → bench.

---

## 12. Demo plan

**Topologies (decide by Tue 27, rehearse the chosen one 3×):**
- **Plan A (matches the deck):** separate *victim* and *attacker* machines/VMs on a network **we control** — own hotspot/router or an isolated libvirt network. Pitfalls: Wi-Fi **client isolation** silently blocks ARP between clients · VMs bridged over Wi-Fi often don't work · test it beforehand.
- **Plan B (safe default):** the §7 namespace lab on one laptop. Zero hardware risk. Same lab used for the bench.
- **Recording (required for Round 2):** screen capture of Plan B, 2–3 min, following the script below; record Sun 25 at 16:00. Re-record a polished version by Thu 29 as the finale fallback (Plan C).
- **Never** run an attack on the MBU/campus network. Unauthorized, and it breaks other people's connectivity.

**Script (~3 min), 4 panes: victim · attacker · attacker tcpdump · dashboard**
1. Baseline: `sentinelx status` → gateway pinned, `verify-log` OK, dashboard green.
2. *Without* Sentinel-X: start `arpspoof`; victim's `ip neigh` shows the attacker's MAC; attacker's `tcpdump` shows victim traffic → "this is the problem".
3. *With* Sentinel-X: restart the attack. Entry never changes / is restored; `tcpdump` goes quiet; dashboard flips to UNDER ATTACK; `detect → heal` appear in the feed.
4. Tamper: `sed` one byte in `log.jsonl` → `sentinelx verify-log` fails at `idx N`; dashboard shows the broken chain.
5. `sentinelx report --last` → local report. Optional: `--llm` shows the anonymized payload preview first.
6. Close with the bench numbers **from the JSON files** and the limits slide (§13).

**Pre-flight checklist:** `make lab-up` clean · fresh `state_dir` · dashboard up · terminal font large · laptop on charger · Plan C video on the desktop · `git tag v1.0` checked out.

---

## 13. Threat model and known limits (put these in `docs/threat-model.md` and the README)

- TOFU is only as trustworthy as the first contact. Multi-probe conflict detection helps; it does not solve an attacker already in the middle at join.
- Protects the **host ↔ gateway** path only. Peer-to-peer LAN traffic is not covered.
- IPv4 ARP only. IPv6 NDP spoofing is out of scope.
- A root-level attacker on the host can stop the daemon or rewrite state and log. Hash chain detects mid-file edits only; tail truncation needs an external anchor of the head hash.
- vMAC allowance (§6.3) is a deliberate false-positive/security trade-off, limited to gateways learned as virtual.
- A legitimate router replacement looks like an attack; the pin wins and the operator runs `sentinelx trust --add-mac`.
- Benchmarks run in a virtual lab, not on a production network.

---

## 14. Decisions already made (change only by editing this file)

| Topic | Decision |
|---|---|
| Language / OS | Python ≥ 3.11, Linux only, run as root for the prototype |
| Packet I/O | Scapy `AsyncSniffer` + BPF `arp`; `ip` (iproute2) for neighbour/route state |
| Log | JSONL + SHA-256 chain, `flock` + `fsync` |
| Config | TOML (`tomllib`) |
| Reports | Jinja2 template; LLM strictly opt-in, default provider Ollama (local) |
| Dashboard | FastAPI + plain HTML, localhost only, read-only |
| Attacker tool in lab | stock `arpspoof`, namespace-gated; no custom attack code |
| Pin default | `always` (prevention); `on_detect` kept for the deck's "restored in N ms" flow |

**Still needs a human:** (1) find the Round 2 submission email/link from Unstop — tonight, and check exactly what it asks for · (2) repo licence (MIT is fine) · (3) demo topology A vs B for the finale — by Tue 27 · (4) LLM provider/model — after Round 2.
