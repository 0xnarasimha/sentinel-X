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
from pathlib import Path
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

# ---- Engine config (additive contract for Engine.__init__) ----
@dataclass(frozen=True, slots=True)
class EngineConfig:
    pin_mode: str = "always"            # "always" | "on_detect"
    heal_cooldown_ms: int = 1000
    incident_idle_s: float = 10.0
    tofu_probes: int = 5
    tofu_window_ms: int = 1000
    tofu_max_retries: int = 3
    extra_allowed_macs: tuple[MAC, ...] = ()

# ---- Verify result (additive contract for ChainLog.verify) ----
@dataclass(frozen=True, slots=True)
class VerifyResult:
    ok: bool
    entries: int
    bad_idx: int | None
    reason: str | None
    head: str

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
2. Trust key = `iface | network_id | gw_ip`. `network_id` = SSID if Wi-Fi (best effort), else `"wired"`.
3. Key exists in `TrustStore` → `Pin` (idempotent) → `MONITOR`.
4. Otherwise `RunTofuProbe`: `tofu_probes` (default 5) ARP who-has requests, 200 ms apart, collect replies for `tofu_window_ms`.
   - **exactly one distinct MAC** → store, `Pin` (if `pin_mode=always`), log `tofu_learned`, `MONITOR`.
   - **0 replies** → retry up to 3×, then `UNPROTECTED` + log `tofu_unprotected`.
   - **≥ 2 distinct MACs** → `CONFLICT`: **do not pin**, log `tofu_conflict` with counts.
5. If the learned MAC is a known VRRP/HSRP virtual MAC (`00:00:5e:00:01:xx`, `00:00:0c:07:ac:xx`, `00:00:0c:9f:f0:xx`) set `virtual_gateway=true` in the entry.

### 6.2 Pin modes (`[core] pin_mode`)
- `always` (default): pin at TOFU.
- `on_detect`: pin only when an incident fires.

### 6.3 Detection (state `MONITOR`)
Ignore packets with `arp_sha == our_mac`. Otherwise:
**R1 — gateway claim mismatch:** `arp_spa == gw_ip` and `arp_sha ∉ allowed_macs` → `gateway_mac_mismatch`.

### 6.4 Incident handling and healing
- Incident key = `(gw_ip, observed_mac)`. Aggregate.
- First packet → `LogRecord("detect", …)`, `Heal(send_corrective=True)`.
- Further packets → count; `Heal(send_corrective=True)` at most once per `heal_cooldown_ms` (default 1000).
- `on_tick`: no packet for `incident_idle_s` (default 10) → `LogRecord("incident_close", {packets, duration_s, first_seen, last_seen, observed_mac, heals})`.
- **Executor on `Heal`:** `neigh_pin` → `neigh_get` read-back → if `send_corrective`, `send_arp_reply` → write `heal` log entry `{verified: bool, pinned_mac, latency_ms_from_first_pkt, corrective_sent}`.

### 6.6 Hash-chained log (`log.jsonl`)
- `hash = sha256( prev + canonical_json({"idx","ts","type","data"}) )` where `canonical_json = json.dumps(obj, sort_keys=True, separators=(",", ":"))`.
- Entry 0 is `genesis` with `prev = "0"*64`.
- Types: `genesis, daemon_start, daemon_stop, tofu_learned, tofu_conflict, tofu_unprotected, network_changed, detect, heal, incident_close`.
- `verify` walks the file → `(ok, entries, bad_idx, reason, head)`. Reasons: `bad_hash`, `bad_prev`, `bad_idx`, `bad_json`, `bad_genesis`.

---

## 13. Threat model and known limits
- TOFU is only as trustworthy as the first contact. Multi-probe conflict detection helps; it does not solve an attacker already in the middle at join.
- Protects the **host ↔ gateway** path only. Peer-to-peer LAN traffic is not covered.
- IPv4 ARP only. IPv6 NDP spoofing is out of scope.
- A root-level attacker on the host can stop the daemon or rewrite state and log. Hash chain detects mid-file edits only; tail truncation needs an external anchor of the head hash.
- vMAC allowance (§6.3) is a deliberate false-positive/security trade-off, limited to gateways learned as virtual.
- A legitimate router replacement looks like an attack; the pin wins and the operator runs `sentinelx trust --add-mac`.
- Benchmarks run in a virtual lab, not on a production network.
