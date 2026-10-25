# Sentinel-X — Architecture Overview

## Separation of Concerns

Sentinel-X separates **packet capture**, **pure decision logic**, and **privileged OS side effects** so that all detection, TOFU, cooldown, and incident-aggregation rules can be deterministically unit-tested without root privileges or network interfaces.

1. **`sentinelx/models.py` (§5 Frozen Contracts):**
   - Defines immutable `@dataclass(frozen=True, slots=True)` structures (`ArpEvent`, `NetState`, `EngineConfig`, `VerifyResult`, `NeighEntry`), `State` enum, `Action` union (`RunTofuProbe`, `Pin`, `Unpin`, `Heal`, `LogRecord`), and `Protocol` interfaces (`NetBackend`, `TrustStore`).
2. **`sentinelx/sniffer.py` (WP1):**
   - `parse_arp(pkt, iface, ts)` converts Scapy `Ether/ARP` frames into normalized `ArpEvent` instances (lowercasing MACs, rejecting non-ARP or malformed frames).
   - `Sniffer` runs Scapy's `AsyncSniffer(filter="arp", store=False)` on a background thread and pushes events into a bounded `asyncio.Queue` via `loop.call_soon_threadsafe`, counting overflows in `dropped_events`.
3. **`sentinelx/engine.py` & `sentinelx/trust.py` (WP2):**
   - `Engine` is a pure state machine (`WAITING_NET`, `TOFU`, `MONITOR`, `CONFLICT`, `UNPROTECTED`) with zero I/O or system calls.
   - `TrustStore` (`MemoryTrustStore` and `JsonTrustStore`) persists learned gateway bindings keyed by `f"{iface}|{network_id}|{gw_ip}"`.
4. **`sentinelx/netctl.py` & `sentinelx/healer.py` (WP3):**
   - `LinuxBackend` executes `ip -j route`, `ip -j addr`, `ip -j neigh`, `ip neigh replace ... nud permanent`, and Scapy ARP probes/replies.
   - `DryRunBackend` and `FakeBackend` allow dry-run execution and deterministic rootless testing.
   - `execute_heal` pins the gateway, verifies the kernel neighbour state by reading it back, sends a unicast corrective ARP reply to the router, and returns structured verification telemetry.
5. **`sentinelx/chainlog.py` (WP4):**
   - Maintains `log.jsonl` where each line commits to the previous line's SHA-256 digest:
     `hash = sha256(prev + canonical_json({"idx", "ts", "type", "data"}))`.
   - Uses `fcntl.flock(LOCK_EX)` + `flush()` + `os.fsync()` on every append.
6. **`sentinelx/daemon.py`, `sentinelx/netwatch.py`, `sentinelx/cli.py` (WP5):**
   - `Daemon` coordinates the `Sniffer` queue consumer, `NetWatcher` (2s route poll), and 1 Hz tick loop (`status.json` atomic updates and idle incident closure), plus `SIGINT`/`SIGTERM` cleanup and the Round 2 host-namespace safety guard.
7. **`sentinelx/dashboard/` (WP8):**
   - Read-only FastAPI + HTML/JS dashboard reading `status.json` and `log.jsonl` and verifying the hash chain via `ChainLog.verify`.
