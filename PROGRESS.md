# Sentinel-X — Build Progress (Round 2)

## Checklist

- [x] **WP0**: Skeleton, `pyproject.toml`, `Makefile`, `sentinelx/models.py` (§5), `sentinelx/config.py`, `lab/` scripts (`netns_up.sh`, `netns_down.sh`, `attack.sh`, `traffic.sh`, `e2e.sh`, `README.md`), `config.example.toml` — **DONE** (Lab netns raw-socket steps **UNVERIFIED** on gVisor sandbox; see below)
- [x] **WP2**: `sentinelx/engine.py` (pure state machine) + `sentinelx/trust.py` (`JsonTrustStore`, `MemoryTrustStore`) + unit tests (`tests/test_engine.py`, `tests/test_trust.py`, `tests/test_scenarios_fp.py`, `tests/test_scenarios_attack.py`) — **DONE**
- [x] **WP4**: `sentinelx/chainlog.py` (`ChainLog` append with `flock` + `fsync`, `verify`) + `sentinelx verify-log` CLI + unit tests (`tests/test_chainlog.py`) — **DONE**
- [x] **WP3**: `sentinelx/netctl.py` (`LinuxBackend`, `DryRunBackend`, `FakeBackend`) + `sentinelx/healer.py` + unit tests (`tests/test_healer.py`, `tests/test_e2e_netns.py`) — **DONE** (Kernel `RTNETLINK` / `AF_PACKET` steps **UNVERIFIED** on gVisor sandbox)
- [x] **WP1**: `sentinelx/sniffer.py` (`parse_arp`, `Sniffer` wrapping Scapy `AsyncSniffer` with bounded `asyncio.Queue` & drop count) + unit tests (`tests/test_sniffer.py`) — **DONE**
- [x] **WP5**: `sentinelx/daemon.py`, `sentinelx/netwatch.py`, `sentinelx/cli.py` (`run`, `status`, `trust`, `sniff`, `verify-log`, `dashboard`), `status.json` at 1 Hz, signal handling, R2 host-namespace safety guard (`--allow-host`) + tests (`tests/test_daemon_fake.py`) — **DONE** (`make e2e` live kernel netns run **UNVERIFIED** on gVisor sandbox)
- [x] **WP8**: `sentinelx/dashboard/app.py`, `sentinelx/dashboard/static/index.html`, fixtures (`tests/fixtures/status.json`, `tests/fixtures/log.jsonl`), unit tests (`tests/test_dashboard.py`) + interactive web dashboard preview — **DONE**
- [x] **WP9-lite (Docs)**: `README.md` (5-line quickstart, architecture diagram, §13 limits, deck numbers labelled "targets"), `docs/demo-runbook.md` (4-pane demo commands), `docs/threat-model.md`, `docs/architecture.md` — **DONE**

## Environment Honesty Check

- `id -u` -> `0` (root inside container)
- `uname -a` -> `Linux localhost 4.19.0-gvisor #1 SMP ... x86_64 GNU/Linux`
- Installed & verified binaries: `python3` (3.11.2), `pip`, `ruff`, `pytest`, `ip` (`/usr/sbin/ip`), `tcpdump` (`/usr/bin/tcpdump`), `arpspoof` (`/usr/sbin/arpspoof` from `dsniff`), `make`.
- **Sandbox Kernel Limitation (`4.19.0-gvisor`):**
  - `ip netns add sx-*` and `veth` creation work, **but** gVisor's user-space network stack returns `RTNETLINK answers: Operation not supported` on `ip neigh show/replace/del` (`RTM_NEWNEIGH`/`RTM_GETNEIGH`) and `OSError: [Errno 95] Operation not supported` on `AF_PACKET` raw frame injection (`sendp` and `arpspoof` `libnet_select_device`).
  - Therefore, all pure unit tests, `FakeBackend`/`DryRunBackend` daemon lifecycle tests, CLI tests, R2 safety guard tests, `ChainLog` multi-process & tamper tests, and dashboard tests (`101 passed, 1 xfailed`) are **VERIFIED**, while `make lab-up && make e2e` requiring kernel `RTNETLINK` neighbour pinning and `AF_PACKET` raw sockets is marked **UNVERIFIED** in this sandbox and listed below for human execution on a native Linux kernel.

## Decisions

1. **Additive §5 Dataclasses**: Added concrete `@dataclass(frozen=True, slots=True)` definitions for `EngineConfig` and `VerifyResult` in `sentinelx/models.py` and documented them in `PLAN.md` §5.
2. **Scapy IPv6 Route Auto-Loading Disabled**: Set `scapy.config.conf.ipv6_enabled = False` and imported `ARP`, `Ether`, `AsyncSniffer`, `sendp` from `scapy.layers.l2` / `scapy.sendrecv` to avoid Scapy 2.8.0's `route6` import crash on interfaces without an IPv6 `scope` attribute and to align strictly with IPv4 ARP scope.
3. **Default Route Egress Resolution**: `lab/netns_up.sh` explicitly passes `dev v-victim` when adding the default route, and `LinuxBackend.default_route()` handles kernels where `ip -j route show default` omits `"dev"` when `iface_override` is provided.
4. **R2 Host-Namespace Safety Guard**: `sentinelx run` compares `(st_dev, st_ino)` of `/proc/self/ns/net` and `/proc/1/ns/net`. Without `--allow-host`, it exits with code `2`; with `--allow-host`, it prints a warning to `stderr` that §6.5 network-change handling is deferred.

## Known Issues

- Tail truncation of `log.jsonl` by a local root attacker cannot be detected without an external anchor of `chain_head` (documented in `README.md`, `docs/threat-model.md`, and `test_truncation_not_detected` marked `xfail(strict=False)` per §9 WP4).

## Commands for the Human to Run (Native Linux Host with Root)

```bash
# 1. Verify unit suite and linter (no root required)
pip install -e ".[dev]"
ruff check .
pytest -m "not integration"

# 2. Verify full namespace lab + arpspoof + TOFU + detect + verified heal + SIGTERM unpin + verify-log
sudo make lab-up && sudo make e2e

# 3. Verify pytest integration marker
sudo -E pytest -m integration

# 4. Run 1-byte tamper check on log.jsonl
cp tests/fixtures/log.jsonl /tmp/tamper.jsonl
sed -i 's/02:77:00:00:00:66/02:77:00:00:00:99/' /tmp/tamper.jsonl
sentinelx verify-log --path /tmp/tamper.jsonl ; echo "Exit code: $?"

# 5. Launch read-only FastAPI dashboard on 127.0.0.1:8787
sentinelx dashboard --port 8787 --state-dir tests/fixtures
```

## Next Step

- Round 2 slice complete. Awaiting human execution of `sudo make lab-up && sudo make e2e` on native Linux kernel and `PHASE 2` trigger for deferred items.
