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


@dataclass(frozen=True, slots=True)
class EngineConfig:
    pin_mode: str = "always"            # "always" | "on_detect"
    heal_cooldown_ms: int = 1000
    incident_idle_s: float = 10.0
    tofu_probes: int = 5
    tofu_window_ms: int = 1000
    tofu_max_retries: int = 3
    extra_allowed_macs: tuple[MAC, ...] = ()


@dataclass(frozen=True, slots=True)
class VerifyResult:
    ok: bool
    entries: int
    bad_idx: int | None
    reason: str | None
    head: str


# ---- Engine output ----
@dataclass(frozen=True, slots=True)
class RunTofuProbe:
    net: NetState


@dataclass(frozen=True, slots=True)
class Pin:
    iface: str
    gw_ip: IPv4
    gw_mac: MAC


@dataclass(frozen=True, slots=True)
class Unpin:
    iface: str
    gw_ip: IPv4


@dataclass(frozen=True, slots=True)
class Heal:          # re-assert pin + (optionally) corrective ARP; executor verifies and logs a "heal" entry
    net: NetState
    gw_mac: MAC
    send_corrective: bool
    reason: str


@dataclass(frozen=True, slots=True)
class LogRecord:
    type: str
    data: dict


Action = RunTofuProbe | Pin | Unpin | Heal | LogRecord


# ---- Engine ----
class Engine(Protocol):
    def __init__(self, trust: TrustStore, cfg: EngineConfig) -> None: ...
    @property
    def state(self) -> State: ...
    def on_net(self, net: NetState | None, now: float) -> list[Action]: ...        # None = link/route lost
    def on_tofu_result(self, replies: dict[MAC, int], now: float) -> list[Action]: ...  # mac -> reply count
    def on_arp(self, ev: ArpEvent, now: float) -> list[Action]: ...
    def on_tick(self, now: float) -> list[Action]: ...                              # closes idle incidents


# ---- System access (all side effects) ----
@dataclass(frozen=True, slots=True)
class NeighEntry:
    ip: IPv4
    mac: MAC
    state: str      # e.g. "PERMANENT", "REACHABLE", "STALE"


class NetBackend(Protocol):
    def default_route(self) -> tuple[str, IPv4] | None: ...          # (iface, gw_ip)
    def net_state(self, iface: str, gw_ip: IPv4) -> NetState: ...
    def neigh_get(self, iface: str, ip: IPv4) -> NeighEntry | None: ...
    def neigh_pin(self, iface: str, ip: IPv4, mac: MAC) -> None: ...  # ip neigh replace ... nud permanent
    def neigh_unpin(self, iface: str, ip: IPv4) -> None: ...          # ip neigh del
    def probe_gateway(self, net: NetState, count: int, window_ms: int) -> dict[MAC, int]: ...
    def send_arp_reply(
        self, iface: str, src_mac: MAC, src_ip: IPv4, dst_mac: MAC, dst_ip: IPv4
    ) -> None: ...


# ---- Log ----
class ChainLog(Protocol):
    def __init__(self, path: Path) -> None: ...
    def append(self, type: str, data: dict) -> dict: ...             # returns the entry; flock + fsync
    def head(self) -> str: ...
    @staticmethod
    def verify(path: Path) -> VerifyResult: ...                      # ok, entries, bad_idx, reason, head


# ---- Trust store ----
class TrustStore(Protocol):
    def get(self, key: str) -> dict | None: ...                      # key = f"{iface}|{network_id}|{gw_ip}"
    def put(self, key: str, entry: dict) -> None: ...
    def add_allowed_mac(self, key: str, mac: MAC) -> None: ...
    def forget(self, key: str) -> None: ...
