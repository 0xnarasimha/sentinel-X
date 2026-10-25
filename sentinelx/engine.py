# sentinelx/engine.py
from __future__ import annotations

from dataclasses import dataclass

from sentinelx.models import (
    MAC,
    Action,
    ArpEvent,
    EngineConfig,
    Heal,
    IPv4,
    LogRecord,
    NetState,
    Pin,
    RunTofuProbe,
    State,
    TrustStore,
    Unpin,
)
from sentinelx.trust import is_mac_allowed, is_virtual_mac, normalize_mac, trust_key


@dataclass(slots=True)
class _ActiveIncident:
    gw_ip: IPv4
    observed_mac: MAC
    first_seen: float
    last_seen: float
    first_pkt_ts: float
    packets: int
    heals: int
    last_heal_ts: float


class Engine:
    """Pure ARP-defense state machine (§5 & §6).

    HARD RULE: Zero I/O, zero subprocess calls, zero sockets, zero `time.time()`.
    All timestamps are passed in via `now: float`.
    """

    def __init__(self, trust: TrustStore, cfg: EngineConfig | None = None) -> None:
        self._trust: TrustStore = trust
        self._cfg: EngineConfig = cfg or EngineConfig()
        self._state: State = State.WAITING_NET
        self._net: NetState | None = None
        self._gw_mac: MAC | None = None
        self._pinned: bool = False
        self._tofu_retries: int = 0
        self._incidents: dict[tuple[IPv4, MAC], _ActiveIncident] = {}
        self._incidents_total: int = 0
        self._last_incident_ts: float | None = None

    @property
    def state(self) -> State:
        return self._state

    @property
    def net(self) -> NetState | None:
        return self._net

    @property
    def gw_mac(self) -> MAC | None:
        return self._gw_mac

    @property
    def pinned(self) -> bool:
        return self._pinned

    @property
    def under_attack(self) -> bool:
        return len(self._incidents) > 0

    @property
    def incidents_total(self) -> int:
        return self._incidents_total

    @property
    def last_incident_ts(self) -> float | None:
        return self._last_incident_ts

    def active_incident_first_pkt_ts(self, observed_mac: MAC | None = None) -> float | None:
        if not self._incidents:
            return None
        if observed_mac is not None and self._net is not None:
            inc = self._incidents.get((self._net.gw_ip, normalize_mac(observed_mac)))
            if inc is not None:
                return inc.first_pkt_ts
        return min(inc.first_pkt_ts for inc in self._incidents.values())

    def on_net(self, net: NetState | None, now: float) -> list[Action]:
        actions: list[Action] = []

        if net is None:
            if self._net is not None:
                if self._pinned:
                    actions.append(Unpin(iface=self._net.iface, gw_ip=self._net.gw_ip))
                actions.append(
                    LogRecord(
                        type="network_changed",
                        data={
                            "reason": "route_lost",
                            "old_iface": self._net.iface,
                            "old_network_id": self._net.network_id,
                            "old_gw_ip": self._net.gw_ip,
                            "ts_epoch": now,
                        },
                    )
                )
            self._net = None
            self._gw_mac = None
            self._pinned = False
            self._tofu_retries = 0
            self._incidents.clear()
            self._state = State.WAITING_NET
            return actions

        norm_net = NetState(
            iface=net.iface,
            network_id=net.network_id,
            our_ip=net.our_ip,
            our_mac=normalize_mac(net.our_mac),
            gw_ip=net.gw_ip,
        )

        # Unchanged (iface, network_id, gw_ip) -> DHCP renew or poll tick; do nothing (§6.5)
        if (
            self._net is not None
            and self._net.iface == norm_net.iface
            and self._net.network_id == norm_net.network_id
            and self._net.gw_ip == norm_net.gw_ip
            and self._state != State.WAITING_NET
        ):
            self._net = norm_net
            return []

        # Network changed from a previous active network
        if self._net is not None and (
            self._net.iface != norm_net.iface
            or self._net.network_id != norm_net.network_id
            or self._net.gw_ip != norm_net.gw_ip
        ):
            if self._pinned:
                actions.append(Unpin(iface=self._net.iface, gw_ip=self._net.gw_ip))
            actions.append(
                LogRecord(
                    type="network_changed",
                    data={
                        "reason": "network_switched",
                        "old_iface": self._net.iface,
                        "old_network_id": self._net.network_id,
                        "old_gw_ip": self._net.gw_ip,
                        "new_iface": norm_net.iface,
                        "new_network_id": norm_net.network_id,
                        "new_gw_ip": norm_net.gw_ip,
                        "ts_epoch": now,
                    },
                )
            )
            self._incidents.clear()
            self._pinned = False
            self._gw_mac = None

        self._net = norm_net
        self._tofu_retries = 0
        key = trust_key(norm_net.iface, norm_net.network_id, norm_net.gw_ip)
        trusted = self._trust.get(key)

        if trusted is not None and trusted.get("gw_mac"):
            gw_mac = normalize_mac(str(trusted["gw_mac"]))
            self._gw_mac = gw_mac
            self._state = State.MONITOR
            if self._cfg.pin_mode == "always":
                self._pinned = True
                actions.append(Pin(iface=norm_net.iface, gw_ip=norm_net.gw_ip, gw_mac=gw_mac))
            else:
                self._pinned = False
            return actions

        self._state = State.TOFU
        actions.append(RunTofuProbe(net=norm_net))
        return actions

    def on_tofu_result(self, replies: dict[MAC, int], now: float) -> list[Action]:
        if self._net is None:
            return []

        norm_replies: dict[MAC, int] = {}
        for mac, count in replies.items():
            if count > 0:
                m = normalize_mac(mac)
                norm_replies[m] = norm_replies.get(m, 0) + int(count)

        # Case 1: Exactly one distinct MAC answered (§6.1)
        if len(norm_replies) == 1:
            gw_mac, reply_count = next(iter(norm_replies.items()))
            v_gw = is_virtual_mac(gw_mac)
            key = trust_key(self._net.iface, self._net.network_id, self._net.gw_ip)
            entry = {
                "gw_mac": gw_mac,
                "allowed_macs": [],
                "learned_at": now,
                "virtual_gateway": v_gw,
            }
            self._trust.put(key, entry)
            self._gw_mac = gw_mac
            self._state = State.MONITOR
            self._tofu_retries = 0

            actions: list[Action] = []
            if self._cfg.pin_mode == "always":
                self._pinned = True
                actions.append(
                    Pin(iface=self._net.iface, gw_ip=self._net.gw_ip, gw_mac=gw_mac)
                )
            else:
                self._pinned = False

            actions.append(
                LogRecord(
                    type="tofu_learned",
                    data={
                        "iface": self._net.iface,
                        "network_id": self._net.network_id,
                        "gw_ip": self._net.gw_ip,
                        "gw_mac": gw_mac,
                        "replies": reply_count,
                        "virtual_gateway": v_gw,
                        "pin_mode": self._cfg.pin_mode,
                    },
                )
            )
            return actions

        # Case 2: 0 replies -> retry up to 3x, then UNPROTECTED (§6.1)
        if len(norm_replies) == 0:
            self._tofu_retries += 1
            if self._tofu_retries < self._cfg.tofu_max_retries:
                self._state = State.TOFU
                return [RunTofuProbe(net=self._net)]
            self._state = State.UNPROTECTED
            self._pinned = False
            return [
                LogRecord(
                    type="tofu_unprotected",
                    data={
                        "iface": self._net.iface,
                        "network_id": self._net.network_id,
                        "gw_ip": self._net.gw_ip,
                        "retries": self._tofu_retries,
                    },
                )
            ]

        # Case 3: >= 2 distinct MACs -> CONFLICT; do not pin (§6.1)
        self._state = State.CONFLICT
        self._pinned = False
        return [
            LogRecord(
                type="tofu_conflict",
                data={
                    "iface": self._net.iface,
                    "network_id": self._net.network_id,
                    "gw_ip": self._net.gw_ip,
                    "candidates": norm_replies,
                },
            )
        ]

    def on_arp(self, ev: ArpEvent, now: float) -> list[Action]:
        if self._state != State.MONITOR or self._net is None or self._gw_mac is None:
            return []

        if ev.iface != self._net.iface:
            return []

        sha = normalize_mac(ev.arp_sha)
        eth_src = normalize_mac(ev.eth_src)

        # Ignore our own frames (§6.3)
        if sha == self._net.our_mac:
            return []

        # R1 — gateway claim mismatch: only trigger when sender claims gateway IP (§6.3)
        if ev.arp_spa != self._net.gw_ip:
            return []

        key = trust_key(self._net.iface, self._net.network_id, self._net.gw_ip)
        trust_entry = self._trust.get(key)
        if trust_entry is None:
            trust_entry = {
                "gw_mac": self._gw_mac,
                "allowed_macs": [],
                "virtual_gateway": is_virtual_mac(self._gw_mac),
            }
        else:
            # Keep active gw_mac synchronized if trust entry was updated
            if trust_entry.get("gw_mac"):
                self._gw_mac = normalize_mac(str(trust_entry["gw_mac"]))

        if is_mac_allowed(sha, trust_entry, self._cfg.extra_allowed_macs):
            return []

        eth_src_mismatch = eth_src != sha
        inc_key = (self._net.gw_ip, sha)
        inc = self._incidents.get(inc_key)

        if inc is None:
            self._incidents[inc_key] = _ActiveIncident(
                gw_ip=self._net.gw_ip,
                observed_mac=sha,
                first_seen=now,
                last_seen=now,
                first_pkt_ts=ev.ts,
                packets=1,
                heals=1,
                last_heal_ts=now,
            )
            self._incidents_total += 1
            self._last_incident_ts = now
            self._pinned = True
            return [
                LogRecord(
                    type="detect",
                    data={
                        "kind": "gateway_mac_mismatch",
                        "iface": self._net.iface,
                        "gw_ip": self._net.gw_ip,
                        "expected_mac": self._gw_mac,
                        "observed_mac": sha,
                        "op": ev.op,
                        "eth_src": eth_src,
                        "eth_src_mismatch": eth_src_mismatch,
                        "first_pkt_ts": ev.ts,
                    },
                ),
                Heal(
                    net=self._net,
                    gw_mac=self._gw_mac,
                    send_corrective=True,
                    reason="gateway_mac_mismatch",
                ),
            ]

        # Existing active incident: aggregate packets, enforce heal cooldown (§6.4)
        inc.packets += 1
        inc.last_seen = now
        self._last_incident_ts = now

        elapsed_ms = (now - inc.last_heal_ts) * 1000.0
        if elapsed_ms >= float(self._cfg.heal_cooldown_ms):
            inc.heals += 1
            inc.last_heal_ts = now
            self._pinned = True
            return [
                Heal(
                    net=self._net,
                    gw_mac=self._gw_mac,
                    send_corrective=True,
                    reason="gateway_mac_mismatch",
                )
            ]

        return []

    def on_tick(self, now: float) -> list[Action]:
        if not self._incidents:
            return []

        actions: list[Action] = []
        to_close: list[tuple[IPv4, MAC]] = []

        for inc_key, inc in self._incidents.items():
            if (now - inc.last_seen) >= float(self._cfg.incident_idle_s):
                to_close.append(inc_key)
                actions.append(
                    LogRecord(
                        type="incident_close",
                        data={
                            "gw_ip": inc.gw_ip,
                            "observed_mac": inc.observed_mac,
                            "packets": inc.packets,
                            "heals": inc.heals,
                            "first_seen": inc.first_seen,
                            "last_seen": inc.last_seen,
                            "duration_s": round(inc.last_seen - inc.first_seen, 6),
                        },
                    )
                )

        for k in to_close:
            del self._incidents[k]

        return actions
