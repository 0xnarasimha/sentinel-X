# sentinelx/netctl.py
from __future__ import annotations

import json
import logging
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any

from sentinelx.models import MAC, IPv4, NeighEntry, NetBackend, NetState
from sentinelx.trust import normalize_mac

logger = logging.getLogger(__name__)


def _run_cmd(args: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, check=check)


class LinuxBackend(NetBackend):
    """Production Linux NetBackend using `ip -j` (iproute2) and Scapy raw sockets."""

    def __init__(self, iface_override: str | None = None) -> None:
        self.iface_override = (
            iface_override if iface_override and iface_override != "auto" else None
        )

    def default_route(self) -> tuple[str, IPv4] | None:
        proc = _run_cmd(["ip", "-j", "route", "show", "default"], check=False)
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        try:
            routes: list[dict[str, Any]] = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return None
        for r in routes:
            dev = r.get("dev") or self.iface_override
            gw = r.get("gateway")
            if self.iface_override and dev and str(dev) != self.iface_override:
                continue
            if dev and gw:
                return str(dev), str(gw)
        return None

    def _detect_network_id(self, iface: str) -> str:
        try:
            proc = _run_cmd(["iwgetid", "-r", iface], check=False)
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.strip()
        except FileNotFoundError:
            pass
        return "wired"

    def net_state(self, iface: str, gw_ip: IPv4) -> NetState:
        proc = _run_cmd(["ip", "-j", "addr", "show", "dev", iface], check=True)
        info_list: list[dict[str, Any]] = json.loads(proc.stdout)
        if not info_list:
            raise RuntimeError(f"Interface {iface} not found in `ip -j addr`")
        info = info_list[0]
        our_mac = normalize_mac(str(info.get("address", "00:00:00:00:00:00")))
        our_ip = "0.0.0.0"
        for addr_entry in info.get("addr_info", []):
            if addr_entry.get("family") == "inet" and addr_entry.get("local"):
                our_ip = str(addr_entry["local"])
                break
        network_id = self._detect_network_id(iface)
        return NetState(
            iface=iface,
            network_id=network_id,
            our_ip=our_ip,
            our_mac=our_mac,
            gw_ip=gw_ip,
        )

    def neigh_get(self, iface: str, ip: IPv4) -> NeighEntry | None:
        proc = _run_cmd(["ip", "-j", "neigh", "show", ip, "dev", iface], check=False)
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        try:
            entries: list[dict[str, Any]] = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return None
        for e in entries:
            if e.get("dst") == ip and e.get("lladdr"):
                mac = normalize_mac(str(e["lladdr"]))
                raw_state = e.get("state", [])
                if isinstance(raw_state, list):
                    state_upper = [str(s).upper() for s in raw_state]
                    state_str = (
                        "PERMANENT"
                        if "PERMANENT" in state_upper
                        else (state_upper[0] if state_upper else "UNKNOWN")
                    )
                else:
                    state_str = str(raw_state).upper()
                return NeighEntry(ip=ip, mac=mac, state=state_str)
        return None

    def neigh_pin(self, iface: str, ip: IPv4, mac: MAC) -> None:
        norm = normalize_mac(mac)
        _run_cmd(
            ["ip", "neigh", "replace", ip, "lladdr", norm, "dev", iface, "nud", "permanent"],
            check=True,
        )

    def neigh_unpin(self, iface: str, ip: IPv4) -> None:
        _run_cmd(["ip", "neigh", "del", ip, "dev", iface], check=False)

    def probe_gateway(self, net: NetState, count: int, window_ms: int) -> dict[MAC, int]:
        from scapy.config import conf  # type: ignore[import-untyped]

        conf.ipv6_enabled = False
        from scapy.layers.l2 import ARP, Ether  # type: ignore[import-untyped]
        from scapy.sendrecv import AsyncSniffer, sendp  # type: ignore[import-untyped]

        replies: dict[MAC, int] = {}

        def _on_pkt(pkt: Any) -> None:
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                if int(arp.op) == 2 and str(arp.psrc) == net.gw_ip:
                    sha = normalize_mac(str(arp.hwsrc))
                    replies[sha] = replies.get(sha, 0) + 1

        sniffer = AsyncSniffer(
            iface=net.iface,
            filter="arp",
            prn=_on_pkt,
            store=False,
        )
        sniffer.start()
        try:
            # Wait briefly for socket bind
            time.sleep(0.05)
            probe_count = max(1, count)
            interval_s = max(0.05, (window_ms / 1000.0) / probe_count)
            req = Ether(src=net.our_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=1,
                hwsrc=net.our_mac,
                psrc=net.our_ip,
                hwdst="00:00:00:00:00:00",
                pdst=net.gw_ip,
            )
            for i in range(probe_count):
                sendp(req, iface=net.iface, verbose=False)
                if i < probe_count - 1:
                    time.sleep(interval_s)
            time.sleep(max(0.1, interval_s))
        finally:
            try:
                sniffer.stop()
            except Exception:
                pass

        return replies

    def send_arp_reply(
        self, iface: str, src_mac: MAC, src_ip: IPv4, dst_mac: MAC, dst_ip: IPv4
    ) -> None:
        from scapy.config import conf  # type: ignore[import-untyped]

        conf.ipv6_enabled = False
        from scapy.sendrecv import sendp  # type: ignore[import-untyped]

        from sentinelx.healer import build_corrective_arp

        pkt = build_corrective_arp(
            our_mac=src_mac,
            our_ip=src_ip,
            gw_mac=dst_mac,
            gw_ip=dst_ip,
        )
        sendp(pkt, iface=iface, verbose=False)


class DryRunBackend(NetBackend):
    """Dry-run backend: logs mutating calls without modifying kernel or sending frames."""

    def __init__(self, inner: NetBackend | None = None) -> None:
        self._inner = inner
        self.actions_log: list[str] = []
        self._pinned: dict[tuple[str, IPv4], NeighEntry] = {}

    def default_route(self) -> tuple[str, IPv4] | None:
        if self._inner is not None:
            return self._inner.default_route()
        return ("eth0", "10.77.0.1")

    def net_state(self, iface: str, gw_ip: IPv4) -> NetState:
        if self._inner is not None:
            return self._inner.net_state(iface, gw_ip)
        return NetState(
            iface=iface,
            network_id="wired",
            our_ip="10.77.0.10",
            our_mac="02:77:00:00:00:10",
            gw_ip=gw_ip,
        )

    def neigh_get(self, iface: str, ip: IPv4) -> NeighEntry | None:
        if (iface, ip) in self._pinned:
            return self._pinned[(iface, ip)]
        if self._inner is not None:
            return self._inner.neigh_get(iface, ip)
        return None

    def neigh_pin(self, iface: str, ip: IPv4, mac: MAC) -> None:
        norm = normalize_mac(mac)
        msg = f"[DRY-RUN] ip neigh replace {ip} lladdr {norm} dev {iface} nud permanent"
        logger.info(msg)
        self.actions_log.append(msg)
        self._pinned[(iface, ip)] = NeighEntry(ip=ip, mac=norm, state="PERMANENT")

    def neigh_unpin(self, iface: str, ip: IPv4) -> None:
        msg = f"[DRY-RUN] ip neigh del {ip} dev {iface}"
        logger.info(msg)
        self.actions_log.append(msg)
        self._pinned.pop((iface, ip), None)

    def probe_gateway(self, net: NetState, count: int, window_ms: int) -> dict[MAC, int]:
        msg = f"[DRY-RUN] probe_gateway iface={net.iface} gw_ip={net.gw_ip} count={count}"
        logger.info(msg)
        self.actions_log.append(msg)
        if self._inner is not None:
            return self._inner.probe_gateway(net, count, window_ms)
        return {"02:77:00:00:00:01": count}

    def send_arp_reply(
        self, iface: str, src_mac: MAC, src_ip: IPv4, dst_mac: MAC, dst_ip: IPv4
    ) -> None:
        msg = (
            f"[DRY-RUN] send_arp_reply iface={iface} "
            f"src={src_ip}({src_mac}) -> dst={dst_ip}({dst_mac})"
        )
        logger.info(msg)
        self.actions_log.append(msg)


@dataclass
class FakeBackend(NetBackend):
    """Scriptable in-memory NetBackend for unit tests (requires no root or network)."""

    route: tuple[str, IPv4] | None = ("v-victim", "10.77.0.1")
    net: NetState = field(
        default_factory=lambda: NetState(
            iface="v-victim",
            network_id="wired",
            our_ip="10.77.0.10",
            our_mac="02:77:00:00:00:10",
            gw_ip="10.77.0.1",
        )
    )
    probe_replies: dict[MAC, int] = field(
        default_factory=lambda: {"02:77:00:00:00:01": 5}
    )
    neigh_table: dict[tuple[str, IPv4], NeighEntry] = field(default_factory=dict)
    sent_arp_replies: list[dict[str, str]] = field(default_factory=list)
    calls: list[tuple[str, Any]] = field(default_factory=list)
    fail_pin_verification: bool = False

    def default_route(self) -> tuple[str, IPv4] | None:
        self.calls.append(("default_route", ()))
        return self.route

    def net_state(self, iface: str, gw_ip: IPv4) -> NetState:
        self.calls.append(("net_state", (iface, gw_ip)))
        return NetState(
            iface=iface,
            network_id=self.net.network_id,
            our_ip=self.net.our_ip,
            our_mac=self.net.our_mac,
            gw_ip=gw_ip,
        )

    def neigh_get(self, iface: str, ip: IPv4) -> NeighEntry | None:
        self.calls.append(("neigh_get", (iface, ip)))
        return self.neigh_table.get((iface, ip))

    def neigh_pin(self, iface: str, ip: IPv4, mac: MAC) -> None:
        norm = normalize_mac(mac)
        self.calls.append(("neigh_pin", (iface, ip, norm)))
        if self.fail_pin_verification:
            self.neigh_table[(iface, ip)] = NeighEntry(ip=ip, mac=norm, state="REACHABLE")
        else:
            self.neigh_table[(iface, ip)] = NeighEntry(ip=ip, mac=norm, state="PERMANENT")

    def neigh_unpin(self, iface: str, ip: IPv4) -> None:
        self.calls.append(("neigh_unpin", (iface, ip)))
        self.neigh_table.pop((iface, ip), None)

    def probe_gateway(self, net: NetState, count: int, window_ms: int) -> dict[MAC, int]:
        self.calls.append(("probe_gateway", (net.iface, net.gw_ip, count, window_ms)))
        return dict(self.probe_replies)

    def send_arp_reply(
        self, iface: str, src_mac: MAC, src_ip: IPv4, dst_mac: MAC, dst_ip: IPv4
    ) -> None:
        rec = {
            "iface": iface,
            "src_mac": normalize_mac(src_mac),
            "src_ip": src_ip,
            "dst_mac": normalize_mac(dst_mac),
            "dst_ip": dst_ip,
        }
        self.calls.append(("send_arp_reply", rec))
        self.sent_arp_replies.append(rec)
