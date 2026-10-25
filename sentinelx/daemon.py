# sentinelx/daemon.py
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinelx.chainlog import ChainLog
from sentinelx.config import AppConfig
from sentinelx.engine import Engine
from sentinelx.healer import execute_heal
from sentinelx.models import (
    Action,
    ArpEvent,
    Heal,
    LogRecord,
    NetBackend,
    NetState,
    Pin,
    RunTofuProbe,
    TrustStore,
    Unpin,
)
from sentinelx.netwatch import NetWatcher
from sentinelx.sniffer import Sniffer
from sentinelx.trust import JsonTrustStore

logger = logging.getLogger(__name__)


def is_host_netns(
    self_ns_path: str = "/proc/self/ns/net",
    init_ns_path: str = "/proc/1/ns/net",
) -> bool:
    """R2 safety guard check: returns True if current process shares network namespace with PID 1."""
    try:
        s_self = os.stat(self_ns_path)
        s_init = os.stat(init_ns_path)
        return (s_self.st_dev, s_self.st_ino) == (s_init.st_dev, s_init.st_ino)
    except OSError:
        # Fallback if /proc/1/ns/net is unreadable: remain conservative
        return True


class Daemon:
    """Asyncio Executor wiring Sniffer, NetWatcher, pure Engine, NetBackend, and ChainLog (§3 & §6.11)."""

    def __init__(
        self,
        cfg: AppConfig,
        backend: NetBackend,
        trust: TrustStore | None = None,
        chainlog: ChainLog | None = None,
        now_fn: Callable[[], float] = time.time,
        enable_live_sniffer: bool = True,
    ) -> None:
        self.cfg = cfg
        self.backend = backend
        self.state_dir = Path(cfg.core.state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)

        self.trust: TrustStore = trust or JsonTrustStore(self.state_dir / "state.json")
        self.chainlog: ChainLog = chainlog or ChainLog(self.state_dir / "log.jsonl")
        self.engine = Engine(self.trust, cfg.to_engine_config())
        self.now_fn = now_fn
        self.enable_live_sniffer = enable_live_sniffer

        self.queue: asyncio.Queue[ArpEvent] = asyncio.Queue(
            maxsize=max(1, cfg.detect.queue_max)
        )
        self.sniffer: Sniffer | None = None
        self.netwatcher = NetWatcher(
            backend=self.backend,
            on_update=self.on_net_update,
            iface_override=cfg.core.iface,
            interval_s=2.0,
        )
        self._stop_event = asyncio.Event()
        self._extra_dropped: int = 0

    @property
    def dropped_events(self) -> int:
        s_drop = self.sniffer.dropped_events if self.sniffer is not None else 0
        return s_drop + self._extra_dropped

    async def handle_actions(self, actions: list[Action]) -> None:
        for a in actions:
            match a:
                case RunTofuProbe(net=net):
                    replies = await asyncio.to_thread(
                        self.backend.probe_gateway,
                        net,
                        self.cfg.detect.tofu_probes,
                        self.cfg.detect.tofu_window_ms,
                    )
                    follow_up = self.engine.on_tofu_result(replies, self.now_fn())
                    await self.handle_actions(follow_up)
                case Pin(iface=iface, gw_ip=gw_ip, gw_mac=gw_mac):
                    await asyncio.to_thread(self.backend.neigh_pin, iface, gw_ip, gw_mac)
                case Unpin(iface=iface, gw_ip=gw_ip):
                    await asyncio.to_thread(self.backend.neigh_unpin, iface, gw_ip)
                case Heal() as heal_act:
                    first_pkt_ts = self.engine.active_incident_first_pkt_ts()
                    heal_data = await asyncio.to_thread(
                        execute_heal,
                        self.backend,
                        heal_act,
                        first_pkt_ts,
                        self.now_fn(),
                    )
                    self.chainlog.append("heal", heal_data)
                case LogRecord(type=rec_type, data=rec_data):
                    payload = dict(rec_data)
                    if rec_type == "incident_close":
                        payload["dropped_events"] = self.dropped_events
                    self.chainlog.append(rec_type, payload)

        self.write_status()

    async def on_net_update(self, net: NetState | None) -> None:
        actions = self.engine.on_net(net, self.now_fn())
        if actions:
            await self.handle_actions(actions)
        if net is not None and self.enable_live_sniffer:
            self._ensure_sniffer(net.iface)
        self.write_status()

    def _ensure_sniffer(self, iface: str) -> None:
        if self.sniffer is not None and self.sniffer.iface == iface:
            return
        if self.sniffer is not None:
            self.sniffer.stop()
        loop = asyncio.get_running_loop()
        self.sniffer = Sniffer(iface=iface, queue=self.queue, loop=loop)
        try:
            self.sniffer.start()
        except Exception as exc:
            logger.warning("Failed to start live Scapy sniffer on %s: %s", iface, exc)

    async def process_arp_event(self, ev: ArpEvent) -> None:
        actions = self.engine.on_arp(ev, self.now_fn())
        if actions:
            await self.handle_actions(actions)

    async def tick_once(self) -> None:
        actions = self.engine.on_tick(self.now_fn())
        if actions:
            await self.handle_actions(actions)
        self.write_status()

    def build_status_dict(self) -> dict[str, Any]:
        net = self.engine.net
        return {
            "state": self.engine.state.value,
            "iface": net.iface if net else (
                self.cfg.core.iface if self.cfg.core.iface != "auto" else None
            ),
            "network_id": net.network_id if net else None,
            "gw_ip": net.gw_ip if net else None,
            "gw_mac": self.engine.gw_mac,
            "pin_mode": self.cfg.core.pin_mode,
            "pinned": self.engine.pinned,
            "under_attack": self.engine.under_attack,
            "incidents_total": self.engine.incidents_total,
            "last_incident_ts": self.engine.last_incident_ts,
            "chain_head": self.chainlog.head(),
            "dropped_events": self.dropped_events,
            "updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        }

    def write_status(self) -> dict[str, Any]:
        status = self.build_status_dict()
        status_path = self.state_dir / "status.json"
        tmp_path = status_path.with_suffix(".json.tmp")
        payload = json.dumps(status, indent=2, sort_keys=True) + "\n"
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, status_path)
        return status

    async def _queue_consumer_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                ev = await asyncio.wait_for(self.queue.get(), timeout=0.25)
            except asyncio.TimeoutError:
                continue
            await self.process_arp_event(ev)
            self.queue.task_done()

    async def _tick_loop(self) -> None:
        while not self._stop_event.is_set():
            await self.tick_once()
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                pass

    async def shutdown(self, reason: str = "signal") -> None:
        if self._stop_event.is_set():
            return
        self._stop_event.set()
        self.netwatcher.stop()
        if self.sniffer is not None:
            self.sniffer.stop()

        net = self.engine.net
        unpinned = False
        if self.cfg.core.unpin_on_exit and net is not None and self.engine.pinned:
            try:
                await asyncio.to_thread(self.backend.neigh_unpin, net.iface, net.gw_ip)
                unpinned = True
            except Exception as exc:
                logger.warning("Failed to unpin on exit: %s", exc)

        self.chainlog.append(
            "daemon_stop",
            {
                "reason": reason,
                "iface": net.iface if net else None,
                "gw_ip": net.gw_ip if net else None,
                "unpinned": unpinned,
            },
        )
        self.write_status()

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(
                    sig,
                    lambda s=sig: asyncio.create_task(self.shutdown(reason=s.name)),
                )
            except NotImplementedError:  # pragma: no cover
                pass

        self.chainlog.append(
            "daemon_start",
            {
                "iface": self.cfg.core.iface,
                "pin_mode": self.cfg.core.pin_mode,
                "dry_run": self.cfg.core.dry_run,
            },
        )
        self.write_status()

        # Perform initial poll immediately so TOFU completes right at startup
        await self.netwatcher.poll_once()

        tasks = [
            asyncio.create_task(self._queue_consumer_loop()),
            asyncio.create_task(self._tick_loop()),
            asyncio.create_task(self.netwatcher.run()),
        ]
        try:
            await self._stop_event.wait()
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exception=True) if False else None
            for t in tasks:
                try:
                    await t
                except asyncio.CancelledError:
                    pass
                except Exception:
                    pass
            await self.shutdown(reason="exit")
