# tests/test_daemon_fake.py
from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

from sentinelx.chainlog import ChainLog
from sentinelx.config import AppConfig
from sentinelx.daemon import Daemon, is_host_netns
from sentinelx.models import ArpEvent, NeighEntry
from sentinelx.netctl import FakeBackend


def test_daemon_fake_backend_full_lifecycle(tmp_path: Path) -> None:
    """With FakeBackend + synthetic events, daemon logs tofu_learned -> detect -> heal -> incident_close."""
    current_time = 1000.0

    def fake_now() -> float:
        return current_time

    cfg = AppConfig()
    cfg = replace(
        cfg,
        core=replace(cfg.core, iface="v-victim", state_dir=tmp_path, unpin_on_exit=True),
        detect=replace(cfg.detect, heal_cooldown_ms=1000, incident_idle_s=10.0),
    )

    fake_backend = FakeBackend()
    daemon = Daemon(
        cfg=cfg,
        backend=fake_backend,
        now_fn=fake_now,
        enable_live_sniffer=False,
    )

    async def _scenario() -> None:
        nonlocal current_time
        daemon.chainlog.append("daemon_start", {"iface": "v-victim"})

        # 1. Poll network -> triggers TOFU -> pins gateway (02:77:00:00:00:01)
        await daemon.netwatcher.poll_once()
        assert daemon.engine.state.value == "monitor"
        assert daemon.engine.pinned is True
        assert fake_backend.neigh_get("v-victim", "10.77.0.1") == NeighEntry(
            ip="10.77.0.1", mac="02:77:00:00:00:01", state="PERMANENT"
        )

        # 2. Feed spoofed ARP reply claiming gateway IP from attacker MAC
        current_time = 1005.0
        spoof_ev = ArpEvent(
            ts=1004.980,
            iface="v-victim",
            op=2,
            eth_src="02:77:00:00:00:66",
            arp_sha="02:77:00:00:00:66",
            arp_spa="10.77.0.1",
            arp_tha="02:77:00:00:00:10",
            arp_tpa="10.77.0.10",
        )
        await daemon.process_arp_event(spoof_ev)
        assert daemon.engine.under_attack is True
        assert len(fake_backend.sent_arp_replies) == 1

        # Status file reflects under_attack=True
        status_data = json.loads((tmp_path / "status.json").read_text(encoding="utf-8"))
        assert status_data["under_attack"] is True
        assert status_data["incidents_total"] == 1

        # 3. Advance past incident_idle_s (10s) and tick -> closes incident
        current_time = 1016.0
        await daemon.tick_once()
        assert daemon.engine.under_attack is False

        # 4. Shutdown -> unpins gateway and writes daemon_stop
        await daemon.shutdown(reason="SIGTERM")
        assert fake_backend.neigh_get("v-victim", "10.77.0.1") is None

    asyncio.run(_scenario())

    log_path = tmp_path / "log.jsonl"
    verify_res = ChainLog.verify(log_path)
    assert verify_res.ok is True

    entries = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    types = [e["type"] for e in entries]
    assert types == [
        "genesis",
        "daemon_start",
        "tofu_learned",
        "detect",
        "heal",
        "incident_close",
        "daemon_stop",
    ]
    heal_entry = next(e for e in entries if e["type"] == "heal")
    assert heal_entry["data"]["verified"] is True
    assert heal_entry["data"]["corrective_sent"] is True


def test_r2_host_namespace_safety_guard_blocks_without_flag(tmp_path: Path) -> None:
    """R2 safety guard: `sentinelx run` must refuse to start in the host network namespace."""
    assert is_host_netns() is True
    proc = subprocess.run(
        [sys.executable, "-m", "sentinelx", "run", "--state-dir", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "Refusing to start in the host network namespace" in proc.stderr


def test_r2_safety_guard_unit_comparison(tmp_path: Path) -> None:
    f1 = tmp_path / "ns1"
    f2 = tmp_path / "ns2"
    f1.write_text("a")
    f2.write_text("b")
    assert is_host_netns(str(f1), str(f1)) is True
    assert is_host_netns(str(f1), str(f2)) is False


def test_cli_verify_log_exit_codes(tmp_path: Path) -> None:
    log_path = tmp_path / "log.jsonl"
    cl = ChainLog(log_path)
    cl.append("daemon_start", {"iface": "v-victim"})
    cl.append("tofu_learned", {"gw_ip": "10.77.0.1", "gw_mac": "02:77:00:00:00:01"})

    # Valid log -> exit 0
    p_ok = subprocess.run(
        [sys.executable, "-m", "sentinelx", "verify-log", "--path", str(log_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert p_ok.returncode == 0
    assert "OK:" in p_ok.stdout

    # Change 1 byte in entry idx 2 -> exit 1 and print bad_idx=2
    lines = log_path.read_text(encoding="utf-8").splitlines()
    lines[2] = lines[2].replace("02:77:00:00:00:01", "02:77:00:00:00:09")
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    p_bad = subprocess.run(
        [sys.executable, "-m", "sentinelx", "verify-log", "--path", str(log_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert p_bad.returncode == 1
    assert "bad_idx=2" in p_bad.stdout


def test_cli_status_and_trust_commands(tmp_path: Path) -> None:
    status_file = tmp_path / "status.json"
    status_file.write_text(
        json.dumps(
            {
                "state": "monitor",
                "iface": "v-victim",
                "network_id": "wired",
                "gw_ip": "10.77.0.1",
                "gw_mac": "02:77:00:00:00:01",
                "pinned": True,
                "under_attack": False,
                "incidents_total": 0,
                "last_incident_ts": None,
                "chain_head": "a" * 64,
                "dropped_events": 0,
                "updated": "2026-10-25T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    p_stat = subprocess.run(
        [sys.executable, "-m", "sentinelx", "status", "--state-dir", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert p_stat.returncode == 0
    assert "10.77.0.1" in p_stat.stdout

    p_trust = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinelx",
            "trust",
            "--state-dir",
            str(tmp_path),
            "--key",
            "v-victim|wired|10.77.0.1",
            "--add-mac",
            "02:77:00:00:00:02",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert p_trust.returncode == 0


def test_sigterm_stop_through_run_lifecycle_writes_daemon_stop(tmp_path: Path) -> None:
    """Regression: SIGTERM must produce exactly one daemon_stop entry via run()'s teardown.

    The signal handler only requests a stop (_request_stop); run()'s finally block
    owns shutdown(), so the unpin + daemon_stop entry are written synchronously
    before the event loop closes (see git history for the detached-task race).
    """
    cfg = AppConfig()
    cfg = replace(
        cfg,
        core=replace(cfg.core, iface="v-victim", state_dir=tmp_path, unpin_on_exit=True),
    )
    fake_backend = FakeBackend()
    daemon = Daemon(cfg=cfg, backend=fake_backend, enable_live_sniffer=False)

    async def _scenario() -> None:
        task = asyncio.create_task(daemon.run())
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 5.0
        while not daemon.engine.pinned:
            if loop.time() > deadline:
                raise TimeoutError("Daemon did not pin the gateway within 5s")
            await asyncio.sleep(0.01)
        daemon._request_stop("SIGTERM")
        await asyncio.wait_for(task, timeout=5.0)

    asyncio.run(_scenario())

    entries = [
        json.loads(line)
        for line in (tmp_path / "log.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    stops = [e for e in entries if e["type"] == "daemon_stop"]
    assert len(stops) == 1
    assert stops[0]["data"]["reason"] == "SIGTERM"
    assert stops[0]["data"]["unpinned"] is True
    assert fake_backend.neigh_get("v-victim", "10.77.0.1") is None
    assert ChainLog.verify(tmp_path / "log.jsonl").ok is True
