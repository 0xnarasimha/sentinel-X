# tests/test_models_config.py
from __future__ import annotations

from pathlib import Path

import pytest

from sentinelx.config import AppConfig
from sentinelx.models import (
    ArpEvent,
    EngineConfig,
    Heal,
    LogRecord,
    NeighEntry,
    NetState,
    Pin,
    RunTofuProbe,
    State,
    Unpin,
    VerifyResult,
)


def test_arp_event_frozen_and_slots() -> None:
    ev = ArpEvent(
        ts=1700000000.5,
        iface="v-victim",
        op=2,
        eth_src="02:77:00:00:00:01",
        arp_sha="02:77:00:00:00:01",
        arp_spa="10.77.0.1",
        arp_tha="02:77:00:00:00:10",
        arp_tpa="10.77.0.10",
    )
    assert ev.op == 2
    assert ev.arp_spa == "10.77.0.1"
    with pytest.raises(Exception):
        ev.op = 1  # type: ignore[misc]


def test_net_state_and_states_enum() -> None:
    net = NetState(
        iface="v-victim",
        network_id="wired",
        our_ip="10.77.0.10",
        our_mac="02:77:00:00:00:10",
        gw_ip="10.77.0.1",
    )
    assert net.network_id == "wired"
    assert State.WAITING_NET.value == "waiting_net"
    assert State.TOFU.value == "tofu"
    assert State.MONITOR.value == "monitor"
    assert State.CONFLICT.value == "conflict"
    assert State.UNPROTECTED.value == "unprotected"


def test_actions_and_neigh_entry_dataclasses() -> None:
    net = NetState("v-victim", "wired", "10.77.0.10", "02:77:00:00:00:10", "10.77.0.1")
    probe = RunTofuProbe(net=net)
    pin = Pin(iface="v-victim", gw_ip="10.77.0.1", gw_mac="02:77:00:00:00:01")
    unpin = Unpin(iface="v-victim", gw_ip="10.77.0.1")
    heal = Heal(net=net, gw_mac="02:77:00:00:00:01", send_corrective=True, reason="mismatch")
    log = LogRecord(type="detect", data={"gw_ip": "10.77.0.1"})
    neigh = NeighEntry(ip="10.77.0.1", mac="02:77:00:00:00:01", state="PERMANENT")
    vr = VerifyResult(ok=True, entries=4, bad_idx=None, reason=None, head="a" * 64)

    assert probe.net.gw_ip == "10.77.0.1"
    assert pin.gw_mac == "02:77:00:00:00:01"
    assert unpin.iface == "v-victim"
    assert heal.send_corrective is True
    assert log.type == "detect"
    assert neigh.state == "PERMANENT"
    assert vr.ok is True


def test_load_example_config_toml() -> None:
    cfg = AppConfig.load(Path("config.example.toml"))
    assert cfg.core.iface == "auto"
    assert cfg.core.state_dir == Path("/var/lib/sentinelx")
    assert cfg.core.pin_mode == "always"
    assert cfg.core.unpin_on_exit is True
    assert cfg.core.dry_run is False
    assert cfg.detect.heal_cooldown_ms == 1000
    assert cfg.detect.incident_idle_s == 10.0
    assert cfg.detect.tofu_probes == 5
    assert cfg.detect.tofu_window_ms == 1000
    assert cfg.detect.queue_max == 1000
    assert cfg.whitelist.allowed_macs == ()
    assert cfg.llm.enabled is False
    assert cfg.llm.provider == "ollama"


def test_custom_config_and_to_engine_config(tmp_path: Path) -> None:
    toml_file = tmp_path / "custom.toml"
    toml_file.write_text(
        """
[core]
iface = "v-victim"
state_dir = "/tmp/sx"
pin_mode = "on_detect"
unpin_on_exit = false
dry_run = true

[detect]
heal_cooldown_ms = 500
incident_idle_s = 5
tofu_probes = 3
tofu_window_ms = 600
queue_max = 250

[whitelist]
allowed_macs = ["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"]
""",
        encoding="utf-8",
    )
    cfg = AppConfig.load(toml_file)
    eng_cfg: EngineConfig = cfg.to_engine_config()
    assert eng_cfg.pin_mode == "on_detect"
    assert eng_cfg.heal_cooldown_ms == 500
    assert eng_cfg.incident_idle_s == 5.0
    assert eng_cfg.tofu_probes == 3
    assert eng_cfg.extra_allowed_macs == ("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66")


def test_missing_config_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        AppConfig.load(tmp_path / "nonexistent.toml")
