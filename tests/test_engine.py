# tests/test_engine.py
from __future__ import annotations

import pytest

from sentinelx.engine import Engine
from sentinelx.models import (
    ArpEvent,
    EngineConfig,
    Heal,
    LogRecord,
    NetState,
    Pin,
    RunTofuProbe,
    State,
    Unpin,
)
from sentinelx.trust import MemoryTrustStore, trust_key

GW_IP = "10.77.0.1"
GW_MAC = "02:77:00:00:00:01"
OUR_IP = "10.77.0.10"
OUR_MAC = "02:77:00:00:00:10"
ATT_MAC = "02:77:00:00:00:66"
PEER_IP = "10.77.0.50"
PEER_MAC = "02:77:00:00:00:50"
IFACE = "v-victim"


def make_net(
    iface: str = IFACE,
    network_id: str = "wired",
    our_ip: str = OUR_IP,
    our_mac: str = OUR_MAC,
    gw_ip: str = GW_IP,
) -> NetState:
    return NetState(
        iface=iface,
        network_id=network_id,
        our_ip=our_ip,
        our_mac=our_mac,
        gw_ip=gw_ip,
    )


def make_arp(
    ts: float = 100.0,
    iface: str = IFACE,
    op: int = 2,
    eth_src: str = ATT_MAC,
    arp_sha: str = ATT_MAC,
    arp_spa: str = GW_IP,
    arp_tha: str = OUR_MAC,
    arp_tpa: str = OUR_IP,
) -> ArpEvent:
    return ArpEvent(
        ts=ts,
        iface=iface,
        op=op,
        eth_src=eth_src,
        arp_sha=arp_sha,
        arp_spa=arp_spa,
        arp_tha=arp_tha,
        arp_tpa=arp_tpa,
    )


def setup_monitored_engine(
    pin_mode: str = "always",
    gw_mac: str = GW_MAC,
    extra_allowed: tuple[str, ...] = (),
) -> tuple[Engine, MemoryTrustStore]:
    store = MemoryTrustStore()
    cfg = EngineConfig(
        pin_mode=pin_mode,
        heal_cooldown_ms=1000,
        incident_idle_s=10.0,
        tofu_probes=5,
        tofu_window_ms=1000,
        tofu_max_retries=3,
        extra_allowed_macs=extra_allowed,
    )
    eng = Engine(store, cfg)
    actions = eng.on_net(make_net(), now=10.0)
    assert actions == [RunTofuProbe(net=make_net())]
    assert eng.state == State.TOFU
    tofu_actions = eng.on_tofu_result({gw_mac: 5}, now=11.0)
    if pin_mode == "always":
        assert Pin(iface=IFACE, gw_ip=GW_IP, gw_mac=gw_mac.lower()) in tofu_actions
    else:
        assert not any(isinstance(a, Pin) for a in tofu_actions)
    assert eng.state == State.MONITOR
    return eng, store


def test_initial_state_is_waiting_net() -> None:
    eng = Engine(MemoryTrustStore(), EngineConfig())
    assert eng.state == State.WAITING_NET
    assert eng.on_net(None, now=1.0) == []


def test_tofu_single_mac_learns_and_pins() -> None:
    eng, store = setup_monitored_engine(pin_mode="always")
    entry = store.get(trust_key(IFACE, "wired", GW_IP))
    assert entry is not None
    assert entry["gw_mac"] == GW_MAC
    assert entry["virtual_gateway"] is False
    assert eng.pinned is True


def test_tofu_on_detect_mode_does_not_pin_at_tofu() -> None:
    eng, _ = setup_monitored_engine(pin_mode="on_detect")
    assert eng.state == State.MONITOR
    assert eng.pinned is False


def test_tofu_known_gateway_skips_probe_and_pins_immediately() -> None:
    store = MemoryTrustStore()
    key = trust_key(IFACE, "wired", GW_IP)
    store.put(key, {"gw_mac": GW_MAC, "allowed_macs": [], "learned_at": 1.0})
    eng = Engine(store, EngineConfig(pin_mode="always"))
    actions = eng.on_net(make_net(), now=5.0)
    assert eng.state == State.MONITOR
    assert actions == [Pin(iface=IFACE, gw_ip=GW_IP, gw_mac=GW_MAC)]


def test_tofu_zero_replies_retries_3x_then_unprotected() -> None:
    store = MemoryTrustStore()
    eng = Engine(store, EngineConfig(tofu_max_retries=3))
    eng.on_net(make_net(), now=1.0)
    # 1st empty reply -> retry 1
    a1 = eng.on_tofu_result({}, now=2.0)
    assert a1 == [RunTofuProbe(net=make_net())]
    assert eng.state == State.TOFU
    # 2nd empty reply -> retry 2
    a2 = eng.on_tofu_result({}, now=3.0)
    assert a2 == [RunTofuProbe(net=make_net())]
    assert eng.state == State.TOFU
    # 3rd empty reply -> UNPROTECTED
    a3 = eng.on_tofu_result({}, now=4.0)
    assert eng.state == State.UNPROTECTED
    assert eng.pinned is False
    assert len(a3) == 1 and isinstance(a3[0], LogRecord)
    assert a3[0].type == "tofu_unprotected"


def test_tofu_multiple_macs_enters_conflict_and_does_not_pin() -> None:
    store = MemoryTrustStore()
    eng = Engine(store, EngineConfig())
    eng.on_net(make_net(), now=1.0)
    actions = eng.on_tofu_result({GW_MAC: 3, ATT_MAC: 2}, now=2.0)
    assert eng.state == State.CONFLICT
    assert eng.pinned is False
    assert not any(isinstance(a, Pin) for a in actions)
    assert len(actions) == 1 and isinstance(actions[0], LogRecord)
    assert actions[0].type == "tofu_conflict"
    assert actions[0].data["candidates"] == {GW_MAC: 3, ATT_MAC: 2}


def test_tofu_virtual_mac_sets_virtual_gateway_flag() -> None:
    eng, store = setup_monitored_engine(gw_mac="00:00:5E:00:01:01")
    entry = store.get(trust_key(IFACE, "wired", GW_IP))
    assert entry is not None
    assert entry["virtual_gateway"] is True


def test_detect_and_heal_on_spoofed_gateway_packet() -> None:
    eng, _ = setup_monitored_engine()
    ev = make_arp(ts=50.0, op=2, eth_src=ATT_MAC, arp_sha=ATT_MAC, arp_spa=GW_IP)
    actions = eng.on_arp(ev, now=50.0)
    assert len(actions) == 2
    log_act, heal_act = actions[0], actions[1]
    assert isinstance(log_act, LogRecord) and log_act.type == "detect"
    assert log_act.data["kind"] == "gateway_mac_mismatch"
    assert log_act.data["expected_mac"] == GW_MAC
    assert log_act.data["observed_mac"] == ATT_MAC
    assert log_act.data["eth_src_mismatch"] is False
    assert isinstance(heal_act, Heal)
    assert heal_act.gw_mac == GW_MAC
    assert heal_act.send_corrective is True
    assert eng.under_attack is True
    assert eng.incidents_total == 1


def test_eth_src_mismatch_enrichment_recorded() -> None:
    eng, _ = setup_monitored_engine()
    ev = make_arp(
        ts=50.0,
        op=2,
        eth_src="de:ad:be:ef:00:01",
        arp_sha=ATT_MAC,
        arp_spa=GW_IP,
    )
    actions = eng.on_arp(ev, now=50.0)
    assert isinstance(actions[0], LogRecord)
    assert actions[0].data["eth_src_mismatch"] is True


def test_incident_aggregation_and_heal_cooldown() -> None:
    eng, _ = setup_monitored_engine()
    ev = make_arp(ts=100.0, arp_sha=ATT_MAC, arp_spa=GW_IP)

    # First packet triggers detect + heal
    a1 = eng.on_arp(ev, now=100.0)
    assert len(a1) == 2

    # Second packet 200ms later (inside 1000ms cooldown) -> aggregated, no actions
    a2 = eng.on_arp(ev, now=100.2)
    assert a2 == []

    # Third packet 500ms later -> still inside cooldown
    a3 = eng.on_arp(ev, now=100.5)
    assert a3 == []

    # Fourth packet at 101.1s (>= 1000ms since last heal) -> Heal only, no new detect log
    a4 = eng.on_arp(ev, now=101.1)
    assert len(a4) == 1
    assert isinstance(a4[0], Heal)

    # Idle tick at 105.0s (< 10s since 101.1s) -> not closed yet
    assert eng.on_tick(now=105.0) == []

    # Idle tick at 111.2s (>= 10s since 101.1s) -> incident_close with 4 packets, 2 heals
    close_actions = eng.on_tick(now=111.2)
    assert len(close_actions) == 1
    close_log = close_actions[0]
    assert isinstance(close_log, LogRecord) and close_log.type == "incident_close"
    assert close_log.data["packets"] == 4
    assert close_log.data["heals"] == 2
    assert close_log.data["observed_mac"] == ATT_MAC
    assert eng.under_attack is False


def test_network_change_unpins_old_gateway_and_restarts_tofu() -> None:
    eng, _ = setup_monitored_engine()
    new_net = make_net(iface="wlan0", network_id="CafeWiFi", gw_ip="192.168.1.1")
    actions = eng.on_net(new_net, now=200.0)
    assert Unpin(iface=IFACE, gw_ip=GW_IP) in actions
    assert any(isinstance(a, LogRecord) and a.type == "network_changed" for a in actions)
    assert RunTofuProbe(net=new_net) in actions
    assert eng.state == State.TOFU


def test_route_loss_unpins_and_waits() -> None:
    eng, _ = setup_monitored_engine()
    actions = eng.on_net(None, now=200.0)
    assert Unpin(iface=IFACE, gw_ip=GW_IP) in actions
    assert eng.state == State.WAITING_NET
    assert eng.pinned is False


def test_dhcp_renew_same_network_is_noop() -> None:
    eng, _ = setup_monitored_engine()
    renewed_net = make_net(our_ip="10.77.0.99")
    actions = eng.on_net(renewed_net, now=200.0)
    assert actions == []
    assert eng.state == State.MONITOR
    assert eng.net is not None and eng.net.our_ip == "10.77.0.99"


# ---- Table-driven packet scenarios (≥ 25 cases for ≥ 38 total tests in test_engine.py) ----
@pytest.mark.parametrize(
    ("desc", "op", "eth_src", "arp_sha", "arp_spa", "arp_tha", "arp_tpa", "v_gw", "should_alert"),
    [
        # Legitimate gateway traffic (must NOT alert)
        ("gw_legit_reply", 2, GW_MAC, GW_MAC, GW_IP, OUR_MAC, OUR_IP, False, False),
        ("gw_legit_request", 1, GW_MAC, GW_MAC, GW_IP, "00:00:00:00:00:00", OUR_IP, False, False),
        ("gw_legit_garp_reply", 2, GW_MAC, GW_MAC, GW_IP, "ff:ff:ff:ff:ff:ff", GW_IP, False, False),
        ("gw_legit_garp_req", 1, GW_MAC, GW_MAC, GW_IP, "00:00:00:00:00:00", GW_IP, False, False),
        ("gw_legit_uppercase_mac", 2, GW_MAC.upper(), GW_MAC.upper(), GW_IP, OUR_MAC, OUR_IP, False, False),
        # Other LAN peers (must NOT alert)
        ("peer_arp_req_for_gw", 1, PEER_MAC, PEER_MAC, PEER_IP, "00:00:00:00:00:00", GW_IP, False, False),
        ("peer_arp_reply_to_us", 2, PEER_MAC, PEER_MAC, PEER_IP, OUR_MAC, OUR_IP, False, False),
        ("peer_garp", 2, PEER_MAC, PEER_MAC, PEER_IP, "ff:ff:ff:ff:ff:ff", PEER_IP, False, False),
        ("att_mac_claiming_own_ip", 2, ATT_MAC, ATT_MAC, "10.77.0.66", OUR_MAC, OUR_IP, False, False),
        # RFC 5227 ARP probes (spa = 0.0.0.0) (must NOT alert)
        ("arp_probe_for_gw_ip", 1, PEER_MAC, PEER_MAC, "0.0.0.0", "00:00:00:00:00:00", GW_IP, False, False),
        ("arp_probe_for_peer_ip", 1, ATT_MAC, ATT_MAC, "0.0.0.0", "00:00:00:00:00:00", PEER_IP, False, False),
        # Our own packets (must NOT alert)
        ("our_own_arp_req", 1, OUR_MAC, OUR_MAC, OUR_IP, "00:00:00:00:00:00", GW_IP, False, False),
        ("our_own_arp_with_gw_ip", 2, OUR_MAC, OUR_MAC, GW_IP, GW_MAC, GW_IP, False, False),
        # VRRP/HSRP virtual gateway cases
        (
            "vrrp_failover_on_virtual_gw",
            2,
            "00:00:5e:00:01:02",
            "00:00:5e:00:01:02",
            GW_IP,
            OUR_MAC,
            OUR_IP,
            True,
            False,
        ),
        ("hsrp_v1_on_virtual_gw", 2, "00:00:0c:07:ac:01", "00:00:0c:07:ac:01", GW_IP, OUR_MAC, OUR_IP, True, False),
        ("hsrp_v2_on_virtual_gw", 2, "00:00:0c:9f:f0:05", "00:00:0c:9f:f0:05", GW_IP, OUR_MAC, OUR_IP, True, False),
        # Spoofed gateway claims (MUST alert)
        ("spoof_is_at_unicast", 2, ATT_MAC, ATT_MAC, GW_IP, OUR_MAC, OUR_IP, False, True),
        ("spoof_who_has_request", 1, ATT_MAC, ATT_MAC, GW_IP, "00:00:00:00:00:00", OUR_IP, False, True),
        ("spoof_garp_broadcast", 2, ATT_MAC, ATT_MAC, GW_IP, "ff:ff:ff:ff:ff:ff", GW_IP, False, True),
        ("spoof_uppercase_att_mac", 2, ATT_MAC.upper(), ATT_MAC.upper(), GW_IP, OUR_MAC, OUR_IP, False, True),
        ("spoof_eth_src_pretending_gw", 2, GW_MAC, ATT_MAC, GW_IP, OUR_MAC, OUR_IP, False, True),
        ("spoof_near_miss_mac", 2, "02:77:00:00:00:02", "02:77:00:00:00:02", GW_IP, OUR_MAC, OUR_IP, False, True),
        (
            "spoof_vrrp_mac_on_non_virtual_gw",
            2,
            "00:00:5e:00:01:01",
            "00:00:5e:00:01:01",
            GW_IP,
            OUR_MAC,
            OUR_IP,
            False,
            True,
        ),
        (
            "spoof_hsrp_mac_on_non_virtual_gw",
            2,
            "00:00:0c:07:ac:01",
            "00:00:0c:07:ac:01",
            GW_IP,
            OUR_MAC,
            OUR_IP,
            False,
            True,
        ),
        ("spoof_non_vmac_on_virtual_gw", 2, ATT_MAC, ATT_MAC, GW_IP, OUR_MAC, OUR_IP, True, True),
    ],
)
def test_table_driven_r1_detection(
    desc: str,
    op: int,
    eth_src: str,
    arp_sha: str,
    arp_spa: str,
    arp_tha: str,
    arp_tpa: str,
    v_gw: bool,
    should_alert: bool,
) -> None:
    initial_gw_mac = "00:00:5e:00:01:01" if v_gw else GW_MAC
    eng, _ = setup_monitored_engine(gw_mac=initial_gw_mac)
    ev = make_arp(
        ts=20.0,
        op=op,
        eth_src=eth_src,
        arp_sha=arp_sha,
        arp_spa=arp_spa,
        arp_tha=arp_tha,
        arp_tpa=arp_tpa,
    )
    actions = eng.on_arp(ev, now=20.0)
    if should_alert:
        assert any(isinstance(a, Heal) for a in actions), f"Expected alert for {desc}"
        assert any(
            isinstance(a, LogRecord) and a.type == "detect" for a in actions
        ), f"Expected detect log for {desc}"
    else:
        assert actions == [], f"Expected no alert for {desc}, got {actions}"
