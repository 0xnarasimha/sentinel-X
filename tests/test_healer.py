# tests/test_healer.py
from __future__ import annotations

from scapy.layers.l2 import ARP, Ether  # type: ignore[import-untyped]

from sentinelx.healer import build_corrective_arp, execute_heal, verify_pinned_entry
from sentinelx.models import Heal, NeighEntry, NetState
from sentinelx.netctl import DryRunBackend, FakeBackend


def make_net() -> NetState:
    return NetState(
        iface="v-victim",
        network_id="wired",
        our_ip="10.77.0.10",
        our_mac="02:77:00:00:00:10",
        gw_ip="10.77.0.1",
    )


def test_build_corrective_arp_matches_spec_exact() -> None:
    pkt = build_corrective_arp(
        our_mac="02:77:00:00:00:10",
        our_ip="10.77.0.10",
        gw_mac="02:77:00:00:00:01",
        gw_ip="10.77.0.1",
    )
    assert pkt.haslayer(Ether)
    assert pkt.haslayer(ARP)
    assert pkt[Ether].src == "02:77:00:00:00:10"
    assert pkt[Ether].dst == "02:77:00:00:00:01"
    assert pkt[ARP].op == 2
    assert pkt[ARP].hwsrc == "02:77:00:00:00:10"
    assert pkt[ARP].psrc == "10.77.0.10"
    assert pkt[ARP].hwdst == "02:77:00:00:00:01"
    assert pkt[ARP].pdst == "10.77.0.1"


def test_execute_heal_pins_verifies_and_sends_corrective() -> None:
    fake = FakeBackend()
    net = make_net()
    # Pre-poison fake neighbour table with attacker MAC
    fake.neigh_table[("v-victim", "10.77.0.1")] = NeighEntry(
        ip="10.77.0.1", mac="02:77:00:00:00:66", state="REACHABLE"
    )
    heal_act = Heal(
        net=net,
        gw_mac="02:77:00:00:00:01",
        send_corrective=True,
        reason="gateway_mac_mismatch",
    )
    result = execute_heal(fake, heal_act, first_pkt_ts=100.0, now=100.042)

    assert result["verified"] is True
    assert result["pinned_mac"] == "02:77:00:00:00:01"
    assert result["corrective_sent"] is True
    assert result["latency_ms_from_first_pkt"] == 42.0
    assert fake.neigh_get("v-victim", "10.77.0.1") == NeighEntry(
        ip="10.77.0.1", mac="02:77:00:00:00:01", state="PERMANENT"
    )
    assert len(fake.sent_arp_replies) == 1
    assert fake.sent_arp_replies[0] == {
        "iface": "v-victim",
        "src_mac": "02:77:00:00:00:10",
        "src_ip": "10.77.0.10",
        "dst_mac": "02:77:00:00:00:01",
        "dst_ip": "10.77.0.1",
    }


def test_execute_heal_detects_failed_verification() -> None:
    fake = FakeBackend(fail_pin_verification=True)
    heal_act = Heal(
        net=make_net(),
        gw_mac="02:77:00:00:00:01",
        send_corrective=False,
        reason="gateway_mac_mismatch",
    )
    result = execute_heal(fake, heal_act, first_pkt_ts=50.0, now=50.01)
    assert result["verified"] is False
    assert result["corrective_sent"] is False
    assert len(fake.sent_arp_replies) == 0


def test_verify_pinned_entry_checks_mac_and_permanent_state() -> None:
    fake = FakeBackend()
    assert verify_pinned_entry(fake, "v-victim", "10.77.0.1", "02:77:00:00:00:01") is False

    fake.neigh_table[("v-victim", "10.77.0.1")] = NeighEntry(
        ip="10.77.0.1", mac="02:77:00:00:00:66", state="PERMANENT"
    )
    assert verify_pinned_entry(fake, "v-victim", "10.77.0.1", "02:77:00:00:00:01") is False

    fake.neigh_table[("v-victim", "10.77.0.1")] = NeighEntry(
        ip="10.77.0.1", mac="02:77:00:00:00:01", state="STALE"
    )
    assert verify_pinned_entry(fake, "v-victim", "10.77.0.1", "02:77:00:00:00:01") is False

    fake.neigh_pin("v-victim", "10.77.0.1", "02:77:00:00:00:01")
    assert verify_pinned_entry(fake, "v-victim", "10.77.0.1", "02:77:00:00:00:01") is True


def test_dry_run_backend_records_actions_without_side_effects() -> None:
    dry = DryRunBackend()
    heal_act = Heal(
        net=make_net(),
        gw_mac="02:77:00:00:00:01",
        send_corrective=True,
        reason="test_dry_run",
    )
    res = execute_heal(dry, heal_act, first_pkt_ts=10.0, now=10.005)
    assert res["verified"] is True
    assert any("ip neigh replace 10.77.0.1" in line for line in dry.actions_log)
    assert any("send_arp_reply" in line for line in dry.actions_log)
    dry.neigh_unpin("v-victim", "10.77.0.1")
    assert dry.neigh_get("v-victim", "10.77.0.1") is None
