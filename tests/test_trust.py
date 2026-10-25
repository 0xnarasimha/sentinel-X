# tests/test_trust.py
from __future__ import annotations

from pathlib import Path

import pytest

from sentinelx.trust import (
    JsonTrustStore,
    MemoryTrustStore,
    is_mac_allowed,
    is_virtual_mac,
    normalize_mac,
    trust_key,
)


def test_normalize_mac_and_trust_key() -> None:
    assert normalize_mac("  AA:BB:CC:DD:EE:FF ") == "aa:bb:cc:dd:ee:ff"
    assert trust_key("v-victim", "wired", "10.77.0.1") == "v-victim|wired|10.77.0.1"


@pytest.mark.parametrize(
    ("mac", "expected"),
    [
        ("00:00:5e:00:01:01", True),
        ("00:00:5E:00:01:FF", True),
        ("00:00:0c:07:ac:0a", True),
        ("00:00:0c:9f:f0:01", True),
        ("00:00:0c:9f:ff:fe", True),
        ("02:77:00:00:00:01", False),
        ("aa:bb:cc:dd:ee:ff", False),
    ],
)
def test_is_virtual_mac(mac: str, expected: bool) -> None:
    assert is_virtual_mac(mac) is expected


def test_is_mac_allowed_rules() -> None:
    entry_non_virtual = {
        "gw_mac": "02:77:00:00:00:01",
        "allowed_macs": ["02:77:00:00:00:02"],
        "virtual_gateway": False,
    }
    assert is_mac_allowed("02:77:00:00:00:01", entry_non_virtual) is True
    assert is_mac_allowed("02:77:00:00:00:02", entry_non_virtual) is True
    assert is_mac_allowed("02:77:00:00:00:66", entry_non_virtual) is False
    # vMAC spoof on a NON-virtual gateway must be rejected (§6.3)
    assert is_mac_allowed("00:00:5e:00:01:05", entry_non_virtual) is False
    # Extra allowed from config
    assert (
        is_mac_allowed(
            "02:77:00:00:00:99",
            entry_non_virtual,
            extra_allowed=("02:77:00:00:00:99",),
        )
        is True
    )

    entry_virtual = {
        "gw_mac": "00:00:5e:00:01:01",
        "allowed_macs": [],
        "virtual_gateway": True,
    }
    # Another VRRP vMAC is allowed when virtual_gateway is True
    assert is_mac_allowed("00:00:5e:00:01:02", entry_virtual) is True
    assert is_mac_allowed("02:77:00:00:00:66", entry_virtual) is False


def test_memory_trust_store_crud() -> None:
    store = MemoryTrustStore()
    key = trust_key("v-victim", "wired", "10.77.0.1")
    assert store.get(key) is None

    store.put(key, {"gw_mac": "AA:BB:CC:DD:EE:01", "allowed_macs": [], "learned_at": 100.0})
    got = store.get(key)
    assert got is not None
    assert got["gw_mac"] == "aa:bb:cc:dd:ee:01"
    assert got["virtual_gateway"] is False

    store.add_allowed_mac(key, "AA:BB:CC:DD:EE:02")
    got2 = store.get(key)
    assert got2 is not None
    assert "aa:bb:cc:dd:ee:02" in got2["allowed_macs"]

    store.forget(key)
    assert store.get(key) is None


def test_json_trust_store_atomic_persistence(tmp_path: Path) -> None:
    state_file = tmp_path / "state.json"
    store = JsonTrustStore(state_file)
    key = trust_key("v-victim", "wired", "10.77.0.1")

    store.put(
        key,
        {
            "gw_mac": "00:00:5E:00:01:01",
            "allowed_macs": ["02:77:00:00:00:05"],
            "learned_at": 1234.5,
        },
    )
    assert state_file.exists()
    assert not state_file.with_suffix(".json.tmp").exists()

    # Reload in a new instance
    store2 = JsonTrustStore(state_file)
    loaded = store2.get(key)
    assert loaded is not None
    assert loaded["gw_mac"] == "00:00:5e:00:01:01"
    assert loaded["virtual_gateway"] is True
    assert loaded["allowed_macs"] == ["02:77:00:00:00:05"]

    store2.add_allowed_mac(key, "02:77:00:00:00:09")
    assert "02:77:00:00:00:09" in (store.get(key) or {})["allowed_macs"]

    store2.forget(key)
    assert store.get(key) is None
