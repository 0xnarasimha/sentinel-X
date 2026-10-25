# sentinelx/trust.py
from __future__ import annotations

import json
import os
from pathlib import Path

from sentinelx.models import MAC, IPv4, TrustStore

# Known VRRP / HSRP virtual MAC prefixes (§6.1 item 5 & §6.3)
# VRRP IPv4: 00:00:5e:00:01:xx
# HSRP v1:   00:00:0c:07:ac:xx
# HSRP v2:   00:00:0c:9f:f0:xx .. 00:00:0c:9f:ff:xx
_VMAC_PREFIXES: tuple[str, ...] = (
    "00:00:5e:00:01:",
    "00:00:0c:07:ac:",
    "00:00:0c:9f:f",
)


def normalize_mac(mac: MAC) -> MAC:
    return mac.strip().lower()


def trust_key(iface: str, network_id: str, gw_ip: IPv4) -> str:
    return f"{iface}|{network_id}|{gw_ip}"


def is_virtual_mac(mac: MAC) -> bool:
    norm = normalize_mac(mac)
    return any(norm.startswith(prefix) for prefix in _VMAC_PREFIXES)


def is_mac_allowed(
    mac: MAC,
    trust_entry: dict | None,
    extra_allowed: tuple[MAC, ...] = (),
) -> bool:
    """Pure whitelist rule evaluation (§6.3).

    A sender MAC claiming the gateway IP is allowed iff:
    1. It matches the pinned `gw_mac` in `trust_entry`, OR
    2. It is listed in `trust_entry["allowed_macs"]`, OR
    3. It is listed in `extra_allowed` (from config.toml `[whitelist]`), OR
    4. `trust_entry["virtual_gateway"]` is True AND `mac` matches a known VRRP/HSRP vMAC pattern.
    """
    norm = normalize_mac(mac)
    allowed: set[str] = {normalize_mac(m) for m in extra_allowed if m}

    if trust_entry is not None:
        gw_mac = trust_entry.get("gw_mac")
        if gw_mac:
            allowed.add(normalize_mac(str(gw_mac)))
        for extra in trust_entry.get("allowed_macs", []):
            if extra:
                allowed.add(normalize_mac(str(extra)))
        if norm in allowed:
            return True
        if bool(trust_entry.get("virtual_gateway", False)) and is_virtual_mac(norm):
            return True
        return False

    return norm in allowed


class MemoryTrustStore(TrustStore):
    """In-memory TrustStore implementation for unit tests (zero file I/O)."""

    def __init__(self, initial: dict[str, dict] | None = None) -> None:
        self._store: dict[str, dict] = {}
        if initial:
            for k, v in initial.items():
                self._store[k] = dict(v)

    def get(self, key: str) -> dict | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        return {
            "gw_mac": entry["gw_mac"],
            "allowed_macs": list(entry.get("allowed_macs", [])),
            "learned_at": entry.get("learned_at"),
            "virtual_gateway": bool(entry.get("virtual_gateway", False)),
        }

    def put(self, key: str, entry: dict) -> None:
        gw_mac = normalize_mac(str(entry["gw_mac"]))
        allowed = [normalize_mac(str(m)) for m in entry.get("allowed_macs", [])]
        self._store[key] = {
            "gw_mac": gw_mac,
            "allowed_macs": allowed,
            "learned_at": entry.get("learned_at"),
            "virtual_gateway": bool(entry.get("virtual_gateway", is_virtual_mac(gw_mac))),
        }

    def add_allowed_mac(self, key: str, mac: MAC) -> None:
        norm = normalize_mac(mac)
        if key not in self._store:
            self._store[key] = {
                "gw_mac": norm,
                "allowed_macs": [norm],
                "learned_at": 0.0,
                "virtual_gateway": is_virtual_mac(norm),
            }
            return
        allowed = list(self._store[key].get("allowed_macs", []))
        if norm not in allowed:
            allowed.append(norm)
        self._store[key]["allowed_macs"] = allowed

    def forget(self, key: str) -> None:
        self._store.pop(key, None)

    def all_entries(self) -> dict[str, dict]:
        return {k: self.get(k) for k in self._store}  # type: ignore[misc]


class JsonTrustStore(TrustStore):
    """Persistent JSON TrustStore using atomic tmp + rename writes (§5)."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def _read_all(self) -> dict[str, dict]:
        if not self.path.exists():
            return {}
        try:
            raw = self.path.read_text(encoding="utf-8").strip()
            if not raw:
                return {}
            data = json.loads(raw)
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _write_all(self, data: dict[str, dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, self.path)

    def get(self, key: str) -> dict | None:
        data = self._read_all()
        entry = data.get(key)
        if not isinstance(entry, dict) or "gw_mac" not in entry:
            return None
        return {
            "gw_mac": normalize_mac(str(entry["gw_mac"])),
            "allowed_macs": [normalize_mac(str(m)) for m in entry.get("allowed_macs", [])],
            "learned_at": entry.get("learned_at"),
            "virtual_gateway": bool(entry.get("virtual_gateway", False)),
        }

    def put(self, key: str, entry: dict) -> None:
        data = self._read_all()
        gw_mac = normalize_mac(str(entry["gw_mac"]))
        allowed = [normalize_mac(str(m)) for m in entry.get("allowed_macs", [])]
        data[key] = {
            "gw_mac": gw_mac,
            "allowed_macs": allowed,
            "learned_at": entry.get("learned_at"),
            "virtual_gateway": bool(entry.get("virtual_gateway", is_virtual_mac(gw_mac))),
        }
        self._write_all(data)

    def add_allowed_mac(self, key: str, mac: MAC) -> None:
        norm = normalize_mac(mac)
        data = self._read_all()
        if key not in data or not isinstance(data[key], dict):
            data[key] = {
                "gw_mac": norm,
                "allowed_macs": [norm],
                "learned_at": 0.0,
                "virtual_gateway": is_virtual_mac(norm),
            }
        else:
            allowed = [normalize_mac(str(m)) for m in data[key].get("allowed_macs", [])]
            if norm not in allowed:
                allowed.append(norm)
            data[key]["allowed_macs"] = allowed
        self._write_all(data)

    def forget(self, key: str) -> None:
        data = self._read_all()
        if key in data:
            del data[key]
            self._write_all(data)

    def all_entries(self) -> dict[str, dict]:
        return self._read_all()
