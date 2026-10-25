# tests/test_dashboard.py
from __future__ import annotations

import json
from pathlib import Path

from sentinelx.chainlog import ChainLog
from sentinelx.dashboard.app import (
    format_banner,
    format_entry_sentence,
    read_dashboard_snapshot,
)


def test_format_banner_all_four_states() -> None:
    # 1. Protected (green)
    b_ok = format_banner(
        {
            "state": "monitor",
            "gw_ip": "10.77.0.1",
            "gw_mac": "02:77:00:00:00:01",
            "pinned": True,
            "under_attack": False,
        }
    )
    assert b_ok["level"] == "ok"
    assert b_ok["state"] == "protected"
    assert "Protected — your router (10.77.0.1) is locked to 02:77:00:00:00:01" in b_ok["headline"]

    # 2. Under attack (red)
    b_att = format_banner(
        {
            "state": "monitor",
            "gw_ip": "10.77.0.1",
            "gw_mac": "02:77:00:00:00:01",
            "pinned": True,
            "under_attack": True,
        },
        log_entries=[{"type": "detect", "data": {"observed_mac": "02:77:00:00:00:66"}}],
    )
    assert b_att["level"] == "danger"
    assert b_att["state"] == "under_attack"
    assert (
        "Under attack — a device (MAC 02:77:00:00:00:66) is pretending to be your router. "
        "Sentinel-X is blocking it."
    ) in b_att["headline"]

    # 3. Unprotected (amber)
    b_unp = format_banner(
        {
            "state": "unprotected",
            "gw_ip": "10.77.0.1",
            "gw_mac": None,
            "pinned": False,
            "under_attack": False,
        }
    )
    assert b_unp["level"] == "warning"
    assert b_unp["state"] == "unprotected"
    assert "Not protected — your router didn't answer" in b_unp["headline"]

    # 4. Conflict (amber)
    b_conf = format_banner(
        {
            "state": "conflict",
            "gw_ip": "10.77.0.1",
            "gw_mac": None,
            "pinned": False,
            "under_attack": False,
        }
    )
    assert b_conf["level"] == "warning"
    assert b_conf["state"] == "conflict"
    assert "Conflict — two devices claim to be your router; nothing was pinned" in b_conf["headline"]


def test_format_entry_sentence_plain_english() -> None:
    s_det = format_entry_sentence(
        {
            "ts": "2026-10-25T10:15:02.114233Z",
            "type": "detect",
            "data": {
                "gw_ip": "10.77.0.1",
                "expected_mac": "02:77:00:00:00:01",
                "observed_mac": "02:77:00:00:00:66",
            },
        }
    )
    assert "10:15:02" in s_det
    assert "02:77:00:00:00:66" in s_det

    s_heal = format_entry_sentence(
        {
            "ts": "2026-10-25T10:15:02.120000Z",
            "type": "heal",
            "data": {
                "verified": True,
                "corrective_sent": True,
                "latency_ms_from_first_pkt": 5.8,
            },
        }
    )
    assert "Correct entry restored" in s_heal
    assert "router warned" in s_heal
    assert "Verified." in s_heal


def test_dashboard_snapshot_and_tamper_badge(tmp_path: Path) -> None:
    log_path = tmp_path / "log.jsonl"
    status_path = tmp_path / "status.json"

    cl = ChainLog(log_path)
    cl.append("daemon_start", {"iface": "v-victim"})
    cl.append("tofu_learned", {"gw_ip": "10.77.0.1", "gw_mac": "02:77:00:00:00:01"})
    cl.append(
        "detect",
        {
            "kind": "gateway_mac_mismatch",
            "gw_ip": "10.77.0.1",
            "expected_mac": "02:77:00:00:00:01",
            "observed_mac": "02:77:00:00:00:66",
        },
    )
    last = cl.append(
        "heal",
        {
            "verified": True,
            "corrective_sent": True,
            "pinned_mac": "02:77:00:00:00:01",
            "latency_ms_from_first_pkt": 6.4,
        },
    )

    status_path.write_text(
        json.dumps(
            {
                "state": "monitor",
                "iface": "v-victim",
                "network_id": "wired",
                "gw_ip": "10.77.0.1",
                "gw_mac": "02:77:00:00:00:01",
                "pinned": True,
                "under_attack": False,
                "incidents_total": 1,
                "last_incident_ts": 1761387302.1,
                "chain_head": last["hash"],
                "dropped_events": 0,
                "updated": "2026-10-25T10:15:03Z",
            }
        ),
        encoding="utf-8",
    )

    snap = read_dashboard_snapshot(tmp_path)
    assert snap["integrity"]["ok"] is True
    assert snap["integrity"]["badge"] == "Verified, 5 entries"
    assert snap["banner"]["state"] == "protected"
    assert len(snap["entries"]) == 5

    # Hand-edit line 3 (idx 3, detect entry) -> badge turns to TAMPERED at entry #3
    lines = log_path.read_text(encoding="utf-8").splitlines()
    lines[3] = lines[3].replace("02:77:00:00:00:66", "02:77:00:00:00:99")
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    snap_tampered = read_dashboard_snapshot(tmp_path)
    assert snap_tampered["integrity"]["ok"] is False
    assert snap_tampered["integrity"]["bad_idx"] == 3
    assert snap_tampered["integrity"]["badge"] == "TAMPERED at entry #3"


def test_committed_lab_fixtures_valid() -> None:
    fixtures_dir = Path("tests/fixtures")
    assert (fixtures_dir / "log.jsonl").exists()
    assert (fixtures_dir / "status.json").exists()
    snap = read_dashboard_snapshot(fixtures_dir)
    assert snap["integrity"]["ok"] is True
    assert snap["integrity"]["entries"] >= 4
    assert snap["status"]["gw_ip"] == "10.77.0.1"


def test_fastapi_create_app_routes() -> None:
    from sentinelx.dashboard.app import create_app

    app = create_app(Path("tests/fixtures"))
    route_paths = {getattr(r, "path", "") for r in app.routes}
    assert "/" in route_paths
    assert "/api/snapshot" in route_paths
    assert "/api/status" in route_paths
    assert "/api/verify" in route_paths
