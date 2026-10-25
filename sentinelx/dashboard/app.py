# sentinelx/dashboard/app.py
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from sentinelx.chainlog import GENESIS_PREV, ChainLog, canonical_json


def format_banner(status: dict[str, Any], log_entries: list[dict[str, Any]] | None = None) -> dict[str, str]:
    """Compute plain-English banner state and copy per §9 WP8 from status.json (+ recent detect entry)."""
    state = str(status.get("state") or "waiting_net")
    under_attack = bool(status.get("under_attack", False))
    gw_ip = status.get("gw_ip") or "unknown"
    gw_mac = status.get("gw_mac") or "unpinned"

    observed_mac = "unknown"
    if log_entries:
        for e in reversed(log_entries):
            if e.get("type") == "detect":
                observed_mac = str(e.get("data", {}).get("observed_mac") or "unknown")
                break

    if under_attack:
        return {
            "level": "danger",
            "state": "under_attack",
            "headline": (
                f"Under attack — a device (MAC {observed_mac}) is pretending to be your router. "
                "Sentinel-X is blocking it."
            ),
        }

    if state == "conflict":
        return {
            "level": "warning",
            "state": "conflict",
            "headline": "Conflict — two devices claim to be your router; nothing was pinned",
        }

    if state in ("unprotected", "waiting_net", "tofu") or not status.get("gw_mac"):
        return {
            "level": "warning",
            "state": "unprotected",
            "headline": "Not protected — your router didn't answer",
        }

    return {
        "level": "ok",
        "state": "protected",
        "headline": f"Protected — your router ({gw_ip}) is locked to {gw_mac}",
    }


def format_entry_sentence(entry: dict[str, Any]) -> str:
    """Format a log.jsonl entry into a plain-English sentence for a normal user (§9 WP8)."""
    ts_raw = str(entry.get("ts", ""))
    ts_short = ts_raw[11:19] if len(ts_raw) >= 19 else ts_raw
    etype = str(entry.get("type", ""))
    data = entry.get("data", {}) if isinstance(entry.get("data"), dict) else {}

    match etype:
        case "genesis":
            return f"{ts_short} — Audit log initialized (genesis block #0)."
        case "daemon_start":
            iface = data.get("iface", "auto")
            return f"{ts_short} — Sentinel-X started monitoring interface {iface}."
        case "tofu_learned":
            gw_ip = data.get("gw_ip", "router")
            gw_mac = data.get("gw_mac", "unknown")
            return f"{ts_short} — Learned router ({gw_ip}) hardware address {gw_mac} and locked it."
        case "tofu_conflict":
            gw_ip = data.get("gw_ip", "router")
            cands = ", ".join(sorted(str(k) for k in (data.get("candidates") or {}).keys()))
            return (
                f"{ts_short} — Conflict: multiple devices ({cands}) "
                f"claimed to be router {gw_ip}; nothing was pinned."
            )
        case "tofu_unprotected":
            gw_ip = data.get("gw_ip", "router")
            return f"{ts_short} — Router {gw_ip} did not answer ARP probes; running unprotected."
        case "detect":
            obs = data.get("observed_mac", "unknown")
            exp = data.get("expected_mac", "unknown")
            gw_ip = data.get("gw_ip", "router")
            return (
                f"{ts_short} — Someone ({obs}) claimed to be your router ({gw_ip}, expected {exp})."
            )
        case "heal":
            verified = bool(data.get("verified", False))
            corr = bool(data.get("corrective_sent", False))
            lat = data.get("latency_ms_from_first_pkt", 0)
            ver_txt = "Verified." if verified else "Verification failed."
            warn_txt = "router warned" if corr else "pin re-asserted"
            return f"{ts_short} — Correct entry restored ({lat} ms), {warn_txt}. {ver_txt}"
        case "incident_close":
            pkts = data.get("packets", 1)
            obs = data.get("observed_mac", "unknown")
            dur = data.get("duration_s", 0)
            heals = data.get("heals", 1)
            return (
                f"{ts_short} — Attack from {obs} ended ({pkts} packets over {dur}s, "
                f"{heals} heal action{'s' if heals != 1 else ''})."
            )
        case "network_changed":
            reason = data.get("reason", "changed")
            return f"{ts_short} — Network changed ({reason}); previous router pin cleared."
        case "daemon_stop":
            unpinned = bool(data.get("unpinned", False))
            suffix = "router pin released cleanly." if unpinned else "stopped."
            return f"{ts_short} — Sentinel-X daemon stopped; {suffix}"
        case _:
            return f"{ts_short} — Event: {etype}"


def read_dashboard_snapshot(state_dir: Path) -> dict[str, Any]:
    """Read status.json, log.jsonl, and run ChainLog.verify without any mock data."""
    status_path = state_dir / "status.json"
    log_path = state_dir / "log.jsonl"

    status: dict[str, Any] = {}
    if status_path.exists():
        try:
            status = json.loads(status_path.read_text(encoding="utf-8"))
        except Exception:
            status = {}

    entries: list[dict[str, Any]] = []
    if log_path.exists():
        for raw_line in log_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    entries.append(
                        {
                            **obj,
                            "sentence": format_entry_sentence(obj),
                            # Exact canonical payload string (§6.6): the bytes that were
                            # hashed as (prev + payload) at write time. Shipping it makes
                            # browser-side re-verification byte-exact (JS floats can
                            # serialize differently from Python reprs).
                            "payload": canonical_json(
                                {
                                    "idx": obj["idx"],
                                    "ts": obj["ts"],
                                    "type": obj["type"],
                                    "data": obj["data"],
                                }
                            ),
                        }
                    )
            except json.JSONDecodeError:
                entries.append(
                    {
                        "idx": len(entries),
                        "ts": "",
                        "type": "corrupt",
                        "data": {"raw": line},
                        "prev": "",
                        "hash": "",
                        "sentence": "Corrupted log line detected.",
                    }
                )

    verify_res = ChainLog.verify(log_path) if log_path.exists() else None
    if verify_res is None:
        integrity = {
            "ok": False,
            "entries": 0,
            "bad_idx": 0,
            "reason": "missing_log",
            "head": GENESIS_PREV,
            "badge": "No log file found",
        }
    elif verify_res.ok:
        integrity = {
            "ok": True,
            "entries": verify_res.entries,
            "bad_idx": None,
            "reason": None,
            "head": verify_res.head,
            "badge": f"Verified, {verify_res.entries} entries",
        }
    else:
        integrity = {
            "ok": False,
            "entries": verify_res.entries,
            "bad_idx": verify_res.bad_idx,
            "reason": verify_res.reason,
            "head": verify_res.head,
            "badge": f"TAMPERED at entry #{verify_res.bad_idx}",
        }

    banner = format_banner(status, entries)
    return {
        "status": status,
        "banner": banner,
        "integrity": integrity,
        "entries": entries,
    }


def create_app(state_dir: Path | str = Path("/var/lib/sentinelx")) -> FastAPI:
    state_path = Path(state_dir)
    app = FastAPI(
        title="Sentinel-X Read-Only Dashboard",
        description="Local read-only ARP-defense status and hash-chain verification dashboard",
        version="0.1.0",
    )

    static_html_path = Path(__file__).parent / "static" / "index.html"

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        return HTMLResponse(static_html_path.read_text(encoding="utf-8"))

    @app.get("/api/snapshot", response_class=JSONResponse)
    def api_snapshot() -> JSONResponse:
        return JSONResponse(read_dashboard_snapshot(state_path))

    @app.get("/api/status", response_class=JSONResponse)
    def api_status() -> JSONResponse:
        snap = read_dashboard_snapshot(state_path)
        return JSONResponse({"status": snap["status"], "banner": snap["banner"]})

    @app.get("/api/verify", response_class=JSONResponse)
    def api_verify() -> JSONResponse:
        snap = read_dashboard_snapshot(state_path)
        return JSONResponse(snap["integrity"])

    return app
