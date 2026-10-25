# sentinelx/chainlog.py
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinelx.models import VerifyResult

GENESIS_PREV = "0" * 64


def canonical_json(obj: dict[str, Any]) -> str:
    """Deterministic canonical JSON serialization per §6.6."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def compute_entry_hash(prev: str, idx: int, ts: str, entry_type: str, data: dict[str, Any]) -> str:
    payload = canonical_json({"idx": idx, "ts": ts, "type": entry_type, "data": data})
    return hashlib.sha256((prev + payload).encode("utf-8")).hexdigest()


def _utc_iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class ChainLog:
    """Tamper-evident SHA-256 hash-chained JSONL log (§5 & §6.6).

    Every append uses `flock(LOCK_EX)` + write + `flush` + `os.fsync` so concurrent
    writers serialize cleanly and crashes leave a verifiable prefix.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_genesis()

    def _ensure_genesis(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a+", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.seek(0)
                content = f.read().strip()
                if not content:
                    ts = _utc_iso_now()
                    data: dict[str, Any] = {"version": 1}
                    h = compute_entry_hash(GENESIS_PREV, 0, ts, "genesis", data)
                    entry = {
                        "idx": 0,
                        "ts": ts,
                        "type": "genesis",
                        "data": data,
                        "prev": GENESIS_PREV,
                        "hash": h,
                    }
                    f.write(json.dumps(entry, separators=(",", ":")) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    def append(self, type: str, data: dict[str, Any], ts: str | None = None) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a+", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.seek(0)
                lines = [ln.strip() for ln in f.read().splitlines() if ln.strip()]
                if not lines:
                    genesis_ts = _utc_iso_now()
                    genesis_data: dict[str, Any] = {"version": 1}
                    genesis_hash = compute_entry_hash(
                        GENESIS_PREV, 0, genesis_ts, "genesis", genesis_data
                    )
                    genesis_entry = {
                        "idx": 0,
                        "ts": genesis_ts,
                        "type": "genesis",
                        "data": genesis_data,
                        "prev": GENESIS_PREV,
                        "hash": genesis_hash,
                    }
                    f.write(json.dumps(genesis_entry, separators=(",", ":")) + "\n")
                    lines = [json.dumps(genesis_entry, separators=(",", ":"))]

                last_obj = json.loads(lines[-1])
                idx = int(last_obj["idx"]) + 1
                prev = str(last_obj["hash"])
                entry_ts = ts or _utc_iso_now()
                entry_hash = compute_entry_hash(prev, idx, entry_ts, type, data)
                entry = {
                    "idx": idx,
                    "ts": entry_ts,
                    "type": type,
                    "data": data,
                    "prev": prev,
                    "hash": entry_hash,
                }
                f.seek(0, os.SEEK_END)
                f.write(json.dumps(entry, separators=(",", ":")) + "\n")
                f.flush()
                os.fsync(f.fileno())
                return entry
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    def head(self) -> str:
        if not self.path.exists():
            return GENESIS_PREV
        lines = [
            ln.strip()
            for ln in self.path.read_text(encoding="utf-8").splitlines()
            if ln.strip()
        ]
        if not lines:
            return GENESIS_PREV
        try:
            last = json.loads(lines[-1])
            return str(last.get("hash", GENESIS_PREV))
        except Exception:
            return GENESIS_PREV

    @staticmethod
    def verify(path: Path | str) -> VerifyResult:
        p = Path(path)
        if not p.exists():
            return VerifyResult(
                ok=False, entries=0, bad_idx=0, reason="bad_genesis", head=GENESIS_PREV
            )

        raw_lines = [
            ln.strip() for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()
        ]
        if not raw_lines:
            return VerifyResult(
                ok=False, entries=0, bad_idx=0, reason="bad_genesis", head=GENESIS_PREV
            )

        expected_prev = GENESIS_PREV
        last_hash = GENESIS_PREV

        for expected_idx, raw_line in enumerate(raw_lines):
            try:
                obj = json.loads(raw_line)
            except json.JSONDecodeError:
                return VerifyResult(
                    ok=False,
                    entries=expected_idx,
                    bad_idx=expected_idx,
                    reason="bad_json",
                    head=last_hash,
                )

            if not isinstance(obj, dict):
                return VerifyResult(
                    ok=False,
                    entries=expected_idx,
                    bad_idx=expected_idx,
                    reason="bad_json",
                    head=last_hash,
                )

            for req_key in ("idx", "ts", "type", "data", "prev", "hash"):
                if req_key not in obj:
                    return VerifyResult(
                        ok=False,
                        entries=expected_idx,
                        bad_idx=expected_idx,
                        reason="bad_json",
                        head=last_hash,
                    )

            idx = obj["idx"]
            ts = obj["ts"]
            entry_type = obj["type"]
            data = obj["data"]
            prev = obj["prev"]
            recorded_hash = obj["hash"]

            if idx != expected_idx:
                return VerifyResult(
                    ok=False,
                    entries=expected_idx,
                    bad_idx=expected_idx,
                    reason="bad_idx",
                    head=last_hash,
                )

            if expected_idx == 0:
                if entry_type != "genesis" or prev != GENESIS_PREV:
                    return VerifyResult(
                        ok=False,
                        entries=0,
                        bad_idx=0,
                        reason="bad_genesis",
                        head=last_hash,
                    )
            else:
                if prev != expected_prev:
                    return VerifyResult(
                        ok=False,
                        entries=expected_idx,
                        bad_idx=expected_idx,
                        reason="bad_prev",
                        head=last_hash,
                    )

            if not isinstance(ts, str) or not isinstance(entry_type, str) or not isinstance(data, dict):
                return VerifyResult(
                    ok=False,
                    entries=expected_idx,
                    bad_idx=expected_idx,
                    reason="bad_json",
                    head=last_hash,
                )

            computed = compute_entry_hash(prev, idx, ts, entry_type, data)
            if recorded_hash != computed:
                return VerifyResult(
                    ok=False,
                    entries=expected_idx,
                    bad_idx=expected_idx,
                    reason="bad_hash",
                    head=last_hash,
                )

            expected_prev = recorded_hash
            last_hash = recorded_hash

        return VerifyResult(
            ok=True,
            entries=len(raw_lines),
            bad_idx=None,
            reason=None,
            head=last_hash,
        )
