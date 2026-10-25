# tests/test_chainlog.py
from __future__ import annotations

import json
import multiprocessing
from pathlib import Path

import pytest

from sentinelx.chainlog import GENESIS_PREV, ChainLog, compute_entry_hash


def _worker_append(log_path: str, worker_id: int, count: int) -> None:
    cl = ChainLog(Path(log_path))
    for i in range(count):
        cl.append("detect", {"worker": worker_id, "seq": i})


def test_append_and_verify_ok(tmp_path: Path) -> None:
    log_path = tmp_path / "log.jsonl"
    cl = ChainLog(log_path)
    e1 = cl.append("daemon_start", {"iface": "v-victim"})
    e2 = cl.append("tofu_learned", {"gw_ip": "10.77.0.1", "gw_mac": "02:77:00:00:00:01"})
    e3 = cl.append("detect", {"observed_mac": "02:77:00:00:00:66"})

    assert e1["idx"] == 1
    assert e2["idx"] == 2
    assert e3["idx"] == 3
    assert cl.head() == e3["hash"]

    res = ChainLog.verify(log_path)
    assert res.ok is True
    assert res.entries == 4  # genesis + 3 entries
    assert res.bad_idx is None
    assert res.reason is None
    assert res.head == e3["hash"]


def test_edit_data_field_detected(tmp_path: Path) -> None:
    log_path = tmp_path / "log.jsonl"
    cl = ChainLog(log_path)
    cl.append("daemon_start", {"iface": "v-victim"})
    cl.append("detect", {"gw_ip": "10.77.0.1", "observed_mac": "02:77:00:00:00:66"})
    cl.append("heal", {"verified": True})

    lines = log_path.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[2])
    obj["data"]["observed_mac"] = "02:77:00:00:00:99"
    lines[2] = json.dumps(obj, separators=(",", ":"))
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    res = ChainLog.verify(log_path)
    assert res.ok is False
    assert res.bad_idx == 2
    assert res.reason == "bad_hash"


def test_edit_ts_detected(tmp_path: Path) -> None:
    log_path = tmp_path / "log.jsonl"
    cl = ChainLog(log_path)
    cl.append("daemon_start", {"iface": "v-victim"})

    lines = log_path.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[1])
    obj["ts"] = "2099-01-01T00:00:00.000000Z"
    lines[1] = json.dumps(obj, separators=(",", ":"))
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    res = ChainLog.verify(log_path)
    assert res.ok is False
    assert res.bad_idx == 1
    assert res.reason == "bad_hash"


def test_delete_middle_line_detected(tmp_path: Path) -> None:
    log_path = tmp_path / "log.jsonl"
    cl = ChainLog(log_path)
    cl.append("daemon_start", {})
    cl.append("detect", {})
    cl.append("heal", {})

    lines = log_path.read_text(encoding="utf-8").splitlines()
    del lines[2]  # delete idx 2
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    res = ChainLog.verify(log_path)
    assert res.ok is False
    assert res.bad_idx == 2
    assert res.reason == "bad_idx"


def test_swap_two_lines_detected(tmp_path: Path) -> None:
    log_path = tmp_path / "log.jsonl"
    cl = ChainLog(log_path)
    cl.append("daemon_start", {})
    cl.append("detect", {})
    cl.append("heal", {})

    lines = log_path.read_text(encoding="utf-8").splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    res = ChainLog.verify(log_path)
    assert res.ok is False
    assert res.bad_idx == 1
    assert res.reason == "bad_idx"


def test_insert_forged_line_with_matching_idx_detected(tmp_path: Path) -> None:
    log_path = tmp_path / "log.jsonl"
    cl = ChainLog(log_path)
    cl.append("daemon_start", {})
    cl.append("detect", {"real": True})

    lines = log_path.read_text(encoding="utf-8").splitlines()
    e1 = json.loads(lines[1])
    forged_ts = "2026-10-25T00:00:00.000000Z"
    forged_data = {"forged": True}
    forged_hash = compute_entry_hash(e1["hash"], 2, forged_ts, "detect", forged_data)
    forged = {
        "idx": 2,
        "ts": forged_ts,
        "type": "detect",
        "data": forged_data,
        "prev": e1["hash"],
        "hash": forged_hash,
    }
    # Replace idx 1's successor by inserting forged at pos 2 and bumping old idx 2 -> 3 without re-chaining
    old_e2 = json.loads(lines[2])
    old_e2["idx"] = 3
    lines = [lines[0], lines[1], json.dumps(forged), json.dumps(old_e2)]
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    res = ChainLog.verify(log_path)
    assert res.ok is False
    assert res.bad_idx == 3
    assert res.reason == "bad_prev"


def test_corrupt_json_detected(tmp_path: Path) -> None:
    log_path = tmp_path / "log.jsonl"
    cl = ChainLog(log_path)
    cl.append("daemon_start", {})

    with open(log_path, "a", encoding="utf-8") as f:
        f.write("{corrupted json line\n")

    res = ChainLog.verify(log_path)
    assert res.ok is False
    assert res.bad_idx == 2
    assert res.reason == "bad_json"


def test_wrong_genesis_detected(tmp_path: Path) -> None:
    log_path = tmp_path / "log.jsonl"
    bad_genesis = {
        "idx": 0,
        "ts": "2026-10-25T00:00:00Z",
        "type": "not_genesis",
        "data": {},
        "prev": GENESIS_PREV,
        "hash": "a" * 64,
    }
    log_path.write_text(json.dumps(bad_genesis) + "\n", encoding="utf-8")

    res = ChainLog.verify(log_path)
    assert res.ok is False
    assert res.bad_idx == 0
    assert res.reason == "bad_genesis"


def test_empty_or_missing_file_detected(tmp_path: Path) -> None:
    empty_path = tmp_path / "empty.jsonl"
    empty_path.write_text("", encoding="utf-8")
    res_empty = ChainLog.verify(empty_path)
    assert res_empty.ok is False
    assert res_empty.bad_idx == 0
    assert res_empty.reason == "bad_genesis"

    res_missing = ChainLog.verify(tmp_path / "does_not_exist.jsonl")
    assert res_missing.ok is False
    assert res_missing.bad_idx == 0
    assert res_missing.reason == "bad_genesis"


def test_concurrent_appends_from_two_processes(tmp_path: Path) -> None:
    log_path = tmp_path / "concurrent.jsonl"
    ChainLog(log_path)

    p1 = multiprocessing.Process(target=_worker_append, args=(str(log_path), 1, 10))
    p2 = multiprocessing.Process(target=_worker_append, args=(str(log_path), 2, 10))
    p1.start()
    p2.start()
    p1.join(timeout=10)
    p2.join(timeout=10)
    assert p1.exitcode == 0
    assert p2.exitcode == 0

    res = ChainLog.verify(log_path)
    assert res.ok is True
    assert res.entries == 21  # genesis + 20 entries


def test_crash_prefix_still_verifies(tmp_path: Path) -> None:
    log_path = tmp_path / "log.jsonl"
    cl = ChainLog(log_path)
    cl.append("daemon_start", {})
    cl.append("tofu_learned", {"gw_mac": "02:77:00:00:00:01"})
    cl.append("detect", {"observed_mac": "02:77:00:00:00:66"})

    # Simulate clean prefix up to line 3 (genesis + 2 entries) before a crash
    lines = log_path.read_text(encoding="utf-8").splitlines()[:3]
    prefix_path = tmp_path / "prefix.jsonl"
    prefix_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    res = ChainLog.verify(prefix_path)
    assert res.ok is True
    assert res.entries == 3


@pytest.mark.xfail(
    strict=False,
    reason="Tail truncation without external head anchor is a documented known limit (§6.6 & §13)",
)
def test_truncation_not_detected(tmp_path: Path) -> None:
    log_path = tmp_path / "log.jsonl"
    cl = ChainLog(log_path)
    cl.append("daemon_start", {})
    cl.append("detect", {})

    # Attacker with root truncates the last entry from the tail
    lines = log_path.read_text(encoding="utf-8").splitlines()[:-1]
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    res = ChainLog.verify(log_path)
    # Without an external anchor of the head hash, local verification cannot know an entry existed after the tail
    assert res.ok is False
