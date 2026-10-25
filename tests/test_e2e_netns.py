# tests/test_e2e_netns.py
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.integration
def test_e2e_netns_attack_detect_heal_verify_and_sigterm(tmp_path: Path) -> None:
    """Integration test in real Linux network namespaces (`sx-gw`, `sx-victim`, `sx-att`)."""
    if os.geteuid() != 0:
        pytest.skip("Integration test requires root")
    if not shutil.which("ip") or not shutil.which("arpspoof"):
        pytest.skip("ip or arpspoof not installed")

    env = dict(os.environ)
    env["SX_E2E_STATE_DIR"] = str(tmp_path / "state")
    env["SX_KEEP_STATE"] = "1"

    proc = subprocess.run(
        ["bash", "lab/e2e.sh"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"e2e.sh failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    assert "PASS: All end-to-end checks succeeded." in proc.stdout
