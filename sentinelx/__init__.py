"""Sentinel-X: ARP-poisoning MITM detection, TOFU pinning, and hash-chained audit daemon."""

from __future__ import annotations

try:
    from scapy.config import conf  # type: ignore[import-untyped]

    conf.ipv6_enabled = False
except Exception:
    pass

__version__ = "0.1.0"
