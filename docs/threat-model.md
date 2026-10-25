# Sentinel-X — Threat Model & Known Limitations

## 1. Adversary Model & Protected Asset

- **Environment:** Untrusted Layer-2 broadcast domain (public/hostel Wi-Fi without client isolation, small office LAN without 802.1X or Dynamic ARP Inspection).
- **Adversary Capabilities:** Another host on the same IPv4 subnet capable of crafting arbitrary Ethernet/ARP frames (e.g., `arpspoof -r`) to poison both the victim's neighbour cache and the default gateway's neighbour cache.
- **Protected Path:** IPv4 Layer-2 resolution between the **protected Linux host** and its **default gateway**.

---

## 2. Defence Mechanisms

1. **Outbound Protection (Kernel Pinning):**
   - Sentinel-X pins the gateway's MAC address in the Linux neighbour table using `ip neigh replace <gw_ip> lladdr <gw_mac> dev <iface> nud permanent`.
   - The Linux kernel ignores unsolicited ARP replies for entries in the `PERMANENT` state, preventing outbound traffic redirection.
2. **Inbound Protection (Active Corrective ARP):**
   - Because an attacker poisoning the gateway sends unicast ARP replies directly to the router, the victim cannot directly observe the router-bound poison frames.
   - Whenever Sentinel-X detects a spoofed ARP packet claiming the gateway IP (`R1: gateway_mac_mismatch`), it assumes a bidirectional MITM attempt and transmits a unicast corrective ARP reply (`op=2`) directly to the legitimate gateway MAC (`Ether(src=our_mac, dst=gw_mac) / ARP(op=2, hwsrc=our_mac, psrc=our_ip, hwdst=gw_mac, pdst=gw_ip)`), restoring the router's cache entry for our host.
3. **Multi-Probe TOFU Conflict Detection:**
   - Before pinning a newly encountered gateway, Sentinel-X sends multiple ARP `who-has` probes over a collection window (`tofu_window_ms`).
   - If more than one distinct MAC address answers (`>= 2`), the engine enters `State.CONFLICT`, refuses to pin an ambiguous address, and logs `tofu_conflict`.

---

## 3. Known Limitations (§13)

1. **Trust on First Use (TOFU) Window:**
   - TOFU is only as trustworthy as the host's first contact with the network. While multi-probe conflict detection catches concurrent spoofers when both the real gateway and attacker respond, it cannot defeat an attacker who is already in-line and able to drop or suppress the real gateway's ARP replies during initial join.
2. **Host ↔ Gateway Path Only:**
   - Sentinel-X protects traffic destined to or arriving from the default gateway. Peer-to-peer traffic to other LAN hosts on the same subnet is not pinned or monitored.
3. **IPv4 ARP Only:**
   - IPv6 Neighbour Discovery Protocol (NDP) and Router Advertisement (RA) spoofing are out of scope.
4. **Local Root Compromise & Hash-Chain Tail Truncation:**
   - A root-level attacker on the victim host itself can terminate the daemon, unpin kernel entries, or rewrite files in `state_dir`.
   - The SHA-256 hash chain (`log.jsonl`) detects **any modification, insertion, deletion, or reordering of entries in the middle of the file**, because subsequent `prev` and `hash` digests break.
   - However, without anchoring the latest `chain_head` hash to an external witness (e.g., remote syslog, object storage, or external transparency log), a local root attacker can **truncate entries from the tail** or regenerate the entire file from `genesis`.
5. **VRRP / HSRP Virtual MAC Trade-Off (§6.3):**
   - Enterprise networks using VRRP (`00:00:5e:00:01:xx`) or Cisco HSRP (`00:00:0c:07:ac:xx`, `00:00:0c:9f:f0:xx`) may legitimately source ARP traffic from virtual MAC addresses.
   - Unconditionally whitelisting VRRP/HSRP MAC prefixes on all networks would let an attacker spoof `00:00:5e:00:01:01` to evade detection on a home or hostel router.
   - Sentinel-X restricts this allowance: vMAC senders are permitted **only if the gateway's initially learned TOFU MAC was itself a vMAC** (`virtual_gateway = true`). On a virtual gateway, an attacker who spoofs another vMAC in the same prefix could evade `R1` detection.
6. **Legitimate Router Hardware Replacement:**
   - If an administrator replaces the physical router with a new device on the same SSID/subnet, Sentinel-X treats the new MAC as a mismatch and maintains the existing pin until the operator runs `sentinelx trust --add-mac <NEW_MAC>` or `--forget`.
7. **Virtual Namespace Lab Benchmarks:**
   - All automated tests and latency/mitigation measurements in `lab/` and `bench/` run over Linux `veth` pairs and an in-kernel software bridge (`sxbr0`), which has lower jitter and frame loss than congested 802.11 Wi-Fi airtime.
