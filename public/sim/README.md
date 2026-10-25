# Sentinel-X Interactive 3D Simulation

An interactive 3D teaching simulation explaining:
1. **How ARP poisoning (Man-In-The-Middle / MITM) attacks work** on local switched networks.
2. **How Sentinel-X (a host-level defense daemon) detects and heals the attack** using kernel pinning and corrective ARPs.
3. **Why its append-only incident log is tamper-evident**, and what its cryptographic limits are.

---

## Quickstart (Offline & Zero-Build)

This application is built as a zero-build static site with native ES modules and importmaps. It runs completely offline without any internet connection.

```bash
cd sim
python3 -m http.server 8000
```
Then open `http://localhost:8000` in your browser. (The applet also runs on port 3000 via `npm run dev`).

---

## Vendored Dependencies
- **three.js**: `0.186.1` (vendored in `sim/vendor/three.module.js`)
- **OrbitControls**: `0.186.1` (vendored in `sim/vendor/controls/OrbitControls.js`)
- **CSS2DRenderer**: `0.186.1` (vendored in `sim/vendor/renderers/CSS2DRenderer.js`)
- **RoomEnvironment**: `0.186.1` (vendored in `sim/vendor/environments/RoomEnvironment.js`)

All dependencies are local; no CDN, remote web fonts, external images, or textures are loaded at runtime.

---

## Unit Testing

Pure logic modules (`engine.js` and `chain.js`) are tested using Node's native test runner (`node --test`), with 31 automated tests passing (run `npm test` from the repo root):

```bash
node --test sim/test/*.test.js
```

### Test Coverage Highlights:
- **`sim/test/chain.test.js`** (9 tests):
  - SHA-256 test vectors verified against `node:crypto`
  - Canonical JSON RFC 8785 subset serialization (recursively sorted keys, no whitespace)
  - Full chain verification from genesis
  - Tamper detection: modified data field (`bad_hash`)
  - Tamper detection: modified timestamp (`bad_hash`)
  - Tamper detection: deleted middle block (`bad_idx` / `bad_prev`)
  - Tamper detection: swapped blocks (`bad_idx` / `bad_prev`)
  - Tamper detection: inserted rogue block (`bad_prev`)
  - Tail truncation limit demonstration (passes without external anchor)
- **`sim/test/engine.test.js`** (18 tests):
  - TOFU with 1 MAC (learns and pins)
  - TOFU with 0 replies (UNPROTECTED)
  - TOFU with 2 distinct MACs (CONFLICT)
  - Legitimate gateway packet (no alert, reasoning lines)
  - Forged ARP reply (Rule R1 detection, Heal execution)
  - Forged ARP request and gratuitous ARP
  - Other host traffic (ignored) and victim's own traffic (ignored)
  - Admin-allowed MAC whitelist
  - Incident aggregation and packet counting
  - 1000 ms Heal cooldown enforcement
  - 10-second idle incident closure (`incident_close`)
  - Network change unpinning and re-TOFU
  - VRRP/HSRP virtual MAC policy (accepted only if gateway was learned as virtual MAC)
  - Attacker clones router MAC: undetected (known limit)
  - `pin_mode on_detect` transient exposure window
  - Dashboard banner exact wording

---

## Cast & Network Topology (10.77.0.0/24)
- **Router (Gateway)**: `10.77.0.1` | MAC `aa:bb:cc:00:00:01`
- **Victim Laptop**: `10.77.0.10` | MAC `aa:bb:cc:00:00:10` (runs Sentinel-X)
- **Attacker Node**: `10.77.0.66` | MAC `de:ad:be:ef:00:66` (runs `arpspoof`, IP forwarding ON)
- **Bystander Peer**: `10.77.0.20` | MAC `aa:bb:cc:00:00:20` (unaffected normal peer)
- **Central Switch**: Delivers unicast frames only to the port of destination MAC; floods broadcasts.

---

## Chapters
- **0. Cast & Map**: Topology, empty caches, switch unicast delivery isolation.
- **1. Normal ARP**: ARP who-has / is-at resolution, REACHABLE cache state, direct data flow.
- **2. The Attack (Unprotected)**: Bidirectional `arpspoof`, caches poisoned, MITM interception (plaintext DNS/HTTP visible, TLS encrypted metadata only).
- **3. Learning Router (TOFU)**: 5 probes, reply collection, permanent kernel pin (`ip neigh replace ... nud permanent`), MONITOR state, CONFLICT case.
- **4. Defended (pin_mode always)**: Attack resumes, kernel pin refusal, Rule R1 trigger, auto-healing corrective ARP, incident aggregation, 1000ms cooldown, residual exposure window.
- **5. pin_mode on_detect**: Illustrative transient poisoning window before detection asserts permanent pin.
- **6. Tamper-Evident Log**: Cryptographic hash chaining. Interactive tampering (edit field, delete middle, delete last entry).
- **7. Edge Cases & Limits**: Network change unpinning (preventing black-hole), VRRP virtual MAC failover, victim MAC randomisation, and cloned router MAC limit.
- **Interactive Sandbox**: Manually trigger forged replies, toggle Sentinel-X on/off, switch pin modes.

---

## Dashboard Banners (Exact Wording)
- **Protected (Green)**: `"Protected - your router (10.77.0.1) is locked to aa:bb:cc:00:00:01"`
- **Under Attack (Red)**: `"Under attack - a device (MAC de:ad:be:ef:00:66) is pretending to be your router. Sentinel-X is blocking it."`
- **Unprotected (Amber)**: `"Not protected - your router didn't answer"`
- **Conflict (Amber)**: `"Conflict - two devices claim to be your router; nothing was pinned"`
- **Integrity Badges**: `"Verified, N entries"` / `"TAMPERED at entry #k"`

---

## Controls
- **Space**: Play / Pause
- **Left Arrow**: Previous step
- **Right Arrow**: Next step
- **R**: Reset chapter
- **1-8**: Jump to chapters 0-7

---

## Key Engineering Decisions
- **Pure JS SHA-256**: Implemented synchronously without WebCrypto so that hashing and verification run identically in Node.js test suites and in browsers without async overhead.
- **Canonical JSON (RFC 8785 subset)**: Keys sorted recursively with no whitespace, ensuring reproducible hashing across environments.
- **Reversible Time-Travel Reducer**: The UI computes current state by reducing all events up to the selected step, guaranteeing that clicking Back always restores the exact prior state without desynchronization.
- **Corner-Docked Host Cards**: Cards are placed in the four corners (Bystander top-left, Router top-right, Victim bottom-left, Attacker bottom-right), keeping the 3D center viewport 100% unobstructed.
