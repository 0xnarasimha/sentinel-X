# Sentinel-X Interactive 3D Simulation

**Live demo:** [https://sentinel-x-interactive-explainer.vercel.app](https://sentinel-x-interactive-explainer.vercel.app)

An interactive 3D teaching simulation for the **Sentinel-X** project — a host-level defense daemon that protects Linux workstations against **ARP-poisoning / MITM attacks** and writes a **tamper-evident, hash-chained incident log**.

Built as an AI Studio prototype, then made production-deployable (static Vite build, dependency fixes, review hardening).

---

## The Simulation Concept

The sim walks a small LAN (Router ⇄ Switch ⇄ Victim ⇄ Attacker ⇄ Bystander, rendered in Three.js) through a story in three acts:

| Stage | What happens |
|---|---|
| **1 · The attack (ARP poisoning)** | The attacker floods a forged ARP reply ("10.77.0.1 is-at de:ad:be:ef:00:66") to the victim. Sent to the broadcast/switch path, the packet overrides the victim's kernel ARP cache — the real router MAC `aa:bb:cc:00:00:01` is replaced with the attacker's MAC. All of the victim's traffic now flows through the attacker (MITM). Without Sentinel-X you watch the cache get poisoned live, including the switch port LEDs flashing and the packet capture log filling up. |
| **2 · Sentinel-X detection & auto-heal** | With Sentinel-X enabled, a pure state-machine engine (`WAITING_NET → TOFU → MONITOR → CONFLICT / UNPROTECTED`) sniffs ARP packets. Rule **R1** fires when a sender claims the gateway IP with a MAC that doesn't match the first-seen (TOFU — *Trust On First Use*) learned gateway MAC. The executor then **auto-heals**: re-pins the real gateway MAC (`ip neigh replace … nud permanent`) and unicasts a corrective ARP both ways so the router and victim also repair their caches. Cooldowns throttle corrective ARPs; incidents aggregate packets and close after idle. |
| **3 · Tamper-evident logging** | Every detect/heal event is appended to a **SHA-256 hash chain** (genesis → block(n), each block hashing `prev + canonicalJSON`). The sandbox lets you verify the chain, edit a field, delete a middle block, or truncate the tail — you can watch tampering break hashes and prev-pointers (and learn the known limit: tail truncation goes unnoticed without an external anchor). |

Every packet is animated, every cache row, engine decision line, and chain block updates in real time, and each chapter ends with the **real kernel commands** the defender would run (`ip neigh show`, `arping`, `ip neigh replace`…).

### Chapters

0. **Cast & Map** — the switched LAN, ARP caches, and switch unicast isolation.
1. **Normal ARP** — broadcast request → unicast reply → dynamic cache learning.
2. **The Attack (Unprotected)** — forged ARP reply poisons the victim's cache; attacker captures all traffic.
3. **Learning Router (TOFU)** — Sentinel-X probes the gateway and pins the first-seen MAC (trust-on-first-use).
4. **Defended (pin_mode always)** — live attack attempt → Rule R1 detection → instant heal with a corrective ARP.
5. **pin_mode on_detect** — the alternate strategy: dynamic cache until detection, then pin.
6. **Tamper-Evident Log** — SHA-256 hash chain under the hood; verify, edit, delete-middle, delete-last.
7. **Edge Cases & Limits** — TOFU conflicts, virtual gateway MACs (VRRP/HSRP), tail-truncation blind spot, network changes.

### Sandbox Tools

- **Inject Forged Reply Now** — manually fire an attack at any step (with Sentinel-X on *or* off).
- **Sentinel-X toggle / pin-mode selector** — flip `always` vs `on_detect` pinning.
- **Verify Chain / Tamper Field / Delete Middle / Delete Last** — hands-on tamper-evidence lab.
- **Step scrubber, play/pause, speed control, camera presets** — teach it at your own pace.

---

## Run Locally

```bash
npm install
npm run dev        # http://localhost:3000
# or fully offline, zero build:
cd public/sim
python3 -m http.server 8000   # http://localhost:8000/sim/index.html
```

## Build & Test

```bash
npm run build      # dist/ = thin React shell + full static sim/
npm test           # node --test  → 31 tests (9 chain + 22 engine), pure Node, no deps
```

## Structure

```
index.html, src/            thin React 19 + Vite 8 shell that iframes the sim
public/sim/                 the real app — zero-build vanilla Three.js + ES modules
├── index.html              importmap: three → vendor/, addons → vendor/
├── src/
│   ├── main.js             app coordinator (chapters, scrubbing, sandbox replay cache)
│   ├── scene.js            3D topology, packets, LEDs, disposal
│   ├── ui.js               HUD: cache cards, engine trace, chain strip, tooltips
│   ├── engine.js           pure Sentinel-X state machine (TOFU / R1 / heal)
│   ├── chain.js            pure SHA-256 + canonical-JSON hash chain
│   ├── chapters.js         10 chapter script definitions
│   └── timeline.js         deterministic state reducer (step N = reduce steps 0..N)
├── test/                   node:test suites for engine + chain
└── vendor/                 three.js 0.186.1 + OrbitControls + CSS2DRenderer + RoomEnvironment
```

## Deployment Notes / Fixes vs the Original Export

- Original AI Studio zip was missing **`vendor/three.core.js`** — three.js r186 splits its build, and its absence killed the whole ES-module graph (blank page). The exact matching 0.186.1 file is committed here.
- `esbuild@^0.28.2` pinned to satisfy `vite@8`'s peer range (the `tsx` dev-tooling that pinned 0.25 was unused and pruned).
- Dependency tree pruned to what's actually used (React shell only; no `express`/`genai`/`dotenv` — the app is 100% static, no API keys).
- Review hardening (heal-gating on TOFU learn, sandbox event replay cache, GPU disposal, `escapeHTML`, chain genesis guard) is applied; tests pin it.

## License / Acknowledgement

Simulation content generated with Google AI Studio; engine logic follows the Sentinel-X Specification 1.6/1.7 from the project's pitch materials. All 3D assets are procedural; no external network calls at runtime.
