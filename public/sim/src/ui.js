/**
 * User Interface & HUD Module for Sentinel-X Simulation.
 * Renders Host ARP Cards, Sentinel-X Engine Card, Tamper-Evident Log Strip,
 * Captions, Status Banners, and Interactive Playback Controls.
 */

import { verifyChain } from './chain.js';

export const HOST_TOOLTIP_DELAY_MS = 300;

/**
 * Pure timer controller for host card tooltips with a 300ms hover delay
 * and immediate cancellation on pointer leave or rapid camera movement.
 */
export function createHostTooltipController({
  delayMs = HOST_TOOLTIP_DELAY_MS,
  onShow,
  onHide,
  setTimer = (fn, ms) => setTimeout(fn, ms),
  clearTimer = (id) => clearTimeout(id)
} = {}) {
  let timerId = null;
  let activeTargetId = null;
  let visible = false;
  let activeText = '';

  function cancelTimer() {
    if (timerId !== null) {
      clearTimer(timerId);
      timerId = null;
    }
  }

  function hoverEnter(targetId, text, element = null) {
    cancelTimer();
    activeTargetId = targetId;
    activeText = text || '';
    if (visible) {
      visible = false;
      onHide?.();
    }
    if (!activeText) return;
    timerId = setTimer(() => {
      timerId = null;
      visible = true;
      onShow?.({ targetId: activeTargetId, text: activeText, element });
    }, delayMs);
  }

  function hoverLeave() {
    cancelTimer();
    activeTargetId = null;
    activeText = '';
    if (visible) {
      visible = false;
      onHide?.();
    }
  }

  function cancelOnCameraMove() {
    hoverLeave();
  }

  function getState() {
    return {
      pending: timerId !== null,
      visible,
      activeTargetId,
      activeText,
      delayMs
    };
  }

  return {
    hoverEnter,
    hoverLeave,
    cancelOnCameraMove,
    getState
  };
}

export function formatChainBlockData(data) {
  if (!data) return '{}';
  if (data.message) return data.message;
  if (data.gateway_mac) return `gw=${data.gateway_mac.slice(-8)}`;
  if (data.src_mac) return `src=${data.src_mac.slice(-8)}`;
  if (data.rule) return `rule=${data.rule}`;
  if (data.verified !== undefined) return `verified=${data.verified}`;
  if (data.conflicting_macs) return `conflicts=${data.conflicting_macs.length}`;
  return JSON.stringify(data).substring(0, 28);
}

/**
 * Pure predicate that checks whether a log chain block matches a search query
 * by event type, block index, formatted data summary, or raw JSON data fields.
 */
export function matchesChainBlockQuery(block, query) {
  const q = String(query || '').trim().toLowerCase();
  if (!q) return true;
  if (!block) return false;
  const typeStr = String(block.type || '').toLowerCase();
  const idxStr = `#${block.idx}`;
  const formattedData = formatChainBlockData(block.data).toLowerCase();
  const rawData = JSON.stringify(block.data || {}).toLowerCase();
  const kvPairs = block.data && typeof block.data === 'object'
    ? Object.entries(block.data).map(([k, v]) => `${k}=${v}`).join(' ').toLowerCase()
    : '';
  return (
    typeStr.includes(q) ||
    idxStr.includes(q) ||
    formattedData.includes(q) ||
    rawData.includes(q) ||
    kvPairs.includes(q)
  );
}

/**
 * Pure filter returning only log chain blocks that match the search query.
 */
export function filterChainBlocks(chain, query) {
  if (!Array.isArray(chain)) return [];
  const q = String(query || '').trim();
  if (!q) return chain.slice();
  return chain.filter((block) => matchesChainBlockQuery(block, q));
}

export class SimulationUI {
  constructor(container, callbacks) {
    this.container = container;
    this.callbacks = callbacks || {};
    this.chainSearchQuery = '';
    this.currentChain = [];

    this.tooltipController = createHostTooltipController({
      delayMs: HOST_TOOLTIP_DELAY_MS,
      onShow: ({ targetId, text, element }) => this.showHostTooltip(targetId, text, element),
      onHide: () => this.hideHostTooltip()
    });

    this.initDOM();
    this.bindEvents();
  }

  initDOM() {
    this.container.innerHTML = `
      <!-- Top Header & Banner -->
      <header class="hud-top" role="banner">
        <div class="brand">
          <div class="logo-shield"></div>
          <div>
            <h1>SENTINEL-X <span class="tag-version">DAEMON SIMULATOR</span></h1>
            <p class="subtitle">Host-Level Defense & Tamper-Evident Logging</p>
          </div>
        </div>

        <!-- Dashboard Status Banner (Section 1.9) -->
        <div id="status-banner" class="status-banner banner-neutral" role="status" aria-live="polite">
          <span class="banner-icon">●</span>
          <span id="banner-text">Waiting for network activity...</span>
        </div>

        <div class="top-meta">
          <span class="badge-illustrative" title="Illustrative network simulation">Simplified model - timings are illustrative</span>
          <button id="btn-legend" class="btn-subtle" aria-label="Toggle Legend">Legend [?]</button>
        </div>
      </header>

      <!-- Main Layout -->
      <div class="hud-main">
        <!-- Left Sidebar: Chapter Selection -->
        <nav class="sidebar-chapters" aria-label="Simulation Chapters">
          <div class="sidebar-header">Chapters</div>
          <ul id="chapter-list" class="chapter-nav-list" role="tablist">
            <!-- Rendered dynamically -->
          </ul>

          <div class="sidebar-divider"></div>
          <div class="sidebar-header">Interactive Sandbox</div>
          <div class="sandbox-controls">
            <button id="sb-attack-btn" class="btn-danger-outline" title="Trigger attacker arpspoof forged reply">
              ⚡ Inject Forged Reply Now
            </button>
            <div class="sandbox-toggle-row">
              <label for="sb-sentinel-toggle">Sentinel-X Defense:</label>
              <input type="checkbox" id="sb-sentinel-toggle" checked />
            </div>
            <div class="sandbox-toggle-row">
              <label for="sb-pinmode-select">Pin Mode:</label>
              <select id="sb-pinmode-select">
                <option value="always">always (pin at TOFU)</option>
                <option value="on_detect">on_detect (pin upon alert)</option>
              </select>
            </div>
          </div>
        </nav>

        <!-- Center 3D Viewport Area overlayed with Host Cards -->
        <main class="viewport-overlay" aria-label="3D Network Overlay">
          <!-- Router Host Card -->
          <section id="card-router" class="host-card card-router" aria-label="Router Status" data-tooltip="Default Gateway (10.77.0.1) — Routes subnet traffic to the Internet; target of bidirectional ARP cache poisoning.">
            <div class="host-card-tooltip" role="tooltip" aria-hidden="true">Default Gateway (10.77.0.1) — Routes subnet traffic to the Internet; target of bidirectional ARP cache poisoning.</div>
            <div class="card-title">
              <span class="host-name">Router (Gateway)</span>
              <span class="host-badge">10.77.0.1</span>
            </div>
            <div class="host-mac">MAC: <code id="router-mac">aa:bb:cc:00:00:01</code></div>
            <div class="cache-section">
              <div class="cache-title">ARP Cache:</div>
              <div id="router-cache-rows" class="cache-rows">
                <div class="cache-empty">Empty</div>
              </div>
            </div>
          </section>

          <!-- Victim Host & Sentinel-X Card -->
          <section id="card-victim" class="host-card card-victim" aria-label="Victim Laptop Status" data-tooltip="Protected Host (10.77.0.10) — Runs Sentinel-X daemon; locks gateway MAC as PERMANENT in kernel neighbour table.">
            <div class="host-card-tooltip" role="tooltip" aria-hidden="true">Protected Host (10.77.0.10) — Runs Sentinel-X daemon; locks gateway MAC as PERMANENT in kernel neighbour table.</div>
            <div class="card-title">
              <span class="host-name">Victim Laptop</span>
              <span class="host-badge badge-victim">10.77.0.10</span>
            </div>
            <div class="host-mac">MAC: <code id="victim-mac">aa:bb:cc:00:00:10</code></div>
            
            <!-- Victim ARP Cache -->
            <div class="cache-section">
              <div class="cache-title">Kernel ARP Table:</div>
              <div id="victim-cache-rows" class="cache-rows">
                <div class="cache-empty">Empty</div>
              </div>
              <div id="refused-note" class="refused-note hidden">update refused: PERMANENT</div>
            </div>

            <!-- Sentinel-X Mini Pipeline -->
            <div class="sentinel-panel">
              <div class="sentinel-header">
                <span class="sentinel-title">Sentinel-X Agent</span>
                <span id="sentinel-state-pill" class="state-pill state-waiting">WAITING_NET</span>
              </div>
              <div class="pinned-row">
                Pinned Gateway: <code id="sentinel-pinned-mac">None</code>
              </div>
              <!-- Pipeline: Sniffer -> Engine -> Executor -->
              <div class="pipeline-row">
                <div id="pipe-sniffer" class="pipe-node" data-tooltip="Sniffer: Captures Layer-2 ARP frames only">Sniffer</div>
                <div class="pipe-arrow">→</div>
                <div id="pipe-engine" class="pipe-node" data-tooltip="Engine: Pure State Machine evaluating Rule R1">Engine</div>
                <div class="pipe-arrow">→</div>
                <div id="pipe-executor" class="pipe-node" data-tooltip="Executor: Pins kernel cache & sends corrective ARP">Executor</div>
              </div>
              <!-- Engine Reasoning Trace -->
              <div class="reasoning-box">
                <div class="reasoning-title">Engine Reasoning Trace:</div>
                <div id="engine-reasoning-lines" class="reasoning-lines">
                  <span class="trace-idle">Awaiting ARP frame...</span>
                </div>
              </div>
            </div>
          </section>

          <!-- Attacker Host Card -->
          <section id="card-attacker" class="host-card card-attacker" aria-label="Attacker Machine Status" data-tooltip="MITM Attacker (10.77.0.66) — Sends forged ARP replies claiming to be the gateway and victim with IP forwarding ON.">
            <div class="host-card-tooltip" role="tooltip" aria-hidden="true">MITM Attacker (10.77.0.66) — Sends forged ARP replies claiming to be the gateway and victim with IP forwarding ON.</div>
            <div class="card-title">
              <span class="host-name">Attacker Node</span>
              <span class="host-badge badge-attacker">10.77.0.66</span>
            </div>
            <div class="host-mac">MAC: <code id="attacker-mac">de:ad:be:ef:00:66</code></div>
            <div class="attacker-sub">arpspoof running • IP forwarding ON</div>
            <div class="capture-section">
              <div class="cache-title">Attacker Packet Capture Log:</div>
              <div id="attacker-capture-rows" class="capture-rows">
                <div class="capture-empty">No intercepted traffic</div>
              </div>
            </div>
          </section>

          <!-- Bystander Host Card -->
          <section id="card-bystander" class="host-card card-bystander" aria-label="Bystander Peer Status" data-tooltip="Uninvolved LAN Peer (10.77.0.20) — Harmless peer whose ARP frames never trigger Sentinel-X Rule R1.">
            <div class="host-card-tooltip" role="tooltip" aria-hidden="true">Uninvolved LAN Peer (10.77.0.20) — Harmless peer whose ARP frames never trigger Sentinel-X Rule R1.</div>
            <div class="card-title">
              <span class="host-name">Bystander Peer</span>
              <span class="host-badge">10.77.0.20</span>
            </div>
            <div class="host-mac">MAC: <code id="bystander-mac">aa:bb:cc:00:00:20</code></div>
            <div class="cache-section">
              <div class="cache-title">ARP Cache:</div>
              <div id="bystander-cache-rows" class="cache-rows">
                <div class="cache-empty">Empty</div>
              </div>
            </div>
          </section>
        </main>

        <!-- Right Sidebar: Captions & Real-World Command Equivalent -->
        <aside class="sidebar-captions" aria-label="Step Explanation">
          <div class="caption-card">
            <div class="step-counter">
              <span id="step-number">Step 1 of 4</span>
              <span id="step-title" class="step-title">Cast Overview</span>
            </div>
            <p id="caption-text" class="caption-body">
              Loading chapter information...
            </p>
            <div class="real-world-box">
              <div class="rw-label">Real-World Command / Equivalent:</div>
              <code id="real-world-code">ip neigh show</code>
            </div>
          </div>

          <!-- Tamper-Evident Log Strip Area -->
          <section class="log-chain-card" aria-label="Tamper-Evident Hash Chain Log">
            <div class="chain-header">
              <div class="chain-title-row">
                <span class="chain-title">Sentinel-X Log (log.jsonl)</span>
                <span id="chain-badge" class="integrity-badge badge-verified">Verified, 1 entry</span>
              </div>
              <p class="chain-desc">Every event is hashed into a SHA-256 tamper-evident chain.</p>
            </div>
            
            <!-- Chain Interactive Actions (Chapter 6 & General) -->
            <div class="chain-actions">
              <button id="btn-verify-chain" class="btn-action">Verify Chain</button>
              <button id="btn-tamper-edit" class="btn-action btn-tamper" title="Simulate attacker editing entry #1">Tamper Field</button>
              <button id="btn-tamper-delete-middle" class="btn-action btn-tamper" title="Delete middle entry">Delete Middle</button>
              <button id="btn-tamper-delete-tail" class="btn-action btn-tamper" title="Delete last entry (Known limit)">Delete Last</button>
            </div>

            <!-- Real-Time Log Filter Search Input -->
            <div class="chain-search-bar">
              <input
                type="search"
                id="chain-search-input"
                class="chain-search-input"
                placeholder="Filter by type or data (e.g. detect, gw=, ef:00:66)..."
                aria-label="Filter log entries by type or data content"
                autocomplete="off"
              />
              <span id="chain-search-count" class="chain-search-count hidden" aria-live="polite"></span>
              <button
                type="button"
                id="chain-search-clear"
                class="chain-search-clear hidden"
                aria-label="Clear log filter"
                title="Clear filter"
              >&times;</button>
            </div>

            <!-- Horizontal Block Strip -->
            <div id="chain-strip" class="chain-strip">
              <!-- Rendered dynamically -->
            </div>
            <div id="chain-filter-empty" class="chain-filter-empty hidden" role="status">
              No log entries match filter.
            </div>
            <div id="chain-result-msg" class="chain-result-msg hidden"></div>
          </section>
        </aside>
      </div>

      <!-- Bottom Floating Control Dock (Collapsed/Expanded according to guidelines) -->
      <footer class="dock-container" role="toolbar" aria-label="Playback Controls">
        <div class="dock-bar">
          <div class="dock-group">
            <button id="btn-prev" class="btn-dock" aria-label="Previous Step">&lt; Prev</button>
            <button id="btn-play" class="btn-dock btn-primary" aria-label="Play / Pause">Play &gt;</button>
            <button id="btn-next" class="btn-dock" aria-label="Next Step">Next &gt;</button>
            <button id="btn-reset" class="btn-dock" aria-label="Reset Chapter">Reset</button>
          </div>

          <!-- Step Scrubber -->
          <div class="scrub-container">
            <input type="range" id="scrub-bar" min="0" max="0" value="0" step="1" aria-label="Timeline Step Scrubber" />
            <div id="scrub-ticks" class="scrub-ticks"></div>
          </div>

          <!-- Speed & Camera Presets -->
          <div class="dock-group">
            <div class="speed-selector">
              <label for="speed-select" class="dock-label">Speed:</label>
              <select id="speed-select">
                <option value="0.5">0.5x</option>
                <option value="1" selected>1.0x</option>
                <option value="1.5">1.5x</option>
                <option value="2">2.0x</option>
              </select>
            </div>

            <div class="cam-presets">
              <button class="btn-cam" data-cam="overview">Overview</button>
              <button class="btn-cam" data-cam="victim">Victim</button>
              <button class="btn-cam" data-cam="router">Router</button>
              <button class="btn-cam" data-cam="attacker">Attacker</button>
              <button class="btn-cam" data-cam="log">Log</button>
            </div>
          </div>
        </div>
      </footer>

      <!-- Legend Modal / Drawer -->
      <div id="legend-modal" class="legend-modal hidden" role="dialog" aria-label="Simulation Legend">
        <div class="legend-content">
          <div class="legend-header">
            <h3>Visual & Packet Legend</h3>
            <button id="btn-close-legend" class="btn-close" aria-label="Close Legend">&times;</button>
          </div>
          <div class="legend-grid">
            <div class="legend-item">
              <span class="legend-swatch leg-arp-ok"></span>
              <div>
                <strong>Legitimate ARP</strong>
                <p>Green solid envelope. Normal resolution.</p>
              </div>
            </div>
            <div class="legend-item">
              <span class="legend-swatch leg-arp-fake"></span>
              <div>
                <strong>Forged ARP (Attack)</strong>
                <p>Red dashed envelope with "FAKE" tag.</p>
              </div>
            </div>
            <div class="legend-item">
              <span class="legend-swatch leg-probe"></span>
              <div>
                <strong>TOFU Probe</strong>
                <p>Amber envelope. Initial gateway learning.</p>
              </div>
            </div>
            <div class="legend-item">
              <span class="legend-swatch leg-corrective"></span>
              <div>
                <strong>Corrective ARP</strong>
                <p>Teal envelope. Repairs router cache.</p>
              </div>
            </div>
            <div class="legend-item">
              <span class="legend-swatch leg-data"></span>
              <div>
                <strong>Data Packet</strong>
                <p>Blue sphere. Application payload.</p>
              </div>
            </div>
            <div class="legend-item">
              <span class="legend-swatch leg-permanent"></span>
              <div>
                <strong>PERMANENT Cache</strong>
                <p>Pinned entry immune to received ARP replies.</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  bindEvents() {
    // Playback buttons
    document.getElementById('btn-prev').addEventListener('click', () => this.callbacks.onPrevStep?.());
    document.getElementById('btn-next').addEventListener('click', () => this.callbacks.onNextStep?.());
    document.getElementById('btn-play').addEventListener('click', () => this.callbacks.onTogglePlay?.());
    document.getElementById('btn-reset').addEventListener('click', () => this.callbacks.onReset?.());

    // Scrub bar
    document.getElementById('scrub-bar').addEventListener('input', (e) => {
      this.callbacks.onScrubTo?.(parseInt(e.target.value, 10));
    });

    // Speed select
    document.getElementById('speed-select').addEventListener('change', (e) => {
      this.callbacks.onSpeedChange?.(parseFloat(e.target.value));
    });

    // Camera presets
    document.querySelectorAll('.btn-cam').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const cam = e.currentTarget.getAttribute('data-cam');
        this.callbacks.onCameraPreset?.(cam);
      });
    });

    // Legend toggle
    const legendModal = document.getElementById('legend-modal');
    document.getElementById('btn-legend').addEventListener('click', () => {
      legendModal.classList.toggle('hidden');
    });
    document.getElementById('btn-close-legend').addEventListener('click', () => {
      legendModal.classList.add('hidden');
    });

    // Sandbox actions
    document.getElementById('sb-attack-btn')?.addEventListener('click', () => {
      this.callbacks.onSandboxAttack?.();
    });
    document.getElementById('sb-sentinel-toggle')?.addEventListener('change', (e) => {
      this.callbacks.onSandboxSentinelToggle?.(e.target.checked);
    });
    document.getElementById('sb-pinmode-select')?.addEventListener('change', (e) => {
      this.callbacks.onSandboxPinModeChange?.(e.target.value);
    });

    // Chain tamper actions
    document.getElementById('btn-verify-chain')?.addEventListener('click', () => {
      this.callbacks.onVerifyChainClick?.();
    });
    document.getElementById('btn-tamper-edit')?.addEventListener('click', () => {
      this.callbacks.onTamperEditClick?.();
    });
    document.getElementById('btn-tamper-delete-middle')?.addEventListener('click', () => {
      this.callbacks.onTamperDeleteMiddleClick?.();
    });
    document.getElementById('btn-tamper-delete-tail')?.addEventListener('click', () => {
      this.callbacks.onTamperDeleteTailClick?.();
    });

    // Real-time chain search filter
    const searchInput = document.getElementById('chain-search-input');
    const clearBtn = document.getElementById('chain-search-clear');
    searchInput?.addEventListener('input', (e) => {
      this.chainSearchQuery = e.target.value || '';
      this.applyChainFilter();
    });
    clearBtn?.addEventListener('click', () => {
      if (searchInput) {
        searchInput.value = '';
        searchInput.focus();
      }
      this.chainSearchQuery = '';
      this.applyChainFilter();
    });

    // Host card 300ms delayed tooltips
    this.container.querySelectorAll('.host-card').forEach((card) => {
      card.addEventListener('pointerenter', () => {
        const text = card.getAttribute('data-tooltip');
        this.tooltipController.hoverEnter(card.id, text, card);
      });
      card.addEventListener('pointerleave', () => {
        this.tooltipController.hoverLeave();
      });
    });

    // Sub-element tooltips inside host cards (e.g. pipeline stages) also use 300ms delay
    this.container.querySelectorAll('.host-card [data-tooltip]').forEach((node) => {
      node.addEventListener('pointerenter', (e) => {
        e.stopPropagation();
        const card = node.closest('.host-card');
        const text = node.getAttribute('data-tooltip');
        if (card && text) {
          this.tooltipController.hoverEnter(node.id || card.id, text, card);
        }
      });
      node.addEventListener('pointerleave', (e) => {
        e.stopPropagation();
        const card = node.closest('.host-card');
        if (card) {
          const text = card.getAttribute('data-tooltip');
          this.tooltipController.hoverEnter(card.id, text, card);
        } else {
          this.tooltipController.hoverLeave();
        }
      });
    });

    // Keyboard shortcuts
    window.addEventListener('keydown', (e) => {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') return;
      if (e.code === 'Space') {
        e.preventDefault();
        this.callbacks.onTogglePlay?.();
      } else if (e.code === 'ArrowLeft') {
        e.preventDefault();
        this.callbacks.onPrevStep?.();
      } else if (e.code === 'ArrowRight') {
        e.preventDefault();
        this.callbacks.onNextStep?.();
      } else if (e.code === 'KeyR') {
        this.callbacks.onReset?.();
      } else if (e.key >= '0' && e.key <= '7') {
        const chId = parseInt(e.key, 10);
        this.callbacks.onSelectChapter?.(chId);
      }
    });
  }

  showHostTooltip(targetId, text, cardElement) {
    this.hideHostTooltip();
    const card = cardElement || document.getElementById(targetId);
    if (!card) return;
    const tooltipEl = card.querySelector('.host-card-tooltip');
    if (tooltipEl) {
      tooltipEl.textContent = text;
      tooltipEl.classList.add('tooltip-visible');
      tooltipEl.setAttribute('aria-hidden', 'false');
    }
    card.setAttribute('data-tooltip-active', 'true');
  }

  hideHostTooltip() {
    this.container.querySelectorAll('.host-card-tooltip').forEach((el) => {
      el.classList.remove('tooltip-visible');
      el.setAttribute('aria-hidden', 'true');
    });
    this.container.querySelectorAll('.host-card[data-tooltip-active]').forEach((card) => {
      card.removeAttribute('data-tooltip-active');
    });
  }

  cancelTooltipsForCameraMove() {
    this.tooltipController.cancelOnCameraMove();
  }

  renderChapterList(chapters, currentChapterId) {
    const list = document.getElementById('chapter-list');
    list.innerHTML = '';
    chapters.forEach(ch => {
      const li = document.createElement('li');
      li.className = `chapter-nav-item ${ch.id === currentChapterId ? 'active' : ''}`;
      li.innerHTML = `
        <button class="chapter-btn" aria-selected="${ch.id === currentChapterId}">
          <span class="ch-num">${ch.title}</span>
          <span class="ch-sub">${ch.subtitle}</span>
        </button>
      `;
      li.querySelector('button').addEventListener('click', () => {
        this.callbacks.onSelectChapter?.(ch.id);
      });
      list.appendChild(li);
    });
  }

  updatePlaybackState(isPlaying) {
    const btn = document.getElementById('btn-play');
    if (isPlaying) {
      btn.textContent = 'Pause ❚❚';
      btn.classList.add('btn-pause');
    } else {
      btn.textContent = 'Play ▸';
      btn.classList.remove('btn-pause');
    }
  }

  renderState(state, chapter) {
    // 1. Dashboard Banner
    const banner = state.banner;
    const bannerEl = document.getElementById('status-banner');
    const bannerText = document.getElementById('banner-text');
    bannerEl.className = `status-banner banner-${banner.severity}`;
    bannerText.textContent = banner.text;

    // 2. Caption Panel
    const step = state.currentStep;
    document.getElementById('step-number').textContent = `Step ${state.stepIndex + 1} of ${state.totalSteps}`;
    document.getElementById('step-title').textContent = step.title || '';
    document.getElementById('caption-text').textContent = step.caption || '';
    document.getElementById('real-world-code').textContent = step.realWorldEquivalent || 'ip neigh show';

    // 3. Scrubber Bar & Step Ticks
    const scrub = document.getElementById('scrub-bar');
    scrub.max = Math.max(0, state.totalSteps - 1);
    scrub.value = state.stepIndex;
    this.renderScrubTicks(state.totalSteps, state.stepIndex);

    // 4. Host Cache Cards
    this.renderCacheRows('router-cache-rows', state.hosts.router.cache);
    this.renderCacheRows('victim-cache-rows', state.hosts.victim.cache);
    this.renderCacheRows('bystander-cache-rows', state.hosts.bystander.cache);

    // Refused note
    const refNote = document.getElementById('refused-note');
    if (state.refusedNote) {
      refNote.textContent = state.refusedNote;
      refNote.classList.remove('hidden');
    } else {
      refNote.classList.add('hidden');
    }

    // 5. Sentinel-X Panel
    const statePill = document.getElementById('sentinel-state-pill');
    statePill.textContent = state.engine.state;
    statePill.className = `state-pill state-${state.engine.state.toLowerCase()}`;

    const pinnedEl = document.getElementById('sentinel-pinned-mac');
    pinnedEl.textContent = state.engine.pinned_mac || (state.engine.learned_gateway_mac ? `${state.engine.learned_gateway_mac} (unpinned)` : 'None');

    // Pipeline Stage LEDs
    document.getElementById('pipe-sniffer').classList.toggle('active', state.pipeline.sniffer);
    document.getElementById('pipe-engine').classList.toggle('active', state.pipeline.engine);
    document.getElementById('pipe-executor').classList.toggle('active', state.pipeline.executor);

    // Reasoning Trace
    const reasonBox = document.getElementById('engine-reasoning-lines');
    if (state.reasoning && state.reasoning.length > 0) {
      reasonBox.innerHTML = state.reasoning.map(line => `<div class="trace-line">${this.escapeHTML(line)}</div>`).join('');
    } else {
      reasonBox.innerHTML = '<span class="trace-idle">No recent ARP packets evaluated</span>';
    }

    // 6. Attacker Capture Log Card (Honest rows from 1.5)
    this.renderAttackerCapture(state.captureList);

    // 7. Hash Chain Strip
    this.renderChainStrip(state.chain);
  }

  renderScrubTicks(totalSteps, activeIndex) {
    const ticksEl = document.getElementById('scrub-ticks');
    if (!ticksEl) return;
    if (totalSteps <= 1) {
      ticksEl.innerHTML = '';
      return;
    }
    const items = [];
    for (let i = 0; i < totalSteps; i++) {
      const stateClass = i === activeIndex ? 'tick-active' : (i < activeIndex ? 'tick-done' : '');
      items.push(`<span class="scrub-tick ${stateClass}" title="Step ${i + 1}"></span>`);
    }
    ticksEl.innerHTML = items.join('');
  }

  renderCacheRows(containerId, cacheObj) {
    const el = document.getElementById(containerId);
    const keys = Object.keys(cacheObj || {});
    if (keys.length === 0) {
      el.innerHTML = '<div class="cache-empty">No active entries</div>';
      return;
    }
    el.innerHTML = keys.map(ip => {
      const entry = cacheObj[ip];
      const isPermanent = entry.state === 'PERMANENT';
      const isPoisoned = entry.mac === 'de:ad:be:ef:00:66';
      const badgeClass = isPermanent ? 'badge-permanent' : (isPoisoned ? 'badge-poisoned' : 'badge-reachable');
      return `
        <div class="cache-row ${isPoisoned ? 'row-poisoned' : (isPermanent ? 'row-permanent' : '')}">
          <span class="row-ip">${this.escapeHTML(ip)}</span>
          <span class="row-arrow">→</span>
          <span class="row-mac">${this.escapeHTML(entry.mac)}</span>
          <span class="row-state ${badgeClass}">${this.escapeHTML(entry.state)}</span>
        </div>
      `;
    }).join('');
  }

  renderAttackerCapture(captureList) {
    const el = document.getElementById('attacker-capture-rows');
    if (!captureList || captureList.length === 0) {
      el.innerHTML = '<div class="capture-empty">Attacker port dark (0 packets seen)</div>';
      return;
    }
    el.innerHTML = captureList.map(item => {
      const isEncrypted = item.tag.includes('encrypted');
      return `
        <div class="capture-item ${isEncrypted ? 'capture-encrypted' : 'capture-readable'}">
          <span class="cap-proto">${this.escapeHTML(item.protocol)}</span>
          <span class="cap-desc">${this.escapeHTML(item.desc)}</span>
          <span class="cap-tag">[${this.escapeHTML(item.tag)}]</span>
        </div>
      `;
    }).join('');
  }

  createChainBlockElement(block, isTampered, isNewAppend) {
    const div = document.createElement('div');
    const typeClass = `b-type-${String(block.type || 'event').replace(/[^a-z0-9_-]/gi, '').toLowerCase()}`;
    div.className = `chain-block${isTampered ? ' block-tampered' : ''}${isNewAppend ? ' chain-block-enter' : ''}`;
    div.setAttribute('data-idx', String(block.idx));
    div.setAttribute('data-sig', `${block.idx}:${block.type}:${block.hash}:${block.prev}:${JSON.stringify(block.data)}`);
    div.innerHTML = `
      <div class="block-top">
        <span class="b-idx">#${block.idx}</span>
        <span class="b-type ${typeClass}">${this.escapeHTML(block.type)}</span>
      </div>
      <div class="b-data">${this.escapeHTML(this.formatBlockData(block.data))}</div>
      <div class="b-hash-row">
        <span class="b-hash-chip" title="Previous block SHA-256">prev ${block.prev.substring(0, 8)}…</span>
        <span class="b-hash-arrow">→</span>
        <span class="b-hash-chip b-hash-self" title="Current block SHA-256">sha256 ${block.hash.substring(0, 8)}…</span>
      </div>
    `;
    return div;
  }

  renderChainStrip(chain) {
    this.currentChain = Array.isArray(chain) ? chain : [];
    const strip = document.getElementById('chain-strip');
    const badge = document.getElementById('chain-badge');
    const resultMsg = document.getElementById('chain-result-msg');

    const verify = verifyChain(this.currentChain);
    if (verify.valid) {
      badge.className = 'integrity-badge badge-verified';
      badge.textContent = `Verified, ${this.currentChain.length} ${this.currentChain.length === 1 ? 'entry' : 'entries'}`;
      resultMsg.classList.add('hidden');
    } else {
      badge.className = 'integrity-badge badge-tampered';
      badge.textContent = `TAMPERED at entry #${verify.badIdx}`;
      resultMsg.className = 'chain-result-msg chain-err';
      resultMsg.textContent = `TAMPERED at entry #${verify.badIdx}: ${verify.reason}`;
      resultMsg.classList.remove('hidden');
    }

    const existingNodes = Array.from(strip.querySelectorAll('.chain-block'));
    const prevCount = existingNodes.length;

    // Remove excess nodes if chain was reset or truncated
    while (existingNodes.length > this.currentChain.length) {
      const removed = existingNodes.pop();
      removed.remove();
    }

    let appendedAny = false;
    this.currentChain.forEach((block, idx) => {
      const isTampered = !verify.valid && idx >= verify.badIdx;
      const sig = `${block.idx}:${block.type}:${block.hash}:${block.prev}:${JSON.stringify(block.data)}`;
      const existing = existingNodes[idx];

      if (existing) {
        if (existing.getAttribute('data-sig') !== sig) {
          const replacement = this.createChainBlockElement(block, isTampered, false);
          strip.replaceChild(replacement, existing);
        } else {
          existing.classList.toggle('block-tampered', isTampered);
        }
      } else {
        const isDynamicAppend = prevCount > 0 && idx >= prevCount;
        const newBlockEl = this.createChainBlockElement(block, isTampered, isDynamicAppend);
        strip.appendChild(newBlockEl);
        appendedAny = true;
      }
    });

    this.applyChainFilter();

    if (appendedAny) {
      strip.scrollTop = strip.scrollHeight;
    }
  }

  applyChainFilter() {
    const strip = document.getElementById('chain-strip');
    const countEl = document.getElementById('chain-search-count');
    const clearBtn = document.getElementById('chain-search-clear');
    const emptyEl = document.getElementById('chain-filter-empty');
    if (!strip) return;

    const query = String(this.chainSearchQuery || '').trim();
    const hasQuery = query.length > 0;
    const blockNodes = Array.from(strip.querySelectorAll('.chain-block'));
    let matchCount = 0;

    blockNodes.forEach((node, idx) => {
      const block = this.currentChain[idx];
      const matched = matchesChainBlockQuery(block, query);
      node.classList.toggle('hidden', !matched);
      if (matched) matchCount++;
    });

    if (countEl) {
      if (hasQuery) {
        countEl.textContent = `${matchCount}/${blockNodes.length}`;
        countEl.classList.remove('hidden');
      } else {
        countEl.textContent = '';
        countEl.classList.add('hidden');
      }
    }

    if (clearBtn) {
      clearBtn.classList.toggle('hidden', !hasQuery);
    }

    if (emptyEl) {
      if (hasQuery && blockNodes.length > 0 && matchCount === 0) {
        emptyEl.textContent = `No log entries match "${query}"`;
        emptyEl.classList.remove('hidden');
      } else {
        emptyEl.classList.add('hidden');
      }
    }
  }

  showChainVerifyFeedback(verify) {
    const resultMsg = document.getElementById('chain-result-msg');
    resultMsg.classList.remove('hidden');
    if (verify.valid) {
      resultMsg.className = 'chain-result-msg chain-ok';
      resultMsg.textContent = `✓ Verification Passed: All ${verify.count} blocks cryptographic SHA-256 hashes & prev pointers valid.`;
    } else {
      resultMsg.className = 'chain-result-msg chain-err';
      resultMsg.textContent = `✗ TAMPERED at entry #${verify.badIdx}: ${verify.reason}`;
    }
  }

  showChainLimitMessage(count) {
    const resultMsg = document.getElementById('chain-result-msg');
    resultMsg.className = 'chain-result-msg chain-warn';
    resultMsg.textContent = `✓ Verification passes (${count} blocks)! Known Limit: Tail truncation goes unnoticed without an external anchor.`;
    resultMsg.classList.remove('hidden');
  }

  formatBlockData(data) {
    return formatChainBlockData(data);
  }

  escapeHTML(str) {
    if (!str) return '';
    return String(str).replace(/[&<>"']/g, m => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[m]));
  }
}

