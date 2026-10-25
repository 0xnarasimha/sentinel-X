/**
 * Sentinel-X Simulation Application Coordinator.
 * Coordinates SimScene, SimulationUI, Chapter Timeline Reducer, and Sandbox Engine.
 */

import { SimScene } from './scene.js';
import { SimulationUI } from './ui.js';
import { CHAPTERS } from './chapters.js';
import { getSimulationStateAtStep } from './timeline.js';
import { handleArpPacket, executeHeal } from './engine.js';
import { verifyChain, appendBlock } from './chain.js';

class SentinelSimulationApp {
  constructor() {
    this.canvasContainer = document.getElementById('scene-canvas-container');
    this.uiContainer = document.getElementById('ui-container');

    this.scene = new SimScene(this.canvasContainer, {
      onCameraMove: () => this.ui?.cancelTooltipsForCameraMove()
    });

    this.currentChapterId = 0;
    this.currentStepIndex = 0;
    this.isPlaying = false;
    this.playTimer = null;
    this.playbackSpeed = 1.0;

    // Sandbox state overrides
    this.sandboxSentinelEnabled = true;
    this.sandboxPinMode = 'always';

    // Sandbox event replay cache: injected attacks mutate transient state that
    // getSimulationStateAtStep() knows nothing about, so they must be re-applied
    // after every recomputed state or their chain blocks/banner silently vanish.
    // selectChapter() clears it: each chapter starts a fresh sandbox context.
    this.sandboxLog = []; // { packet, ts, sentinelEnabled }

    this.ui = new SimulationUI(this.uiContainer, {
      onSelectChapter: (id) => this.selectChapter(id),
      onNextStep: () => this.nextStep(),
      onPrevStep: () => this.prevStep(),
      onTogglePlay: () => this.togglePlay(),
      onReset: () => this.resetChapter(),
      onScrubTo: (idx) => this.goToStep(idx),
      onSpeedChange: (speed) => { this.playbackSpeed = speed; },
      onCameraPreset: (preset) => this.scene.setCameraPreset(preset),
      onSandboxAttack: () => this.triggerSandboxAttack(),
      onSandboxSentinelToggle: (enabled) => { this.sandboxSentinelEnabled = enabled; this.recomputeState(); },
      onSandboxPinModeChange: (mode) => { this.sandboxPinMode = mode; this.recomputeState(); },
      onVerifyChainClick: () => this.handleVerifyChain(),
      onTamperEditClick: () => this.handleTamperEdit(),
      onTamperDeleteMiddleClick: () => this.handleTamperDeleteMiddle(),
      onTamperDeleteTailClick: () => this.handleTamperDeleteTail()
    });

    this.ui.renderChapterList(CHAPTERS, this.currentChapterId);
    this.selectChapter(0);
  }

  getCurrentChapter() {
    return CHAPTERS.find(c => c.id === this.currentChapterId) || CHAPTERS[0];
  }

  selectChapter(chapterId) {
    this.pause();
    this.currentChapterId = chapterId;
    this.currentStepIndex = 0;
    this.sandboxLog = []; // fresh chapter -> fresh sandbox history

    const chapter = this.getCurrentChapter();
    this.ui.renderChapterList(CHAPTERS, this.currentChapterId);

    // Apply chapter camera preset
    if (chapter.cameraPreset) {
      this.scene.setCameraPreset(chapter.cameraPreset);
    }

    this.recomputeState();
  }

  recomputeState() {
    const chapter = this.getCurrentChapter();
    this.scene.clearPackets();

    const simState = getSimulationStateAtStep(chapter, this.currentStepIndex, {
      sentinelEnabled: this.sandboxSentinelEnabled,
      pin_mode: this.sandboxPinMode
    });

    // Re-apply sandbox-attack history onto the recomputed state so injected
    // detect/heal chain blocks, the incident and the banner survive scrubbing.
    for (const entry of this.sandboxLog) {
      this.applySandboxAttack(simState, entry.packet, entry.ts, entry.sentinelEnabled, false);
    }

    this.currentState = simState;
    this.ui.renderState(simState, chapter);

    // Trigger visual packet animations for this step
    if (simState.currentStep.events) {
      for (const evt of simState.currentStep.events) {
        if (evt.packets) {
          for (const p of evt.packets) {
            this.scene.spawnPacketAnimation(p);
          }
        }
      }
    }

    if (simState.refusedNote) {
      this.scene.triggerShieldBounce();
    }
  }

  goToStep(stepIdx) {
    const chapter = this.getCurrentChapter();
    const target = Math.max(0, Math.min(stepIdx, chapter.steps.length - 1));
    this.currentStepIndex = target;
    this.recomputeState();
  }

  nextStep() {
    const chapter = this.getCurrentChapter();
    if (this.currentStepIndex < chapter.steps.length - 1) {
      this.currentStepIndex++;
      this.recomputeState();
    } else {
      this.pause();
    }
  }

  prevStep() {
    if (this.currentStepIndex > 0) {
      this.currentStepIndex--;
      this.recomputeState();
    }
  }

  resetChapter() {
    this.pause();
    this.currentStepIndex = 0;
    this.recomputeState();
  }

  togglePlay() {
    if (this.isPlaying) {
      this.pause();
    } else {
      this.play();
    }
  }

  play() {
    this.isPlaying = true;
    this.ui.updatePlaybackState(true);
    this.scheduleNextTick();
  }

  pause() {
    this.isPlaying = false;
    this.ui.updatePlaybackState(false);
    if (this.playTimer) {
      clearTimeout(this.playTimer);
      this.playTimer = null;
    }
  }

  scheduleNextTick() {
    if (!this.isPlaying) return;
    const baseInterval = 3200; // Step duration in ms
    const interval = baseInterval / this.playbackSpeed;

    this.playTimer = setTimeout(() => {
      const chapter = this.getCurrentChapter();
      if (this.currentStepIndex < chapter.steps.length - 1) {
        this.nextStep();
        this.scheduleNextTick();
      } else {
        this.pause();
      }
    }, interval);
  }

  // --- Sandbox Actions ---
  triggerSandboxAttack() {
    if (!this.currentState) return;

    const forgedPacket = {
      op: 2,
      sha: 'de:ad:be:ef:00:66',
      spa: '10.77.0.1',
      tha: 'aa:bb:cc:00:00:10',
      tpa: '10.77.0.10',
      eth_src: 'de:ad:be:ef:00:66',
      eth_dst: 'aa:bb:cc:00:00:10'
    };

    const now = Date.now();
    const sentinelEnabled = this.sandboxSentinelEnabled;

    // Record first, apply after: replays reconstruct identical engine decisions.
    this.sandboxLog.push({ packet: forgedPacket, ts: now, sentinelEnabled });
    this.applySandboxAttack(this.currentState, forgedPacket, now, sentinelEnabled, true);

    this.ui.renderState(this.currentState, this.getCurrentChapter());
  }

  applySandboxAttack(simState, forgedPacket, now, sentinelEnabled, animate) {
    if (animate) {
      // Animate packet flying to victim
      this.scene.spawnPacketAnimation({
        id: 'sandbox_attack_' + now,
        type: 'forged_arp',
        from: 'attacker',
        to: 'victim',
        viaSwitch: true,
        tag: 'FAKE',
        summary: 'FAKE: 10.77.0.1 is-at de:ad:be:ef:00:66'
      });
    }

    if (sentinelEnabled) {
      simState.pipeline.sniffer = true;
      simState.pipeline.engine = true;

      const decision = handleArpPacket(simState.engine, forgedPacket, now);
      simState.reasoning = decision.reasoning;

      if (decision.detected) {
        simState.pipeline.executor = true;
        if (animate) this.scene.triggerShieldBounce();
        simState.refusedNote = 'update refused: PERMANENT';

        for (const e of decision.events) {
          appendBlock(simState.chain, e.type, e.data, e.ts);
        }

        if (animate) {
          // Send corrective ARP
          this.scene.spawnPacketAnimation({
            id: 'sandbox_heal_' + now,
            type: 'corrective_arp',
            from: 'victim',
            to: 'router',
            viaSwitch: true,
            summary: 'Corrective ARP unicast to 10.77.0.1'
          });
        }
      }

      simState.banner = {
        severity: 'red',
        text: `Under attack - a device (MAC de:ad:be:ef:00:66) is pretending to be your router. Sentinel-X is blocking it.`
      };
    } else {
      // Sentinel-X OFF -> cache gets poisoned!
      simState.hosts.victim.cache['10.77.0.1'] = {
        mac: 'de:ad:be:ef:00:66',
        state: 'REACHABLE'
      };
      simState.banner = {
        severity: 'red',
        text: 'Attacked without Sentinel-X! Kernel ARP cache successfully poisoned by attacker.'
      };
    }
  }

  // --- Tamper Actions ---
  handleVerifyChain() {
    if (!this.currentState) return;
    const res = verifyChain(this.currentState.chain);
    this.ui.showChainVerifyFeedback(res);
  }

  handleTamperEdit() {
    if (!this.currentState || this.currentState.chain.length < 2) return;
    // Alter block #1 data
    this.currentState.chain[1].data.tampered = true;
    this.currentState.chain[1].data.gateway_mac = 'de:ad:be:ef:00:66';
    const verify = verifyChain(this.currentState.chain);
    this.ui.renderChainStrip(this.currentState.chain);
    this.ui.showChainVerifyFeedback(verify);
  }

  handleTamperDeleteMiddle() {
    if (!this.currentState || this.currentState.chain.length < 3) return;
    this.currentState.chain.splice(1, 1);
    const verify = verifyChain(this.currentState.chain);
    this.ui.renderChainStrip(this.currentState.chain);
    this.ui.showChainVerifyFeedback(verify);
  }

  handleTamperDeleteTail() {
    if (!this.currentState || this.currentState.chain.length < 2) return;
    this.currentState.chain.pop();
    const verify = verifyChain(this.currentState.chain);
    this.ui.renderChainStrip(this.currentState.chain);
    this.ui.showChainVerifyFeedback(verify);
    this.ui.showChainLimitMessage(this.currentState.chain.length);
  }
}

// Bootstrap once DOM ready
window.addEventListener('DOMContentLoaded', () => {
  new SentinelSimulationApp();
});
