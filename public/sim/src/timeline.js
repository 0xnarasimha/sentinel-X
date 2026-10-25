/**
 * Pure simulation state reducer.
 * Ensures the simulation is 100% deterministic and reversible.
 * State at any step N is computed by reducing initial state with steps [0..N].
 */

import {
  createEngine,
  joinNetwork,
  handleTofuReplies,
  handleArpPacket,
  checkIncidentIdle,
  getDashboardBanner,
  EngineState
} from './engine.js';

import {
  createChain,
  appendBlock,
  verifyChain
} from './chain.js';

export const INITIAL_TOPOLOGY = {
  router: {
    name: 'Router (Gateway)',
    ip: '10.77.0.1',
    mac: 'aa:bb:cc:00:00:01',
    cache: {}
  },
  victim: {
    name: 'Victim Laptop',
    ip: '10.77.0.10',
    mac: 'aa:bb:cc:00:00:10',
    cache: {}
  },
  attacker: {
    name: 'Attacker',
    ip: '10.77.0.66',
    mac: 'de:ad:be:ef:00:66',
    ip_forwarding: true,
    captured: []
  },
  bystander: {
    name: 'Bystander Peer',
    ip: '10.77.0.20',
    mac: 'aa:bb:cc:00:00:20',
    cache: {}
  }
};

export function createInitialSimulationState(configOverrides = {}) {
  const engine = createEngine({
    pin_mode: configOverrides.pin_mode || 'always',
    admin_allowed_macs: configOverrides.admin_allowed_macs || []
  });

  const chain = createChain(1700000000000);

  return {
    hosts: JSON.parse(JSON.stringify(INITIAL_TOPOLOGY)),
    engine,
    chain,
    sentinelEnabled: configOverrides.sentinelEnabled !== false,
    banner: {
      severity: 'neutral',
      text: 'Waiting for network activity...'
    },
    pipeline: {
      sniffer: false,
      engine: false,
      executor: false
    },
    reasoning: [],
    refusedNote: null,
    inboundExposure: false,
    lastCorrectiveArp: null,
    captureList: [],
    packetsInFlight: []
  };
}

/**
 * Pure step reducer. Applies a step event to clone of currentState.
 */
export function reduceSimulationStep(state, step) {
  // Deep clone state to preserve purity
  const next = {
    hosts: JSON.parse(JSON.stringify(state.hosts)),
    engine: JSON.parse(JSON.stringify(state.engine)),
    chain: JSON.parse(JSON.stringify(state.chain)),
    sentinelEnabled: state.sentinelEnabled,
    banner: { ...state.banner },
    pipeline: { sniffer: false, engine: false, executor: false },
    reasoning: [],
    refusedNote: null,
    inboundExposure: false,
    lastCorrectiveArp: null,
    captureList: [...state.captureList],
    packetsInFlight: []
  };

  const events = step.events || [];
  const now = step.timestamp || (1700000000000 + (step.id || 0) * 1000);

  for (const evt of events) {
    switch (evt.type) {
      case 'JOIN_NETWORK': {
        const netInfo = evt.net || {};
        const res = joinNetwork(next.engine, netInfo, now);
        for (const e of res.events) {
          appendBlock(next.chain, e.type, e.data, e.ts);
        }
        next.banner = getDashboardBanner(next.engine);
        break;
      }

      case 'TOFU_PROBES_SENT': {
        next.engine.state = EngineState.TOFU;
        next.banner = getDashboardBanner(next.engine);
        if (evt.packets) {
          next.packetsInFlight.push(...evt.packets);
        }
        break;
      }

      case 'TOFU_REPLIES_RECEIVED': {
        const replies = evt.replies || [];
        const res = handleTofuReplies(next.engine, replies, now);
        for (const e of res.events) {
          appendBlock(next.chain, e.type, e.data, e.ts);
        }
        // Mirror kernel cache to victim host cache
        next.hosts.victim.cache = JSON.parse(JSON.stringify(next.engine.kernel_cache));
        next.banner = getDashboardBanner(next.engine);
        if (evt.packets) {
          next.packetsInFlight.push(...evt.packets);
        }
        break;
      }

      case 'ARP_PACKET': {
        const pkt = evt.packet;
        if (evt.packets) {
          next.packetsInFlight.push(...evt.packets);
        }

        // 1. Physical packet traversal and non-Sentinel hosts cache reaction:
        applyPhysicalArpToHosts(next, pkt);

        // 2. Sentinel-X processing on Victim:
        if (next.sentinelEnabled) {
          next.pipeline.sniffer = true;
          next.pipeline.engine = true;

          const engineResult = handleArpPacket(next.engine, pkt, now);
          next.reasoning = engineResult.reasoning;

          if (engineResult.detected) {
            next.pipeline.executor = true;
            for (const logEvt of engineResult.events) {
              appendBlock(next.chain, logEvt.type, logEvt.data, logEvt.ts);
            }

            // Did the forged packet bounce off PERMANENT entry?
            if (next.engine.pinned_mac && next.hosts.victim.cache[next.engine.net.gateway_ip]?.state === 'PERMANENT') {
              next.refusedNote = 'update refused: PERMANENT';
            }

            // Sync kernel cache back to victim host
            next.hosts.victim.cache = JSON.parse(JSON.stringify(next.engine.kernel_cache));

            // Execute corrective ARP to router if emitted
            const correctiveAction = engineResult.actions.find(a => a.type === 'send_corrective_arp');
            if (correctiveAction) {
              next.lastCorrectiveArp = correctiveAction.packet;
              // Repair router's cache back to victim MAC!
              next.hosts.router.cache[next.engine.net.victim_ip] = {
                mac: next.engine.net.victim_mac,
                state: 'REACHABLE'
              };
            }
          } else {
            // Legitimate packet or ignored
            if (!next.engine.pinned_mac && pkt.spa === next.engine.net.gateway_ip) {
              next.hosts.victim.cache[pkt.spa] = {
                mac: pkt.sha,
                state: 'REACHABLE'
              };
            }
          }

          next.banner = getDashboardBanner(next.engine);
        } else {
          // Sentinel-X is OFF: standard Linux behaviour
          // Linux updates an existing non-permanent cache entry from ANY ARP reply, even unasked
          if (pkt.op === 2 && pkt.tpa === next.hosts.victim.ip) {
            next.hosts.victim.cache[pkt.spa] = {
              mac: pkt.sha,
              state: 'REACHABLE'
            };
          }
          if (pkt.op === 2 && pkt.tpa === next.hosts.router.ip) {
            next.hosts.router.cache[pkt.spa] = {
              mac: pkt.sha,
              state: 'REACHABLE'
            };
          }
        }
        break;
      }

      case 'DATA_TRANSFER': {
        if (evt.packets) {
          next.packetsInFlight.push(...evt.packets);
        }
        if (evt.capturedItem) {
          next.captureList.push(evt.capturedItem);
          next.hosts.attacker.captured.push(evt.capturedItem);
        }
        if (evt.inboundExposure) {
          next.inboundExposure = true;
        }
        break;
      }

      case 'IDLE_CHECK': {
        const res = checkIncidentIdle(next.engine, now);
        for (const e of res.events) {
          appendBlock(next.chain, e.type, e.data, e.ts);
        }
        next.banner = getDashboardBanner(next.engine);
        break;
      }

      case 'SET_VICTIM_CACHE': {
        next.hosts.victim.cache[evt.ip] = { mac: evt.mac, state: evt.state };
        next.engine.kernel_cache[evt.ip] = { mac: evt.mac, state: evt.state };
        break;
      }

      case 'SET_ROUTER_CACHE': {
        next.hosts.router.cache[evt.ip] = { mac: evt.mac, state: evt.state };
        break;
      }

      case 'CLEAR_CACHES': {
        next.hosts.victim.cache = {};
        next.hosts.router.cache = {};
        next.hosts.attacker.captured = [];
        next.captureList = [];
        next.engine.kernel_cache = {};
        next.engine.pinned_mac = null;
        break;
      }

      case 'MANUAL_TAMPER': {
        if (evt.tamperType === 'EDIT_FIELD') {
          if (next.chain[evt.blockIdx]) {
            next.chain[evt.blockIdx].data = {
              ...next.chain[evt.blockIdx].data,
              ...evt.editedData
            };
          }
        } else if (evt.tamperType === 'DELETE_MIDDLE') {
          if (next.chain.length > evt.blockIdx) {
            next.chain.splice(evt.blockIdx, 1);
          }
        } else if (evt.tamperType === 'DELETE_TAIL') {
          next.chain.pop();
        }
        break;
      }

      default:
        break;
    }
  }

  return next;
}

/**
 * Handle non-Sentinel host ARP cache dynamics (e.g. Router or Bystander)
 */
function applyPhysicalArpToHosts(simState, pkt) {
  // If packet targets router, router updates dynamic cache
  if (pkt.tpa === simState.hosts.router.ip && pkt.op === 2) {
    simState.hosts.router.cache[pkt.spa] = {
      mac: pkt.sha,
      state: 'REACHABLE'
    };
  }

  // If packet targets bystander, bystander updates dynamic cache
  if (pkt.tpa === simState.hosts.bystander.ip && pkt.op === 2) {
    simState.hosts.bystander.cache[pkt.spa] = {
      mac: pkt.sha,
      state: 'REACHABLE'
    };
  }
}

/**
 * Compute the complete simulation state at step index `stepIdx` for a chapter.
 */
export function getSimulationStateAtStep(chapter, stepIdx, configOverrides = {}) {
  let state = createInitialSimulationState({
    pin_mode: chapter.pinMode || configOverrides.pin_mode || 'always',
    sentinelEnabled: chapter.sentinelEnabled !== undefined ? chapter.sentinelEnabled : configOverrides.sentinelEnabled,
    admin_allowed_macs: chapter.adminAllowedMacs || configOverrides.admin_allowed_macs || []
  });

  const maxStep = Math.min(stepIdx, chapter.steps.length - 1);
  for (let i = 0; i <= maxStep; i++) {
    state = reduceSimulationStep(state, chapter.steps[i]);
  }

  // Attach step caption and metadata
  const currentStep = chapter.steps[maxStep] || { caption: '', realWorldEquivalent: '' };
  state.currentStep = currentStep;
  state.stepIndex = maxStep;
  state.totalSteps = chapter.steps.length;

  return state;
}
