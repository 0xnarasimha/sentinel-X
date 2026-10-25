/**
 * Sentinel-X Engine - Pure state machine for host-level ARP defense.
 * Follows Sentinel-X Specification 1.6 & 1.7 strictly.
 * Pure JS: no DOM, no Three.js, time passed in.
 */

export const EngineState = {
  WAITING_NET: 'WAITING_NET',
  TOFU: 'TOFU',
  MONITOR: 'MONITOR',
  CONFLICT: 'CONFLICT',
  UNPROTECTED: 'UNPROTECTED'
};

/**
 * Check if a MAC belongs to a standard VRRP or HSRP virtual router cluster.
 */
export function isVirtualMac(mac) {
  if (!mac || typeof mac !== 'string') return false;
  const lower = mac.toLowerCase();
  // VRRP IPv4: 00:00:5e:00:01:xx
  if (lower.startsWith('00:00:5e:00:01:')) return true;
  // HSRP v1: 00:00:0c:07:ac:xx, HSRP v2: 00:00:0c:9f:f
  if (lower.startsWith('00:00:0c:07:ac:') || lower.startsWith('00:00:0c:9f:f')) return true;
  return false;
}

export function createEngine(options = {}) {
  return {
    state: EngineState.WAITING_NET,
    config: {
      pin_mode: options.pin_mode || 'always', // 'always' | 'on_detect'
      admin_allowed_macs: options.admin_allowed_macs ? [...options.admin_allowed_macs] : [],
      cooldown_ms: options.cooldown_ms || 1000,
      idle_timeout_ms: options.idle_timeout_ms || 10000
    },
    net: {
      iface: options.iface || 'eth0',
      network_id: options.network_id || 'LAN_10_77_0',
      gateway_ip: options.gateway_ip || '10.77.0.1',
      victim_ip: options.victim_ip || '10.77.0.10',
      victim_mac: options.victim_mac || 'aa:bb:cc:00:00:10'
    },
    learned_gateway_mac: null,
    gateway_is_virtual: false,
    pinned_mac: null,
    kernel_cache: {}, // ip -> { mac, state: 'PERMANENT' | 'REACHABLE' | 'STALE' }
    incident: null, // { active: boolean, startTime, lastPacketTime, packetCount, attackerMac, lastHealTime }
    recentEvents: []
  };
}

/**
 * Trigger network connection (join network or change network)
 */
export function joinNetwork(engine, netInfo = {}, now = 0) {
  const actions = [];
  const events = [];

  const oldGateway = engine.net.gateway_ip;
  const isChange = engine.learned_gateway_mac !== null;

  if (isChange) {
    events.push({
      type: 'network_changed',
      ts: now,
      data: {
        from: { ...engine.net },
        to: { ...engine.net, ...netInfo }
      }
    });
    // Unpin old gateway in kernel
    if (engine.pinned_mac) {
      actions.push({
        type: 'unpin_cache',
        ip: oldGateway,
        command: `ip neigh del ${oldGateway} dev ${engine.net.iface}`
      });
      delete engine.kernel_cache[oldGateway];
      engine.pinned_mac = null;
    }
  }

  // Update network info
  engine.net = {
    ...engine.net,
    ...netInfo
  };

  engine.learned_gateway_mac = null;
  engine.gateway_is_virtual = false;
  engine.incident = null;
  engine.state = EngineState.TOFU;

  actions.push({
    type: 'send_probes',
    count: 5,
    interval_ms: 200,
    target_ip: engine.net.gateway_ip
  });

  return { state: engine.state, actions, events };
}

/**
 * Handle collection of probe replies during TOFU.
 * replies: array of string MAC addresses answering "who-has gateway_ip"
 */
export function handleTofuReplies(engine, replies = [], now = 0) {
  const actions = [];
  const events = [];

  const uniqueMacs = [...new Set(replies.map(m => m.toLowerCase()))];

  if (uniqueMacs.length === 1) {
    const mac = uniqueMacs[0];
    engine.learned_gateway_mac = mac;
    engine.gateway_is_virtual = isVirtualMac(mac);
    engine.state = EngineState.MONITOR;

    events.push({
      type: 'tofu_learned',
      ts: now,
      data: {
        gateway_ip: engine.net.gateway_ip,
        gateway_mac: mac,
        iface: engine.net.iface,
        network_id: engine.net.network_id
      }
    });

    if (engine.config.pin_mode === 'always') {
      engine.pinned_mac = mac;
      engine.kernel_cache[engine.net.gateway_ip] = {
        mac,
        state: 'PERMANENT'
      };
      actions.push({
        type: 'pin_cache',
        ip: engine.net.gateway_ip,
        mac,
        command: `ip neigh replace ${engine.net.gateway_ip} lladdr ${mac} dev ${engine.net.iface} nud permanent`
      });
    } else {
      // In on_detect mode, cache starts as normal dynamic REACHABLE
      engine.pinned_mac = null;
      engine.kernel_cache[engine.net.gateway_ip] = {
        mac,
        state: 'REACHABLE'
      };
    }
  } else if (uniqueMacs.length >= 2) {
    engine.state = EngineState.CONFLICT;
    engine.learned_gateway_mac = null;
    engine.pinned_mac = null;

    events.push({
      type: 'tofu_conflict',
      ts: now,
      data: {
        gateway_ip: engine.net.gateway_ip,
        conflicting_macs: uniqueMacs
      }
    });
  } else {
    // 0 replies
    engine.state = EngineState.UNPROTECTED;
    engine.learned_gateway_mac = null;
    engine.pinned_mac = null;
  }

  return { state: engine.state, actions, events };
}

/**
 * Inspect an ARP packet against Rule R1.
 * Pure decision function.
 *
 * Packet structure:
 * {
 *   op: 1 | 2,          // 1 = who-has request, 2 = is-at reply
 *   sha: string,        // sender hardware address (MAC)
 *   spa: string,        // sender protocol address (IP)
 *   tha: string,        // target hardware address (MAC)
 *   tpa: string,        // target protocol address (IP)
 *   eth_src: string,
 *   eth_dst: string
 * }
 */
export function handleArpPacket(engine, packet, now = 0) {
  const actions = [];
  const events = [];
  const reasoning = [];

  const sha = (packet.sha || '').toLowerCase();
  const spa = packet.spa || '';
  const victimMac = (engine.net.victim_mac || '').toLowerCase();
  const gatewayIp = engine.net.gateway_ip;
  const pinnedMac = (engine.pinned_mac || engine.learned_gateway_mac || '').toLowerCase();

  // Rule 0: Ignore packets sent by victim itself
  if (sha === victimMac) {
    reasoning.push(`Packet sent by victim host (${victimMac}) -> IGNORED`);
    return { detected: false, reasoning, actions, events };
  }

  // Rule 0b: Packets about other IPs never trigger anything
  if (spa !== gatewayIp) {
    reasoning.push(`Sender IP (${spa}) != gateway IP (${gatewayIp}) -> IGNORED (not gateway traffic)`);
    return { detected: false, reasoning, actions, events };
  }

  reasoning.push(`sender IP == gateway IP? YES (${spa} == ${gatewayIp})`);

  // Check allowed MAC set:
  // Pinned/learned MAC + admin_allowed_macs
  const allowedSet = new Set();
  if (pinnedMac) allowedSet.add(pinnedMac);
  for (const adm of engine.config.admin_allowed_macs) {
    allowedSet.add(adm.toLowerCase());
  }

  // Virtual MAC policy check:
  // A VRRP/HSRP virtual MAC is accepted ONLY if the gateway itself was learned as a virtual MAC
  let isAllowed = allowedSet.has(sha);
  if (!isAllowed && isVirtualMac(sha)) {
    if (engine.gateway_is_virtual) {
      reasoning.push(`Sender MAC is VRRP/HSRP virtual MAC and gateway learned as virtual -> ACCEPTED`);
      isAllowed = true;
    } else {
      reasoning.push(`Sender MAC is VRRP/HSRP virtual MAC but gateway is physical -> REJECTED (anti-evasion)`);
      isAllowed = false;
    }
  }

  if (isAllowed) {
    reasoning.push(`sender MAC in allowed set? YES (${sha}) -> LEGITIMATE`);

    // In normal state without pin (or if entry was stale), kernel might update
    if (!engine.pinned_mac && engine.kernel_cache[gatewayIp]) {
      engine.kernel_cache[gatewayIp] = {
        mac: sha,
        state: 'REACHABLE'
      };
    }

    return { detected: false, reasoning, actions, events };
  }

  // R1 TRIGGERED: sender IP == gateway IP AND sender MAC is NOT in allowed set
  reasoning.push(`sender MAC in allowed set? NO (${sha} not in [${[...allowedSet].join(', ')}]) -> gateway_mac_mismatch`);

  const attackerMac = sha;

  // Heal requires a known real gateway MAC (TOFU completed). Without it there is
  // nothing to pin — pinning null would corrupt the kernel cache and corrupt the log.
  const canHeal = !!engine.learned_gateway_mac;

  // If on_detect mode and not pinned yet, kernel cache gets poisoned before heal:
  if (engine.config.pin_mode === 'on_detect' && !engine.pinned_mac && canHeal) {
    engine.kernel_cache[gatewayIp] = {
      mac: attackerMac,
      state: 'REACHABLE'
    };
    actions.push({
      type: 'cache_poisoned_temporarily',
      ip: gatewayIp,
      mac: attackerMac
    });
  }

  // Check incident state
  if (!engine.incident || !engine.incident.active) {
    // Start new incident
    engine.incident = {
      active: true,
      startTime: now,
      lastPacketTime: now,
      packetCount: 1,
      attackerMac,
      lastHealTime: now,
      healDeferred: !canHeal
    };

    events.push({
      type: 'detect',
      ts: now,
      data: {
        src_ip: spa,
        src_mac: attackerMac,
        rule: 'gateway_mac_mismatch'
      }
    });

    // Run Heal immediately on first detection (only when the real gateway MAC is known)
    if (canHeal) {
      const healResult = executeHeal(engine, now);
      actions.push(...healResult.actions);
      events.push(...healResult.events);
    } else {
      reasoning.push('Gateway MAC not yet learned (TOFU unresolved) -> heal deferred, detection logged');
    }
  } else {
    // Existing incident: aggregate packet count
    engine.incident.packetCount += 1;
    engine.incident.lastPacketTime = now;

    // Check cooldown for repeating corrective ARP (at most once per cooldown_ms)
    const timeSinceLastHeal = now - engine.incident.lastHealTime;
    if (engine.incident.healDeferred) {
      // Try to heal now that a gateway MAC may have been learned since
      if (canHeal) {
        engine.incident.healDeferred = false;
        engine.incident.lastHealTime = now;
        const healResult = executeHeal(engine, now);
        actions.push(...healResult.actions);
        events.push(...healResult.events);
        reasoning.push('Gateway MAC learned -> deferred heal executed');
      } else {
        reasoning.push(`Cooldown active (${timeSinceLastHeal}ms < ${engine.config.cooldown_ms}ms) -> Packet counted (#${engine.incident.packetCount}), gateway still unknown`);
      }
    } else if (timeSinceLastHeal >= engine.config.cooldown_ms) {
      engine.incident.lastHealTime = now;
      const healResult = executeHeal(engine, now);
      actions.push(...healResult.actions);
      events.push(...healResult.events);
      reasoning.push(`Cooldown passed (${timeSinceLastHeal}ms >= ${engine.config.cooldown_ms}ms) -> Corrective ARP re-sent`);
    } else {
      reasoning.push(`Cooldown active (${timeSinceLastHeal}ms < ${engine.config.cooldown_ms}ms) -> Packet counted (#${engine.incident.packetCount}), corrective ARP suppressed`);
    }
  }

  return { detected: true, reasoning, actions, events };
}

/**
 * Execute Heal:
 * (a) re-assert pin and verify PERMANENT
 * (b) send corrective ARP unicast to router
 * (c) log 'heal' { verified: true }
 */
export function executeHeal(engine, now = 0) {
  const actions = [];
  const events = [];

  const realGatewayMac = engine.learned_gateway_mac;
  const gatewayIp = engine.net.gateway_ip;
  const victimMac = engine.net.victim_mac;
  const victimIp = engine.net.victim_ip;

  // (a) Pin cache entry in kernel
  engine.pinned_mac = realGatewayMac;
  engine.kernel_cache[gatewayIp] = {
    mac: realGatewayMac,
    state: 'PERMANENT'
  };

  actions.push({
    type: 'pin_cache',
    ip: gatewayIp,
    mac: realGatewayMac,
    command: `ip neigh replace ${gatewayIp} lladdr ${realGatewayMac} dev ${engine.net.iface} nud permanent`,
    verified: true
  });

  // (b) Send corrective ARP unicast to router:
  // Ethernet(src=victim MAC, dst=router MAC) + ARP(op=is-at, sender=victim MAC/victim IP, target=router MAC/gateway IP)
  const correctiveArp = {
    eth_src: victimMac,
    eth_dst: realGatewayMac,
    op: 2, // is-at
    sha: victimMac,
    spa: victimIp,
    tha: realGatewayMac,
    tpa: gatewayIp
  };

  actions.push({
    type: 'send_corrective_arp',
    packet: correctiveArp,
    summary: `ARP is-at ${victimIp} is-at ${victimMac} -> unicast to ${realGatewayMac}`
  });

  // (c) Log 'heal'
  events.push({
    type: 'heal',
    ts: now,
    data: {
      verified: true,
      router_mac: realGatewayMac,
      router_ip: gatewayIp
    }
  });

  return { actions, events };
}

/**
 * Check if the current incident has been idle for >= 10s (10000ms).
 * Closes the incident and logs 'incident_close'.
 */
export function checkIncidentIdle(engine, now = 0) {
  const events = [];
  const actions = [];

  if (engine.incident && engine.incident.active) {
    const idleDuration = now - engine.incident.lastPacketTime;
    if (idleDuration >= engine.config.idle_timeout_ms) {
      const duration = now - engine.incident.startTime;
      const packetCount = engine.incident.packetCount;

      events.push({
        type: 'incident_close',
        ts: now,
        data: {
          packets: packetCount,
          duration_ms: duration
        }
      });

      actions.push({
        type: 'incident_closed',
        packets: packetCount,
        duration_ms: duration
      });

      engine.incident = null;
    }
  }

  return { events, actions };
}

/**
 * Generate UI banner text and severity color based on 1.9 specification.
 */
export function getDashboardBanner(engine) {
  if (engine.incident && engine.incident.active) {
    return {
      severity: 'red',
      text: `Under attack - a device (MAC ${engine.incident.attackerMac}) is pretending to be your router. Sentinel-X is blocking it.`
    };
  }

  switch (engine.state) {
    case EngineState.MONITOR:
      return {
        severity: 'green',
        text: `Protected - your router (${engine.net.gateway_ip}) is locked to ${engine.learned_gateway_mac}`
      };
    case EngineState.CONFLICT:
      return {
        severity: 'amber',
        text: 'Conflict - two devices claim to be your router; nothing was pinned'
      };
    case EngineState.UNPROTECTED:
      return {
        severity: 'amber',
        text: "Not protected - your router didn't answer"
      };
    case EngineState.TOFU:
      return {
        severity: 'blue',
        text: `Probing gateway ${engine.net.gateway_ip} (TOFU)...`
      };
    case EngineState.WAITING_NET:
    default:
      return {
        severity: 'neutral',
        text: 'Waiting for network connection...'
      };
  }
}
