import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createEngine,
  joinNetwork,
  handleTofuReplies,
  handleArpPacket,
  checkIncidentIdle,
  getDashboardBanner,
  EngineState
} from '../src/engine.js';
import {
  createHostTooltipController,
  HOST_TOOLTIP_DELAY_MS,
  matchesChainBlockQuery,
  filterChainBlocks
} from '../src/ui.js';

const ROUTER_IP = '10.77.0.1';
const ROUTER_MAC = 'aa:bb:cc:00:00:01';
const VICTIM_IP = '10.77.0.10';
const VICTIM_MAC = 'aa:bb:cc:00:00:10';
const ATTACKER_MAC = 'de:ad:be:ef:00:66';
const BYSTANDER_IP = '10.77.0.20';
const BYSTANDER_MAC = 'aa:bb:cc:00:00:20';

function setupMonitoredEngine(pinMode = 'always') {
  const engine = createEngine({ pin_mode: pinMode });
  joinNetwork(engine, {}, 1000);
  handleTofuReplies(engine, [ROUTER_MAC, ROUTER_MAC, ROUTER_MAC, ROUTER_MAC, ROUTER_MAC], 2000);
  return engine;
}

test('1. TOFU with 1 distinct MAC transitions to MONITOR and pins cache (pin_mode always)', () => {
  const engine = createEngine({ pin_mode: 'always' });
  joinNetwork(engine, {}, 1000);
  assert.equal(engine.state, EngineState.TOFU);

  const res = handleTofuReplies(engine, [ROUTER_MAC, ROUTER_MAC], 2000);
  assert.equal(engine.state, EngineState.MONITOR);
  assert.equal(engine.learned_gateway_mac, ROUTER_MAC);
  assert.equal(engine.pinned_mac, ROUTER_MAC);
  assert.equal(engine.kernel_cache[ROUTER_IP].state, 'PERMANENT');
  assert.equal(res.events[0].type, 'tofu_learned');
});

test('2. TOFU with 0 replies transitions to UNPROTECTED', () => {
  const engine = createEngine();
  joinNetwork(engine, {}, 1000);
  handleTofuReplies(engine, [], 2000);

  assert.equal(engine.state, EngineState.UNPROTECTED);
  assert.equal(engine.pinned_mac, null);
  const banner = getDashboardBanner(engine);
  assert.equal(banner.severity, 'amber');
  assert.equal(banner.text, "Not protected - your router didn't answer");
});

test('3. TOFU with 2 distinct MACs transitions to CONFLICT (someone is lying)', () => {
  const engine = createEngine();
  joinNetwork(engine, {}, 1000);
  const res = handleTofuReplies(engine, [ROUTER_MAC, ATTACKER_MAC], 2000);

  assert.equal(engine.state, EngineState.CONFLICT);
  assert.equal(engine.pinned_mac, null);
  assert.equal(res.events[0].type, 'tofu_conflict');
  const banner = getDashboardBanner(engine);
  assert.equal(banner.severity, 'amber');
  assert.equal(banner.text, "Conflict - two devices claim to be your router; nothing was pinned");
});

test('4. Legit gateway packet causes no alert and is acknowledged', () => {
  const engine = setupMonitoredEngine();
  const pkt = {
    op: 2,
    sha: ROUTER_MAC,
    spa: ROUTER_IP,
    tha: VICTIM_MAC,
    tpa: VICTIM_IP
  };
  const res = handleArpPacket(engine, pkt, 3000);
  assert.equal(res.detected, false);
  assert.ok(res.reasoning.some(r => r.includes('LEGITIMATE')));
});

test('5. Forged ARP reply (spa = router IP, sha = attacker MAC) triggers R1 detection and Heal', () => {
  const engine = setupMonitoredEngine();
  const forgedReply = {
    op: 2,
    sha: ATTACKER_MAC,
    spa: ROUTER_IP,
    tha: VICTIM_MAC,
    tpa: VICTIM_IP
  };

  const res = handleArpPacket(engine, forgedReply, 3000);
  assert.equal(res.detected, true);
  assert.equal(res.events[0].type, 'detect');
  assert.equal(res.events[0].data.rule, 'gateway_mac_mismatch');
  assert.equal(res.events[1].type, 'heal');
  assert.equal(res.events[1].data.verified, true);

  // Corrective ARP sent to router
  const correctiveAction = res.actions.find(a => a.type === 'send_corrective_arp');
  assert.ok(correctiveAction);
  assert.equal(correctiveAction.packet.tha, ROUTER_MAC);
  assert.equal(correctiveAction.packet.spa, VICTIM_IP);
});

test('6. Forged ARP request (who-has from attacker claiming to be gateway) triggers R1 detection', () => {
  const engine = setupMonitoredEngine();
  const forgedReq = {
    op: 1, // who-has
    sha: ATTACKER_MAC,
    spa: ROUTER_IP,
    tha: '00:00:00:00:00:00',
    tpa: VICTIM_IP
  };

  const res = handleArpPacket(engine, forgedReq, 3000);
  assert.equal(res.detected, true);
  assert.equal(res.events[0].type, 'detect');
});

test('7. Gratuitous ARP packet claiming gateway IP from attacker MAC triggers R1 detection', () => {
  const engine = setupMonitoredEngine();
  const garp = {
    op: 2,
    sha: ATTACKER_MAC,
    spa: ROUTER_IP,
    tha: 'ff:ff:ff:ff:ff:ff',
    tpa: ROUTER_IP
  };

  const res = handleArpPacket(engine, garp, 3000);
  assert.equal(res.detected, true);
});

test('8. Packet from another host (bystander 10.77.0.20) is ignored', () => {
  const engine = setupMonitoredEngine();
  const bystanderPkt = {
    op: 1,
    sha: BYSTANDER_MAC,
    spa: BYSTANDER_IP,
    tha: 'ff:ff:ff:ff:ff:ff',
    tpa: '10.77.0.255'
  };

  const res = handleArpPacket(engine, bystanderPkt, 3000);
  assert.equal(res.detected, false);
  assert.ok(res.reasoning.some(r => r.includes('IGNORED (not gateway traffic)')));
});

test('9. Packet sent by victim itself is ignored', () => {
  const engine = setupMonitoredEngine();
  const ownPkt = {
    op: 1,
    sha: VICTIM_MAC,
    spa: VICTIM_IP,
    tha: '00:00:00:00:00:00',
    tpa: ROUTER_IP
  };

  const res = handleArpPacket(engine, ownPkt, 3000);
  assert.equal(res.detected, false);
  assert.ok(res.reasoning.some(r => r.includes('Packet sent by victim host')));
});

test('10. Allowed secondary MAC (admin_allowed_macs) passes without detection', () => {
  const backupRouterMac = 'aa:bb:cc:00:00:02';
  const engine = createEngine({ admin_allowed_macs: [backupRouterMac] });
  joinNetwork(engine, {}, 1000);
  handleTofuReplies(engine, [ROUTER_MAC], 2000);

  const failoverPkt = {
    op: 2,
    sha: backupRouterMac,
    spa: ROUTER_IP,
    tha: VICTIM_MAC,
    tpa: VICTIM_IP
  };

  const res = handleArpPacket(engine, failoverPkt, 3000);
  assert.equal(res.detected, false);
});

test('11. Incident aggregation: multiple forged packets counted under one incident', () => {
  const engine = setupMonitoredEngine();
  const forged = {
    op: 2,
    sha: ATTACKER_MAC,
    spa: ROUTER_IP,
    tha: VICTIM_MAC,
    tpa: VICTIM_IP
  };

  const res1 = handleArpPacket(engine, forged, 3000);
  assert.equal(res1.events[0].type, 'detect');
  assert.equal(engine.incident.packetCount, 1);

  const res2 = handleArpPacket(engine, forged, 3200);
  // Second packet does not emit a new 'detect' event
  assert.equal(res2.events.length, 0);
  assert.equal(engine.incident.packetCount, 2);

  const res3 = handleArpPacket(engine, forged, 3400);
  assert.equal(res3.events.length, 0);
  assert.equal(engine.incident.packetCount, 3);
});

test('12. Heal cooldown suppresses repeating corrective ARP within 1000 ms', () => {
  const engine = setupMonitoredEngine();
  const forged = {
    op: 2,
    sha: ATTACKER_MAC,
    spa: ROUTER_IP,
    tha: VICTIM_MAC,
    tpa: VICTIM_IP
  };

  // Packet at t=3000: heals
  const r1 = handleArpPacket(engine, forged, 3000);
  assert.ok(r1.actions.some(a => a.type === 'send_corrective_arp'));

  // Packet at t=3500 (500ms later): cooldown active, does not re-send heal
  const r2 = handleArpPacket(engine, forged, 3500);
  assert.equal(r2.actions.some(a => a.type === 'send_corrective_arp'), false);

  // Packet at t=4050 (>1000ms later): cooldown elapsed, re-sends heal
  const r3 = handleArpPacket(engine, forged, 4050);
  assert.ok(r3.actions.some(a => a.type === 'send_corrective_arp'));
});

test('13. Incident closes after 10 s (10000 ms) of idle time', () => {
  const engine = setupMonitoredEngine();
  const forged = {
    op: 2,
    sha: ATTACKER_MAC,
    spa: ROUTER_IP,
    tha: VICTIM_MAC,
    tpa: VICTIM_IP
  };

  handleArpPacket(engine, forged, 3000);
  handleArpPacket(engine, forged, 4000);
  assert.ok(engine.incident);

  // At 9000ms idle (t=13000), not closed yet
  const r1 = checkIncidentIdle(engine, 13000);
  assert.equal(r1.events.length, 0);
  assert.ok(engine.incident);

  // At 10001ms idle (t=14001), closed
  const r2 = checkIncidentIdle(engine, 14001);
  assert.equal(r2.events.length, 1);
  assert.equal(r2.events[0].type, 'incident_close');
  assert.equal(r2.events[0].data.packets, 2);
  assert.equal(engine.incident, null);
});

test('14. Network change unpins old gateway and transitions back to TOFU', () => {
  const engine = setupMonitoredEngine();
  assert.equal(engine.pinned_mac, ROUTER_MAC);

  const res = joinNetwork(engine, { network_id: 'CoffeeShop_WiFi', gateway_ip: '192.168.1.1' }, 10000);
  assert.equal(engine.state, EngineState.TOFU);
  assert.equal(engine.pinned_mac, null);
  assert.equal(engine.kernel_cache[ROUTER_IP], undefined);
  assert.ok(res.actions.some(a => a.type === 'unpin_cache'));
  assert.equal(res.events[0].type, 'network_changed');
});

test('15. Virtual MAC acceptance: accepted only if gateway was learned as virtual MAC', () => {
  // Case A: Gateway was learned as physical MAC -> virtual MAC packet is rejected (anti-evasion)
  const engineA = setupMonitoredEngine();
  const vrrpMac2 = '00:00:5e:00:01:02';
  const pktA = {
    op: 2,
    sha: vrrpMac2,
    spa: ROUTER_IP,
    tha: VICTIM_MAC,
    tpa: VICTIM_IP
  };
  const resA = handleArpPacket(engineA, pktA, 5000);
  assert.equal(resA.detected, true);
  assert.ok(resA.reasoning.some(r => r.includes('anti-evasion')));

  // Case B: Gateway was learned as virtual MAC (vrrpMac1) -> failover to vrrpMac2 is accepted
  const vrrpMac1 = '00:00:5e:00:01:01';
  const engineB = createEngine();
  joinNetwork(engineB, {}, 1000);
  handleTofuReplies(engineB, [vrrpMac1], 2000);
  assert.equal(engineB.gateway_is_virtual, true);

  const resB = handleArpPacket(engineB, pktA, 5000);
  assert.equal(resB.detected, false);
  assert.ok(resB.reasoning.some(r => r.includes('ACCEPTED')));
});

test('16. Attacker clones router MAC: undetected (known limit)', () => {
  const engine = setupMonitoredEngine();
  // Attacker spoofs router IP and clones router's real MAC
  const clonedAttack = {
    op: 2,
    sha: ROUTER_MAC, // Cloned!
    spa: ROUTER_IP,
    tha: VICTIM_MAC,
    tpa: VICTIM_IP
  };

  const res = handleArpPacket(engine, clonedAttack, 5000);
  // Engine cannot detect MAC cloning from ARP fields alone (honest known limit)
  assert.equal(res.detected, false);
});

test('17. Pin mode on_detect: cache is poisoned briefly before detection asserts pin', () => {
  const engine = setupMonitoredEngine('on_detect');
  assert.equal(engine.pinned_mac, null);
  assert.equal(engine.kernel_cache[ROUTER_IP].state, 'REACHABLE');

  const forged = {
    op: 2,
    sha: ATTACKER_MAC,
    spa: ROUTER_IP,
    tha: VICTIM_MAC,
    tpa: VICTIM_IP
  };

  const res = handleArpPacket(engine, forged, 5000);
  assert.equal(res.detected, true);
  // Shows temporary cache poison action, then heal pins it
  assert.ok(res.actions.some(a => a.type === 'cache_poisoned_temporarily'));
  assert.equal(engine.pinned_mac, ROUTER_MAC);
  assert.equal(engine.kernel_cache[ROUTER_IP].state, 'PERMANENT');
});

test('18. Dashboard banner text matches Section 1.9 exactly', () => {
  const engine = setupMonitoredEngine();
  let b = getDashboardBanner(engine);
  assert.equal(b.severity, 'green');
  assert.equal(b.text, `Protected - your router (${ROUTER_IP}) is locked to ${ROUTER_MAC}`);

  // Under attack
  handleArpPacket(engine, {
    op: 2,
    sha: ATTACKER_MAC,
    spa: ROUTER_IP,
    tha: VICTIM_MAC,
    tpa: VICTIM_IP
  }, 5000);

  b = getDashboardBanner(engine);
  assert.equal(b.severity, 'red');
  assert.equal(b.text, `Under attack - a device (MAC ${ATTACKER_MAC}) is pretending to be your router. Sentinel-X is blocking it.`);
});

test('19. Host card tooltip enforces 300ms hover delay before showing', () => {
  assert.equal(HOST_TOOLTIP_DELAY_MS, 300);

  let scheduledFn = null;
  let scheduledMs = 0;
  let shownTooltip = null;
  let hideCount = 0;

  const controller = createHostTooltipController({
    delayMs: HOST_TOOLTIP_DELAY_MS,
    onShow: (info) => { shownTooltip = info; },
    onHide: () => { shownTooltip = null; hideCount++; },
    setTimer: (fn, ms) => { scheduledFn = fn; scheduledMs = ms; return 42; },
    clearTimer: () => { scheduledFn = null; }
  });

  controller.hoverEnter('card-victim', 'Protected Host (10.77.0.10)');
  assert.equal(scheduledMs, 300);
  assert.equal(controller.getState().pending, true);
  assert.equal(controller.getState().visible, false);
  assert.equal(shownTooltip, null);

  // Fire timer at 300ms
  scheduledFn();
  assert.equal(controller.getState().pending, false);
  assert.equal(controller.getState().visible, true);
  assert.equal(shownTooltip.targetId, 'card-victim');
  assert.equal(shownTooltip.text, 'Protected Host (10.77.0.10)');
});

test('20. Host card tooltip cancels pending 300ms timer on early leave or rapid camera movement', () => {
  let scheduledFn = null;
  let clearedId = null;
  let shownTooltip = null;

  const controller = createHostTooltipController({
    delayMs: 300,
    onShow: (info) => { shownTooltip = info; },
    onHide: () => { shownTooltip = null; },
    setTimer: (fn) => { scheduledFn = fn; return 99; },
    clearTimer: (id) => { clearedId = id; scheduledFn = null; }
  });

  // Hover starts 300ms timer, but camera moves before 300ms elapses
  controller.hoverEnter('card-router', 'Default Gateway (10.77.0.1)');
  assert.equal(controller.getState().pending, true);

  controller.cancelOnCameraMove();
  assert.equal(clearedId, 99);
  assert.equal(controller.getState().pending, false);
  assert.equal(controller.getState().visible, false);
  assert.equal(shownTooltip, null);

  // Hover again and let 300ms elapse, then camera moves -> hides visible tooltip
  controller.hoverEnter('card-attacker', 'MITM Attacker (10.77.0.66)');
  scheduledFn();
  assert.equal(controller.getState().visible, true);

  controller.cancelOnCameraMove();
  assert.equal(controller.getState().visible, false);
  assert.equal(shownTooltip, null);
});

test('21. Real-time chain search filters log entries by event type or data content', () => {
  const sampleChain = [
    { idx: 0, type: 'genesis', data: { message: 'Sentinel-X log started' }, prev: '0'.repeat(64), hash: 'a'.repeat(64) },
    { idx: 1, type: 'tofu_learned', data: { gateway_ip: ROUTER_IP, gateway_mac: ROUTER_MAC }, prev: 'a'.repeat(64), hash: 'b'.repeat(64) },
    { idx: 2, type: 'detection', data: { rule: 'R1', src_mac: ATTACKER_MAC, claimed_ip: ROUTER_IP }, prev: 'b'.repeat(64), hash: 'c'.repeat(64) },
    { idx: 3, type: 'action_pin', data: { verified: true, gateway_mac: ROUTER_MAC }, prev: 'c'.repeat(64), hash: 'd'.repeat(64) }
  ];

  // Empty query returns all entries
  assert.equal(filterChainBlocks(sampleChain, '').length, 4);
  assert.equal(filterChainBlocks(sampleChain, '   ').length, 4);

  // Filter by event type (case-insensitive)
  const detectOnly = filterChainBlocks(sampleChain, 'DETECT');
  assert.equal(detectOnly.length, 1);
  assert.equal(detectOnly[0].idx, 2);

  // Filter by formatted data shorthand (e.g., gw=00:00:01 or verified=true)
  const verifiedOnly = filterChainBlocks(sampleChain, 'verified=true');
  assert.equal(verifiedOnly.length, 1);
  assert.equal(verifiedOnly[0].type, 'action_pin');

  // Filter by raw data content (e.g., full attacker MAC or rule R1)
  const attackerMacMatches = filterChainBlocks(sampleChain, 'de:ad:be:ef:00:66');
  assert.equal(attackerMacMatches.length, 1);
  assert.equal(attackerMacMatches[0].idx, 2);

  const gwMatches = filterChainBlocks(sampleChain, '00:00:01');
  assert.equal(gwMatches.length, 2);
  assert.deepEqual(gwMatches.map(b => b.idx), [1, 3]);

  // Non-matching query returns empty list
  assert.equal(filterChainBlocks(sampleChain, 'nonexistent_token').length, 0);
  assert.equal(matchesChainBlockQuery(sampleChain[0], 'Sentinel-X'), true);
});

test('22. Attack before TOFU resolves: no null-MAC heal/pin; deferred heal runs after learn', () => {
  const forged = {
    op: 2,
    sha: ATTACKER_MAC,
    spa: ROUTER_IP,
    tha: VICTIM_MAC,
    tpa: VICTIM_IP,
    eth_src: ATTACKER_MAC,
    eth_dst: VICTIM_MAC
  };

  // --- Case A: firewall in WAITING_NET (no joinNetwork) -> learned_gateway_mac null ---
  const waiting = createEngine({ pin_mode: 'always' });
  const d1 = handleArpPacket(waiting, forged, 500);

  assert.equal(d1.detected, true);
  assert.ok(d1.events.some(e => e.type === 'detect'));
  assert.equal(d1.events.some(e => e.type === 'heal'), false);
  const cacheEntry = waiting.kernel_cache[ROUTER_IP];
  assert.ok(!cacheEntry || cacheEntry.mac !== null, 'kernel cache must never contain a null-MAC entry');
  assert.equal(waiting.learned_gateway_mac, null);
  assert.equal(waiting.incident.healDeferred, true);

  // --- Case B: TOFU fails (0 replies -> UNPROTECTED) -> same guard applies ---
  const unprotected = createEngine({ pin_mode: 'always' });
  joinNetwork(unprotected, {}, 1000);
  handleTofuReplies(unprotected, [], 2000);
  const d2 = handleArpPacket(unprotected, forged, 2500);

  assert.equal(d2.events.some(e => e.type === 'heal'), false);
  const entry2 = unprotected.kernel_cache[ROUTER_IP];
  assert.ok(!entry2 || entry2.mac !== null);
  assert.equal(unprotected.incident.healDeferred, true);

  // --- Case C: TOFU completes later -> deferred heal executes on next forged packet ---
  const deferred = createEngine({ pin_mode: 'always' });
  joinNetwork(deferred, {}, 1000);
  handleArpPacket(deferred, forged, 1500); // incident starts, heal deferred
  handleTofuReplies(deferred, [ROUTER_MAC], 5000);
  assert.equal(deferred.learned_gateway_mac, ROUTER_MAC);
  assert.equal(deferred.state, EngineState.MONITOR);

  const d3 = handleArpPacket(deferred, forged, 6000);
  const healEvents = d3.events.filter(e => e.type === 'heal');
  assert.equal(healEvents.length, 1);
  assert.equal(healEvents[0].data.router_mac, ROUTER_MAC);
  assert.equal(deferred.kernel_cache[ROUTER_IP].mac, ROUTER_MAC);
});


