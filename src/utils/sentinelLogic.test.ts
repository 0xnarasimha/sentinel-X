// src/utils/sentinelLogic.test.ts
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  GENESIS_PREV,
  computeEntryHash,
  formatBanner,
  formatEntrySentence,
  isVirtualMac,
  verifyChain,
  type LogEntry,
  type StatusJson,
} from './sentinelLogic';

function makeValidChain(): LogEntry[] {
  const ts0 = '2026-10-25T05:00:00.000000Z';
  const d0 = { version: 1 };
  const h0 = computeEntryHash(GENESIS_PREV, 0, ts0, 'genesis', d0);

  const ts1 = '2026-10-25T05:00:00.100000Z';
  const d1 = { dry_run: false, iface: 'v-victim', pin_mode: 'always' };
  const h1 = computeEntryHash(h0, 1, ts1, 'daemon_start', d1);

  const ts2 = '2026-10-25T05:00:00.900000Z';
  const d2 = {
    gw_ip: '10.77.0.1',
    gw_mac: '02:77:00:00:00:01',
    iface: 'v-victim',
    network_id: 'wired',
    pin_mode: 'always',
    replies: 5,
    virtual_gateway: false,
  };
  const h2 = computeEntryHash(h1, 2, ts2, 'tofu_learned', d2);

  const ts3 = '2026-10-25T05:00:02.114233Z';
  const d3 = {
    eth_src: '02:77:00:00:00:66',
    eth_src_mismatch: false,
    expected_mac: '02:77:00:00:00:01',
    first_pkt_ts: 1761368402.11,
    gw_ip: '10.77.0.1',
    iface: 'v-victim',
    kind: 'gateway_mac_mismatch',
    observed_mac: '02:77:00:00:00:66',
    op: 2,
  };
  const h3 = computeEntryHash(h2, 3, ts3, 'detect', d3);

  const ts4 = '2026-10-25T05:00:02.121500Z';
  const d4 = {
    corrective_sent: true,
    gw_ip: '10.77.0.1',
    iface: 'v-victim',
    latency_ms_from_first_pkt: 7.267,
    pinned_mac: '02:77:00:00:00:01',
    reason: 'gateway_mac_mismatch',
    verified: true,
  };
  const h4 = computeEntryHash(h3, 4, ts4, 'heal', d4);

  return [
    { idx: 0, ts: ts0, type: 'genesis', data: d0, prev: GENESIS_PREV, hash: h0 },
    { idx: 1, ts: ts1, type: 'daemon_start', data: d1, prev: h0, hash: h1 },
    { idx: 2, ts: ts2, type: 'tofu_learned', data: d2, prev: h1, hash: h2 },
    { idx: 3, ts: ts3, type: 'detect', data: d3, prev: h2, hash: h3 },
    { idx: 4, ts: ts4, type: 'heal', data: d4, prev: h3, hash: h4 },
  ];
}

test('verifyChain passes on valid SHA-256 chain', () => {
  const chain = makeValidChain();
  const res = verifyChain(chain);
  assert.equal(res.ok, true);
  assert.equal(res.entries, 5);
  assert.equal(res.bad_idx, null);
  assert.equal(res.badge, 'Verified, 5 entries');
});

test('verifyChain detects 1-byte modification in middle entry', () => {
  const chain = makeValidChain();
  chain[3] = {
    ...chain[3],
    data: { ...chain[3].data, observed_mac: '02:77:00:00:00:99' },
  };
  const res = verifyChain(chain);
  assert.equal(res.ok, false);
  assert.equal(res.bad_idx, 3);
  assert.equal(res.reason, 'bad_hash');
  assert.equal(res.badge, 'TAMPERED at entry #3');
});

test('verifyChain detects deleted middle line', () => {
  const chain = makeValidChain();
  chain.splice(2, 1);
  const res = verifyChain(chain);
  assert.equal(res.ok, false);
  assert.equal(res.bad_idx, 2);
  assert.equal(res.reason, 'bad_idx');
});

test('formatBanner renders all four required WP8 states', () => {
  const baseStatus: StatusJson = {
    state: 'monitor',
    iface: 'v-victim',
    network_id: 'wired',
    gw_ip: '10.77.0.1',
    gw_mac: '02:77:00:00:00:01',
    pin_mode: 'always',
    pinned: true,
    under_attack: false,
    incidents_total: 1,
    last_incident_ts: 1761368402.11,
    chain_head: 'a'.repeat(64),
    dropped_events: 0,
    updated: '2026-10-25T05:00:03Z',
  };

  const bProtected = formatBanner(baseStatus, makeValidChain());
  assert.equal(bProtected.state, 'protected');
  assert.equal(bProtected.level, 'ok');
  assert.match(bProtected.headline, /Protected — your router \(10\.77\.0\.1\) is locked to 02:77:00:00:00:01/);

  const bAttack = formatBanner({ ...baseStatus, under_attack: true }, makeValidChain());
  assert.equal(bAttack.state, 'under_attack');
  assert.equal(bAttack.level, 'danger');
  assert.match(bAttack.headline, /Under attack — a device \(MAC 02:77:00:00:00:66\) is pretending to be your router/);

  const bUnprotected = formatBanner({ ...baseStatus, state: 'unprotected', gw_mac: null, pinned: false });
  assert.equal(bUnprotected.state, 'unprotected');
  assert.equal(bUnprotected.level, 'warning');
  assert.match(bUnprotected.headline, /Not protected — your router didn't answer/);

  const bConflict = formatBanner({ ...baseStatus, state: 'conflict', gw_mac: null, pinned: false });
  assert.equal(bConflict.state, 'conflict');
  assert.equal(bConflict.level, 'warning');
  assert.match(bConflict.headline, /Conflict — two devices claim to be your router; nothing was pinned/);
});

test('formatEntrySentence produces human-readable plain-English sentences', () => {
  const chain = makeValidChain();
  assert.match(formatEntrySentence(chain[2]), /Learned router \(10\.77\.0\.1\) hardware address 02:77:00:00:00:01/);
  assert.match(formatEntrySentence(chain[3]), /Someone \(02:77:00:00:00:66\) claimed to be your router/);
  assert.match(formatEntrySentence(chain[4]), /Correct entry restored \(7\.267 ms\), router warned\. Verified\./);
});

test('isVirtualMac identifies VRRP and HSRP MAC prefixes', () => {
  assert.equal(isVirtualMac('00:00:5e:00:01:01'), true);
  assert.equal(isVirtualMac('00:00:0c:07:ac:0a'), true);
  assert.equal(isVirtualMac('00:00:0c:9f:f0:01'), true);
  assert.equal(isVirtualMac('02:77:00:00:00:01'), false);
});

test('committed tests/fixtures/log.jsonl verifies cleanly in TypeScript verifyChain', async () => {
  const fs = await import('node:fs');
  const raw = fs.readFileSync('tests/fixtures/log.jsonl', 'utf-8');
  const entries = raw
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => JSON.parse(l) as LogEntry);
  const res = verifyChain(entries);
  assert.equal(res.ok, true);
  assert.equal(res.bad_idx, null);
});
