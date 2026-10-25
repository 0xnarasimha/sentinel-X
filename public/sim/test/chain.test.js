import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  sha256,
  canonicalJSON,
  createChain,
  appendBlock,
  verifyChain,
  computeBlockHash
} from '../src/chain.js';

test('1. SHA-256 known vectors match node:crypto', () => {
  const vectors = [
    '',
    'abc',
    'message digest',
    'Sentinel-X daemon initialized',
    '{"data":{"ip":"10.77.0.1","mac":"aa:bb:cc:00:00:01"},"idx":1,"ts":1700000001000,"type":"tofu_learned"}'
  ];

  for (const v of vectors) {
    const expected = crypto.createHash('sha256').update(v).digest('hex');
    const actual = sha256(v);
    assert.equal(actual, expected, `Mismatch for vector: "${v}"`);
  }
});

test('2. canonicalJSON produces deterministic sorted output with no spaces', () => {
  const obj = {
    z: 1,
    a: 'hello',
    nested: { c: true, b: [3, 2, 1] }
  };
  const json = canonicalJSON(obj);
  assert.equal(json, '{"a":"hello","nested":{"b":[3,2,1],"c":true},"z":1}');
});

test('3. verifyChain passes for an untampered chain', () => {
  const chain = createChain(1700000000000);
  appendBlock(chain, 'daemon_start', { pid: 1234 }, 1700000001000);
  appendBlock(chain, 'tofu_learned', { ip: '10.77.0.1', mac: 'aa:bb:cc:00:00:01' }, 1700000002000);
  appendBlock(chain, 'detect', { src_ip: '10.77.0.1', src_mac: 'de:ad:be:ef:00:66' }, 1700000003000);
  appendBlock(chain, 'heal', { verified: true }, 1700000004000);

  const res = verifyChain(chain);
  assert.equal(res.valid, true);
  assert.equal(res.count, 5);
});

test('4. verifyChain detects an edited data field (bad_hash)', () => {
  const chain = createChain(1700000000000);
  appendBlock(chain, 'tofu_learned', { ip: '10.77.0.1', mac: 'aa:bb:cc:00:00:01' }, 1700000001000);
  appendBlock(chain, 'heal', { verified: true }, 1700000002000);

  // Attacker tampers with the MAC in entry 1
  chain[1].data.mac = 'de:ad:be:ef:00:66';

  const res = verifyChain(chain);
  assert.equal(res.valid, false);
  assert.equal(res.badIdx, 1);
  assert.equal(res.reason, 'bad_hash');
});

test('5. verifyChain detects an edited timestamp (bad_hash)', () => {
  const chain = createChain(1700000000000);
  appendBlock(chain, 'detect', { count: 1 }, 1700000001000);
  appendBlock(chain, 'heal', { verified: true }, 1700000002000);

  // Attacker edits timestamp on block 2
  chain[2].ts = 1700000099999;

  const res = verifyChain(chain);
  assert.equal(res.valid, false);
  assert.equal(res.badIdx, 2);
  assert.equal(res.reason, 'bad_hash');
});

test('6. verifyChain detects deleted middle block', () => {
  const chain = createChain(1700000000000);
  appendBlock(chain, 'tofu_learned', { ip: '10.77.0.1' }, 1700000001000);
  appendBlock(chain, 'detect', { attacker: 'de:ad' }, 1700000002000);
  appendBlock(chain, 'heal', { ok: true }, 1700000003000);

  // Delete block 2 (detect)
  chain.splice(2, 1);

  const res = verifyChain(chain);
  assert.equal(res.valid, false);
  // Either bad_idx (since block 3 still has idx 3 at array index 2) or bad_prev
  assert.ok(res.badIdx === 2);
  assert.ok(res.reason === 'bad_idx' || res.reason === 'bad_prev');
});

test('7. verifyChain detects swapped blocks', () => {
  const chain = createChain(1700000000000);
  appendBlock(chain, 'block_A', { step: 'A' }, 1700000001000);
  appendBlock(chain, 'block_B', { step: 'B' }, 1700000002000);
  appendBlock(chain, 'block_C', { step: 'C' }, 1700000003000);

  // Swap block 1 and block 2
  const temp = chain[1];
  chain[1] = chain[2];
  chain[2] = temp;

  const res = verifyChain(chain);
  assert.equal(res.valid, false);
  assert.equal(res.badIdx, 1);
});

test('8. verifyChain detects inserted block in middle', () => {
  const chain = createChain(1700000000000);
  appendBlock(chain, 'block_A', { step: 'A' }, 1700000001000);
  appendBlock(chain, 'block_B', { step: 'B' }, 1700000002000);

  // Insert a rogue block at index 1
  const rogue = {
    idx: 1,
    ts: 1700000001500,
    type: 'fake',
    data: {},
    prev: chain[0].hash,
    hash: ''
  };
  rogue.hash = computeBlockHash(rogue.prev, rogue);
  chain.splice(1, 0, rogue);

  const res = verifyChain(chain);
  assert.equal(res.valid, false);
  // Block 2 (former block 1) now has wrong prev or wrong idx
  assert.equal(res.badIdx, 2);
});

test('9. Truncation of tail is NOT detected without external head anchor (known limit)', () => {
  const chain = createChain(1700000000000);
  appendBlock(chain, 'tofu_learned', { ip: '10.77.0.1' }, 1700000001000);
  appendBlock(chain, 'detect', { attacker: 'de:ad' }, 1700000002000);
  appendBlock(chain, 'heal', { ok: true }, 1700000003000);

  // Attacker truncates the last block (heal)
  chain.pop();

  const res = verifyChain(chain);
  // Without external anchor/witness, internal verification still appears valid
  assert.equal(res.valid, true);
  assert.equal(res.count, 3);
});
