// src/utils/sentinelLogic.ts
export interface StatusJson {
  state: 'waiting_net' | 'tofu' | 'monitor' | 'conflict' | 'unprotected';
  iface: string | null;
  network_id: string | null;
  gw_ip: string | null;
  gw_mac: string | null;
  pin_mode?: 'always' | 'on_detect';
  pinned: boolean;
  under_attack: boolean;
  incidents_total: number;
  last_incident_ts: number | null;
  chain_head: string;
  dropped_events: number;
  updated: string;
}

export interface LogEntry {
  idx: number;
  ts: string;
  type: string;
  data: Record<string, unknown>;
  prev: string;
  hash: string;
}

export interface BannerInfo {
  level: 'ok' | 'danger' | 'warning';
  state: 'protected' | 'under_attack' | 'unprotected' | 'conflict';
  headline: string;
}

export interface VerifyChainResult {
  ok: boolean;
  entries: number;
  bad_idx: number | null;
  reason: string | null;
  head: string;
  badge: string;
}

export const GENESIS_PREV = '0'.repeat(64);

const VMAC_PREFIXES = [
  '00:00:5e:00:01:',
  '00:00:0c:07:ac:',
  '00:00:0c:9f:f',
];

export function normalizeMac(mac: string): string {
  return mac.trim().toLowerCase();
}

export function isVirtualMac(mac: string): boolean {
  const norm = normalizeMac(mac);
  return VMAC_PREFIXES.some((prefix) => norm.startsWith(prefix));
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map((item) => canonicalJson(item)).join(',') + ']';
  }
  const obj = value as Record<string, unknown>;
  const sortedKeys = Object.keys(obj).sort();
  const parts = sortedKeys.map(
    (k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`
  );
  return '{' + parts.join(',') + '}';
}

/**
 * Pure synchronous SHA-256 implementation (FIPS 180-4) so hash-chain verification
 * runs deterministically in both browser UI and Node tests without async overhead.
 */
export function sha256Hex(ascii: string): string {
  const rightRotate = (value: number, amount: number) =>
    (value >>> amount) | (value << (32 - amount));

  const k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  const h = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ];

  const utf8 = new TextEncoder().encode(ascii);
  const bitLen = utf8.length * 8;
  const totalBytes = Math.ceil((utf8.length + 9) / 64) * 64;
  const buf = new Uint8Array(totalBytes);
  buf.set(utf8);
  buf[utf8.length] = 0x80;

  const view = new DataView(buf.buffer);
  view.setUint32(totalBytes - 8, Math.floor(bitLen / 0x100000000), false);
  view.setUint32(totalBytes - 4, bitLen >>> 0, false);

  const w = new Uint32Array(64);
  for (let offset = 0; offset < totalBytes; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rightRotate(w[i - 15], 7) ^ rightRotate(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rightRotate(w[i - 2], 17) ^ rightRotate(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }

    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (hh + S1 + ch + k[i] + w[i]) | 0;
      const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) | 0;

      hh = g;
      g = f;
      f = e;
      e = (d + temp1) | 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) | 0;
    }

    h[0] = (h[0] + a) | 0;
    h[1] = (h[1] + b) | 0;
    h[2] = (h[2] + c) | 0;
    h[3] = (h[3] + d) | 0;
    h[4] = (h[4] + e) | 0;
    h[5] = (h[5] + f) | 0;
    h[6] = (h[6] + g) | 0;
    h[7] = (h[7] + hh) | 0;
  }

  return h.map((v) => (v >>> 0).toString(16).padStart(8, '0')).join('');
}

export function computeEntryHash(
  prev: string,
  idx: number,
  ts: string,
  type: string,
  data: Record<string, unknown>
): string {
  const payload = canonicalJson({ idx, ts, type, data });
  return sha256Hex(prev + payload);
}

export function verifyChain(entries: LogEntry[]): VerifyChainResult {
  if (!entries || entries.length === 0) {
    return {
      ok: false,
      entries: 0,
      bad_idx: 0,
      reason: 'bad_genesis',
      head: GENESIS_PREV,
      badge: 'TAMPERED at entry #0',
    };
  }

  let expectedPrev = GENESIS_PREV;
  let lastHash = GENESIS_PREV;

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    if (
      !entry ||
      typeof entry.idx !== 'number' ||
      typeof entry.ts !== 'string' ||
      typeof entry.type !== 'string' ||
      typeof entry.data !== 'object' ||
      entry.data === null ||
      typeof entry.prev !== 'string' ||
      typeof entry.hash !== 'string'
    ) {
      return {
        ok: false,
        entries: i,
        bad_idx: i,
        reason: 'bad_json',
        head: lastHash,
        badge: `TAMPERED at entry #${i}`,
      };
    }

    if (entry.idx !== i) {
      return {
        ok: false,
        entries: i,
        bad_idx: i,
        reason: 'bad_idx',
        head: lastHash,
        badge: `TAMPERED at entry #${i}`,
      };
    }

    if (i === 0) {
      if (entry.type !== 'genesis' || entry.prev !== GENESIS_PREV) {
        return {
          ok: false,
          entries: 0,
          bad_idx: 0,
          reason: 'bad_genesis',
          head: lastHash,
          badge: 'TAMPERED at entry #0',
        };
      }
    } else if (entry.prev !== expectedPrev) {
      return {
        ok: false,
        entries: i,
        bad_idx: i,
        reason: 'bad_prev',
        head: lastHash,
        badge: `TAMPERED at entry #${i}`,
      };
    }

    const computed = computeEntryHash(entry.prev, entry.idx, entry.ts, entry.type, entry.data);
    if (entry.hash !== computed) {
      return {
        ok: false,
        entries: i,
        bad_idx: i,
        reason: 'bad_hash',
        head: lastHash,
        badge: `TAMPERED at entry #${i}`,
      };
    }

    expectedPrev = entry.hash;
    lastHash = entry.hash;
  }

  return {
    ok: true,
    entries: entries.length,
    bad_idx: null,
    reason: null,
    head: lastHash,
    badge: `Verified, ${entries.length} entries`,
  };
}

export function formatBanner(status: StatusJson, entries: LogEntry[] = []): BannerInfo {
  const state = status.state || 'waiting_net';
  const gwIp = status.gw_ip || 'unknown';
  const gwMac = status.gw_mac || 'unpinned';

  let observedMac = 'unknown';
  for (let i = entries.length - 1; i >= 0; i--) {
    if (entries[i].type === 'detect' && entries[i].data?.observed_mac) {
      observedMac = String(entries[i].data.observed_mac);
      break;
    }
  }

  if (status.under_attack) {
    return {
      level: 'danger',
      state: 'under_attack',
      headline: `Under attack — a device (MAC ${observedMac}) is pretending to be your router. Sentinel-X is blocking it.`,
    };
  }

  if (state === 'conflict') {
    return {
      level: 'warning',
      state: 'conflict',
      headline: 'Conflict — two devices claim to be your router; nothing was pinned',
    };
  }

  if (state === 'unprotected' || state === 'waiting_net' || state === 'tofu' || !status.gw_mac) {
    return {
      level: 'warning',
      state: 'unprotected',
      headline: "Not protected — your router didn't answer",
    };
  }

  return {
    level: 'ok',
    state: 'protected',
    headline: `Protected — your router (${gwIp}) is locked to ${gwMac}`,
  };
}

export function formatEntrySentence(entry: LogEntry): string {
  const tsRaw = String(entry.ts || '');
  const tsShort = tsRaw.length >= 19 ? tsRaw.slice(11, 19) : tsRaw;
  const data = entry.data || {};

  switch (entry.type) {
    case 'genesis':
      return `${tsShort} — Audit log initialized (genesis block #0).`;
    case 'daemon_start':
      return `${tsShort} — Sentinel-X started monitoring interface ${data.iface ?? 'auto'}.`;
    case 'tofu_learned':
      return `${tsShort} — Learned router (${data.gw_ip ?? 'router'}) hardware address ${data.gw_mac ?? 'unknown'} and locked it.`;
    case 'tofu_conflict': {
      const cands = Object.keys((data.candidates as Record<string, number>) || {})
        .sort()
        .join(', ');
      return `${tsShort} — Conflict: multiple devices (${cands}) claimed to be router ${data.gw_ip ?? 'router'}; nothing was pinned.`;
    }
    case 'tofu_unprotected':
      return `${tsShort} — Router ${data.gw_ip ?? 'router'} did not answer ARP probes; running unprotected.`;
    case 'detect':
      return `${tsShort} — Someone (${data.observed_mac ?? 'unknown'}) claimed to be your router (${data.gw_ip ?? 'router'}, expected ${data.expected_mac ?? 'unknown'}).`;
    case 'heal': {
      const verified = Boolean(data.verified);
      const corr = Boolean(data.corrective_sent);
      const lat = data.latency_ms_from_first_pkt ?? 0;
      return `${tsShort} — Correct entry restored (${lat} ms), ${corr ? 'router warned' : 'pin re-asserted'}. ${verified ? 'Verified.' : 'Verification failed.'}`;
    }
    case 'incident_close': {
      const pkts = Number(data.packets ?? 1);
      const heals = Number(data.heals ?? 1);
      return `${tsShort} — Attack from ${data.observed_mac ?? 'unknown'} ended (${pkts} packets over ${data.duration_s ?? 0}s, ${heals} heal action${heals === 1 ? '' : 's'}).`;
    }
    case 'network_changed':
      return `${tsShort} — Network changed (${data.reason ?? 'switched'}); previous router pin cleared.`;
    case 'daemon_stop':
      return `${tsShort} — Sentinel-X daemon stopped; ${data.unpinned ? 'router pin released cleanly.' : 'stopped.'}`;
    default:
      return `${tsShort} — Event: ${entry.type}`;
  }
}
