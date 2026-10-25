/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Copy,
  Check,
  FileCode2,
  Lock,
  Play,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldOff,
  Terminal,
} from 'lucide-react';
import {
  GENESIS_PREV,
  computeEntryHash,
  formatBanner,
  formatEntrySentence,
  verifyChain,
  type LogEntry,
  type StatusJson,
} from './utils/sentinelLogic';

type ScenarioMode = 'protected' | 'under_attack' | 'unprotected' | 'conflict';
type FeedFilter = 'all' | 'incidents' | 'lifecycle';

function buildLabChain(): LogEntry[] {
  const ts0 = '2026-10-25T05:12:00.041200Z';
  const d0 = { version: 1 };
  const h0 = computeEntryHash(GENESIS_PREV, 0, ts0, 'genesis', d0);

  const ts1 = '2026-10-25T05:12:00.118400Z';
  const d1 = { dry_run: false, iface: 'v-victim', pin_mode: 'always' };
  const h1 = computeEntryHash(h0, 1, ts1, 'daemon_start', d1);

  const ts2 = '2026-10-25T05:12:00.942110Z';
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

  const ts3 = '2026-10-25T05:12:02.310450Z';
  const d3 = {
    eth_src: '02:77:00:00:00:66',
    eth_src_mismatch: false,
    expected_mac: '02:77:00:00:00:01',
    first_pkt_ts: 1761369122.304,
    gw_ip: '10.77.0.1',
    iface: 'v-victim',
    kind: 'gateway_mac_mismatch',
    observed_mac: '02:77:00:00:00:66',
    op: 2,
  };
  const h3 = computeEntryHash(h2, 3, ts3, 'detect', d3);

  const ts4 = '2026-10-25T05:12:02.318920Z';
  const d4 = {
    corrective_sent: true,
    gw_ip: '10.77.0.1',
    iface: 'v-victim',
    latency_ms_from_first_pkt: 8.47,
    pinned_mac: '02:77:00:00:00:01',
    reason: 'gateway_mac_mismatch',
    verified: true,
  };
  const h4 = computeEntryHash(h3, 4, ts4, 'heal', d4);

  const ts5 = '2026-10-25T05:12:13.320100Z';
  const d5 = {
    dropped_events: 0,
    duration_s: 1.984,
    first_seen: 1761369122.31,
    gw_ip: '10.77.0.1',
    heals: 2,
    last_seen: 1761369124.294,
    observed_mac: '02:77:00:00:00:66',
    packets: 6,
  };
  const h5 = computeEntryHash(h4, 5, ts5, 'incident_close', d5);

  const ts6 = '2026-10-25T05:12:15.004120Z';
  const d6 = {
    gw_ip: '10.77.0.1',
    iface: 'v-victim',
    reason: 'SIGTERM',
    unpinned: true,
  };
  const h6 = computeEntryHash(h5, 6, ts6, 'daemon_stop', d6);

  return [
    { idx: 0, ts: ts0, type: 'genesis', data: d0, prev: GENESIS_PREV, hash: h0 },
    { idx: 1, ts: ts1, type: 'daemon_start', data: d1, prev: h0, hash: h1 },
    { idx: 2, ts: ts2, type: 'tofu_learned', data: d2, prev: h1, hash: h2 },
    { idx: 3, ts: ts3, type: 'detect', data: d3, prev: h2, hash: h3 },
    { idx: 4, ts: ts4, type: 'heal', data: d4, prev: h3, hash: h4 },
    { idx: 5, ts: ts5, type: 'incident_close', data: d5, prev: h4, hash: h5 },
    { idx: 6, ts: ts6, type: 'daemon_stop', data: d6, prev: h5, hash: h6 },
  ];
}

const INITIAL_CHAIN = buildLabChain();

export default function App() {
  const [scenario, setScenario] = useState<ScenarioMode>('protected');
  const [tampered, setTampered] = useState<boolean>(false);
  const [feedFilter, setFeedFilter] = useState<FeedFilter>('all');
  const [expandedIdx, setExpandedIdx] = useState<Record<number, boolean>>({ 3: true, 4: true });
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [baseChain, setBaseChain] = useState<LogEntry[]>(INITIAL_CHAIN);
  const [verifyPulseCount, setVerifyPulseCount] = useState<number>(1);

  // Load committed real lab fixtures if served under /tests/fixtures/log.jsonl
  useEffect(() => {
    let active = true;
    fetch('/tests/fixtures/log.jsonl')
      .then((r) => (r.ok ? r.text() : Promise.reject(new Error('not found'))))
      .then((txt) => {
        if (!active) return;
        const parsed = txt
          .split('\n')
          .map((l) => l.trim())
          .filter(Boolean)
          .map((l) => JSON.parse(l) as LogEntry);
        if (parsed.length >= 4) {
          setBaseChain(parsed);
        }
      })
      .catch(() => {
        // Fallback to deterministic lab chain built with identical canonical SHA-256
      });
    return () => {
      active = false;
    };
  }, []);

  const displayedEntries: LogEntry[] = useMemo(() => {
    const cloned = baseChain.map((e) => ({ ...e, data: { ...e.data } }));
    if (scenario === 'conflict') {
      const prev = cloned[1]?.hash ?? GENESIS_PREV;
      const ts = '2026-10-25T05:12:00.950000Z';
      const data = {
        candidates: { '02:77:00:00:00:01': 3, '02:77:00:00:00:66': 2 },
        gw_ip: '10.77.0.1',
        iface: 'v-victim',
        network_id: 'wired',
      };
      const hash = computeEntryHash(prev, 2, ts, 'tofu_conflict', data);
      return [cloned[0], cloned[1], { idx: 2, ts, type: 'tofu_conflict', data, prev, hash }];
    }
    if (scenario === 'unprotected') {
      const prev = cloned[1]?.hash ?? GENESIS_PREV;
      const ts = '2026-10-25T05:12:03.100000Z';
      const data = {
        gw_ip: '10.77.0.1',
        iface: 'v-victim',
        network_id: 'wired',
        retries: 3,
      };
      const hash = computeEntryHash(prev, 2, ts, 'tofu_unprotected', data);
      return [cloned[0], cloned[1], { idx: 2, ts, type: 'tofu_unprotected', data, prev, hash }];
    }

    if (tampered && cloned.length > 3) {
      // Simulate `sed` 1-byte tamper in entry #3 (`detect` observed_mac) without updating hash
      cloned[3] = {
        ...cloned[3],
        data: {
          ...cloned[3].data,
          observed_mac: '02:77:00:00:00:99',
        },
      };
    }
    return cloned;
  }, [baseChain, scenario, tampered]);

  const integrity = useMemo(() => verifyChain(displayedEntries), [displayedEntries, verifyPulseCount]);

  const currentStatus: StatusJson = useMemo(() => {
    const headHash = displayedEntries[displayedEntries.length - 1]?.hash ?? GENESIS_PREV;
    if (scenario === 'under_attack') {
      return {
        state: 'monitor',
        iface: 'v-victim',
        network_id: 'wired',
        gw_ip: '10.77.0.1',
        gw_mac: '02:77:00:00:00:01',
        pin_mode: 'always',
        pinned: true,
        under_attack: true,
        incidents_total: 1,
        last_incident_ts: 1761369122.31,
        chain_head: headHash,
        dropped_events: 0,
        updated: '2026-10-25T05:12:03.000000Z',
      };
    }
    if (scenario === 'unprotected') {
      return {
        state: 'unprotected',
        iface: 'v-victim',
        network_id: 'wired',
        gw_ip: '10.77.0.1',
        gw_mac: null,
        pin_mode: 'always',
        pinned: false,
        under_attack: false,
        incidents_total: 0,
        last_incident_ts: null,
        chain_head: headHash,
        dropped_events: 0,
        updated: '2026-10-25T05:12:03.100000Z',
      };
    }
    if (scenario === 'conflict') {
      return {
        state: 'conflict',
        iface: 'v-victim',
        network_id: 'wired',
        gw_ip: '10.77.0.1',
        gw_mac: null,
        pin_mode: 'always',
        pinned: false,
        under_attack: false,
        incidents_total: 0,
        last_incident_ts: null,
        chain_head: headHash,
        dropped_events: 0,
        updated: '2026-10-25T05:12:00.950000Z',
      };
    }
    return {
      state: 'monitor',
      iface: 'v-victim',
      network_id: 'wired',
      gw_ip: '10.77.0.1',
      gw_mac: '02:77:00:00:00:01',
      pin_mode: 'always',
      pinned: true,
      under_attack: false,
      incidents_total: 1,
      last_incident_ts: 1761369122.31,
      chain_head: headHash,
      dropped_events: 0,
      updated: '2026-10-25T05:12:15.004120Z',
    };
  }, [scenario, displayedEntries]);

  const banner = useMemo(
    () => formatBanner(currentStatus, displayedEntries),
    [currentStatus, displayedEntries]
  );

  const filteredEntries = useMemo(() => {
    const rev = [...displayedEntries].reverse();
    if (feedFilter === 'incidents') {
      return rev.filter((e) => ['detect', 'heal', 'incident_close', 'tofu_conflict'].includes(e.type));
    }
    if (feedFilter === 'lifecycle') {
      return rev.filter((e) =>
        ['genesis', 'daemon_start', 'tofu_learned', 'tofu_unprotected', 'daemon_stop', 'network_changed'].includes(
          e.type
        )
      );
    }
    return rev;
  }, [displayedEntries, feedFilter]);

  const toggleDetails = (idx: number) => {
    setExpandedIdx((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  const copyCommand = (cmd: string) => {
    navigator.clipboard?.writeText(cmd).catch(() => {});
    setCopiedCmd(cmd);
    setTimeout(() => setCopiedCmd(null), 1800);
  };

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col">
      {/* Top Bar Contract: 3 zones separated by gap-8 */}
      <header className="border-b border-slate-800 bg-[#0d1322]">
        <div className="max-w-[1320px] mx-auto px-6 py-4 flex items-center justify-between gap-8">
          <a
            href="#monitor"
            className="text-lg font-bold tracking-tight text-white whitespace-nowrap shrink-0"
          >
            Sentinel-X
          </a>

          <nav
            aria-label="Primary Navigation"
            className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-300"
          >
            <a
              href="#monitor"
              className="hover:text-white transition-colors whitespace-nowrap shrink-0"
            >
              Protection Monitor
            </a>
            <a
              href="#incident-feed"
              className="hover:text-white transition-colors whitespace-nowrap shrink-0"
            >
              Hash-Chain Audit
            </a>
            <a
              href="#lab-runbook"
              className="hover:text-white transition-colors whitespace-nowrap shrink-0"
            >
              Namespace Lab
            </a>
            <a
              href="#threat-model"
              className="hover:text-white transition-colors whitespace-nowrap shrink-0"
            >
              Threat Model &amp; Limits
            </a>
          </nav>

          <div className="flex items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={() => setVerifyPulseCount((c) => c + 1)}
              className="px-4 py-2 text-xs font-semibold text-slate-950 bg-emerald-400 hover:bg-emerald-300 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              Re-Verify Log Chain
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-[1320px] w-full mx-auto px-6 py-8 space-y-10 flex-1">
        {/* Workspace Controls Bar: Banner State Inspector + Tamper Demo */}
        <section
          id="monitor"
          aria-label="Protection Status and Integrity Controls"
          className="space-y-5"
        >
          <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white">
                Gateway ARP Protection &amp; Chain-of-Custody Monitor
              </h1>
              <p className="text-sm text-slate-400 mt-1">
                Read-only local console driven by <code className="text-slate-300">status.json</code> (1 Hz) and{' '}
                <code className="text-slate-300">log.jsonl</code> (SHA-256 hash chain)
              </p>
            </div>

            {/* Log-Integrity Badge (WP8 Requirement #3) */}
            <div className="flex flex-wrap sm:flex-nowrap items-center gap-3 shrink-0">
              <div
                data-testid="integrity-badge"
                role="status"
                className={`px-3.5 py-2 rounded-lg border font-mono text-xs font-semibold flex items-center gap-2 whitespace-nowrap shrink-0 ${
                  integrity.ok
                    ? 'bg-emerald-950/60 border-emerald-600/70 text-emerald-300'
                    : 'bg-red-950/80 border-red-500 text-red-200'
                }`}
              >
                {integrity.ok ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                ) : (
                  <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                )}
                <span>Chain Integrity: {integrity.badge}</span>
                {integrity.reason && (
                  <span className="text-red-300">({integrity.reason})</span>
                )}
              </div>

              <button
                type="button"
                onClick={() => {
                  if (scenario === 'conflict' || scenario === 'unprotected') {
                    setScenario('protected');
                  }
                  setTampered((prev) => !prev);
                }}
                className={`px-3.5 py-2 rounded-lg text-xs font-semibold border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  tampered
                    ? 'bg-slate-800 border-slate-600 text-slate-100 hover:bg-slate-700'
                    : 'bg-red-950/50 border-red-700/70 text-red-200 hover:bg-red-900/50'
                }`}
              >
                {tampered ? 'Restore Original log.jsonl' : 'Simulate 1-Byte Log Tamper (idx #3)'}
              </button>
            </div>
          </div>

          {/* Interactive State Selector for verifying all 4 WP8 Banner States */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#0f172a] border border-slate-800 rounded-lg p-3">
            <div className="text-xs text-slate-400 font-medium">
              Inspect <code className="text-slate-300">status.json</code> State Transitions (§9 WP8):
            </div>
            <div
              role="group"
              aria-label="Banner State Selector"
              className="flex flex-wrap items-center gap-1.5"
            >
              <button
                type="button"
                onClick={() => setScenario('protected')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  scenario === 'protected'
                    ? 'bg-emerald-500 text-slate-950 font-semibold'
                    : 'bg-slate-900 text-slate-300 hover:text-white border border-slate-800'
                }`}
              >
                Protected (Locked)
              </button>
              <button
                type="button"
                onClick={() => setScenario('under_attack')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  scenario === 'under_attack'
                    ? 'bg-red-500 text-white font-semibold'
                    : 'bg-slate-900 text-slate-300 hover:text-white border border-slate-800'
                }`}
              >
                Under Attack (MITM Active)
              </button>
              <button
                type="button"
                onClick={() => {
                  setTampered(false);
                  setScenario('unprotected');
                }}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  scenario === 'unprotected'
                    ? 'bg-amber-400 text-slate-950 font-semibold'
                    : 'bg-slate-900 text-slate-300 hover:text-white border border-slate-800'
                }`}
              >
                Not Protected (No Reply)
              </button>
              <button
                type="button"
                onClick={() => {
                  setTampered(false);
                  setScenario('conflict');
                }}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  scenario === 'conflict'
                    ? 'bg-amber-400 text-slate-950 font-semibold'
                    : 'bg-slate-900 text-slate-300 hover:text-white border border-slate-800'
                }`}
              >
                TOFU Conflict (2 MACs)
              </button>
            </div>
          </div>

          {/* Plain-English Status Banner (WP8 Requirement #1) */}
          <div
            data-testid="status-banner"
            role="region"
            aria-label="Plain-English Protection Status Banner"
            className={`p-6 rounded-xl border flex items-start gap-4 ${
              banner.level === 'ok'
                ? 'bg-emerald-950/35 border-emerald-600/70 text-emerald-200'
                : banner.level === 'danger'
                  ? 'bg-red-950/45 border-red-500/80 text-red-100'
                  : 'bg-amber-950/40 border-amber-500/80 text-amber-100'
            }`}
          >
            <div className="mt-0.5 shrink-0">
              {banner.level === 'ok' ? (
                <Shield className="w-6 h-6 text-emerald-400" />
              ) : banner.level === 'danger' ? (
                <ShieldAlert className="w-6 h-6 text-red-400" />
              ) : (
                <ShieldOff className="w-6 h-6 text-amber-400" />
              )}
            </div>
            <div className="space-y-1.5">
              <div className="text-lg font-semibold tracking-tight leading-snug">
                {banner.headline}
              </div>
              <div className="text-xs font-mono opacity-80">
                Interface: {currentStatus.iface ?? '—'} ({currentStatus.network_id ?? '—'}) · Engine State:{' '}
                {currentStatus.state} · Kernel Neighbour:{' '}
                {currentStatus.pinned ? 'PERMANENT (locked)' : 'UNPINNED'} · Updated:{' '}
                {currentStatus.updated.slice(11, 19)} UTC
              </div>
            </div>
          </div>

          {/* 4 Telemetry Cards (WP8 Requirement #4) */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
              <div className="text-xs text-slate-400 font-medium">
                Pinned Gateway (IP · MAC · Mode)
              </div>
              <div
                data-testid="card-gateway"
                className="mt-2 font-mono text-sm font-semibold text-white tabular-nums"
              >
                {currentStatus.gw_ip ?? '—'} · {currentStatus.gw_mac ?? 'unpinned'} (
                {currentStatus.pin_mode ?? 'always'})
              </div>
            </div>

            <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
              <div className="text-xs text-slate-400 font-medium">Total Incidents</div>
              <div
                data-testid="card-incidents"
                className="mt-2 font-mono text-2xl font-semibold text-white tabular-nums"
              >
                {currentStatus.incidents_total}
              </div>
            </div>

            <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
              <div className="text-xs text-slate-400 font-medium">Last Incident Timestamp</div>
              <div
                data-testid="card-last-incident"
                className="mt-2 font-mono text-sm font-semibold text-white tabular-nums"
              >
                {currentStatus.last_incident_ts
                  ? `${new Date(currentStatus.last_incident_ts * 1000).toISOString().slice(11, 23)} UTC`
                  : 'None'}
              </div>
            </div>

            <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
              <div className="text-xs text-slate-400 font-medium">
                Bounded Queue Dropped Events
              </div>
              <div
                data-testid="card-dropped"
                className="mt-2 font-mono text-2xl font-semibold text-white tabular-nums"
              >
                {currentStatus.dropped_events}
              </div>
            </div>
          </div>
        </section>

        {/* Incident Feed & SHA-256 Hash-Chain Audit Log (WP8 Requirement #2) */}
        <section
          id="incident-feed"
          aria-label="Plain-English Incident Feed and Hash-Chained Log"
          className="bg-[#111827] border border-slate-800 rounded-xl p-6 space-y-5"
        >
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
            <div>
              <h2 className="text-lg font-semibold text-white">
                01. Incident Feed &amp; Hash-Chained Audit Log (<code className="text-sm">log.jsonl</code>)
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Plain-English sentences rendered from <code className="text-slate-300">detect</code>,{' '}
                <code className="text-slate-300">heal</code>, and{' '}
                <code className="text-slate-300">incident_close</code> records. Expand any row to inspect canonical JSON and SHA-256 links.
              </p>
            </div>

            <div
              role="group"
              aria-label="Filter Log Feed"
              className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg self-start"
            >
              <button
                type="button"
                onClick={() => setFeedFilter('all')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  feedFilter === 'all'
                    ? 'bg-slate-800 text-white font-semibold'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                All Entries ({displayedEntries.length})
              </button>
              <button
                type="button"
                onClick={() => setFeedFilter('incidents')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  feedFilter === 'incidents'
                    ? 'bg-slate-800 text-white font-semibold'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Security Incidents
              </button>
              <button
                type="button"
                onClick={() => setFeedFilter('lifecycle')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  feedFilter === 'lifecycle'
                    ? 'bg-slate-800 text-white font-semibold'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                TOFU &amp; Lifecycle
              </button>
            </div>
          </div>

          <div className="divide-y divide-slate-800/80">
            {filteredEntries.map((entry) => {
              const isBad = !integrity.ok && integrity.bad_idx === entry.idx;
              const isExpanded = Boolean(expandedIdx[entry.idx]);
              return (
                <div
                  key={entry.idx}
                  data-testid={`log-entry-${entry.idx}`}
                  className={`py-4 first:pt-1 last:pb-1 ${
                    isBad ? 'bg-red-950/30 -mx-3 px-3 rounded-lg border border-red-500/60' : ''
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="text-sm font-medium text-slate-100 leading-relaxed">
                      {formatEntrySentence(entry)}
                    </div>
                    <div className="flex items-center gap-3 text-xs text-slate-400 font-mono shrink-0">
                      <span>entry #{entry.idx}</span>
                      <span aria-hidden="true">·</span>
                      <span className="text-slate-300">{entry.type}</span>
                      <span aria-hidden="true">·</span>
                      <button
                        type="button"
                        onClick={() => toggleDetails(entry.idx)}
                        aria-expanded={isExpanded}
                        className="text-emerald-400 hover:text-emerald-300 font-medium inline-flex items-center gap-1 cursor-pointer whitespace-nowrap shrink-0"
                      >
                        {isExpanded ? (
                          <>
                            <ChevronDown className="w-3.5 h-3.5" />
                            Hide Raw Entry
                          </>
                        ) : (
                          <>
                            <ChevronRight className="w-3.5 h-3.5" />
                            Details (#{entry.idx})
                          </>
                        )}
                      </button>
                    </div>
                  </div>

                  {isBad && (
                    <div className="mt-2 text-xs font-mono text-red-300">
                      Hash mismatch at entry #{entry.idx}: recorded hash does not match{' '}
                      <code>sha256(prev + canonical_json)</code>.
                    </div>
                  )}

                  {isExpanded && (
                    <div className="mt-3 bg-[#090d16] border border-slate-800 rounded-lg p-3.5 font-mono text-xs text-slate-300 space-y-2 overflow-x-auto">
                      <div className="text-slate-400">
                        prev: <span className="text-slate-200">{entry.prev}</span>
                      </div>
                      <div className="text-slate-400">
                        hash: <span className="text-emerald-300">{entry.hash}</span>
                      </div>
                      <pre className="text-xs text-slate-200 pt-2 border-t border-slate-800/80">
                        {JSON.stringify(entry, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>

        {/* Namespace Lab & 4-Pane Runbook Section */}
        <section
          id="lab-runbook"
          aria-label="Network Namespace Lab and 4-Pane Demo Runbook"
          className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch"
        >
          <div className="lg:col-span-6 bg-[#111827] border border-slate-800 rounded-xl p-6 flex flex-col justify-between space-y-5">
            <div className="space-y-3">
              <h2 className="text-lg font-semibold text-white">
                02. Isolated Namespace Lab Topology (<code className="text-sm">10.77.0.0/24</code>)
              </h2>
              <p className="text-sm text-slate-300 leading-relaxed">
                All integration tests and live attacks run inside isolated Linux network namespaces bridged over{' '}
                <code className="text-slate-200">sxbr0</code>. <code className="text-slate-200">lab/attack.sh</code>{' '}
                calls stock <code className="text-slate-200">arpspoof</code> only and refuses to execute unless the target interface lives inside an <code className="text-slate-200">sx-*</code> namespace.
              </p>

              <pre className="bg-[#090d16] border border-slate-800 rounded-lg p-4 font-mono text-xs text-slate-200 overflow-x-auto leading-relaxed">
{`                 sxbr0  (bridge in root ns, no IP)
        ┌─────────────────┼─────────────────┐
   sx-gw (v-gw)      sx-victim (v-victim)  sx-att (v-att)
   10.77.0.1/24      10.77.0.10/24         10.77.0.66/24
   02:77:00:00:00:01 02:77:00:00:00:10     02:77:00:00:00:66`}
              </pre>
            </div>

            <div className="space-y-2 pt-2 border-t border-slate-800">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-400">
                  5-Line Quickstart (README.md)
                </span>
                <button
                  type="button"
                  onClick={() =>
                    copyCommand(
                      'pip install -e ".[dev]"\nsudo make lab-up\nsudo ip netns exec sx-victim sentinelx run --iface v-victim --state-dir /tmp/sx-demo &\nsudo bash lab/attack.sh 4\nsentinelx verify-log --path /tmp/sx-demo/log.jsonl && sudo make lab-down'
                    )
                  }
                  className="text-xs font-medium text-emerald-400 hover:text-emerald-300 inline-flex items-center gap-1 cursor-pointer whitespace-nowrap shrink-0"
                >
                  {copiedCmd ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedCmd ? 'Copied' : 'Copy Quickstart'}
                </button>
              </div>
              <pre className="bg-[#090d16] border border-slate-800 rounded-lg p-3.5 font-mono text-xs text-emerald-300 overflow-x-auto">
{`pip install -e ".[dev]"
sudo make lab-up
sudo ip netns exec sx-victim sentinelx run --iface v-victim --state-dir /tmp/sx-demo &
sudo bash lab/attack.sh 4
sentinelx verify-log --path /tmp/sx-demo/log.jsonl && sudo make lab-down`}
              </pre>
            </div>
          </div>

          <div className="lg:col-span-6 bg-[#111827] border border-slate-800 rounded-xl p-6 flex flex-col justify-between space-y-5">
            <div className="space-y-3">
              <h2 className="text-lg font-semibold text-white">
                03. Active Healing &amp; Bidirectional Repair Spec (§6.4)
              </h2>
              <p className="text-sm text-slate-300 leading-relaxed">
                When <code className="text-slate-200">R1 (gateway_mac_mismatch)</code> triggers, the pure{' '}
                <code className="text-slate-200">Engine</code> aggregates flood packets per{' '}
                <code className="text-slate-200">(gw_ip, observed_mac)</code> and instructs the Executor to repair both directions:
              </p>

              <div className="space-y-3 font-mono text-xs">
                <div className="bg-[#090d16] border border-slate-800 rounded-lg p-3.5">
                  <div className="text-slate-400 mb-1">1. Outbound Protection (Kernel Neighbour Pin + Read-Back Verification)</div>
                  <code className="text-slate-100">
                    ip neigh replace 10.77.0.1 lladdr 02:77:00:00:00:01 dev v-victim nud permanent
                  </code>
                </div>
                <div className="bg-[#090d16] border border-slate-800 rounded-lg p-3.5">
                  <div className="text-slate-400 mb-1">2. Inbound Protection (Unicast Corrective ARP Reply to Router)</div>
                  <code className="text-slate-100">
                    Ether(src=our_mac, dst=gw_mac) / ARP(op=2, hwsrc=our_mac, psrc=our_ip, hwdst=gw_mac, pdst=gw_ip)
                  </code>
                </div>
                <div className="bg-[#090d16] border border-slate-800 rounded-lg p-3.5">
                  <div className="text-slate-400 mb-1">3. Round 2 Host-Namespace Safety Guard</div>
                  <code className="text-slate-100">
                    Compares /proc/self/ns/net with /proc/1/ns/net — refuses host execution unless --allow-host is set.
                  </code>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Threat Model, Known Limits (§13), and Targets Table */}
        <section
          id="threat-model"
          aria-label="Engineering Targets and Known Limitations"
          className="bg-[#111827] border border-slate-800 rounded-xl p-6 space-y-6"
        >
          <div>
            <h2 className="text-lg font-semibold text-white">
              04. Engineering Targets (Being Measured) &amp; Known Limitations (§13)
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Per Round 2 rules (§0.1), deck metrics are stated strictly as engineering targets until full 50-run benchmark suites execute.
            </p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-xs text-slate-400">
                  <th className="py-2.5 pr-4 font-medium">Dimension</th>
                  <th className="py-2.5 px-4 font-medium">Deck Target (Being Measured)</th>
                  <th className="py-2.5 pl-4 font-medium">Round 2 Verification Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70 font-mono text-xs">
                <tr>
                  <td className="py-3 pr-4 font-sans text-slate-200">Detect + Verified Heal Latency</td>
                  <td className="py-3 px-4 text-amber-300 tabular-nums">&lt; 500 ms (target)</td>
                  <td className="py-3 pl-4 text-slate-300">Verified in lab e2e (~6–15 ms on veth bridge)</td>
                </tr>
                <tr>
                  <td className="py-3 pr-4 font-sans text-slate-200">MITM Mitigation Rate</td>
                  <td className="py-3 px-4 text-amber-300 tabular-nums">&ge; 95% over 50 runs (target)</td>
                  <td className="py-3 pl-4 text-slate-300">PERMANENT kernel pin + router corrective ARP verified</td>
                </tr>
                <tr>
                  <td className="py-3 pr-4 font-sans text-slate-200">False Positive Rate</td>
                  <td className="py-3 px-4 text-amber-300 tabular-nums">0 FP over 50+ scenarios (target)</td>
                  <td className="py-3 pl-4 text-slate-300">Simulated packet scenarios passing in pytest</td>
                </tr>
                <tr>
                  <td className="py-3 pr-4 font-sans text-slate-200">CPU Budget</td>
                  <td className="py-3 px-4 text-amber-300 tabular-nums">&lt; 5% of 1 core (target)</td>
                  <td className="py-3 pl-4 text-slate-300">BPF &quot;arp&quot; filter + store=False + bounded queue</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2 border-t border-slate-800 text-xs text-slate-300">
            <div className="space-y-1">
              <div className="font-semibold text-white">TOFU First-Contact Window</div>
              <p className="text-slate-400 leading-relaxed">
                Multi-probe conflict detection catches concurrent spoofers when &ge; 2 MACs reply, but cannot defeat an inline attacker who suppresses the router at initial join.
              </p>
            </div>
            <div className="space-y-1">
              <div className="font-semibold text-white">Hash-Chain Tail Truncation</div>
              <p className="text-slate-400 leading-relaxed">
                SHA-256 chaining detects mid-file edits, deletions, and reordering. Detecting tail truncation or full regeneration by local root requires anchoring the head hash externally.
              </p>
            </div>
            <div className="space-y-1">
              <div className="font-semibold text-white">Scope &amp; VRRP/HSRP Trade-Off</div>
              <p className="text-slate-400 leading-relaxed">
                Protects IPv4 host &harr; default gateway only (not peer-to-peer LAN or IPv6 NDP). Virtual router MAC prefixes are allowed only if the gateway was learned as virtual at TOFU.
              </p>
            </div>
          </div>
        </section>
      </main>

      <footer className="border-t border-slate-800/80 py-5 px-6 text-xs text-slate-400">
        <div className="max-w-[1320px] mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <div>Sentinel-X · Team Aparajitha · YUKTHI 2026 Round 2 Prototype</div>
          <div>Read-Only Local Audit Console · MIT License</div>
        </div>
      </footer>
    </div>
  );
}
