# sentinelx/cli.py
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import replace
from pathlib import Path

from sentinelx.chainlog import ChainLog
from sentinelx.config import AppConfig
from sentinelx.daemon import Daemon, is_host_netns
from sentinelx.models import ArpEvent, NetBackend
from sentinelx.netctl import DryRunBackend, LinuxBackend
from sentinelx.sniffer import Sniffer
from sentinelx.trust import JsonTrustStore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinelx",
        description="Sentinel-X: ARP-poisoning MITM detection, TOFU pinning, and hash-chained audit daemon.",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    # run
    p_run = sub.add_parser("run", help="Run the Sentinel-X protection daemon")
    p_run.add_argument("--iface", default=None, help="Network interface (default: from config or auto)")
    p_run.add_argument("--config", default=None, help="Path to config.toml")
    p_run.add_argument("--state-dir", default=None, help="State directory (default: /var/lib/sentinelx)")
    p_run.add_argument("--dry-run", action="store_true", help="Do not modify kernel state or send frames")
    p_run.add_argument(
        "--allow-host",
        action="store_true",
        help="Allow running in the host network namespace (prints R2 network-change warning)",
    )

    # status
    p_status = sub.add_parser("status", help="Show current daemon status from status.json")
    p_status.add_argument("--state-dir", default="/var/lib/sentinelx", help="State directory")
    p_status.add_argument("--json", action="store_true", help="Print raw status.json")

    # verify-log
    p_verify = sub.add_parser("verify-log", help="Verify hash-chained log.jsonl integrity")
    p_verify.add_argument("--path", default=None, help="Path to log.jsonl")
    p_verify.add_argument("--state-dir", default="/var/lib/sentinelx", help="State directory")

    # trust
    p_trust = sub.add_parser("trust", help="Inspect or update TrustStore entries")
    p_trust.add_argument("--state-dir", default="/var/lib/sentinelx", help="State directory")
    p_trust.add_argument("--show", action="store_true", help="Display all trust entries")
    p_trust.add_argument("--add-mac", default=None, metavar="MAC", help="Add an allowed gateway MAC")
    p_trust.add_argument("--forget", action="store_true", help="Forget trust entry for key")
    p_trust.add_argument("--key", default=None, help="Trust key (<iface>|<network_id>|<gw_ip>)")

    # sniff
    p_sniff = sub.add_parser("sniff", help="Debug ARP sniffer on an interface")
    p_sniff.add_argument("--iface", required=True, help="Interface to sniff ARP packets on")
    p_sniff.add_argument("--count", type=int, default=0, help="Stop after N ARP packets (0 = infinite)")

    # dashboard
    p_dash = sub.add_parser("dashboard", help="Run the read-only local web dashboard (127.0.0.1)")
    p_dash.add_argument("--port", type=int, default=8787, help="Port to bind on 127.0.0.1 (default: 8787)")
    p_dash.add_argument("--state-dir", default="/var/lib/sentinelx", help="State directory to read")

    return parser


def _cmd_run(args: argparse.Namespace) -> int:
    # R2 safety guard (HARD RULE): refuse to start in host netns unless --allow-host is passed
    if is_host_netns():
        if not args.allow_host:
            print(
                "ERROR: Refusing to start in the host network namespace (R2 safety guard).\n"
                "Run inside a lab namespace (e.g. `ip netns exec sx-victim sentinelx run ...`) "
                "or pass `--allow-host` if you understand the risk.",
                file=sys.stderr,
            )
            return 2
        print(
            "WARNING: Running in host network namespace (--allow-host): "
            "network-change handling (§6.5) is not built in Round 2; a stale pin can disrupt connectivity.",
            file=sys.stderr,
        )

    cfg = AppConfig.load(args.config) if args.config else AppConfig()
    core = cfg.core
    if args.iface:
        core = replace(core, iface=args.iface)
    if args.state_dir:
        core = replace(core, state_dir=Path(args.state_dir))
    if args.dry_run:
        core = replace(core, dry_run=True)
    cfg = replace(cfg, core=core)

    linux_backend = LinuxBackend(iface_override=cfg.core.iface)
    backend: NetBackend = DryRunBackend(inner=linux_backend) if cfg.core.dry_run else linux_backend

    daemon = Daemon(
        cfg=cfg,
        backend=backend,
        enable_live_sniffer=not cfg.core.dry_run,
    )
    try:
        asyncio.run(daemon.run())
    except KeyboardInterrupt:
        pass
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    status_path = Path(args.state_dir) / "status.json"
    if not status_path.exists():
        print(f"No status.json found in {args.state_dir}", file=sys.stderr)
        return 1
    raw = status_path.read_text(encoding="utf-8")
    if args.json:
        print(raw.strip())
        return 0
    data = json.loads(raw)
    print(f"State:           {data.get('state')}")
    print(f"Interface:       {data.get('iface')} ({data.get('network_id')})")
    print(f"Gateway:         {data.get('gw_ip')} -> {data.get('gw_mac')}")
    print(f"Pinned:          {data.get('pinned')} (mode={data.get('pin_mode', 'always')})")
    print(f"Under Attack:    {data.get('under_attack')}")
    print(f"Total Incidents: {data.get('incidents_total')}")
    print(f"Chain Head:      {data.get('chain_head')}")
    print(f"Dropped Events:  {data.get('dropped_events')}")
    print(f"Updated:         {data.get('updated')}")
    return 0


def _cmd_verify_log(args: argparse.Namespace) -> int:
    log_path = Path(args.path) if args.path else Path(args.state_dir) / "log.jsonl"
    res = ChainLog.verify(log_path)
    if res.ok:
        print(f"OK: verified {res.entries} entries (head={res.head})")
        return 0
    print(f"TAMPERED: bad_idx={res.bad_idx} reason={res.reason}")
    return 1


def _cmd_trust(args: argparse.Namespace) -> int:
    state_path = Path(args.state_dir) / "state.json"
    store = JsonTrustStore(state_path)
    entries = store.all_entries()

    if args.add_mac:
        target_key = args.key
        if not target_key:
            if len(entries) == 1:
                target_key = next(iter(entries.keys()))
            else:
                print("ERROR: Specify --key <iface>|<network_id>|<gw_ip> when adding a MAC.", file=sys.stderr)
                return 1
        store.add_allowed_mac(target_key, args.add_mac)
        print(f"Added allowed MAC {args.add_mac.lower()} to {target_key}")
        return 0

    if args.forget:
        if not args.key:
            for k in list(entries.keys()):
                store.forget(k)
            print("Cleared all trust entries.")
        else:
            store.forget(args.key)
            print(f"Forgot trust key {args.key}")
        return 0

    print(json.dumps(store.all_entries(), indent=2, sort_keys=True))
    return 0


def _cmd_sniff(args: argparse.Namespace) -> int:
    async def _run_sniff() -> int:
        loop = asyncio.get_running_loop()
        q: asyncio.Queue[ArpEvent] = asyncio.Queue(maxsize=1000)
        sniffer = Sniffer(iface=args.iface, queue=q, loop=loop)
        sniffer.start()
        seen = 0
        try:
            while True:
                ev = await q.get()
                op_name = "who-has" if ev.op == 1 else "is-at"
                print(
                    f"[{ev.ts:.6f}] dev={ev.iface} op={op_name} "
                    f"spa={ev.arp_spa} sha={ev.arp_sha} (eth_src={ev.eth_src}) -> "
                    f"tpa={ev.arp_tpa} tha={ev.arp_tha}",
                    flush=True,
                )
                seen += 1
                if args.count > 0 and seen >= args.count:
                    break
        finally:
            sniffer.stop()
        return 0

    try:
        return asyncio.run(_run_sniff())
    except KeyboardInterrupt:
        return 0


def _cmd_dashboard(args: argparse.Namespace) -> int:
    import uvicorn  # type: ignore[import-untyped]

    from sentinelx.dashboard.app import create_app

    app = create_app(state_dir=Path(args.state_dir))
    uvicorn.run(app, host="127.0.0.1", port=int(args.port), log_level="info")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    match args.subcommand:
        case "run":
            return _cmd_run(args)
        case "status":
            return _cmd_status(args)
        case "verify-log":
            return _cmd_verify_log(args)
        case "trust":
            return _cmd_trust(args)
        case "sniff":
            return _cmd_sniff(args)
        case "dashboard":
            return _cmd_dashboard(args)
        case _:
            parser.print_help()
            return 1
