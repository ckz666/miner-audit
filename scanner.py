#!/usr/bin/env python3
"""
miner-audit — Passive ASIC Miner Security Scanner
==================================================

Identifies Bitcoin mining hardware on a network and evaluates their security posture
using ONLY passive observation. No credentials are attempted. No configuration is changed.

Usage:
    python3 scanner.py 192.168.1.0/24              # Scan a subnet
    python3 scanner.py 10.0.0.1,10.0.0.2,10.0.0.3  # Scan specific IPs
    python3 scanner.py 192.168.1.1-192.168.1.50    # Scan a range
    python3 scanner.py -v 192.168.1.0/24           # Verbose output
    python3 scanner.py --json-output 192.168.1.0/24 # JSON output
    python3 scanner.py --timeout 2 192.168.1.0/24   # Custom timeout

WARNING: Only scan networks you own or have explicit written permission to test.
Unauthorized scanning may violate laws in your jurisdiction.
"""

import argparse
import asyncio
import json
import math
import os
import random
import signal
import sys
import time
from typing import Optional

from ports import scan_host, MINER_PORTS, _parse_targets, _RateLimiter, scale_concurrency
from fingerprint import fingerprint_host, MinerFingerprint

# ─── Terminal Colors ───────────────────────────────────────────────

COLORS = {
    "critical":  "\033[1;41m",
    "high":      "\033[1;31m",
    "medium":    "\033[1;33m",
    "low":       "\033[1;32m",
    "info":      "\033[1;34m",
    "unknown":   "\033[1;37m",
    "reset":     "\033[0m",
    "bold":      "\033[1m",
    "dim":       "\033[2m",
    "header":    "\033[1;36m",
    "progress":  "\033[1;33m",
    "success":   "\033[1;32m",
    "warn":      "\033[1;33m",
    "stage":     "\033[1;35m",
    "ip":        "\033[1;37m",
    "detail":    "\033[0;37m",
}

USE_COLORS = sys.stdout.isatty()
VERBOSE = False

# Bounds how many hosts are fingerprinted concurrently. Unlike the port scan
# step (which only opens one TCP connection per port per host and scales its
# semaphore with range size), fingerprinting issues several sequential HTTP
# requests per host — running it unbounded via bare asyncio.gather() would
# open connections to every host with an open port all at once, which is
# exactly the ">4000 simultaneous connections" problem ports.py's own
# concurrency scaling is designed to avoid. Kept as a separate, smaller
# semaphore from the port-scan one so the two steps — pipelined per host
# below — don't compete for the same concurrency budget.
FINGERPRINT_CONCURRENCY = 50


def c(color: str, text: str) -> str:
    if not USE_COLORS:
        return text
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


# ─── Progress Bar ──────────────────────────────────────────────────

def _progress_bar(current: int, total: int, label: str = "", width: int = 30):
    if total == 0:
        return
    pct = current / total
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    # "\033[K" erases from the cursor to the end of the line — used instead
    # of padding/overwriting with a guessed number of spaces, since the
    # label includes the last-scanned IP and can be longer than any fixed
    # width (a shorter next line would otherwise leave stale characters
    # from a longer previous one trailing after it).
    sys.stderr.write(f"\r  {c('progress', f'[{bar}]')} {pct*100:5.1f}% ({current}/{total})  {label}\033[K")
    sys.stderr.flush()


def _progress_done(label: str = ""):
    sys.stderr.write(f"\r\033[K  {c('success', '✓')} {label}\n")
    sys.stderr.flush()


def _verbose(line: str):
    if VERBOSE:
        sys.stderr.write(f"    {c('detail', line)}\n")
        sys.stderr.flush()


def _format_duration(seconds: float) -> str:
    """Format seconds as '0d:00h:03m:34s'."""
    total = int(round(seconds))
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    return f"{days}d:{hours:02d}h:{minutes:02d}m:{secs:02d}s"


def _stage(msg: str):
    sys.stderr.write(f"\n  {c('stage', '▸')} {msg}\n")
    sys.stderr.flush()


def _info(msg: str):
    sys.stderr.write(f"  {c('dim', msg)}\n")
    sys.stderr.flush()


# ─── Report Formatting ─────────────────────────────────────────────

def _format_fingerprint(fp: MinerFingerprint) -> str:
    lines = []
    risk_color = fp.risk_level

    vendor_model = f"{fp.vendor or 'Unknown'} {fp.model_hint or ''}".strip()
    lines.append(
        f"{c(risk_color, f'[{fp.risk_level.upper():>8}]')} "
        f"{c('bold', fp.ip):<16} "
        f"{c('header', vendor_model):<28} "
        f"{c('dim', fp.miner_id or 'unknown'):<22}"
    )

    for detail in fp.details:
        lines.append(f"          {detail}")

    if fp.firmware_version:
        lines.append(f"          {c('dim', f'Firmware: {fp.firmware_version}')}")

    ports_str = ", ".join(str(p) for p in fp.open_ports)
    lines.append(f"          {c('dim', f'Open ports: {ports_str}')}")

    if fp.auth_required is True:
        lines.append(f"          {c('low', 'Auth: Required ✓')}")
    elif fp.auth_required is False:
        lines.append(f"          {c('critical', 'Auth: NOT REQUIRED ✗')}")
    else:
        lines.append(f"          {c('medium', 'Auth: Unknown ?')}")

    lines.append("")
    return "\n".join(lines)


def print_report(
    fingerprints: list[MinerFingerprint],
    scan_time: float,
    hosts_scanned: int,
    hosts_total: int,
    output_json: bool = False,
):
    if output_json:
        result = {
            "scan_time_seconds": round(scan_time, 2),
            "hosts_total": hosts_total,
            "hosts_with_open_ports": hosts_scanned,
            "miners_found": len(fingerprints),
            "summary": {
                "critical": sum(1 for fp in fingerprints if fp.risk_level == "critical"),
                "high": sum(1 for fp in fingerprints if fp.risk_level == "high"),
                "medium": sum(1 for fp in fingerprints if fp.risk_level == "medium"),
                "low": sum(1 for fp in fingerprints if fp.risk_level == "low"),
                "info": sum(1 for fp in fingerprints if fp.risk_level == "info"),
            },
            "miners": [
                {
                    "ip": fp.ip,
                    "vendor": fp.vendor,
                    "model": fp.model_hint,
                    "miner_id": fp.miner_id,
                    "firmware_version": fp.firmware_version,
                    "auth_required": fp.auth_required,
                    "risk_level": fp.risk_level,
                    "open_ports": fp.open_ports,
                    "details": fp.details,
                }
                for fp in fingerprints
            ],
        }
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    # ─── Text report ───
    print()
    print(c("header", "╔══════════════════════════════════════════════════════════════════╗"))
    print(c("header", "║              MINER AUDIT — Passive Security Scan                ║"))
    print(c("header", "╚══════════════════════════════════════════════════════════════════╝"))
    print()
    print(f"  Target:        {hosts_total} hosts")
    print(f"  Open ports:    {hosts_scanned} hosts ({hosts_scanned/hosts_total*100:.0f}%)" if hosts_total else "")
    print(f"  Miners found:  {len(fingerprints)}")
    print(f"  Scan time:     {scan_time:.1f}s")
    print()

    if not fingerprints:
        print(c("info", "  ✓ No mining devices detected on the scanned range."))
        print()
        return

    counts = {
        "critical": sum(1 for fp in fingerprints if fp.risk_level == "critical"),
        "high": sum(1 for fp in fingerprints if fp.risk_level == "high"),
        "medium": sum(1 for fp in fingerprints if fp.risk_level == "medium"),
        "low": sum(1 for fp in fingerprints if fp.risk_level == "low"),
        "info": sum(1 for fp in fingerprints if fp.risk_level == "info"),
    }
    summary_parts = []
    for level in ["critical", "high", "medium", "low", "info"]:
        if counts[level] > 0:
            summary_parts.append(f"{c(level, level.upper())}: {counts[level]}")
    print("  " + "  ".join(summary_parts))
    print()

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    fingerprints.sort(key=lambda fp: severity_order.get(fp.risk_level, 99))

    for fp in fingerprints:
        print(_format_fingerprint(fp))

    # Recommendations
    print(c("header", "─── Recommendations ───────────────────────────────────────────────"))
    print()

    if counts["critical"] > 0:
        print(c("critical", f"  ✗ {counts['critical']} CRITICAL finding(s):"), end=" ")
        print("Immediately isolate these devices from public networks.")
        print("     Apply firmware passwords and firewall rules before reconnecting.")
        print()

    if counts["high"] > 0:
        print(c("high", f"  ! {counts['high']} HIGH risk finding(s):"), end=" ")
        print("Stratum V1 is unencrypted. Consider upgrading to Stratum V2,")
        print("     or use a VPN between miners and pool endpoints.")
        print()

    if counts["medium"] > 0:
        print(c("medium", f"  ~ {counts['medium']} MEDIUM risk finding(s):"), end=" ")
        print("Review SSH access, firmware versions, and authentication settings.")
        print()

    print(c("dim", "  Always: Use unique strong passwords, keep firmware updated,"))
    print(c("dim", "  deploy miners behind a VPN, and enable pool payout address locking."))
    print()


# ─── Main Scanner Logic ─────────────────────────────────────────────

async def run_scan(
    target: str,
    timeout: float = 2.0,
    json_output: bool = False,
    ports: list[int] = None,
    rate_limit: Optional[float] = 300,
) -> tuple[list[MinerFingerprint], float, int, int]:
    start_total = time.monotonic()

    # Cooperative interrupt flag instead of relying on KeyboardInterrupt
    # landing inside a specific coroutine — SIGINT typically interrupts the
    # event loop's dispatch itself, not whichever "await" happens to be
    # pending in one particular task, so a plain try/except around a loop
    # body doesn't reliably catch it. A second Ctrl+C forces an immediate
    # exit in case cooperative cancellation is taking a moment.
    interrupted = asyncio.Event()
    _sigint_count = 0

    # Populated once the worker pool exists (below) — declared here (as
    # mutable containers, filled in later via .extend()/.add(), never
    # reassigned) so the signal handler's closure sees whatever's actually
    # in flight at the moment Ctrl+C fires, not just stop new work from
    # starting via the cooperative `interrupted` flag.
    scan_workers: list[asyncio.Task] = []
    fingerprint_tasks: set[asyncio.Task] = set()

    def _on_sigint():
        nonlocal _sigint_count
        _sigint_count += 1
        if _sigint_count >= 2:
            sys.stderr.write("\n  Second interrupt — exiting immediately.\n")
            os._exit(130)
        interrupted.set()
        for t in scan_workers:
            t.cancel()
        for t in fingerprint_tasks:
            t.cancel()

    asyncio.get_running_loop().add_signal_handler(signal.SIGINT, _on_sigint)

    # Parse targets upfront to know how many hosts
    all_ips = _parse_targets(target)
    total_hosts = len(all_ips)

    # Shuffle to spread timeout-prone hosts among fast-failing ones —
    # sequential IP order gets stuck on dead subnets that silently drop
    # packets.
    random.shuffle(all_ips)

    if ports is None:
        ports = list(MINER_PORTS.keys())

    if not json_output:
        _stage(f"Target: {c('bold', target)} → {total_hosts} host(s)")
        _info(f"Ports:  {', '.join(str(p) for p in ports)}")
        _info(f"Timeout: {timeout:.0f}s per host")
        _info(f"Rate limit: {rate_limit:.0f} conn/s" if rate_limit else c("warn", "Rate limit: DISABLED — may overwhelm routers/firewalls on large ranges"))
        # Warn on large ranges
        if total_hosts > 5000:
            if rate_limit:
                # Bounded by the rate limiter now, not by concurrency —
                # total attempts = hosts * ports, gated at rate_limit/sec.
                est = math.ceil(total_hosts * len(ports) / rate_limit)
            else:
                concurrency = 400 if total_hosts > 30000 else 300 if total_hosts > 10000 else 200
                est = math.ceil(total_hosts / concurrency * 0.2)  # ~0.2s avg per batch (dead IPs fail in ms)
            _info(c("warn", f"⚠  Large range ({total_hosts} hosts). Est. scan time: ~{_format_duration(est)}"))
            if timeout < 2.0:
                _info(c("dim", f"   Slow IoT devices (ESP32/Shelly) may need ≥2s timeout to respond."))

    if total_hosts == 0:
        return [], time.monotonic() - start_total, 0, 0

    # ── Pipeline: scan + fingerprint per host ────────────────────
    #
    # A fixed-size pool of scan workers pulls IPs from a shared iterator —
    # NOT one asyncio.Task created per host up front. Creating a Task per
    # host (the previous approach) scales fine into the tens of thousands
    # (a /16) but collapses on ranges like a /12 (1M+ hosts): each pending
    # Task holds a live coroutine frame plus a waiter entry on the
    # concurrency semaphore, so thousands become a few hundred MB and
    # millions become a memory/scheduler meltdown — a semaphore only bounds
    # how many tasks are *actively working*, not how many *exist*. A worker
    # pool keeps exactly `concurrency` scan tasks alive regardless of range
    # size.
    #
    # Fingerprinting stays on its own smaller semaphore rather than folded
    # into the same worker loop: fingerprinting takes several sequential
    # HTTP round trips, so a scan worker that fingerprinted inline would sit
    # idle on a slow host instead of moving on to scan the next one. Instead
    # a worker fires off fingerprinting as its own tracked task and
    # immediately continues scanning — that overlap (fingerprinting one host
    # while others are still being port-scanned) is the whole point of the
    # pipeline. Hits are a small fraction of a real range, so one task per
    # *hit* (not per host) stays cheap even on huge ranges.
    if not json_output:
        _stage(f"Scanning + fingerprinting {total_hosts} host(s)... (Ctrl+C to stop early and report what's found so far)")

    concurrency = scale_concurrency(total_hosts)
    fp_sem = asyncio.Semaphore(FINGERPRINT_CONCURRENCY)
    rate_limiter = _RateLimiter(rate_limit) if rate_limit else None

    fingerprints: list[MinerFingerprint] = []
    progress = {"scanned": 0, "hits": 0, "found": 0}
    print_lock = asyncio.Lock()

    def _update_progress(last_ip: str):
        if not json_output:
            _progress_bar(
                progress["scanned"], total_hosts,
                f"open: {progress['hits']}  miners: {progress['found']}  last: {last_ip}",
            )

    async def _fingerprint_one(hr) -> None:
        async with fp_sem:
            result = await fingerprint_host(hr.ip, hr.open_ports, timeout=timeout)
        if result is not None:
            fingerprints.append(result)
            progress["found"] += 1

        if not json_output:
            # Serialize terminal writes — with concurrent hosts in flight,
            # unsynchronized stderr writes can otherwise interleave into
            # garbled output.
            async with print_lock:
                if result is not None:
                    sys.stderr.write("\r\033[K")
                    tag = c(result.risk_level, f"[{result.risk_level.upper()}]")
                    vendor_info = f"{result.vendor or '?'} {result.model_hint or ''}"
                    fw_info = f" (FW: {result.firmware_version})" if result.firmware_version else ""
                    sys.stderr.write(f"  {tag} {c('ip', hr.ip):<16} {c('header', vendor_info):<35}{c('dim', fw_info)}\n")
                    sys.stderr.flush()
                elif VERBOSE:
                    sys.stderr.write("\r\033[K")
                    sys.stderr.write(f"  {c('dim', '·')} {c('detail', hr.ip):<16} not a mining device\n")
                    sys.stderr.flush()
                _update_progress(hr.ip)

    ip_iter = iter(all_ips)

    async def _scan_worker() -> None:
        # Advancing a plain iterator via `for` is synchronous (no await in
        # between), so multiple workers sharing `ip_iter` can't race each
        # other onto the same IP — asyncio only switches coroutines at an
        # `await`, by which point this worker has already claimed its `ip`.
        for ip in ip_iter:
            if interrupted.is_set():
                return
            hr = await scan_host(ip, ports, concurrency=50, timeout=timeout, rate_limiter=rate_limiter)
            progress["scanned"] += 1

            if hr.open_ports:
                progress["hits"] += 1
                t = asyncio.ensure_future(_fingerprint_one(hr))
                fingerprint_tasks.add(t)
                t.add_done_callback(fingerprint_tasks.discard)
            elif not json_output:
                async with print_lock:
                    _update_progress(ip)

    # Extends the same list the SIGINT handler (registered above) already
    # closes over, so a Ctrl+C reaching it cancels these directly.
    scan_workers.extend(asyncio.ensure_future(_scan_worker()) for _ in range(concurrency))

    await asyncio.gather(*scan_workers, return_exceptions=True)
    if fingerprint_tasks:
        await asyncio.gather(*fingerprint_tasks, return_exceptions=True)

    was_interrupted = interrupted.is_set()
    if not json_output:
        if was_interrupted:
            _progress_done(c("warn", f"⚠ Interrupted — {progress['scanned']}/{total_hosts} hosts processed, {len(fingerprints)} miner(s) identified so far ({time.monotonic()-start_total:.1f}s)"))
        else:
            _progress_done(f"Done — {progress['hits']}/{total_hosts} hosts with open ports, {len(fingerprints)} miner(s) identified ({time.monotonic()-start_total:.1f}s)")

    scan_time = time.monotonic() - start_total
    return fingerprints, scan_time, progress["hits"], total_hosts


# ─── CLI ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="miner-audit — Passive ASIC Miner Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  python3 scanner.py 192.168.1.0/24           # Scan a /24 subnet
  python3 scanner.py 10.0.0.1,10.0.0.2        # Scan specific IPs
  python3 scanner.py 192.168.1.1-192.168.1.50 # Scan an IP range
  python3 scanner.py -v 10.0.0.0/24           # Verbose: show every host
  python3 scanner.py -j 10.0.0.0/24           # JSON report
  python3 scanner.py -p 80,3333,8081 10.0.0.0/24  # Custom ports

WARNING: Only scan networks you own or have permission to test.
        """,
    )
    parser.add_argument(
        "target",
        help="IP, CIDR range, comma-separated IPs, or IP range (start-end)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output — show every host checked and non-miner results",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=float,
        default=2.0,
        help="Per-host timeout in seconds (default: 2.0)",
    )
    parser.add_argument(
        "--json-output", "-j",
        action="store_true",
        help="Output results as JSON instead of formatted text",
    )
    parser.add_argument(
        "--ports", "-p",
        type=str,
        default=None,
        help="Custom port list (comma-separated, e.g. '80,8081,3333'). Default: miner-relevant ports.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output (force plain text)",
    )
    parser.add_argument(
        "--rate-limit", "-r",
        type=float,
        default=300,
        help="Max new connection attempts per second across the whole scan (default: 300). "
             "This bounds packets-per-second regardless of range size — large mostly-empty "
             "ranges fail fast per host, so concurrency alone can otherwise burst well beyond "
             "what a router's connection tracking / port-scan detection can absorb, dropping "
             "legitimate traffic along with it. Set to 0 to disable.",
    )

    args = parser.parse_args()

    global USE_COLORS, VERBOSE
    if args.no_color:
        USE_COLORS = False
    VERBOSE = args.verbose

    ports = None
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            parser.error(f"invalid --ports value {args.ports!r} — expected comma-separated integers, e.g. '80,8081,3333'")

    rate_limit = args.rate_limit if args.rate_limit > 0 else None

    # run_scan() already turns a Ctrl+C during either phase into a graceful
    # early stop with partial results. This is only a last-resort net for
    # an interrupt landing somewhere else (e.g. a second Ctrl+C, or before
    # either phase has started) so it prints a clean line instead of a
    # raw traceback.
    try:
        fingerprints, scan_time, hosts_scanned, hosts_total = asyncio.run(
            run_scan(args.target, timeout=args.timeout, json_output=args.json_output, ports=ports, rate_limit=rate_limit)
        )
    except KeyboardInterrupt:
        sys.stderr.write("\n  Interrupted.\n")
        sys.exit(130)

    print_report(fingerprints, scan_time, hosts_scanned, hosts_total, output_json=args.json_output)


if __name__ == "__main__":
    main()
