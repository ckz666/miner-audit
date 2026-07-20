"""
Passive port scanner — identifies open ports on target hosts.

Uses raw sockets, no external dependencies. Fast, concurrent, read-only.
"""

import asyncio
import ipaddress
import socket
import time
from dataclasses import dataclass, field
from typing import Optional

# Only scan ports relevant to mining infrastructure
MINER_PORTS = {
    80: "HTTP (Miner Web UI)",
    443: "HTTPS (Miner Web UI)",
    22: "SSH (Miner Admin)",
    3333: "Stratum V1 (Mining Protocol)",
    4028: "cgminer RPC API",
    8080: "HTTP Alt (Miner Web UI)",
}


@dataclass
class HostResult:
    ip: str
    open_ports: dict[int, str] = field(default_factory=dict)
    error: Optional[str] = None
    scan_time_ms: float = 0.0


class _RateLimiter:
    """
    Token-bucket limiter capping new connection attempts per second.

    Concurrency alone doesn't bound packet rate: on a large, mostly-empty
    range each dead host fails in milliseconds, so even a modest
    concurrency ceiling can turn into a burst of tens of thousands of SYNs
    per second — far beyond what intermediate network gear (router
    conntrack tables, port-scan-detection firewalls) can absorb, and it can
    end up dropping legitimate traffic along with the scan's own packets.
    This throttles the actual attempt rate regardless of how many hosts are
    being scanned "concurrently".
    """

    def __init__(self, rate: float):
        self.rate = rate
        self.capacity = max(1.0, rate)
        self.tokens = self.capacity
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            while True:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.last_refill) * self.rate)
                self.last_refill = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                await asyncio.sleep((1 - self.tokens) / self.rate)


async def _check_port(
    sem: asyncio.Semaphore,
    ip: str,
    port: int,
    timeout: float = 1.0,
    rate_limiter: Optional[_RateLimiter] = None,
) -> tuple[int, bool]:
    """Check if a single TCP port is open. Returns (port, is_open)."""
    async with sem:
        if rate_limiter is not None:
            await rate_limiter.acquire()
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return port, False

        # The handshake already succeeded at this point — the port is open
        # regardless of what happens during teardown. Embedded miner
        # network stacks routinely RST on close, so a cleanup failure here
        # must not flip an open port to closed.
        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass
        return port, True


async def scan_host(
    ip: str,
    ports: list[int] = None,
    concurrency: int = 50,
    timeout: float = 1.0,
    rate_limiter: Optional[_RateLimiter] = None,
) -> HostResult:
    """Scan a single host for mining-related open ports."""
    if ports is None:
        ports = list(MINER_PORTS.keys())

    result = HostResult(ip=ip)
    sem = asyncio.Semaphore(concurrency)

    start = time.monotonic()

    try:
        tasks = [_check_port(sem, ip, port, timeout, rate_limiter) for port in ports]
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)

        for outcome in outcomes:
            if isinstance(outcome, Exception):
                continue
            port, is_open = outcome
            if is_open:
                result.open_ports[port] = MINER_PORTS.get(port, f"Port {port}")

    except Exception as e:
        result.error = str(e)

    result.scan_time_ms = (time.monotonic() - start) * 1000
    return result


def scale_concurrency(num_hosts: int, concurrency: int = 200) -> int:
    """
    Auto-scale port-scan concurrency for large ranges so there are always
    enough in-flight scans to keep the rate limiter's token bucket
    saturated. This no longer needs to be conservative on its own —
    rate_limit is what actually bounds packets-per-second now.
    """
    if num_hosts > 30000:
        return max(concurrency, 400)
    elif num_hosts > 10000:
        return max(concurrency, 300)
    return concurrency


def _parse_targets(target: str) -> list[str]:
    """Parse scan targets into a list of IP strings.

    Each comma-separated segment is parsed independently — a malformed
    entry (bad CIDR, bad range, unresolvable host) is skipped rather than
    aborting the whole batch, so one typo doesn't drop every other valid
    target from the scan.
    """
    ips = []
    for part in target.split(","):
        part = part.strip()
        try:
            if "/" in part:
                # CIDR range
                network = ipaddress.IPv4Network(part, strict=False)
                ips.extend(str(ip) for ip in network.hosts())
            elif "-" in part and "." in part:
                # Range like 192.168.1.1-192.168.1.10
                start, end = part.split("-")
                start_ip = ipaddress.IPv4Address(start.strip())
                end_ip = ipaddress.IPv4Address(end.strip())
                current = int(start_ip)
                last = int(end_ip)
                while current <= last:
                    ips.append(str(ipaddress.IPv4Address(current)))
                    current += 1
            else:
                # Single IP
                try:
                    ipaddress.IPv4Address(part)
                    ips.append(part)
                except ipaddress.AddressValueError:
                    # Try DNS resolve
                    try:
                        resolved = socket.gethostbyname(part)
                        ips.append(resolved)
                    except socket.gaierror:
                        pass
        except ValueError:
            # Malformed CIDR (e.g. "/33") or malformed range (bad IP, or
            # more than one "-") — skip this segment, keep the rest.
            continue
    return ips
