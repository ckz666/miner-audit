"""
Passive port scanner — identifies open ports on target hosts.

Uses raw sockets, no external dependencies. Fast, concurrent, read-only.
"""

import asyncio
import hashlib
import ipaddress
import os
import socket
import struct
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
    8333: "Bitcoin Core P2P (often paired with a mining pool)",
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


async def _verify_ssh(reader: asyncio.StreamReader, timeout: float) -> bool:
    """SSH servers send their banner ('SSH-2.0-...') unprompted, immediately
    on connect — no request needed."""
    try:
        banner = await asyncio.wait_for(reader.read(64), timeout=timeout)
        return banner.startswith(b"SSH-")
    except (asyncio.TimeoutError, OSError):
        return False


async def _verify_stratum(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, timeout: float) -> bool:
    """Stratum V1 is JSON-RPC over a raw TCP line stream. mining.subscribe is
    the standard handshake request — read-only, no credentials, exactly what
    a real miner sends first."""
    try:
        writer.write(b'{"id":1,"method":"mining.subscribe","params":[]}\n')
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(512), timeout=timeout)
        stripped = resp.strip()
        return stripped.startswith(b"{") and b'"id"' in stripped
    except (asyncio.TimeoutError, OSError):
        return False


async def _verify_cgminer(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, timeout: float) -> bool:
    """cgminer's RPC API takes a single-line JSON command and replies with
    JSON (classic cgminer null-terminates the reply; most derivatives don't
    bother). 'version' is a read-only info query, same as our HTTP GETs."""
    try:
        writer.write(b'{"command":"version"}')
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        stripped = resp.strip(b"\x00").strip()
        return stripped.startswith(b"{") and b"STATUS" in resp.upper()
    except (asyncio.TimeoutError, OSError):
        return False


def _bitcoin_version_payload() -> bytes:
    """Minimal but valid Bitcoin P2P 'version' message payload — same
    handshake any Bitcoin node sends when connecting to a peer, just to
    identify the protocol. No different in spirit than the JSON probes
    above; nothing here writes to or configures the remote node."""
    version = struct.pack("<i", 70015)
    services = struct.pack("<Q", 0)
    timestamp = struct.pack("<q", int(time.time()))
    # addr_recv / addr_from: services(8) + ip(16, IPv4-mapped IPv6) + port(2) = 26 bytes.
    # Real values don't matter for a bare handshake probe — any well-formed
    # address is accepted.
    dummy_addr = struct.pack("<Q", 0) + (b"\x00" * 10 + b"\xff\xff" + bytes(4)) + struct.pack(">H", 8333)
    nonce = struct.pack("<Q", int.from_bytes(os.urandom(8), "little"))
    user_agent = b"\x00"  # varint 0 = empty string
    start_height = struct.pack("<i", 0)
    relay = b"\x00"
    return version + services + timestamp + dummy_addr + dummy_addr + nonce + user_agent + start_height + relay


async def _verify_bitcoin_p2p(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, timeout: float) -> bool:
    """Bitcoin's P2P wire protocol requires the connecting side to speak
    first (real nodes never send anything unprompted, unlike SSH) — sends a
    minimal 'version' message and checks the reply starts with the real
    network magic bytes, which is effectively impossible for an unrelated
    service or middlebox to produce by coincidence."""
    MAGIC = b"\xf9\xbe\xb4\xd9"  # mainnet
    try:
        payload = _bitcoin_version_payload()
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        command = b"version".ljust(12, b"\x00")
        header = MAGIC + command + struct.pack("<I", len(payload)) + checksum
        writer.write(header + payload)
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(4), timeout=timeout)
        return resp == MAGIC
    except (asyncio.TimeoutError, OSError):
        return False


# Ports where a plain TCP connect isn't enough evidence on its own — a
# middlebox, deception tool, or unrelated service can complete a TCP
# handshake on any port without actually speaking the protocol we're
# inferring from the port number. HTTP-ish ports (80/443/8080) aren't in
# this table: fingerprint_host()'s GET request and title/body matching
# already only succeeds against a real response, so a middlebox there just
# naturally fails to match any signature instead of silently being trusted.
_PROTOCOL_VERIFIERS = {22, 3333, 4028, 8333}


async def _check_port(
    sem: asyncio.Semaphore,
    ip: str,
    port: int,
    timeout: float = 1.0,
    rate_limiter: Optional[_RateLimiter] = None,
) -> tuple[int, bool]:
    """Check if a single TCP port is open. Returns (port, is_open).

    For ports where the port number alone is otherwise treated as a strong
    signal (SSH, Stratum, cgminer RPC, Bitcoin P2P — see fingerprint.py's
    fallback logic for hosts with no HTTP match, and _assess_risk for
    8333), a bare TCP connect isn't trusted on its own: verified with a
    minimal read-only protocol probe first.
    """
    async with sem:
        if rate_limiter is not None:
            await rate_limiter.acquire()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return port, False

        is_open = True
        if port in _PROTOCOL_VERIFIERS:
            try:
                if port == 22:
                    is_open = await _verify_ssh(reader, timeout)
                elif port == 3333:
                    is_open = await _verify_stratum(reader, writer, timeout)
                elif port == 4028:
                    is_open = await _verify_cgminer(reader, writer, timeout)
                elif port == 8333:
                    is_open = await _verify_bitcoin_p2p(reader, writer, timeout)
            except Exception:
                is_open = False

        # The handshake already succeeded at this point — the port is open
        # regardless of what happens during teardown. Embedded miner
        # network stacks routinely RST on close, so a cleanup failure here
        # must not flip an open port to closed.
        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass
        return port, is_open


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
