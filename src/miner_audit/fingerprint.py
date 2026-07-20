"""
Passive miner fingerprinting — identifies ASIC miner make, model, firmware, and
authentication posture using only HTTP GET requests and TCP handshakes.

NO authentication credentials are attempted. NO configuration is modified.
Only observes what a miner voluntarily exposes on its default pages.
"""

import asyncio
import gzip
import json
import re
import ssl
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Optional

# Load signatures
_signatures_path = Path(__file__).parent / "signatures.json"
with open(_signatures_path) as f:
    _SIGNATURES = json.load(f)["miners"]

# Ports that should be probed with TLS. 443 is standard; 8443 is a common
# alt-HTTPS port on embedded web UIs.
_HTTPS_PORTS = {443, 8443}

# Ports that are already known to speak something other than HTTP — no
# point sending a GET and waiting out a full timeout for a response that
# will never come. Each of these already gets its own risk signal in
# _assess_risk.
_KNOWN_NON_HTTP_PORTS = {22, 3333, 4028, 8333}


@dataclass
class MinerFingerprint:
    ip: str
    vendor: Optional[str] = None       # e.g. "Bitmain", "MicroBT"
    miner_id: Optional[str] = None     # e.g. "antminer", "whatsminer"
    model_hint: Optional[str] = None   # e.g. "S19", "M50"
    firmware_version: Optional[str] = None
    auth_required: Optional[bool] = None  # True = 401/403, False = no auth visible, None = unknown
    open_ports: list[int] = field(default_factory=list)
    risk_level: str = "unknown"        # "critical", "high", "medium", "low", "info", "unknown"
    raw_banner: Optional[str] = None
    details: list[str] = field(default_factory=list)


async def _http_get(
    ip: str,
    path: str,
    port: int = 80,
    timeout: float = 3.0,
    use_ssl: bool = False,
) -> tuple[int, str, dict[str, str]]:
    """
    Perform an HTTP GET request. Returns (status_code, body, headers).

    Pure socket implementation — no requests/httpx dependency.
    Strips out any accidentally received Set-Cookie headers from response (irrelevant for scanners).
    """
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )

        request = (
            f"GET {path} HTTP/1.0\r\n"
            f"Host: {ip}\r\n"
            f"User-Agent: MinerAudit/1.0 (passive-scanner)\r\n"
            f"Accept: text/html,application/json,text/plain\r\n"
            f"Accept-Encoding: gzip\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        writer.write(request.encode())
        await writer.drain()

        # Read raw response. Stop as soon as we can tell the message is
        # complete (Content-Length reached, or the chunked terminator seen)
        # instead of always waiting for the peer to close the connection or
        # for the read to time out — plenty of embedded miner httpds ignore
        # "Connection: close" and idle-hold the socket open, which otherwise
        # means paying the full timeout on every single request.
        response = b""
        expected_end: Optional[int] = None
        is_chunked = False
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                if not chunk:
                    break
                response += chunk
                if len(response) > 131072:
                    break
            except asyncio.TimeoutError:
                break

            if expected_end is None and not is_chunked:
                hdr_end = response.find(b"\r\n\r\n")
                if hdr_end != -1:
                    hdr_text = response[:hdr_end].decode("utf-8", errors="replace")
                    if re.search(r"transfer-encoding:\s*chunked", hdr_text, re.IGNORECASE):
                        is_chunked = True
                    else:
                        cl_match = re.search(r"content-length:\s*(\d+)", hdr_text, re.IGNORECASE)
                        if cl_match:
                            expected_end = hdr_end + 4 + int(cl_match.group(1))

            if expected_end is not None and len(response) >= expected_end:
                break
            if is_chunked and response.endswith(b"0\r\n\r\n"):
                break

        # Close the socket defensively: embedded miner httpds routinely RST
        # the connection on teardown. A failure here must not discard a
        # response we've already fully read.
        try:
            writer.close()
            await writer.wait_closed()
        except (OSError, ssl.SSLError):
            pass

        if not response:
            return 0, "", {}

        # Split on \r\n\r\n boundary (headers | body)
        hdr_end = response.find(b"\r\n\r\n")
        if hdr_end == -1:
            return 0, response.decode("utf-8", errors="replace"), {}

        hdr_bytes = response[:hdr_end]
        raw_body = response[hdr_end + 4:]

        # Parse headers
        hdr_text = hdr_bytes.decode("utf-8", errors="replace")
        hdr_lines = hdr_text.split("\r\n")

        status_code = 0
        if hdr_lines:
            parts = hdr_lines[0].split()
            if len(parts) >= 2:
                try:
                    status_code = int(parts[1])
                except ValueError:
                    pass

        headers: dict[str, str] = {}
        for line in hdr_lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        # Handle Transfer-Encoding: chunked
        te = headers.get("transfer-encoding", "").lower()
        if "chunked" in te:
            raw_body = _decode_chunked(raw_body)

        # Handle Content-Encoding: gzip
        ce = headers.get("content-encoding", "").lower()
        if "gzip" in ce:
            try:
                raw_body = gzip.decompress(raw_body)
            except (gzip.BadGzipFile, OSError, EOFError):
                pass

        body = raw_body.decode("utf-8", errors="replace")

        return status_code, body, headers

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError, ssl.SSLError) as e:
        return -1, str(e), {}
    except Exception as e:
        return -2, str(e), {}


def _decode_chunked(data: bytes) -> bytes:
    """Decode HTTP chunked transfer encoding."""
    result = bytearray()
    pos = 0
    while pos < len(data):
        # Find chunk size line
        crlf = data.find(b"\r\n", pos)
        if crlf == -1:
            break
        size_line = data[pos:crlf].split(b";", 1)[0].strip()
        try:
            chunk_size = int(size_line, 16)
        except ValueError:
            break
        if chunk_size == 0:
            break
        pos = crlf + 2
        if pos + chunk_size > len(data):
            break
        result.extend(data[pos:pos + chunk_size])
        pos += chunk_size + 2  # chunk data + trailing CRLF
    return bytes(result)


async def _try_http_paths(
    ip: str,
    paths: list[str],
    port: int = 80,
    timeout: float = 3.0,
) -> tuple[int, str, str]:
    """Try multiple HTTP paths, return the first successful response."""
    for path in paths:
        status, body, headers = await _http_get(ip, path, port, timeout, use_ssl=(port in _HTTPS_PORTS))
        if status > 0:
            return status, body, path
    return -1, "", ""


def _score_signature(sig: dict, title: str, body: str) -> tuple[int, int]:
    """
    Score how well a signature matches. Returns (base_score, specificity).

    base_score keeps the original weighting (title hit=3, body hit=2) so the
    existing "confident match" threshold (>=2) is unchanged. specificity is
    the summed length of the distinct (case-folded) patterns that matched —
    used only to break ties between signatures that reach the same
    base_score (e.g. the overlapping ESP32-based miner families) instead of
    silently picking whichever signature happens to be listed first.
    """
    title_lower = title.lower()
    body_lower = body.lower()

    def _distinct_hits(patterns: list[str], haystack: str) -> set[str]:
        return {pat.lower() for pat in patterns if pat.lower() in haystack}

    title_hits = _distinct_hits(sig.get("title_patterns", []), title_lower)
    body_hits = _distinct_hits(sig.get("body_patterns", []), body_lower)

    base_score = (3 if title_hits else 0) + (2 if body_hits else 0)
    specificity = sum(len(p) for p in title_hits | body_hits)
    return base_score, specificity


def _extract_version(body: str, signature: dict) -> Optional[str]:
    """Extract firmware version from page body using signature regex."""
    fw_conf = signature.get("firmware_extraction")
    if not fw_conf:
        return None
    pattern = fw_conf.get("regex", "")
    if not pattern:
        return None
    try:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            return match.group(1)
    except (re.error, IndexError, AttributeError):
        pass
    return None


def _assess_risk(fp: MinerFingerprint):
    """Assign risk level based on fingerprint data."""
    risks = []

    # Auth not required on API endpoints = critical
    if fp.auth_required is False:
        risks.append(("critical", "Web UI or API accessible without authentication"))
    elif fp.auth_required is None:
        risks.append(("medium", "Could not determine authentication status"))
    else:
        risks.append(("info", "Authentication required for API access"))

    # Stratum V1 open
    if 3333 in fp.open_ports:
        risks.append(("high", "Stratum V1 port (3333) exposed — unencrypted, no authentication"))

    # cgminer RPC open
    if 4028 in fp.open_ports:
        risks.append(("critical", "cgminer RPC API (4028) exposed — typically no auth, allows configuration changes"))

    # SSH open
    if 22 in fp.open_ports:
        risks.append(("medium", "SSH port (22) exposed — check for default credentials"))

    # Bitcoin Core P2P open — not itself a vulnerability (any full node is
    # meant to be publicly reachable on 8333), just a strong signal this
    # host likely runs a paired mining pool alongside the miner/dashboard
    # already identified above. Not used to independently classify a host
    # as a miner (see fingerprint_host) — a bare reachable full node with
    # no other mining signal is just... a Bitcoin node.
    if 8333 in fp.open_ports:
        risks.append(("info", "Bitcoin Core P2P port (8333) open — full node detected, likely paired with a mining pool"))

    # Old firmware — age is computed relative to *today*, not a hardcoded
    # cutoff year, so this stays meaningful as time passes.
    if fp.firmware_version:
        # Bitmain uses date-based versions like "20220215"
        date_match = re.match(r"(\d{4})(\d{2})(\d{2})", fp.firmware_version)
        if date_match:
            year, month, day = int(date_match.group(1)), int(date_match.group(2)), int(date_match.group(3))
            try:
                fw_date = date(year, month, day)
            except ValueError:
                fw_date = None
            if fw_date:
                age_days = (date.today() - fw_date).days
                if age_days > 730:
                    risks.append(("high", f"Firmware from {year}-{month:02d} (~{age_days // 365}y old) — likely has known CVEs"))
                elif age_days > 365:
                    risks.append(("medium", f"Firmware from {year}-{month:02d} (~{age_days // 365}y old) — check for updates"))

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    risks.sort(key=lambda r: severity_order.get(r[0], 99))

    fp.details = [f"[{r[0].upper()}] {r[1]}" for r in risks]
    fp.risk_level = risks[0][0] if risks else "unknown"


async def fingerprint_host(ip: str, open_ports: dict[int, str], timeout: float = 3.0) -> Optional[MinerFingerprint]:
    """
    Attempt to identify a miner on the given host.

    Only uses publicly accessible endpoints — no credentials, no writes.
    """
    fp = MinerFingerprint(ip=ip, open_ports=list(open_ports.keys()))

    # Determine which HTTP ports to probe — try all open ports except ones
    # already known to be something else (miner web UIs sometimes run on
    # non-standard ports, so we don't want to be too narrow here).
    # Prioritize known HTTP ports first, then try the rest.
    known_http = [80, 443, 8080]
    other_ports = [p for p in open_ports if p not in known_http and p not in _KNOWN_NON_HTTP_PORTS]
    http_ports = [p for p in known_http if p in open_ports] + other_ports

    if not http_ports:
        # No TCP ports at all? Try mining-only signature
        if 3333 in open_ports or 4028 in open_ports:
            fp.risk_level = "high"
            fp.details.append("[HIGH] Mining protocol ports detected without HTTP — "
                             "likely a miner with web UI on non-standard port or disabled")
            return fp
        return None

    best_match: Optional[dict] = None
    best_key: tuple[int, int] = (0, 0)
    best_body: Optional[str] = None
    last_body: Optional[str] = None

    # Fire the root-path request at every candidate port at once instead of
    # waiting on them one at a time — matters when a host exposes more than
    # one HTTP-ish port (e.g. a pool dashboard also serving on an alt port).
    root_responses = await asyncio.gather(
        *(_try_http_paths(ip, ["/"], port, timeout) for port in http_ports)
    )

    for status, body, path in root_responses:
        if status <= 0:
            continue

        last_body = body

        title_match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE)
        title = title_match.group(1) if title_match else ""

        # Try each miner signature. Ties on base_score are broken by
        # specificity, not by list order — see _score_signature.
        for sig in _SIGNATURES:
            key = _score_signature(sig, title, body)
            if key > best_key:
                best_key = key
                best_match = sig
                best_body = body

    best_score = best_key[0]

    # Keep something for diagnostics even if nothing matched a signature.
    banner_source = best_body if best_match else last_body
    fp.raw_banner = banner_source[:2000] if banner_source else None

    if best_match and best_score >= 2:
        fp.vendor = best_match["vendor"]
        fp.miner_id = best_match["id"]

        # Try to extract model from the body that actually produced the match
        for model in best_match.get("models", []):
            if model.lower() in (best_body or "").lower():
                fp.model_hint = model
                break

        # Extract firmware version from the matching root page
        fp.firmware_version = _extract_version(best_body or "", best_match)

        # If not found on root page, try the firmware-specific API endpoint
        # — queried on every candidate port at once, then resolved in
        # http_ports order so the result is the same as trying them one by
        # one, just without paying for each port's timeout in sequence.
        if not fp.firmware_version:
            fw_conf = best_match.get("firmware_extraction", {})
            fw_path = fw_conf.get("path", "")
            if fw_path and fw_path != "/":
                fw_responses = await asyncio.gather(
                    *(_try_http_paths(ip, [fw_path], port, timeout) for port in http_ports)
                )
                for fw_code, fw_body, _ in fw_responses:
                    if fw_code == 200:
                        fp.firmware_version = _extract_version(fw_body, best_match)
                        if fp.firmware_version:
                            break

        # Check auth status on a sensitive endpoint, same one-request-per-port
        # fan-out, resolved in http_ports order.
        auth_path = best_match.get("auth_indicator_path")
        if auth_path:
            auth_responses = await asyncio.gather(
                *(_try_http_paths(ip, [auth_path], port, timeout) for port in http_ports)
            )
            for status, body, _ in auth_responses:
                if status == 200:
                    fp.auth_required = False
                    break
                elif status in (401, 403):
                    fp.auth_required = True
                    break
                elif 300 <= status < 400:
                    # Redirect to a login page is itself an auth-required signal
                    fp.auth_required = True
                    break
            # status == 0/-1 or all failed → None (unknown)
    elif 4028 in fp.open_ports:
        fp.vendor = "Generic"
        fp.miner_id = "cgminer_api"
        fp.auth_required = False  # cgminer API has no auth by default
    elif 3333 in fp.open_ports:
        # Likely a miner but couldn't identify via HTTP
        fp.miner_id = "unknown_stratum_device"
        fp.vendor = "Unknown"
    else:
        # Not identified as miner
        return None

    _assess_risk(fp)
    return fp
