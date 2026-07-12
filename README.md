# miner-audit

Passive ASIC miner security scanner. Finds Bitcoin mining hardware on a network and
evaluates its security posture using only HTTP GET requests and TCP handshakes.

**No credentials are attempted. No configuration is ever changed.** It only reports
what a device already voluntarily exposes on its default pages.

> **Only scan networks you own or have explicit written permission to test.**
> Unauthorized scanning may violate laws in your jurisdiction.

## What it detects

- **Vendor / model / firmware** — Bitmain (Antminer), MicroBT (Whatsminer), Canaan
  (Avalon), Braiins OS, the Bitaxe/NerdQaxe/AxeOS "OSMU" ESP32 family, Vnish, LuxOS,
  and generic `cgminer`/stratum devices. Signatures live in `signatures.json`.
- **Auth exposure** — whether the web UI or API is reachable without credentials.
- **Risky open ports** — unauthenticated `cgminer` RPC (4028), plaintext Stratum V1
  (3333), exposed SSH (22).
- **Firmware age** — flags firmware older than 1–2 years as a CVE risk.

Each finding gets a risk level (`critical` → `info`) and a one-line explanation.

## Usage

```bash
python3 scanner.py 192.168.1.0/24              # Scan a subnet
python3 scanner.py 10.0.0.1,10.0.0.2,10.0.0.3  # Scan specific IPs
python3 scanner.py 192.168.1.1-192.168.1.50    # Scan a range
python3 scanner.py -v 192.168.1.0/24           # Verbose — show every host, not just hits
python3 scanner.py -j 192.168.1.0/24            # JSON output
python3 scanner.py -p 80,3333,8081 192.168.1.0/24  # Custom port list
python3 scanner.py --rate-limit 100 10.0.0.0/16    # Throttle to 100 conn/s
```

Run `python3 scanner.py --help` for the full flag list.

Press **Ctrl+C** once during either phase to stop it early and move on with whatever
was found so far (a port scan interrupted early still gets fingerprinted; a
fingerprint pass interrupted early still gets reported). A second Ctrl+C forces an
immediate exit.

## Rate limiting

Large, mostly-empty ranges fail per-host in milliseconds, so concurrency alone
doesn't bound how many packets/second go out — an unthrottled sweep of a big range
can burst well past what a router's connection tracking or port-scan detection can
absorb, and drop legitimate replies along with the flood. `--rate-limit` (default
**300 conn/s**) caps new connection attempts across the whole scan regardless of
range size. Set it to `0` to disable. For a range much larger than a `/24`, prefer
scanning the specific `/24`s you actually have over blasting a whole `/16`.

## Requirements

Python 3.10+, standard library only — no dependencies to install.

## Project layout

| File | Purpose |
|---|---|
| `scanner.py` | CLI: argument parsing, two-phase orchestration, text/JSON reports |
| `ports.py` | Async TCP port scanner with the token-bucket rate limiter |
| `fingerprint.py` | Passive HTTP-based vendor/model/firmware/auth fingerprinting |
| `signatures.json` | Per-vendor detection patterns and firmware-extraction rules |

## How it works

1. **Port scan** — every target IP is checked against a small set of miner-relevant
   ports (80, 443, 22, 3333, 4028, 8080 by default). Only hosts with at least one
   open port move on.
2. **Fingerprint** — each surviving host gets a `GET /` (and vendor-specific
   follow-up requests) to identify what it's running, whether auth is required, and
   how old the firmware is. Fingerprinting runs concurrently across hosts and across
   a single host's candidate ports.

Both phases are read-only: TCP connect + HTTP GET, nothing else.
