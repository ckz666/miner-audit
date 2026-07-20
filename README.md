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

## Install

```bash
git clone https://github.com/ckz666/miner-audit.git
cd miner-audit
pip install .              # or -e . for development (edits take effect without reinstalling)
```

This installs a `miner-audit` command on your `PATH`. No external dependencies —
standard library only.

**On Kali, current Ubuntu/Debian, or anything else with Python 3.11+:** a plain
`pip install` into the system Python will refuse with `externally-managed-environment`
(PEP 668). Use a venv or `pipx` instead:

```bash
# venv (recommended if you're also editing the code — use -e . inside it)
python3 -m venv ~/.venvs/miner-audit
source ~/.venvs/miner-audit/bin/activate
pip install -e .

# or pipx (simplest if you just want the command available, no editing)
pipx install .
```

If you used a venv, `miner-audit` only exists while it's activated. To get it on
your `PATH` in every new terminal without manually activating, add this to your
`~/.bashrc`:

```bash
export PATH="$HOME/.venvs/miner-audit/bin:$PATH"
```

## Usage

```bash
miner-audit 192.168.1.0/24              # Scan a subnet
miner-audit 10.0.0.1,10.0.0.2,10.0.0.3  # Scan specific IPs
miner-audit 192.168.1.1-192.168.1.50    # Scan a range
miner-audit -v 192.168.1.0/24           # Verbose — show every host, not just hits
miner-audit -j 192.168.1.0/24           # JSON output
miner-audit -p 80,3333,8081 192.168.1.0/24  # Custom port list
miner-audit --rate-limit 100 10.0.0.0/16    # Throttle to 100 conn/s
miner-audit -o report.txt 192.168.1.0/24    # Also save the report to a file
```

Run `miner-audit --help` for the full flag list.

Didn't install it? Run it straight from a clone instead:
`python3 -m miner_audit.scanner <target>` from the `src/` directory.

### Saving a report (`-o`)

`-o FILE` writes the same final report you see on screen (text or, combined with
`-j`, JSON) to a file, tagged with the scan target and start time. This is the
finished report only — not a raw transcript of the live progress bar, which is full
of `\r`/ANSI codes that would look like garbage outside a terminal. The terminal
still shows the normal live view either way.

Press **Ctrl+C** once to stop early and report whatever was found so far. A second
Ctrl+C forces an immediate exit.

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
| `src/miner_audit/scanner.py` | CLI: argument parsing, per-host scan+fingerprint pipeline, text/JSON reports |
| `src/miner_audit/ports.py` | Async TCP port scanner with the token-bucket rate limiter |
| `src/miner_audit/fingerprint.py` | Passive HTTP-based vendor/model/firmware/auth fingerprinting |
| `src/miner_audit/signatures.json` | Per-vendor detection patterns and firmware-extraction rules |
| `pyproject.toml` | Packaging — installs the `miner-audit` command |

## How it works

Each target IP runs through a two-step pipeline, but the steps are pipelined
*across* hosts rather than run as two separate whole-range passes:

1. **Port scan** — checked against a small set of miner-relevant ports (80, 443,
   22, 3333, 4028, 8080 by default). For 22, 3333, and 4028, a bare TCP handshake
   isn't enough to count as "open": a minimal read-only protocol probe confirms the
   port actually speaks SSH, Stratum V1, or the cgminer RPC API before trusting it
   — a middlebox or unrelated service that completes a TCP handshake without
   speaking the real protocol is otherwise indistinguishable from the real thing,
   and those three ports are treated as a strong signal on their own further down
   the pipeline. 80/443/8080 don't need this: the HTTP fingerprint step below
   already only matches a real response.
2. **Fingerprint** — if a host has at least one open port, it gets a `GET /` (and
   vendor-specific follow-up requests) immediately, without waiting for the rest of
   the range to finish scanning — to identify what it's running, whether auth is
   required, and how old the firmware is.

The two steps use separate concurrency limits (port scanning is many short TCP
connects and scales with range size; fingerprinting is a handful of sequential HTTP
requests per host, capped much lower) so a host that starts fingerprinting doesn't
block another host's port scan from starting. Both steps are read-only: TCP connect
+ HTTP GET (or the equivalent read-only query for 22/3333/4028), nothing else.

## False positives

Signature patterns are checked against real devices and real upstream source where
possible, not just written from memory — generic terms that happen to double as a
mining signal (a common chip name, a common JSON field name, a brand word reused by
unrelated products) have caused real false positives against non-mining gear (an
unrelated router's admin panel, for one) and are actively avoided. If you get a
result that looks wrong, it's worth a bug report — false positives are treated as
real bugs here, not just noise.
