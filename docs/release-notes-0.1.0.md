# WireScope v0.1.0 - Release Notes (draft)

## Highlights

WireScope is a streaming PCAP/PCAPNG/CAP analysis toolkit built for quick
network-forensics triage: who talked to whom, what DNS/HTTP/TLS activity
happened, which flows are worth a second look, and a clean JSON/CSV/HTML
report to hand off. It never loads a capture wholesale into memory, never
decrypts TLS, and never performs active network actions (no scanning, no
injection) - it is read-only, offline analysis.

This is the first tagged release, after an initial build followed by a
dedicated hardening/code-review pass (see CHANGELOG's "Unreleased"
section for the exact list) that focused on making the existing feature
set more correct and safer rather than growing it further: per-packet
crash isolation, CSV/HTML output-injection safeguards, bounded memory
growth across every collection (not just the ones that were already
capped), suffix-based IOC domain matching, and clean CLI error/exit-code/
Ctrl+C behavior.

## Features

- Streaming capture engine (Scapy `PcapReader`), bounded memory on
  multi-gigabyte captures.
- Capture summary, host/port analysis, normalized 5-tuple conversations.
- DNS (A/AAAA/CNAME/MX/TXT, NXDOMAIN), plaintext HTTP, TLS SNI metadata.
- ARP/ICMP/TCP-flag statistics.
- Hedged heuristic findings (INFO/LOW/MEDIUM/HIGH) - a triage aid, not an
  IDS; see the README's Detection Philosophy section.
- Flat-file IOC matching (IP/domain, suffix-based for domains).
- `--ip`/`--port`/`--protocol` filters, combinable.
- JSON, per-category CSV, and offline single-file HTML exports.
- Typer + Rich CLI with clean error handling (no raw tracebacks by
  default, `-v`/`-vv` for more detail) and distinct exit codes for bad
  input (1), interruption (130), and unexpected internal errors (2).

## Known limitations

- No IOC hash/URL matching - IP and domain only.
- No PyShark/tshark backend - Scapy only.
- No X.509 certificate parsing, no JA3/JA4 fingerprinting.
- No HTTP file/object extraction.
- No TUI/GUI.
- Heuristic thresholds are reasonable starting points, not tuned against
  a real traffic baseline - expect false positives on NAT gateways, DHCP
  churn, CDNs, and busy servers. See README's Detection Philosophy.

## Installation

```bash
git clone https://github.com/yigitatmaca42/WireScope.git
cd WireScope
python3 -m venv .venv && source .venv/bin/activate
pip install .
wirescope --help
```

See the README for Quick Start, full usage, and architecture notes.
