# WireScope

**Lightweight PCAP Analysis & Network Forensics Toolkit**

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![CI](https://github.com/yigitatmaca42/WireScope/actions/workflows/ci.yml/badge.svg)

WireScope reads `.pcap` / `.pcapng` / `.cap` captures and pulls out the
things a network forensics triage actually needs first: who talked to whom,
what DNS/HTTP/TLS activity happened, which flows look worth a second look,
and a clean JSON/CSV/HTML report you can hand off or archive. It streams
packets instead of loading a capture into memory, so a multi-gigabyte pcap
doesn't require a multi-gigabyte machine.

It's built for network analysts doing quick triage, forensics/CTF players
picking apart a capture, and anyone who wants a real (if intentionally
scoped) starting point for PCAP tooling rather than a 200-line script.

## Features

- **Streaming engine** - Scapy's `PcapReader` iterates the capture packet by
  packet; nothing is loaded wholesale into memory.
- **Capture summary** - packet/byte totals, duration, rates, protocol mix.
- **Host & port analysis** - top talkers with bytes/peers/ports, top source
  and destination ports with a small well-known-service lookup.
- **Conversations/flows** - normalized 5-tuple flows (A→B and B→A folded
  into one), with packet/byte counts and timing.
- **DNS** - queries and responses, A/AAAA/CNAME/MX/TXT, NXDOMAIN tracking,
  unique-domain and burst detection.
- **Plaintext HTTP** - method/host/path/user-agent on requests,
  status/content-type/server on responses. TLS is never decrypted.
- **TLS metadata** - SNI extraction from the ClientHello (hand-parsed, no
  extra dependency); record-layer version only, no certificate parsing.
- **ARP / ICMP / TCP flags** - IP↔MAC mapping with inconsistency flagging,
  ICMP type/code stats, SYN/ACK/FIN/RST/PSH counters.
- **Hedged heuristic findings** - INFO/LOW/MEDIUM/HIGH findings for things
  like plaintext-protocol usage, scanning-shaped behavior, DNS bursts,
  unusually long DNS labels, large transfers, and ARP inconsistencies. See
  [Detection Philosophy](#detection-philosophy) below - none of this is a
  verdict.
- **Simple IOC matching** - a flat text file of IPs/domains, checked against
  what showed up in the capture. Domain matching is suffix-based (an IOC
  entry of `example.com` also matches `sub.example.com`), IP matching
  supports both IPv4 and IPv6.
- **Filters** - `--ip`, `--port`, `--protocol`, combinable, applied
  consistently across the whole analysis (including the summary).
- **Exports** - structured JSON, per-category CSV files, and a
  self-contained offline HTML report (no CDN, no JS framework).

## Installation

```bash
git clone https://github.com/yigitatmaca42/WireScope.git
cd WireScope
python3 -m venv .venv && source .venv/bin/activate
pip install .
```

For development (tests/lint/type-checking):

```bash
pip install -e ".[dev]"
```

Requires Python 3.11+.

## Quick Start

```bash
# Don't have a capture handy? Generate a small synthetic one:
python examples/generate_sample_pcap.py

wirescope examples/sample_capture.pcap
```

## Usage

```
wirescope <pcap> [options]
```

| Option | Effect |
|---|---|
| *(none)* | Summary + top hosts + top ports + findings |
| `--summary` | Just the capture summary, hosts, and ports |
| `--dns` | DNS query/response table |
| `--http` | Plaintext HTTP transaction table |
| `--tls` | TLS ClientHello / SNI table |
| `--conversations` | Top conversations/flows |
| `--findings` | Heuristic findings only |
| `--ip IP` | Filter to this IP (repeatable) |
| `--port N` | Filter to this port (repeatable) |
| `--protocol NAME` | Filter to this protocol: tcp, udp, dns, http, tls, arp, icmp (repeatable) |
| `--ioc FILE` | Match hosts/domains against a text file of IOCs |
| `--json FILE` | Write a JSON report |
| `--csv DIR` | Write per-category CSV reports into a directory |
| `--html FILE` | Write a standalone offline HTML report |
| `-v` / `-vv` | More verbose logging; `-vv` also shows tracebacks on error |
| `-q` / `--quiet` | Suppress the terminal report (pairs well with `--json`/`--csv`/`--html`) |

Flags combine freely:

```bash
wirescope capture.pcap --dns --http --findings
wirescope capture.pcap --ip 10.0.0.5 --protocol dns
wirescope capture.pcap --json report.json --csv reports/ --html report.html --quiet
wirescope capture.pcap --ioc iocs.txt --findings
```

## Example Output

```
WireScope  sample_capture.pcap
Packets: 52   Duration: 00:01   Size: 3.22 KB

               Capture Summary
File size            4.05 KB
Capture start        2026-09-28 20:29:45 UTC
Capture end          2026-09-28 20:29:46 UTC
Duration             00:01
Total packets        52
Total bytes          3.22 KB
Average packet size  63.3 B
Packets / second     38.52
Bytes / second       2.38 KB

      Protocols
┏━━━━━━━━━━┳━━━━━━━━━┓
┃ Protocol ┃ Packets ┃
┡━━━━━━━━━━╇━━━━━━━━━┩
│ IPV4     │      50 │
│ TCP      │      40 │
│ UDP      │       8 │
│ ICMP     │       2 │
│ ARP      │       2 │
└──────────┴─────────┘

                Findings (3)
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Severity ┃ Title                   ┃ Confidence ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ MEDIUM   │ Host contacted many     │ medium     │
│          │ distinct destination   │            │
│          │ ports                  │            │
│ LOW      │ Plaintext HTTP traffic │ high       │
│          │ observed               │            │
│ INFO     │ NXDOMAIN responses     │ high       │
│          │ observed               │            │
└──────────┴─────────────────────────┴────────────┘
```

(Captured from an actual run against `examples/sample_capture.pcap`, which
includes a simulated port-scan burst - that's what the MEDIUM finding is
about.)

## Reports

- **JSON** (`--json report.json`) - stable top-level keys: `capture`,
  `statistics`, `hosts`, `ports` (`source`/`destination`), `conversations`,
  `dns`, `http`, `tls`, `arp`, `findings`. Field-by-field reference:
  [docs/report-schema.md](docs/report-schema.md).
- **CSV** (`--csv reports/`) - `hosts.csv`, `ports.csv`,
  `conversations.csv`, `dns.csv`, `http.csv`, `findings.csv`.
- **HTML** (`--html report.html`) - a single offline file: capture
  overview, an SVG packets-over-time timeline, protocol distribution,
  top hosts/ports, DNS/HTTP/TLS tables, conversations, and findings. No
  external CDN, no JS framework - pure HTML/CSS plus a little inline SVG.

## Architecture

```
wirescope/
├── models.py            # Plain dataclasses - the only thing every other module shares
├── filters.py            # --ip/--port/--protocol inclusion filtering
├── exceptions.py          # WireScopeError hierarchy -> clean CLI errors, no raw tracebacks
├── analyzer.py            # Streaming packet engine (Scapy PcapReader) -> AnalysisResult (FACTS)
├── protocols/
│   ├── dns.py             # DNS query/response parsing (Scapy's DNS layer)
│   ├── http.py            # Plaintext HTTP request/response parsing (hand-rolled, no scapy_http)
│   ├── tls.py             # TLS ClientHello / SNI extraction (hand-rolled, no cert parsing)
│   ├── arp.py             # ARP request/reply -> IP/MAC events
│   ├── icmp.py             # ICMP type/code events
│   └── tcp.py              # TCP flag events
├── detection/
│   ├── heuristics.py       # FACTS -> hedged INTERPRETATIONS (Finding objects)
│   └── ioc.py               # Flat-file IP/domain IOC matching
├── exporters/
│   ├── json_exporter.py     # Stable JSON schema
│   ├── csv_exporter.py       # Per-category CSV files
│   └── html_exporter.py       # Offline HTML report (inline SVG bar charts/timeline)
├── reporting.py              # Rich terminal tables
├── utils/                    # formatting, well-known ports, entropy, timeline bucketing
└── cli.py                    # Typer CLI wiring everything together
```

The analyzer never imports the detection or reporting layers, and the
protocol parsers never see `AnalysisResult` - each layer only depends on
the one below it. That's what section 46 of this project's spec called the
FACTS/INTERPRETATION split, and it's enforced by import direction, not just
convention.

## Detection Philosophy

**WireScope is a triage aid, not an intrusion detection system.** Every
finding is a hypothesis for a human analyst to check, phrased with words
like *Possible*, *Potential*, *Observed*, or *review recommended* - never
*detected* or *confirmed*. The thresholds behind them (SYN-ratio cutoffs,
"many ports" counts, DNS burst sizes, entropy cutoffs) are simple constants
chosen to be reasonable starting points, not values tuned against a real
traffic baseline. Expect false positives on legitimate NAT gateways, DHCP
churn, CDNs, and busy servers. See [SECURITY.md](SECURITY.md) for more on
what WireScope does and doesn't claim.

## Known Limitations

- IOC matching covers IPs and domains only - no hash or URL IOCs.
- TLS support is limited to SNI and record-layer version: no X.509
  certificate parsing, no JA3/JA4 fingerprinting, no decryption.
- No HTTP file/object extraction.
- Scapy is the only packet backend (no PyShark/tshark).
- Terminal-only: no TUI or GUI. HTML reports are static.
- Heuristic thresholds are untuned starting points and will produce false
  positives on real-world traffic.

## Roadmap

Shipped in 1.0.0: everything listed under Features above.

WireScope follows [Semantic Versioning](https://semver.org/): `1.0.x` for
backward-compatible fixes, `1.x.0` for new backward-compatible features,
`2.0.0` for breaking CLI/report-schema changes or major architecture
changes. The JSON report has its own `schema_version` (see
[docs/report-schema.md](docs/report-schema.md)), separate from the package
version.

Planned (none of this is implemented yet - it is listed here so it is not
silently implied by a feature that only sort-of works):

- **1.x** - IOC hash/URL support, PyShark/tshark as an alternate backend,
  TLS certificate (X.509) parsing and JA3/JA4 fingerprinting, plaintext
  HTTP file/object extraction, HTML report interactivity, TUI
- **2.0** - Plugin architecture, GUI (large architectural changes)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) - in particular, treat any PCAP you feed
into WireScope (or any tool built on Scapy) as untrusted input, and never
share a real capture without reviewing what's inside it first (see
[SECURITY.md](SECURITY.md#data-privacy)).

## License

[MIT](LICENSE) - Yiğit Atmaca.
