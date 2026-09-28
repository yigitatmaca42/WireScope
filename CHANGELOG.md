# Changelog

All notable changes to this project are documented in this file.

## [0.1.0] - 2026-09-28

Initial release.

### Added

- Streaming PCAP/PCAPNG/CAP analysis engine built on Scapy's `PcapReader`.
- Capture summary (packet/byte totals, duration, rates, protocol mix).
- Host analysis (packets, bytes sent/received, unique peers, ports used).
- Port analysis (top source/destination ports with well-known-service
  labels for a small hardcoded set of ports).
- Conversation/flow tracking with normalized 5-tuple direction.
- DNS parsing: queries, responses, A/AAAA/CNAME/MX/TXT records, NXDOMAIN
  tracking, unique-domain counting.
- Plaintext HTTP request/response parsing (method, host, path, user-agent,
  status code, content-type, server).
- TLS ClientHello SNI extraction (record-layer version only; no
  certificate parsing, no decryption).
- ARP request/reply tracking with IP↔MAC mapping.
- ICMP type/code statistics.
- TCP flag statistics (SYN/ACK/FIN/RST/PSH).
- Hedged heuristic findings (INFO/LOW/MEDIUM/HIGH): plaintext HTTP/FTP/
  Telnet, uncommon ports, high SYN-to-ACK ratio, one host contacting many
  ports/peers, DNS query bursts, unusually long DNS labels, large
  transfers, ARP inconsistencies, high-entropy payloads.
- Simple IOC matching against a flat text file of IPs/domains.
- CLI filters: `--ip`, `--port`, `--protocol` (combinable, applied
  consistently across the whole analysis).
- Rich-based terminal output: summary, hosts, ports, DNS, HTTP, TLS,
  conversations, findings.
- JSON export with a stable schema.
- CSV export (one file per category).
- Standalone offline HTML report with inline SVG visualizations
  (protocol distribution, top hosts, packets-over-time timeline).
- `examples/generate_sample_pcap.py` for generating a synthetic capture
  without needing a real one.
- Test suite (pytest) covering models, protocol parsers, the analyzer,
  heuristics, IOC matching, exporters, and the CLI.
- GitHub Actions CI (Python 3.11/3.12/3.13: install, lint, test).

### Known limitations (see README Roadmap)

- No IOC hash/URL matching yet, only IP/domain.
- No PyShark/tshark backend - Scapy only.
- No X.509 certificate parsing or JA3/JA4 fingerprinting.
- No HTTP file/object extraction.
- No TUI/GUI.
