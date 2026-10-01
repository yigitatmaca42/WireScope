# Changelog

All notable changes to this project are documented in this file.

## [Unreleased] - hardening pass

### Fixed

- Analyzer: a single malformed/unexpected packet no longer aborts analysis
  of the rest of the capture - per-packet processing is now isolated in a
  try/except, with skipped packets counted in `malformed_packet_count`
  (surfaced in the terminal header, JSON, and HTML report).
- CSV export: values starting with `=`, `+`, `-`, or `@` are now
  neutralized against spreadsheet "formula injection" before being
  written (capture-derived strings are untrusted input).
- `CollectionLimits` now also bounds `hosts`, `ports_src`/`ports_dst`, and
  `arp_entries` (previously only DNS/HTTP/TLS/conversations were capped),
  closing a memory-growth gap on captures with many unique IPs/ports.
- IOC domain matching is now suffix-based (`example.com` also matches
  `sub.example.com`) instead of exact-match only, and is documented as
  such; malformed IOC file lines are now reported as a warning instead of
  being silently treated as unmatchable domains.
- CLI: unexpected internal errors (anything not already a `WireScopeError`)
  now get the same clean-error treatment as known errors, with a distinct
  exit code (2) from "bad input" errors (1); Ctrl+C now prints a clean
  "Analysis interrupted." instead of a raw `KeyboardInterrupt` traceback
  (exit 130).
- HTML report: tables now scroll horizontally on narrow viewports instead
  of overflowing; added a small-viewport media query and a minimal print
  stylesheet.
- Local default branch renamed `master` -> `main` to match the CI
  workflow's trigger and modern convention (no history rewritten).

### Added

- Dedicated flow-normalization tests (A<->B folding across IPv4/IPv6/
  TCP/UDP, non-folding of distinct 5-tuples, order-independence).
- A regression test proving a malformed DNS packet is skipped rather than
  crashing the run, with the rest of the capture still processed.
- A regression test proving the HTML report HTML-escapes every
  capture-derived field (DNS query name, HTTP host/path/user-agent, TLS
  SNI, finding text) - this was already correct, now pinned down.
- Malformed/fuzz-lite input tests for the HTTP and TLS parsers (random
  bytes, truncation at every byte offset of a valid TLS ClientHello,
  case-insensitive Host header, unknown TLS extensions before SNI).
- `docs/report-schema.md`: field-by-field documentation of the JSON
  export schema (also covers CSV/HTML, which share the same model).

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
