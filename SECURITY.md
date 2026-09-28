# Security Policy

## Scope and intent

WireScope is an **offline PCAP analysis tool**. It:

- Does **not** perform port scanning, packet injection, or any form of
  active network attack.
- Does **not** decrypt TLS traffic. TLS handling is limited to metadata
  visible in the unencrypted ClientHello (SNI, record-layer version).
- Does **not** claim to detect malware, intrusions, or confirmed attacks.
  Its detection layer produces hedged findings for human review - see the
  README's [Detection Philosophy](README.md#detection-philosophy) section.

If you're looking for an active scanning, exploitation, or traffic
injection tool, WireScope is the wrong tool - that's out of scope by
design (see the project's original spec, section 27).

## Processing untrusted captures

**Treat every PCAP file as untrusted input, especially one you didn't
generate yourself.** A capture is attacker-influenceable data: a malicious
or malformed file can attempt to exploit vulnerabilities in the packet
parser it's fed to.

Concretely, for WireScope:

- The packet engine is [Scapy](https://github.com/secdev/scapy). Scapy has
  had parsing bugs in the past (as has every packet-parsing library), and
  WireScope's own protocol parsers (`wirescope/protocols/http.py`,
  `wirescope/protocols/tls.py`) do their own hand-rolled byte-level parsing
  on top of raw payloads. Both layers are exercised against malformed input
  by the test suite, but neither is a hardened, fuzzed parser.
- WireScope's parsers are written defensively (bounds-checked slicing,
  `None` returns instead of exceptions on malformed structures), but "we
  tried to be careful" is not the same guarantee as a security audit.
- If you're analyzing a capture from an untrusted or adversarial source
  (e.g. a CTF challenge, a suspected-malicious capture from an incident),
  consider running WireScope in an isolated environment (container, VM, or
  a low-privilege user) rather than directly on a machine with sensitive
  access.

## Reporting a vulnerability

If you find a way to make WireScope crash, hang, consume excessive memory,
or behave unexpectedly on a crafted capture file, please open an issue on
the GitHub repository describing:

- The WireScope version and Python version
- What kind of malformed input triggered it (a redacted/synthetic
  reproduction is preferred over sharing a real, potentially sensitive
  capture)
- The observed behavior (crash, hang, high memory use, incorrect output)

There is currently no dedicated security contact address for this project
beyond GitHub issues - for anything you'd rather not post publicly before
a fix exists, mention that in the issue title and a maintainer will follow
up privately.

## Data privacy

PCAP files routinely contain sensitive information: IP addresses, domain
names, URLs, credentials, cookies, and raw payload data. WireScope reads
this data locally and never transmits it anywhere - but **you** are
responsible for what you do with the capture and the reports WireScope
generates from it. Review a capture (and any JSON/CSV/HTML report
generated from it) before sharing it with anyone, filing it in a ticket,
or committing it to a repository.
